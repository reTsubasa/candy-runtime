use anyhow::{bail, Context, Result};
use candy_netd_proto::{
    FirewallPolicy, PrepareDeclaration, RouteDeclaration, RouteKind, UnderlayExclusion,
    UnderlayKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const INPUT_LIMIT: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub template_plan: PathBuf,
    pub published_plan: PathBuf,
}

#[derive(Deserialize)]
struct Descriptor {
    schema_version: u8,
    activation_id: String,
    projection_generation: u64,
    core_role: String,
    core_config: String,
    netd_declaration: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudDeclaration {
    table_id: u32,
    overlay_router_ipv4: std::net::Ipv4Addr,
    effective_mtu: u16,
    routes: Vec<CloudRoute>,
    exclusions: Vec<CloudExclusion>,
    firewall: FirewallPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudRoute {
    prefix: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudExclusion {
    prefix: String,
    kind: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u8,
    activation_id: String,
    source_sha256: String,
    template_sha256: String,
    plan_sha256: String,
}

fn read_private(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > INPUT_LIMIT
    {
        bail!("code=cloud_plan_input_rejected module=cloud_plan_bridge detail=input must be owned private bounded regular file");
    }
    let mut bytes = Vec::new();
    file.take(INPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > INPUT_LIMIT {
        bail!("Cloud plan input grew past its limit");
    }
    Ok(bytes)
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(path.parent().context("Cloud plan path has no parent")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn declaration(value: CloudDeclaration) -> Result<PrepareDeclaration> {
    let routes = value
        .routes
        .into_iter()
        .map(|route| {
            Ok(RouteDeclaration {
                prefix: crate::parse_prefix(&route.prefix)?,
                kind: match route.kind.as_str() {
                    "local" => RouteKind::Local,
                    "remote" => RouteKind::Remote,
                    "remote-egress" => RouteKind::RemoteEgress,
                    "remote-egress-gateway" => RouteKind::RemoteEgressGateway,
                    _ => bail!("unknown Cloud route kind"),
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let exclusions = value
        .exclusions
        .into_iter()
        .map(|entry| {
            Ok(UnderlayExclusion {
                prefix: crate::parse_prefix(&entry.prefix)?,
                kind: match entry.kind.as_str() {
                    "cloud-api" => UnderlayKind::CloudApi,
                    "hub-endpoint" => UnderlayKind::HubEndpoint,
                    "management" => UnderlayKind::Management,
                    _ => bail!("unknown Cloud exclusion kind"),
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PrepareDeclaration {
        table_id: value.table_id,
        overlay_router_ipv4: value.overlay_router_ipv4.octets(),
        effective_mtu: value.effective_mtu,
        routes,
        exclusions,
        firewall: value.firewall,
    })
}

fn candidate_directory(state_dir: &Path) -> Result<PathBuf> {
    let target = fs::read_link(state_dir.join("candidate"))?;
    let parts = target.components().collect::<Vec<_>>();
    if parts.len() != 2 || parts[0] != Component::Normal("activations".as_ref()) {
        bail!("code=cloud_plan_candidate_path_rejected module=cloud_plan_bridge detail=candidate must point to an immutable activation generation");
    }
    let Component::Normal(id) = parts[1] else {
        bail!("invalid activation generation");
    };
    let id = id.to_str().context("activation ID is not UTF-8")?;
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("invalid activation ID");
    }
    let directory = state_dir.join(target);
    for path in [state_dir.join("activations"), directory.clone()] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            bail!("activation generation requires owned 0700 directories");
        }
    }
    Ok(directory)
}

pub(super) fn reconcile(
    state_dir: &Path,
    binding: &Binding,
    deadline: std::time::Instant,
) -> Result<bool> {
    let directory = candidate_directory(state_dir)?;
    let descriptor: Descriptor =
        serde_json::from_slice(&read_private(&directory.join("activation-v1.json"))?)?;
    if descriptor.schema_version != 1
        || descriptor.core_role != "client_sdwan"
        || descriptor.core_config != "core.toml"
        || descriptor.netd_declaration != "declaration.json"
        || directory.file_name().and_then(|name| name.to_str())
            != Some(descriptor.activation_id.as_str())
    {
        bail!("code=cloud_plan_descriptor_rejected module=cloud_plan_bridge detail=activation descriptor differs from pinned client generation");
    }
    let core_config = directory.join("core.toml");
    #[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
    let source = hash(&crate::signed_snapshot::fingerprint(&core_config)?);
    #[cfg(not(all(feature = "experimental-tunio-rebind", target_os = "linux")))]
    let source = hash(&read_private(&core_config)?);
    let template = hash(&read_private(&binding.template_plan)?);
    let receipt_path = binding.published_plan.with_extension("cloud-source.json");
    if let (Ok(receipt), Ok(plan)) = (
        read_private(&receipt_path),
        read_private(&binding.published_plan),
    ) {
        if let Ok(receipt) = serde_json::from_slice::<Receipt>(&receipt) {
            if receipt.schema_version == 1
                && receipt.activation_id == descriptor.activation_id
                && receipt.source_sha256 == source
                && receipt.template_sha256 == template
                && receipt.plan_sha256 == hash(&plan)
            {
                return Ok(false);
            }
        }
    }
    let declaration = declaration(serde_json::from_slice(&read_private(
        &directory.join("declaration.json"),
    )?)?)?;
    let bytes = crate::experimental_tunio::cloud_activation_plan(
        &binding.template_plan,
        &core_config,
        declaration,
        descriptor.projection_generation,
        binding
            .published_plan
            .parent()
            .context("published Cloud plan has no parent")?,
        deadline,
    )?;
    #[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
    if source != hash(&crate::signed_snapshot::fingerprint(&core_config)?) {
        bail!("code=cloud_plan_source_changed module=cloud_plan_bridge detail=source changed during signature verification; preserve previous plan");
    }
    atomic_private(&binding.published_plan, &bytes)?;
    atomic_private(
        &receipt_path,
        &serde_json::to_vec(&Receipt {
            schema_version: 1,
            activation_id: descriptor.activation_id.clone(),
            source_sha256: source,
            template_sha256: template,
            plan_sha256: hash(&bytes),
        })?,
    )?;
    eprintln!("level=info code=cloud_plan_published module=cloud_plan_bridge activation_id={} plan={} action=domain_reconcile_preserve_infrastructure", descriptor.activation_id, binding.published_plan.display());
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn candidate_cannot_escape_activation_directory() {
        let root = tempfile::tempdir().unwrap();
        for target in ["../elsewhere", "/etc", "activations/../elsewhere"] {
            symlink(target, root.path().join("candidate")).unwrap();
            assert!(candidate_directory(root.path()).is_err());
            fs::remove_file(root.path().join("candidate")).unwrap();
        }
    }

    #[test]
    fn candidate_generation_cannot_be_a_symlink() {
        let root = tempfile::tempdir().unwrap();
        let id = "a".repeat(64);
        fs::create_dir(root.path().join("activations")).unwrap();
        fs::set_permissions(
            root.path().join("activations"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        symlink("/tmp", root.path().join("activations").join(&id)).unwrap();
        symlink(format!("activations/{id}"), root.path().join("candidate")).unwrap();
        assert!(candidate_directory(root.path()).is_err());
    }

    #[test]
    fn rejected_candidate_preserves_existing_plan() {
        let root = tempfile::tempdir().unwrap();
        let binding = Binding {
            template_plan: root.path().join("template.json"),
            published_plan: root.path().join("plan.json"),
        };
        atomic_private(&binding.published_plan, b"existing verified plan").unwrap();
        symlink("../bad-candidate", root.path().join("candidate")).unwrap();
        assert!(reconcile(
            root.path(),
            &binding,
            std::time::Instant::now() + std::time::Duration::from_secs(1)
        )
        .is_err());
        assert_eq!(
            read_private(&binding.published_plan).unwrap(),
            b"existing verified plan"
        );
    }
}
