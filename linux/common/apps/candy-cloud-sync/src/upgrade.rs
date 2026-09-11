use super::*;
use nix::fcntl::{Flock, FlockArg};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const CATALOG_KEY: &str =
    include_str!("../../../../../openwrt/client/packages/candy-client/catalog-release.pub");
const RELEASE_ROOT: &str = "https://github.com/reTsubasa/candy-release/releases/download/";
const MAX_BUNDLE: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Target {
    component: String,
    current_version: String,
    version: String,
    version_key: String,
    digest: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct Job {
    id: Uuid,
    node_id: Uuid,
    device_id: Uuid,
    device_key_id: Uuid,
    target: Target,
    state: String,
    error_code: Option<String>,
    // Cloud emits RFC3339 timestamps; the executor only persists/echoes them.
    // Keep them as strings so the wire contract does not depend on chrono's
    // optional serde feature in minimal runtime builds.
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    job: Job,
    phase: String,
    error_code: Option<String>,
}

#[derive(Serialize)]
struct Inventory {
    schema_version: u8,
    platform: &'static str,
    architecture: String,
    targets: Vec<Target>,
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"._+-".contains(&v))
}

fn private_root(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("stage=upgrade_journal error_code=unsafe_state_directory")
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn fetch(client: &Client, url: &str, destination: &Path, limit: u64) -> Result<()> {
    let response = client.get(url).send()?.error_for_status()?;
    if response.content_length().is_some_and(|n| n > limit) {
        bail!("artifact_size_limit");
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(destination)?;
    let length = std::io::copy(&mut response.take(limit + 1), &mut output)?;
    output.sync_all()?;
    if length == 0 || length > limit {
        bail!("artifact_size_limit");
    }
    Ok(())
}

fn command(program: &str, arguments: &[&str], root: &Path) -> Result<()> {
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(root.join("execution.log"))?;
    let mut child = ProcessCommand::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("command_exit_{}", status.code().unwrap_or(-1));
            }
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(15 * 60) {
            // SIGTERM lets existing transactional managers run their rollback trap.
            unsafe {
                nix::libc::kill(child.id() as i32, nix::libc::SIGTERM);
            }
            child.wait()?;
            bail!("installer_timeout");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn catalog(root: &Path) -> Result<serde_json::Value> {
    let client = Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(180))
        .connect_timeout(Duration::from_secs(10))
        .build()?;
    let raw = "https://raw.githubusercontent.com/reTsubasa/candy-release/main/channels/stable.json";
    fetch(&client, raw, &root.join("catalog.json"), 4 * 1024 * 1024)?;
    fetch(
        &client,
        &format!("{raw}.sig"),
        &root.join("catalog.sig"),
        4096,
    )?;
    atomic_bytes(&root.join("catalog.pub"), CATALOG_KEY.as_bytes(), 0o600)?;
    command(
        "usign",
        &[
            "-V",
            "-p",
            root.join("catalog.pub").to_str().context("path")?,
            "-m",
            root.join("catalog.json").to_str().context("path")?,
            "-x",
            root.join("catalog.sig").to_str().context("path")?,
        ],
        root,
    )
    .context("stage=catalog_signature error_code=signature_verification_failed")?;
    let value: serde_json::Value = read_bounded_json(&root.join("catalog.json"), 4 * 1024 * 1024)?;
    let sequence = value["sequence"]
        .as_u64()
        .context("catalog_sequence_missing")?;
    let previous = fs::read_to_string(root.join("catalog-sequence"))
        .unwrap_or_default()
        .parse::<u64>()
        .unwrap_or(0);
    if sequence < previous || value["schema_version"] != 1 || value["channel"] != "stable" {
        bail!("catalog_rollback_or_invalid_schema");
    }
    atomic_bytes(
        &root.join("catalog-sequence"),
        sequence.to_string().as_bytes(),
        0o600,
    )?;
    Ok(value)
}

fn manager(openwrt: bool) -> &'static str {
    if openwrt {
        "/usr/libexec/candy-core-manager"
    } else {
        "/usr/local/bin/candy-core-manager"
    }
}

fn current(component: &str, openwrt: bool) -> Result<String> {
    if component == "core" {
        let output = ProcessCommand::new(manager(openwrt))
            .arg("status")
            .output()?;
        if !output.status.success() {
            bail!("core_status_failed");
        }
        let status: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        return Ok(status["current_version"]
            .as_str()
            .unwrap_or("uninstalled")
            .into());
    }
    if openwrt {
        let output = ProcessCommand::new("apk")
            .args(["info", "-v", "candy-client"])
            .output()?;
        if !output.status.success() {
            bail!("runtime_status_failed");
        }
        return String::from_utf8(output.stdout)?
            .lines()
            .find_map(|s| s.strip_prefix("candy-client-"))
            .map(str::to_owned)
            .context("runtime_version_missing");
    }
    Ok(fs::read_to_string("/opt/candy/current/RUNTIME-RELEASE")?
        .trim()
        .into())
}

fn target_key(component: &str, openwrt: bool, arch: &str) -> Result<String> {
    match (component, openwrt, arch) {
        ("core", _, "x86_64" | "aarch64") => Ok(format!("linux_musl_{arch}")),
        ("core", true, "arm") => Ok("linux_musl_armv7".into()),
        ("runtime", false, "x86_64" | "aarch64") => Ok(format!("linux_{arch}")),
        ("runtime", true, "x86_64") => Ok("openwrt_25_12_4_x86_64".into()),
        ("runtime", true, "arm") => Ok("openwrt_25_12_4_arm_cortex_a7_neon_vfpv4".into()),
        _ => bail!("unsupported_upgrade_platform"),
    }
}

fn candidate(
    catalog: &serde_json::Value,
    component: &str,
    openwrt: bool,
    arch: &str,
    key: &str,
) -> Result<(Target, serde_json::Value)> {
    if !token(key) || !matches!(component, "core" | "runtime") {
        bail!("invalid_upgrade_target");
    }
    let release = &catalog[component]["releases"][key];
    let artifact = release["targets"][target_key(component, openwrt, arch)?].clone();
    if artifact.is_null() {
        bail!("target_not_in_signed_catalog");
    }
    let version = release[if component == "runtime" {
        "display_version"
    } else {
        "version"
    }]
    .as_str()
    .context("catalog_version_missing")?;
    if !token(version) {
        bail!("invalid_catalog_version");
    }
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&artifact)?));
    Ok((
        Target {
            component: component.into(),
            current_version: current(component, openwrt)?,
            version: version.into(),
            version_key: key.into(),
            digest,
        },
        artifact,
    ))
}

fn download_artifact(root: &Path, artifact: &serde_json::Value, name: &str) -> Result<PathBuf> {
    let url = artifact["url"].as_str().context("artifact_url_missing")?;
    if !url.starts_with(RELEASE_ROOT) {
        bail!("untrusted_artifact_origin");
    }
    let size = artifact["size"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= MAX_BUNDLE)
        .context("artifact_size_invalid")?;
    let path = root.join(name);
    let client = Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(300))
        .build()?;
    fetch(&client, url, &path, size)?;
    let bytes = read_bounded(&path, MAX_BUNDLE)?;
    if bytes.len() as u64 != size
        || format!("{:x}", Sha256::digest(&bytes)) != artifact["sha256"].as_str().unwrap_or("")
    {
        bail!("artifact_integrity_mismatch");
    }
    Ok(path)
}

fn install(
    root: &Path,
    target: &Target,
    artifact: &serde_json::Value,
    openwrt: bool,
) -> Result<()> {
    if target.component == "core" {
        let bundle = download_artifact(root, artifact, "core.tar.gz")?;
        command(
            manager(openwrt),
            &[
                "install",
                &target.version,
                bundle.to_str().context("path")?,
                artifact["sha256"].as_str().context("digest")?,
            ],
            root,
        )?;
        command(manager(openwrt), &["activate", &target.version], root)?;
    } else if openwrt {
        // The existing OpenWrt manager verifies its catalog and APKs and owns
        // package rollback. Refuse if the freshly checked artifact has changed.
        command("/usr/libexec/candy-update-manager", &["check"], root)?;
        let cache: serde_json::Value = read_bounded_json(
            Path::new("/var/lib/candy/update/catalog.json"),
            4 * 1024 * 1024,
        )?;
        let (checked, _) = candidate(
            &cache,
            "runtime",
            true,
            std::env::consts::ARCH,
            &target.version_key,
        )?;
        if checked.digest != target.digest {
            bail!("catalog_target_changed");
        }
        command(
            "/usr/libexec/candy-update-manager",
            &["install-runtime", &target.version_key],
            root,
        )?;
    } else {
        let bundle = download_artifact(root, &artifact["runtime"], "runtime.tar.gz")?;
        // Only extract the one installer from an authenticated artifact. Its
        // own archive validation and transaction remain authoritative.
        let output = ProcessCommand::new("tar")
            .args([
                "-xOf",
                bundle.to_str().context("path")?,
                "./install/upgrade-candy-server.sh",
            ])
            .output()?;
        if !output.status.success() || output.stdout.len() > 128 * 1024 {
            bail!("runtime_installer_invalid");
        }
        let script = root.join("upgrade.sh");
        atomic_bytes(&script, &output.stdout, 0o700)?;
        command(
            "sh",
            &[
                script.to_str().context("path")?,
                "--bundle-file",
                bundle.to_str().context("path")?,
                "--sha256",
                artifact["runtime"]["sha256"].as_str().context("digest")?,
                "--version",
                &target.version,
            ],
            root,
        )?;
    }
    if current(&target.component, openwrt)? != target.version {
        bail!("installed_version_mismatch");
    }
    Ok(())
}

fn receipt(client: &Client, cloud: &Url, journal: &Journal, state: &str) -> Result<()> {
    client
        .put(endpoint(cloud, "auth/v1/runtime/upgrades")?)
        .json(
            &serde_json::json!({"id":journal.job.id,"state":state,"error_code":journal.error_code}),
        )
        .send()?
        .error_for_status()?;
    Ok(())
}

pub(super) fn run(args: &Args) -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("upgrade_requires_root");
    }
    let openwrt = Path::new("/etc/openwrt_release").exists();
    let root = Path::new(if openwrt {
        "/etc/candy/node-upgrades"
    } else {
        "/var/lib/candy/node-upgrades"
    });
    private_root(root)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(root.join("lock"))?;
    let _lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| e)?;
    let identity_dir = args
        .identity_dir
        .clone()
        .unwrap_or_else(|| args.state_dir.join("identity"));
    let identity: DeviceIdentity = read_bounded_json(
        &identity_dir.join("device-identity-v1.json"),
        MAX_PROFILE_BYTES,
    )?;
    validate_identity(&identity)?;
    let cloud = validate_cloud(&identity.cloud_address)?;
    let client = build_client(
        &identity_dir,
        args.ca_certificate.as_deref(),
        &cloud,
        &resolve_cloud_endpoints(&args.state_dir, &cloud)?,
    )?;
    let journal_path = root.join("receipt.json");
    if journal_path.exists() {
        let mut journal: Journal = read_bounded_json(&journal_path, MAX_PROFILE_BYTES)?;
        if journal.job.device_id != identity.device_id
            || journal.job.device_key_id != identity.device_key_id
        {
            bail!("upgrade_journal_identity_changed");
        }
        if journal.phase == "executing" {
            journal.phase = "failed".into();
            journal.error_code = Some("upgrade_interrupted_verify_required".into());
            atomic_bytes(&journal_path, &serde_json::to_vec(&journal)?, 0o600)?;
        }
        if matches!(journal.phase.as_str(), "succeeded" | "failed") {
            receipt(&client, &cloud, &journal, &journal.phase)?;
            fs::remove_file(&journal_path)?;
            File::open(root)?.sync_all()?;
        }
    }
    let catalog = catalog(root)?;
    let arch = std::env::consts::ARCH;
    let targets = ["runtime", "core"]
        .iter()
        .filter_map(|component| {
            let key = catalog[*component]["latest"].as_str()?;
            candidate(&catalog, component, openwrt, arch, key)
                .ok()
                .map(|(t, _)| t)
        })
        .collect();
    client
        .put(endpoint(&cloud, "auth/v1/runtime/upgrade-inventory")?)
        .json(&Inventory {
            schema_version: 1,
            platform: if openwrt { "openwrt" } else { "linux" },
            architecture: arch.into(),
            targets,
        })
        .send()?
        .error_for_status()?;
    let response = client
        .get(endpoint(&cloud, "auth/v1/runtime/upgrades")?)
        .send()?
        .error_for_status()?;
    let Some(job) =
        serde_json::from_slice::<Option<Job>>(&bounded_response(response, MAX_PROFILE_BYTES)?)?
    else {
        return Ok(());
    };
    if job.device_id != identity.device_id || job.device_key_id != identity.device_key_id {
        bail!("upgrade_identity_mismatch");
    }
    let (target, artifact) = candidate(
        &catalog,
        &job.target.component,
        openwrt,
        arch,
        &job.target.version_key,
    )?;
    let mut journal = Journal {
        job,
        phase: "prepared".into(),
        error_code: None,
    };
    atomic_bytes(&journal_path, &serde_json::to_vec(&journal)?, 0o600)?;
    receipt(&client, &cloud, &journal, "running")?;
    journal.phase = "executing".into();
    atomic_bytes(&journal_path, &serde_json::to_vec(&journal)?, 0o600)?;
    let result = if target != journal.job.target {
        Err(anyhow::anyhow!("catalog_or_installed_version_changed"))
    } else {
        install(root, &target, &artifact, openwrt)
    };
    journal.phase = if result.is_ok() {
        "succeeded"
    } else {
        "failed"
    }
    .into();
    if let Err(error) = result {
        eprintln!(
            "event=node_upgrade_failed id={} detail={}",
            journal.job.id,
            sanitize_log_value(&format!("{error:#}"))
        );
        journal.error_code = Some("upgrade_install_or_health_check_failed".into());
    }
    atomic_bytes(&journal_path, &serde_json::to_vec(&journal)?, 0o600)?;
    receipt(&client, &cloud, &journal, &journal.phase)?;
    fs::remove_file(journal_path)?;
    File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifiers_and_architectures_are_restricted() {
        assert!(token("v0_4_0_r112"));
        for value in ["", "$(id)", "../core", "v1;reboot", "--version x"] {
            assert!(!token(value));
        }
        assert!(target_key("runtime", false, "mips").is_err());
        assert_eq!(
            target_key("core", false, "aarch64").unwrap(),
            "linux_musl_aarch64"
        );
    }
}
