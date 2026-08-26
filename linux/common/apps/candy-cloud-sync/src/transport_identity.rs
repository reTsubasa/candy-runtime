use std::{collections::BTreeMap, fs, net::SocketAddr, path::Path, process::Command};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

const MAX_INSPECT_BYTES: usize = 64 * 1024;
const MAX_PUBLIC_ENDPOINTS: usize = 8;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TransportPreset {
    Current,
    BbrV1,
    Aggressive,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectedEndpoint {
    pub listen: String,
    pub server_cert_sha256: String,
    pub transport_preset: TransportPreset,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectReport {
    schema_version: u8,
    endpoints: Vec<InspectedEndpoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisteredEndpoint {
    pub endpoint: String,
    pub server_cert_sha256: String,
    pub transport_preset: TransportPreset,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransportIdentityRequest {
    pub schema_version: u8,
    pub request_id: String,
    pub endpoints: Vec<RegisteredEndpoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingRegistration {
    digest: String,
    request: TransportIdentityRequest,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityBinding {
    pub device_id: Uuid,
    pub device_key_id: Uuid,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReconcileState {
    schema_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<IdentityBinding>,
    applied_digest: Option<String>,
    pending: Option<PendingRegistration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileOutcome {
    NoExplicitEndpoints,
    Unchanged,
    Applied,
}

pub fn inspect_core(core: &Path, server_config: &Path) -> Result<Vec<InspectedEndpoint>> {
    let output = Command::new(core)
        .args(["server", "inspect-transport-identity", "--config"])
        .arg(server_config)
        .output()
        .with_context(|| format!("inspect Core transport identity: {}", core.display()))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Candy Core transport identity inspection failed: {}",
            detail.chars().take(1024).collect::<String>()
        )
    }
    if output.stdout.is_empty() || output.stdout.len() > MAX_INSPECT_BYTES {
        bail!("Candy Core transport identity report size is invalid")
    }
    let report: InspectReport =
        serde_json::from_slice(&output.stdout).context("parse Core transport identity report")?;
    validate_inspect_report(&report)?;
    Ok(report.endpoints)
}

fn validate_inspect_report(report: &InspectReport) -> Result<()> {
    if report.schema_version != 1
        || report.endpoints.is_empty()
        || report.endpoints.len() > MAX_PUBLIC_ENDPOINTS
    {
        bail!("Core transport identity report has an invalid schema or endpoint count")
    }
    for endpoint in &report.endpoints {
        let listen: SocketAddr = endpoint
            .listen
            .parse()
            .context("Core transport listener is not a SocketAddr")?;
        if listen.port() == 0
            || endpoint.listen != listen.to_string()
            || !canonical_hex(&endpoint.server_cert_sha256, 32)
        {
            bail!("Core transport identity endpoint is not canonical")
        }
    }
    Ok(())
}

pub fn build_registration(
    inspected: &[InspectedEndpoint],
    public_endpoints: &[SocketAddr],
) -> Result<Option<TransportIdentityRequest>> {
    if public_endpoints.is_empty() {
        return Ok(None);
    }
    if public_endpoints.len() > MAX_PUBLIC_ENDPOINTS {
        bail!("explicit public_endpoints exceeds the supported bound")
    }
    let mut by_port = BTreeMap::<u16, (String, TransportPreset)>::new();
    for endpoint in inspected {
        let listen: SocketAddr = endpoint.listen.parse()?;
        let identity = (
            endpoint.server_cert_sha256.clone(),
            endpoint.transport_preset,
        );
        if by_port
            .insert(listen.port(), identity.clone())
            .is_some_and(|existing| existing != identity)
        {
            bail!("Core reports ambiguous transport identities for one listener port")
        }
    }

    let mut requested = public_endpoints.to_vec();
    requested.sort_by_key(SocketAddr::to_string);
    requested.dedup();
    if requested.len() != public_endpoints.len() {
        bail!("explicit public_endpoints contains duplicates")
    }
    let mut endpoints = Vec::with_capacity(requested.len());
    for endpoint in requested {
        if endpoint.port() == 0 || endpoint.ip().is_unspecified() {
            bail!("explicit public endpoint must contain a concrete address and non-zero port")
        }
        let (server_cert_sha256, transport_preset) = by_port
            .get(&endpoint.port())
            .cloned()
            .context("explicit public endpoint port is not a Core listener")?;
        endpoints.push(RegisteredEndpoint {
            endpoint: endpoint.to_string(),
            server_cert_sha256,
            transport_preset,
        });
    }
    let digest = registration_digest(&endpoints)?;
    Ok(Some(TransportIdentityRequest {
        schema_version: 1,
        request_id: format!("transport-v1-{digest}"),
        endpoints,
    }))
}

pub fn reconcile<F>(
    state_path: &Path,
    identity: IdentityBinding,
    desired: Option<TransportIdentityRequest>,
    put: F,
) -> Result<ReconcileOutcome>
where
    F: FnOnce(&TransportIdentityRequest) -> Result<()>,
{
    let Some(desired) = desired else {
        return Ok(ReconcileOutcome::NoExplicitEndpoints);
    };
    validate_request(&desired)?;
    validate_identity(identity)?;
    let digest = registration_digest(&desired.endpoints)?;
    let mut state = load_state(state_path)?.unwrap_or(ReconcileState {
        schema_version: 2,
        identity: Some(identity),
        ..ReconcileState::default()
    });
    validate_state(&state)?;
    if state.schema_version != 2 || state.identity != Some(identity) {
        state = ReconcileState {
            schema_version: 2,
            identity: Some(identity),
            ..ReconcileState::default()
        };
    }
    if state.applied_digest.as_deref() == Some(&digest) && state.pending.is_none() {
        return Ok(ReconcileOutcome::Unchanged);
    }
    if state.pending.as_ref().map(|pending| &pending.digest) != Some(&digest) {
        state.pending = Some(PendingRegistration {
            digest: digest.clone(),
            request: desired.clone(),
        });
        super::atomic_json(state_path, &state, 0o600)?;
    }
    let request = state
        .pending
        .as_ref()
        .context("transport identity reconcile lost its pending request")?
        .request
        .clone();
    put(&request)?;
    state.applied_digest = Some(digest);
    state.pending = None;
    super::atomic_json(state_path, &state, 0o600)?;
    Ok(ReconcileOutcome::Applied)
}

pub fn put_to_cloud(
    client: &reqwest::blocking::Client,
    endpoint: Url,
    request: &TransportIdentityRequest,
) -> Result<()> {
    validate_request(request)?;
    let response = client
        .put(endpoint)
        .json(request)
        .send()
        .context("publish Runtime transport identity")?;
    // Cloud V1 specifies 204. Accept 200 from older Cloud images during a
    // rolling upgrade; the response body is intentionally ignored.
    if !matches!(
        response.status(),
        reqwest::StatusCode::NO_CONTENT | reqwest::StatusCode::OK
    ) {
        bail!(
            "Cloud rejected Runtime transport identity with HTTP {}",
            response.status()
        )
    }
    Ok(())
}

fn load_state(path: &Path) -> Result<Option<ReconcileState>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 64 * 1024
            {
                bail!("transport identity state must be a bounded regular file")
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect transport identity state"),
    }
    let state: ReconcileState = serde_json::from_slice(&fs::read(path)?)?;
    validate_state(&state)?;
    Ok(Some(state))
}

fn validate_state(state: &ReconcileState) -> Result<()> {
    match (state.schema_version, state.identity) {
        (1, None) => {}
        (2, Some(identity)) => validate_identity(identity)?,
        _ => bail!("unsupported transport identity state schema or identity binding"),
    }
    if let Some(digest) = &state.applied_digest {
        if !canonical_hex(digest, 32) {
            bail!("transport identity applied digest is invalid")
        }
    }
    if let Some(pending) = &state.pending {
        validate_request(&pending.request)?;
        if pending.digest != registration_digest(&pending.request.endpoints)? {
            bail!("pending transport identity digest is inconsistent")
        }
    }
    Ok(())
}

fn validate_identity(identity: IdentityBinding) -> Result<()> {
    if identity.device_id.is_nil() || identity.device_key_id.is_nil() {
        bail!("transport identity cache binding is invalid")
    }
    Ok(())
}

fn validate_request(request: &TransportIdentityRequest) -> Result<()> {
    if request.schema_version != 1
        || request.endpoints.is_empty()
        || request.endpoints.len() > MAX_PUBLIC_ENDPOINTS
        || request.request_id
            != format!("transport-v1-{}", registration_digest(&request.endpoints)?)
    {
        bail!("Runtime transport identity request is invalid")
    }
    for endpoint in &request.endpoints {
        let address: SocketAddr = endpoint.endpoint.parse()?;
        if endpoint.endpoint != address.to_string()
            || address.port() == 0
            || address.ip().is_unspecified()
            || !canonical_hex(&endpoint.server_cert_sha256, 32)
        {
            bail!("Runtime transport identity endpoint is invalid")
        }
    }
    Ok(())
}

fn registration_digest(endpoints: &[RegisteredEndpoint]) -> Result<String> {
    if endpoints.is_empty() || endpoints.len() > MAX_PUBLIC_ENDPOINTS {
        bail!("transport identity endpoint count is invalid")
    }
    let bytes = serde_json::to_vec(endpoints)?;
    let mut digest = Sha256::new();
    digest.update(b"candy/runtime-transport-identity-v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

fn canonical_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    fn inspected() -> Vec<InspectedEndpoint> {
        vec![InspectedEndpoint {
            listen: "0.0.0.0:4433".into(),
            server_cert_sha256: "ab".repeat(32),
            transport_preset: TransportPreset::Current,
        }]
    }

    fn identity(seed: u8) -> IdentityBinding {
        IdentityBinding {
            device_id: Uuid::from_bytes([seed; 16]),
            device_key_id: Uuid::from_bytes([seed.saturating_add(1); 16]),
        }
    }

    #[test]
    fn explicit_endpoint_replaces_only_listener_address() {
        let request = build_registration(&inspected(), &["203.0.113.7:4433".parse().unwrap()])
            .unwrap()
            .unwrap();
        assert_eq!(request.endpoints[0].endpoint, "203.0.113.7:4433");
        assert_eq!(request.endpoints[0].server_cert_sha256, "ab".repeat(32));
        assert_eq!(
            request.endpoints[0].transport_preset,
            TransportPreset::Current
        );
        assert!(build_registration(&inspected(), &["203.0.113.7:8443".parse().unwrap()]).is_err());
    }

    #[test]
    fn absent_explicit_endpoint_never_withdraws_or_guesses() {
        assert!(build_registration(&inspected(), &[]).unwrap().is_none());
        let root = tempdir().unwrap();
        assert_eq!(
            reconcile(
                &root.path().join("state.json"),
                identity(1),
                None,
                |_| unreachable!(),
            )
            .unwrap(),
            ReconcileOutcome::NoExplicitEndpoints
        );
    }

    #[test]
    fn lost_response_reuses_persisted_request_and_keeps_last_good() {
        let root = tempdir().unwrap();
        let path = root.path().join("state.json");
        let desired =
            build_registration(&inspected(), &["203.0.113.7:4433".parse().unwrap()]).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let first_seen = Arc::clone(&seen);
        assert!(reconcile(&path, identity(1), desired.clone(), |request| {
            first_seen.lock().unwrap().push(request.request_id.clone());
            bail!("response lost")
        })
        .is_err());
        let second_seen = Arc::clone(&seen);
        assert_eq!(
            reconcile(&path, identity(1), desired, |request| {
                second_seen.lock().unwrap().push(request.request_id.clone());
                Ok(())
            })
            .unwrap(),
            ReconcileOutcome::Applied
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0], seen[1]);
    }

    #[test]
    fn re_enrollment_republishes_unchanged_endpoints_for_the_new_identity() {
        let root = tempdir().unwrap();
        let path = root.path().join("state.json");
        let desired =
            build_registration(&inspected(), &["203.0.113.7:4433".parse().unwrap()]).unwrap();
        assert_eq!(
            reconcile(&path, identity(1), desired.clone(), |_| Ok(())).unwrap(),
            ReconcileOutcome::Applied
        );
        assert_eq!(
            reconcile(&path, identity(1), desired.clone(), |_| unreachable!()).unwrap(),
            ReconcileOutcome::Unchanged
        );
        assert_eq!(
            reconcile(&path, identity(3), desired, |_| Ok(())).unwrap(),
            ReconcileOutcome::Applied
        );

        let state: ReconcileState = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(state.schema_version, 2);
        assert_eq!(state.identity, Some(identity(3)));
    }

    #[test]
    fn legacy_unbound_cache_is_republished_and_upgraded() {
        let root = tempdir().unwrap();
        let path = root.path().join("state.json");
        let desired = build_registration(&inspected(), &["203.0.113.7:4433".parse().unwrap()])
            .unwrap()
            .unwrap();
        super::super::atomic_json(
            &path,
            &ReconcileState {
                schema_version: 1,
                applied_digest: Some(registration_digest(&desired.endpoints).unwrap()),
                ..ReconcileState::default()
            },
            0o600,
        )
        .unwrap();

        assert_eq!(
            reconcile(&path, identity(1), Some(desired), |_| Ok(())).unwrap(),
            ReconcileOutcome::Applied
        );
    }

    #[test]
    fn same_port_with_different_core_identity_is_rejected() {
        let mut endpoints = inspected();
        endpoints.push(InspectedEndpoint {
            listen: "[::]:4433".into(),
            server_cert_sha256: "cd".repeat(32),
            transport_preset: TransportPreset::Current,
        });
        assert!(build_registration(&endpoints, &["203.0.113.7:4433".parse().unwrap()]).is_err());
    }
}
