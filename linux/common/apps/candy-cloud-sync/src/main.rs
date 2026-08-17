use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use reqwest::{
    blocking::{Client, Response},
    header::{CONTENT_TYPE, ETAG, IF_MATCH, IF_NONE_MATCH},
    StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

const MAX_PROFILE_BYTES: u64 = 64 * 1024;
const MAX_CONFIGURATION_BYTES: u64 = 3 * 1024 * 1024;
const MAX_ROUTE_ENVELOPE_BYTES: usize = 1024 * 1024;
const CONFIGURATION_MEDIA_TYPE: &str = "application/vnd.candy.runtime-configuration.v1+json";

#[derive(Debug, Parser)]
#[command(
    name = "candy-cloud-sync",
    version,
    about = "Candy Cloud Runtime synchronizer"
)]
struct Args {
    #[arg(long, default_value = "/var/lib/candy/sdwan")]
    state_dir: PathBuf,
    #[arg(long)]
    identity_dir: Option<PathBuf>,
    #[arg(long)]
    ca_certificate: Option<PathBuf>,
    #[arg(long)]
    core: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    SyncOnce,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceIdentity {
    schema_version: u8,
    cloud_address: String,
    organization_id: Uuid,
    tenant_id: Option<Uuid>,
    device_id: Uuid,
    device_key_id: Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProfile {
    organization_id: Uuid,
    organization_name: String,
    tenant_id: Uuid,
    tenant_name: String,
    device_id: Uuid,
    device_key_id: Uuid,
    device_name: String,
    site_id: Option<Uuid>,
    site_name: Option<String>,
    segment_id: Option<Uuid>,
    segment_name: Option<String>,
    attachment_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfiguration {
    schema_version: u8,
    projection_publication_id: Uuid,
    projection_id: Uuid,
    segment_id: Uuid,
    attachment_id: Uuid,
    segment_generation: u64,
    projection_generation: u64,
    projection_content_hash: String,
    route_signing_key_id: String,
    route_signing_public_key: String,
    segment_snapshot: String,
    site_projection: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedControlReport {
    schema_version: u16,
    ok: bool,
    tenant_id: String,
    segment_id: String,
    site_id: String,
    attachment_id: String,
    projection_id: String,
    device_id: String,
    device_key_id: String,
    segment_generation: u64,
    projection_generation: u64,
    projection_content_hash: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyncState {
    schema_version: u8,
    etag: Option<String>,
    configuration_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct SyncResult<'a> {
    schema_version: u8,
    state: &'a str,
    network_ready: bool,
    profile_changed: bool,
    configuration_changed: bool,
    etag: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct LocalSyncStatus<'a> {
    schema_version: u8,
    state: &'a str,
    updated_at: u64,
    error_code: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct ConfigurationStatus<'a> {
    projection_publication_id: Uuid,
    projection_content_hash: &'a str,
    state: &'a str,
    error_code: Option<&'a str>,
}

fn main() {
    let args = Args::parse();
    let state_dir = args.state_dir.clone();
    if let Err(error) = run(args) {
        let error_text = format!("{error:#}");
        let error_code = if error_text.contains("Core") {
            "core_verification_failed"
        } else if error_text.contains("publish") || error_text.contains("atomic") {
            "local_publish_failed"
        } else {
            "cloud_sync_failed"
        };
        let _ = write_local_sync_status(&state_dir, "error", Some(error_code));
        eprintln!("candy-cloud-sync: {error:#}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    match args.command {
        Command::SyncOnce => sync_once(&args),
    }
}

fn sync_once(args: &Args) -> Result<()> {
    ensure_private_directory(&args.state_dir)?;
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
    let client = build_client(&identity_dir, args.ca_certificate.as_deref())?;

    let profile: RuntimeProfile = get_json(
        &client,
        endpoint(&cloud, "auth/v1/runtime/profile")?,
        MAX_PROFILE_BYTES,
    )?;
    validate_profile(&identity, &profile)?;
    let profile_bytes = serde_json::to_vec(&profile)?;
    let profile_path = args.state_dir.join("profile-v1.json");
    let profile_changed = !same_file(&profile_path, &profile_bytes)?;
    if profile_changed {
        atomic_bytes(&profile_path, &profile_bytes, 0o600)?;
    }

    let state_path = args.state_dir.join("sync-state-v1.json");
    let mut state: SyncState = if state_path.exists() {
        read_bounded_json(&state_path, MAX_PROFILE_BYTES)?
    } else {
        SyncState {
            schema_version: 1,
            ..SyncState::default()
        }
    };
    if state.schema_version != 1 {
        bail!("unsupported Cloud synchronization state schema")
    }

    let mut request = client.get(endpoint(&cloud, "auth/v1/runtime/configuration")?);
    if let Some(etag) = state.etag.as_deref() {
        validate_etag(etag)?;
        request = request.header(IF_NONE_MATCH, etag);
    }
    let response = request.send().context("request Runtime configuration")?;
    match response.status() {
        StatusCode::NO_CONTENT => {
            write_local_sync_status(&args.state_dir, "waiting_for_network_configuration", None)?;
            println!(
                "{}",
                serde_json::to_string(&SyncResult {
                    schema_version: 1,
                    state: "waiting_for_network_configuration",
                    network_ready: false,
                    profile_changed,
                    configuration_changed: false,
                    etag: state.etag.as_deref(),
                })?
            );
        }
        StatusCode::NOT_MODIFIED => {
            let etag = required_etag(&response)?;
            if state.etag.as_deref() != Some(etag.as_str()) {
                bail!("Cloud returned 304 with an unexpected ETag")
            }
            write_local_sync_status(&args.state_dir, "configuration_unchanged", None)?;
            println!(
                "{}",
                serde_json::to_string(&SyncResult {
                    schema_version: 1,
                    state: "configuration_unchanged",
                    network_ready: true,
                    profile_changed,
                    configuration_changed: false,
                    etag: state.etag.as_deref(),
                })?
            );
        }
        StatusCode::OK => {
            require_content_type(&response, CONFIGURATION_MEDIA_TYPE)?;
            let etag = required_etag(&response)?;
            let bytes = bounded_response(response, MAX_CONFIGURATION_BYTES)?;
            let configuration: RuntimeConfiguration =
                serde_json::from_slice(&bytes).context("parse Runtime configuration")?;
            validate_configuration(&configuration, &profile)?;
            let segment = decode_envelope(&configuration.segment_snapshot, "segment snapshot")?;
            let projection = decode_envelope(&configuration.site_projection, "site projection")?;
            let digest = configuration_digest(&segment, &projection);
            let expected = etag
                .strip_prefix("\"sha256-")
                .and_then(|value| value.strip_suffix('"'))
                .context("invalid Runtime configuration ETag")?;
            if digest != expected {
                bail!("Runtime configuration body does not match its ETag")
            }
            if let Err(error) = verify_control_with_core(
                &args.state_dir,
                args.core.as_deref(),
                &configuration,
                &identity,
                &profile,
                &segment,
                &projection,
            ) {
                report_configuration_status(
                    &client,
                    &cloud,
                    &configuration,
                    &etag,
                    "rejected",
                    Some("core_verification_failed"),
                )
                .context("report rejected Core verification to Cloud")?;
                return Err(error);
            }
            if let Err(error) = publish_configuration_generation(
                &args.state_dir,
                &digest,
                &segment,
                &projection,
                configuration.route_signing_public_key.as_bytes(),
                &bytes,
            ) {
                report_configuration_status(
                    &client,
                    &cloud,
                    &configuration,
                    &etag,
                    "rejected",
                    Some("local_publish_failed"),
                )
                .context("report rejected local publication to Cloud")?;
                return Err(error);
            }
            state.etag = Some(etag);
            state.configuration_sha256 = Some(digest);
            atomic_json(&state_path, &state, 0o600)?;
            write_local_sync_status(&args.state_dir, "configuration_verified", None)?;
            println!(
                "{}",
                serde_json::to_string(&SyncResult {
                    schema_version: 1,
                    state: "configuration_updated",
                    network_ready: true,
                    profile_changed,
                    configuration_changed: true,
                    etag: state.etag.as_deref(),
                })?
            );
        }
        status => bail!("Cloud Runtime configuration request failed with HTTP {status}"),
    }
    Ok(())
}

fn write_local_sync_status(state_dir: &Path, state: &str, error_code: Option<&str>) -> Result<()> {
    let updated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system clock for synchronization status")?
        .as_secs();
    atomic_json(
        &state_dir.join("cloud-sync-status-v1.json"),
        &LocalSyncStatus {
            schema_version: 1,
            state,
            updated_at,
            error_code,
        },
        0o600,
    )
}

fn report_configuration_status(
    client: &Client,
    cloud: &Url,
    configuration: &RuntimeConfiguration,
    etag: &str,
    state: &str,
    error_code: Option<&str>,
) -> Result<()> {
    let response = client
        .put(endpoint(cloud, "auth/v1/runtime/configuration/status")?)
        .header(IF_MATCH, etag)
        .json(&ConfigurationStatus {
            projection_publication_id: configuration.projection_publication_id,
            projection_content_hash: &configuration.projection_content_hash,
            state,
            error_code,
        })
        .send()
        .context("report Runtime configuration status")?;
    if response.status() != StatusCode::NO_CONTENT {
        bail!(
            "Cloud rejected Runtime configuration status with HTTP {}",
            response.status()
        )
    }
    Ok(())
}

fn verify_control_with_core(
    state_dir: &Path,
    requested_core: Option<&Path>,
    configuration: &RuntimeConfiguration,
    identity: &DeviceIdentity,
    profile: &RuntimeProfile,
    segment: &[u8],
    projection: &[u8],
) -> Result<()> {
    let core = requested_core
        .map(Path::to_path_buf)
        .or_else(|| {
            [
                PathBuf::from("/usr/lib/candy/cores/current/candy-core"),
                PathBuf::from("/opt/candy/cores/current/candy-core"),
            ]
            .into_iter()
            .find(|candidate| candidate.exists())
        })
        .context("Candy Core is not installed; signed SD-WAN configuration was not activated")?;
    let metadata = fs::metadata(&core).context("inspect active Candy Core")?;
    if !metadata.is_file() {
        bail!("active Candy Core is not a regular file")
    }
    let verification = state_dir.join(format!(".verify.{}", Uuid::new_v4()));
    ensure_private_directory(&verification)?;
    let result = (|| {
        let segment_path = verification.join("segment.snapshot");
        let projection_path = verification.join("site.projection");
        atomic_bytes(&segment_path, segment, 0o600)?;
        atomic_bytes(&projection_path, projection, 0o600)?;
        let output = ProcessCommand::new(&core)
            .args(["client", "sdwan", "verify-control", "--segment-snapshot"])
            .arg(&segment_path)
            .arg("--site-projection")
            .arg(&projection_path)
            .arg("--route-signing-public-key")
            .arg(&configuration.route_signing_public_key)
            .arg("--route-signing-key-id")
            .arg(&configuration.route_signing_key_id)
            .output()
            .context("run Candy Core signed-control verification")?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            bail!(
                "Candy Core rejected signed SD-WAN control: {}",
                detail.chars().take(1024).collect::<String>()
            )
        }
        if output.stdout.is_empty() || output.stdout.len() > 64 * 1024 {
            bail!("Candy Core returned an invalid signed-control report")
        }
        let report: VerifiedControlReport = serde_json::from_slice(&output.stdout)
            .context("parse Candy Core verification report")?;
        validate_verified_report(&report, configuration, identity, profile)
    })();
    let cleanup = fs::remove_dir_all(&verification).context("remove Core verification staging");
    result.and(cleanup)
}

fn validate_verified_report(
    report: &VerifiedControlReport,
    configuration: &RuntimeConfiguration,
    identity: &DeviceIdentity,
    profile: &RuntimeProfile,
) -> Result<()> {
    let uuid_hex = |value: Uuid| value.simple().to_string();
    if report.schema_version != 1
        || !report.ok
        || report.tenant_id != uuid_hex(profile.tenant_id)
        || report.segment_id != uuid_hex(configuration.segment_id)
        || profile.site_id.map(uuid_hex).as_deref() != Some(report.site_id.as_str())
        || report.attachment_id != uuid_hex(configuration.attachment_id)
        || report.projection_id != uuid_hex(configuration.projection_id)
        || report.device_id != uuid_hex(identity.device_id)
        || report.device_key_id != uuid_hex(identity.device_key_id)
        || report.segment_generation != configuration.segment_generation
        || report.projection_generation != configuration.projection_generation
        || report.projection_content_hash != configuration.projection_content_hash
    {
        bail!("Candy Core verification report does not match the authenticated Cloud profile")
    }
    Ok(())
}

fn validate_identity(identity: &DeviceIdentity) -> Result<()> {
    if identity.schema_version != 1
        || identity.organization_id.is_nil()
        || identity.device_id.is_nil()
        || identity.device_key_id.is_nil()
    {
        bail!("invalid local Cloud device identity")
    }
    Ok(())
}

fn validate_profile(identity: &DeviceIdentity, profile: &RuntimeProfile) -> Result<()> {
    if profile.organization_id != identity.organization_id
        || profile.device_id != identity.device_id
        || profile.device_key_id != identity.device_key_id
        || identity
            .tenant_id
            .is_some_and(|value| value != profile.tenant_id)
        || profile.organization_name.trim().is_empty()
        || profile.tenant_name.trim().is_empty()
        || profile.device_name.trim().is_empty()
        || profile.organization_name.len() > 200
        || profile.tenant_name.len() > 200
        || profile.device_name.len() > 200
        || profile.site_id.is_some() != profile.site_name.is_some()
        || profile.segment_id.is_some() != profile.segment_name.is_some()
        || profile.attachment_id.is_some() != profile.site_id.is_some()
    {
        bail!("Cloud Runtime profile does not match the local device identity")
    }
    Ok(())
}

fn validate_configuration(value: &RuntimeConfiguration, profile: &RuntimeProfile) -> Result<()> {
    if value.schema_version != 1
        || value.projection_publication_id.is_nil()
        || value.projection_id.is_nil()
        || value.segment_id.is_nil()
        || value.attachment_id.is_nil()
        || value.segment_generation == 0
        || value.projection_generation == 0
        || profile.segment_id != Some(value.segment_id)
        || profile.attachment_id != Some(value.attachment_id)
        || value.route_signing_key_id.is_empty()
        || value.route_signing_key_id.len() > 64
    {
        bail!("Cloud Runtime configuration is not bound to the current profile")
    }
    validate_hex(
        &value.projection_content_hash,
        32,
        "projection content hash",
    )?;
    validate_hex(
        &value.route_signing_public_key,
        32,
        "route signing public key",
    )?;
    Ok(())
}

fn validate_cloud(value: &str) -> Result<Url> {
    let cloud = Url::parse(value).context("parse Cloud address")?;
    if cloud.scheme() != "https"
        || cloud.host_str().is_none()
        || !cloud.username().is_empty()
        || cloud.password().is_some()
        || cloud.query().is_some()
        || cloud.fragment().is_some()
    {
        bail!("Cloud address must be an absolute https:// URL without credentials")
    }
    Ok(cloud)
}

fn endpoint(cloud: &Url, path: &str) -> Result<Url> {
    Url::parse(&format!(
        "{}/{}",
        cloud.as_str().trim_end_matches('/'),
        path
    ))
    .context("construct Cloud Runtime endpoint")
}

fn build_client(identity_dir: &Path, ca_certificate: Option<&Path>) -> Result<Client> {
    let identity_pem = read_bounded(&identity_dir.join("device-mtls.pem"), 512 * 1024)?;
    let identity =
        reqwest::Identity::from_pem(&identity_pem).context("parse device mTLS identity")?;
    let mut builder = Client::builder()
        .identity(identity)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .https_only(true)
        .user_agent(concat!("candy-cloud-sync/", env!("CARGO_PKG_VERSION")));
    if let Some(path) = ca_certificate {
        let certificate = reqwest::Certificate::from_pem(&read_bounded(path, 512 * 1024)?)
            .context("parse Cloud CA certificate")?;
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().context("build Cloud Runtime client")
}

fn get_json<T: DeserializeOwned>(client: &Client, url: Url, maximum: u64) -> Result<T> {
    let response = client
        .get(url)
        .send()
        .context("request Cloud Runtime profile")?;
    if response.status() != StatusCode::OK {
        bail!(
            "Cloud Runtime profile request failed with HTTP {}",
            response.status()
        )
    }
    require_content_type(&response, "application/json")?;
    serde_json::from_slice(&bounded_response(response, maximum)?)
        .context("parse Cloud Runtime profile")
}

fn bounded_response(response: Response, maximum: u64) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|size| size > maximum) {
        bail!("Cloud Runtime response exceeds {maximum} bytes")
    }
    let bytes = response.bytes().context("read Cloud Runtime response")?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        bail!("Cloud Runtime response size is invalid")
    }
    Ok(bytes.to_vec())
}

fn require_content_type(response: &Response, expected: &str) -> Result<()> {
    let value = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if value.split(';').next().map(str::trim) != Some(expected) {
        bail!("Cloud Runtime response has an unexpected media type")
    }
    Ok(())
}

fn required_etag(response: &Response) -> Result<String> {
    let value = response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .context("Cloud Runtime response is missing an ETag")?
        .to_owned();
    validate_etag(&value)?;
    Ok(value)
}

fn validate_etag(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("\"sha256-")
        .and_then(|value| value.strip_suffix('"'))
        .context("invalid Runtime configuration ETag")?;
    validate_hex(digest, 32, "Runtime configuration ETag")
}

fn validate_hex(value: &str, bytes: usize, label: &str) -> Result<()> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be canonical lowercase hexadecimal")
    }
    Ok(())
}

fn decode_envelope(value: &str, label: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("decode {label}"))?;
    if bytes.is_empty() || bytes.len() > MAX_ROUTE_ENVELOPE_BYTES {
        bail!("{label} size is invalid")
    }
    Ok(bytes)
}

fn configuration_digest(segment: &[u8], projection: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"candy/runtime-configuration-v1\0");
    digest.update((segment.len() as u64).to_be_bytes());
    digest.update(segment);
    digest.update((projection.len() as u64).to_be_bytes());
    digest.update(projection);
    format!("{:x}", digest.finalize())
}

fn publish_configuration_generation(
    state_dir: &Path,
    digest: &str,
    segment: &[u8],
    projection: &[u8],
    route_key: &[u8],
    manifest: &[u8],
) -> Result<()> {
    validate_hex(digest, 32, "Runtime configuration digest")?;
    let generations = state_dir.join("generations");
    ensure_private_directory(&generations)?;
    let generation = generations.join(digest);
    if !generation.exists() {
        let staging = generations.join(format!(".{digest}.{}.tmp", Uuid::new_v4()));
        ensure_private_directory(&staging)?;
        let write_result = (|| {
            atomic_bytes(&staging.join("segment.snapshot"), segment, 0o600)?;
            atomic_bytes(&staging.join("site.projection"), projection, 0o600)?;
            atomic_bytes(&staging.join("route-signing-public-key"), route_key, 0o600)?;
            atomic_bytes(&staging.join("configuration-v1.json"), manifest, 0o600)?;
            File::open(&staging)
                .and_then(|directory| directory.sync_all())
                .context("sync staged Runtime configuration")?;
            fs::rename(&staging, &generation)
                .context("publish Runtime configuration generation")?;
            File::open(&generations)
                .and_then(|directory| directory.sync_all())
                .context("sync Runtime generation directory")
        })();
        if write_result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        write_result?;
    } else {
        let metadata = fs::symlink_metadata(&generation)
            .context("inspect existing Runtime configuration generation")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("Runtime configuration generation is not a real directory")
        }
        if read_bounded(
            &generation.join("segment.snapshot"),
            MAX_ROUTE_ENVELOPE_BYTES as u64,
        )? != segment
            || read_bounded(
                &generation.join("site.projection"),
                MAX_ROUTE_ENVELOPE_BYTES as u64,
            )? != projection
            || read_bounded(&generation.join("route-signing-public-key"), 128)? != route_key
            || read_bounded(
                &generation.join("configuration-v1.json"),
                MAX_CONFIGURATION_BYTES,
            )? != manifest
        {
            bail!("immutable Runtime configuration generation has conflicting content")
        }
    }

    let current = state_dir.join("configuration");
    if current.exists() && !fs::symlink_metadata(&current)?.file_type().is_symlink() {
        let legacy = generations.join(format!("legacy-{}", Uuid::new_v4()));
        fs::rename(&current, legacy).context("preserve legacy Runtime configuration")?;
    }
    let next = state_dir.join(format!(".configuration.{}.tmp", Uuid::new_v4()));
    #[cfg(unix)]
    std::os::unix::fs::symlink(Path::new("generations").join(digest), &next)
        .context("stage Runtime configuration pointer")?;
    #[cfg(not(unix))]
    bail!("atomic Runtime generation pointers require a Unix platform");
    if let Err(error) = fs::rename(&next, &current) {
        let _ = fs::remove_file(&next);
        return Err(error).context("activate Runtime configuration generation");
    }
    File::open(state_dir)
        .and_then(|directory| directory.sync_all())
        .context("sync active Runtime configuration pointer")?;
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).context("inspect Runtime state directory")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("Runtime state directory must be a real directory")
        }
    } else {
        fs::create_dir_all(path).context("create Runtime state directory")?;
    }
    set_mode(path, 0o700)?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        bail!("{} is not a bounded regular file", path.display())
    }
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

fn read_bounded_json<T: DeserializeOwned>(path: &Path, maximum: u64) -> Result<T> {
    serde_json::from_slice(&read_bounded(path, maximum)?)
        .with_context(|| format!("parse {}", path.display()))
}

fn same_file(path: &Path, value: &[u8]) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    Ok(read_bounded(path, MAX_CONFIGURATION_BYTES)? == value)
}

fn atomic_json(path: &Path, value: &impl Serialize, mode: u32) -> Result<()> {
    atomic_bytes(path, &serde_json::to_vec(value)?, mode)
}

fn atomic_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    ensure_private_directory(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options
        .open(&temporary)
        .context("create atomic state file")?;
    file.write_all(bytes).context("write atomic state file")?;
    file.sync_all().context("sync atomic state file")?;
    set_file_mode(&file, mode)?;
    drop(file);
    fs::rename(&temporary, path).context("replace atomic state file")?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("sync Runtime state directory")?;
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_file: &File, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_digest_matches_cloud_domain_separation() {
        let segment = [1, 2, 3];
        let projection = [4, 5];
        let digest = configuration_digest(&segment, &projection);
        let mut expected = Sha256::new();
        expected.update(b"candy/runtime-configuration-v1\0");
        expected.update(3_u64.to_be_bytes());
        expected.update(segment);
        expected.update(2_u64.to_be_bytes());
        expected.update(projection);
        assert_eq!(digest, format!("{:x}", expected.finalize()));
    }

    #[test]
    fn profile_must_match_local_device_identity() {
        let identity = DeviceIdentity {
            schema_version: 1,
            cloud_address: "https://cloud.example.test".into(),
            organization_id: Uuid::from_bytes([1; 16]),
            tenant_id: Some(Uuid::from_bytes([2; 16])),
            device_id: Uuid::from_bytes([3; 16]),
            device_key_id: Uuid::from_bytes([4; 16]),
        };
        let mut profile = RuntimeProfile {
            organization_id: identity.organization_id,
            organization_name: "Candy".into(),
            tenant_id: identity.tenant_id.unwrap(),
            tenant_name: "Default".into(),
            device_id: identity.device_id,
            device_key_id: identity.device_key_id,
            device_name: "Router".into(),
            site_id: None,
            site_name: None,
            segment_id: None,
            segment_name: None,
            attachment_id: None,
        };
        validate_profile(&identity, &profile).unwrap();
        profile.device_id = Uuid::new_v4();
        assert!(validate_profile(&identity, &profile).is_err());
    }

    #[test]
    fn core_report_must_bind_every_runtime_identity_dimension() {
        let identity = DeviceIdentity {
            schema_version: 1,
            cloud_address: "https://cloud.example.test".into(),
            organization_id: Uuid::from_bytes([1; 16]),
            tenant_id: Some(Uuid::from_bytes([2; 16])),
            device_id: Uuid::from_bytes([3; 16]),
            device_key_id: Uuid::from_bytes([4; 16]),
        };
        let profile = RuntimeProfile {
            organization_id: identity.organization_id,
            organization_name: "Candy".into(),
            tenant_id: identity.tenant_id.unwrap(),
            tenant_name: "Default".into(),
            device_id: identity.device_id,
            device_key_id: identity.device_key_id,
            device_name: "Router".into(),
            site_id: Some(Uuid::from_bytes([5; 16])),
            site_name: Some("Site A".into()),
            segment_id: Some(Uuid::from_bytes([6; 16])),
            segment_name: Some("Production".into()),
            attachment_id: Some(Uuid::from_bytes([7; 16])),
        };
        let configuration = RuntimeConfiguration {
            schema_version: 1,
            projection_publication_id: Uuid::from_bytes([8; 16]),
            projection_id: Uuid::from_bytes([9; 16]),
            segment_id: profile.segment_id.unwrap(),
            attachment_id: profile.attachment_id.unwrap(),
            segment_generation: 4,
            projection_generation: 5,
            projection_content_hash: "11".repeat(32),
            route_signing_key_id: "route-1".into(),
            route_signing_public_key: "22".repeat(32),
            segment_snapshot: "AA".into(),
            site_projection: "AA".into(),
        };
        let mut report = VerifiedControlReport {
            schema_version: 1,
            ok: true,
            tenant_id: profile.tenant_id.simple().to_string(),
            segment_id: configuration.segment_id.simple().to_string(),
            site_id: profile.site_id.unwrap().simple().to_string(),
            attachment_id: configuration.attachment_id.simple().to_string(),
            projection_id: configuration.projection_id.simple().to_string(),
            device_id: identity.device_id.simple().to_string(),
            device_key_id: identity.device_key_id.simple().to_string(),
            segment_generation: configuration.segment_generation,
            projection_generation: configuration.projection_generation,
            projection_content_hash: configuration.projection_content_hash.clone(),
        };
        validate_verified_report(&report, &configuration, &identity, &profile).unwrap();
        report.device_id = Uuid::new_v4().simple().to_string();
        assert!(validate_verified_report(&report, &configuration, &identity, &profile).is_err());
    }

    #[test]
    fn atomic_state_rejects_symlink_parent_and_replaces_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        atomic_bytes(&path, b"first", 0o600).unwrap();
        atomic_bytes(&path, b"second", 0o600).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"second");
    }

    #[test]
    fn configuration_generation_switch_is_atomic_and_immutable() {
        let directory = tempfile::tempdir().unwrap();
        publish_configuration_generation(
            directory.path(),
            &configuration_digest(b"segment-1", b"projection-1"),
            b"segment-1",
            b"projection-1",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            br#"{"generation":1}"#,
        )
        .unwrap();
        let current = directory.path().join("configuration");
        assert!(fs::symlink_metadata(&current)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read(current.join("segment.snapshot")).unwrap(),
            b"segment-1"
        );

        publish_configuration_generation(
            directory.path(),
            &configuration_digest(b"segment-2", b"projection-2"),
            b"segment-2",
            b"projection-2",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            br#"{"generation":2}"#,
        )
        .unwrap();
        assert_eq!(
            fs::read(current.join("segment.snapshot")).unwrap(),
            b"segment-2"
        );
        assert_eq!(
            fs::read_dir(directory.path().join("generations"))
                .unwrap()
                .count(),
            2
        );
    }
}
