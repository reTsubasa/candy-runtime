use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use clap::Parser;
use ed25519_dalek::{pkcs8::EncodePrivateKey, Signer, SigningKey};
use rand::rngs::OsRng;
use reqwest::{blocking::Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

const TRANSCRIPT_DOMAIN: &[u8] = b"candy/device-enrollment/v1";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "candy-cloud-enroll",
    about = "Candy Cloud device enrollment client"
)]
struct Args {
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    bootstrap_file: Option<PathBuf>,
    #[arg(long, default_value = "LINUX")]
    expected_platform: String,
    #[arg(long)]
    expected_architecture: Option<String>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    ca_certificate: Option<PathBuf>,
    #[arg(long, default_value_t = 15)]
    connect_timeout_seconds: u64,
    #[arg(long, default_value_t = 45)]
    request_timeout_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentState {
    schema_version: u8,
    cloud_address: String,
    enrollment_instance_id: String,
    display_name: String,
    #[serde(default)]
    tenant_id: Option<Uuid>,
    #[serde(default)]
    site_id: Option<Uuid>,
    challenge_request_id: String,
    completion_request_id: String,
    root_public_key: String,
    operational_public_key: String,
    metadata_hash: String,
    attestation_hash: String,
    challenge: Option<ChallengeState>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeState {
    challenge_id: Uuid,
    organization_id: Uuid,
    server_nonce: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct ChallengeRequest<'a> {
    activation_credential: &'a str,
    request_id: &'a str,
    enrollment_instance_id: &'a str,
    display_name: &'a str,
    root_public_key: &'a str,
    operational_public_key: &'a str,
    metadata_hash: &'a str,
    attestation_hash: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapDocument {
    schema_version: u8,
    cloud_address: String,
    bootstrap_code: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct BootstrapExchangeRequest<'a> {
    bootstrap_code: &'a str,
    installation_instance_id: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapManifest {
    schema_version: u8,
    activation_id: Uuid,
    tenant_id: Uuid,
    site_id: Uuid,
    display_name: String,
    platform: String,
    architecture: String,
    enrollment_endpoint: String,
    enrollment_authorization: String,
    signing_key_id: String,
    expires_at: String,
    replayed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeResponse {
    challenge_id: Uuid,
    organization_id: Uuid,
    server_nonce: String,
    expires_at: String,
    replayed: bool,
}

#[derive(Debug, Serialize)]
struct CompleteRequest<'a> {
    challenge_id: Uuid,
    request_id: &'a str,
    operational_proof: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteResponse {
    device_id: Uuid,
    device_key_id: Uuid,
    certificate_der: String,
    certificate_chain_pem: String,
    not_after: String,
    replayed: bool,
}

#[derive(Debug, Serialize)]
struct DeviceIdentity<'a> {
    schema_version: u8,
    cloud_address: &'a str,
    organization_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    site_id: Option<Uuid>,
    display_name: &'a str,
    device_id: Uuid,
    device_key_id: Uuid,
    not_after: &'a str,
}

#[derive(Debug, Serialize)]
struct EnrollmentResult<'a> {
    schema_version: u8,
    state: &'static str,
    cloud_address: &'a str,
    organization_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    site_id: Option<Uuid>,
    display_name: &'a str,
    device_id: Uuid,
    device_key_id: Uuid,
    not_after: &'a str,
    challenge_replayed: bool,
    completion_replayed: bool,
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("candy-cloud-enroll: {error:#}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    let bootstrap_path = args
        .bootstrap_file
        .as_deref()
        .context("--bootstrap-file is required")?;
    let bootstrap = read_bootstrap_document(bootstrap_path)?;
    let cloud = Url::parse(&bootstrap.cloud_address).context("parse bootstrap Cloud address")?;
    validate_cloud(&cloud)?;
    ensure_state_dir(&args.state_dir)?;
    let state_path = args.state_dir.join("enrollment-v1.json");
    let installation_instance_path = args.state_dir.join("installation-instance-id");
    let root_key_path = args.state_dir.join("root-key.pem");
    let operational_key_path = args.state_dir.join("operational-key.pem");
    if !state_path.exists() && args.state_dir.join("device-identity-v1.json").exists() {
        bail!("this node is already registered; remove the existing identity only through candy leave")
    }
    let mut state = if state_path.exists() {
        let existing: EnrollmentState = read_bounded_json(&state_path, 64 * 1024)?;
        persist_installation_instance_id(
            &installation_instance_path,
            &existing.enrollment_instance_id,
        )?;
        if existing.cloud_address != cloud.as_str().trim_end_matches('/') {
            bail!("an enrollment transaction for another Cloud is already pending; leave it before joining a different Cloud")
        }
        existing
    } else {
        let display_name = args
            .display_name
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(default_display_name);
        validate_display_name(&display_name)?;
        let root_key = SigningKey::generate(&mut OsRng);
        let operational_key = SigningKey::generate(&mut OsRng);
        write_private_key(&root_key_path, &root_key)?;
        write_private_key(&operational_key_path, &operational_key)?;
        let enrollment_instance_id =
            load_or_create_installation_instance_id(&installation_instance_path)?;
        let root_public_key = url_encode(root_key.verifying_key().to_bytes());
        let operational_public_key = url_encode(operational_key.verifying_key().to_bytes());
        let metadata_hash = url_encode(hash_fields(&[
            b"candy/device-enrollment-metadata/v1",
            enrollment_instance_id.as_bytes(),
            display_name.as_bytes(),
        ]));
        let attestation_hash = url_encode(hash_fields(&[
            b"candy/device-software-attestation/unavailable/v1",
            enrollment_instance_id.as_bytes(),
        ]));
        let created = EnrollmentState {
            schema_version: 1,
            cloud_address: cloud.as_str().trim_end_matches('/').to_owned(),
            enrollment_instance_id,
            display_name,
            tenant_id: None,
            site_id: None,
            challenge_request_id: format!("challenge-{}", Uuid::new_v4()),
            completion_request_id: format!("complete-{}", Uuid::new_v4()),
            root_public_key,
            operational_public_key,
            metadata_hash,
            attestation_hash,
            challenge: None,
        };
        atomic_json(&state_path, &created, 0o600)?;
        created
    };

    let operational_key = read_private_key(&operational_key_path)?;
    let root_key = read_private_key(&root_key_path).context("read root private key")?;
    if url_encode(root_key.verifying_key().to_bytes()) != state.root_public_key {
        bail!("persisted root key does not match the pending enrollment transaction")
    }
    if url_encode(operational_key.verifying_key().to_bytes()) != state.operational_public_key {
        bail!("persisted operational key does not match the pending enrollment transaction")
    }
    validate_installation_instance_id(&state.enrollment_instance_id)?;
    let client = build_client(&args)?;
    let mut challenge_replayed = false;
    if state.challenge.is_none() {
        let manifest: BootstrapManifest = post_json(
            &client,
            endpoint(&cloud, "auth/v1/bootstrap/exchange")?,
            &BootstrapExchangeRequest {
                bootstrap_code: &bootstrap.bootstrap_code,
                installation_instance_id: &state.enrollment_instance_id,
            },
            &[StatusCode::OK],
        )?;
        validate_bootstrap_manifest(
            &manifest,
            &args.expected_platform,
            args.expected_architecture.as_deref(),
        )?;
        state.display_name = manifest.display_name;
        state.tenant_id = Some(manifest.tenant_id);
        state.site_id = Some(manifest.site_id);
        state.metadata_hash = url_encode(hash_fields(&[
            b"candy/device-enrollment-metadata/v1",
            state.enrollment_instance_id.as_bytes(),
            state.display_name.as_bytes(),
        ]));
        atomic_json(&state_path, &state, 0o600)?;
        let response: ChallengeResponse = post_json(
            &client,
            bootstrap_endpoint(&cloud, &manifest.enrollment_endpoint)?,
            &ChallengeRequest {
                activation_credential: &manifest.enrollment_authorization,
                request_id: &state.challenge_request_id,
                enrollment_instance_id: &state.enrollment_instance_id,
                display_name: &state.display_name,
                root_public_key: &state.root_public_key,
                operational_public_key: &state.operational_public_key,
                metadata_hash: &state.metadata_hash,
                attestation_hash: &state.attestation_hash,
            },
            &[StatusCode::OK, StatusCode::CREATED],
        )?;
        validate_base64url(&response.server_nonce, 32, "server nonce")?;
        challenge_replayed = response.replayed;
        state.challenge = Some(ChallengeState {
            challenge_id: response.challenge_id,
            organization_id: response.organization_id,
            server_nonce: response.server_nonce,
            expires_at: response.expires_at,
        });
        atomic_json(&state_path, &state, 0o600)?;
    }
    let challenge = state
        .challenge
        .as_ref()
        .context("missing enrollment challenge")?;
    let transcript = encode_transcript(&state, challenge)?;
    let proof = url_encode(operational_key.sign(&transcript).to_bytes());
    let completed: CompleteResponse = post_json(
        &client,
        endpoint(&cloud, "auth/v1/enrollment/complete")?,
        &CompleteRequest {
            challenge_id: challenge.challenge_id,
            request_id: &state.completion_request_id,
            operational_proof: proof,
        },
        &[StatusCode::OK],
    )?;
    let certificate_der = general_purpose::STANDARD
        .decode(&completed.certificate_der)
        .context("Cloud returned invalid certificate DER encoding")?;
    if certificate_der.is_empty() || certificate_der.len() > MAX_RESPONSE_BYTES as usize {
        bail!("Cloud returned an invalid device certificate")
    }
    validate_pem_chain(&completed.certificate_chain_pem)?;
    validate_device_certificate(
        &certificate_der,
        &operational_key.verifying_key().to_bytes(),
        completed.device_id,
        completed.device_key_id,
    )?;
    let leaf_pem = pem_certificate(&certificate_der);
    atomic_bytes(
        &args.state_dir.join("device-cert.der"),
        &certificate_der,
        0o600,
    )?;
    atomic_bytes(
        &args.state_dir.join("device-cert.pem"),
        leaf_pem.as_bytes(),
        0o600,
    )?;
    atomic_bytes(
        &args.state_dir.join("device-chain.pem"),
        completed.certificate_chain_pem.as_bytes(),
        0o600,
    )?;
    let operational_key_pem =
        fs::read(&operational_key_path).context("read operational key for mTLS identity")?;
    let mut mtls_identity = Vec::new();
    mtls_identity.extend_from_slice(leaf_pem.as_bytes());
    mtls_identity.extend_from_slice(completed.certificate_chain_pem.as_bytes());
    if !completed.certificate_chain_pem.ends_with('\n') {
        mtls_identity.push(b'\n');
    }
    mtls_identity.extend_from_slice(&operational_key_pem);
    atomic_bytes(
        &args.state_dir.join("device-mtls.pem"),
        &mtls_identity,
        0o600,
    )?;
    let identity = DeviceIdentity {
        schema_version: 1,
        cloud_address: &state.cloud_address,
        organization_id: challenge.organization_id,
        tenant_id: state.tenant_id,
        site_id: state.site_id,
        display_name: &state.display_name,
        device_id: completed.device_id,
        device_key_id: completed.device_key_id,
        not_after: &completed.not_after,
    };
    atomic_json(
        &args.state_dir.join("device-identity-v1.json"),
        &identity,
        0o600,
    )?;
    fs::remove_file(&state_path).context("remove completed enrollment transaction")?;
    fs::remove_file(bootstrap_path).context("remove consumed bootstrap file")?;
    println!(
        "{}",
        serde_json::to_string(&EnrollmentResult {
            schema_version: 1,
            state: "registered",
            cloud_address: &state.cloud_address,
            organization_id: challenge.organization_id,
            tenant_id: state.tenant_id,
            site_id: state.site_id,
            display_name: &state.display_name,
            device_id: completed.device_id,
            device_key_id: completed.device_key_id,
            not_after: &completed.not_after,
            challenge_replayed,
            completion_replayed: completed.replayed,
        })?
    );
    Ok(())
}

fn validate_cloud(cloud: &Url) -> Result<()> {
    if cloud.scheme() != "https" || cloud.host_str().is_none() {
        bail!("Cloud address must be an absolute https:// URL")
    }
    if !cloud.username().is_empty() || cloud.password().is_some() {
        bail!("Cloud address must not contain user information")
    }
    if cloud.query().is_some() || cloud.fragment().is_some() {
        bail!("Cloud address must not contain a query or fragment")
    }
    Ok(())
}

fn endpoint(cloud: &Url, path: &str) -> Result<Url> {
    Url::parse(&format!(
        "{}/{}",
        cloud.as_str().trim_end_matches('/'),
        path
    ))
    .context("construct Cloud enrollment endpoint")
}

fn bootstrap_endpoint(cloud: &Url, path: &str) -> Result<Url> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains(['?', '#']) {
        bail!("Cloud returned an invalid enrollment endpoint")
    }
    endpoint(cloud, path.trim_start_matches('/'))
}

fn read_bootstrap_document(path: &Path) -> Result<BootstrapDocument> {
    let metadata = fs::symlink_metadata(path).context("inspect bootstrap file")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > 16 * 1024
    {
        bail!("bootstrap file must be a non-empty regular file of at most 16384 bytes")
    }
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0 {
        bail!("bootstrap file must not be accessible by group or other users")
    }
    let document: BootstrapDocument = read_bounded_json(path, 16 * 1024)?;
    if document.schema_version != 1 {
        bail!("unsupported bootstrap document schema")
    }
    let cloud = Url::parse(&document.cloud_address).context("parse bootstrap Cloud address")?;
    validate_cloud(&cloud)?;
    validate_base64url(&document.bootstrap_code, 32, "bootstrap code")?;
    if document.expires_at.is_empty() || document.expires_at.len() > 64 {
        bail!("bootstrap expiration is invalid")
    }
    validate_future_expiration(&document.expires_at, "bootstrap file")?;
    Ok(document)
}

fn validate_bootstrap_manifest(
    manifest: &BootstrapManifest,
    expected_platform: &str,
    expected_architecture: Option<&str>,
) -> Result<()> {
    if manifest.schema_version != 1
        || manifest.activation_id.is_nil()
        || manifest.tenant_id.is_nil()
        || manifest.site_id.is_nil()
        || !matches!(expected_platform, "LINUX" | "OPEN_WRT")
        || manifest.platform != expected_platform
        || manifest.architecture.is_empty()
        || manifest.architecture.len() > 80
        || manifest.signing_key_id.is_empty()
        || manifest.signing_key_id.len() > 64
        || manifest.expires_at.is_empty()
    {
        bail!("Cloud returned an invalid bootstrap manifest")
    }
    if expected_architecture.is_some_and(|expected| manifest.architecture != expected) {
        bail!("bootstrap file was created for a different processor architecture")
    }
    validate_display_name(&manifest.display_name)?;
    validate_base64url(
        &manifest.enrollment_authorization,
        32,
        "enrollment authorization",
    )?;
    validate_future_expiration(&manifest.expires_at, "bootstrap authorization")?;
    let _ = manifest.replayed;
    Ok(())
}

fn validate_future_expiration(value: &str, subject: &str) -> Result<()> {
    let expires_at = DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{subject} expiration is not RFC 3339"))?
        .with_timezone(&Utc);
    if expires_at <= Utc::now() {
        bail!("{subject} has expired")
    }
    Ok(())
}

fn validate_installation_instance_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 120
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        bail!("persisted installation instance ID is invalid")
    }
    Ok(())
}

fn load_or_create_installation_instance_id(path: &Path) -> Result<String> {
    if path.exists() {
        let value = fs::read_to_string(path)
            .context("read persistent installation instance ID")?
            .trim()
            .to_owned();
        validate_installation_instance_id(&value)?;
        return Ok(value);
    }
    let value = format!("candy-{}", Uuid::new_v4());
    atomic_bytes(path, format!("{value}\n").as_bytes(), 0o600)?;
    Ok(value)
}

fn persist_installation_instance_id(path: &Path, expected: &str) -> Result<()> {
    validate_installation_instance_id(expected)?;
    if path.exists() {
        let persisted = load_or_create_installation_instance_id(path)?;
        if persisted != expected {
            bail!("persistent installation instance ID does not match the pending enrollment transaction")
        }
        return Ok(());
    }
    atomic_bytes(path, format!("{expected}\n").as_bytes(), 0o600)
}

fn ensure_state_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("enrollment state path has no parent")?;
    let parent_metadata =
        fs::symlink_metadata(parent).context("inspect Runtime state directory")?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("Runtime state directory must be a real directory")
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("enrollment state path must be a real directory")
        }
    } else {
        fs::create_dir_all(path).context("create enrollment state directory")?;
    }
    set_mode(path, 0o700)?;
    set_path_owner(path, &parent_metadata)
}

fn validate_display_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 200 || value.chars().any(char::is_control) {
        bail!("device display name must be 1 to 200 printable characters")
    }
    Ok(())
}

fn default_display_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "Candy Linux node".to_owned())
}

fn build_client(args: &Args) -> Result<Client> {
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_secs(args.connect_timeout_seconds))
        .timeout(Duration::from_secs(args.request_timeout_seconds))
        .https_only(true)
        .user_agent(concat!("candy-runtime/", env!("CARGO_PKG_VERSION")));
    if let Some(path) = &args.ca_certificate {
        let pem = fs::read(path).context("read Cloud CA certificate")?;
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&pem).context("parse Cloud CA certificate")?,
        );
    }
    builder
        .build()
        .context("build Cloud enrollment HTTP client")
}

fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
    client: &Client,
    url: Url,
    body: &T,
    accepted: &[StatusCode],
) -> Result<R> {
    let response = client
        .post(url.clone())
        .json(body)
        .send()
        .with_context(|| format!("Cloud enrollment request to {} failed", url.path()))?;
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        bail!("Cloud enrollment response exceeded its size limit")
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read Cloud enrollment response")?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        bail!("Cloud enrollment response exceeded its size limit")
    }
    if !accepted.contains(&status) {
        let code = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("code")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "unexpected_response".to_owned());
        bail!(
            "Cloud enrollment endpoint {} returned HTTP {} ({code})",
            url.path(),
            status.as_u16()
        )
    }
    serde_json::from_slice(&bytes).context("decode Cloud enrollment response")
}

fn encode_transcript(state: &EnrollmentState, challenge: &ChallengeState) -> Result<Vec<u8>> {
    let nonce = decode_fixed(&challenge.server_nonce, 32, "server nonce")?;
    let root = decode_fixed(&state.root_public_key, 32, "root public key")?;
    let operational = decode_fixed(&state.operational_public_key, 32, "operational public key")?;
    let metadata = decode_fixed(&state.metadata_hash, 32, "metadata hash")?;
    let attestation = decode_fixed(&state.attestation_hash, 32, "attestation hash")?;
    let fields: [&[u8]; 8] = [
        TRANSCRIPT_DOMAIN,
        challenge.challenge_id.as_bytes(),
        &nonce,
        &root,
        &operational,
        challenge.organization_id.as_bytes(),
        &metadata,
        &attestation,
    ];
    let mut result = Vec::with_capacity(256);
    for field in fields {
        let length = u16::try_from(field.len()).context("enrollment transcript field too large")?;
        result.extend_from_slice(&length.to_be_bytes());
        result.extend_from_slice(field);
    }
    Ok(result)
}

fn decode_fixed(value: &str, length: usize, name: &str) -> Result<Vec<u8>> {
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("invalid {name} encoding"))?;
    if decoded.len() != length {
        bail!("{name} must decode to exactly {length} bytes")
    }
    Ok(decoded)
}

fn validate_base64url(value: &str, length: usize, name: &str) -> Result<()> {
    if value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("{name} must use unpadded base64url")
    }
    decode_fixed(value, length, name).map(|_| ())
}

fn hash_fields(fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

fn url_encode(value: impl AsRef<[u8]>) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(value)
}

fn write_private_key(path: &Path, key: &SigningKey) -> Result<()> {
    let pem = key
        .to_pkcs8_pem(Default::default())
        .context("encode device private key")?;
    atomic_bytes(path, pem.as_bytes(), 0o600)
}

fn read_private_key(path: &Path) -> Result<SigningKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let pem = fs::read_to_string(path).context("read operational private key")?;
    SigningKey::from_pkcs8_pem(&pem).context("decode operational private key")
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(path: &Path, max: u64) -> Result<T> {
    let metadata = fs::symlink_metadata(path).context("inspect enrollment state")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max
    {
        bail!("enrollment state file is invalid")
    }
    serde_json::from_slice(&fs::read(path).context("read enrollment state")?)
        .context("parse enrollment state")
}

fn atomic_json(path: &Path, value: &impl Serialize, mode: u32) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).context("encode enrollment state")?;
    bytes.push(b'\n');
    atomic_bytes(path, &bytes, mode)
}

fn atomic_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent).context("inspect state directory")?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("state directory must be a real directory")
    }
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().unwrap().to_string_lossy(),
        Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(&temporary)
        .context("create temporary state file")?;
    set_file_mode(&file, mode)?;
    set_file_owner(&file, &parent_metadata)?;
    file.write_all(bytes)
        .context("write temporary state file")?;
    file.sync_all().context("sync temporary state file")?;
    drop(file);
    fs::rename(&temporary, path).context("atomically replace state file")?;
    fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .context("sync state directory")?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .context("set state directory permissions")
}

#[cfg(unix)]
fn set_file_mode(file: &fs::File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .context("set state file permissions")
}

#[cfg(unix)]
fn set_file_owner(file: &fs::File, parent: &fs::Metadata) -> Result<()> {
    use nix::unistd::{fchown, getegid, geteuid, Gid, Uid};
    use std::os::fd::AsRawFd;
    if parent.uid() == geteuid().as_raw() && parent.gid() == getegid().as_raw() {
        return Ok(());
    }
    fchown(
        file.as_raw_fd(),
        Some(Uid::from_raw(parent.uid())),
        Some(Gid::from_raw(parent.gid())),
    )
    .context("set state file ownership")
}

#[cfg(unix)]
fn set_path_owner(path: &Path, parent: &fs::Metadata) -> Result<()> {
    use nix::unistd::{chown, getegid, geteuid, Gid, Uid};
    if parent.uid() == geteuid().as_raw() && parent.gid() == getegid().as_raw() {
        return Ok(());
    }
    chown(
        path,
        Some(Uid::from_raw(parent.uid())),
        Some(Gid::from_raw(parent.gid())),
    )
    .context("set enrollment directory ownership")
}

fn validate_pem_chain(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_RESPONSE_BYTES as usize
        || !value.contains("-----BEGIN CERTIFICATE-----")
        || !value.contains("-----END CERTIFICATE-----")
    {
        bail!("Cloud returned an invalid certificate chain")
    }
    Ok(())
}

fn validate_device_certificate(
    der: &[u8],
    operational_public_key: &[u8; 32],
    device_id: Uuid,
    device_key_id: Uuid,
) -> Result<()> {
    let (remaining, certificate) =
        parse_x509_certificate(der).context("parse Cloud device certificate")?;
    if !remaining.is_empty()
        || certificate.public_key().subject_public_key.data.as_ref() != operational_public_key
    {
        bail!("Cloud device certificate is not bound to the local operational key")
    }
    if !certificate.validity().is_valid() {
        bail!("Cloud returned a device certificate outside its validity period")
    }
    let san = certificate
        .subject_alternative_name()
        .context("read Cloud device certificate SAN")?
        .context("Cloud device certificate has no SAN")?;
    let mut has_device = false;
    let mut has_key = false;
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            has_device |= *uri == format!("candy:device:{device_id}");
            has_key |= *uri == format!("candy:device-key:{device_key_id}");
        }
    }
    if !has_device || !has_key {
        bail!("Cloud device certificate identity does not match the enrollment response")
    }
    Ok(())
}

fn pem_certificate(der: &[u8]) -> String {
    let encoded = general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is UTF-8"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment_state() -> EnrollmentState {
        EnrollmentState {
            schema_version: 1,
            cloud_address: "https://cloud.example.test".into(),
            enrollment_instance_id: "linux-test".into(),
            display_name: "test node".into(),
            tenant_id: Some(Uuid::from_bytes([2; 16])),
            site_id: Some(Uuid::from_bytes([3; 16])),
            challenge_request_id: "challenge-test".into(),
            completion_request_id: "complete-test".into(),
            root_public_key: url_encode([8; 32]),
            operational_public_key: url_encode([7; 32]),
            metadata_hash: url_encode([9; 32]),
            attestation_hash: url_encode([10; 32]),
            challenge: None,
        }
    }

    #[test]
    fn transcript_matches_cloud_length_prefixed_contract() {
        let state = enrollment_state();
        let challenge = ChallengeState {
            challenge_id: Uuid::from_bytes([1; 16]),
            organization_id: Uuid::from_bytes([2; 16]),
            server_nonce: url_encode([3; 32]),
            expires_at: "2030-01-01T00:00:00Z".into(),
        };
        let encoded = encode_transcript(&state, &challenge).unwrap();
        let fields: [&[u8]; 8] = [
            TRANSCRIPT_DOMAIN,
            challenge.challenge_id.as_bytes(),
            &[3; 32],
            &[8; 32],
            &[7; 32],
            challenge.organization_id.as_bytes(),
            &[9; 32],
            &[10; 32],
        ];
        let mut expected = Vec::new();
        for field in fields {
            expected.extend_from_slice(&(field.len() as u16).to_be_bytes());
            expected.extend_from_slice(field);
        }
        assert_eq!(encoded, expected);
    }

    #[test]
    fn pending_state_never_contains_activation_credential() {
        let serialized = serde_json::to_string(&enrollment_state()).unwrap();
        assert!(!serialized.contains("activation"));
        assert!(!serialized.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn device_identity_retains_cloud_profile_scope() {
        let tenant_id = Uuid::from_bytes([2; 16]);
        let site_id = Uuid::from_bytes([3; 16]);
        let identity = DeviceIdentity {
            schema_version: 1,
            cloud_address: "https://cloud.example.test",
            organization_id: Uuid::from_bytes([1; 16]),
            tenant_id: Some(tenant_id),
            site_id: Some(site_id),
            display_name: "branch router",
            device_id: Uuid::from_bytes([4; 16]),
            device_key_id: Uuid::from_bytes([5; 16]),
            not_after: "2030-01-01T00:00:00Z",
        };
        let serialized = serde_json::to_value(identity).unwrap();
        assert_eq!(serialized["tenant_id"], tenant_id.to_string());
        assert_eq!(serialized["site_id"], site_id.to_string());
        assert_eq!(serialized["display_name"], "branch router");
    }

    #[test]
    fn cloud_address_rejects_non_https_and_userinfo() {
        assert!(validate_cloud(&Url::parse("http://cloud.example.test").unwrap()).is_err());
        assert!(validate_cloud(&Url::parse("https://user@cloud.example.test").unwrap()).is_err());
        assert!(validate_cloud(&Url::parse("https://cloud.example.test").unwrap()).is_ok());
    }

    fn bootstrap_manifest(platform: &str, architecture: &str) -> BootstrapManifest {
        BootstrapManifest {
            schema_version: 1,
            activation_id: Uuid::from_bytes([1; 16]),
            tenant_id: Uuid::from_bytes([2; 16]),
            site_id: Uuid::from_bytes([3; 16]),
            display_name: "test node".into(),
            platform: platform.into(),
            architecture: architecture.into(),
            enrollment_endpoint: "/auth/v1/enrollment/challenge".into(),
            enrollment_authorization: url_encode([4; 32]),
            signing_key_id: "enrollment-v1".into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
            replayed: false,
        }
    }

    #[test]
    fn bootstrap_manifest_is_bound_to_the_runtime_platform() {
        assert!(validate_bootstrap_manifest(
            &bootstrap_manifest("LINUX", "x86_64"),
            "LINUX",
            Some("x86_64")
        )
        .is_ok());
        assert!(validate_bootstrap_manifest(
            &bootstrap_manifest("OPEN_WRT", "x86_64"),
            "LINUX",
            Some("x86_64")
        )
        .is_err());
        assert!(validate_bootstrap_manifest(
            &bootstrap_manifest("LINUX", "x86_64"),
            "OPEN_WRT",
            Some("x86_64")
        )
        .is_err());
    }

    #[test]
    fn bootstrap_manifest_is_bound_to_the_processor_architecture() {
        assert!(validate_bootstrap_manifest(
            &bootstrap_manifest("LINUX", "aarch64"),
            "LINUX",
            Some("x86_64")
        )
        .is_err());
    }

    #[test]
    fn persisted_installation_instance_id_is_strict_and_bounded() {
        assert!(
            validate_installation_instance_id("candy-7e5f78c4-7a11-4c96-a97d-ef11ea842caa").is_ok()
        );
        assert!(validate_installation_instance_id("contains space").is_err());
        assert!(validate_installation_instance_id("../escape").is_err());
        assert!(validate_installation_instance_id(&"a".repeat(121)).is_err());
    }

    #[test]
    fn installation_instance_id_is_created_once_and_reused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("installation-instance-id");
        let first = load_or_create_installation_instance_id(&path).unwrap();
        let second = load_or_create_installation_instance_id(&path).unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("candy-"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn bootstrap_expiration_is_validated_locally() {
        assert!(validate_future_expiration("2000-01-01T00:00:00Z", "bootstrap file").is_err());
        assert!(validate_future_expiration("not-a-time", "bootstrap file").is_err());
        assert!(validate_future_expiration("2999-01-01T00:00:00Z", "bootstrap file").is_ok());
    }

    #[test]
    fn bootstrap_file_requires_private_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bootstrap.json");
        fs::write(
            &path,
            format!(
                "{{\"schema_version\":1,\"cloud_address\":\"https://cloud.example.test\",\"bootstrap_code\":\"{}\",\"expires_at\":\"2030-01-01T00:00:00Z\"}}",
                url_encode([5; 32])
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_bootstrap_document(&path).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(read_bootstrap_document(&path).is_ok());
    }

    #[test]
    fn private_key_round_trip_preserves_operational_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operational-key.pem");
        let key = SigningKey::from_bytes(&[42; 32]);
        write_private_key(&path, &key).unwrap();
        let restored = read_private_key(&path).unwrap();
        assert_eq!(restored.verifying_key(), key.verifying_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
