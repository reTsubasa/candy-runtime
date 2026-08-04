use anyhow::{Context, Result};
use base64::Engine as _;
use candy_core::manifest::core_manifest;
use candy_core::{
    build_dns_trace, parse_gfwlist_provider, parse_ip_cidr_provider, validate_dns_answer,
    AnswerGeo, CompiledIpProvider, CompiledRules, DnsAnswerValidation, DnsQtype, DnsResolveMode,
    DnsResolver, DnsResolverAnswer, DnsResolverQuery, DnsRouteBindingTarget, DomainClass,
    RuntimeNode, RuntimeSnapshot, SmartDnsRuntime, UdpRedundancyPolicy, UserProfile,
};
#[cfg(unix)]
use candy_core::{RuntimeFingerprint, RuntimeReloadClass};
use candy_proto::address::Address;
use candy_proto::ids::KeyId;
use candy_proto::session::Network;
use carrier_client::{
    client_config_from_candy_snapshot, dns_route_bindings_for_snapshot, empty_dns_route_bindings,
    probe_http_download_once, probe_udp_datagram_once,
    run_client_with_reconnect_policy_and_passive_status,
    run_multinode_client_with_reconnect_policy_and_passive_status, validate_candy_client_profile,
    validate_client_listener_bindings, withdraw_client_readiness, CandyClientAuthProfile,
    ClientConfig, ClientReconnectPolicy, Forward, TransparentTcpForward, UdpMode,
};
#[cfg(unix)]
use carrier_client::{
    run_multinode_client_with_runtime_reload, runtime_reload_channel, RuntimeReloadAck,
    RuntimeReloadCancellation, RuntimeReloadCommand, RuntimeReloadSender,
};
use carrier_runtime::session_state::HARD_MAX_TOTAL_OPENS;
use carrier_runtime::ClientCredentials;
use carrier_transport::{
    parse_sha256_hex, ClientEchConfig, ServerIdentity, TransportSecurityProfile,
};
use clap::{Parser, Subcommand};
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

const MAX_PASSIVE_STATUS_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const MAX_RUNTIME_CONFIG_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const MAX_RELOAD_REQUEST_BYTES: usize = 16 * 1024;
#[cfg(unix)]
const MAX_RELOAD_RESPONSE_BYTES: usize = 16 * 1024;
#[cfg(unix)]
const RELOAD_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(unix)]
const RELOAD_HANDLER_TIMEOUT: Duration = Duration::from_secs(25);
#[cfg(unix)]
const RELOAD_ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(30);

const LEGACY_TOML_FORMAT: &str = concat!("car", "rier-toml");

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Option<CommandKind>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "candy-toml")]
    format: String,
    #[arg(long)]
    check_config: bool,
    #[arg(long)]
    render_runtime: bool,
    #[arg(long)]
    passive_status_path: Option<PathBuf>,
    #[arg(long)]
    control_socket_path: Option<PathBuf>,
    #[arg(long)]
    platform: Option<String>,
    #[arg(long, value_enum)]
    congestion: Option<CliCongestion>,
    #[arg(long, value_enum, default_value = "current")]
    candy_bbr_preset: CliBbrPreset,
    #[arg(long, default_value_t = false)]
    automatic_bbr_fallback: bool,
    #[command(flatten)]
    client_policy: ClientPolicyOverrides,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum CliCongestion {
    CandyBbr,
    Cubic,
}

impl From<CliCongestion> for carrier_transport::config::CongestionChoice {
    fn from(value: CliCongestion) -> Self {
        match value {
            CliCongestion::CandyBbr => Self::CandyBbr,
            CliCongestion::Cubic => Self::Cubic,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum CliBbrPreset {
    #[default]
    Current,
    BbrV1,
    Aggressive,
}

impl From<CliBbrPreset> for carrier_transport::config::CandyBbrPreset {
    fn from(value: CliBbrPreset) -> Self {
        match value {
            CliBbrPreset::Current => Self::Current,
            CliBbrPreset::BbrV1 => Self::BbrV1,
            CliBbrPreset::Aggressive => Self::Aggressive,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, clap::Args, serde::Deserialize)]
struct ClientPolicyOverrides {
    #[arg(long)]
    session_request_timeout_ms: Option<u64>,
    #[arg(long)]
    max_local_sessions: Option<usize>,
    #[arg(long)]
    stable_reset_after_ms: Option<u64>,
    #[arg(long)]
    max_connection_age_ms: Option<u64>,
    #[arg(long)]
    max_connection_bytes: Option<u64>,
}

fn resolve_client_policy(
    cli: &ClientPolicyOverrides,
    file: Option<&ClientPolicyOverrides>,
) -> Result<ClientReconnectPolicy> {
    let defaults = ClientReconnectPolicy::default();
    let session_request_timeout_ms = cli
        .session_request_timeout_ms
        .or_else(|| file.and_then(|policy| policy.session_request_timeout_ms));
    let max_local_sessions = cli
        .max_local_sessions
        .or_else(|| file.and_then(|policy| policy.max_local_sessions));
    let stable_reset_after_ms = cli
        .stable_reset_after_ms
        .or_else(|| file.and_then(|policy| policy.stable_reset_after_ms));
    let max_connection_age_ms = cli
        .max_connection_age_ms
        .or_else(|| file.and_then(|policy| policy.max_connection_age_ms));
    let max_connection_bytes = cli
        .max_connection_bytes
        .or_else(|| file.and_then(|policy| policy.max_connection_bytes));

    if session_request_timeout_ms == Some(0) {
        anyhow::bail!("session_request_timeout_ms must be greater than zero");
    }
    if max_local_sessions.is_some_and(|value| value == 0 || value > HARD_MAX_TOTAL_OPENS) {
        anyhow::bail!("max_local_sessions must be between 1 and {HARD_MAX_TOTAL_OPENS}");
    }
    if stable_reset_after_ms == Some(0) {
        anyhow::bail!("stable_reset_after_ms must be greater than zero");
    }
    if max_connection_age_ms == Some(0) {
        anyhow::bail!("max_connection_age_ms must be greater than zero");
    }
    if max_connection_bytes == Some(0) {
        anyhow::bail!("max_connection_bytes must be greater than zero");
    }

    Ok(ClientReconnectPolicy {
        session_request_timeout: session_request_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(defaults.session_request_timeout),
        max_local_sessions: max_local_sessions.unwrap_or(defaults.max_local_sessions),
        stable_reset_after: stable_reset_after_ms
            .map(Duration::from_millis)
            .unwrap_or(defaults.stable_reset_after),
        max_connection_age: max_connection_age_ms
            .map(Duration::from_millis)
            .unwrap_or(defaults.max_connection_age),
        max_connection_bytes: max_connection_bytes.unwrap_or(defaults.max_connection_bytes),
        ..defaults
    })
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    CoreInfo,
    Status {
        #[arg(long)]
        path: PathBuf,
    },
    #[command(subcommand)]
    Geo(GeoCommand),
    #[command(subcommand)]
    Dns(DnsCommand),
    Reload {
        #[arg(long, default_value = "/var/run/candy/control.sock")]
        control_socket: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long, default_value = "/var/run/candy/runtime.json")]
        active: PathBuf,
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        expected_generation: u64,
    },
    CongestionTest {
        #[arg(long, default_value_t = 2)]
        samples: u8,
        #[arg(long, default_value_t = 2_097_152)]
        max_bytes: usize,
        #[arg(long, default_value_t = 20_000)]
        timeout_ms: u64,
    },
}

#[derive(serde::Serialize)]
struct CongestionTestSample {
    controller: &'static str,
    preset: Option<&'static str>,
    sample: u8,
    session_open_ms: Option<u32>,
    stream_open_ms: Option<u32>,
    ttfb_ms: Option<u32>,
    total_ms: Option<u32>,
    bytes_read: Option<u64>,
    goodput_bps: Option<u64>,
    error: Option<String>,
}

async fn resolve_congestion_test_target(host: &str, port: u16) -> Result<Address> {
    let mut addresses = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve congestion test target {host}:{port}"))?;
    let mut fallback = None;
    let address = addresses
        .find(|address| {
            fallback.get_or_insert(*address);
            address.is_ipv4()
        })
        .or(fallback)
        .ok_or_else(|| anyhow::anyhow!("no address for congestion test target {host}:{port}"))?;
    Ok(match address {
        SocketAddr::V4(address) => Address::V4(address.ip().octets(), address.port()),
        SocketAddr::V6(address) => Address::V6(address.ip().octets(), address.port()),
    })
}

async fn run_congestion_test(
    snapshot: &RuntimeSnapshot,
    platform: carrier_transport::config::ClientPlatform,
    samples: u8,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Vec<CongestionTestSample>> {
    anyhow::ensure!(
        (1..=3).contains(&samples),
        "samples must be between 1 and 3"
    );
    anyhow::ensure!(
        (65_536..=8 * 1024 * 1024).contains(&max_bytes),
        "max_bytes must be between 65536 and 8388608"
    );
    anyhow::ensure!(
        (5_000..=60_000).contains(&timeout.as_millis()),
        "timeout_ms must be between 5000 and 60000"
    );
    let variants = [
        (carrier_transport::config::CongestionChoice::Cubic, None),
        (
            carrier_transport::config::CongestionChoice::CandyBbr,
            Some(carrier_transport::config::CandyBbrPreset::Current),
        ),
        (
            carrier_transport::config::CongestionChoice::CandyBbr,
            Some(carrier_transport::config::CandyBbrPreset::BbrV1),
        ),
        (
            carrier_transport::config::CongestionChoice::CandyBbr,
            Some(carrier_transport::config::CandyBbrPreset::Aggressive),
        ),
    ];
    let target_host = "dl.google.com";
    let target = resolve_congestion_test_target(target_host, 443).await?;
    let mut output = Vec::new();
    for (controller, preset) in variants {
        for sample in 1..=samples {
            let mut config = client_config_from_candy_snapshot(snapshot)?;
            config.transport =
                carrier_transport::config::CandyTransportProfile::for_client(platform);
            config.transport.congestion = controller;
            config.transport.automatic_bbr_fallback = false;
            if let Some(preset) = preset {
                config.transport.candy_bbr_preset = preset;
            }
            let path = "/linux/direct/google-chrome-stable_current_amd64.deb";
            let result = probe_http_download_once(
                config,
                target.clone(),
                target_host,
                path,
                timeout,
                max_bytes,
            )
            .await;
            output.push(match result {
                Ok(result) => CongestionTestSample {
                    controller: controller.as_str(),
                    preset: preset.map(|value| value.as_str()),
                    sample,
                    session_open_ms: Some(result.session_open_ms),
                    stream_open_ms: Some(result.stream_open_ms),
                    ttfb_ms: Some(result.ttfb_ms),
                    total_ms: Some(result.total_ms),
                    bytes_read: Some(result.bytes_read),
                    goodput_bps: Some(result.goodput_bps),
                    error: None,
                },
                Err(error) => CongestionTestSample {
                    controller: controller.as_str(),
                    preset: preset.map(|value| value.as_str()),
                    sample,
                    session_open_ms: None,
                    stream_open_ms: None,
                    ttfb_ms: None,
                    total_ms: None,
                    bytes_read: None,
                    goodput_bps: None,
                    error: Some(error.to_string()),
                },
            });
        }
    }
    Ok(output)
}

#[cfg(unix)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ReloadControlRequest {
    candidate_path: PathBuf,
    active_path: PathBuf,
    candidate_sha256: String,
    expected_generation: u64,
}

#[cfg(unix)]
#[derive(Debug)]
struct ValidatedReloadCandidate {
    snapshot: RuntimeSnapshot,
    config_sha256: RuntimeFingerprint,
    expected_generation: u64,
    candidate_path: PathBuf,
    active_path: PathBuf,
}

#[cfg(unix)]
#[derive(Debug)]
struct ReloadCandidateError {
    code: &'static str,
    message: String,
}

#[cfg(unix)]
impl ReloadCandidateError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[cfg(unix)]
fn normalize_sha256(value: &str) -> std::result::Result<String, ReloadCandidateError> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ReloadCandidateError::new(
            "invalid_sha256",
            "candidate SHA-256 must contain exactly 64 hexadecimal characters",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(unix)]
fn read_reload_candidate(
    request: ReloadControlRequest,
) -> std::result::Result<ValidatedReloadCandidate, ReloadCandidateError> {
    let expected_sha256 = normalize_sha256(&request.candidate_sha256)?;
    if !request.candidate_path.is_absolute() {
        return Err(ReloadCandidateError::new(
            "candidate_path_invalid",
            "candidate config path must be absolute",
        ));
    }
    if !request.active_path.is_absolute()
        || request.active_path.file_name() != Some(std::ffi::OsStr::new("runtime.json"))
        || request.active_path.parent() != request.candidate_path.parent()
    {
        return Err(ReloadCandidateError::new(
            "active_path_invalid",
            "active config must be an absolute runtime.json path in the candidate directory",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(nix::libc::O_NOFOLLOW);
    let mut file = options.open(&request.candidate_path).map_err(|error| {
        ReloadCandidateError::new(
            "candidate_open_failed",
            format!("candidate open failed: {error}"),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        ReloadCandidateError::new(
            "candidate_metadata_failed",
            format!("candidate metadata failed: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return Err(ReloadCandidateError::new(
            "candidate_not_regular",
            "candidate config is not a regular file",
        ));
    }
    if metadata.len() > MAX_RUNTIME_CONFIG_BYTES as u64 {
        return Err(ReloadCandidateError::new(
            "candidate_too_large",
            format!("candidate config exceeds {MAX_RUNTIME_CONFIG_BYTES} bytes"),
        ));
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take((MAX_RUNTIME_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ReloadCandidateError::new(
                "candidate_read_failed",
                format!("candidate read failed: {error}"),
            )
        })?;
    if bytes.len() > MAX_RUNTIME_CONFIG_BYTES {
        return Err(ReloadCandidateError::new(
            "candidate_too_large",
            format!("candidate config exceeds {MAX_RUNTIME_CONFIG_BYTES} bytes"),
        ));
    }
    let actual_sha256 = RuntimeFingerprint::from_bytes(Sha256::digest(&bytes).into());
    if actual_sha256.to_hex() != expected_sha256 {
        return Err(ReloadCandidateError::new(
            "sha256_mismatch",
            "candidate SHA-256 does not match the opened file",
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        ReloadCandidateError::new(
            "candidate_not_utf8",
            format!("candidate config is not UTF-8: {error}"),
        )
    })?;
    let snapshot = parse_candy_config(text).map_err(|error| {
        ReloadCandidateError::new(
            "candidate_invalid",
            format!("candidate config validation failed: {error}"),
        )
    })?;
    Ok(ValidatedReloadCandidate {
        snapshot,
        config_sha256: actual_sha256,
        expected_generation: request.expected_generation,
        candidate_path: request.candidate_path,
        active_path: request.active_path,
    })
}

#[cfg(unix)]
async fn read_bounded(stream: &mut UnixStream, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    stream
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "control message exceeds size limit",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
async fn write_reload_ack(stream: &mut UnixStream, ack: &RuntimeReloadAck) -> Result<()> {
    let bytes = serde_json::to_vec(ack)?;
    anyhow::ensure!(
        bytes.len() <= MAX_RELOAD_RESPONSE_BYTES,
        "reload response exceeds size limit"
    );
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(unix)]
async fn submit_reload_request(
    control_socket: &std::path::Path,
    request: &ReloadControlRequest,
) -> Result<RuntimeReloadAck> {
    let mut stream = UnixStream::connect(control_socket).await?;
    let bytes = serde_json::to_vec(request)?;
    anyhow::ensure!(
        bytes.len() <= MAX_RELOAD_REQUEST_BYTES,
        "reload request exceeds size limit"
    );
    tokio::time::timeout(RELOAD_ROUND_TRIP_TIMEOUT, async {
        stream.write_all(&bytes).await?;
        stream.shutdown().await?;
        let response = read_bounded(&mut stream, MAX_RELOAD_RESPONSE_BYTES).await?;
        Ok::<_, anyhow::Error>(serde_json::from_slice(&response)?)
    })
    .await
    .context("reload control request timed out")?
}

#[cfg(unix)]
struct ReloadSocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl Drop for ReloadSocketGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

#[cfg(unix)]
struct ReloadBusyGuard(Arc<AtomicBool>);

#[cfg(unix)]
impl Drop for ReloadBusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(unix)]
async fn run_reload_control_server<H, Fut>(socket_path: PathBuf, handler: H) -> Result<()>
where
    H: Fn(ValidatedReloadCandidate, RuntimeReloadCancellation) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<RuntimeReloadAck>> + Send + 'static,
{
    if let Some(parent) = socket_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(&socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            match std::os::unix::net::UnixStream::connect(&socket_path) {
                Ok(_) => anyhow::bail!("reload control socket is already active"),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    std::fs::remove_file(&socket_path)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(_) => anyhow::bail!("reload control path exists and is not a socket"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(&socket_path)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    let metadata = std::fs::symlink_metadata(&socket_path)?;
    let _socket_guard = ReloadSocketGuard {
        path: socket_path,
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let handler = Arc::new(handler);
    let busy = Arc::new(AtomicBool::new(false));

    loop {
        let (mut stream, _) = listener.accept().await?;
        let handler = Arc::clone(&handler);
        let busy = Arc::clone(&busy);
        tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            if busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                let ack = reload_failure_ack(
                    "reload_busy",
                    "another reload is in progress",
                    started.elapsed(),
                );
                let _ = write_reload_ack(&mut stream, &ack).await;
                return;
            }
            let _busy_guard = ReloadBusyGuard(busy);
            let ack = match tokio::time::timeout(
                RELOAD_REQUEST_TIMEOUT,
                read_bounded(&mut stream, MAX_RELOAD_REQUEST_BYTES),
            )
            .await
            {
                Err(_) => reload_failure_ack(
                    "request_timeout",
                    "reload control request timed out",
                    started.elapsed(),
                ),
                Ok(Err(error)) => {
                    reload_failure_ack("invalid_request", error.to_string(), started.elapsed())
                }
                Ok(Ok(bytes)) => match serde_json::from_slice::<ReloadControlRequest>(&bytes) {
                    Err(error) => reload_failure_ack(
                        "invalid_request",
                        format!("invalid reload request: {error}"),
                        started.elapsed(),
                    ),
                    Ok(request) => match read_reload_candidate(request) {
                        Err(error) => {
                            reload_failure_ack(error.code, error.message, started.elapsed())
                        }
                        Ok(candidate) => {
                            let cancellation = RuntimeReloadCancellation::new();
                            let mut reload = Box::pin(handler(candidate, cancellation.clone()));
                            let timeout = tokio::time::sleep(RELOAD_HANDLER_TIMEOUT);
                            tokio::pin!(timeout);
                            let result = tokio::select! {
                                result = &mut reload => Some(result),
                                _ = &mut timeout => None,
                            };
                            match result {
                                Some(Ok(mut ack)) => {
                                    ack.duration_ms =
                                        started.elapsed().as_millis().min(u128::from(u64::MAX))
                                            as u64;
                                    ack
                                }
                                Some(Err(error)) => reload_failure_ack(
                                    "reload_rejected",
                                    error.to_string(),
                                    started.elapsed(),
                                ),
                                None if cancellation.cancel() => reload_failure_ack(
                                    "reload_timeout",
                                    "runtime reload timed out",
                                    started.elapsed(),
                                ),
                                None => match reload.await {
                                    Ok(mut ack) => {
                                        ack.duration_ms =
                                            started.elapsed().as_millis().min(u128::from(u64::MAX))
                                                as u64;
                                        ack
                                    }
                                    Err(error) => reload_failure_ack(
                                        "reload_rejected",
                                        error.to_string(),
                                        started.elapsed(),
                                    ),
                                },
                            }
                        }
                    },
                },
            };
            let _ = write_reload_ack(&mut stream, &ack).await;
        });
    }
}

#[cfg(unix)]
fn reload_failure_ack(
    code: impl Into<String>,
    message: impl Into<String>,
    duration: Duration,
) -> RuntimeReloadAck {
    RuntimeReloadAck {
        ok: false,
        generation: 0,
        mode: RuntimeReloadClass::Unchanged,
        duration_ms: duration.as_millis().min(u128::from(u64::MAX)) as u64,
        error_code: Some(code.into()),
        message: Some(message.into()),
    }
}

#[cfg(unix)]
async fn submit_validated_reload(
    sender: RuntimeReloadSender,
    candidate: ValidatedReloadCandidate,
    cancellation: RuntimeReloadCancellation,
) -> Result<RuntimeReloadAck> {
    let (response, receiver) = tokio::sync::oneshot::channel();
    sender
        .send(RuntimeReloadCommand {
            expected_generation: candidate.expected_generation,
            config_sha256: candidate.config_sha256,
            snapshot: candidate.snapshot,
            candidate_path: candidate.candidate_path,
            active_path: candidate.active_path,
            cancellation,
            response,
        })
        .await
        .map_err(|_| anyhow::anyhow!("runtime reload manager is unavailable"))?;
    receiver
        .await
        .map_err(|_| anyhow::anyhow!("runtime reload manager dropped its response"))
}

fn read_passive_status(path: &std::path::Path) -> Result<serde_json::Value> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "passive status path is not a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_PASSIVE_STATUS_BYTES as u64,
        "passive status file is too large"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take((MAX_PASSIVE_STATUS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_PASSIVE_STATUS_BYTES,
        "passive status file is too large"
    );
    let status: serde_json::Value =
        serde_json::from_slice(&bytes).context("invalid passive status JSON")?;
    fn rejects_credentials(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
                matches!(
                    key.as_str(),
                    "credentials" | "secret" | "auth" | "authentication_key"
                ) || rejects_credentials(value)
            }),
            serde_json::Value::Array(values) => values.iter().any(rejects_credentials),
            _ => false,
        }
    }
    anyhow::ensure!(
        !rejects_credentials(&status),
        "passive status contains a credential field"
    );
    let schema_version = status
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("passive status schema_version is missing"))?;
    anyhow::ensure!(
        matches!(schema_version, 1 | 2),
        "unsupported passive status schema version {schema_version}",
    );
    Ok(status)
}

#[derive(Debug, Subcommand)]
enum GeoCommand {
    Update {
        provider: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DnsCommand {
    Update {
        provider: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        output: PathBuf,
    },
    Trace {
        domain: String,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, default_value = "8.8.8.8:53")]
        egress_dns: String,
    },
}

struct DomainProviderSummary {
    entry_count: usize,
}

#[derive(serde::Deserialize)]
struct FileConfig {
    server: String,
    server_name: String,
    #[serde(default)]
    server_identity: Option<String>,
    #[serde(default)]
    server_pin: Option<String>,
    /// Base64 value from the DNS HTTPS/SVCB `ech` parameter.
    #[serde(default)]
    ech: Option<String>,
    key_id: String,
    #[serde(default)]
    secret: String,
    /// Authentication profile. Defaults to `standard` for existing configs.
    #[serde(default)]
    auth_profile: Option<String>,
    #[serde(default)]
    cloud_auth: Option<FileCloudAuth>,
    #[serde(default = "default_udp_multiplier")]
    udp_client_multiplier: u8,
    #[serde(default = "default_udp_multiplier")]
    udp_server_multiplier: u8,
    #[serde(default)]
    forwards: Vec<FileForward>,
    #[serde(default)]
    transparent_tcp: Vec<FileTransparentTcp>,
    #[serde(default)]
    transparent_udp: Vec<FileTransparentTcp>,
    #[serde(default)]
    transport: FileClientTransport,
    #[serde(default, flatten)]
    client_policy: ClientPolicyOverrides,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCloudAuth {
    #[serde(default)]
    grant_envelope_path: Option<PathBuf>,
    #[serde(default)]
    grant_envelope_base64: Option<String>,
    #[serde(default)]
    device_signing_key_path: Option<PathBuf>,
    #[serde(default)]
    device_signing_key_base64: Option<String>,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileClientTransport {
    profile: Option<carrier_transport::config::ClientPlatform>,
    stream_priority_enabled: Option<bool>,
    congestion: Option<carrier_transport::config::CongestionChoice>,
    candy_bbr_preset: Option<carrier_transport::config::CandyBbrPreset>,
    automatic_bbr_fallback: Option<bool>,
}

fn default_udp_multiplier() -> u8 {
    1
}

#[derive(serde::Deserialize)]
struct FileForward {
    network: String,
    local: String,
    target: String,
    #[serde(default)]
    udp_mode: Option<String>,
}

#[derive(serde::Deserialize)]
struct FileTransparentTcp {
    local: String,
}

#[cfg(test)]
fn parse_carrying_config(text: &str) -> Result<ClientConfig> {
    Ok(parse_carrying_config_with_policy(text)?.0)
}

fn parse_carrying_config_with_policy(text: &str) -> Result<(ClientConfig, ClientPolicyOverrides)> {
    let fc: FileConfig = toml::from_str(text)?;
    let authentication =
        parse_file_authentication(fc.auth_profile.as_deref(), fc.cloud_auth, &fc.key_id)?;
    let client_policy = fc.client_policy;
    let transport = build_file_client_transport(fc.transport)?;
    let server_identity = parse_file_server_identity(
        fc.server_identity.as_deref(),
        fc.server_pin.as_deref(),
        &fc.server_name,
    )?;
    let ech = fc
        .ech
        .as_deref()
        .map(ClientEchConfig::from_base64)
        .transpose()?;
    let mut forwards = Vec::new();
    for f in fc.forwards {
        let network = match f.network.as_str() {
            "tcp" => Network::Tcp,
            "udp" => Network::Udp,
            other => anyhow::bail!("unknown forward network: {other}"),
        };
        let udp_mode = match f.udp_mode.as_deref().unwrap_or("datagram") {
            "datagram" => UdpMode::Datagram,
            "stream_fallback" => UdpMode::StreamFallback,
            other => anyhow::bail!("unknown udp_mode: {other}"),
        };
        forwards.push(Forward {
            network,
            local: f.local.parse()?,
            target: parse_target(&f.target)?,
            udp_mode,
        });
    }
    let mut transparent_tcp = Vec::new();
    for f in fc.transparent_tcp {
        transparent_tcp.push(TransparentTcpForward {
            local: f.local.parse()?,
        });
    }
    let mut transparent_udp = Vec::new();
    for f in fc.transparent_udp {
        transparent_udp.push(TransparentTcpForward {
            local: f.local.parse()?,
        });
    }
    let config = ClientConfig {
        server: fc.server.parse()?,
        server_name: fc.server_name,
        active_node_name: None,
        server_identity,
        ech,
        credentials: ClientCredentials {
            key_id: KeyId::new(fc.key_id),
            secret: fc.secret.into_bytes(),
        },
        authentication,
        rules: CompiledRules::default(),
        dns_route_bindings: empty_dns_route_bindings(),
        performance_mode: candy_core::PerformanceMode::Auto,
        lane_mode: candy_core::LaneMode::Auto,
        udp_redundancy: UdpRedundancyPolicy::new(
            fc.udp_client_multiplier,
            fc.udp_server_multiplier,
        ),
        security: TransportSecurityProfile::default(),
        transport,
        forwards,
        transparent_tcp,
        transparent_udp,
    };
    validate_client_listener_bindings(&config)?;
    Ok((config, client_policy))
}

fn parse_file_authentication(
    profile: Option<&str>,
    cloud: Option<FileCloudAuth>,
    key_id: &str,
) -> Result<CandyClientAuthProfile> {
    let profile = profile.unwrap_or("standard").to_ascii_lowercase();
    match profile.as_str() {
        "standard" => {
            if cloud.is_some() {
                anyhow::bail!("cloud_auth requires auth_profile = 'cloud_grant_v1'");
            }
            Ok(CandyClientAuthProfile::Standard)
        }
        "cloud_grant_v1" | "cloud-grant-v1" => {
            carrier_runtime::cloud_auth::normalize_cloud_device_id(&KeyId::new(key_id.to_owned()))
                .map_err(|error| {
                    anyhow::anyhow!("cloud auth key_id must be canonical UUID: {error}")
                })?;
            let cloud = cloud.ok_or_else(|| {
                anyhow::anyhow!("auth_profile = 'cloud_grant_v1' requires [cloud_auth]")
            })?;
            let grant_envelope = load_cloud_secret(
                cloud.grant_envelope_path.as_deref(),
                cloud.grant_envelope_base64.as_deref(),
                "grant envelope",
            )?;
            if grant_envelope.is_empty() {
                anyhow::bail!("cloud grant envelope must not be empty");
            }
            let device_key = load_cloud_secret(
                cloud.device_signing_key_path.as_deref(),
                cloud.device_signing_key_base64.as_deref(),
                "device signing key",
            )?;
            let device_signing_key: [u8; 32] = device_key.try_into().map_err(|_| {
                anyhow::anyhow!("cloud device signing key must decode to exactly 32 bytes")
            })?;
            Ok(CandyClientAuthProfile::CloudGrantV1 {
                grant_envelope,
                device_signing_key,
            })
        }
        other => {
            anyhow::bail!("unknown auth_profile '{other}'; expected 'standard' or 'cloud_grant_v1'")
        }
    }
}

fn load_cloud_secret(
    path: Option<&Path>,
    inline_base64: Option<&str>,
    label: &str,
) -> Result<Vec<u8>> {
    match (path, inline_base64) {
        (Some(_), Some(_)) => {
            anyhow::bail!("{label} must configure only one of *_path or *_base64")
        }
        (Some(path), None) => std::fs::read(path)
            .with_context(|| format!("read cloud {label} from {}", path.display())),
        (None, Some(value)) => base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .with_context(|| format!("decode cloud {label} base64")),
        (None, None) => anyhow::bail!("cloud {label} requires a path or inline base64 value"),
    }
}

fn build_file_client_transport(
    file: FileClientTransport,
) -> Result<carrier_transport::config::CandyTransportProfile> {
    let mut profile = carrier_transport::config::CandyTransportProfile::for_client(
        file.profile
            .unwrap_or(carrier_transport::config::ClientPlatform::Linux),
    );
    if let Some(value) = file.stream_priority_enabled {
        profile.stream_priority_enabled = value;
    }
    if let Some(value) = file.congestion {
        profile.congestion = value;
    }
    if let Some(value) = file.candy_bbr_preset {
        profile.candy_bbr_preset = value;
    }
    if let Some(value) = file.automatic_bbr_fallback {
        profile.automatic_bbr_fallback = value;
    }
    profile.validate()?;
    Ok(profile)
}

fn parse_candy_client_platform(value: &str) -> Result<carrier_transport::config::ClientPlatform> {
    match value {
        "openwrt" => Ok(carrier_transport::config::ClientPlatform::OpenWrt),
        "macos" => Ok(carrier_transport::config::ClientPlatform::MacOs),
        "android-foreground" => Ok(carrier_transport::config::ClientPlatform::AndroidForeground),
        "android-restricted" => Ok(carrier_transport::config::ClientPlatform::AndroidRestricted),
        "linux" => Ok(carrier_transport::config::ClientPlatform::Linux),
        other => anyhow::bail!("unknown Candy client platform: {other}"),
    }
}

fn parse_file_server_identity(
    server_identity: Option<&str>,
    server_pin: Option<&str>,
    server_name: &str,
) -> Result<ServerIdentity> {
    match (server_identity, server_pin) {
        (Some(identity), None) => parse_server_identity_value(identity, server_name),
        (None, Some(pin)) => Ok(ServerIdentity::PinnedSha256(parse_sha256_hex(
            pin.strip_prefix("sha256:").unwrap_or(pin),
        )?)),
        (Some(_), Some(_)) => {
            anyhow::bail!("server_identity and server_pin cannot both be configured")
        }
        (None, None) => anyhow::bail!("one of server_identity or server_pin must be configured"),
    }
}

fn parse_server_identity_value(value: &str, server_name: &str) -> Result<ServerIdentity> {
    if value == "webpki" {
        rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|error| anyhow::anyhow!("invalid WebPKI server_name: {error}"))?;
        return Ok(ServerIdentity::WebPki);
    }
    let pin = value.strip_prefix("sha256:").unwrap_or(value);
    Ok(ServerIdentity::PinnedSha256(parse_sha256_hex(pin)?))
}

fn parse_candy_config(text: &str) -> Result<RuntimeSnapshot> {
    let profile: UserProfile = serde_json::from_str(text)?;
    validate_candy_client_profile(profile)
}

#[cfg(test)]
fn parse_candy_transport_config(text: &str) -> Result<ClientConfig> {
    let snapshot = parse_candy_config(text)?;
    client_config_from_candy_snapshot(&snapshot)
}

fn parse_target(s: &str) -> Result<Address> {
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Ok(match sa {
            std::net::SocketAddr::V4(v4) => Address::V4(v4.ip().octets(), v4.port()),
            std::net::SocketAddr::V6(v6) => Address::V6(v6.ip().octets(), v6.port()),
        });
    }
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("target must be host:port"))?;
    Ok(Address::Domain(host.to_string(), port.parse()?))
}

fn render_runtime(snapshot: &RuntimeSnapshot) {
    println!("{snapshot:#?}");
}

fn update_geo_provider(
    provider: &str,
    url: &str,
    output: &std::path::Path,
) -> Result<CompiledIpProvider> {
    if provider != "cn-ip" {
        anyhow::bail!("unsupported geo provider: {provider}");
    }
    let text = read_provider_from_url(url)?;
    let summary = parse_ip_cidr_provider(provider, &text)?;
    atomic_write(output, text.as_bytes())?;
    Ok(summary)
}

fn update_dns_provider(
    provider: &str,
    url: &str,
    output: &std::path::Path,
) -> Result<DomainProviderSummary> {
    if provider != "gfwlist" {
        anyhow::bail!("unsupported dns provider: {provider}");
    }
    let text = read_provider_from_url(url)?;
    let domains = parse_gfwlist_domains(&text)?;
    if domains.is_empty() {
        anyhow::bail!("dns provider has no domain entries: {provider}");
    }
    let mut output_text = domains.join("\n");
    output_text.push('\n');
    atomic_write(output, output_text.as_bytes())?;
    Ok(DomainProviderSummary {
        entry_count: domains.len(),
    })
}

#[derive(serde::Serialize)]
struct DnsTraceOutput {
    domain: String,
    domain_class: &'static str,
    resolve_mode: &'static str,
    node_id: Option<String>,
    resolver_profile: String,
    resolver_perspective: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_perspective: Option<&'static str>,
    route_binding: String,
    answer_ip: Option<String>,
    answer_ips: Vec<String>,
    ttl_seconds: Option<u32>,
    cache_hit: bool,
    answer_geo: Option<&'static str>,
    fallback_reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    validation_results: Vec<DnsValidationTraceOutput>,
}

#[derive(serde::Serialize)]
struct DnsValidationTraceOutput {
    resolver_perspective: &'static str,
    resolver_profile: String,
    node_id: Option<String>,
    route_binding: String,
    answer_ip: Option<String>,
    answer_ips: Vec<String>,
    ttl_seconds: Option<u32>,
    answer_geo: Option<&'static str>,
    accepted: bool,
    selected: bool,
    rejection_reason: Option<String>,
}

fn render_dns_trace_json(domain: &str, node: Option<String>) -> Result<String> {
    let rules = CompiledRules::default();
    render_dns_trace_json_with_rules(&rules, domain, node)
}

#[cfg(test)]
fn render_dns_trace_json_for_snapshot(
    snapshot: &RuntimeSnapshot,
    domain: &str,
    node: Option<String>,
) -> Result<String> {
    render_dns_trace_json_for_snapshot_with_resolver(snapshot, domain, node, SystemDnsResolver)
}

fn render_dns_trace_json_for_snapshot_with_resolver<R: DnsResolver>(
    snapshot: &RuntimeSnapshot,
    domain: &str,
    node: Option<String>,
    resolver: R,
) -> Result<String> {
    let mut runtime = SmartDnsRuntime::new(snapshot.clone(), resolver, node);
    let result = runtime.resolve(domain, DnsQtype::A, unix_now_ms())?;
    let answer_ips = result
        .answers
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>();
    let output = DnsTraceOutput {
        domain: result.trace.domain,
        domain_class: domain_class_label(result.trace.domain_class),
        resolve_mode: resolve_mode_label(result.trace.decision.mode),
        node_id: result.trace.decision.node_id,
        resolver_profile: result.trace.decision.resolver_profile,
        resolver_perspective: "system-local",
        selected_perspective: None,
        route_binding: route_binding_label(&result.route_binding),
        answer_ip: answer_ips.first().cloned(),
        answer_ips,
        ttl_seconds: Some(result.ttl_seconds),
        cache_hit: result.cache_hit,
        answer_geo: result.answer_geo.map(answer_geo_label),
        fallback_reason: result.trace.fallback_reason,
        validation_results: Vec::new(),
    };
    Ok(serde_json::to_string_pretty(&output)?)
}

fn render_dns_trace_json_with_rules(
    rules: &CompiledRules,
    domain: &str,
    node: Option<String>,
) -> Result<String> {
    let trace = build_dns_trace(rules, domain, node.as_deref());
    let output = DnsTraceOutput {
        domain: trace.domain,
        domain_class: domain_class_label(trace.domain_class),
        resolve_mode: resolve_mode_label(trace.decision.mode),
        node_id: trace.decision.node_id,
        resolver_profile: trace.decision.resolver_profile,
        resolver_perspective: "route-only",
        selected_perspective: None,
        route_binding: route_binding_label(&trace.decision.route_binding),
        answer_ip: None,
        answer_ips: Vec::new(),
        ttl_seconds: None,
        cache_hit: false,
        answer_geo: None,
        fallback_reason: trace.fallback_reason,
        validation_results: Vec::new(),
    };
    Ok(serde_json::to_string_pretty(&output)?)
}

async fn render_dns_trace_json_for_snapshot_via_egress(
    snapshot: &RuntimeSnapshot,
    domain: &str,
    node: Option<String>,
    egress_dns: Address,
) -> Result<String> {
    render_dns_trace_json_for_snapshot_with_packet_probe(
        snapshot,
        domain,
        node,
        egress_dns,
        |config, target, payload, timeout| {
            probe_udp_datagram_once(config, target, payload, timeout)
        },
    )
    .await
}

async fn render_dns_trace_json_for_snapshot_with_packet_probe<F, Fut>(
    snapshot: &RuntimeSnapshot,
    domain: &str,
    node: Option<String>,
    egress_dns: Address,
    probe: F,
) -> Result<String>
where
    F: FnOnce(ClientConfig, Address, Vec<u8>, Duration) -> Fut,
    Fut: Future<Output = Result<Vec<u8>>>,
{
    render_dns_trace_json_for_snapshot_with_resolver_and_packet_probe(
        snapshot,
        domain,
        node,
        egress_dns,
        SystemDnsResolver,
        probe,
    )
    .await
}

async fn render_dns_trace_json_for_snapshot_with_resolver_and_packet_probe<R, F, Fut>(
    snapshot: &RuntimeSnapshot,
    domain: &str,
    node: Option<String>,
    egress_dns: Address,
    resolver: R,
    probe: F,
) -> Result<String>
where
    R: DnsResolver,
    F: FnOnce(ClientConfig, Address, Vec<u8>, Duration) -> Fut,
    Fut: Future<Output = Result<Vec<u8>>>,
{
    let trace = build_dns_trace(snapshot.rules(), domain, node.as_deref());
    match trace.decision.mode {
        DnsResolveMode::ParallelValidate => {
            return render_parallel_validate_dns_trace(
                snapshot, trace, egress_dns, resolver, probe,
            )
            .await;
        }
        DnsResolveMode::Remote | DnsResolveMode::EgressCoherent => {}
        _ => {
            return render_dns_trace_json_for_snapshot_with_resolver(
                snapshot, domain, node, resolver,
            )
        }
    }

    render_egress_dns_trace(snapshot, trace, egress_dns, probe, Vec::new(), None).await
}

async fn render_egress_dns_trace<F, Fut>(
    snapshot: &RuntimeSnapshot,
    trace: candy_core::DnsTrace,
    egress_dns: Address,
    probe: F,
    validation_results: Vec<DnsValidationTraceOutput>,
    selected_perspective: Option<&'static str>,
) -> Result<String>
where
    F: FnOnce(ClientConfig, Address, Vec<u8>, Duration) -> Fut,
    Fut: Future<Output = Result<Vec<u8>>>,
{
    let request = build_dns_a_query(&trace.domain)?;
    let config = client_config_from_candy_snapshot_for_dns_probe(
        snapshot,
        trace.decision.node_id.as_deref(),
    )?;
    let response = probe(config, egress_dns, request, Duration::from_secs(2)).await?;
    let answer = parse_dns_a_response(&response)?;
    let first_ip = *answer
        .ips
        .first()
        .ok_or_else(|| anyhow::anyhow!("DNS response had no A answers"))?;
    let answer_geo = match validate_dns_answer(trace.domain_class, first_ip) {
        DnsAnswerValidation::Accept(geo) => geo,
        DnsAnswerValidation::Reject(geo) => {
            anyhow::bail!(
                "egress DNS answer for {} rejected as {}",
                trace.domain,
                answer_geo_label(geo)
            )
        }
    };
    let answer_ips = answer
        .ips
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>();
    let output = DnsTraceOutput {
        domain: trace.domain,
        domain_class: domain_class_label(trace.domain_class),
        resolve_mode: resolve_mode_label(trace.decision.mode),
        node_id: trace.decision.node_id,
        resolver_profile: trace.decision.resolver_profile,
        resolver_perspective: "egress-node",
        selected_perspective,
        route_binding: route_binding_label(&trace.decision.route_binding),
        answer_ip: answer_ips.first().cloned(),
        answer_ips,
        ttl_seconds: Some(answer.ttl_seconds),
        cache_hit: false,
        answer_geo: Some(answer_geo_label(answer_geo)),
        fallback_reason: trace.fallback_reason,
        validation_results,
    };
    Ok(serde_json::to_string_pretty(&output)?)
}

async fn render_parallel_validate_dns_trace<R, F, Fut>(
    snapshot: &RuntimeSnapshot,
    trace: candy_core::DnsTrace,
    egress_dns: Address,
    resolver: R,
    probe: F,
) -> Result<String>
where
    R: DnsResolver,
    F: FnOnce(ClientConfig, Address, Vec<u8>, Duration) -> Fut,
    Fut: Future<Output = Result<Vec<u8>>>,
{
    let domestic_decision = candy_core::DnsRouteDecision {
        mode: DnsResolveMode::Local,
        node_id: None,
        resolver_profile: "domestic".to_string(),
        route_binding: DnsRouteBindingTarget::Direct,
    };
    let domestic_query = DnsResolverQuery {
        domain: trace.domain.clone(),
        qtype: DnsQtype::A,
        resolver_profile: domestic_decision.resolver_profile.clone(),
        node_id: None,
    };
    let domestic_result = resolver.resolve(&domestic_query);
    let mut domestic_selected = false;
    let domestic_evidence = match domestic_result {
        Ok(answer) => {
            let evidence = validation_trace_from_answer(
                "system-local",
                &domestic_decision,
                trace.domain_class,
                &answer,
                false,
            );
            domestic_selected =
                evidence.accepted && matches!(evidence.answer_geo, Some("china") | Some("private"));
            evidence
        }
        Err(err) => validation_trace_from_error("system-local", &domestic_decision, err),
    };

    if domestic_selected {
        let answer_ip = domestic_evidence.answer_ip.clone();
        let answer_ips = domestic_evidence.answer_ips.clone();
        let output = DnsTraceOutput {
            domain: trace.domain,
            domain_class: domain_class_label(trace.domain_class),
            resolve_mode: resolve_mode_label(trace.decision.mode),
            node_id: trace.decision.node_id,
            resolver_profile: trace.decision.resolver_profile,
            resolver_perspective: "parallel-validate",
            selected_perspective: Some("system-local"),
            route_binding: route_binding_label(&DnsRouteBindingTarget::Direct),
            answer_ip,
            answer_ips,
            ttl_seconds: domestic_evidence.ttl_seconds,
            cache_hit: false,
            answer_geo: domestic_evidence.answer_geo,
            fallback_reason: Some("domestic-answer-accepted".to_string()),
            validation_results: vec![DnsValidationTraceOutput {
                selected: true,
                ..domestic_evidence
            }],
        };
        return Ok(serde_json::to_string_pretty(&output)?);
    }

    let egress_decision = candy_core::DnsRouteDecision {
        mode: DnsResolveMode::EgressCoherent,
        node_id: trace.decision.node_id.clone(),
        resolver_profile: "foreign-egress".to_string(),
        route_binding: trace
            .decision
            .node_id
            .clone()
            .map(DnsRouteBindingTarget::Node)
            .unwrap_or(DnsRouteBindingTarget::Deferred),
    };
    let request = build_dns_a_query(&trace.domain)?;
    let config = client_config_from_candy_snapshot_for_dns_probe(
        snapshot,
        trace.decision.node_id.as_deref(),
    )?;
    let response = probe(config, egress_dns, request, Duration::from_secs(2)).await?;
    let egress_answer = parse_dns_a_response(&response)?;
    let egress_evidence = validation_trace_from_answer(
        "egress-node",
        &egress_decision,
        trace.domain_class,
        &egress_answer,
        true,
    );
    if !egress_evidence.accepted {
        anyhow::bail!(
            "egress DNS answer for {} rejected: {}",
            trace.domain,
            egress_evidence
                .rejection_reason
                .as_deref()
                .unwrap_or("unknown")
        );
    }

    let answer_ips = egress_evidence.answer_ips.clone();
    let output = DnsTraceOutput {
        domain: trace.domain,
        domain_class: domain_class_label(trace.domain_class),
        resolve_mode: resolve_mode_label(trace.decision.mode),
        node_id: trace.decision.node_id,
        resolver_profile: trace.decision.resolver_profile,
        resolver_perspective: "parallel-validate",
        selected_perspective: Some("egress-node"),
        route_binding: egress_evidence.route_binding.clone(),
        answer_ip: answer_ips.first().cloned(),
        answer_ips,
        ttl_seconds: egress_evidence.ttl_seconds,
        cache_hit: false,
        answer_geo: egress_evidence.answer_geo,
        fallback_reason: Some("domestic-answer-not-cn".to_string()),
        validation_results: vec![
            domestic_evidence,
            DnsValidationTraceOutput {
                selected: true,
                ..egress_evidence
            },
        ],
    };
    Ok(serde_json::to_string_pretty(&output)?)
}

fn validation_trace_from_answer(
    resolver_perspective: &'static str,
    decision: &candy_core::DnsRouteDecision,
    domain_class: DomainClass,
    answer: &DnsResolverAnswer,
    selected: bool,
) -> DnsValidationTraceOutput {
    let answer_ips = answer
        .ips
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>();
    let (answer_geo, accepted, rejection_reason) = answer
        .ips
        .first()
        .copied()
        .map(
            |first_ip| match validate_dns_answer(domain_class, first_ip) {
                DnsAnswerValidation::Accept(geo) => (Some(answer_geo_label(geo)), true, None),
                DnsAnswerValidation::Reject(geo) => (
                    Some(answer_geo_label(geo)),
                    false,
                    Some(format!("rejected-answer-geo:{}", answer_geo_label(geo))),
                ),
            },
        )
        .unwrap_or((None, false, Some("no-answer".to_string())));
    DnsValidationTraceOutput {
        resolver_perspective,
        resolver_profile: decision.resolver_profile.clone(),
        node_id: decision.node_id.clone(),
        route_binding: route_binding_label(&decision.route_binding),
        answer_ip: answer_ips.first().cloned(),
        answer_ips,
        ttl_seconds: Some(answer.ttl_seconds),
        answer_geo,
        accepted,
        selected,
        rejection_reason,
    }
}

fn validation_trace_from_error(
    resolver_perspective: &'static str,
    decision: &candy_core::DnsRouteDecision,
    err: candy_core::DnsRuntimeError,
) -> DnsValidationTraceOutput {
    DnsValidationTraceOutput {
        resolver_perspective,
        resolver_profile: decision.resolver_profile.clone(),
        node_id: decision.node_id.clone(),
        route_binding: route_binding_label(&decision.route_binding),
        answer_ip: None,
        answer_ips: Vec::new(),
        ttl_seconds: None,
        answer_geo: None,
        accepted: false,
        selected: false,
        rejection_reason: Some(err.to_string()),
    }
}

fn client_config_from_candy_snapshot_for_dns_probe(
    snapshot: &RuntimeSnapshot,
    node_id: Option<&str>,
) -> Result<ClientConfig> {
    let node = match node_id {
        Some(node_id) => snapshot
            .nodes()
            .get(node_id)
            .ok_or_else(|| anyhow::anyhow!("node not found for DNS trace: {node_id}"))?,
        None => return client_config_from_candy_snapshot(snapshot),
    };
    client_config_from_runtime_node_for_dns_probe(snapshot, node)
}

fn client_config_from_runtime_node_for_dns_probe(
    snapshot: &RuntimeSnapshot,
    node: &RuntimeNode,
) -> Result<ClientConfig> {
    Ok(ClientConfig {
        server: node.server.parse()?,
        server_name: node.server_name.clone(),
        active_node_name: Some(node.name.clone()),
        server_identity: parse_server_identity_value(&node.pin, &node.server_name)?,
        ech: node
            .ech
            .as_deref()
            .map(ClientEchConfig::from_base64)
            .transpose()?,
        credentials: ClientCredentials {
            key_id: KeyId::new(node.key_id.clone()),
            secret: node.auth().as_bytes().to_vec(),
        },
        authentication: CandyClientAuthProfile::Standard,
        rules: snapshot.rules().clone(),
        dns_route_bindings: dns_route_bindings_for_snapshot(snapshot),
        performance_mode: snapshot.performance().mode,
        lane_mode: snapshot.performance().lanes,
        udp_redundancy: snapshot.performance().udp_redundancy,
        security: TransportSecurityProfile {
            alpn: snapshot.security().alpn.as_bytes().to_vec(),
            auth_failure_delay_ms: snapshot.security().auth_failure_delay_ms,
            control_padding: snapshot.security().control_padding,
            legacy_alpn_compatibility: snapshot.security().alpn_compatibility,
        },
        transport: carrier_transport::config::CandyTransportProfile::for_client(
            carrier_transport::config::ClientPlatform::Linux,
        ),
        forwards: Vec::new(),
        transparent_tcp: Vec::new(),
        transparent_udp: Vec::new(),
    })
}

struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(
        &self,
        query: &DnsResolverQuery,
    ) -> std::result::Result<DnsResolverAnswer, candy_core::DnsRuntimeError> {
        system_dns_resolve(query).map_err(|_| candy_core::DnsRuntimeError::NoAnswer {
            domain: query.domain.clone(),
            resolver_profile: query.resolver_profile.clone(),
        })
    }
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn system_dns_resolve(query: &DnsResolverQuery) -> Result<DnsResolverAnswer> {
    if query.qtype != DnsQtype::A {
        anyhow::bail!("system DNS trace currently supports A records only");
    }
    let server = system_nameserver().unwrap_or_else(|| "8.8.8.8:53".parse().unwrap());
    let request = build_dns_a_query(&query.domain)?;
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    socket.send_to(&request, server)?;
    let mut buf = [0u8; 1500];
    let (len, _) = socket.recv_from(&mut buf)?;
    parse_dns_a_response(&buf[..len])
}

fn system_nameserver() -> Option<std::net::SocketAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let addr = rest.split_whitespace().next()?;
        if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
            return Some(std::net::SocketAddr::new(ip, 53));
        }
    }
    None
}

fn build_dns_a_query(domain: &str) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&0x4344u16.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            anyhow::bail!("invalid DNS label in {domain}");
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Ok(packet)
}

fn parse_dns_a_response(packet: &[u8]) -> Result<DnsResolverAnswer> {
    if packet.len() < 12 {
        anyhow::bail!("truncated DNS response");
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x000f != 0 {
        anyhow::bail!("DNS response error: rcode={}", flags & 0x000f);
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(packet, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|next| *next <= packet.len())
            .ok_or_else(|| anyhow::anyhow!("truncated DNS question"))?;
    }

    let mut ips = Vec::new();
    let mut ttl_seconds = u32::MAX;
    for _ in 0..ancount {
        offset = skip_dns_name(packet, offset)?;
        if offset + 10 > packet.len() {
            anyhow::bail!("truncated DNS answer");
        }
        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            anyhow::bail!("truncated DNS rdata");
        }
        if rr_type == 1 && rr_class == 1 && rdlen == 4 {
            ips.push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            )));
            ttl_seconds = ttl_seconds.min(ttl);
        }
        offset += rdlen;
    }

    if ips.is_empty() {
        anyhow::bail!("DNS response had no A answers");
    }
    Ok(DnsResolverAnswer {
        ips,
        ttl_seconds: if ttl_seconds == u32::MAX {
            0
        } else {
            ttl_seconds
        },
    })
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Result<usize> {
    loop {
        if offset >= packet.len() {
            anyhow::bail!("truncated DNS name");
        }
        let len = packet[offset];
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= packet.len() {
                anyhow::bail!("truncated DNS compression pointer");
            }
            return Ok(offset + 2);
        }
        offset += 1;
        if len == 0 {
            return Ok(offset);
        }
        if len & 0xc0 != 0 {
            anyhow::bail!("unsupported DNS label");
        }
        offset = offset
            .checked_add(len as usize)
            .filter(|next| *next <= packet.len())
            .ok_or_else(|| anyhow::anyhow!("truncated DNS label"))?;
    }
}

fn domain_class_label(class: DomainClass) -> &'static str {
    match class {
        DomainClass::Domestic => "domestic",
        DomainClass::Foreign => "foreign",
        DomainClass::Video => "video",
        DomainClass::Cdn => "cdn",
        DomainClass::Google => "google",
        DomainClass::Apple => "apple",
        DomainClass::Bootstrap => "bootstrap",
        DomainClass::Private => "private",
        DomainClass::DirectCn => "direct-cn",
        DomainClass::Sensitive => "sensitive",
        DomainClass::Unknown => "unknown",
    }
}

fn answer_geo_label(geo: AnswerGeo) -> &'static str {
    match geo {
        AnswerGeo::China => "china",
        AnswerGeo::Foreign => "foreign",
        AnswerGeo::Private => "private",
        AnswerGeo::Reserved => "reserved",
        AnswerGeo::Unknown => "unknown",
    }
}

fn resolve_mode_label(mode: DnsResolveMode) -> &'static str {
    match mode {
        DnsResolveMode::Local => "local",
        DnsResolveMode::Remote => "remote",
        DnsResolveMode::EgressCoherent => "egress-coherent",
        DnsResolveMode::ParallelValidate => "parallel-validate",
        DnsResolveMode::Reject => "reject",
    }
}

fn route_binding_label(binding: &DnsRouteBindingTarget) -> String {
    match binding {
        DnsRouteBindingTarget::Direct => "direct".to_string(),
        DnsRouteBindingTarget::Reject => "reject".to_string(),
        DnsRouteBindingTarget::Node(node) => format!("node:{node}"),
        DnsRouteBindingTarget::Deferred => "deferred".to_string(),
    }
}

fn parse_gfwlist_domains(text: &str) -> Result<Vec<String>> {
    Ok(parse_gfwlist_provider("gfwlist", text)?.domains().to_vec())
}

fn read_provider_from_url(url: &str) -> Result<String> {
    if let Some(path) = url.strip_prefix("file://") {
        return Ok(std::fs::read_to_string(path)?);
    }

    for (program, args) in [
        ("uclient-fetch", vec!["-q", "-O", "-", url]),
        ("wget", vec!["-qO-", url]),
        ("curl", vec!["-fsSL", url]),
    ] {
        let Ok(output) = Command::new(program).args(args).output() else {
            continue;
        };
        if output.status.success() {
            return Ok(String::from_utf8(output.stdout)?);
        }
    }
    anyhow::bail!("failed to download provider from {url}");
}

fn atomic_write(path: &std::path::Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp_path, data)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn withdraw_startup_readiness(path: Option<PathBuf>) -> Result<()> {
    if let Some(path) = path.filter(|path| !path.as_os_str().is_empty()) {
        withdraw_client_readiness(&path)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(command) = args.command.as_ref() {
        match command {
            CommandKind::CoreInfo => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&core_manifest())?
                );
                return Ok(());
            }
            CommandKind::Status { path } => {
                let status = read_passive_status(path)?;
                println!("{}", serde_json::to_string(&status)?);
                return Ok(());
            }
            _ => {}
        }
    }

    withdraw_startup_readiness(std::env::var_os("CANDY_READY_FILE").map(PathBuf::from))?;
    tracing_subscriber::fmt::init();
    if let Some(command) = args.command {
        match command {
            CommandKind::CoreInfo | CommandKind::Status { .. } => {
                unreachable!("informational commands return before startup")
            }
            CommandKind::Geo(GeoCommand::Update {
                provider,
                url,
                output,
            }) => {
                let summary = update_geo_provider(&provider, &url, &output)?;
                println!(
                    "updated {provider}: {} entries -> {}",
                    summary.entry_count,
                    output.display()
                );
                return Ok(());
            }
            CommandKind::Dns(DnsCommand::Update {
                provider,
                url,
                output,
            }) => {
                let summary = update_dns_provider(&provider, &url, &output)?;
                println!(
                    "updated {provider}: {} entries -> {}",
                    summary.entry_count,
                    output.display()
                );
                return Ok(());
            }
            CommandKind::Dns(DnsCommand::Trace {
                domain,
                node,
                egress_dns,
            }) => {
                if let Some(config) = args.config.as_ref() {
                    if args.format != "candy-json" {
                        anyhow::bail!("dns trace with --config requires --format candy-json");
                    }
                    let text = std::fs::read_to_string(config)?;
                    let snapshot = parse_candy_config(&text)?;
                    let egress_dns = parse_target(&egress_dns)?;
                    println!(
                        "{}",
                        render_dns_trace_json_for_snapshot_via_egress(
                            &snapshot, &domain, node, egress_dns
                        )
                        .await?
                    );
                } else {
                    println!("{}", render_dns_trace_json(&domain, node)?);
                }
                return Ok(());
            }
            CommandKind::Reload {
                control_socket,
                candidate,
                active,
                sha256,
                expected_generation,
            } => {
                #[cfg(unix)]
                {
                    let request = ReloadControlRequest {
                        candidate_path: candidate,
                        active_path: active,
                        candidate_sha256: normalize_sha256(&sha256)
                            .map_err(|error| anyhow::anyhow!(error.message))?,
                        expected_generation,
                    };
                    let ack = submit_reload_request(&control_socket, &request).await?;
                    println!("{}", serde_json::to_string(&ack)?);
                    anyhow::ensure!(
                        ack.ok,
                        "reload rejected: {}",
                        ack.message.as_deref().unwrap_or("unknown error")
                    );
                    return Ok(());
                }
                #[cfg(not(unix))]
                {
                    let _ = (
                        control_socket,
                        candidate,
                        active,
                        sha256,
                        expected_generation,
                    );
                    anyhow::bail!("reload control socket is only available on Unix platforms");
                }
            }
            CommandKind::CongestionTest {
                samples,
                max_bytes,
                timeout_ms,
            } => {
                let config = args
                    .config
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("--config is required for congestion-test"))?;
                anyhow::ensure!(
                    args.format == "candy-json",
                    "congestion-test requires candy-json"
                );
                let snapshot = parse_candy_config(&std::fs::read_to_string(config)?)?;
                let platform = args
                    .platform
                    .as_deref()
                    .map(parse_candy_client_platform)
                    .transpose()?
                    .unwrap_or(carrier_transport::config::ClientPlatform::Linux);
                let result = run_congestion_test(
                    &snapshot,
                    platform,
                    samples,
                    max_bytes,
                    Duration::from_millis(timeout_ms),
                )
                .await?;
                println!("{}", serde_json::to_string(&result)?);
                return Ok(());
            }
        }
    }
    let config = args
        .config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--config is required unless a subcommand is used"))?;
    let text = std::fs::read_to_string(config)?;

    match args.format.as_str() {
        format if format == "candy-toml" || format == LEGACY_TOML_FORMAT => {
            // legacy compatibility alias
            if args.render_runtime {
                anyhow::bail!("render-runtime is only available for candy-json config");
            }
            let (config, file_policy) = parse_carrying_config_with_policy(&text)?;
            let policy = resolve_client_policy(&args.client_policy, Some(&file_policy))?;
            if args.check_config {
                println!("config ok");
                return Ok(());
            }
            run_client_with_reconnect_policy_and_passive_status(
                config,
                policy,
                args.passive_status_path.clone(),
            )
            .await
        }
        "candy-json" => {
            let policy = resolve_client_policy(&args.client_policy, None)?;
            if args.check_config || args.render_runtime {
                let snapshot = parse_candy_config(&text)?;
                if args.check_config {
                    println!("config ok");
                }
                if args.render_runtime {
                    render_runtime(&snapshot);
                }
                return Ok(());
            }
            let snapshot = parse_candy_config(&text)?;
            let platform = args
                .platform
                .as_deref()
                .map(parse_candy_client_platform)
                .transpose()?
                .unwrap_or(carrier_transport::config::ClientPlatform::Linux);
            let mut transport_profile =
                carrier_transport::config::CandyTransportProfile::for_client(platform);
            if let Some(congestion) = args.congestion {
                transport_profile.congestion = congestion.into();
            }
            transport_profile.candy_bbr_preset = args.candy_bbr_preset.into();
            transport_profile.automatic_bbr_fallback = args.automatic_bbr_fallback;
            #[cfg(unix)]
            if let Some(control_socket_path) = args.control_socket_path.clone() {
                let (reload_sender, reload_receiver) = runtime_reload_channel(1);
                let server_sender = reload_sender.clone();
                let runtime = run_multinode_client_with_runtime_reload(
                    snapshot,
                    policy,
                    args.passive_status_path.clone(),
                    transport_profile,
                    Some(reload_receiver),
                );
                let control = run_reload_control_server(
                    control_socket_path,
                    move |candidate, cancellation| {
                        let sender = server_sender.clone();
                        async move { submit_validated_reload(sender, candidate, cancellation).await }
                    },
                );
                return tokio::try_join!(runtime, control).map(|_| ());
            }
            run_multinode_client_with_reconnect_policy_and_passive_status(
                snapshot,
                policy,
                args.passive_status_path.clone(),
                transport_profile,
            )
            .await
        }
        other => anyhow::bail!("unknown format: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELOAD_TEST_CONFIG: &str = r#"{
  "name": "reload-test",
  "mode": "rule",
  "dns": { "remote": true },
  "nodes": [
    {
      "name": "hk-1",
      "server": "203.0.113.10:18443",
      "auth": "super-secret-token",
      "pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "groups": [
    { "name": "Proxy", "type": "select", "nodes": ["hk-1"] }
  ],
  "rules": ["MATCH,Proxy"],
  "forwards": []
}"#;

    fn reload_test_path(label: &str) -> PathBuf {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "candy-reload-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn reload_test_sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn passive_status_test_file(label: &str, bytes: &[u8]) -> PathBuf {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "candy-cli-passive-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    #[cfg(unix)]
    fn reload_candidate_is_validated_from_nofollow_file_descriptor() {
        let path = reload_test_path("candidate.json");
        std::fs::write(&path, RELOAD_TEST_CONFIG).unwrap();
        let sha256 = reload_test_sha256(RELOAD_TEST_CONFIG.as_bytes());
        let candidate = read_reload_candidate(ReloadControlRequest {
            candidate_path: path.clone(),
            active_path: path.with_file_name("runtime.json"),
            candidate_sha256: sha256.clone().to_ascii_uppercase(),
            expected_generation: 7,
        })
        .unwrap();

        assert_eq!(candidate.snapshot.name(), "reload-test");
        assert_eq!(candidate.config_sha256.to_hex(), sha256);
        assert_eq!(candidate.expected_generation, 7);

        let symlink = reload_test_path("candidate-link.json");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        let error = read_reload_candidate(ReloadControlRequest {
            candidate_path: symlink.clone(),
            active_path: symlink.with_file_name("runtime.json"),
            candidate_sha256: reload_test_sha256(RELOAD_TEST_CONFIG.as_bytes()),
            expected_generation: 7,
        })
        .unwrap_err();
        assert_eq!(error.code, "candidate_open_failed");

        std::fs::remove_file(symlink).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_reload_control_command() {
        let args = Args::try_parse_from([
            "client-cli",
            "reload",
            "--control-socket",
            "/tmp/candy-control.sock",
            "--candidate",
            "/tmp/runtime.next.json",
            "--sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--expected-generation",
            "41",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(CommandKind::Reload {
                control_socket,
                candidate,
                expected_generation: 41,
                ..
            }) if control_socket.as_path() == std::path::Path::new("/tmp/candy-control.sock")
                && candidate.as_path() == std::path::Path::new("/tmp/runtime.next.json")
        ));
    }

    #[test]
    fn parses_manual_congestion_and_bbr_preset() {
        let args = Args::try_parse_from([
            "client-cli",
            "--config",
            "/tmp/runtime.json",
            "--format",
            "candy-json",
            "--congestion",
            "candy-bbr",
            "--candy-bbr-preset",
            "aggressive",
        ])
        .unwrap();
        assert!(matches!(args.congestion, Some(CliCongestion::CandyBbr)));
        assert!(matches!(args.candy_bbr_preset, CliBbrPreset::Aggressive));
        assert!(!args.automatic_bbr_fallback);
    }

    #[test]
    fn parses_bounded_congestion_test_command() {
        let args = Args::try_parse_from([
            "client-cli",
            "--config",
            "/tmp/runtime.json",
            "--format",
            "candy-json",
            "congestion-test",
            "--samples",
            "2",
            "--max-bytes",
            "1048576",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(CommandKind::CongestionTest {
                samples: 2,
                max_bytes: 1_048_576,
                ..
            })
        ));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn reload_control_socket_is_private_and_returns_typed_ack() {
        let directory = reload_test_path("control");
        let socket = directory.join("control.sock");
        let candidate_path = directory.join("runtime.next.json");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(&candidate_path, RELOAD_TEST_CONFIG).unwrap();
        let sha256 = reload_test_sha256(RELOAD_TEST_CONFIG.as_bytes());
        let (reload_sender, mut reload_receiver) = runtime_reload_channel(1);
        let expected_sha256 = sha256.clone();
        let manager = tokio::spawn(async move {
            let command = reload_receiver.recv().await.unwrap();
            assert_eq!(command.expected_generation, 11);
            assert_eq!(command.config_sha256.to_hex(), expected_sha256);
            assert_eq!(command.snapshot.name(), "reload-test");
            command
                .response
                .send(RuntimeReloadAck {
                    ok: true,
                    generation: 12,
                    mode: RuntimeReloadClass::HotPolicy,
                    duration_ms: 1,
                    error_code: None,
                    message: None,
                })
                .unwrap();
        });
        let server_socket = socket.clone();
        let server = tokio::spawn(run_reload_control_server(
            server_socket,
            move |candidate, cancellation| {
                let sender = reload_sender.clone();
                async move { submit_validated_reload(sender, candidate, cancellation).await }
            },
        ));
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(socket.exists(), "control socket was not created");
        let mode = std::fs::symlink_metadata(&socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let ack = submit_reload_request(
            &socket,
            &ReloadControlRequest {
                candidate_path: candidate_path.clone(),
                active_path: directory.join("runtime.json"),
                candidate_sha256: sha256,
                expected_generation: 11,
            },
        )
        .await
        .unwrap();
        assert!(ack.ok);
        assert_eq!(ack.generation, 12);
        assert_eq!(ack.mode, RuntimeReloadClass::HotPolicy);
        assert_eq!(ack.error_code, None);
        manager.await.unwrap();

        server.abort();
        let _ = server.await;
        assert!(!socket.exists(), "control socket guard did not clean up");
        std::fs::remove_file(candidate_path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn passive_status_command_does_not_require_network_configuration() {
        let args =
            Args::try_parse_from(["client-cli", "status", "--path", "/tmp/status.json"]).unwrap();
        assert!(args.config.is_none());
        assert!(matches!(
            args.command,
            Some(CommandKind::Status { path }) if path == std::path::Path::new("/tmp/status.json")
        ));
    }

    #[test]
    fn passive_status_reader_preserves_unavailable_values() {
        let path = passive_status_test_file(
            "nulls",
            br#"{"schema_version":1,"configured_intent":null,"applied_transport":null,"local":null,"peer":null,"fallback_reason":null,"updated_unix_ms":17}
"#,
        );
        let value = read_passive_status(&path).unwrap();
        assert!(value["local"].is_null());
        assert!(value["peer"].is_null());
        assert!(value["applied_transport"].is_null());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn passive_status_reader_accepts_multinode_schema_v2() {
        let path = passive_status_test_file(
            "multinode",
            br#"{"schema_version":2,"nodes":{"hk-1":{"state":"ready","url_test":{"status":"ok","latency_ms":42},"passive":{"local":{},"peer":{},"applied_transport":{}}}},"process":{},"updated_unix_ms":17}
"#,
        );

        let value = read_passive_status(&path).unwrap();

        assert_eq!(value["nodes"]["hk-1"]["url_test"]["latency_ms"], 42);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn passive_status_reader_rejects_wrong_schema_and_credential_fields() {
        for (label, bytes) in [
            (
                "schema",
                br#"{"schema_version":3,"configured_intent":null,"applied_transport":null,"local":null,"peer":null,"fallback_reason":null,"updated_unix_ms":17}"#.as_slice(),
            ),
            (
                "secret",
                br#"{"schema_version":1,"configured_intent":null,"applied_transport":null,"local":null,"peer":null,"fallback_reason":null,"updated_unix_ms":17,"credentials":"do-not-print"}"#.as_slice(),
            ),
        ] {
            let path = passive_status_test_file(label, bytes);
            assert!(read_passive_status(&path).is_err());
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn passive_status_reader_rejects_oversized_files() {
        let path = passive_status_test_file("oversized", &vec![b' '; MAX_PASSIVE_STATUS_BYTES + 1]);
        let error = read_passive_status(&path).unwrap_err().to_string();
        assert!(error.contains("too large"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn passive_status_reader_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let target = passive_status_test_file(
            "symlink-target",
            br#"{"schema_version":1,"configured_intent":null,"applied_transport":null,"local":null,"peer":null,"fallback_reason":null,"updated_unix_ms":17}"#,
        );
        let link = target.with_extension("link");
        symlink(&target, &link).unwrap();

        assert!(read_passive_status(&link).is_err());

        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(target).unwrap();
    }

    fn carrying_config_error(text: &str) -> String {
        match parse_carrying_config(text) {
            Ok(_) => panic!("configuration should be rejected"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn client_policy_cli_defaults_preserve_library_defaults() {
        let args = Args::try_parse_from(["client-cli", "--config", "client.json"]).unwrap();

        for file_policy in [None, Some(ClientPolicyOverrides::default())] {
            let policy = resolve_client_policy(&args.client_policy, file_policy.as_ref()).unwrap();
            assert_eq!(policy, carrier_client::ClientReconnectPolicy::default());
        }
    }

    #[test]
    fn client_policy_cli_explicit_values_apply_to_both_formats() {
        let args = Args::try_parse_from([
            "client-cli",
            "--config",
            "client.json",
            "--session-request-timeout-ms",
            "2500",
            "--max-local-sessions",
            "37",
            "--stable-reset-after-ms",
            "45000",
            "--max-connection-age-ms",
            "90000",
            "--max-connection-bytes",
            "1073741824",
        ])
        .unwrap();

        for file_policy in [None, Some(ClientPolicyOverrides::default())] {
            let policy = resolve_client_policy(&args.client_policy, file_policy.as_ref()).unwrap();
            assert_eq!(policy.session_request_timeout, Duration::from_millis(2500));
            assert_eq!(policy.max_local_sessions, 37);
            assert_eq!(policy.stable_reset_after, Duration::from_millis(45000));
            assert_eq!(policy.max_connection_age, Duration::from_millis(90000));
            assert_eq!(policy.max_connection_bytes, 1_073_741_824);
        }
    }

    #[test]
    fn legacy_toml_policy_values_are_parsed_and_cli_can_override_them() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"
session_request_timeout_ms = 3000
max_local_sessions = 64
stable_reset_after_ms = 60000
max_connection_age_ms = 120000
max_connection_bytes = 2147483648
"#;
        let (_config, file_policy) = parse_carrying_config_with_policy(text).unwrap();

        let file_resolved =
            resolve_client_policy(&ClientPolicyOverrides::default(), Some(&file_policy)).unwrap();
        assert_eq!(
            file_resolved.session_request_timeout,
            Duration::from_secs(3)
        );
        assert_eq!(file_resolved.max_local_sessions, 64);
        assert_eq!(file_resolved.stable_reset_after, Duration::from_secs(60));
        assert_eq!(file_resolved.max_connection_age, Duration::from_secs(120));
        assert_eq!(file_resolved.max_connection_bytes, 2_147_483_648);

        let cli = ClientPolicyOverrides {
            max_local_sessions: Some(8),
            ..ClientPolicyOverrides::default()
        };
        let overridden = resolve_client_policy(&cli, Some(&file_policy)).unwrap();
        assert_eq!(overridden.max_local_sessions, 8);
        assert_eq!(overridden.session_request_timeout, Duration::from_secs(3));
    }

    #[test]
    fn legacy_toml_transport_profile_and_overrides_are_applied() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"

[transport]
profile = "macos"
stream_priority_enabled = false
congestion = "candy-bbr"
"#;

        let config = parse_carrying_config(text).unwrap();

        assert_eq!(
            config.transport.platform,
            carrier_transport::config::CandyPlatform::MacOs
        );
        assert_eq!(config.transport.keep_alive, Some(Duration::from_secs(15)));
        assert!(!config.transport.stream_priority_enabled);
        assert_eq!(
            config.transport.congestion,
            carrier_transport::config::CongestionChoice::CandyBbr
        );
        assert_eq!(config.transport.initial_incoming_bidi, 0);
        assert_eq!(config.transport.incoming_uni, 0);
    }

    #[test]
    fn cloud_grant_authentication_is_loaded_from_inline_base64() {
        let device_key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let text = format!(
            r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
key_id = "00112233-4455-6677-8899-aabbccddeeff"
auth_profile = "cloud_grant_v1"

[cloud_auth]
grant_envelope_base64 = "AQID"
device_signing_key_base64 = "{device_key}"
"#
        );
        let config = parse_carrying_config(&text).unwrap();
        match config.authentication {
            CandyClientAuthProfile::CloudGrantV1 {
                grant_envelope,
                device_signing_key,
            } => {
                assert_eq!(grant_envelope, vec![1, 2, 3]);
                assert_eq!(device_signing_key, [7u8; 32]);
            }
            CandyClientAuthProfile::Standard => panic!("expected cloud auth profile"),
        }
    }

    #[test]
    fn cloud_grant_authentication_rejects_noncanonical_device_id() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
key_id = "00112233-4455-6677-8899-AABBCCDDEEFF"
auth_profile = "cloud_grant_v1"

[cloud_auth]
grant_envelope_base64 = "AQID"
device_signing_key_base64 = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
"#;
        let error = carrying_config_error(text);
        assert!(error.contains("canonical UUID"), "{error}");
    }

    #[test]
    fn standard_auth_rejects_accidental_cloud_secret_configuration() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"

[cloud_auth]
grant_envelope_base64 = "AQID"
device_signing_key_base64 = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
"#;
        let error = carrying_config_error(text);
        assert!(error.contains("requires auth_profile"), "{error}");
    }

    #[test]
    fn legacy_toml_parses_ech_and_rejects_malformed_values() {
        let valid = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
ech = "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA=="
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"
"#;
        assert!(parse_carrying_config(valid).unwrap().ech.is_some());

        let invalid = valid.replace(
            "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==",
            "not base64!",
        );
        let error = match parse_carrying_config(&invalid) {
            Ok(_) => panic!("malformed ECH config must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("invalid ECH base64"), "{error}");
    }

    #[test]
    fn client_policy_rejects_zero_max_connection_age() {
        let cli = ClientPolicyOverrides {
            max_connection_age_ms: Some(0),
            ..ClientPolicyOverrides::default()
        };

        let error = resolve_client_policy(&cli, None).unwrap_err().to_string();

        assert!(error.contains("max_connection_age_ms"), "{error}");
    }

    #[test]
    fn client_policy_rejects_zero_max_connection_bytes() {
        let cli = ClientPolicyOverrides {
            max_connection_bytes: Some(0),
            ..ClientPolicyOverrides::default()
        };

        let error = resolve_client_policy(&cli, None).unwrap_err().to_string();

        assert!(error.contains("max_connection_bytes"), "{error}");
    }

    #[test]
    fn client_policy_rejects_max_local_sessions_above_hard_open_bound() {
        let cli = ClientPolicyOverrides {
            max_local_sessions: Some(1_048_577),
            ..ClientPolicyOverrides::default()
        };

        let error = resolve_client_policy(&cli, None).unwrap_err().to_string();

        assert!(error.contains("1048576"), "{error}");
    }

    #[test]
    fn legacy_toml_accepts_explicit_webpki_identity() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "example.com"
server_identity = "webpki"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"
"#;

        let config = parse_carrying_config(text).unwrap();

        assert!(matches!(config.server_identity, ServerIdentity::WebPki));
    }

    #[test]
    fn legacy_toml_accepts_explicit_sha256_identity() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_identity = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"
"#;

        let config = parse_carrying_config(text).unwrap();

        assert!(matches!(
            config.server_identity,
            ServerIdentity::PinnedSha256(_)
        ));
    }

    #[test]
    fn legacy_toml_rejects_overlapping_listener_addresses() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_identity = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"

[[forwards]]
network = "udp"
local = "0.0.0.0:15353"
target = "8.8.8.8:53"

[[transparent_udp]]
local = "127.0.0.1:15353"
"#;

        let error = carrying_config_error(text);

        assert!(error.contains("conflicting UDP listener"), "{error}");
    }

    #[test]
    fn legacy_toml_rejects_both_identity_fields() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_identity = "webpki"
server_pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"
"#;

        let error = carrying_config_error(text);

        assert!(error.contains("server_identity"), "{error}");
        assert!(error.contains("server_pin"), "{error}");
    }

    #[test]
    fn legacy_toml_rejects_missing_identity() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"
"#;

        let error = carrying_config_error(text);

        assert!(error.contains("server_identity"), "{error}");
        assert!(error.contains("server_pin"), "{error}");
    }

    #[test]
    fn legacy_toml_rejects_webpki_without_server_name() {
        let text = r#"
server = "example.com:18443"
server_identity = "webpki"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"
"#;

        let error = carrying_config_error(text);

        assert!(error.contains("server_name"), "{error}");
    }

    #[test]
    fn startup_withdraws_stale_readiness_file() {
        let path =
            std::env::temp_dir().join(format!("candy-cli-ready-test-{}", std::process::id()));
        std::fs::write(&path, b"stale").unwrap();

        withdraw_startup_readiness(Some(path.clone())).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn parse_target_kinds() {
        assert_eq!(
            parse_target("127.0.0.1:80").unwrap(),
            Address::V4([127, 0, 0, 1], 80)
        );
        assert!(matches!(
            parse_target("[::1]:53").unwrap(),
            Address::V6(_, 53)
        ));
        assert_eq!(
            parse_target("example.com:80").unwrap(),
            Address::Domain("example.com".into(), 80)
        );
    }

    #[test]
    fn parses_transparent_tcp_forwards() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"

[[transparent_tcp]]
local = "127.0.0.1:12345"
"#;

        let config = parse_carrying_config(text).unwrap();

        assert_eq!(config.transparent_tcp.len(), 1);
        assert_eq!(
            config.transparent_tcp[0].local,
            "127.0.0.1:12345".parse().unwrap()
        );
    }

    #[test]
    fn parses_transparent_udp_forwards() {
        let text = r#"
server = "203.0.113.10:18443"
server_name = "localhost"
server_pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
key_id = "router-1"
secret = "secret-with-at-least-16-bytes"

[[transparent_udp]]
local = "0.0.0.0:12346"
"#;

        let config = parse_carrying_config(text).unwrap();

        assert_eq!(config.transparent_udp.len(), 1);
        assert_eq!(
            config.transparent_udp[0].local,
            "0.0.0.0:12346".parse().unwrap()
        );
    }

    #[test]
    fn parses_candy_json_for_check_config() {
        let text = r#"
{
  "name": "home-router",
  "mode": "rule",
  "dns": { "remote": true },
  "nodes": [
    {
      "name": "hk-1",
      "server": "203.0.113.10:18443",
      "auth": "super-secret-token",
      "pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "groups": [
    { "name": "Proxy", "type": "select", "nodes": ["hk-1"] }
  ],
  "rules": ["MATCH,Proxy"],
  "forwards": []
}
"#;

        let snapshot = parse_candy_config(text).unwrap();

        assert_eq!(snapshot.name(), "home-router");
        assert!(snapshot.dns().remote);
    }

    #[test]
    fn candy_json_rejects_webpki_without_explicit_server_name() {
        let text = r#"
{
  "name": "home-router",
  "mode": "rule",
  "nodes": [
    {
      "name": "hk-1",
      "server": "203.0.113.10:18443",
      "auth": "super-secret-token",
      "pin": "webpki"
    }
  ],
  "groups": [
    { "name": "Proxy", "type": "select", "nodes": ["hk-1"] }
  ],
  "rules": ["MATCH,Proxy"],
  "forwards": []
}
"#;

        let error = parse_candy_config(text).unwrap_err().to_string();

        assert!(error.contains("server_name"), "{error}");
    }

    #[test]
    fn candy_json_rejects_unsupported_dns_configuration_fields() {
        let base = serde_json::json!({
            "name": "dns-settings",
            "mode": "rule",
            "dns": {
                "mode": "smart",
                "cache": { "enabled": true, "max_entries": 64 },
                "split": { "enabled": true }
            },
            "nodes": [{
                "name": "hk-1",
                "server": "203.0.113.10:18443",
                "auth": "secret",
                "pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }],
            "groups": [{ "name": "Proxy", "type": "select", "nodes": ["hk-1"] }],
            "rules": ["MATCH,Proxy"]
        });

        let mut cases = Vec::new();
        let mut stale = base.clone();
        stale["dns"]["cache"]["stale_while_revalidate"] = false.into();
        cases.push(("stale_while_revalidate", stale));
        let mut ecs = base.clone();
        ecs["dns"]["ecs"] = serde_json::json!({
            "mode": "egress-subnet",
            "ipv4_prefix": 20,
            "ipv6_prefix": 48
        });
        cases.push(("ecs", ecs));
        let mut cname = base;
        cname["dns"]["split"]["cname_classify"] = false.into();
        cases.push(("cname_classify", cname));

        for (field, profile) in cases {
            let error = parse_candy_config(&profile.to_string())
                .expect_err("unsupported DNS field must be rejected")
                .to_string();
            assert!(error.contains("unknown field"), "{field}: {error}");
            assert!(error.contains(field), "{field}: {error}");
        }
    }

    #[test]
    fn parses_production_smart_dns_settings() {
        let text = r#"{
  "name": "dns-settings",
  "mode": "rule",
  "dns": {
    "mode": "smart",
    "cache": {
      "enabled": true,
      "max_entries": 64
    },
    "split": {
      "enabled": true,
      "unknown_strategy": "prefer-proxy",
      "answer_geo_validate": true,
      "bind_answers_to_route": true,
      "ttl_cap_seconds": 180,
      "negative_ttl_seconds": 30,
      "domestic_resolvers": ["system", "223.5.5.5:53"],
      "egress_resolver": "9.9.9.9:53",
      "bootstrap_resolvers": ["system", "1.1.1.1:53"]
    }
  },
  "nodes": [{
    "name": "hk-1",
    "server": "203.0.113.10:18443",
    "auth": "secret",
    "pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }],
  "groups": [{ "name": "Proxy", "type": "select", "nodes": ["hk-1"] }],
  "rules": ["MATCH,Proxy"]
}"#;

        let snapshot = parse_candy_config(text).unwrap();

        assert_eq!(snapshot.dns().cache.max_entries, 64);
        assert_eq!(snapshot.dns().split.ttl_cap_seconds, 180);
        assert_eq!(snapshot.dns().split.negative_ttl_seconds, 30);
        assert_eq!(
            snapshot.dns().split.domestic_resolvers,
            vec!["system".to_string(), "223.5.5.5:53".to_string()]
        );
        assert_eq!(snapshot.dns().split.egress_resolver, "9.9.9.9:53");
        assert_eq!(
            snapshot.dns().split.bootstrap_resolvers,
            vec!["system".to_string(), "1.1.1.1:53".to_string()]
        );
    }

    #[test]
    fn candy_runtime_render_redacts_auth() {
        let text = r#"
{
  "name": "home-router",
  "mode": "rule",
  "nodes": [
    {
      "name": "hk-1",
      "server": "203.0.113.10:18443",
      "auth": "super-secret-token",
      "pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "groups": [
    { "name": "Proxy", "type": "select", "nodes": ["hk-1"] }
  ],
  "rules": ["MATCH,Proxy"],
  "forwards": []
}
"#;

        let snapshot = parse_candy_config(text).unwrap();
        let rendered = format!("{snapshot:#?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret-token"));
    }

    #[test]
    fn candy_json_can_be_converted_to_transport_config() {
        let text = r#"
{
  "name": "home-router",
  "mode": "rule",
  "nodes": [
    {
      "name": "hk-1",
      "key_id": "router-1",
      "server": "203.0.113.10:18443",
      "server_name": "node.example.test",
      "auth": "super-secret-token",
      "pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "ech": "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA=="
    }
  ],
  "groups": [
    { "name": "Proxy", "type": "select", "nodes": ["hk-1"] }
  ],
  "security": {
    "alpn": "candy-private/1",
    "alpn_compatibility": false,
    "auth_failure_delay_ms": 10,
    "control_padding": true
  },
  "rules": ["MATCH,Proxy"],
  "forwards": [],
  "transparent_tcp": [{ "local": "0.0.0.0:12345" }],
  "transparent_udp": [{ "local": "0.0.0.0:12346" }]
}
"#;

        let config = parse_candy_transport_config(text).unwrap();

        assert_eq!(config.server_name, "node.example.test");
        assert_eq!(config.credentials.key_id.0, "router-1");
        assert!(config.ech.is_some());
        assert_eq!(config.security.alpn, b"candy-private/1");
        assert!(!config.security.legacy_alpn_compatibility);
        assert_eq!(config.security.auth_failure_delay_ms, 10);
        assert!(config.security.control_padding);
        assert_eq!(
            config.transparent_tcp[0].local,
            "0.0.0.0:12345".parse().unwrap()
        );
        assert_eq!(
            config.transparent_udp[0].local,
            "0.0.0.0:12346".parse().unwrap()
        );
    }

    #[test]
    fn parses_geo_update_command() {
        let args = Args::try_parse_from([
            "candy-client",
            "geo",
            "update",
            "cn-ip",
            "--url",
            "file:///tmp/cn-ip.cidr",
            "--output",
            "/etc/candy/rulesets/cn-ip.cidr",
        ])
        .unwrap();

        assert!(matches!(
            args.command,
            Some(CommandKind::Geo(GeoCommand::Update {
                provider,
                url,
                output,
            })) if provider == "cn-ip"
                && url == "file:///tmp/cn-ip.cidr"
                && output.as_path() == std::path::Path::new("/etc/candy/rulesets/cn-ip.cidr")
        ));
    }

    #[test]
    fn parses_dns_gfwlist_update_command() {
        let args = Args::try_parse_from([
            "candy-client",
            "dns",
            "update",
            "gfwlist",
            "--url",
            "file:///tmp/gfwlist.txt",
            "--output",
            "/etc/candy/rulesets/gfwlist.domains",
        ])
        .unwrap();

        assert!(matches!(
            args.command,
            Some(CommandKind::Dns(DnsCommand::Update {
                provider,
                url,
                output,
            })) if provider == "gfwlist"
                && url == "file:///tmp/gfwlist.txt"
                && output.as_path() == std::path::Path::new("/etc/candy/rulesets/gfwlist.domains")
        ));
    }

    #[test]
    fn parses_dns_trace_command() {
        let args = Args::try_parse_from([
            "candy-client",
            "dns",
            "trace",
            "rr1---sn.example.googlevideo.com",
            "--node",
            "us-la-1",
        ])
        .unwrap();

        assert!(matches!(
            args.command,
            Some(CommandKind::Dns(DnsCommand::Trace {
                domain,
                node,
                egress_dns
            }))
                if domain == "rr1---sn.example.googlevideo.com"
                    && node.as_deref() == Some("us-la-1")
                    && egress_dns == "8.8.8.8:53"
        ));
    }

    #[test]
    fn dns_trace_json_includes_route_decision() {
        let text = render_dns_trace_json(
            "rr1---sn.example.googlevideo.com",
            Some("us-la-1".to_string()),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(json["domain"], "rr1---sn.example.googlevideo.com");
        assert_eq!(json["domain_class"], "video");
        assert_eq!(json["resolve_mode"], "egress-coherent");
        assert_eq!(json["node_id"], "us-la-1");
        assert_eq!(json["resolver_profile"], "foreign-egress");
        assert_eq!(json["route_binding"], "node:us-la-1");
        assert_eq!(json["answer_geo"], serde_json::Value::Null);
        assert_eq!(json["fallback_reason"], serde_json::Value::Null);
    }

    #[test]
    fn dns_trace_json_uses_candy_profile_rules() {
        let mut provider = std::env::temp_dir();
        provider.push(format!(
            "candy-cli-trace-gfwlist-{}.txt",
            std::process::id()
        ));
        std::fs::write(&provider, "||google.com\n").unwrap();
        let text = format!(
            r#"{{
  "name": "home-router",
  "mode": "rule",
  "geo": {{
    "providers": [
      {{ "name": "gfwlist", "kind": "gfw-list", "path": "{}" }}
    ]
  }},
  "nodes": [
    {{
      "name": "hk-1",
      "server": "203.0.113.10:18443",
      "auth": "super-secret-token",
      "pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }}
  ],
  "groups": [
    {{ "name": "Proxy", "type": "select", "nodes": ["hk-1"] }}
  ],
  "rules": ["RULE-SET,gfwlist,Proxy", "MATCH,DIRECT"]
}}"#,
            provider.display()
        );
        let snapshot = parse_candy_config(&text).unwrap();

        let rendered = render_dns_trace_json_for_snapshot(
            &snapshot,
            "mail.google.com",
            Some("hk-1".to_string()),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["domain_class"], "foreign");
        assert_eq!(json["resolver_profile"], "foreign-egress");
        assert_eq!(json["route_binding"], "node:hk-1");
    }

    #[test]
    fn dns_trace_json_includes_resolution_evidence() {
        let text = r#"{
  "name": "home-router",
  "mode": "rule",
  "nodes": [
    {
      "name": "hk-1",
      "server": "203.0.113.10:18443",
      "auth": "super-secret-token",
      "pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "groups": [
    { "name": "Proxy", "type": "select", "nodes": ["hk-1"] }
  ],
  "rules": ["DOMAIN-SUFFIX,google.com,Proxy", "MATCH,DIRECT"]
}"#;
        let snapshot = parse_candy_config(text).unwrap();
        let resolver = candy_core::StaticDnsResolver::new().with_answer(
            "foreign-egress",
            "hk-1",
            "mail.google.com",
            vec!["8.8.8.8".parse().unwrap()],
            123,
        );

        let rendered = render_dns_trace_json_for_snapshot_with_resolver(
            &snapshot,
            "mail.google.com",
            Some("hk-1".to_string()),
            resolver,
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["answer_ip"], "8.8.8.8");
        assert_eq!(json["answer_ips"][0], "8.8.8.8");
        assert_eq!(json["ttl_seconds"], 123);
        assert_eq!(json["cache_hit"], false);
        assert_eq!(json["answer_geo"], "foreign");
        assert_eq!(json["route_binding"], "node:hk-1");
        assert_eq!(json["fallback_reason"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn dns_trace_json_uses_egress_probe_for_foreign_domains() {
        let text = r#"{
  "name": "home-router",
  "mode": "rule",
  "nodes": [
    {
      "name": "hk-1",
      "server": "203.0.113.10:18443",
      "auth": "super-secret-token",
      "pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "groups": [
    { "name": "Proxy", "type": "select", "nodes": ["hk-1"] }
  ],
  "rules": ["DOMAIN-SUFFIX,google.com,Proxy", "MATCH,DIRECT"]
}"#;
        let snapshot = parse_candy_config(text).unwrap();
        let rendered = render_dns_trace_json_for_snapshot_with_packet_probe(
            &snapshot,
            "mail.google.com",
            Some("hk-1".to_string()),
            Address::V4([9, 9, 9, 9], 53),
            |_config: ClientConfig, target: Address, packet: Vec<u8>, _timeout: Duration| async move {
                assert_eq!(target, Address::V4([9, 9, 9, 9], 53));
                Ok(dns_a_response_for_query(&packet, [8, 8, 4, 4], 321))
            },
        )
        .await
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["resolver_perspective"], "egress-node");
        assert_eq!(json["resolver_profile"], "foreign-egress");
        assert_eq!(json["answer_ip"], "8.8.4.4");
        assert_eq!(json["ttl_seconds"], 321);
        assert_eq!(json["route_binding"], "node:hk-1");
    }

    #[tokio::test]
    async fn dns_trace_parallel_validate_records_domestic_and_egress_evidence() {
        let text = r#"{
  "name": "home-router",
  "mode": "rule",
  "nodes": [
    {
      "name": "hk-1",
      "server": "203.0.113.10:18443",
      "auth": "super-secret-token",
      "pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "groups": [
    { "name": "Proxy", "type": "select", "nodes": ["hk-1"] }
  ],
  "rules": ["GEOIP,CN,DIRECT,no-resolve"]
}"#;
        let snapshot = parse_candy_config(text).unwrap();
        let resolver = candy_core::StaticDnsResolver::new().with_answer(
            "domestic",
            "direct",
            "unknown.example",
            vec!["8.8.8.8".parse().unwrap()],
            111,
        );

        let rendered = render_dns_trace_json_for_snapshot_with_resolver_and_packet_probe(
            &snapshot,
            "unknown.example",
            Some("hk-1".to_string()),
            Address::V4([9, 9, 9, 9], 53),
            resolver,
            |_config: ClientConfig, target: Address, packet: Vec<u8>, _timeout: Duration| async move {
                assert_eq!(target, Address::V4([9, 9, 9, 9], 53));
                Ok(dns_a_response_for_query(&packet, [8, 8, 4, 4], 222))
            },
        )
        .await
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["domain_class"], "unknown");
        assert_eq!(json["resolve_mode"], "parallel-validate");
        assert_eq!(json["selected_perspective"], "egress-node");
        assert_eq!(json["answer_ip"], "8.8.4.4");
        assert_eq!(json["ttl_seconds"], 222);
        assert_eq!(json["route_binding"], "node:hk-1");
        assert_eq!(json["validation_results"].as_array().unwrap().len(), 2);
        assert_eq!(
            json["validation_results"][0]["resolver_perspective"],
            "system-local"
        );
        assert_eq!(
            json["validation_results"][0]["resolver_profile"],
            "domestic"
        );
        assert_eq!(json["validation_results"][0]["answer_ip"], "8.8.8.8");
        assert_eq!(json["validation_results"][0]["selected"], false);
        assert_eq!(
            json["validation_results"][1]["resolver_perspective"],
            "egress-node"
        );
        assert_eq!(
            json["validation_results"][1]["resolver_profile"],
            "foreign-egress"
        );
        assert_eq!(json["validation_results"][1]["answer_ip"], "8.8.4.4");
        assert_eq!(json["validation_results"][1]["selected"], true);
    }

    fn dns_a_response_for_query(query: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&query[0..2]);
        packet.extend_from_slice(&0x8180u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&query[12..]);
        packet.extend_from_slice(&0xc00cu16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&ip);
        packet
    }

    #[test]
    fn dns_gfwlist_update_decodes_and_writes_unique_domains_atomically() {
        let mut source = std::env::temp_dir();
        source.push(format!(
            "candy-cli-gfwlist-source-{}.txt",
            std::process::id()
        ));
        let mut output = std::env::temp_dir();
        output.push(format!(
            "candy-cli-gfwlist-output-{}.domains",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&output);
        std::fs::write(
            &source,
            "W0F1dG9Qcm94eSAwLjIuOV0KIQp8fGdvb2dsZS5jb20KQEB8fHdoaXRlbGlzdGVkLmV4YW1wbGUKfGh0dHA6Ly9pbWcuZXhhbXBsZS5uZXQvcGF0aAovcmVnZXgvCnR3aXR0ZXIuY29tLyoK",
        )
        .unwrap();

        let summary =
            update_dns_provider("gfwlist", &format!("file://{}", source.display()), &output)
                .unwrap();

        assert_eq!(summary.entry_count, 3);
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            "google.com\nimg.example.net\ntwitter.com\n"
        );
    }

    #[test]
    fn geo_update_validates_and_writes_provider_atomically() {
        let mut source = std::env::temp_dir();
        source.push(format!("candy-cli-source-{}.cidr", std::process::id()));
        let mut output = std::env::temp_dir();
        output.push(format!("candy-cli-output-{}.cidr", std::process::id()));
        let _ = std::fs::remove_file(&output);
        std::fs::write(&source, "# cn\n1.0.1.0/24\n").unwrap();

        let summary =
            update_geo_provider("cn-ip", &format!("file://{}", source.display()), &output).unwrap();

        assert_eq!(summary.entry_count, 1);
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            "# cn\n1.0.1.0/24\n"
        );
    }
}
