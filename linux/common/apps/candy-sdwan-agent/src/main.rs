use anyhow::{bail, Context, Result};
use candy_netd_client::{IpcError, NetdClient};
use candy_netd_proto::{
    ErrorCode, FirewallPolicy, Ipv4Prefix, LeaseOwner, PrepareDeclaration, RouteDeclaration,
    RouteKind, UnderlayExclusion, UnderlayKind,
};
use clap::{Parser, ValueEnum};
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_DECLARATION_BYTES: u64 = 1024 * 1024;
const MIN_LEASE_MS: u64 = 5_000;
const MAX_LEASE_MS: u64 = 120_000;
const MIN_READINESS_TIMEOUT_MS: u64 = 1_000;
const MAX_READINESS_TIMEOUT_MS: u64 = 120_000;
const MAX_STATUS_BYTES: u64 = 256 * 1024;
// A connected QUIC lane can briefly rewrite/remove its readiness report while
// reconnecting.  Once netd has committed SD-WAN, keep the Core and its dialers
// alive during that hand-off instead of tearing down the whole data plane.
const CORE_READINESS_RECOVERY_GRACE: Duration = Duration::from_secs(20);
const PARTIAL_ROUTE_RETRY_LOG_INTERVAL: Duration = Duration::from_secs(30);
const MAX_ACTIVATION_BYTES: u64 = 64 * 1024;
const CORE_TERMINATION_GRACE: Duration = Duration::from_secs(15);
const RETRY_INITIAL_DELAY: Duration = Duration::from_secs(1);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(30);
const RETRY_STABLE_RESET: Duration = Duration::from_secs(60);
const RETRY_POLL_INTERVAL: Duration = Duration::from_millis(100);
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

fn sanitize_log_value(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\n' | '\r' | '\t' => ' ',
            character if character.is_control() => '?',
            character => character,
        })
        .collect()
}

fn netd_reconfigure_error_code(error: &IpcError) -> &'static str {
    match error {
        IpcError::Remote(ErrorCode::InvalidRequest) | IpcError::InvalidTransition => {
            "netd_reconfigure_invalid_transition"
        }
        IpcError::Remote(ErrorCode::GenerationConflict) => "netd_reconfigure_owner_conflict",
        IpcError::Remote(ErrorCode::PreflightFailed) => "netd_reconfigure_platform_failed",
        IpcError::Remote(ErrorCode::UnauthorizedPeer) => "netd_reconfigure_unauthorized",
        IpcError::Remote(ErrorCode::SystemFailure) => "netd_reconfigure_system_failed",
        // netd closes the per-request Unix socket after a daemon restart or
        // transaction rollback.  Keep this distinct from a platform failure;
        // callers can safely retry the same generation after reconnecting.
        IpcError::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            "netd_reconfigure_peer_closed"
        }
        _ => "netd_reconfigure_ipc_failed",
    }
}

#[cfg(test)]
static RUN_TEST_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

#[derive(Parser, Debug)]
#[command(
    name = "candy-sdwan-agent",
    version,
    about = "Candy SD-WAN transaction agent"
)]
struct Args {
    #[command(subcommand)]
    command: Option<CommandKind>,
    #[arg(long, global = true, default_value = "/var/run/candy-netd/netd.sock")]
    socket: PathBuf,
    #[arg(long, global = true)]
    core: Option<PathBuf>,
    /// Cloud-published candidate symlink. When present, all security-critical
    /// launch values are derived from its immutable activation descriptor.
    #[arg(long, global = true)]
    activation: Option<PathBuf>,
    #[arg(long, global = true)]
    activation_ready: Option<PathBuf>,
    #[arg(long, global = true)]
    ordinary_config: Option<PathBuf>,
    #[arg(long, global = true, value_enum)]
    core_role: Option<CoreRole>,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true)]
    declaration: Option<PathBuf>,
    /// Runtime-owned status file passed through to the Core process.
    #[arg(long, global = true)]
    status: Option<PathBuf>,
    #[arg(long, global = true)]
    instance_id: Option<String>,
    #[arg(long, global = true)]
    generation: Option<u64>,
    #[arg(long, global = true, default_value_t = 30_000)]
    lease_ms: u64,
    #[arg(long, global = true, default_value_t = 20_000)]
    readiness_timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
enum CoreRole {
    ClientSdwan,
    Server,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActivationDescriptor {
    schema_version: u8,
    activation_id: String,
    delivery_etag: String,
    delivery_sha256: String,
    projection_publication_id: String,
    projection_content_hash: String,
    segment_generation: u64,
    projection_generation: u64,
    core_role: CoreRole,
    core_config: String,
    netd_declaration: String,
    grant_refresh_after_unix: u64,
    grant_expires_at_unix: u64,
}

#[derive(Clone, Debug)]
struct RuntimeArgs {
    socket: PathBuf,
    core: PathBuf,
    core_role: CoreRole,
    config: PathBuf,
    declaration: PathBuf,
    status: PathBuf,
    instance_id: String,
    generation: u64,
    lease_ms: u64,
    readiness_timeout_ms: u64,
    activation_link: Option<PathBuf>,
    activation_target: Option<PathBuf>,
    activation_descriptor: Option<ActivationDescriptor>,
    activation_config_sha256: Option<[u8; 32]>,
    activation_declaration_sha256: Option<[u8; 32]>,
    activation_ready: Option<PathBuf>,
    ordinary_config: Option<PathBuf>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CoreReloadRequest<'a> {
    schema_version: u16,
    action: CoreReloadAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_id: Option<&'a str>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CoreReloadAction {
    Prepare,
    Commit,
    Abort,
    Suspend,
    Resume,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReloadResponse {
    schema_version: u16,
    ok: bool,
    generation: Option<u64>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivationReadyReceipt {
    schema_version: u8,
    activation_id: String,
    candidate_target: String,
    generation: u64,
    agent_pid: u32,
    state: &'static str,
    error_code: Option<&'static str>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RuntimeFailureMarker {
    schema_version: u8,
    generation: u64,
    error_code: String,
}

#[derive(clap::Subcommand, Debug)]
enum CommandKind {
    Run,
    ValidateActivation {
        #[arg(long)]
        activation: PathBuf,
        #[arg(long, value_enum)]
        expected_core_role: CoreRole,
        #[arg(long)]
        ordinary_config: Option<PathBuf>,
    },
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct JsonDeclaration {
    table_id: u32,
    overlay_router_ipv4: String,
    effective_mtu: u16,
    routes: Vec<JsonRoute>,
    exclusions: Vec<JsonExclusion>,
    firewall: JsonFirewall,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct JsonRoute {
    prefix: String,
    kind: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct JsonExclusion {
    prefix: String,
    kind: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct JsonFirewall {
    allow_forward: bool,
    clamp_tcp_mss: bool,
    require_ipv4_forwarding: bool,
    manage_rp_filter: bool,
}

#[derive(Deserialize, Debug)]
struct CoreReadinessStatus {
    schema_version: u16,
    generation: u64,
    pid: u32,
    readiness_token: String,
    lifecycle: String,
    configured_peers: usize,
    active_peers: usize,
    required_route_owners: usize,
    ready_route_owners: usize,
    /// Exact route prefixes whose authenticated owner is currently missing.
    /// `None` means an older Core that cannot safely support scoped recovery.
    #[serde(default)]
    failed_prefixes: Option<Vec<String>>,
    #[serde(default)]
    inbound_listener_configured: bool,
    #[serde(default)]
    inbound_listener_ready: bool,
    #[serde(default)]
    inbound_listener_endpoints: Vec<String>,
    fail_open_required: bool,
    #[serde(default)]
    last_error_code: Option<String>,
    #[serde(default)]
    last_error_detail: Option<String>,
    #[serde(default)]
    paths: Option<Vec<CoreReadinessPath>>,
}

fn parse_failed_prefixes(
    status: &CoreReadinessStatus,
    declaration: &PrepareDeclaration,
) -> Result<Option<Vec<Ipv4Prefix>>> {
    let Some(values) = &status.failed_prefixes else {
        return Ok(None);
    };
    let mut prefixes = Vec::with_capacity(values.len());
    for value in values {
        let prefix = parse_prefix(value)
            .with_context(|| format!("Core reported invalid failed prefix {value}"))?;
        if !declaration
            .routes
            .iter()
            .any(|route| route.prefix == prefix)
        {
            bail!("Core reported failed prefix {value} outside netd declaration")
        }
        if !prefixes.contains(&prefix) {
            prefixes.push(prefix);
        }
    }
    Ok(Some(prefixes))
}

#[derive(Debug, Deserialize)]
struct CoreReadinessPath {
    rtt_sample_count: u64,
    #[serde(rename = "rx_bytes")]
    _rx_bytes: u64,
    #[serde(rename = "rx_idle_ms")]
    _rx_idle_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessState {
    Waiting,
    ListenerReady,
    Degraded,
    Ready,
    RecoverablePeerLoss,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessPolicy {
    Strict,
    /// The activation has already committed netd steering. Losing all
    /// authenticated peers is recoverable: keep the Core/dialers alive while
    /// steering is suspended, then resume when a peer returns.
    Committed,
    CommittedServer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessWait {
    Ready,
    ShutdownRequested,
}

fn parse_ipv4(value: &str) -> Result<[u8; 4]> {
    let mut octets = value.split('.');
    let result = [
        octets.next().context("invalid IPv4 address")?,
        octets.next().context("invalid IPv4 address")?,
        octets.next().context("invalid IPv4 address")?,
        octets.next().context("invalid IPv4 address")?,
    ];
    if octets.next().is_some() {
        bail!("invalid IPv4 address")
    }
    let mut out = [0; 4];
    for (idx, part) in result.into_iter().enumerate() {
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            bail!("non-canonical IPv4 address")
        }
        out[idx] = part.parse::<u8>().context("invalid IPv4 octet")?;
    }
    Ok(out)
}

fn parse_prefix(value: &str) -> Result<Ipv4Prefix> {
    let (address, length) = value.split_once('/').context("CIDR prefix is required")?;
    let prefix_len: u8 = length.parse().context("invalid CIDR prefix length")?;
    let address = parse_ipv4(address)?;
    Ipv4Prefix::new(address, prefix_len)
        .map_err(|_| anyhow::anyhow!("CIDR is not canonical or is invalid"))
}

fn route_kind(value: &str) -> Result<RouteKind> {
    match value {
        "local" => Ok(RouteKind::Local),
        "remote" => Ok(RouteKind::Remote),
        "remote-egress" => Ok(RouteKind::RemoteEgress),
        "remote-egress-gateway" => Ok(RouteKind::RemoteEgressGateway),
        _ => bail!("unknown route kind"),
    }
}

fn underlay_kind(value: &str) -> Result<UnderlayKind> {
    match value {
        "cloud-api" | "cloud_api" => Ok(UnderlayKind::CloudApi),
        "hub-endpoint" | "hub_endpoint" => Ok(UnderlayKind::HubEndpoint),
        "management" => Ok(UnderlayKind::Management),
        _ => bail!("unknown underlay kind"),
    }
}

fn parse_declaration(path: &PathBuf) -> Result<PrepareDeclaration> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("SD-WAN declaration is unavailable: {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("SD-WAN declaration must be a regular file")
    }
    if metadata.len() == 0 || metadata.len() > MAX_DECLARATION_BYTES {
        bail!("SD-WAN declaration size is invalid")
    }
    let bytes = fs::read(path).context("read SD-WAN declaration")?;
    let input: JsonDeclaration =
        serde_json::from_slice(&bytes).context("parse SD-WAN declaration")?;
    let declaration = PrepareDeclaration {
        table_id: input.table_id,
        overlay_router_ipv4: parse_ipv4(&input.overlay_router_ipv4)?,
        effective_mtu: input.effective_mtu,
        routes: input
            .routes
            .into_iter()
            .map(|route| {
                Ok(RouteDeclaration {
                    prefix: parse_prefix(&route.prefix)?,
                    kind: route_kind(&route.kind)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        exclusions: input
            .exclusions
            .into_iter()
            .map(|item| {
                Ok(UnderlayExclusion {
                    prefix: parse_prefix(&item.prefix)?,
                    kind: underlay_kind(&item.kind)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        firewall: FirewallPolicy {
            allow_forward: input.firewall.allow_forward,
            clamp_tcp_mss: input.firewall.clamp_tcp_mss,
            require_ipv4_forwarding: input.firewall.require_ipv4_forwarding,
            manage_rp_filter: input.firewall.manage_rp_filter,
        },
    };
    declaration
        .validate()
        .map_err(|_| anyhow::anyhow!("SD-WAN declaration failed protocol validation"))?;
    Ok(declaration)
}

fn parse_instance_id(value: &str) -> Result<[u8; 16]> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("instance id must be exactly 32 hexadecimal characters")
    }
    let mut result = [0_u8; 16];
    for index in 0..16 {
        result[index] = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    if result == [0; 16] {
        bail!("instance id cannot be zero")
    }
    Ok(result)
}

fn validate_lower_hex(value: &str, bytes: usize, label: &str) -> Result<()> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be exactly {bytes} bytes of lowercase hexadecimal")
    }
    Ok(())
}

fn validate_activation_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect activation file {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!(
            "activation file must be a bounded regular file: {}",
            path.display()
        )
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        bail!("activation file must have mode 0600: {}", path.display())
    }
    let effective_uid = unsafe { nix::libc::geteuid() };
    if metadata.uid() != effective_uid {
        bail!(
            "activation file has an unexpected owner: {}",
            path.display()
        )
    }
    fs::read(path).with_context(|| format!("read activation file {}", path.display()))
}

fn validate_ordinary_config(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect ordinary Candy Server config {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 1024 * 1024 {
        bail!("ordinary Candy Server config must be a bounded regular file")
    }
    let mode = metadata.permissions().mode() & 0o777;
    let effective_uid = unsafe { nix::libc::geteuid() };
    if !matches!(metadata.uid(), 0) && metadata.uid() != effective_uid {
        bail!("ordinary Candy Server config has an unexpected owner")
    }
    if !matches!(mode, 0o600 | 0o640) {
        bail!("ordinary Candy Server config must have mode 0600 or 0640")
    }
    File::open(path)
        .context("ordinary Candy Server config is not readable by the service identity")?;
    Ok(())
}

fn relative_activation_file(directory: &Path, value: &str, label: &str) -> Result<PathBuf> {
    let relative = Path::new(value);
    let mut components = relative.components();
    let name = match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => name,
        _ => bail!("{label} must be a single relative file name"),
    };
    let path = directory.join(name);
    validate_activation_file(&path, MAX_DECLARATION_BYTES)?;
    Ok(path)
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    Ok(Sha256::digest(
        fs::read(path).with_context(|| format!("read activation file {}", path.display()))?,
    )
    .into())
}

fn resolve_activation(link: &Path) -> Result<(ActivationDescriptor, PathBuf, PathBuf, PathBuf)> {
    let metadata = fs::symlink_metadata(link)
        .with_context(|| format!("inspect activation pointer {}", link.display()))?;
    if !metadata.file_type().is_symlink() {
        bail!("activation pointer must be a symbolic link")
    }
    let relative_target = fs::read_link(link).context("read activation pointer")?;
    let components = relative_target.components().collect::<Vec<_>>();
    if components.len() != 2
        || components[0] != Component::Normal("activations".as_ref())
        || !matches!(components[1], Component::Normal(_))
    {
        bail!("activation pointer must target activations/<activation-id>")
    }
    let target_name = components[1]
        .as_os_str()
        .to_str()
        .context("activation id is not UTF-8")?;
    validate_lower_hex(target_name, 32, "activation pointer id")?;
    let parent = link.parent().context("activation pointer has no parent")?;
    let directory = parent.join(&relative_target);
    let directory_metadata =
        fs::symlink_metadata(&directory).context("inspect immutable activation directory")?;
    if !directory_metadata.is_dir() || directory_metadata.file_type().is_symlink() {
        bail!("activation target must be a real directory")
    }
    if directory_metadata.permissions().mode() & 0o777 != 0o700 {
        bail!("activation target must have mode 0700")
    }
    let effective_uid = unsafe { nix::libc::geteuid() };
    if directory_metadata.uid() != effective_uid {
        bail!("activation target has an unexpected owner")
    }
    let descriptor_path = directory.join("activation-v1.json");
    let descriptor: ActivationDescriptor = serde_json::from_slice(&validate_activation_file(
        &descriptor_path,
        MAX_ACTIVATION_BYTES,
    )?)
    .context("parse activation descriptor")?;
    validate_lower_hex(&descriptor.activation_id, 32, "activation id")?;
    validate_lower_hex(&descriptor.delivery_sha256, 32, "delivery digest")?;
    validate_lower_hex(
        &descriptor.projection_content_hash,
        32,
        "projection content hash",
    )?;
    if descriptor.schema_version != 1
        || descriptor.activation_id != target_name
        || descriptor.delivery_etag != format!("\"sha256-{}\"", descriptor.delivery_sha256)
        || uuid::Uuid::parse_str(&descriptor.projection_publication_id).is_err()
        || descriptor.segment_generation == 0
        || descriptor.projection_generation == 0
        || descriptor.grant_refresh_after_unix > descriptor.grant_expires_at_unix
    {
        bail!("activation descriptor metadata is invalid")
    }
    let config = relative_activation_file(&directory, &descriptor.core_config, "Core config")?;
    let declaration =
        relative_activation_file(&directory, &descriptor.netd_declaration, "netd declaration")?;
    Ok((descriptor, relative_target, config, declaration))
}

fn resolve_runtime_args(args: Args) -> Result<RuntimeArgs> {
    let core = args.core.context("--core is required")?;
    if let Some(requested_activation) = args.activation.as_deref() {
        let link = if requested_activation
            .file_name()
            .and_then(|name| name.to_str())
            == Some("activation-v1.json")
        {
            requested_activation
                .parent()
                .context("activation descriptor has no candidate pointer parent")?
        } else {
            requested_activation
        };
        let (descriptor, relative_target, config, declaration) = resolve_activation(link)?;
        let config_sha256 = sha256_file(&config)?;
        let declaration_sha256 = sha256_file(&declaration)?;
        let ordinary_config = args.ordinary_config.clone();
        if descriptor.core_role == CoreRole::Server {
            let ordinary = ordinary_config
                .as_deref()
                .context("server activation requires --ordinary-config")?;
            validate_ordinary_config(ordinary)?;
        } else if args.ordinary_config.is_some() {
            bail!("ordinary-config is only valid for the server Core role")
        }
        return Ok(RuntimeArgs {
            socket: args.socket,
            core,
            core_role: descriptor.core_role,
            config,
            declaration,
            status: args.status.unwrap_or_else(|| {
                PathBuf::from(format!(
                    "/run/candy/sdwan-{}.status.json",
                    descriptor.activation_id
                ))
            }),
            instance_id: descriptor.activation_id[..32].to_owned(),
            generation: descriptor.projection_generation,
            lease_ms: args.lease_ms,
            readiness_timeout_ms: args.readiness_timeout_ms,
            activation_link: Some(link.to_path_buf()),
            activation_target: Some(relative_target),
            activation_descriptor: Some(descriptor),
            activation_config_sha256: Some(config_sha256),
            activation_declaration_sha256: Some(declaration_sha256),
            activation_ready: args.activation_ready,
            ordinary_config,
        });
    }
    Ok(RuntimeArgs {
        socket: args.socket,
        core,
        core_role: args.core_role.unwrap_or(CoreRole::ClientSdwan),
        config: args
            .config
            .context("--config or --activation is required")?,
        declaration: args
            .declaration
            .context("--declaration or --activation is required")?,
        status: args
            .status
            .context("--status or --activation is required")?,
        instance_id: args
            .instance_id
            .context("--instance-id or --activation is required")?,
        generation: args
            .generation
            .context("--generation or --activation is required")?,
        lease_ms: args.lease_ms,
        readiness_timeout_ms: args.readiness_timeout_ms,
        activation_link: None,
        activation_target: None,
        activation_descriptor: None,
        activation_config_sha256: None,
        activation_declaration_sha256: None,
        activation_ready: args.activation_ready,
        ordinary_config: None,
    })
}

fn monotonic_ms() -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        let uptime = fs::read_to_string("/proc/uptime").context("read monotonic clock")?;
        let seconds = uptime
            .split_whitespace()
            .next()
            .context("invalid monotonic clock")?
            .parse::<f64>()?;
        return Ok((seconds * 1000.0) as u64);
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("read fallback clock")?
            .as_millis()
            .try_into()
            .context("fallback clock overflow")
    }
}

fn clear_cloexec(fd: &OwnedFd) -> Result<()> {
    fcntl(fd.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty()))
        .context("clear TUN close-on-exec flag")?;
    Ok(())
}

/// Set OS resource limits appropriate for a constrained OpenWRT device.
/// Prevents the Core process from exhausting file descriptors or memory
/// and taking down the entire router.
fn set_resource_limits() -> Result<()> {
    // Raise the soft fd limit to a reasonable ceiling. Core with QUIC
    // connections can use dozens of fds; the default 1024 on OpenWRT is
    // often too low under load. 4096 is safe for typical WRT hardware.
    let mut rlim = nix::libc::rlimit {
        rlim_cur: 4096,
        rlim_max: 4096,
    };
    let rc = unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_NOFILE, &rlim) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!(
            "level=warn event=sdwan_rlimit_nofile_failed error={}",
            sanitize_log_value(&err.to_string())
        );
        // Non-fatal: the default limit may still work.
    }

    // Prevent the Core process from locking too much memory.
    rlim.rlim_cur = 64 * 1024 * 1024; // 64 MiB
    rlim.rlim_max = 64 * 1024 * 1024;
    let rc = unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_MEMLOCK, &rlim) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!(
            "level=warn event=sdwan_rlimit_memlock_failed error={}",
            sanitize_log_value(&err.to_string())
        );
    }

    Ok(())
}

fn spawn_core(args: &RuntimeArgs, tun: &OwnedFd, readiness_token: &str) -> Result<Child> {
    set_resource_limits()?;
    clear_cloexec(tun)?;
    let fd = tun.as_raw_fd().to_string();
    let mut command = Command::new(&args.core);
    match args.core_role {
        CoreRole::ClientSdwan => {
            command.args(["client", "sdwan", "run"]);
        }
        CoreRole::Server => {
            command.arg("server");
        }
    }
    command
        .arg("--config")
        .arg(&args.config)
        .arg("--tun-fd")
        .arg(fd)
        .arg("--status")
        .arg(&args.status)
        .arg("--readiness-token")
        .arg(readiness_token)
        .arg("--reload-socket")
        .arg(core_reload_socket(args)?)
        .spawn()
        .with_context(|| format!("start Candy Core: {}", args.core.display()))
}

fn core_reload_socket(args: &RuntimeArgs) -> Result<PathBuf> {
    Ok(args
        .status
        .parent()
        .context("Core status path has no parent")?
        .join("sdwan-core-reload.sock"))
}

fn reload_runtime_args(current: &RuntimeArgs) -> Result<RuntimeArgs> {
    let link = current
        .activation_link
        .as_deref()
        .context("hot reload requires a Cloud activation pointer")?;
    let (descriptor, relative_target, config, declaration) = resolve_activation(link)?;
    anyhow::ensure!(
        descriptor.core_role == current.core_role,
        "hot reload cannot change the Core role"
    );
    Ok(RuntimeArgs {
        socket: current.socket.clone(),
        core: current.core.clone(),
        core_role: current.core_role,
        activation_config_sha256: Some(sha256_file(&config)?),
        activation_declaration_sha256: Some(sha256_file(&declaration)?),
        config,
        declaration,
        status: current
            .status
            .parent()
            .context("Core status path has no parent")?
            .join(format!("sdwan-{}.status.json", descriptor.activation_id)),
        instance_id: descriptor.activation_id[..32].to_owned(),
        generation: descriptor.projection_generation,
        lease_ms: current.lease_ms,
        readiness_timeout_ms: current.readiness_timeout_ms,
        activation_link: current.activation_link.clone(),
        activation_target: Some(relative_target),
        activation_descriptor: Some(descriptor),
        activation_ready: current.activation_ready.clone(),
        ordinary_config: current.ordinary_config.clone(),
    })
}

fn request_core_control(
    args: &RuntimeArgs,
    child: &mut Child,
    netd: &mut NetdClient,
    action: CoreReloadAction,
) -> Result<()> {
    let mut next = Instant::now();
    request_core_transaction(args, child, action, None, || {
        renew_transition_lease(args, netd, &mut next)
    })
}

fn request_core_transaction(
    args: &RuntimeArgs,
    child: &mut Child,
    action: CoreReloadAction,
    transaction_id: Option<&str>,
    mut progress: impl FnMut() -> Result<()>,
) -> Result<()> {
    use std::io::{Read as _, Write as _};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    anyhow::ensure!(
        child.try_wait()?.is_none(),
        "Candy Core exited before hot reload"
    );
    let mut stream = UnixStream::connect(core_reload_socket(args)?)
        .context("connect Candy Core hot reload socket")?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = CoreReloadRequest {
        schema_version: 1,
        action,
        config: matches!(action, CoreReloadAction::Prepare).then_some(args.config.as_path()),
        status: matches!(action, CoreReloadAction::Prepare).then_some(args.status.as_path()),
        transaction_id,
    };
    stream.write_all(&serde_json::to_vec(&request)?)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        progress()?;
        anyhow::ensure!(
            Instant::now() < deadline,
            "Candy Core reload response timed out"
        );
        let mut buffer = [0_u8; 4096];
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                anyhow::ensure!(
                    response.len() + count <= 64 * 1024,
                    "Core reload response too large"
                );
                response.extend_from_slice(&buffer[..count]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let response: CoreReloadResponse =
        serde_json::from_slice(&response).context("parse Candy Core reload response")?;
    anyhow::ensure!(
        response.schema_version == 1,
        "unsupported Core reload response"
    );
    let generation_matches =
        !matches!(action, CoreReloadAction::Prepare | CoreReloadAction::Commit)
            || response.generation == Some(args.generation);
    if matches!(action, CoreReloadAction::Prepare) && !response.ok {
        if let Some(detail) = response
            .error
            .as_deref()
            .and_then(|error| error.strip_prefix("peer_preparation_pending:"))
        {
            return Err(anyhow::Error::new(CorePreparationPending(
                detail.trim().to_owned(),
            )));
        }
    }
    anyhow::ensure!(
        response.ok && generation_matches,
        "Candy Core rejected hot reload: {}",
        response.error.as_deref().unwrap_or("unknown error")
    );
    Ok(())
}

fn renew_transition_lease(
    args: &RuntimeArgs,
    netd: &mut NetdClient,
    next: &mut Instant,
) -> Result<()> {
    if Instant::now() >= *next {
        let deadline = monotonic_ms()?
            .checked_add(args.lease_ms)
            .context("transition lease overflow")?;
        netd.renew_lease(deadline)
            .context("renew netd lease during policy transition")?;
        *next = Instant::now() + Duration::from_millis((args.lease_ms / 3).max(1_000));
    }
    Ok(())
}

fn abort_core_preparation(args: &RuntimeArgs, child: &mut Child, id: &str) {
    // Abort is best effort and has a Core-side TTL. Do not spend another
    // response timeout here without renewing the still-active old lease.
    let result: Result<()> = (|| {
        anyhow::ensure!(child.try_wait()?.is_none(), "Core exited before abort");
        let mut stream = std::os::unix::net::UnixStream::connect(core_reload_socket(args)?)?;
        stream.set_write_timeout(Some(Duration::from_millis(250)))?;
        stream.write_all(&serde_json::to_vec(&CoreReloadRequest {
            schema_version: 1,
            action: CoreReloadAction::Abort,
            config: None,
            status: None,
            transaction_id: Some(id),
        })?)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("level=warn event=sdwan_policy_abort_pending transaction_id={} generation={} error={} action=expire_candidate",
            id, args.generation, sanitize_log_value(&format!("{error:#}")));
    }
}

fn generate_readiness_token() -> Result<String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .context("generate SD-WAN Core readiness token")?;
    let mut output = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(output)
}

fn remove_stale_status(path: &PathBuf) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                bail!("SD-WAN Core status path must be a regular file")
            }
            fs::remove_file(path).context("remove stale SD-WAN Core status")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect stale SD-WAN Core status"),
    }
    Ok(())
}

fn is_activation_status_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(activation_id) = name
        .strip_prefix("sdwan-")
        .and_then(|value| value.strip_suffix(".status.json"))
    else {
        return false;
    };
    activation_id.len() == 64
        && activation_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

// Each activation owns a distinct Core status file so a replacement cannot
// mistake an earlier Core's readiness for its own. The agent is the sole
// activation supervisor, therefore old files in this namespace are safe to
// reclaim once its current status has been removed before a new Core starts.
fn cleanup_superseded_activation_statuses(current: &Path) -> Result<usize> {
    let Some(directory) = current.parent() else {
        bail!("SD-WAN Core status path has no parent directory")
    };
    let Some(current_name) = current.file_name() else {
        bail!("SD-WAN Core status path has no file name")
    };
    if !is_activation_status_name(current_name) {
        return Ok(0);
    }

    let mut removed = 0;
    for entry in fs::read_dir(directory).context("list SD-WAN Core status directory")? {
        let entry = entry.context("inspect SD-WAN Core status directory entry")?;
        if entry.file_name() == current_name || !is_activation_status_name(&entry.file_name()) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect superseded SD-WAN Core status {}", path.display()))?;
        if !metadata.file_type().is_file() {
            eprintln!(
                "level=warn event=sdwan_status_cleanup_skipped path={} reason=not_regular_file",
                path.display()
            );
            continue;
        }
        fs::remove_file(&path)
            .with_context(|| format!("remove superseded SD-WAN Core status {}", path.display()))?;
        removed += 1;
    }
    Ok(removed)
}

fn remove_activation_receipt(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                bail!("activation receipt path must be a regular file")
            }
            fs::remove_file(path).context("remove activation receipt")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect activation receipt"),
    }
    Ok(())
}

fn write_activation_receipt(
    path: Option<&Path>,
    generation: u64,
    activation_id: Option<&str>,
    candidate_target: Option<&Path>,
    state: &'static str,
    error_code: Option<&'static str>,
) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let parent = path.parent().context("activation receipt has no parent")?;
    let metadata = fs::symlink_metadata(parent).context("inspect activation receipt directory")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("activation receipt directory must be a real directory")
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .context("activation receipt has no file name")?
            .to_string_lossy(),
        std::process::id()
    ));
    let (activation_id, candidate_target) = match (activation_id, candidate_target) {
        (Some(id), Some(target)) => (id.to_owned(), target.to_string_lossy().into_owned()),
        (None, None) => (String::new(), String::new()),
        _ => bail!("activation receipt requires both activation identity fields"),
    };
    if !matches!(
        (state, error_code),
        ("committed", None) | ("rejected", Some(_))
    ) {
        bail!("activation receipt result is invalid")
    }
    let bytes = serde_json::to_vec(&ActivationReadyReceipt {
        schema_version: 1,
        activation_id,
        candidate_target,
        generation,
        agent_pid: std::process::id(),
        state,
        error_code,
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("create activation receipt")?;
    let result = (|| {
        file.write_all(&bytes).context("write activation receipt")?;
        file.sync_all().context("sync activation receipt")?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        drop(file);
        fs::rename(&temporary, path).context("publish activation receipt")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("sync activation receipt directory")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_runtime_activation_receipt(
    args: &RuntimeArgs,
    state: &'static str,
    error_code: Option<&'static str>,
) -> Result<()> {
    write_activation_receipt(
        args.activation_ready.as_deref(),
        args.generation,
        args.activation_target
            .as_deref()
            .and_then(|target| target.file_name().and_then(|name| name.to_str())),
        args.activation_target.as_deref(),
        state,
        error_code,
    )
}

fn write_failed_activation_receipt(args: &RuntimeArgs, error_code: &'static str) -> Result<()> {
    if activation_pointer_unchanged(args)? {
        write_runtime_activation_receipt(args, "rejected", Some(error_code))
    } else {
        remove_activation_receipt(args.activation_ready.as_deref())
    }
}

fn runtime_failure_marker_path(status: &Path) -> Result<PathBuf> {
    let name = status
        .file_name()
        .context("Core status path has no file name")?
        .to_string_lossy();
    Ok(status.with_file_name(format!("{name}.error.json")))
}

fn write_runtime_failure_marker(args: &RuntimeArgs, error_code: &'static str) -> Result<()> {
    let path = runtime_failure_marker_path(&args.status)?;
    let parent = path
        .parent()
        .context("Runtime failure marker has no parent")?;
    let metadata = fs::symlink_metadata(parent).context("inspect Runtime status directory")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("Runtime status directory must be a real directory")
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .context("Runtime failure marker has no file name")?
            .to_string_lossy(),
        std::process::id()
    ));
    let bytes = serde_json::to_vec(&RuntimeFailureMarker {
        schema_version: 1,
        generation: args.generation,
        error_code: error_code.into(),
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("create Runtime failure marker")?;
    let result = (|| {
        file.write_all(&bytes)
            .context("write Runtime failure marker")?;
        file.sync_all().context("sync Runtime failure marker")?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        drop(file);
        fs::rename(&temporary, &path).context("publish Runtime failure marker")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("sync Runtime status directory")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_runtime_failure_marker(status: &Path) -> Result<()> {
    let path = runtime_failure_marker_path(status)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(path).context("remove Runtime failure marker")
        }
        Ok(_) => bail!("Runtime failure marker must be a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect Runtime failure marker"),
    }
}

fn activation_pointer_unchanged(args: &RuntimeArgs) -> Result<bool> {
    match (&args.activation_link, &args.activation_target) {
        (Some(link), Some(target)) => match fs::read_link(link) {
            Ok(current) => Ok(current == *target),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).context("read active candidate pointer"),
        },
        (None, None) => Ok(true),
        _ => bail!("incomplete activation pointer binding"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivationPointerState {
    Unchanged,
    Superseded,
    Withdrawn,
}

fn activation_pointer_state(args: &RuntimeArgs) -> Result<ActivationPointerState> {
    match (&args.activation_link, &args.activation_target) {
        (Some(link), Some(target)) => match fs::read_link(link) {
            Ok(current) if current == *target => Ok(ActivationPointerState::Unchanged),
            Ok(_) => Ok(ActivationPointerState::Superseded),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ActivationPointerState::Withdrawn)
            }
            Err(error) => Err(error).context("read active candidate pointer"),
        },
        (None, None) => Ok(ActivationPointerState::Unchanged),
        _ => bail!("incomplete activation pointer binding"),
    }
}

fn activation_binding_unchanged(args: &RuntimeArgs) -> Result<bool> {
    let (
        Some(link),
        Some(expected_target),
        Some(expected_descriptor),
        Some(expected_config_sha256),
        Some(expected_declaration_sha256),
    ) = (
        args.activation_link.as_deref(),
        args.activation_target.as_deref(),
        args.activation_descriptor.as_ref(),
        args.activation_config_sha256,
        args.activation_declaration_sha256,
    )
    else {
        return Ok(false);
    };
    if !activation_pointer_unchanged(args)? {
        return Ok(false);
    }
    let (descriptor, target, config, declaration) = resolve_activation(link)?;
    Ok(descriptor == *expected_descriptor
        && target == expected_target
        && config == args.config
        && declaration == args.declaration
        && sha256_file(&config)? == expected_config_sha256
        && sha256_file(&declaration)? == expected_declaration_sha256
        && descriptor.core_role == args.core_role
        && descriptor.projection_generation == args.generation)
}

fn activation_retry_eligible(args: &RuntimeArgs) -> Result<bool> {
    if !activation_binding_unchanged(args)? {
        return Ok(false);
    }
    let descriptor = args
        .activation_descriptor
        .as_ref()
        .context("retry requires an authenticated activation descriptor")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system time before SD-WAN retry")?
        .as_secs();
    Ok(grant_retry_eligible(descriptor, now))
}

fn grant_retry_eligible(descriptor: &ActivationDescriptor, now: u64) -> bool {
    (descriptor.grant_refresh_after_unix == 0 && descriptor.grant_expires_at_unix == 0)
        || descriptor.grant_expires_at_unix > now
}

fn validate_activation_command(
    activation: &Path,
    expected_core_role: CoreRole,
    ordinary_config: Option<&Path>,
) -> Result<()> {
    let link =
        if activation.file_name().and_then(|name| name.to_str()) == Some("activation-v1.json") {
            activation
                .parent()
                .context("activation descriptor has no candidate pointer parent")?
        } else {
            activation
        };
    let (descriptor, _, _, _) = resolve_activation(link)?;
    if descriptor.core_role != expected_core_role {
        bail!("activation Core role does not match the expected service role")
    }
    match (expected_core_role, ordinary_config) {
        (CoreRole::Server, Some(path)) => validate_ordinary_config(path),
        (CoreRole::Server, None) => bail!("server activation validation requires ordinary-config"),
        (CoreRole::ClientSdwan, Some(_)) => {
            bail!("ordinary-config is only valid for the server Core role")
        }
        (CoreRole::ClientSdwan, None) => Ok(()),
    }
}

fn read_core_readiness(
    path: &PathBuf,
    generation: u64,
    pid: u32,
    readiness_token: &str,
) -> Result<Option<ReadinessState>> {
    read_core_readiness_with_policy(
        path,
        generation,
        pid,
        readiness_token,
        ReadinessPolicy::Strict,
    )
}

fn read_core_readiness_with_policy(
    path: &PathBuf,
    generation: u64,
    pid: u32,
    readiness_token: &str,
    policy: ReadinessPolicy,
) -> Result<Option<ReadinessState>> {
    let Some(status) = read_core_status(path, generation, pid, readiness_token)? else {
        return Ok(None);
    };
    classify_core_readiness(&status, policy).map(Some)
}

fn read_core_status(
    path: &PathBuf,
    generation: u64,
    pid: u32,
    readiness_token: &str,
) -> Result<Option<CoreReadinessStatus>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect SD-WAN Core readiness status"),
    };
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_STATUS_BYTES {
        bail!("SD-WAN Core readiness status must be a bounded regular file")
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        bail!("SD-WAN Core readiness status must have mode 0600")
    }
    let status: CoreReadinessStatus =
        serde_json::from_slice(&fs::read(path).context("read SD-WAN Core readiness status")?)
            .context("parse SD-WAN Core readiness status")?;
    if status.schema_version != 3 || status.pid != pid || status.readiness_token != readiness_token
    {
        bail!("SD-WAN Core readiness status does not match the candidate process")
    }
    if status.generation < generation {
        // The status writer follows the routing actor asynchronously. An
        // authenticated report from this process for the previous generation
        // is not a rejection of the newly acknowledged policy.
        return Ok(None);
    }
    if status.generation > generation {
        bail!("SD-WAN Core readiness generation is newer than the requested activation")
    }
    if status.active_peers > status.configured_peers
        || status.ready_route_owners > status.active_peers
        || status.ready_route_owners > status.required_route_owners
    {
        bail!("SD-WAN Core readiness status has impossible peer counters")
    }
    Ok(Some(status))
}

fn classify_core_readiness(
    status: &CoreReadinessStatus,
    policy: ReadinessPolicy,
) -> Result<ReadinessState> {
    // Route-owner readiness is the lifecycle authority. Receive idleness is
    // telemetry freshness and must not restart an otherwise authenticated path.
    // A newly authenticated QUIC lane can legitimately have no received
    // payload bytes yet (for example, immediately after a peer reconnect or
    // while the route is idle).  RX bytes are telemetry, not an admission
    // requirement.  Use the Core-owned path inventory and RTT sample as the
    // authentication/readiness evidence; otherwise recovery is classified as
    // failed and the agent tears down the freshly restored lane again.
    let has_authenticated_path_evidence = status.paths.as_ref().is_some_and(|paths| {
        paths
            .iter()
            .filter(|path| path.rtt_sample_count > 0)
            .count()
            >= status.ready_route_owners
    });
    let listener_ready = status.inbound_listener_configured
        && status.inbound_listener_ready
        && !status.inbound_listener_endpoints.is_empty();
    // These errors describe loss of all peer lanes, not a broken Core/TUN
    // process.  Once an activation has committed, keep the dialers alive and
    // let the agent suspend only SD-WAN steering while peers reconnect.  In
    // particular, Core reports this condition with lifecycle="active" before
    // its status writer transitions to "failed"; treating only failed/starting
    // as recoverable caused the agent to tear down a perfectly recoverable
    // session under sustained traffic (the all_peer_lanes_unavailable loop).
    let recoverable_peer_loss_code = matches!(
        status.last_error_code.as_deref(),
        Some("all_peer_reads_failed" | "all_peer_writes_failed" | "route_has_no_active_peer")
    );
    let recoverable_committed_peer_loss =
        matches!(
            policy,
            ReadinessPolicy::Committed | ReadinessPolicy::CommittedServer
        ) && matches!(status.lifecycle.as_str(), "active" | "failed" | "starting")
            && status.fail_open_required
            && (policy == ReadinessPolicy::Committed || listener_ready)
            && status.configured_peers > 0
            && status.required_route_owners > 0
            && status.ready_route_owners == 0
            && recoverable_peer_loss_code;
    let recoverable_committed_partial_loss =
        matches!(
            policy,
            ReadinessPolicy::Committed | ReadinessPolicy::CommittedServer
        ) && matches!(status.lifecycle.as_str(), "active" | "failed" | "starting")
            && (policy == ReadinessPolicy::Committed || listener_ready)
            && status.required_route_owners > 1
            && status.ready_route_owners > 0
            && status.ready_route_owners < status.required_route_owners
            && has_authenticated_path_evidence
            && (!status.fail_open_required || recoverable_peer_loss_code);
    let state = match status.lifecycle.as_str() {
        "starting" if !status.fail_open_required && listener_ready => ReadinessState::ListenerReady,
        "starting" if !status.fail_open_required => ReadinessState::Waiting,
        "active"
            if !status.fail_open_required
                && status.required_route_owners > 0
                && status.ready_route_owners == status.required_route_owners
                && has_authenticated_path_evidence =>
        {
            ReadinessState::Ready
        }
        "active" | "failed" | "starting" if recoverable_committed_partial_loss => {
            ReadinessState::Degraded
        }
        "active"
            if !status.fail_open_required
                && status.required_route_owners > 0
                && status.ready_route_owners > 0
                && status.ready_route_owners < status.required_route_owners
                && has_authenticated_path_evidence
                && listener_ready =>
        {
            ReadinessState::Degraded
        }
        "active"
            if !status.fail_open_required
                && status.required_route_owners > 0
                && status.ready_route_owners > 0
                && status.ready_route_owners < status.required_route_owners
                && has_authenticated_path_evidence =>
        {
            ReadinessState::Waiting
        }
        "active" | "failed" | "starting" if recoverable_committed_peer_loss => {
            ReadinessState::RecoverablePeerLoss
        }
        "failed" | "stopping" | "stopped" => ReadinessState::Failed,
        "active"
            if status.fail_open_required
                || status.required_route_owners == 0
                || status.ready_route_owners == 0 =>
        {
            ReadinessState::Failed
        }
        _ => bail!("SD-WAN Core readiness status has an invalid lifecycle"),
    };
    if state == ReadinessState::Failed {
        let code = status.last_error_code.as_deref().unwrap_or("not_ready");
        if let Some(detail) = status.last_error_detail.as_deref() {
            bail!("SD-WAN Core candidate failed readiness: {code}: {detail}")
        }
        bail!("SD-WAN Core candidate failed readiness: {code}")
    }
    Ok(state)
}

fn wait_for_core_readiness(
    args: &RuntimeArgs,
    child: &mut Child,
    readiness_token: &str,
    netd: &mut NetdClient,
) -> Result<ReadinessWait> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(args.readiness_timeout_ms))
        .context("Core readiness deadline overflow")?;
    let renew_every = Duration::from_millis((args.lease_ms / 3).max(1_000));
    let mut next_renewal = Instant::now() + renew_every;
    loop {
        if shutdown_requested() {
            return Ok(ReadinessWait::ShutdownRequested);
        }
        if let Some(status) = child.try_wait().context("wait for candidate Candy Core")? {
            if shutdown_requested() {
                return Ok(ReadinessWait::ShutdownRequested);
            }
            // Preserve an authenticated Core rejection or malformed readiness
            // report as a hard failure. Only an exit without such evidence is
            // eligible for reconnect retry.
            read_core_readiness(&args.status, args.generation, child.id(), readiness_token)?;
            return Err(anyhow::Error::new(TransientReadinessFailure(format!(
                "Candy Core exited before SD-WAN readiness with status {}",
                status.code().unwrap_or(1)
            ))));
        }
        let readiness =
            read_core_readiness(&args.status, args.generation, child.id(), readiness_token)?;
        if shutdown_requested() {
            return Ok(ReadinessWait::ShutdownRequested);
        }
        if matches!(readiness, Some(ReadinessState::Ready))
            || (args.core_role == CoreRole::Server
                && matches!(readiness, Some(ReadinessState::Degraded)))
        {
            return Ok(ReadinessWait::Ready);
        }
        let server_listener_ready = args.core_role == CoreRole::Server
            && matches!(readiness, Some(ReadinessState::ListenerReady));
        // An authenticated server listener can be healthy before a peer is
        // connected. Keep Core alive in that phase so the peer's next dial can
        // complete; netd remains prepared but uncommitted until a route owner
        // is authenticated.
        if Instant::now() >= deadline && !server_listener_ready {
            return Err(anyhow::Error::new(TransientReadinessFailure(
                "Candy Core SD-WAN readiness timed out".into(),
            )));
        }
        if !activation_pointer_unchanged(args)? {
            bail!("Cloud candidate changed before Core route readiness")
        }
        if Instant::now() >= next_renewal {
            let renewed_deadline = monotonic_ms()?
                .checked_add(args.lease_ms)
                .context("prepared lease deadline overflow")?;
            netd.renew_lease(renewed_deadline)
                .context("renew prepared netd lease while waiting for Core")?;
            next_renewal = Instant::now() + renew_every;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

extern "C" fn request_shutdown(_signal: nix::libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

fn install_shutdown_handlers() -> Result<()> {
    let mut action: nix::libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = request_shutdown as *const () as usize;
    action.sa_flags = 0;
    unsafe {
        nix::libc::sigemptyset(&mut action.sa_mask);
        if nix::libc::sigaction(nix::libc::SIGTERM, &action, std::ptr::null_mut()) != 0
            || nix::libc::sigaction(nix::libc::SIGINT, &action, std::ptr::null_mut()) != 0
        {
            return Err(std::io::Error::last_os_error()).context("install shutdown handlers");
        }
    }
    Ok(())
}

fn stop_core(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let term_result =
        unsafe { nix::libc::kill(child.id() as nix::libc::pid_t, nix::libc::SIGTERM) };
    if term_result == 0 {
        let deadline = Instant::now() + CORE_TERMINATION_GRACE;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(error) => {
                    eprintln!(
                        "level=warn event=sdwan_core_stop_wait_failed error={}",
                        sanitize_log_value(&error.to_string())
                    );
                    break;
                }
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn rollback_or_report(netd: &mut NetdClient, cause: &str) -> Result<()> {
    netd.rollback()
        .map(|_| ())
        .with_context(|| format!("{cause}; netd rollback failed"))
}

#[cfg(not(test))]
fn spawn_ordinary_server(args: &RuntimeArgs) -> Result<Child> {
    let ordinary_config = args
        .ordinary_config
        .as_deref()
        .context("server fail-open requires the validated ordinary config")?;
    Command::new(&args.core)
        .args(["server", "--config"])
        .arg(ordinary_config)
        .spawn()
        .with_context(|| {
            format!(
                "start ordinary Candy Server after SD-WAN rollback: {}",
                args.core.display()
            )
        })
}

fn keep_server_fail_open(args: &RuntimeArgs, cause: &str) -> Result<()> {
    if shutdown_requested() {
        remove_activation_receipt(args.activation_ready.as_deref())?;
        eprintln!(
            "level=info event=sdwan_server_fail_open_skipped reason=shutdown_requested generation={}",
            args.generation
        );
        return Ok(());
    }
    eprintln!("level=warn event=sdwan_server_fail_open reason={cause} mode=ordinary_only");
    #[cfg(test)]
    {
        let ordinary_config = args
            .ordinary_config
            .as_deref()
            .context("server fail-open requires the validated ordinary config")?;
        bail!(
            "ordinary Candy Server fallback requested: core={} config={}",
            args.core.display(),
            ordinary_config.display()
        )
    }
    #[cfg(not(test))]
    {
        let mut child = spawn_ordinary_server(args)?;
        loop {
            if shutdown_requested() {
                stop_core(&mut child);
                remove_activation_receipt(args.activation_ready.as_deref())?;
                eprintln!(
                    "level=info event=sdwan_stopped generation={} phase=ordinary_fail_open rollback_ok=true",
                    args.generation
                );
                return Ok(());
            }
            match child
                .try_wait()
                .context("wait for ordinary Candy Server after SD-WAN rollback")?
            {
                Some(status) if status.success() => return Ok(()),
                Some(status) => bail!(
                    "ordinary Candy Server exited after SD-WAN rollback with status {}",
                    status.code().unwrap_or(1)
                ),
                None => thread::sleep(Duration::from_millis(50)),
            }
        }
    }
}

fn finish_shutdown_after_rollback(
    args: &RuntimeArgs,
    rollback: Result<()>,
    phase: &str,
) -> Result<()> {
    if let Err(rollback_error) = &rollback {
        eprintln!("level=error event=sdwan_rollback_failed error={rollback_error:#}");
    }
    rollback?;
    remove_activation_receipt(args.activation_ready.as_deref())?;
    eprintln!(
        "level=info event=sdwan_stopped generation={} phase={} rollback_ok=true",
        args.generation, phase
    );
    Ok(())
}

#[derive(Debug)]
struct RetryableFailure {
    error_code: &'static str,
    detail: String,
    // run_once may have hot-switched since run() started. Recovery must bind
    // to that latest immutable activation, never the initial launch snapshot.
    activation: Box<RuntimeArgs>,
}

impl std::fmt::Display for RetryableFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.error_code, self.detail)
    }
}

impl std::error::Error for RetryableFailure {}

#[derive(Debug)]
struct TransientReadinessFailure(String);

impl std::fmt::Display for TransientReadinessFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TransientReadinessFailure {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetryWait {
    Retry,
    Stop,
}

#[derive(Debug)]
struct RetryBackoff {
    next: Duration,
}

impl RetryBackoff {
    fn new() -> Self {
        Self {
            next: RETRY_INITIAL_DELAY,
        }
    }

    fn delay_after_failure(&mut self, attempt_uptime: Duration) -> Duration {
        if attempt_uptime >= RETRY_STABLE_RESET {
            self.next = RETRY_INITIAL_DELAY;
        }
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(RETRY_MAX_DELAY);
        delay
    }
}

fn retry_after_rollback(
    args: &RuntimeArgs,
    child: &mut Child,
    netd: &mut NetdClient,
    cause: &str,
    error_code: &'static str,
    error: anyhow::Error,
) -> Result<()> {
    eprintln!(
        "level=warn event=sdwan_runtime_interrupted error_code={} error={}",
        error_code,
        sanitize_log_value(&format!("{error:#}"))
    );
    stop_core(child);
    let rollback = rollback_or_report(netd, cause);
    let reported_error_code = if rollback.is_err() {
        "rollback_failed"
    } else {
        error_code
    };
    if let Err(rollback_error) = &rollback {
        eprintln!("level=error event=sdwan_rollback_failed error={rollback_error:#}");
    }
    remove_activation_receipt(args.activation_ready.as_deref())?;
    if let Err(marker_error) = write_runtime_failure_marker(args, reported_error_code) {
        eprintln!(
            "level=error event=sdwan_runtime_failure_marker_failed error_code={} error={}",
            reported_error_code,
            sanitize_log_value(&format!("{marker_error:#}"))
        );
    }
    // A netd daemon restart can close the IPC socket after it has already
    // removed the transaction.  Treat that as a recoverable cleanup failure:
    // the next activation creates a fresh owner/session.  Propagating the
    // ECONNRESET here used to terminate the agent and made a peer outage
    // permanent until a service restart.
    if let Err(rollback_error) = rollback {
        eprintln!(
            "level=warn event=sdwan_rollback_deferred generation={} error_code=rollback_ipc_unavailable error={}",
            args.generation,
            sanitize_log_value(&format!("{rollback_error:#}"))
        );
    }
    if let Err(status_error) = remove_stale_status(&args.status) {
        eprintln!(
            "level=warn event=sdwan_status_cleanup_deferred generation={} error={}",
            args.generation,
            sanitize_log_value(&format!("{status_error:#}"))
        );
    }
    if shutdown_requested() {
        eprintln!(
            "level=info event=sdwan_stopped generation={} phase=runtime_failure rollback_ok=true",
            args.generation
        );
        return Ok(());
    }
    Err(anyhow::Error::new(RetryableFailure {
        error_code,
        detail: format!("{error:#}"),
        activation: Box::new(args.clone()),
    }))
}

fn wait_before_retry(args: &RuntimeArgs, delay: Duration) -> Result<RetryWait> {
    let mut ordinary_child: Option<Child> = if args.core_role == CoreRole::Server {
        #[cfg(not(test))]
        {
            Some(spawn_ordinary_server(args)?)
        }
        #[cfg(test)]
        {
            None
        }
    } else {
        None
    };
    if ordinary_child.is_some() {
        eprintln!(
            "level=info event=sdwan_retry_fail_open generation={} mode=ordinary_only",
            args.generation
        );
    }
    let deadline = Instant::now()
        .checked_add(delay)
        .context("SD-WAN retry deadline overflow")?;
    loop {
        if shutdown_requested() {
            if let Some(child) = ordinary_child.as_mut() {
                stop_core(child);
            }
            remove_activation_receipt(args.activation_ready.as_deref())?;
            return Ok(RetryWait::Stop);
        }
        if !activation_pointer_unchanged(args)? {
            if let Some(child) = ordinary_child.as_mut() {
                stop_core(child);
            }
            remove_activation_receipt(args.activation_ready.as_deref())?;
            eprintln!(
                "level=info event=sdwan_retry_cancelled generation={} reason=candidate_changed",
                args.generation
            );
            return Ok(RetryWait::Stop);
        }
        if let Some(child) = ordinary_child.as_mut() {
            if let Some(status) = child
                .try_wait()
                .context("wait for ordinary Candy Server during SD-WAN retry")?
            {
                eprintln!(
                    "level=warn event=sdwan_retry_fail_open_exit generation={} exit={}",
                    args.generation,
                    status.code().unwrap_or(1)
                );
                ordinary_child = None;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(RETRY_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    if let Some(child) = ordinary_child.as_mut() {
        stop_core(child);
    }
    if !activation_retry_eligible(args)? {
        remove_activation_receipt(args.activation_ready.as_deref())?;
        eprintln!(
            "level=info event=sdwan_retry_cancelled generation={} reason=candidate_invalid_or_expired",
            args.generation
        );
        return Ok(RetryWait::Stop);
    }
    Ok(RetryWait::Retry)
}

fn fail_before_prepare(
    args: &RuntimeArgs,
    cause: &str,
    error_code: &'static str,
    error: anyhow::Error,
) -> Result<()> {
    eprintln!(
        "level=error event=sdwan_activation_rejected error_code={} error={}",
        error_code,
        sanitize_log_value(&format!("{error:#}"))
    );
    match args.core_role {
        CoreRole::ClientSdwan => Err(error),
        CoreRole::Server => {
            if let Err(marker_error) = write_failed_activation_receipt(args, error_code) {
                eprintln!(
                    "level=error event=sdwan_rejection_receipt_failed error={marker_error:#}"
                );
            }
            keep_server_fail_open(args, cause)
        }
    }
}

fn fail_after_rollback(
    args: &RuntimeArgs,
    child: &mut Child,
    netd: &mut NetdClient,
    cause: &str,
    error_code: &'static str,
    error: anyhow::Error,
) -> Result<()> {
    eprintln!(
        "level=error event=sdwan_activation_failed error_code={} error={}",
        error_code,
        sanitize_log_value(&format!("{error:#}"))
    );
    stop_core(child);
    let rollback = rollback_or_report(netd, cause);
    if shutdown_requested() {
        return finish_shutdown_after_rollback(args, rollback, "activation_failure");
    }
    let receipt_code = if rollback.is_err() {
        "rollback_failed"
    } else {
        error_code
    };
    let marker = write_failed_activation_receipt(args, receipt_code);
    if let Err(rollback_error) = &rollback {
        eprintln!("level=error event=sdwan_rollback_failed error={rollback_error:#}");
    }
    if let Err(marker_error) = &marker {
        eprintln!("level=error event=sdwan_rejection_receipt_failed error={marker_error:#}");
    }
    match args.core_role {
        CoreRole::ClientSdwan => {
            rollback?;
            marker?;
            Err(error)
        }
        CoreRole::Server => keep_server_fail_open(args, cause),
    }
}

#[derive(Default)]
struct HotTransitionState {
    core_suspended: bool,
    steering_suspended: bool,
}

impl HotTransitionState {
    fn complete(&self) -> bool {
        self.core_suspended && self.steering_suspended
    }
}

fn enter_proxy_fallback(
    args: &RuntimeArgs,
    child: &mut Child,
    netd: &mut NetdClient,
    state: &mut HotTransitionState,
) -> Result<()> {
    if !state.steering_suspended {
        netd.suspend()
            .context("remove SD-WAN steering before entering Candy Proxy fallback")?;
        state.steering_suspended = true;
    }
    if !state.core_suspended {
        // If the data-plane process has already exited, forwarding is already
        // stopped.  Do not turn that expected failure state into a second
        // fatal "fallback failed" error; leave the steering suspended and let
        // the outer retry loop start a new Core instance.
        if child
            .try_wait()
            .context("inspect Core before entering fallback")?
            .is_some()
        {
            state.core_suspended = true;
        } else {
            request_core_control(args, child, netd, CoreReloadAction::Suspend)
                .context("suspend Core forwarding after steering was removed")?;
            state.core_suspended = true;
        }
    }
    Ok(())
}

fn leave_proxy_fallback(
    args: &RuntimeArgs,
    child: &mut Child,
    netd: &mut NetdClient,
    state: &mut HotTransitionState,
) -> Result<()> {
    if state.core_suspended {
        request_core_control(args, child, netd, CoreReloadAction::Resume)
            .context("resume Core forwarding before restoring SD-WAN steering")?;
        state.core_suspended = false;
    }
    if state.steering_suspended {
        if let Err(error) = netd.resume() {
            if request_core_control(args, child, netd, CoreReloadAction::Suspend).is_ok() {
                state.core_suspended = true;
            }
            return Err(anyhow::Error::from(error).context("restore SD-WAN steering"));
        }
        state.steering_suspended = false;
    }
    Ok(())
}

fn restore_uncommitted_netd_activation(
    current: &RuntimeArgs,
    child: &mut Child,
    netd: &mut NetdClient,
    previous_declaration: PrepareDeclaration,
    transition: &mut HotTransitionState,
    resume_previous: bool,
) -> Result<()> {
    let deadline = monotonic_ms()?
        .checked_add(current.lease_ms)
        .context("last-good lease deadline overflow")?;
    netd.reconfigure_with_owner(previous_declaration, current.generation, deadline)
        .context("restore last-good netd declaration")?;
    // Core has not received Commit. Its old policy and dialers are still
    // installed; redialing them here would destroy that safety boundary.
    if resume_previous {
        leave_proxy_fallback(current, child, netd, transition)
            .context("resume last-good SD-WAN after rejected hot reload")?;
    }
    Ok(())
}

fn hot_replace_activation(
    current: &RuntimeArgs,
    replacement: &RuntimeArgs,
    child: &mut Child,
    netd: &mut NetdClient,
    readiness_token: &str,
    transition: &mut HotTransitionState,
) -> Result<bool> {
    // A stale activation can be delivered while Cloud is reconciling a
    // rollout (or after a retry races the committed pointer).  Never tear
    // down the currently active lane for it: doing so turns a harmless
    // ordering race into a site-wide outage. Rollback must be a new signed
    // generation; equal-generation credential refresh remains supported.
    if replacement.generation < current.generation {
        eprintln!(
            "level=warn event=sdwan_hot_reload_ignored_stale generation={} active_generation={} error_code=stale_policy_generation",
            replacement.generation,
            current.generation
        );
        write_failed_activation_receipt(replacement, "stale_policy_generation")?;
        return Ok(false);
    }
    let already_suspended = transition.complete();
    let previous_declaration = parse_declaration(&current.declaration)?;
    let replacement_declaration = match parse_declaration(&replacement.declaration) {
        Ok(declaration) => declaration,
        Err(error) => {
            write_failed_activation_receipt(replacement, "declaration_invalid")?;
            eprintln!(
                "level=error event=sdwan_hot_reload_rejected generation={} error_code=declaration_invalid error={}",
                replacement.generation,
                sanitize_log_value(&format!("{error:#}"))
            );
            return Ok(false);
        }
    };
    let transaction_id = format!(
        "{}{}",
        generate_readiness_token()?,
        generate_readiness_token()?
    );
    let mut next_renewal = Instant::now();
    eprintln!("level=info event=sdwan_policy_preparing generation={} transaction_id={} steering=unchanged",
        replacement.generation, transaction_id);
    let prepared = request_core_transaction(
        replacement,
        child,
        CoreReloadAction::Prepare,
        Some(&transaction_id),
        || renew_transition_lease(current, netd, &mut next_renewal),
    )
    .and_then(|_| {
        anyhow::ensure!(
            !shutdown_requested() && activation_binding_unchanged(replacement)?,
            "candidate withdrawn or changed during preparation"
        );
        Ok(())
    });
    if let Err(error) = prepared {
        abort_core_preparation(replacement, child, &transaction_id);
        if error.downcast_ref::<CorePreparationPending>().is_some() {
            eprintln!("level=warn event=sdwan_policy_prepare_retry generation={} transaction_id={} error_code=peer_preparation_pending steering=unchanged error={}",
                replacement.generation, transaction_id, sanitize_log_value(&format!("{error:#}")));
            return Err(error);
        }
        // A receipt write failure must not turn a preparation rejection into
        // the caller's destructive transition-failure path.
        if let Err(receipt_error) =
            write_failed_activation_receipt(replacement, "core_policy_prepare_failed")
        {
            eprintln!(
                "level=warn event=sdwan_activation_receipt_failed error={}",
                sanitize_log_value(&format!("{receipt_error:#}"))
            );
        }
        eprintln!("level=error event=sdwan_policy_prepare_failed generation={} transaction_id={} error_code=core_policy_prepare_failed steering=unchanged error={}",
            replacement.generation, transaction_id, sanitize_log_value(&format!("{error:#}")));
        return Ok(false);
    }
    let replacement_deadline = monotonic_ms()?
        .checked_add(replacement.lease_ms)
        .context("hot reload lease deadline overflow")?;
    let netd_result = if already_suspended {
        netd.reconfigure_with_owner(
            replacement_declaration,
            replacement.generation,
            replacement_deadline,
        )
    } else {
        netd.prepare_replacement_with_owner(
            replacement_declaration,
            replacement.generation,
            replacement_deadline,
        )
    };
    if let Err(error) = netd_result {
        abort_core_preparation(replacement, child, &transaction_id);
        if already_suspended {
            leave_proxy_fallback(current, child, netd, transition)
                .context("restore last-good SD-WAN after rejected reconfigure")
                .map_err(|error| anyhow::Error::new(HotReloadRecoveryRequired(error)))?;
        }
        let error_code = netd_reconfigure_error_code(&error);
        write_failed_activation_receipt(replacement, error_code)?;
        eprintln!(
            "level=error event=sdwan_hot_reload_rejected generation={} error_code={} error={}",
            replacement.generation,
            error_code,
            sanitize_log_value(&error.to_string())
        );
        return Ok(false);
    }
    // Recheck after netd work as well; Cloud may have withdrawn/superseded
    // the candidate while the kernel transaction was running.
    if !activation_binding_unchanged(replacement).unwrap_or(false) || shutdown_requested() {
        abort_core_preparation(replacement, child, &transaction_id);
        if already_suspended {
            restore_uncommitted_netd_activation(
                current,
                child,
                netd,
                previous_declaration,
                transition,
                true,
            )
            .map_err(|error| anyhow::Error::new(HotReloadRecoveryRequired(error)))?;
        } else {
            netd.rollback()
                .context("discard prepared netd replacement")?;
        }
        return Ok(false);
    }
    if let Err(error) = remove_stale_status(&replacement.status) {
        abort_core_preparation(replacement, child, &transaction_id);
        if already_suspended {
            restore_uncommitted_netd_activation(
                current,
                child,
                netd,
                previous_declaration,
                transition,
                true,
            )
            .map_err(|error| anyhow::Error::new(HotReloadRecoveryRequired(error)))?;
        } else {
            netd.rollback()
                .context("discard prepared netd replacement")?;
        }
        eprintln!("level=error event=sdwan_policy_prepare_failed generation={} error_code=core_policy_prepare_failed error={}",
            replacement.generation, sanitize_log_value(&format!("{error:#}")));
        return Ok(false);
    }
    let mut commit = request_core_transaction(
        replacement,
        child,
        CoreReloadAction::Commit,
        Some(&transaction_id),
        || renew_transition_lease(replacement, netd, &mut next_renewal),
    );
    if commit.is_err() {
        // Core caches the outcome. Retry the same ID to recover a lost reply;
        // never issue Replace or a lower generation as a guessed rollback.
        commit = request_core_transaction(
            replacement,
            child,
            CoreReloadAction::Commit,
            Some(&transaction_id),
            || renew_transition_lease(replacement, netd, &mut next_renewal),
        );
    }
    if let Err(error) = commit {
        eprintln!("level=error event=sdwan_policy_commit_unresolved generation={} transaction_id={} error_code=core_policy_commit_unresolved fallback=candy_proxy error={}",
            replacement.generation, transaction_id, sanitize_log_value(&format!("{error:#}")));
        return Err(anyhow::Error::new(AppliedHotReloadPending(error)));
    }
    if !already_suspended {
        netd.commit_replacement()
            .context("commit prepared netd replacement")?;
    }

    let deadline = Instant::now()
        .checked_add(Duration::from_millis(replacement.readiness_timeout_ms))
        .context("hot reload readiness deadline overflow")?;
    let readiness_failure = loop {
        if let Err(error) = renew_transition_lease(replacement, netd, &mut next_renewal) {
            break Some(("netd_lease_renewal_failed", error));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break Some((
                    "core_exit_during_hot_reload",
                    anyhow::anyhow!("Candy Core exited during hot reload with status {status}"),
                ))
            }
            Err(error) => {
                break Some((
                    "core_readiness_failed",
                    anyhow::Error::from(error).context("inspect Candy Core during hot reload"),
                ))
            }
            Ok(None) => {}
        }
        match read_core_readiness(
            &replacement.status,
            replacement.generation,
            child.id(),
            readiness_token,
        ) {
            Err(error) => break Some(("core_readiness_failed", error)),
            Ok(Some(ReadinessState::Ready)) | Ok(Some(ReadinessState::Degraded))
                if replacement.core_role == CoreRole::Server =>
            {
                break None
            }
            Ok(Some(ReadinessState::Ready)) => break None,
            Ok(_) if Instant::now() >= deadline => {
                break Some((
                    "core_readiness_timeout",
                    anyhow::anyhow!("Candy Core hot reload readiness timed out"),
                ))
            }
            _ => thread::sleep(Duration::from_millis(20)),
        }
    };
    if let Some((error_code, error)) = readiness_failure {
        // Core has already committed. A REJECTED receipt makes cloud-sync
        // remove this candidate, which disables recovery and strands steering
        // in fallback. Only terminal pre-commit failures may reject a candidate.
        if !already_suspended {
            // The candidate commit leaves netd in Draining while the old
            // declaration is retained.  Before the outer loop enters Candy
            // Proxy fallback, finish that transaction so Suspend can operate
            // on the promoted candidate instead of being rejected as an
            // invalid Draining transition.
            let now = monotonic_ms().context("read monotonic clock before fallback drain")?;
            if let Err(drain_error) = netd.drain_old(now) {
                eprintln!(
                    "level=error event=sdwan_hot_reload_drain_failed generation={} error_code=netd_drain_failed error={}",
                    replacement.generation,
                    sanitize_log_value(&format!("{drain_error:#}"))
                );
                return Err(anyhow::Error::new(AppliedHotReloadPending(
                    anyhow::Error::from(drain_error)
                        .context("drain committed replacement before fallback"),
                )));
            }
        }
        eprintln!(
            "level=error event=sdwan_hot_reload_recovering generation={} error_code={} fallback=candy_proxy error={}",
            replacement.generation,
            error_code,
            sanitize_log_value(&format!("{error:#}"))
        );
        return Err(anyhow::Error::new(AppliedHotReloadPending(error)));
    }
    if !activation_binding_unchanged(replacement).unwrap_or(false) || shutdown_requested() {
        if !already_suspended {
            let now = monotonic_ms().context("read monotonic clock before fallback drain")?;
            if let Err(drain_error) = netd.drain_old(now) {
                return Err(anyhow::Error::new(AppliedHotReloadPending(
                    anyhow::Error::from(drain_error)
                        .context("drain superseded replacement before fallback"),
                )));
            }
        }
        return Err(anyhow::Error::new(AppliedHotReloadPending(
            anyhow::anyhow!(
                "candidate withdrawn or superseded after Core commit; steering stays suspended"
            ),
        )));
    }
    if !already_suspended {
        let now = monotonic_ms().context("read monotonic clock before netd drain")?;
        if let Err(error) = netd.drain_old(now) {
            return Err(anyhow::Error::new(AppliedHotReloadPending(
                anyhow::Error::from(error).context("drain old netd owner"),
            )));
        }
    } else if let Err(error) = leave_proxy_fallback(replacement, child, netd, transition) {
        return Err(anyhow::Error::new(AppliedHotReloadPending(error)));
    }
    write_runtime_activation_receipt(replacement, "committed", None)
        .map_err(|error| anyhow::Error::new(AppliedHotReloadPending(error)))?;
    eprintln!(
        "level=info event=sdwan_hot_reload_committed previous_generation={} generation={} core_pid={} fallback=candy_proxy",
        current.generation,
        replacement.generation,
        child.id()
    );
    Ok(true)
}

#[derive(Debug)]
struct AppliedHotReloadPending(anyhow::Error);

#[derive(Debug)]
struct CorePreparationPending(String);

impl std::fmt::Display for CorePreparationPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "candidate preparation pending: {}", self.0)
    }
}

impl std::error::Error for CorePreparationPending {}

#[derive(Debug)]
struct HotReloadRecoveryRequired(anyhow::Error);

impl std::fmt::Display for HotReloadRecoveryRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "hot reload rollback incomplete; network recovery required: {:#}",
            self.0
        )
    }
}

impl std::error::Error for HotReloadRecoveryRequired {}

impl std::fmt::Display for AppliedHotReloadPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Core commit dispatched; activation confirmation/recovery pending: {:#}",
            self.0
        )
    }
}

impl std::error::Error for AppliedHotReloadPending {}

fn fail_without_core(
    args: &RuntimeArgs,
    netd: &mut NetdClient,
    cause: &str,
    error_code: &'static str,
    error: anyhow::Error,
) -> Result<()> {
    eprintln!(
        "level=error event=sdwan_activation_failed error_code={} error={}",
        error_code,
        sanitize_log_value(&format!("{error:#}"))
    );
    let rollback = rollback_or_report(netd, cause);
    if shutdown_requested() {
        return finish_shutdown_after_rollback(args, rollback, "activation_failure");
    }
    let receipt_code = if rollback.is_err() {
        "rollback_failed"
    } else {
        error_code
    };
    let marker = write_failed_activation_receipt(args, receipt_code);
    if let Err(rollback_error) = &rollback {
        eprintln!("level=error event=sdwan_rollback_failed error={rollback_error:#}");
    }
    if let Err(marker_error) = &marker {
        eprintln!("level=error event=sdwan_rejection_receipt_failed error={marker_error:#}");
    }
    match args.core_role {
        CoreRole::ClientSdwan => {
            rollback?;
            marker?;
            Err(error)
        }
        CoreRole::Server => keep_server_fail_open(args, cause),
    }
}

fn run_once(mut args: RuntimeArgs, recovery_attempt: bool) -> Result<()> {
    if args.generation == 0 {
        return fail_before_prepare(
            &args,
            "invalid SD-WAN generation",
            "invalid_generation",
            anyhow::anyhow!("generation must be non-zero"),
        );
    }
    if !(MIN_LEASE_MS..=MAX_LEASE_MS).contains(&args.lease_ms) {
        return fail_before_prepare(
            &args,
            "invalid SD-WAN lease",
            "invalid_lease",
            anyhow::anyhow!("lease-ms is outside the supported bound"),
        );
    }
    if !(MIN_READINESS_TIMEOUT_MS..=MAX_READINESS_TIMEOUT_MS).contains(&args.readiness_timeout_ms) {
        return fail_before_prepare(
            &args,
            "invalid Core readiness timeout",
            "invalid_readiness_timeout",
            anyhow::anyhow!("readiness-timeout-ms is outside the supported bound"),
        );
    }
    if let Err(error) = install_shutdown_handlers() {
        return fail_before_prepare(
            &args,
            "install SD-WAN shutdown handlers",
            "signal_handler_failed",
            error,
        );
    }
    let declaration = match parse_declaration(&args.declaration) {
        Ok(declaration) => declaration,
        Err(error) => {
            return fail_before_prepare(
                &args,
                "invalid netd declaration",
                "declaration_invalid",
                error,
            )
        }
    };
    let deadline = match monotonic_ms().and_then(|now| {
        now.checked_add(args.lease_ms)
            .context("lease deadline overflow")
    }) {
        Ok(deadline) => deadline,
        Err(error) => {
            return fail_before_prepare(
                &args,
                "invalid monotonic lease deadline",
                "lease_clock_failed",
                error,
            )
        }
    };
    let instance_id = match parse_instance_id(&args.instance_id) {
        Ok(instance_id) => instance_id,
        Err(error) => {
            return fail_before_prepare(
                &args,
                "invalid SD-WAN instance identity",
                "instance_id_invalid",
                error,
            )
        }
    };
    let owner = LeaseOwner {
        instance_id,
        pid: std::process::id(),
        generation: args.generation,
        lease_deadline_mono_ms: deadline,
    };
    eprintln!(
        "level=info event=sdwan_prepare generation={} pid={}",
        owner.generation, owner.pid
    );
    let mut netd = NetdClient::new(&args.socket, owner);
    let prepared = match netd.prepare(declaration).context("netd prepare") {
        Ok(prepared) => prepared,
        Err(error) => {
            return fail_before_prepare(&args, "netd prepare failed", "netd_prepare_failed", error)
        }
    };
    if let Err(error) = remove_stale_status(&args.status) {
        return fail_without_core(
            &args,
            &mut netd,
            "stale Core readiness cleanup failed",
            "status_cleanup_failed",
            error,
        );
    }
    match cleanup_superseded_activation_statuses(&args.status) {
        Ok(removed) if removed > 0 => eprintln!(
            "level=info event=sdwan_status_cleanup removed={} status={}",
            removed,
            args.status.display()
        ),
        Ok(_) => {}
        // Status cleanup must not turn a working candidate into an outage.
        Err(error) => eprintln!(
            "level=warn event=sdwan_status_cleanup_failed status={} error={}",
            args.status.display(),
            sanitize_log_value(&format!("{error:#}"))
        ),
    }
    let readiness_token = match generate_readiness_token() {
        Ok(token) => token,
        Err(error) => {
            return fail_without_core(
                &args,
                &mut netd,
                "Core readiness token generation failed",
                "readiness_token_failed",
                error,
            )
        }
    };
    let mut child = match spawn_core(&args, &prepared.tun, &readiness_token) {
        Ok(child) => child,
        Err(error) => {
            return fail_without_core(
                &args,
                &mut netd,
                "Candy Core start failed",
                "core_start_failed",
                error,
            );
        }
    };
    match wait_for_core_readiness(&args, &mut child, &readiness_token, &mut netd) {
        Ok(ReadinessWait::Ready) => {}
        Ok(ReadinessWait::ShutdownRequested) => {
            stop_core(&mut child);
            let rollback = rollback_or_report(&mut netd, "SD-WAN agent shutdown before readiness");
            let receipt = remove_activation_receipt(args.activation_ready.as_deref());
            rollback?;
            receipt?;
            eprintln!(
                "level=info event=sdwan_stopped generation={} phase=readiness rollback_ok=true",
                owner.generation
            );
            return Ok(());
        }
        Err(error) => {
            return if error.downcast_ref::<TransientReadinessFailure>().is_some() {
                retry_after_rollback(
                    &args,
                    &mut child,
                    &mut netd,
                    "Candy Core readiness failed",
                    "core_readiness_failed",
                    error,
                )
            } else {
                fail_after_rollback(
                    &args,
                    &mut child,
                    &mut netd,
                    "Candy Core readiness failed",
                    "core_readiness_failed",
                    error,
                )
            }
        }
    }
    if let Err(error) = netd.commit() {
        return if recovery_attempt {
            retry_after_rollback(
                &args,
                &mut child,
                &mut netd,
                "netd recovery commit failed",
                "netd_commit_failed",
                error.into(),
            )
        } else {
            fail_after_rollback(
                &args,
                &mut child,
                &mut netd,
                "netd commit failed",
                "netd_commit_failed",
                error.into(),
            )
        };
    }
    if let Err(error) = write_runtime_activation_receipt(&args, "committed", None) {
        return fail_after_rollback(
            &args,
            &mut child,
            &mut netd,
            "activation receipt publication failed",
            "activation_receipt_failed",
            error,
        );
    }
    if let Err(error) = remove_runtime_failure_marker(&args.status) {
        eprintln!(
            "level=warn event=sdwan_runtime_failure_marker_cleanup_failed error={}",
            sanitize_log_value(&format!("{error:#}"))
        );
    }
    eprintln!(
        "level=info event=sdwan_commit generation={}",
        owner.generation
    );
    let renew_every = Duration::from_millis((args.lease_ms / 3).max(1_000));
    let mut next_renewal = Instant::now() + renew_every;
    let mut transition = HotTransitionState::default();
    let mut peer_loss_fallback = false;
    // This is deliberately separate from `peer_loss_fallback`: the latter is
    // the current forwarding mode, while this flag records that this process
    // has completed one successful activation.  A post-commit readiness flap
    // is recoverable and must not be treated like an initial activation
    // failure.
    let mut committed_ready = true;
    let mut readiness_lost_since = None::<Instant>;
    let mut last_partial_route_log = None::<Instant>;
    let mut rejected_activation = None::<PathBuf>;
    let mut preparation_retry_target = None::<PathBuf>;
    let mut next_preparation_retry = Instant::now();
    loop {
        // All recovery and candidate-inspection branches below may continue
        // early. Renew first so repeated transient states cannot starve netd.
        if let Err(error) = renew_transition_lease(&args, &mut netd, &mut next_renewal) {
            return retry_after_rollback(
                &args,
                &mut child,
                &mut netd,
                "netd lease renewal failed",
                "netd_lease_failed",
                error,
            );
        }
        match activation_pointer_state(&args) {
            Ok(ActivationPointerState::Unchanged) => {}
            Ok(ActivationPointerState::Superseded) => {
                let replacement = match reload_runtime_args(&args) {
                    Ok(replacement) => replacement,
                    Err(error) => {
                        eprintln!(
                            "level=error event=sdwan_hot_reload_rejected generation={} error_code=activation_invalid error={}",
                            args.generation,
                            sanitize_log_value(&format!("{error:#}"))
                        );
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                };
                if rejected_activation.as_ref() != replacement.activation_target.as_ref()
                    && (preparation_retry_target != replacement.activation_target
                        || Instant::now() >= next_preparation_retry)
                {
                    match hot_replace_activation(
                        &args,
                        &replacement,
                        &mut child,
                        &mut netd,
                        &readiness_token,
                        &mut transition,
                    ) {
                        Ok(true) => {
                            args = replacement;
                            peer_loss_fallback = false;
                            rejected_activation = None;
                            next_renewal = Instant::now() + renew_every;
                        }
                        Ok(false) => {
                            rejected_activation = replacement.activation_target.clone();
                        }
                        Err(error) if error.downcast_ref::<CorePreparationPending>().is_some() => {
                            // Keep old ownership/readiness and retry this
                            // publication after backoff. A new candidate need
                            // not wait for the previous candidate's deadline.
                            preparation_retry_target = replacement.activation_target.clone();
                            next_preparation_retry = Instant::now() + RETRY_INITIAL_DELAY;
                        }
                        Err(error) if error.downcast_ref::<AppliedHotReloadPending>().is_some() => {
                            // Core has crossed its commit point. Keep ownership
                            // and readiness checks on that generation and retry
                            // forwarding, never attempt a lower signed generation.
                            args = replacement;
                            peer_loss_fallback = true;
                            rejected_activation = None;
                            next_renewal = Instant::now();
                            eprintln!("level=warn event=sdwan_activation_recovery_pending generation={} error={}", args.generation, sanitize_log_value(&format!("{error:#}")));
                        }
                        Err(error)
                            if error.downcast_ref::<HotReloadRecoveryRequired>().is_some() =>
                        {
                            // A poisoned netd transaction cannot Resume. Clean
                            // it and retry the desired activation, rather than
                            // rejecting it and remaining stuck in fallback.
                            return retry_after_rollback(
                                &replacement,
                                &mut child,
                                &mut netd,
                                "hot reload rollback incomplete",
                                "hot_transition_failed",
                                error,
                            );
                        }
                        Err(error) => {
                            if !transition.complete() {
                                let _ = enter_proxy_fallback(
                                    &args,
                                    &mut child,
                                    &mut netd,
                                    &mut transition,
                                );
                            }
                            let _ = write_failed_activation_receipt(
                                &replacement,
                                "hot_transition_failed",
                            );
                            rejected_activation = replacement.activation_target.clone();
                            eprintln!(
                                "level=error event=sdwan_hot_reload_rejected generation={} error_code=hot_transition_failed fallback={} error={}",
                                replacement.generation,
                                if transition.steering_suspended { "candy_proxy" } else { "last_good_sdwan" },
                                sanitize_log_value(&format!("{error:#}"))
                            );
                        }
                    }
                }
            }
            Ok(ActivationPointerState::Withdrawn) => {
                // A withdrawn Cloud policy owns the fallback decision. Do not
                // let a stale pre-withdrawal readiness report resume steering.
                peer_loss_fallback = false;
                rejected_activation = None;
                let was_in_fallback = transition.complete();
                if !was_in_fallback {
                    if let Err(error) =
                        enter_proxy_fallback(&args, &mut child, &mut netd, &mut transition)
                    {
                        eprintln!(
                            "level=error event=sdwan_hot_degrade_retry generation={} error_code=proxy_fallback_failed error={}",
                            args.generation,
                            sanitize_log_value(&format!("{error:#}"))
                        );
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    eprintln!(
                        "level=info event=sdwan_hot_degraded generation={} source=candy_proxy core_pid={} reason=cloud_policy_withdrawn",
                        args.generation,
                        child.id()
                    );
                }
                // The policy may be withdrawn while the agent is already in
                // the peer-loss fallback path. Receipt removal must therefore
                // be unconditional; otherwise Cloud keeps observing the old
                // activation as committed after the policy is gone.
                if let Err(error) = remove_activation_receipt(args.activation_ready.as_deref()) {
                    eprintln!(
                        "level=error event=sdwan_activation_receipt_cleanup_failed generation={} error_code=activation_receipt_cleanup_failed error={}",
                        args.generation,
                        sanitize_log_value(&format!("{error:#}"))
                    );
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
            }
            Err(error) => {
                eprintln!(
                    "level=error event=sdwan_candidate_inspection_retry generation={} error_code=candidate_inspection_failed fallback=last_good_sdwan error={}",
                    args.generation,
                    sanitize_log_value(&format!("{error:#}"))
                );
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        }
        if shutdown_requested() {
            stop_core(&mut child);
            let rollback = rollback_or_report(&mut netd, "SD-WAN agent shutdown");
            let receipt = remove_activation_receipt(args.activation_ready.as_deref());
            rollback?;
            receipt?;
            eprintln!(
                "level=info event=sdwan_stopped generation={} rollback_ok=true",
                owner.generation
            );
            return Ok(());
        }
        let child_status = match child.try_wait().context("wait for Candy Core") {
            Ok(status) => status,
            Err(error) => {
                return retry_after_rollback(
                    &args,
                    &mut child,
                    &mut netd,
                    "Candy Core process inspection failed",
                    "core_process_inspection_failed",
                    error,
                )
            }
        };
        if let Some(status) = child_status {
            let code = status.code().unwrap_or(1);
            return retry_after_rollback(
                &args,
                &mut child,
                &mut netd,
                "Candy Core SD-WAN exited",
                "core_exit",
                anyhow::anyhow!("Candy Core SD-WAN exited with status {code}"),
            );
        }
        if !transition.steering_suspended || peer_loss_fallback {
            let readiness_policy = if args.core_role == CoreRole::Server {
                ReadinessPolicy::CommittedServer
            } else {
                ReadinessPolicy::Committed
            };
            match read_core_readiness_with_policy(
                &args.status,
                args.generation,
                child.id(),
                &readiness_token,
                readiness_policy,
            ) {
                Ok(Some(ReadinessState::Ready | ReadinessState::Degraded))
                    if args.core_role == CoreRole::Server =>
                {
                    committed_ready = true;
                    readiness_lost_since = None;
                    last_partial_route_log = None;
                    if peer_loss_fallback {
                        match leave_proxy_fallback(&args, &mut child, &mut netd, &mut transition)
                            .and_then(|_| {
                                write_runtime_activation_receipt(&args, "committed", None)
                            }) {
                            Ok(()) => {
                                peer_loss_fallback = false;
                                eprintln!("level=info event=sdwan_recovered generation={} source=peer_reconnect", args.generation);
                            }
                            Err(error) => eprintln!(
                                "level=warn event=sdwan_recovery_pending generation={} error={}",
                                args.generation,
                                sanitize_log_value(&format!("{error:#}"))
                            ),
                        }
                    }
                }
                Ok(Some(ReadinessState::Ready)) => {
                    committed_ready = true;
                    readiness_lost_since = None;
                    last_partial_route_log = None;
                    if peer_loss_fallback {
                        if let Err(error) =
                            leave_proxy_fallback(&args, &mut child, &mut netd, &mut transition)
                                .and_then(|_| {
                                    write_runtime_activation_receipt(&args, "committed", None)
                                })
                        {
                            eprintln!(
                                "level=warn event=sdwan_recovery_pending error_code=steering_resume_failed error={}",
                                sanitize_log_value(&format!("{error:#}"))
                            );
                        } else {
                            peer_loss_fallback = false;
                            eprintln!(
                                "level=info event=sdwan_recovered generation={} source=peer_reconnect",
                                args.generation
                            );
                        }
                    }
                }
                Ok(Some(ReadinessState::Degraded)) => {
                    committed_ready = true;
                    readiness_lost_since = None;
                    // A recovered owner must restore healthy-route forwarding
                    // immediately after an all-peer fallback. The current
                    // Core/netd contract cannot identify and withdraw only the
                    // failed owner's prefixes, so keep the failure explicitly
                    // visible instead of tearing down every healthy route.
                    if peer_loss_fallback {
                        if let Err(error) =
                            leave_proxy_fallback(&args, &mut child, &mut netd, &mut transition)
                                .and_then(|_| {
                                    write_runtime_activation_receipt(&args, "committed", None)
                                })
                        {
                            eprintln!(
                                "level=warn event=sdwan_partial_route_recovery_pending generation={} error_code=steering_resume_failed error={}",
                                args.generation,
                                sanitize_log_value(&format!("{error:#}"))
                            );
                            thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                        peer_loss_fallback = false;
                    }
                    let should_log = last_partial_route_log
                        .is_none_or(|logged| logged.elapsed() >= PARTIAL_ROUTE_RETRY_LOG_INTERVAL);
                    if should_log {
                        last_partial_route_log = Some(Instant::now());
                        let evidence = read_core_status(
                            &args.status,
                            args.generation,
                            child.id(),
                            &readiness_token,
                        )
                        .ok()
                        .flatten();
                        eprintln!(
                            "level=warn event=sdwan_partial_route_degraded generation={} error_code=partial_route_owner_unavailable action=preserve_healthy_routes_and_retry failed_prefix_fallback=unavailable_contract configured_peers={} active_peers={} required_routes={} ready_routes={}",
                            args.generation,
                            evidence.as_ref().map_or(0, |status| status.configured_peers),
                            evidence.as_ref().map_or(0, |status| status.active_peers),
                            evidence.as_ref().map_or(0, |status| status.required_route_owners),
                            evidence.as_ref().map_or(0, |status| status.ready_route_owners),
                        );
                    }
                }
                Ok(Some(ReadinessState::ListenerReady)) => {
                    if committed_ready {
                        let lost_since = readiness_lost_since.get_or_insert_with(Instant::now);
                        if !peer_loss_fallback {
                            if let Err(error) =
                                enter_proxy_fallback(&args, &mut child, &mut netd, &mut transition)
                            {
                                return retry_after_rollback(
                                    &args,
                                    &mut child,
                                    &mut netd,
                                    "SD-WAN route readiness fallback failed",
                                    "peer_loss_fallback_failed",
                                    error,
                                );
                            }
                            peer_loss_fallback = true;
                            eprintln!(
                                "level=warn event=sdwan_peer_loss_fallback generation={} source=candy_proxy reason=route_readiness_lost error_code=peer_readiness_transient action=preserve_core_and_retry",
                                args.generation
                            );
                        }
                        if lost_since.elapsed() < CORE_READINESS_RECOVERY_GRACE {
                            thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                    }
                    return retry_after_rollback(
                        &args,
                        &mut child,
                        &mut netd,
                        "Candy Core lost SD-WAN route readiness",
                        "core_route_readiness_lost",
                        anyhow::anyhow!(
                            "Candy Core listener remains ready but no route owner is active"
                        ),
                    );
                }
                Ok(Some(ReadinessState::Waiting)) | Ok(None) => {
                    if committed_ready {
                        let lost_since = readiness_lost_since.get_or_insert_with(Instant::now);
                        if !peer_loss_fallback {
                            if let Err(error) =
                                enter_proxy_fallback(&args, &mut child, &mut netd, &mut transition)
                            {
                                return retry_after_rollback(
                                    &args,
                                    &mut child,
                                    &mut netd,
                                    "SD-WAN readiness fallback failed",
                                    "peer_loss_fallback_failed",
                                    error,
                                );
                            }
                            peer_loss_fallback = true;
                            eprintln!(
                                "level=warn event=sdwan_peer_loss_fallback generation={} source=candy_proxy reason=core_readiness_temporarily_unavailable error_code=peer_readiness_transient action=preserve_core_and_retry",
                                args.generation
                            );
                        }
                        if lost_since.elapsed() < CORE_READINESS_RECOVERY_GRACE {
                            thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                    }
                    return retry_after_rollback(
                        &args,
                        &mut child,
                        &mut netd,
                        "Candy Core lost SD-WAN readiness",
                        "core_readiness_lost",
                        anyhow::anyhow!("Candy Core lost SD-WAN readiness after netd commit"),
                    );
                }
                Ok(Some(ReadinessState::RecoverablePeerLoss)) => {
                    readiness_lost_since.get_or_insert_with(Instant::now);
                    if args.core_role == CoreRole::ClientSdwan && !peer_loss_fallback {
                        if let Err(error) =
                            enter_proxy_fallback(&args, &mut child, &mut netd, &mut transition)
                        {
                            return retry_after_rollback(
                                &args,
                                &mut child,
                                &mut netd,
                                "SD-WAN peer loss fallback failed",
                                "peer_loss_fallback_failed",
                                error,
                            );
                        }
                        peer_loss_fallback = true;
                        let evidence = read_core_status(
                            &args.status,
                            args.generation,
                            child.id(),
                            &readiness_token,
                        )
                        .ok()
                        .flatten();
                        let error_code = evidence
                            .as_ref()
                            .and_then(|status| status.last_error_code.as_deref())
                            .unwrap_or("sdwan_peer_loss");
                        let detail = evidence
                            .as_ref()
                            .and_then(|status| status.last_error_detail.as_deref())
                            .unwrap_or("all required peer lanes are unavailable");
                        eprintln!(
                            "level=warn event=sdwan_peer_loss_fallback generation={} source=candy_proxy reason=all_peer_lanes_unavailable error_code={} detail={} configured_peers={} active_peers={} required_routes={} ready_routes={} action=preserve_core_and_reconnect",
                            args.generation,
                            error_code,
                            sanitize_log_value(detail),
                            evidence.as_ref().map_or(0, |status| status.configured_peers),
                            evidence.as_ref().map_or(0, |status| status.active_peers),
                            evidence.as_ref().map_or(0, |status| status.required_route_owners),
                            evidence.as_ref().map_or(0, |status| status.ready_route_owners),
                        );
                    }
                }
                Ok(Some(ReadinessState::Failed)) => {
                    unreachable!("failed readiness returns an error")
                }
                Err(error) => {
                    return retry_after_rollback(
                        &args,
                        &mut child,
                        &mut netd,
                        "Candy Core reported SD-WAN failure",
                        "core_runtime_failed",
                        error.context("Candy Core failed after netd commit"),
                    );
                }
            }
            match read_core_status(&args.status, args.generation, child.id(), &readiness_token) {
                // During the bounded post-commit recovery window the status
                // file may legitimately be absent while Core atomically
                // replaces it.  Readiness handling above already put traffic
                // on the independent Candy Proxy fallback in that case.
                Ok(None) if peer_loss_fallback => {}
                Ok(Some(status)) => {
                    let declaration = parse_declaration(&args.declaration)
                        .context("parse declaration for failed-prefix recovery")?;
                    if let Some(prefixes) = parse_failed_prefixes(&status, &declaration)? {
                        netd.set_failed_prefixes(prefixes)
                            .context("apply Core failed-prefix route set")?;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    return retry_after_rollback(
                        &args,
                        &mut child,
                        &mut netd,
                        "Candy Core traffic status inspection failed",
                        "core_status_inspection_failed",
                        error,
                    );
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn run(mut args: RuntimeArgs) -> Result<()> {
    // The signal latch and child lifecycle are process-wide. Keep the test
    // fixture lock across every retry and reset the latch only after taking it.
    #[cfg(test)]
    let _test_guard = RUN_TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("SD-WAN agent test lock poisoned");
    #[cfg(test)]
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);

    let mut retry_backoff = RetryBackoff::new();
    let mut recovery_attempt = false;
    loop {
        let attempt_started = Instant::now();
        match run_once(args.clone(), recovery_attempt) {
            Err(error) if error.downcast_ref::<RetryableFailure>().is_some() => {
                let failure = error
                    .downcast_ref::<RetryableFailure>()
                    .expect("retryable failure downcast changed");
                let error_code = failure.error_code;
                args = (*failure.activation).clone();
                if args.activation_link.is_none() {
                    return Err(error);
                }
                let retry_delay = retry_backoff.delay_after_failure(attempt_started.elapsed());
                eprintln!(
                    "level=info event=sdwan_retry_scheduled generation={} error_code={} delay_ms={}",
                    args.generation,
                    error_code,
                    retry_delay.as_millis()
                );
                match wait_before_retry(&args, retry_delay)? {
                    RetryWait::Retry => recovery_attempt = true,
                    RetryWait::Stop => return Ok(()),
                }
            }
            result => return result,
        }
    }
}

fn main() {
    let args = Args::parse();
    let result = match args.command.as_ref() {
        Some(CommandKind::ValidateActivation {
            activation,
            expected_core_role,
            ordinary_config,
        }) => {
            validate_activation_command(activation, *expected_core_role, ordinary_config.as_deref())
        }
        Some(CommandKind::Run) | None => resolve_runtime_args(args).and_then(run),
    };
    if let Err(error) = result {
        eprintln!("level=error event=sdwan_agent_failed error={error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_netd_ipc_is_classified_as_retryable_peer_closed() {
        let error = IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "write failed",
        ));
        assert_eq!(
            netd_reconfigure_error_code(&error),
            "netd_reconfigure_peer_closed"
        );
        let error = IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "netd closed response",
        ));
        assert_eq!(
            netd_reconfigure_error_code(&error),
            "netd_reconfigure_peer_closed"
        );
    }
    use candy_netd_client::{recv_request, send_response};
    use candy_netd_proto::{ErrorCode, NetdOperation, NetdResponse, ResponseBody};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[derive(Clone, Copy, PartialEq)]
    enum ReloadFault {
        PrepareRejected,
        PreparePending,
        CandidateChanged,
        LostCommitReply,
        CommitUnresolved,
        NetdRollbackIncomplete,
    }

    fn exercise_prepared_hot_reload(fault: ReloadFault) {
        use std::sync::{Arc, Mutex};
        let _guard = RUN_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        let (_root, mut current) = server_runtime_fixture();
        current.core_role = CoreRole::ClientSdwan;
        current.generation = 6;
        let (_candidate_root, candidate, _) = activation_fixture();
        write_private(
            &candidate.join("declaration.json"),
            &fs::read(&current.declaration).unwrap(),
        );
        let (descriptor, target, config, declaration) = resolve_activation(&candidate).unwrap();
        let mut replacement = current.clone();
        replacement.generation = descriptor.projection_generation;
        replacement.activation_link = Some(candidate);
        replacement.activation_target = Some(target);
        replacement.activation_descriptor = Some(descriptor);
        replacement.activation_config_sha256 = Some(sha256_file(&config).unwrap());
        replacement.activation_declaration_sha256 = Some(sha256_file(&declaration).unwrap());
        replacement.config = config;
        replacement.declaration = declaration;
        struct TestChild(Child);
        impl Drop for TestChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = TestChild(Command::new("/bin/sleep").arg("60").spawn().unwrap());
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let finished = Arc::new(AtomicBool::new(false));
        let netd_listener = UnixListener::bind(&current.socket).unwrap();
        netd_listener.set_nonblocking(true).unwrap();
        let netd_events = events.clone();
        let netd_finished = finished.clone();
        let netd_task = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let stream = match netd_listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if netd_finished.load(Ordering::SeqCst) {
                            break;
                        }
                        assert!(Instant::now() < deadline, "netd mock timed out");
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                let request = recv_request(&stream).unwrap();
                let generation = request.owner.generation;
                let tun = File::open("/dev/null").unwrap();
                let mut fd = None;
                let (name, body) = match request.operation {
                    NetdOperation::Prepare(_) => {
                        fd = Some(tun.as_raw_fd());
                        (
                            "prepare",
                            ResponseBody::Prepared {
                                generation,
                                tun_fd_attached: true,
                            },
                        )
                    }
                    NetdOperation::Commit => ("commit", ResponseBody::Committed { generation }),
                    NetdOperation::LeaseRenew => {
                        ("lease", ResponseBody::LeaseRenewed { generation })
                    }
                    NetdOperation::Suspend => ("suspend", ResponseBody::Suspended { generation }),
                    NetdOperation::Reconfigure(_) => (
                        "reconfigure",
                        if fault == ReloadFault::NetdRollbackIncomplete {
                            ResponseBody::Error(ErrorCode::SystemFailure)
                        } else {
                            ResponseBody::Reconfigured { generation }
                        },
                    ),
                    NetdOperation::Resume => (
                        "resume",
                        if fault == ReloadFault::NetdRollbackIncomplete {
                            ResponseBody::Error(ErrorCode::SystemFailure)
                        } else {
                            ResponseBody::Resumed { generation }
                        },
                    ),
                    NetdOperation::Status => (
                        "status",
                        ResponseBody::Status {
                            phase: candy_netd_proto::SessionPhase::Suspended,
                            generation: 6,
                        },
                    ),
                    NetdOperation::Rollback => {
                        ("rollback", ResponseBody::RolledBack { generation })
                    }
                    NetdOperation::Drain { .. } => {
                        ("drain", ResponseBody::Drained { generation })
                    }
                    other => panic!("unexpected netd operation {other:?}"),
                };
                netd_events.lock().unwrap().push(format!("netd:{name}"));
                send_response(
                    &stream,
                    &NetdResponse {
                        request_id: request.request_id,
                        body,
                    },
                    fd,
                )
                .unwrap();
            }
        });
        let core_listener = UnixListener::bind(core_reload_socket(&replacement).unwrap()).unwrap();
        core_listener.set_nonblocking(true).unwrap();
        let core_events = events.clone();
        let core_finished = finished.clone();
        let candidate_config = replacement.config.clone();
        let status_path = replacement.status.clone();
        let pid = child.0.id();
        let core_task = thread::spawn(move || {
            let mut id = None;
            let mut commits = 0;
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let mut stream = match core_listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if core_finished.load(Ordering::SeqCst) {
                            break;
                        }
                        assert!(Instant::now() < deadline, "Core mock timed out");
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                // macOS can reject SO_RCVTIMEO after Abort's sender has
                // closed. Its buffered request is still readable.
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).unwrap();
                let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let action = request["action"].as_str().unwrap();
                core_events.lock().unwrap().push(format!("core:{action}"));
                if action == "prepare" {
                    let transaction = request["transaction_id"].as_str().unwrap();
                    assert_eq!(transaction.len(), 64);
                    id = Some(transaction.to_owned());
                    if fault == ReloadFault::CandidateChanged {
                        write_private(&candidate_config, b"changed while preparing");
                    }
                }
                if matches!(action, "commit" | "abort") {
                    assert_eq!(request["transaction_id"].as_str(), id.as_deref());
                }
                if action == "commit" {
                    commits += 1;
                    if fault == ReloadFault::LostCommitReply {
                        write_private(&status_path, serde_json::json!({
                            "schema_version":3,"generation":7,"pid":pid,"readiness_token":"test-token",
                            "lifecycle":"active","configured_peers":1,"active_peers":1,
                            "required_route_owners":1,"ready_route_owners":1,"fail_open_required":false,
                            "last_error_code":null,"paths":[{"rtt_sample_count":1,"rx_bytes":0,"rx_idle_ms":0}]
                        }).to_string().as_bytes());
                        if commits == 1 {
                            continue;
                        }
                    }
                }
                let ok = !(action == "prepare"
                    && matches!(
                        fault,
                        ReloadFault::PrepareRejected | ReloadFault::PreparePending
                    )
                    || action == "commit" && fault == ReloadFault::CommitUnresolved);
                let response = serde_json::json!({"schema_version":1,"ok":ok,
                    "generation": if matches!(action, "prepare" | "commit") { Some(7) } else { None },
                    "error": if ok { None } else if fault == ReloadFault::PreparePending {
                        Some("peer_preparation_pending: required route owner is unreachable")
                    } else { Some("injected failure") }});
                let _ = stream.write_all(&serde_json::to_vec(&response).unwrap());
            }
        });
        let mut netd = NetdClient::new(
            &current.socket,
            LeaseOwner {
                instance_id: [1; 16],
                pid: std::process::id(),
                generation: 6,
                lease_deadline_mono_ms: monotonic_ms().unwrap() + current.lease_ms,
            },
        );
        let _prepared = netd
            .prepare(parse_declaration(&current.declaration).unwrap())
            .unwrap();
        netd.commit().unwrap();
        events.lock().unwrap().clear();
        let mut transition = HotTransitionState::default();
        let result = hot_replace_activation(
            &current,
            &replacement,
            &mut child.0,
            &mut netd,
            "test-token",
            &mut transition,
        );
        if matches!(
            fault,
            ReloadFault::CommitUnresolved | ReloadFault::NetdRollbackIncomplete
        ) {
            let retry = retry_after_rollback(
                &replacement,
                &mut child.0,
                &mut netd,
                "test unresolved commit recovery",
                "core_policy_commit_unresolved",
                anyhow::anyhow!("injected missing acknowledgement"),
            )
            .unwrap_err();
            let failure = retry.downcast_ref::<RetryableFailure>().unwrap();
            assert_eq!(failure.activation.generation, 7);
            assert_eq!(
                failure.activation.activation_target,
                replacement.activation_target
            );
            assert_eq!(
                wait_before_retry(&failure.activation, Duration::ZERO).unwrap(),
                RetryWait::Retry
            );
            assert!(
                !activation_retry_eligible(&current).unwrap_or(false),
                "launch snapshot should be superseded in this regression"
            );
        }
        drop(netd); // teardown while the mock can acknowledge rollback
        finished.store(true, Ordering::SeqCst);
        core_task.join().unwrap();
        netd_task.join().unwrap();
        let events = events.lock().unwrap();
        assert!(
            events.iter().any(|event| event == "netd:lease"),
            "preparation must renew the old lease"
        );
        let operations: Vec<_> = events
            .iter()
            .filter(|event| !matches!(event.as_str(), "netd:lease" | "netd:rollback"))
            .map(String::as_str)
            .collect();
        match fault {
            ReloadFault::PreparePending => {
                assert!(result
                    .unwrap_err()
                    .downcast_ref::<CorePreparationPending>()
                    .is_some());
                assert_eq!(operations, ["core:prepare", "core:abort"]);
                assert!(!transition.core_suspended && !transition.steering_suspended);
                assert!(
                    !replacement.activation_ready.unwrap().exists(),
                    "temporarily unreachable candidate must not publish a permanent rejection"
                );
            }
            ReloadFault::PrepareRejected | ReloadFault::CandidateChanged => {
                assert!(!result.unwrap());
                assert_eq!(operations, ["core:prepare", "core:abort"]);
                assert!(!transition.core_suspended && !transition.steering_suspended);
            }
            ReloadFault::LostCommitReply => {
                assert!(result.unwrap());
                assert_eq!(
                    operations,
                    [
                        "core:prepare",
                        "netd:suspend",
                        "core:suspend",
                        "netd:reconfigure",
                        "core:commit",
                        "core:commit",
                        "core:resume",
                        "netd:resume"
                    ]
                );
                let receipt: serde_json::Value = serde_json::from_slice(
                    &fs::read(replacement.activation_ready.unwrap()).unwrap(),
                )
                .unwrap();
                assert_eq!(receipt["state"], "committed");
            }
            ReloadFault::CommitUnresolved => {
                assert!(result
                    .unwrap_err()
                    .downcast_ref::<AppliedHotReloadPending>()
                    .is_some());
                assert_eq!(
                    operations,
                    [
                        "core:prepare",
                        "netd:suspend",
                        "core:suspend",
                        "netd:reconfigure",
                        "core:commit",
                        "core:commit"
                    ]
                );
                assert!(transition.complete());
                assert!(
                    !replacement.activation_ready.unwrap().exists(),
                    "uncertain commit must not publish rejection"
                );
            }
            ReloadFault::NetdRollbackIncomplete => {
                assert!(!result.unwrap());
                assert!(!operations.contains(&"core:commit"));
                assert!(!transition.complete());
                assert!(
                    !replacement.activation_ready.unwrap().exists(),
                    "incomplete rollback needs cleanup/retry, not a permanent rejection"
                );
            }
        }
    }

    #[test]
    fn failed_preparation_preserves_live_steering() {
        exercise_prepared_hot_reload(ReloadFault::PrepareRejected);
    }

    #[test]
    fn unavailable_prepared_route_is_retryable_without_mutating_live_steering() {
        exercise_prepared_hot_reload(ReloadFault::PreparePending);
    }

    #[test]
    fn superseded_preparation_aborts_before_netd_mutation() {
        exercise_prepared_hot_reload(ReloadFault::CandidateChanged);
    }

    #[test]
    fn lost_commit_reply_retries_same_transaction_before_resuming() {
        exercise_prepared_hot_reload(ReloadFault::LostCommitReply);
    }

    #[test]
    fn unresolved_commit_preserves_candidate_for_recovery() {
        exercise_prepared_hot_reload(ReloadFault::CommitUnresolved);
    }

    #[test]
    fn incomplete_netd_rollback_retries_desired_activation_instead_of_stalling() {
        exercise_prepared_hot_reload(ReloadFault::NetdRollbackIncomplete);
    }

    #[test]
    fn core_reply_wait_keeps_progress_alive_across_partial_reads() {
        let (_root, args) = server_runtime_fixture();
        let listener = UnixListener::bind(core_reload_socket(&args).unwrap()).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream
                .write_all(br#"{"schema_version":1,"ok":true,"#)
                .unwrap();
            thread::sleep(Duration::from_millis(600));
            stream
                .write_all(br#""generation":7,"error":null}"#)
                .unwrap();
        });
        let mut child = Command::new("/bin/sleep").arg("10").spawn().unwrap();
        let mut progress_calls = 0;
        let result = request_core_transaction(
            &args,
            &mut child,
            CoreReloadAction::Prepare,
            Some(&"a".repeat(64)),
            || {
                progress_calls += 1;
                Ok(())
            },
        );
        let _ = child.kill();
        let _ = child.wait();
        server.join().unwrap();
        result.unwrap();
        assert!(
            progress_calls >= 3,
            "waiting for a split reply must continue lease heartbeats"
        );
    }

    fn activation_fixture() -> (tempfile::TempDir, PathBuf, String) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let activations = root.path().join("activations");
        fs::create_dir(&activations).unwrap();
        fs::set_permissions(&activations, fs::Permissions::from_mode(0o700)).unwrap();
        let activation_id = "a".repeat(64);
        let generation = activations.join(&activation_id);
        fs::create_dir(&generation).unwrap();
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o700)).unwrap();
        write_private(&generation.join("core.toml"), b"schema_version = 1\n");
        write_private(&generation.join("declaration.json"), b"{}");
        write_private(
            &generation.join("activation-v1.json"),
            serde_json::json!({
                "schema_version": 1,
                "activation_id": activation_id,
                "delivery_etag": format!("\"sha256-{}\"", "b".repeat(64)),
                "delivery_sha256": "b".repeat(64),
                "projection_publication_id": "8bf15734-8cdc-40b8-af96-308902a876d8",
                "projection_content_hash": "c".repeat(64),
                "segment_generation": 3,
                "projection_generation": 7,
                "core_role": "client_sdwan",
                "core_config": "core.toml",
                "netd_declaration": "declaration.json",
                "grant_refresh_after_unix": 4_000_000_000_u64,
                "grant_expires_at_unix": 4_102_444_800_u64
            })
            .to_string()
            .as_bytes(),
        );
        let candidate = root.path().join("candidate");
        symlink(Path::new("activations").join(&activation_id), &candidate).unwrap();
        (root, candidate, activation_id)
    }

    fn server_runtime_fixture() -> (tempfile::TempDir, RuntimeArgs) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let candidate = root.path().join("candidate");
        let activation_id = "a".repeat(64);
        let target = Path::new("activations").join(&activation_id);
        symlink(&target, &candidate).unwrap();
        let ordinary = root.path().join("ordinary.toml");
        write_private(&ordinary, b"listen = \"127.0.0.1:8443\"\n");
        let declaration = root.path().join("declaration.json");
        write_private(
            &declaration,
            br#"{"table_id":20000,"overlay_router_ipv4":"10.250.0.1","effective_mtu":1180,"routes":[{"prefix":"10.0.0.0/24","kind":"local"}],"exclusions":[{"prefix":"198.51.100.1/32","kind":"cloud-api"}],"firewall":{"allow_forward":true,"clamp_tcp_mss":true,"require_ipv4_forwarding":true,"manage_rp_filter":true}}"#,
        );
        let args = RuntimeArgs {
            socket: root.path().join("netd.sock"),
            core: root.path().join("missing-core"),
            core_role: CoreRole::Server,
            config: root.path().join("merged.toml"),
            declaration,
            status: root.path().join("status.json"),
            instance_id: activation_id[..32].to_owned(),
            generation: 7,
            lease_ms: 30_000,
            readiness_timeout_ms: 5_000,
            activation_link: Some(candidate),
            activation_target: Some(target),
            activation_descriptor: None,
            activation_config_sha256: None,
            activation_declaration_sha256: None,
            activation_ready: Some(root.path().join("activation-ready-v1.json")),
            ordinary_config: Some(ordinary),
        };
        (root, args)
    }

    fn start_netd_mock_with_shutdown(
        socket: &Path,
        commit_result: Option<bool>,
        shutdown_during_rollback: bool,
    ) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(socket).unwrap();
        thread::spawn(move || {
            let (prepare_stream, _) = listener.accept().unwrap();
            let prepare = recv_request(&prepare_stream).unwrap();
            assert!(matches!(prepare.operation, NetdOperation::Prepare(_)));
            let tun = File::open("/dev/null").unwrap();
            send_response(
                &prepare_stream,
                &NetdResponse {
                    request_id: prepare.request_id,
                    body: ResponseBody::Prepared {
                        generation: prepare.owner.generation,
                        tun_fd_attached: true,
                    },
                },
                Some(tun.as_raw_fd()),
            )
            .unwrap();
            if let Some(commit_ok) = commit_result {
                let (commit_stream, _) = listener.accept().unwrap();
                let commit = recv_request(&commit_stream).unwrap();
                assert!(matches!(commit.operation, NetdOperation::Commit));
                send_response(
                    &commit_stream,
                    &NetdResponse {
                        request_id: commit.request_id,
                        body: if commit_ok {
                            ResponseBody::Committed {
                                generation: commit.owner.generation,
                            }
                        } else {
                            ResponseBody::Error(ErrorCode::SystemFailure)
                        },
                    },
                    None,
                )
                .unwrap();
            }
            let (rollback_stream, _) = listener.accept().unwrap();
            let rollback = recv_request(&rollback_stream).unwrap();
            assert!(matches!(rollback.operation, NetdOperation::Rollback));
            if shutdown_during_rollback {
                request_shutdown(nix::libc::SIGTERM);
            }
            send_response(
                &rollback_stream,
                &NetdResponse {
                    request_id: rollback.request_id,
                    body: ResponseBody::RolledBack {
                        generation: rollback.owner.generation,
                    },
                },
                None,
            )
            .unwrap();
        })
    }

    fn start_netd_mock(socket: &Path, commit_result: Option<bool>) -> thread::JoinHandle<()> {
        start_netd_mock_with_shutdown(socket, commit_result, false)
    }

    fn install_fake_ready_core(path: &Path, lifecycle: &str) {
        let script = format!(
            r#"#!/bin/sh
set -eu
status=
token=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --status) shift; status=$1 ;;
        --readiness-token) shift; token=$1 ;;
    esac
    shift
done
[ -n "$status" ]
[ -n "$token" ]
rm -f "$0"
umask 077
status_tmp="$status.$$".tmp
trap 'rm -f "$status_tmp"' EXIT
printf '{{"schema_version":3,"generation":7,"pid":%s,"readiness_token":"%s","lifecycle":"{}","configured_peers":1,"active_peers":1,"required_route_owners":1,"ready_route_owners":1,"inbound_listener_configured":true,"inbound_listener_ready":true,"inbound_listener_endpoints":["127.0.0.1:8443"],"fail_open_required":false,"last_error_code":null,"paths":[{{"rtt_sample_count":1,"rx_bytes":1,"rx_idle_ms":0}}]}}\n' "$$" "$token" >"$status_tmp"
mv -f "$status_tmp" "$status"
sleep 30
"#,
            lifecycle
        );
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn install_fake_shutdown_core(path: &Path) {
        let script = r#"#!/bin/sh
set -eu
status=
token=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --status) shift; status=$1 ;;
        --readiness-token) shift; token=$1 ;;
    esac
    shift
done
[ -n "$status" ]
[ -n "$token" ]
rm -f "$0"
umask 077
status_tmp="$status.$$".tmp
trap 'rm -f "$status_tmp"' EXIT
printf '{"schema_version":3,"generation":7,"pid":%s,"readiness_token":"%s","lifecycle":"starting","configured_peers":0,"active_peers":0,"required_route_owners":0,"ready_route_owners":0,"inbound_listener_configured":true,"inbound_listener_ready":true,"inbound_listener_endpoints":["127.0.0.1:8443"],"fail_open_required":false,"last_error_code":null}\n' "$$" "$token" >"$status_tmp"
mv -f "$status_tmp" "$status"
kill -TERM "$PPID"
sleep 30
"#;
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn install_fake_partial_server_ready_core(path: &Path) {
        let script = r#"#!/bin/sh
set -eu
status=
token=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --status) shift; status=$1 ;;
        --readiness-token) shift; token=$1 ;;
    esac
    shift
done
[ -n "$status" ]
[ -n "$token" ]
rm -f "$0"
umask 077
status_tmp="$status.$$".tmp
trap 'rm -f "$status_tmp"' EXIT
printf '{"schema_version":3,"generation":7,"pid":%s,"readiness_token":"%s","lifecycle":"active","configured_peers":2,"active_peers":1,"required_route_owners":2,"ready_route_owners":1,"inbound_listener_configured":true,"inbound_listener_ready":true,"inbound_listener_endpoints":["127.0.0.1:8443"],"fail_open_required":false,"last_error_code":null,"paths":[{"rtt_sample_count":1,"rx_bytes":1,"rx_idle_ms":0}]}\n' "$$" "$token" >"$status_tmp"
mv -f "$status_tmp" "$status"
sleep 1
kill -TERM "$PPID"
sleep 30
"#;
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn install_fake_recovering_server_core(path: &Path) {
        let script = r#"#!/bin/sh
set -eu
status=
token=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --status) shift; status=$1 ;;
        --readiness-token) shift; token=$1 ;;
    esac
    shift
done
[ -n "$status" ]
[ -n "$token" ]
rm -f "$0"
umask 077
status_tmp="$status.$$".tmp
trap 'rm -f "$status_tmp"' EXIT
printf '{"schema_version":3,"generation":7,"pid":%s,"readiness_token":"%s","lifecycle":"active","configured_peers":1,"active_peers":1,"required_route_owners":1,"ready_route_owners":1,"inbound_listener_configured":true,"inbound_listener_ready":true,"inbound_listener_endpoints":["127.0.0.1:8443"],"fail_open_required":false,"last_error_code":null,"paths":[{"rtt_sample_count":1,"rx_bytes":1,"rx_idle_ms":0}]}\n' "$$" "$token" >"$status_tmp"
mv -f "$status_tmp" "$status"
sleep 1
printf '{"schema_version":3,"generation":7,"pid":%s,"readiness_token":"%s","lifecycle":"failed","configured_peers":1,"active_peers":0,"required_route_owners":1,"ready_route_owners":0,"inbound_listener_configured":true,"inbound_listener_ready":true,"inbound_listener_endpoints":["127.0.0.1:8443"],"fail_open_required":true,"last_error_code":"all_peer_reads_failed","paths":[]}\n' "$$" "$token" >"$status_tmp"
mv -f "$status_tmp" "$status"
sleep 1
printf '{"schema_version":3,"generation":7,"pid":%s,"readiness_token":"%s","lifecycle":"starting","configured_peers":1,"active_peers":0,"required_route_owners":1,"ready_route_owners":0,"inbound_listener_configured":true,"inbound_listener_ready":true,"inbound_listener_endpoints":["127.0.0.1:8443"],"fail_open_required":true,"last_error_code":"all_peer_reads_failed","paths":[]}\n' "$$" "$token" >"$status_tmp"
mv -f "$status_tmp" "$status"
sleep 1
printf '{"schema_version":3,"generation":7,"pid":%s,"readiness_token":"%s","lifecycle":"active","configured_peers":1,"active_peers":1,"required_route_owners":1,"ready_route_owners":1,"inbound_listener_configured":true,"inbound_listener_ready":true,"inbound_listener_endpoints":["127.0.0.1:8443"],"fail_open_required":false,"last_error_code":null,"paths":[{"rtt_sample_count":2,"rx_bytes":2,"rx_idle_ms":0}]}\n' "$$" "$token" >"$status_tmp"
mv -f "$status_tmp" "$status"
sleep 1
kill -TERM "$PPID"
sleep 30
"#;
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn install_fake_exiting_core(path: &Path) {
        let script = r#"#!/bin/sh
set -eu
status=
token=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --status) shift; status=$1 ;;
        --readiness-token) shift; token=$1 ;;
    esac
    shift
done
[ -n "$status" ]
[ -n "$token" ]
umask 077
status_tmp="$status.$$".tmp
trap 'rm -f "$status_tmp"' EXIT
printf '{"schema_version":3,"generation":7,"pid":%s,"readiness_token":"%s","lifecycle":"active","configured_peers":1,"active_peers":1,"required_route_owners":1,"ready_route_owners":1,"inbound_listener_configured":true,"inbound_listener_ready":true,"inbound_listener_endpoints":["127.0.0.1:8443"],"fail_open_required":false,"last_error_code":null,"paths":[{"rtt_sample_count":1,"rx_bytes":1,"rx_idle_ms":0}]}\n' "$$" "$token" >"$status_tmp"
mv -f "$status_tmp" "$status"
sleep 1
exit 17
"#;
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn activation_descriptor_is_bound_to_immutable_candidate_target() {
        let (_root, candidate, activation_id) = activation_fixture();
        let (descriptor, target, config, declaration) = resolve_activation(&candidate).unwrap();
        assert_eq!(descriptor.activation_id, activation_id);
        assert_eq!(target, Path::new("activations").join(&activation_id));
        assert_eq!(config.file_name().unwrap(), "core.toml");
        assert_eq!(declaration.file_name().unwrap(), "declaration.json");
        validate_activation_command(&candidate, CoreRole::ClientSdwan, None).unwrap();
        assert!(validate_activation_command(&candidate, CoreRole::Server, None).is_err());
    }

    #[test]
    fn documented_run_first_cli_accepts_global_runtime_arguments() {
        let args = Args::try_parse_from([
            "candy-sdwan-agent",
            "run",
            "--core",
            "/bin/true",
            "--activation",
            "/var/lib/candy/sdwan/candidate",
        ])
        .unwrap();
        assert!(matches!(args.command, Some(CommandKind::Run)));
        assert_eq!(args.core.as_deref(), Some(Path::new("/bin/true")));
    }

    #[test]
    fn server_activation_requires_a_readable_ordinary_config_for_fail_open() {
        let (_root, candidate, _) = activation_fixture();
        let descriptor_path = candidate.join("activation-v1.json");
        let mut descriptor: serde_json::Value =
            serde_json::from_slice(&fs::read(&descriptor_path).unwrap()).unwrap();
        descriptor["core_role"] = serde_json::Value::String("server".into());
        write_private(
            &descriptor_path,
            serde_json::to_string(&descriptor).unwrap().as_bytes(),
        );
        let args = Args::try_parse_from([
            "candy-sdwan-agent",
            "run",
            "--core",
            "/bin/true",
            "--activation",
            candidate.to_str().unwrap(),
        ])
        .unwrap();
        let error = resolve_runtime_args(args).unwrap_err();
        assert!(error.to_string().contains("ordinary-config"));
    }

    #[test]
    fn server_invalid_declaration_falls_back_to_ordinary_core() {
        let (_root, args) = server_runtime_fixture();
        write_private(&args.declaration, b"{}");
        let error = run(args).unwrap_err();
        assert!(
            format!("{error:#}").contains("ordinary Candy Server"),
            "{error:#}"
        );
    }

    #[test]
    fn server_netd_prepare_failure_falls_back_to_ordinary_core() {
        let (_root, args) = server_runtime_fixture();
        let receipt = args.activation_ready.clone().unwrap();
        let error = run(args).unwrap_err();
        assert!(
            format!("{error:#}").contains("ordinary Candy Server"),
            "{error:#}"
        );
        let value: serde_json::Value = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        assert_eq!(value["state"], "rejected");
        assert_eq!(value["error_code"], "netd_prepare_failed");
    }

    #[test]
    fn server_merged_core_spawn_failure_rolls_back_then_falls_back() {
        let (_root, args) = server_runtime_fixture();
        let receipt = args.activation_ready.clone().unwrap();
        let netd = start_netd_mock(&args.socket, None);
        let error = run(args).unwrap_err();
        netd.join().unwrap();
        assert!(
            format!("{error:#}").contains("ordinary Candy Server"),
            "{error:#}"
        );
        let value: serde_json::Value = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        assert_eq!(value["state"], "rejected");
        assert_eq!(value["error_code"], "core_start_failed");
    }

    #[test]
    fn server_readiness_failure_rolls_back_then_falls_back() {
        let (_root, mut args) = server_runtime_fixture();
        install_fake_ready_core(&args.core, "failed");
        let receipt = args.activation_ready.clone().unwrap();
        args.readiness_timeout_ms = 2_000;
        let netd = start_netd_mock(&args.socket, None);
        let error = run(args).unwrap_err();
        netd.join().unwrap();
        assert!(
            format!("{error:#}").contains("ordinary Candy Server"),
            "{error:#}"
        );
        let value: serde_json::Value = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        assert_eq!(value["error_code"], "core_readiness_failed");
    }

    #[test]
    fn server_shutdown_during_readiness_rolls_back_without_rejection_or_fallback() {
        let (_root, mut args) = server_runtime_fixture();
        install_fake_shutdown_core(&args.core);
        let receipt = args.activation_ready.clone().unwrap();
        write_private(&receipt, b"stale receipt");
        args.readiness_timeout_ms = 2_000;
        let netd = start_netd_mock(&args.socket, None);

        let result = run(args);

        netd.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert!(
            !receipt.exists(),
            "normal shutdown retained or replaced the activation receipt"
        );
    }

    #[test]
    fn server_partial_route_readiness_commits_when_listener_is_ready() {
        let (_root, mut args) = server_runtime_fixture();
        install_fake_partial_server_ready_core(&args.core);
        let receipt = args.activation_ready.clone().unwrap();
        args.readiness_timeout_ms = 2_000;
        let netd = start_netd_mock(&args.socket, Some(true));

        let result = run(args);

        netd.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert!(
            !receipt.exists(),
            "normal shutdown retained the activation receipt"
        );
    }

    #[test]
    fn committed_server_waits_for_recoverable_peer_loss_without_restarting_core() {
        let (_root, mut args) = server_runtime_fixture();
        install_fake_recovering_server_core(&args.core);
        let receipt = args.activation_ready.clone().unwrap();
        args.readiness_timeout_ms = 2_000;
        let netd = start_netd_mock(&args.socket, Some(true));

        let result = run(args);

        netd.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert!(
            !receipt.exists(),
            "normal shutdown retained the activation receipt"
        );
    }

    #[test]
    fn server_commit_failure_stops_merged_core_rolls_back_and_falls_back() {
        let (_root, args) = server_runtime_fixture();
        install_fake_ready_core(&args.core, "active");
        let receipt = args.activation_ready.clone().unwrap();
        let netd = start_netd_mock(&args.socket, Some(false));
        let error = run(args).unwrap_err();
        netd.join().unwrap();
        assert!(
            format!("{error:#}").contains("ordinary Candy Server"),
            "{error:#}"
        );
        let value: serde_json::Value = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        assert_eq!(value["error_code"], "netd_commit_failed");
    }

    #[test]
    fn server_shutdown_during_failure_rollback_never_starts_ordinary_core() {
        let (_root, args) = server_runtime_fixture();
        install_fake_ready_core(&args.core, "active");
        let receipt = args.activation_ready.clone().unwrap();
        write_private(&receipt, b"stale receipt");
        let netd = start_netd_mock_with_shutdown(&args.socket, Some(false), true);

        let result = run(args);

        netd.join().unwrap();
        assert!(
            result.is_ok(),
            "shutdown entered ordinary fallback: {result:?}"
        );
        assert!(
            !receipt.exists(),
            "shutdown retained or published an activation rejection receipt"
        );
    }

    #[test]
    fn server_receipt_failure_rolls_back_and_falls_back() {
        let (_root, mut args) = server_runtime_fixture();
        install_fake_ready_core(&args.core, "active");
        args.activation_ready = Some(args.socket.join("missing/receipt.json"));
        let netd = start_netd_mock(&args.socket, Some(true));
        let error = run(args).unwrap_err();
        netd.join().unwrap();
        assert!(
            format!("{error:#}").contains("ordinary Candy Server"),
            "{error:#}"
        );
    }

    #[test]
    fn activation_pointer_replacement_is_detected_after_launch() {
        let (root, candidate, activation_id) = activation_fixture();
        let args = RuntimeArgs {
            socket: PathBuf::new(),
            core: PathBuf::new(),
            core_role: CoreRole::ClientSdwan,
            config: PathBuf::new(),
            declaration: PathBuf::new(),
            status: PathBuf::new(),
            instance_id: String::new(),
            generation: 1,
            lease_ms: 30_000,
            readiness_timeout_ms: 20_000,
            activation_link: Some(candidate.clone()),
            activation_target: Some(Path::new("activations").join(activation_id)),
            activation_descriptor: None,
            activation_config_sha256: None,
            activation_declaration_sha256: None,
            activation_ready: None,
            ordinary_config: None,
        };
        assert!(activation_pointer_unchanged(&args).unwrap());
        assert_eq!(
            activation_pointer_state(&args).unwrap(),
            ActivationPointerState::Unchanged
        );
        fs::remove_file(&candidate).unwrap();
        symlink(
            "activations/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            &candidate,
        )
        .unwrap();
        assert!(!activation_pointer_unchanged(&args).unwrap());
        assert_eq!(
            activation_pointer_state(&args).unwrap(),
            ActivationPointerState::Superseded
        );
        fs::remove_file(&candidate).unwrap();
        assert_eq!(
            activation_pointer_state(&args).unwrap(),
            ActivationPointerState::Withdrawn
        );
        drop(root);
    }

    #[test]
    fn withdrawn_activation_receipt_cleanup_is_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let receipt = root.path().join("activation-ready-v1.json");
        write_private(&receipt, br#"{"state":"committed","generation":7}"#);

        remove_activation_receipt(Some(&receipt)).unwrap();
        // A withdrawn policy is observed repeatedly until its candidate is
        // replaced. Reprocessing the event must remain harmless after the
        // first successful cleanup.
        remove_activation_receipt(Some(&receipt)).unwrap();
        assert!(!receipt.exists());
    }

    #[test]
    fn retry_backoff_is_exponential_capped_and_resets_after_stability() {
        let mut backoff = RetryBackoff::new();
        assert_eq!(
            backoff.delay_after_failure(Duration::ZERO),
            Duration::from_secs(1)
        );
        assert_eq!(
            backoff.delay_after_failure(Duration::ZERO),
            Duration::from_secs(2)
        );
        for _ in 0..10 {
            backoff.delay_after_failure(Duration::ZERO);
        }
        assert_eq!(
            backoff.delay_after_failure(Duration::ZERO),
            Duration::from_secs(30)
        );
        assert_eq!(
            backoff.delay_after_failure(RETRY_STABLE_RESET),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn retry_wait_is_cancelled_by_candidate_withdrawal() {
        let (_root, candidate, _) = activation_fixture();
        let args = resolve_runtime_args(
            Args::try_parse_from([
                "candy-sdwan-agent",
                "run",
                "--core",
                "/bin/true",
                "--activation",
                candidate.to_str().unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        fs::remove_file(&candidate).unwrap();
        assert_eq!(
            wait_before_retry(&args, Duration::ZERO).unwrap(),
            RetryWait::Stop
        );
    }

    #[test]
    fn non_expiring_server_activation_remains_retry_eligible() {
        let (_root, candidate, _) = activation_fixture();
        let mut args = resolve_runtime_args(
            Args::try_parse_from([
                "candy-sdwan-agent",
                "run",
                "--core",
                "/bin/true",
                "--activation",
                candidate.to_str().unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        let descriptor = args.activation_descriptor.as_mut().unwrap();
        descriptor.grant_refresh_after_unix = 0;
        descriptor.grant_expires_at_unix = 0;
        assert!(grant_retry_eligible(
            args.activation_descriptor.as_ref().unwrap(),
            u64::MAX
        ));
    }

    #[test]
    fn retry_wait_is_cancelled_by_descriptor_change() {
        let (_root, candidate, _) = activation_fixture();
        let args = resolve_runtime_args(
            Args::try_parse_from([
                "candy-sdwan-agent",
                "run",
                "--core",
                "/bin/true",
                "--activation",
                candidate.to_str().unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        let descriptor_path = candidate.join("activation-v1.json");
        let mut descriptor: serde_json::Value =
            serde_json::from_slice(&fs::read(&descriptor_path).unwrap()).unwrap();
        descriptor["projection_content_hash"] = serde_json::Value::String("d".repeat(64));
        write_private(
            &descriptor_path,
            serde_json::to_string(&descriptor).unwrap().as_bytes(),
        );
        assert_eq!(
            wait_before_retry(&args, Duration::ZERO).unwrap(),
            RetryWait::Stop
        );
    }

    #[test]
    fn retry_wait_is_cancelled_by_activation_content_change() {
        let (_root, candidate, _) = activation_fixture();
        let args = resolve_runtime_args(
            Args::try_parse_from([
                "candy-sdwan-agent",
                "run",
                "--core",
                "/bin/true",
                "--activation",
                candidate.to_str().unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        write_private(
            &candidate.join("core.toml"),
            b"schema_version = 1\nchanged = true\n",
        );
        assert_eq!(
            wait_before_retry(&args, Duration::ZERO).unwrap(),
            RetryWait::Stop
        );
    }

    #[test]
    fn retry_wait_is_interrupted_by_shutdown() {
        let _test_guard = RUN_TEST_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("SD-WAN agent test lock poisoned");
        let (_root, candidate, _) = activation_fixture();
        let args = resolve_runtime_args(
            Args::try_parse_from([
                "candy-sdwan-agent",
                "run",
                "--core",
                "/bin/true",
                "--activation",
                candidate.to_str().unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
        let result = wait_before_retry(&args, Duration::from_secs(30));
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        assert_eq!(result.unwrap(), RetryWait::Stop);
    }

    #[test]
    fn committed_core_exit_rolls_back_before_becoming_retryable() {
        let _test_guard = RUN_TEST_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("SD-WAN agent test lock poisoned");
        let (_root, candidate, _) = activation_fixture();
        let activation = candidate
            .parent()
            .unwrap()
            .join("activations")
            .join("a".repeat(64));
        write_private(
            &activation.join("declaration.json"),
            br#"{"table_id":20000,"overlay_router_ipv4":"10.250.0.1","effective_mtu":1180,"routes":[{"prefix":"10.0.0.0/24","kind":"local"}],"exclusions":[{"prefix":"198.51.100.1/32","kind":"cloud-api"}],"firewall":{"allow_forward":true,"clamp_tcp_mss":true,"require_ipv4_forwarding":true,"manage_rp_filter":true}}"#,
        );
        let core = candidate.parent().unwrap().join("fake-core");
        install_fake_exiting_core(&core);
        let socket = candidate.parent().unwrap().join("netd.sock");
        let receipt = candidate.parent().unwrap().join("activation-ready-v1.json");
        let core_status = candidate.parent().unwrap().join("core-status.json");
        let args = resolve_runtime_args(
            Args::try_parse_from([
                "candy-sdwan-agent",
                "run",
                "--socket",
                socket.to_str().unwrap(),
                "--core",
                core.to_str().unwrap(),
                "--activation",
                candidate.to_str().unwrap(),
                "--activation-ready",
                receipt.to_str().unwrap(),
                "--status",
                core_status.to_str().unwrap(),
                "--readiness-timeout-ms",
                "2000",
            ])
            .unwrap(),
        )
        .unwrap();
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        let status = args.status.clone();
        let netd = start_netd_mock(&socket, Some(true));

        let error = run_once(args.clone(), false).unwrap_err();

        netd.join().unwrap();
        let failure = error
            .downcast_ref::<RetryableFailure>()
            .expect("committed Core exit was not classified as retryable");
        assert_eq!(failure.error_code, "core_exit");
        assert!(!receipt.exists(), "committed receipt survived fail-open");
        assert!(!status.exists(), "stale Core status survived fail-open");
        let marker: RuntimeFailureMarker = serde_json::from_slice(
            &fs::read(runtime_failure_marker_path(&status).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(marker.generation, args.generation);
        assert_eq!(marker.error_code, "core_exit");
        assert!(activation_retry_eligible(&args).unwrap());
    }

    #[test]
    fn transient_readiness_exit_remains_retryable_without_rejection() {
        let _test_guard = RUN_TEST_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("SD-WAN agent test lock poisoned");
        let (_root, candidate, _) = activation_fixture();
        let activation = candidate
            .parent()
            .unwrap()
            .join("activations")
            .join("a".repeat(64));
        write_private(
            &activation.join("declaration.json"),
            br#"{"table_id":20000,"overlay_router_ipv4":"10.250.0.1","effective_mtu":1180,"routes":[{"prefix":"10.0.0.0/24","kind":"local"}],"exclusions":[{"prefix":"198.51.100.1/32","kind":"cloud-api"}],"firewall":{"allow_forward":true,"clamp_tcp_mss":true,"require_ipv4_forwarding":true,"manage_rp_filter":true}}"#,
        );
        let core = candidate.parent().unwrap().join("early-exit-core");
        fs::write(&core, "#!/bin/sh\nexit 17\n").unwrap();
        fs::set_permissions(&core, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = candidate.parent().unwrap().join("recovery-netd.sock");
        let receipt = candidate.parent().unwrap().join("activation-ready-v1.json");
        let core_status = candidate.parent().unwrap().join("recovery-status.json");
        let args = resolve_runtime_args(
            Args::try_parse_from([
                "candy-sdwan-agent",
                "run",
                "--socket",
                socket.to_str().unwrap(),
                "--core",
                core.to_str().unwrap(),
                "--activation",
                candidate.to_str().unwrap(),
                "--activation-ready",
                receipt.to_str().unwrap(),
                "--status",
                core_status.to_str().unwrap(),
                "--readiness-timeout-ms",
                "2000",
            ])
            .unwrap(),
        )
        .unwrap();
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        let netd = start_netd_mock(&socket, None);

        let error = run_once(args, true).unwrap_err();

        netd.join().unwrap();
        let failure = error
            .downcast_ref::<RetryableFailure>()
            .expect("recovery readiness failure was not retryable");
        assert_eq!(failure.error_code, "core_readiness_failed");
        assert!(!receipt.exists(), "recovery published a rejection receipt");
        assert!(!core_status.exists(), "recovery retained stale Core status");
    }
    #[test]
    fn rejects_noncanonical_prefix() {
        assert!(parse_prefix("10.0.0.1/8").is_err());
    }
    #[test]
    fn parses_instance_id() {
        assert_eq!(
            parse_instance_id("00112233445566778899aabbccddeeff").unwrap()[0],
            0
        );
    }
    #[test]
    fn rejects_short_instance_id() {
        assert!(parse_instance_id("abcd").is_err());
    }

    fn status(generation: u64, lifecycle: &str, configured: usize, active: usize) -> String {
        serde_json::json!({
            "schema_version": 3,
            "generation": generation,
            "pid": 42,
            "readiness_token": "00112233445566778899aabbccddeeff",
            "lifecycle": lifecycle,
            "configured_peers": configured,
            "active_peers": active,
            "required_route_owners": 1,
            "ready_route_owners": active.min(1),
            "inbound_listener_configured": false,
            "inbound_listener_ready": false,
            "inbound_listener_endpoints": [],
            "fail_open_required": false,
            "last_error_code": null,
            "paths": if lifecycle == "active" { serde_json::json!([{"rtt_sample_count": 1, "rx_bytes": 1, "rx_idle_ms": 0}]) } else { serde_json::json!([]) }
        })
        .to_string()
    }

    #[test]
    fn readiness_requires_matching_generation_and_an_active_authorized_peer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        fs::write(&path, status(9, "starting", 1, 0)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").unwrap(),
            Some(ReadinessState::Waiting)
        );
        fs::write(&path, status(9, "active", 1, 1)).unwrap();
        let mut no_path =
            serde_json::from_str::<serde_json::Value>(&status(9, "active", 1, 1)).unwrap();
        no_path.as_object_mut().unwrap().remove("paths");
        fs::write(&path, serde_json::to_vec(&no_path).unwrap()).unwrap();
        assert!(read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").is_err());
        let mut active =
            serde_json::from_str::<serde_json::Value>(&status(9, "active", 1, 1)).unwrap();
        fs::write(&path, serde_json::to_vec(&active).unwrap()).unwrap();
        assert_eq!(
            read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").unwrap(),
            Some(ReadinessState::Ready)
        );
        // A freshly reconnected lane may not have received payload bytes yet,
        // but its authenticated path and RTT sample are sufficient to resume
        // SD-WAN.  RX counters must not force an unnecessary Core restart.
        active["paths"] =
            serde_json::json!([{ "rtt_sample_count": 1, "rx_bytes": 0, "rx_idle_ms": 0 }]);
        fs::write(&path, serde_json::to_vec(&active).unwrap()).unwrap();
        assert_eq!(
            read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").unwrap(),
            Some(ReadinessState::Ready)
        );
        active["paths"] = serde_json::json!([]);
        fs::write(&path, serde_json::to_vec(&active).unwrap()).unwrap();
        assert!(read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").is_err());
        active["paths"] =
            serde_json::json!([{ "rtt_sample_count": 0, "rx_bytes": 1, "rx_idle_ms": 0 }]);
        fs::write(&path, serde_json::to_vec(&active).unwrap()).unwrap();
        assert!(read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").is_err());
        active["configured_peers"] = serde_json::json!(2);
        active["active_peers"] = serde_json::json!(2);
        active["required_route_owners"] = serde_json::json!(2);
        active["ready_route_owners"] = serde_json::json!(2);
        active["paths"] =
            serde_json::json!([{ "rtt_sample_count": 1, "rx_bytes": 1, "rx_idle_ms": 0 }]);
        fs::write(&path, serde_json::to_vec(&active).unwrap()).unwrap();
        assert!(read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").is_err());
        active["paths"] = serde_json::json!([
            { "rtt_sample_count": 1, "rx_bytes": 1, "rx_idle_ms": 0 },
            { "rtt_sample_count": 2, "rx_bytes": 1, "rx_idle_ms": 0 }
        ]);
        fs::write(&path, serde_json::to_vec(&active).unwrap()).unwrap();
        assert_eq!(
            read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").unwrap(),
            Some(ReadinessState::Ready)
        );
        active["paths"] = serde_json::json!([
            { "rtt_sample_count": 1, "rx_bytes": 1, "rx_idle_ms": 120_000 },
            { "rtt_sample_count": 2, "rx_bytes": 1, "rx_idle_ms": 180_000 }
        ]);
        fs::write(&path, serde_json::to_vec(&active).unwrap()).unwrap();
        assert_eq!(
            read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").unwrap(),
            Some(ReadinessState::Ready)
        );
        active["ready_route_owners"] = serde_json::json!(1);
        active["paths"] =
            serde_json::json!([{ "rtt_sample_count": 1, "rx_bytes": 1, "rx_idle_ms": 0 }]);
        fs::write(&path, serde_json::to_vec(&active).unwrap()).unwrap();
        assert_eq!(
            read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").unwrap(),
            Some(ReadinessState::Waiting)
        );
        active["paths"] =
            serde_json::json!([{ "rtt_sample_count": 0, "rx_bytes": 1, "rx_idle_ms": 0 }]);
        fs::write(&path, serde_json::to_vec(&active).unwrap()).unwrap();
        assert!(read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").is_err());
        assert_eq!(
            read_core_readiness(&path, 10, 42, "00112233445566778899aabbccddeeff").unwrap(),
            None
        );
        assert!(read_core_readiness(&path, 8, 42, "00112233445566778899aabbccddeeff").is_err());
        assert!(read_core_readiness(&path, 9, 43, "00112233445566778899aabbccddeeff").is_err());
        assert!(read_core_readiness(&path, 9, 42, "11112233445566778899aabbccddeeff").is_err());
        fs::write(&path, status(9, "active", 1, 0)).unwrap();
        assert!(read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").is_err());
    }

    #[test]
    fn listener_readiness_is_distinct_from_route_readiness() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        fs::write(
            &path,
            serde_json::json!({
                "schema_version": 3,
                "generation": 9,
                "pid": 42,
                "readiness_token": "00112233445566778899aabbccddeeff",
                "lifecycle": "starting",
                "configured_peers": 0,
                "active_peers": 0,
                "required_route_owners": 0,
                "ready_route_owners": 0,
                "inbound_listener_configured": true,
                "inbound_listener_ready": true,
                "inbound_listener_endpoints": ["127.0.0.1:8443"],
                "fail_open_required": false,
                "last_error_code": null
            })
            .to_string(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").unwrap(),
            Some(ReadinessState::ListenerReady)
        );
        fs::write(&path, status(9, "active", 1, 1)).unwrap();
        assert_eq!(
            read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").unwrap(),
            Some(ReadinessState::Ready)
        );
        let mut partial =
            serde_json::from_str::<serde_json::Value>(&status(9, "active", 2, 1)).unwrap();
        partial["required_route_owners"] = serde_json::json!(2);
        partial["inbound_listener_configured"] = serde_json::json!(true);
        partial["inbound_listener_ready"] = serde_json::json!(true);
        partial["inbound_listener_endpoints"] = serde_json::json!(["127.0.0.1:8443"]);
        fs::write(&path, serde_json::to_vec(&partial).unwrap()).unwrap();
        assert_eq!(
            read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").unwrap(),
            Some(ReadinessState::Degraded)
        );
    }

    #[test]
    fn recoverable_peer_loss_requires_a_committed_activation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut failed = serde_json::json!({
            "schema_version": 3,
            "generation": 9,
            "pid": 42,
            "readiness_token": "00112233445566778899aabbccddeeff",
            "lifecycle": "failed",
            "configured_peers": 1,
            "active_peers": 0,
            "required_route_owners": 1,
            "ready_route_owners": 0,
            "inbound_listener_configured": true,
            "inbound_listener_ready": true,
            "inbound_listener_endpoints": ["127.0.0.1:8443"],
            "fail_open_required": true,
            "last_error_code": "all_peer_reads_failed",
            "paths": []
        });
        write_private(&path, &serde_json::to_vec(&failed).unwrap());

        assert!(read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").is_err());
        assert_eq!(
            read_core_readiness_with_policy(
                &path,
                9,
                42,
                "00112233445566778899aabbccddeeff",
                ReadinessPolicy::Committed,
            )
            .unwrap(),
            Some(ReadinessState::RecoverablePeerLoss)
        );
        assert_eq!(
            read_core_readiness_with_policy(
                &path,
                9,
                42,
                "00112233445566778899aabbccddeeff",
                ReadinessPolicy::CommittedServer,
            )
            .unwrap(),
            Some(ReadinessState::RecoverablePeerLoss)
        );

        // Core can remain lifecycle=active while the routing actor records
        // fail-open after the final peer lane drops.  This is the normal
        // transient state seen during a reconnect and must not trigger a
        // process restart or permanent rejection.
        failed["lifecycle"] = serde_json::json!("active");
        write_private(&path, &serde_json::to_vec(&failed).unwrap());
        assert_eq!(
            read_core_readiness_with_policy(
                &path,
                9,
                42,
                "00112233445566778899aabbccddeeff",
                ReadinessPolicy::Committed,
            )
            .unwrap(),
            Some(ReadinessState::RecoverablePeerLoss)
        );

        failed["last_error_code"] = serde_json::json!("route_has_no_active_peer");
        write_private(&path, &serde_json::to_vec(&failed).unwrap());
        assert_eq!(
            read_core_readiness_with_policy(
                &path,
                9,
                42,
                "00112233445566778899aabbccddeeff",
                ReadinessPolicy::CommittedServer,
            )
            .unwrap(),
            Some(ReadinessState::RecoverablePeerLoss)
        );

        failed["last_error_code"] = serde_json::json!("all_peer_writes_failed");
        write_private(&path, &serde_json::to_vec(&failed).unwrap());
        assert_eq!(
            read_core_readiness_with_policy(
                &path,
                9,
                42,
                "00112233445566778899aabbccddeeff",
                ReadinessPolicy::CommittedServer,
            )
            .unwrap(),
            Some(ReadinessState::RecoverablePeerLoss)
        );

        failed["lifecycle"] = serde_json::json!("starting");
        write_private(&path, &serde_json::to_vec(&failed).unwrap());
        assert_eq!(
            read_core_readiness_with_policy(
                &path,
                9,
                42,
                "00112233445566778899aabbccddeeff",
                ReadinessPolicy::CommittedServer,
            )
            .unwrap(),
            Some(ReadinessState::RecoverablePeerLoss)
        );

        for (field, value) in [
            ("inbound_listener_ready", serde_json::json!(false)),
            ("required_route_owners", serde_json::json!(0)),
            ("ready_route_owners", serde_json::json!(1)),
            ("last_error_code", serde_json::json!("tun_read_failed")),
        ] {
            let mut rejected = failed.clone();
            rejected[field] = value;
            write_private(&path, &serde_json::to_vec(&rejected).unwrap());
            assert!(read_core_readiness_with_policy(
                &path,
                9,
                42,
                "00112233445566778899aabbccddeeff",
                ReadinessPolicy::CommittedServer,
            )
            .is_err());
        }
    }

    #[test]
    fn committed_partial_route_loss_preserves_healthy_owners() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let status = serde_json::json!({
            "schema_version": 3,
            "generation": 9,
            "pid": 42,
            "readiness_token": "00112233445566778899aabbccddeeff",
            "lifecycle": "active",
            "configured_peers": 2,
            "active_peers": 1,
            "required_route_owners": 2,
            "ready_route_owners": 1,
            "inbound_listener_configured": false,
            "inbound_listener_ready": false,
            "inbound_listener_endpoints": [],
            "fail_open_required": false,
            "last_error_code": "route_has_no_active_peer",
            "last_error_detail": "one route owner is unavailable",
            "paths": [{"rtt_sample_count": 1, "rx_bytes": 512, "rx_idle_ms": 0}]
        });
        write_private(&path, &serde_json::to_vec(&status).unwrap());

        assert_eq!(
            read_core_readiness_with_policy(
                &path,
                9,
                42,
                "00112233445566778899aabbccddeeff",
                ReadinessPolicy::Committed,
            )
            .unwrap(),
            Some(ReadinessState::Degraded)
        );
        // Initial activation remains conservative: without a committed
        // steering owner, partial readiness must not be admitted.
        assert_eq!(
            read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").unwrap(),
            Some(ReadinessState::Waiting)
        );

        let mut fatal = status;
        fatal["last_error_code"] = serde_json::json!("tun_read_failed");
        fatal["fail_open_required"] = serde_json::json!(true);
        write_private(&path, &serde_json::to_vec(&fatal).unwrap());
        assert!(read_core_readiness_with_policy(
            &path,
            9,
            42,
            "00112233445566778899aabbccddeeff",
            ReadinessPolicy::Committed,
        )
        .is_err());
    }

    #[test]
    fn stale_status_is_removed_before_candidate_start() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        fs::write(&path, status(9, "active", 1, 1)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        remove_stale_status(&path).unwrap();
        assert!(!path.exists());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(directory.path().join("target"), &path).unwrap();
            assert!(remove_stale_status(&path).is_err());
        }
    }

    #[test]
    fn superseded_activation_statuses_are_reclaimed_without_touching_other_files() {
        let directory = tempfile::tempdir().unwrap();
        let current = directory
            .path()
            .join(format!("sdwan-{}.status.json", "a".repeat(64)));
        let stale = directory
            .path()
            .join(format!("sdwan-{}.status.json", "b".repeat(64)));
        let unrelated = directory.path().join("sdwan-status.json");
        fs::write(&current, status(9, "active", 1, 1)).unwrap();
        fs::write(&stale, status(8, "active", 1, 1)).unwrap();
        fs::write(&unrelated, "runtime product status").unwrap();

        assert_eq!(cleanup_superseded_activation_statuses(&current).unwrap(), 1);
        assert!(current.exists());
        assert!(!stale.exists());
        assert!(unrelated.exists());

        #[cfg(unix)]
        {
            let link = directory
                .path()
                .join(format!("sdwan-{}.status.json", "c".repeat(64)));
            std::os::unix::fs::symlink(directory.path().join("target"), &link).unwrap();
            assert_eq!(cleanup_superseded_activation_statuses(&current).unwrap(), 0);
            assert!(link.exists() || fs::symlink_metadata(&link).is_ok());
        }
    }

    #[test]
    fn readiness_token_is_random_bounded_hex() {
        let first = generate_readiness_token().unwrap();
        let second = generate_readiness_token().unwrap();
        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }
}
