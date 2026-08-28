use anyhow::{bail, Context, Result};
use candy_netd_client::NetdClient;
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, LeaseOwner, PrepareDeclaration, RouteDeclaration, RouteKind,
    UnderlayExclusion, UnderlayKind,
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
const MAX_ACTIVATION_BYTES: u64 = 64 * 1024;
const CORE_TERMINATION_GRACE: Duration = Duration::from_secs(15);
const RETRY_INITIAL_DELAY: Duration = Duration::from_secs(1);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(30);
const RETRY_STABLE_RESET: Duration = Duration::from_secs(60);
const RETRY_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TRAFFIC_BLACKHOLE_PACKET_THRESHOLD: u64 = 8;
const TRAFFIC_BLACKHOLE_WINDOW: Duration = Duration::from_secs(5);
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

#[derive(Debug)]
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
    paths: Option<Vec<CoreReadinessPath>>,
    #[serde(default)]
    counters: CoreTrafficCounters,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
struct CoreTrafficCounters {
    tun_packets_received: u64,
    tun_packets_sent: u64,
    peer_records_sent: u64,
    drops: u64,
}

#[derive(Debug, Default)]
struct TrafficBlackholeMonitor {
    baseline: Option<(CoreTrafficCounters, Instant)>,
}

impl TrafficBlackholeMonitor {
    fn observe(&mut self, counters: CoreTrafficCounters, now: Instant) -> bool {
        let Some((baseline, baseline_at)) = self.baseline else {
            self.baseline = Some((counters, now));
            return false;
        };
        if now.saturating_duration_since(baseline_at) > TRAFFIC_BLACKHOLE_WINDOW {
            self.baseline = Some((counters, now));
            return false;
        }
        let received = counters
            .tun_packets_received
            .saturating_sub(baseline.tun_packets_received);
        let forwarded = counters
            .peer_records_sent
            .saturating_sub(baseline.peer_records_sent)
            .saturating_add(
                counters
                    .tun_packets_sent
                    .saturating_sub(baseline.tun_packets_sent),
            );
        let dropped = counters.drops.saturating_sub(baseline.drops);
        if forwarded > 0 {
            self.baseline = Some((counters, now));
            return false;
        }
        if received >= TRAFFIC_BLACKHOLE_PACKET_THRESHOLD {
            self.baseline = Some((counters, now));
            return dropped >= received;
        }
        false
    }
}

#[derive(Debug, Deserialize)]
struct CoreReadinessPath {
    rtt_sample_count: u64,
    rx_bytes: u64,
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
        .spawn()
        .with_context(|| format!("start Candy Core: {}", args.core.display()))
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
    if status.schema_version != 3
        || status.generation != generation
        || status.pid != pid
        || status.readiness_token != readiness_token
    {
        bail!("SD-WAN Core readiness status does not match the candidate process")
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
    let has_authenticated_path_evidence = status.paths.as_ref().is_some_and(|paths| {
        paths.len() >= status.ready_route_owners
            && paths
                .iter()
                .all(|path| path.rtt_sample_count > 0 && path.rx_bytes > 0)
    });
    let listener_ready = status.inbound_listener_configured
        && status.inbound_listener_ready
        && !status.inbound_listener_endpoints.is_empty();
    let recoverable_committed_server_peer_loss = policy == ReadinessPolicy::CommittedServer
        && matches!(status.lifecycle.as_str(), "failed" | "starting")
        && status.fail_open_required
        && listener_ready
        && status.configured_peers > 0
        && status.required_route_owners > 0
        && status.ready_route_owners == 0
        && matches!(
            status.last_error_code.as_deref(),
            Some("all_peer_reads_failed" | "all_peer_writes_failed" | "route_has_no_active_peer")
        );
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
        "failed" | "starting" if recoverable_committed_server_peer_loss => {
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
        let detail = status.last_error_code.as_deref().unwrap_or("not_ready");
        bail!("SD-WAN Core candidate failed readiness: {detail}")
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
    rollback_or_report(netd, cause)?;
    remove_activation_receipt(args.activation_ready.as_deref())?;
    remove_stale_status(&args.status)?;
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

fn finish_control_transition(
    args: &RuntimeArgs,
    child: &mut Child,
    netd: &mut NetdClient,
    state: ActivationPointerState,
) -> Result<()> {
    let (event, phase) = match state {
        ActivationPointerState::Superseded => ("sdwan_generation_superseded", "superseded"),
        ActivationPointerState::Withdrawn => ("sdwan_configuration_withdrawn", "withdrawn"),
        ActivationPointerState::Unchanged => bail!("control transition requires a changed pointer"),
    };
    eprintln!(
        "level=info event={} generation={} transition=expected",
        event, args.generation
    );
    stop_core(child);
    rollback_or_report(netd, "SD-WAN control transition")?;
    remove_activation_receipt(args.activation_ready.as_deref())?;
    eprintln!(
        "level=info event=sdwan_stopped generation={} phase={} rollback_ok=true",
        args.generation, phase
    );
    Ok(())
}

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

fn run_once(args: &RuntimeArgs, recovery_attempt: bool) -> Result<()> {
    if args.generation == 0 {
        return fail_before_prepare(
            args,
            "invalid SD-WAN generation",
            "invalid_generation",
            anyhow::anyhow!("generation must be non-zero"),
        );
    }
    if !(MIN_LEASE_MS..=MAX_LEASE_MS).contains(&args.lease_ms) {
        return fail_before_prepare(
            args,
            "invalid SD-WAN lease",
            "invalid_lease",
            anyhow::anyhow!("lease-ms is outside the supported bound"),
        );
    }
    if !(MIN_READINESS_TIMEOUT_MS..=MAX_READINESS_TIMEOUT_MS).contains(&args.readiness_timeout_ms) {
        return fail_before_prepare(
            args,
            "invalid Core readiness timeout",
            "invalid_readiness_timeout",
            anyhow::anyhow!("readiness-timeout-ms is outside the supported bound"),
        );
    }
    if let Err(error) = install_shutdown_handlers() {
        return fail_before_prepare(
            args,
            "install SD-WAN shutdown handlers",
            "signal_handler_failed",
            error,
        );
    }
    let declaration = match parse_declaration(&args.declaration) {
        Ok(declaration) => declaration,
        Err(error) => {
            return fail_before_prepare(
                args,
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
                args,
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
                args,
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
            return fail_before_prepare(args, "netd prepare failed", "netd_prepare_failed", error)
        }
    };
    if let Err(error) = remove_stale_status(&args.status) {
        return fail_without_core(
            args,
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
                args,
                &mut netd,
                "Core readiness token generation failed",
                "readiness_token_failed",
                error,
            )
        }
    };
    let mut child = match spawn_core(args, &prepared.tun, &readiness_token) {
        Ok(child) => child,
        Err(error) => {
            return fail_without_core(
                args,
                &mut netd,
                "Candy Core start failed",
                "core_start_failed",
                error,
            );
        }
    };
    match wait_for_core_readiness(args, &mut child, &readiness_token, &mut netd) {
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
                    args,
                    &mut child,
                    &mut netd,
                    "Candy Core readiness failed",
                    "core_readiness_failed",
                    error,
                )
            } else {
                fail_after_rollback(
                    args,
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
                args,
                &mut child,
                &mut netd,
                "netd recovery commit failed",
                "netd_commit_failed",
                error.into(),
            )
        } else {
            fail_after_rollback(
                args,
                &mut child,
                &mut netd,
                "netd commit failed",
                "netd_commit_failed",
                error.into(),
            )
        };
    }
    if let Err(error) = write_runtime_activation_receipt(args, "committed", None) {
        return fail_after_rollback(
            args,
            &mut child,
            &mut netd,
            "activation receipt publication failed",
            "activation_receipt_failed",
            error,
        );
    }
    eprintln!(
        "level=info event=sdwan_commit generation={}",
        owner.generation
    );
    let renew_every = Duration::from_millis((args.lease_ms / 3).max(1_000));
    let mut next_renewal = Instant::now() + renew_every;
    let mut traffic_monitor = TrafficBlackholeMonitor::default();
    loop {
        match activation_pointer_state(args) {
            Ok(ActivationPointerState::Unchanged) => {}
            Ok(state) => return finish_control_transition(args, &mut child, &mut netd, state),
            Err(error) => {
                return fail_after_rollback(
                    args,
                    &mut child,
                    &mut netd,
                    "Cloud candidate pointer inspection failed",
                    "candidate_inspection_failed",
                    error,
                )
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
                    args,
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
                args,
                &mut child,
                &mut netd,
                "Candy Core SD-WAN exited",
                "core_exit",
                anyhow::anyhow!("Candy Core SD-WAN exited with status {code}"),
            );
        }
        let readiness_policy = if args.core_role == CoreRole::Server {
            ReadinessPolicy::CommittedServer
        } else {
            ReadinessPolicy::Strict
        };
        match read_core_readiness_with_policy(
            &args.status,
            args.generation,
            child.id(),
            &readiness_token,
            readiness_policy,
        ) {
            Ok(Some(ReadinessState::Ready)) => {}
            Ok(Some(ReadinessState::Degraded)) if args.core_role == CoreRole::Server => {}
            Ok(Some(ReadinessState::Degraded)) => {
                return retry_after_rollback(
                    args,
                    &mut child,
                    &mut netd,
                    "Candy Core lost full SD-WAN route readiness",
                    "core_route_readiness_lost",
                    anyhow::anyhow!("Candy Core has only partial route readiness"),
                );
            }
            Ok(Some(ReadinessState::ListenerReady)) => {
                return retry_after_rollback(
                    args,
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
                return retry_after_rollback(
                    args,
                    &mut child,
                    &mut netd,
                    "Candy Core lost SD-WAN readiness",
                    "core_readiness_lost",
                    anyhow::anyhow!("Candy Core lost SD-WAN readiness after netd commit"),
                );
            }
            Ok(Some(ReadinessState::RecoverablePeerLoss)) => {}
            Ok(Some(ReadinessState::Failed)) => unreachable!("failed readiness returns an error"),
            Err(error) => {
                return retry_after_rollback(
                    args,
                    &mut child,
                    &mut netd,
                    "Candy Core reported SD-WAN failure",
                    "core_runtime_failed",
                    error.context("Candy Core failed after netd commit"),
                );
            }
        }
        match read_core_status(&args.status, args.generation, child.id(), &readiness_token) {
            Ok(Some(status)) if traffic_monitor.observe(status.counters, Instant::now()) => {
                return fail_after_rollback(
                    args,
                    &mut child,
                    &mut netd,
                    "Candy Core dropped all intercepted traffic",
                    "core_traffic_blackhole",
                    anyhow::anyhow!("Candy Core received intercepted packets but forwarded none"),
                );
            }
            Ok(_) => {}
            Err(error) => {
                return retry_after_rollback(
                    args,
                    &mut child,
                    &mut netd,
                    "Candy Core traffic status inspection failed",
                    "core_status_inspection_failed",
                    error,
                );
            }
        }
        if Instant::now() < next_renewal {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        let next_deadline = match monotonic_ms().and_then(|now| {
            now.checked_add(args.lease_ms)
                .context("lease deadline overflow")
        }) {
            Ok(deadline) => deadline,
            Err(error) => {
                return retry_after_rollback(
                    args,
                    &mut child,
                    &mut netd,
                    "netd lease clock failed",
                    "lease_clock_failed",
                    error,
                )
            }
        };
        if let Err(error) = netd.renew_lease(next_deadline) {
            return retry_after_rollback(
                args,
                &mut child,
                &mut netd,
                "netd lease renewal failed",
                "netd_lease_failed",
                anyhow::Error::from(error).context("netd lease renewal"),
            );
        }
        next_renewal = Instant::now() + renew_every;
    }
}

fn run(args: RuntimeArgs) -> Result<()> {
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
        match run_once(&args, recovery_attempt) {
            Err(error) if error.downcast_ref::<RetryableFailure>().is_some() => {
                let error_code = error
                    .downcast_ref::<RetryableFailure>()
                    .expect("retryable failure downcast changed")
                    .error_code;
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
    use candy_netd_client::{recv_request, send_response};
    use candy_netd_proto::{ErrorCode, NetdOperation, NetdResponse, ResponseBody};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
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

        let error = run_once(&args, false).unwrap_err();

        netd.join().unwrap();
        let failure = error
            .downcast_ref::<RetryableFailure>()
            .expect("committed Core exit was not classified as retryable");
        assert_eq!(failure.error_code, "core_exit");
        assert!(!receipt.exists(), "committed receipt survived fail-open");
        assert!(!status.exists(), "stale Core status survived fail-open");
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

        let error = run_once(&args, true).unwrap_err();

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
        assert!(read_core_readiness(&path, 10, 42, "00112233445566778899aabbccddeeff").is_err());
        assert!(read_core_readiness(&path, 9, 43, "00112233445566778899aabbccddeeff").is_err());
        assert!(read_core_readiness(&path, 9, 42, "11112233445566778899aabbccddeeff").is_err());
        fs::write(&path, status(9, "active", 1, 0)).unwrap();
        assert!(read_core_readiness(&path, 9, 42, "00112233445566778899aabbccddeeff").is_err());
    }

    #[test]
    fn sustained_total_traffic_loss_is_a_blackhole() {
        let mut monitor = TrafficBlackholeMonitor::default();
        let now = Instant::now();
        assert!(!monitor.observe(CoreTrafficCounters::default(), now));
        assert!(!monitor.observe(
            CoreTrafficCounters {
                tun_packets_received: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD - 1,
                drops: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD - 1,
                ..CoreTrafficCounters::default()
            },
            now + Duration::from_secs(1)
        ));
        assert!(monitor.observe(
            CoreTrafficCounters {
                tun_packets_received: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD,
                drops: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD,
                ..CoreTrafficCounters::default()
            },
            now + Duration::from_secs(2)
        ));
    }

    #[test]
    fn successful_forwarding_resets_blackhole_detection() {
        let mut monitor = TrafficBlackholeMonitor::default();
        let now = Instant::now();
        assert!(!monitor.observe(CoreTrafficCounters::default(), now));
        assert!(!monitor.observe(
            CoreTrafficCounters {
                tun_packets_received: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD,
                peer_records_sent: 1,
                drops: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD - 1,
                ..CoreTrafficCounters::default()
            },
            now + Duration::from_secs(1)
        ));
        assert!(!monitor.observe(
            CoreTrafficCounters {
                tun_packets_received: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD * 2 - 1,
                peer_records_sent: 1,
                drops: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD * 2 - 2,
                ..CoreTrafficCounters::default()
            },
            now + Duration::from_secs(2)
        ));
        assert!(monitor.observe(
            CoreTrafficCounters {
                tun_packets_received: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD * 2,
                peer_records_sent: 1,
                drops: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD * 2 - 1,
                ..CoreTrafficCounters::default()
            },
            now + Duration::from_secs(3)
        ));
    }

    #[test]
    fn sparse_drops_do_not_trip_blackhole_detection() {
        let mut monitor = TrafficBlackholeMonitor::default();
        let now = Instant::now();
        assert!(!monitor.observe(CoreTrafficCounters::default(), now));
        assert!(!monitor.observe(
            CoreTrafficCounters {
                tun_packets_received: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD,
                drops: TRAFFIC_BLACKHOLE_PACKET_THRESHOLD,
                ..CoreTrafficCounters::default()
            },
            now + TRAFFIC_BLACKHOLE_WINDOW + Duration::from_secs(1)
        ));
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
    fn recoverable_peer_loss_is_only_allowed_for_committed_server_monitoring() {
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
                ReadinessPolicy::CommittedServer,
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
