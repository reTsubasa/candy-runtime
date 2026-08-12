use anyhow::{bail, Context, Result};
use candy_netd_client::NetdClient;
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, LeaseOwner, PrepareDeclaration, RouteDeclaration, RouteKind,
    UnderlayExclusion, UnderlayKind,
};
use clap::Parser;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use serde::Deserialize;
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MAX_DECLARATION_BYTES: u64 = 1024 * 1024;
const MIN_LEASE_MS: u64 = 5_000;
const MAX_LEASE_MS: u64 = 120_000;
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Parser, Debug)]
#[command(
    name = "candy-sdwan-agent",
    version,
    about = "Candy SD-WAN transaction agent"
)]
struct Args {
    #[command(subcommand)]
    command: Option<CommandKind>,
    #[arg(long, default_value = "/var/run/candy-netd/netd.sock")]
    socket: PathBuf,
    #[arg(long)]
    core: PathBuf,
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    declaration: PathBuf,
    /// Runtime-owned status file passed through to the Core process.
    #[arg(long)]
    status: PathBuf,
    #[arg(long)]
    instance_id: String,
    #[arg(long)]
    generation: u64,
    #[arg(long, default_value_t = 30_000)]
    lease_ms: u64,
}

#[derive(clap::Subcommand, Debug)]
enum CommandKind {
    Run,
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

fn monotonic_ms() -> Result<u64> {
    let uptime = fs::read_to_string("/proc/uptime").context("read monotonic clock")?;
    let seconds = uptime
        .split_whitespace()
        .next()
        .context("invalid monotonic clock")?
        .parse::<f64>()?;
    Ok((seconds * 1000.0) as u64)
}

fn clear_cloexec(fd: &OwnedFd) -> Result<()> {
    fcntl(fd.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty()))
        .context("clear TUN close-on-exec flag")?;
    Ok(())
}

fn spawn_core(args: &Args, tun: &OwnedFd) -> Result<Child> {
    clear_cloexec(tun)?;
    let fd = tun.as_raw_fd().to_string();
    Command::new(&args.core)
        .arg("client")
        .arg("sdwan")
        .arg("run")
        .arg("--config")
        .arg(&args.config)
        .arg("--tun-fd")
        .arg(fd)
        .arg("--status")
        .arg(&args.status)
        .spawn()
        .with_context(|| format!("start Candy Core: {}", args.core.display()))
}

extern "C" fn request_shutdown(_signal: nix::libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
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
    let _ = child.kill();
    let _ = child.wait();
}

fn rollback_or_report(netd: &mut NetdClient, cause: &str) -> Result<()> {
    netd.rollback()
        .map(|_| ())
        .with_context(|| format!("{cause}; netd rollback failed"))
}

fn run(args: Args) -> Result<()> {
    if args.generation == 0 {
        bail!("generation must be non-zero")
    }
    if !(MIN_LEASE_MS..=MAX_LEASE_MS).contains(&args.lease_ms) {
        bail!("lease-ms is outside the supported bound")
    }
    install_shutdown_handlers()?;
    let declaration = parse_declaration(&args.declaration)?;
    let deadline = monotonic_ms()?
        .checked_add(args.lease_ms)
        .context("lease deadline overflow")?;
    let owner = LeaseOwner {
        instance_id: parse_instance_id(&args.instance_id)?,
        pid: std::process::id(),
        generation: args.generation,
        lease_deadline_mono_ms: deadline,
    };
    eprintln!(
        "level=info event=sdwan_prepare generation={} pid={}",
        owner.generation, owner.pid
    );
    let mut netd = NetdClient::new(&args.socket, owner);
    let prepared = netd.prepare(declaration).context("netd prepare")?;
    let mut child = match spawn_core(&args, &prepared.tun) {
        Ok(child) => child,
        Err(error) => {
            rollback_or_report(&mut netd, "Candy Core start failed")?;
            return Err(error);
        }
    };
    if let Err(error) = netd.commit() {
        stop_core(&mut child);
        rollback_or_report(&mut netd, "netd commit failed")?;
        return Err(error.into());
    }
    eprintln!(
        "level=info event=sdwan_commit generation={}",
        owner.generation
    );
    let renew_every = Duration::from_millis((args.lease_ms / 3).max(1_000));
    let mut next_renewal = Instant::now() + renew_every;
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            stop_core(&mut child);
            rollback_or_report(&mut netd, "SD-WAN agent shutdown")?;
            eprintln!(
                "level=info event=sdwan_stopped generation={} rollback_ok=true",
                owner.generation
            );
            return Ok(());
        }
        if let Some(status) = child.try_wait().context("wait for Candy Core")? {
            let code = status.code().unwrap_or(1);
            rollback_or_report(&mut netd, "Candy Core SD-WAN exited")?;
            if code == 0 {
                return Ok(());
            }
            bail!("Candy Core SD-WAN exited with status {}", code)
        }
        if Instant::now() < next_renewal {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        let next_deadline = monotonic_ms()?
            .checked_add(args.lease_ms)
            .context("lease deadline overflow")?;
        if let Err(error) = netd.renew_lease(next_deadline) {
            stop_core(&mut child);
            rollback_or_report(&mut netd, "netd lease renewal failed")?;
            return Err(error).context("netd lease renewal");
        }
        next_renewal = Instant::now() + renew_every;
    }
}

fn main() {
    let args = Args::parse();
    let result = match args.command {
        Some(CommandKind::Run) | None => run(args),
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
}
