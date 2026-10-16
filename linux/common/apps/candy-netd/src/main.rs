#![cfg(unix)]

#[cfg(target_os = "linux")]
use candy_netd::{
    bind_private_socket_for, FileNetworkJournal, LinuxNetworkBackend, NetdService,
    NetworkTransaction, SystemTunFactory,
};
#[cfg(target_os = "linux")]
use candy_runtime_log::structured_eprintln as eprintln;
use clap::Parser;
#[cfg(target_os = "linux")]
use nix::unistd::{Group, User};
#[cfg(target_os = "linux")]
use std::io::ErrorKind;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "candy-netd")]
struct Args {
    #[arg(long, conflicts_with_all = ["socket", "allowed_uid", "allowed_gid", "journal", "recover"])]
    probe_socket: Option<PathBuf>,
    /// IPC ABI expected by the read-only health check; never auto-detect a different ABI.
    #[arg(long, value_enum, default_value = "v1", requires = "probe_socket")]
    probe_protocol: ProbeProtocol,
    #[arg(long, required_unless_present_any = ["probe_socket", "recover", "check_domain_resources"])]
    socket: Option<PathBuf>,
    #[arg(long, required_unless_present_any = ["probe_socket", "recover", "allowed_user", "check_domain_resources"])]
    allowed_uid: Option<u32>,
    #[arg(long, required_unless_present_any = ["probe_socket", "recover", "allowed_group", "check_domain_resources"])]
    allowed_gid: Option<u32>,
    #[arg(long, conflicts_with = "allowed_uid", requires = "allowed_group")]
    allowed_user: Option<String>,
    #[arg(long, conflicts_with = "allowed_gid", requires = "allowed_user")]
    allowed_group: Option<String>,
    #[arg(long, conflicts_with_all = [
        "probe_socket",
        "socket",
        "allowed_uid",
        "allowed_gid",
        "allowed_user",
        "allowed_group"
    ])]
    recover: bool,
    #[arg(long, default_value = "/var/lib/candy/netd.journal")]
    journal: PathBuf,
    /// Enable the independent infrastructure ABI; version 1 is never accepted in this mode.
    #[arg(long, conflicts_with_all = ["probe_socket", "recover"])]
    protocol_v2: bool,
    #[arg(long, default_value = "/var/lib/candy/netd-infrastructure-v2.journal")]
    infrastructure_journal: PathBuf,
    /// Bind explicit domain identities to independent precreated network namespaces.
    #[arg(long, requires = "protocol_v2")]
    domain_config: Option<PathBuf>,
    /// Check configured resource budgets without binding a socket or recovering domains.
    #[arg(long, conflicts_with_all = ["probe_socket", "recover", "socket", "allowed_uid", "allowed_gid", "allowed_user", "allowed_group", "protocol_v2", "domain_config"])]
    check_domain_resources: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ProbeProtocol {
    V1,
    V2,
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    return run_linux(Args::parse());
    #[cfg(not(target_os = "linux"))]
    {
        let _ = Args::parse();
        anyhow::bail!("candy-netd privileged networking is supported only on Linux")
    }
}

#[cfg(target_os = "linux")]
fn sanitize_log_value(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(target_os = "linux")]
fn run_linux(args: Args) -> anyhow::Result<()> {
    if let Some(path) = args.check_domain_resources {
        candy_netd::v2::domains::DomainsConfig::load(&path)?.validate_resource_admission()?;
        eprintln!("level=info code=domain_resource_check_passed module=netd_domains scope=resource_admission");
        return Ok(());
    }
    if let Some(path) = args.probe_socket {
        let protocol = match args.probe_protocol {
            ProbeProtocol::V1 => candy_netd_client::probe::Protocol::V1,
            ProbeProtocol::V2 => candy_netd_client::probe::Protocol::V2,
        };
        candy_netd_client::probe::socket(&path, protocol, Duration::from_millis(750))?;
        return Ok(());
    }
    if args.recover {
        let network = NetworkTransaction::new(
            LinuxNetworkBackend::new()?,
            FileNetworkJournal::new(args.journal)?,
        )?;
        let mut service = NetdService::with_network(0, 0, SystemTunFactory, network);
        // The legacy journal stores deadlines in CLOCK_MONOTONIC units.  Keep
        // this path on the legacy clock; BOOTTIME is reserved for protocol v2
        // authorization and would make an orphan look expired after suspend.
        let recovered = service.recover_orphan(monotonic_millis()?)?;
        eprintln!(
            "level=info component=candy-netd event=orphan_recovery completed=true recovered={recovered}"
        );
        return Ok(());
    }
    let (allowed_uid, allowed_gid) = resolve_allowed_identity(&args)?;
    let socket = args.socket.expect("clap requires --socket");
    if let Some(config_path) = args.domain_config {
        use candy_netd::v2::domains::{DomainsConfig, FrontDispatcher, MultiDomainService};
        let service =
            MultiDomainService::new(allowed_uid, allowed_gid, DomainsConfig::load(&config_path)?)?;
        let front = FrontDispatcher::new(std::sync::Arc::new(service))?;
        let listener = bind_private_socket_for(&socket, allowed_uid, allowed_gid)?;
        listener.set_nonblocking(true)?;
        install_shutdown_handlers()?;
        eprintln!("level=info component=candy-netd event=service_started protocol=2 domain_routing=namespace infrastructure=preserved");
        while !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Err(error) = front.dispatch(stream) {
                        eprintln!("level=warn code=netd_domain_request_failed module=netd_domains reason={}", sanitize_log_value(&error.to_string()));
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        eprintln!("level=info component=candy-netd event=service_stopped protocol=2 infrastructure=preserved");
        return Ok(());
    }
    let listener = bind_private_socket_for(&socket, allowed_uid, allowed_gid)?;
    listener.set_nonblocking(true)?;
    if args.protocol_v2 {
        let journal = candy_netd::v2::InfrastructureJournal::new(args.infrastructure_journal)?;
        let mut service = candy_netd::v2::InfrastructureService::new(
            allowed_uid,
            allowed_gid,
            SystemTunFactory,
            LinuxNetworkBackend::new()?,
            journal,
        )?;
        install_shutdown_handlers()?;
        eprintln!("level=info component=candy-netd event=service_started protocol=2 independent_infrastructure=true multi_domain=false");
        while !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    if let Err(error) =
                        service.serve_once(&stream, candy_netd::v2::clock::now_ms()?)
                    {
                        eprintln!(
                            "level=warn code=netd_v2_request_failed module=netd_v2 reason={}",
                            sanitize_log_value(&error.to_string())
                        );
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            if let Err(error) = service.recover_expired(candy_netd::v2::clock::now_ms()?) {
                eprintln!(
                    "level=error code=netd_v2_recovery_failed module=netd_v2 reason={}",
                    sanitize_log_value(&error.to_string())
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // A netd restart is not an infrastructure retirement or a forwarding rollback.
        eprintln!("level=info component=candy-netd event=service_stopped protocol=2 infrastructure=preserved");
        return Ok(());
    }
    let network = NetworkTransaction::new(
        LinuxNetworkBackend::new()?,
        FileNetworkJournal::new(args.journal)?,
    )?;
    let mut service =
        NetdService::with_network(allowed_uid, allowed_gid, SystemTunFactory, network);
    let recovered = service.recover_orphan(monotonic_millis()?)?;
    eprintln!("level=info component=candy-netd event=service_started orphan_recovered={recovered}");
    install_shutdown_handlers()?;
    let service_result = (|| -> anyhow::Result<()> {
        while !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    if let Err(error) = service.serve_once(&stream) {
                        eprintln!(
                            "level=warn component=candy-netd event=request_failed stage=request_service cause={}",
                            sanitize_log_value(&format!("{:#}", anyhow::Error::new(error)))
                        );
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            service.recover_orphan(monotonic_millis()?)?;
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    })();
    let shutdown_result = service.shutdown();
    eprintln!(
        "level=info component=candy-netd event=service_stopped rollback_ok={}",
        shutdown_result.is_ok()
    );
    shutdown_result?;
    service_result
}

#[cfg(target_os = "linux")]
fn resolve_allowed_identity(args: &Args) -> anyhow::Result<(u32, u32)> {
    match (&args.allowed_user, &args.allowed_group) {
        (Some(user), Some(group)) => {
            let uid = User::from_name(user)?
                .ok_or_else(|| anyhow::anyhow!("allowed user does not exist: {user}"))?
                .uid
                .as_raw();
            let gid = Group::from_name(group)?
                .ok_or_else(|| anyhow::anyhow!("allowed group does not exist: {group}"))?
                .gid
                .as_raw();
            Ok((uid, gid))
        }
        (None, None) => Ok((
            args.allowed_uid.expect("clap requires --allowed-uid"),
            args.allowed_gid.expect("clap requires --allowed-gid"),
        )),
        _ => anyhow::bail!("allowed user and group must be provided together"),
    }
}

#[cfg(target_os = "linux")]
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
extern "C" fn request_shutdown(_signal: nix::libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

#[cfg(target_os = "linux")]
fn install_shutdown_handlers() -> anyhow::Result<()> {
    let mut action: nix::libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = request_shutdown as *const () as usize;
    action.sa_flags = 0;
    unsafe {
        nix::libc::sigemptyset(&mut action.sa_mask);
        if nix::libc::sigaction(nix::libc::SIGTERM, &action, std::ptr::null_mut()) != 0
            || nix::libc::sigaction(nix::libc::SIGINT, &action, std::ptr::null_mut()) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn monotonic_millis() -> anyhow::Result<u64> {
    let mut value = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &mut value) };
    if result != 0 || value.tv_sec < 0 || value.tv_nsec < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let seconds = u64::try_from(value.tv_sec)?;
    let nanos = u64::try_from(value.tv_nsec)?;
    seconds
        .checked_mul(1000)
        .and_then(|millis| millis.checked_add(nanos / 1_000_000))
        .ok_or_else(|| anyhow::anyhow!("monotonic clock overflow"))
}

#[cfg(test)]
mod argument_tests {
    use super::*;

    #[test]
    fn probe_protocol_is_explicit_and_server_arguments_still_work() {
        assert!(Args::try_parse_from([
            "candy-netd",
            "--socket",
            "/tmp/test.sock",
            "--allowed-uid",
            "0",
            "--allowed-gid",
            "0"
        ])
        .is_ok());
        let probe = Args::try_parse_from([
            "candy-netd",
            "--probe-socket",
            "/tmp/test.sock",
            "--probe-protocol",
            "v2",
        ])
        .unwrap();
        assert!(matches!(probe.probe_protocol, ProbeProtocol::V2));
        assert!(Args::try_parse_from(["candy-netd", "--probe-protocol", "v2"]).is_err());
    }
}
