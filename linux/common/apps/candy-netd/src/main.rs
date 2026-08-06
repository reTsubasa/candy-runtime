#![cfg(unix)]

#[cfg(target_os = "linux")]
use candy_netd::{
    bind_private_socket_for, FileNetworkJournal, LinuxNetworkBackend, NetdService,
    NetworkTransaction, SystemTunFactory,
};
use clap::Parser;
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
    #[arg(long, required_unless_present_any = ["probe_socket", "recover"])]
    socket: Option<PathBuf>,
    #[arg(long, required_unless_present_any = ["probe_socket", "recover"])]
    allowed_uid: Option<u32>,
    #[arg(long, required_unless_present_any = ["probe_socket", "recover"])]
    allowed_gid: Option<u32>,
    #[arg(long, conflicts_with_all = ["probe_socket", "socket", "allowed_uid", "allowed_gid"])]
    recover: bool,
    #[arg(long, default_value = "/var/lib/candy/netd.journal")]
    journal: PathBuf,
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
fn run_linux(args: Args) -> anyhow::Result<()> {
    if let Some(path) = args.probe_socket {
        std::os::unix::net::UnixStream::connect(path)?;
        return Ok(());
    }
    if args.recover {
        let network = NetworkTransaction::new(
            LinuxNetworkBackend::new()?,
            FileNetworkJournal::new(args.journal)?,
        )?;
        let mut service = NetdService::with_network(0, 0, SystemTunFactory, network);
        let recovered = service.recover_orphan(monotonic_millis()?)?;
        eprintln!(
            "level=info component=candy-netd event=orphan_recovery completed=true recovered={recovered}"
        );
        return Ok(());
    }
    let socket = args.socket.expect("clap requires --socket");
    let allowed_uid = args.allowed_uid.expect("clap requires --allowed-uid");
    let allowed_gid = args.allowed_gid.expect("clap requires --allowed-gid");
    let listener = bind_private_socket_for(&socket, allowed_uid, allowed_gid)?;
    listener.set_nonblocking(true)?;
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
                            "level=warn component=candy-netd event=request_failed error={error}"
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
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
extern "C" fn request_shutdown(_signal: nix::libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

#[cfg(target_os = "linux")]
fn install_shutdown_handlers() -> anyhow::Result<()> {
    let mut action: nix::libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = request_shutdown as usize;
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
