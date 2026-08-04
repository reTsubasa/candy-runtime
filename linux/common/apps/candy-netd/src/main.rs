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
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "candy-netd")]
struct Args {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    allowed_uid: u32,
    #[arg(long)]
    allowed_gid: u32,
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
    let listener = bind_private_socket_for(&args.socket, args.allowed_uid, args.allowed_gid)?;
    listener.set_nonblocking(true)?;
    let network = NetworkTransaction::new(
        LinuxNetworkBackend::new()?,
        FileNetworkJournal::new(args.journal)?,
    )?;
    let mut service = NetdService::with_network(
        args.allowed_uid,
        args.allowed_gid,
        SystemTunFactory,
        network,
    );
    service.recover_orphan(monotonic_millis()?)?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                let _ = service.serve_once(&stream);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        service.recover_orphan(monotonic_millis()?)?;
        std::thread::sleep(Duration::from_millis(100));
    }
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
