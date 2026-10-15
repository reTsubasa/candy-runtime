use anyhow::{bail, Context, Result};
use candy_netd_client::v2::InfrastructureClient;
use candy_netd_proto::v2::{Body, Operation};
use candy_packet_port::fd::InheritedPacketFd;
use candy_packet_port::packet_port_ipc::{PacketPortBinding, PacketPortRole, UnixPacketPort};
use candy_tunio::control;
use clap::Parser;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UnixDatagram;
use tokio::sync::watch;
use tokio::time::Instant;

mod logging;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    experimental_packet_port_ipc: bool,
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    instance_id: String,
    #[arg(long)]
    routing_domain_id: Option<String>,
    #[arg(long)]
    packet_port_fd: i32,
    #[arg(long)]
    packet_port_binding_file: PathBuf,
    #[arg(long)]
    auth_deadline_unix: u64,
    /// Absolute CLOCK_BOOTTIME deadline inherited from Runtime recovery.
    /// This is a cap: it can only shorten the wall-clock authorization.
    #[arg(long)]
    auth_deadline_mono_ms: Option<u64>,
    #[arg(long,requires_all=["status","readiness_token"])]
    control_socket: Option<PathBuf>,
    #[arg(long,requires_all=["control_socket","readiness_token"])]
    status: Option<PathBuf>,
    #[arg(long,requires_all=["control_socket","status"])]
    readiness_token: Option<String>,
}

fn read_binding(path: &PathBuf) -> Result<PacketPortBinding> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > 4096
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        bail!("packet binding must be a current-user 0600 bounded regular file");
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        bail!("packet binding too large");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    logging::init()?;
    control::install_startup_guard()?;
    let args = Args::parse();
    if !args.experimental_packet_port_ipc {
        bail!("explicit experimental-packet-port-ipc gate required");
    }
    if args.packet_port_fd < 3 {
        bail!("packet port fd must not alias stdio");
    }
    let authorization_anchor = Instant::now();
    let authorization_remaining = Duration::from_secs(args.auth_deadline_unix)
        .checked_sub(SystemTime::now().duration_since(UNIX_EPOCH)?)
        .filter(|value| !value.is_zero())
        .context("owner authorization expired")?;
    if args.control_socket.is_some() && authorization_remaining > Duration::from_secs(3600) {
        bail!("experimental detached owner authorization is limited to one hour");
    }
    let mut auth_deadline = authorization_anchor + authorization_remaining;
    if let Some(cap_ms) = args.auth_deadline_mono_ms {
        candy_tunio::authority_control::install_bootstrap_cap(cap_ms)?;
        let now_ms = candy_tunio::authority_control::monotonic_ms()?;
        let cap = if cap_ms <= now_ms {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "code=authority_expired module=tunio_authority detail=monotonic recovery deadline reached").into());
        } else {
            authorization_anchor + Duration::from_millis(cap_ms - now_ms)
        };
        auth_deadline = auth_deadline.min(cap);
    }
    let binding = read_binding(&args.packet_port_binding_file)?;
    // Reject unauthenticated or disconnected IPC before acquiring a TUN queue.
    let port_fd = unsafe { OwnedFd::from_raw_fd(args.packet_port_fd) };
    nix::fcntl::fcntl(
        port_fd.as_raw_fd(),
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )?;
    if nix::sys::socket::getsockopt(&port_fd, nix::sys::socket::sockopt::SockType)?
        != nix::sys::socket::SockType::Datagram
    {
        bail!("packet port descriptor must be a datagram socket");
    }
    nix::sys::socket::getsockname::<nix::sys::socket::UnixAddr>(port_fd.as_raw_fd())
        .context("packet port descriptor must belong to AF_UNIX")?;
    let socket = std::os::unix::net::UnixDatagram::from(port_fd);
    socket
        .peer_addr()
        .context("packet port must be a connected Unix datagram socket")?;
    #[cfg(target_os = "linux")]
    {
        let peer =
            nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::PeerCredentials)?;
        if peer.uid() != nix::unistd::geteuid().as_raw()
            || peer.pid() != unsafe { nix::libc::getppid() }
        {
            bail!("packet port was not provided by the current Runtime supervisor");
        }
    }
    if args.instance_id.len() != 32
        || !args
            .instance_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("instance-id must be 16-byte hex");
    }
    let mut instance = [0; 16];
    for (i, byte) in instance.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&args.instance_id[i * 2..i * 2 + 2], 16)?;
    }
    if instance == [0; 16] {
        bail!("instance-id cannot be zero");
    }
    // The I/O process calls acquire itself: netd fences the actual fd holder PID.
    let mut netd = InfrastructureClient::new(args.socket, instance);
    let acquire = Operation::InfraAcquireIoFd {
        infra_id: binding.infrastructure_id,
        generation: binding.infrastructure_generation,
        io_epoch: binding.io_epoch,
    };
    let (body, fd) = if let Some(domain) = args.routing_domain_id {
        if domain.len() != 32 || !domain.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("routing-domain-id must be 16-byte hex");
        }
        let mut decoded = [0; 16];
        for (i, byte) in decoded.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&domain[i * 2..i * 2 + 2], 16)?;
        }
        if decoded != binding.routing_domain_id {
            bail!("routing domain differs from immutable packet binding");
        }
        netd.exchange_in_domain(decoded, binding.infrastructure_id, acquire)?
    } else {
        netd.exchange(acquire)?
    };
    match body {
        Body::IoFd { spec, io_epoch, .. }
            if spec.infra_id == binding.infrastructure_id
                && spec.generation == binding.infrastructure_generation
                && io_epoch == binding.io_epoch => {}
        Body::Error {
            code,
            module,
            reason,
        } => bail!("code={code} module={module} detail={reason}"),
        _ => bail!("netd returned mismatched infrastructure identity"),
    }
    let tun = InheritedPacketFd::new(fd.context("netd omitted packet device descriptor")?)?;
    // The Agent transfers a connected socket; the business worker never receives a TUN fd.
    socket.set_nonblocking(true)?;
    let port = UnixPacketPort::new(
        UnixDatagram::from_std(socket)?,
        binding,
        PacketPortRole::Infrastructure,
    )?;
    let (stop, shutdown) = watch::channel(false);
    let signal_stop = stop.clone();
    tokio::spawn(async move {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install terminate handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => (), _ = terminate.recv() => (), }
        let _ = signal_stop.send(true);
    });
    if let (Some(socket), Some(status), Some(token)) =
        (args.control_socket, args.status, args.readiness_token)
    {
        let managed =
            candy_tunio::start_managed_infrastructure(tun, port, shutdown, auth_deadline).await?;
        let registration = match control::start(
            socket,
            status,
            token,
            binding.policy_generation,
            args.auth_deadline_unix,
            stop.clone(),
            binding,
            managed.updates,
            auth_deadline,
        ) {
            Ok(registration) => registration,
            Err(error) => {
                let _ = stop.send(true);
                let _ = managed.task.await;
                return Err(error);
            }
        };
        registration.observe_bridge(managed.output_status, stop.subscribe())?;
        if let Err(error) = registration.wait().await {
            let _ = stop.send(true);
            let _ = managed.task.await;
            return Err(error);
        }
        eprintln!("level=info code=tunio_ready module=tunio pid={} io_epoch={} infrastructure_generation={} action=serve_rebindable_single_domain", std::process::id(), binding.io_epoch, binding.infrastructure_generation);
        let result = managed
            .task
            .await
            .context("managed PacketPort task failed")??;
        let _ = stop.send(true);
        eprintln!("level=info code=tunio_stopped module=tunio detail={result:?}");
        return Ok(());
    }
    eprintln!("level=info code=tunio_ready module=tunio pid={} io_epoch={} infrastructure_generation={} action=serve_single_domain", std::process::id(), binding.io_epoch, binding.infrastructure_generation);
    let result = candy_tunio::run_infrastructure(tun, port, shutdown, auth_deadline).await?;
    eprintln!("level=info code=tunio_stopped module=tunio detail={result:?}");
    Ok(())
}
