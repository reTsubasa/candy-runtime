//! Explicit experimental live-owner attachment. The local Agent has already
//! validated the signed policy; rebind cannot extend its original authority.
use anyhow::{bail, Context, Result};
pub use candy_packet_port::packet_port_ipc::PacketPortBinding;
use candy_packet_port::{
    packet_port_ipc::{PacketPortRole, UnixPacketPort},
    packet_port_manager::{PacketPortOwnerChange, PacketPortOwnerUpdate},
};
pub use candy_process_control::ProcessIdentity;
use candy_process_control::{peer_identity, process_is_current};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot, watch};

const CONTROL_BYTES: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketControlOperation {
    Attach,
    Revoke,
    Probe,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketControlRequest {
    pub schema_version: u8,
    pub process: ProcessIdentity,
    pub controller: ProcessIdentity,
    pub controller_epoch: u64,
    pub token_sha256: String,
    pub nonce: String,
    pub operation: PacketControlOperation,
    pub binding: PacketPortBinding,
    pub auth_deadline_unix: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketControlResponse {
    pub schema_version: u8,
    pub process: ProcessIdentity,
    pub controller: ProcessIdentity,
    pub controller_epoch: u64,
    pub nonce: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub current_binding: PacketPortBinding,
    pub auth_deadline_unix: u64,
}

pub fn packet_control_path(supervision_socket: &Path) -> PathBuf {
    let mut path = supervision_socket.as_os_str().to_os_string();
    path.push(".packet");
    PathBuf::from(path)
}

pub(crate) fn remaining(deadline: Instant) -> Result<Duration> {
    deadline.checked_duration_since(Instant::now()).filter(|duration| !duration.is_zero())
        .context("code=packet_control_deadline module=tunio_control detail=absolute request deadline elapsed")
}

pub(crate) fn validate_endpoint(path: &Path) -> Result<()> {
    crate::control::private_parent(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        bail!("PacketPort control must be a current-user mode-0600 Unix socket");
    }
    Ok(())
}

pub(crate) fn connect_until(path: &Path, deadline: Instant) -> Result<UnixStream> {
    use nix::{
        fcntl::{fcntl, FcntlArg, FdFlag, OFlag},
        sys::socket::{
            connect, getsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
        },
    };
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;
    fcntl(fd.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    fcntl(fd.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    match connect(fd.as_raw_fd(), &UnixAddr::new(path)?) {
        Ok(()) => (),
        Err(nix::errno::Errno::EINPROGRESS) | Err(nix::errno::Errno::EAGAIN) => loop {
            let wait = remaining(deadline)?;
            let mut poll = nix::libc::pollfd {
                fd: fd.as_raw_fd(),
                events: nix::libc::POLLOUT,
                revents: 0,
            };
            let result = unsafe {
                nix::libc::poll(
                    &mut poll,
                    1,
                    wait.as_millis().clamp(1, i32::MAX as u128) as i32,
                )
            };
            if result == 0 {
                bail!("PacketPort control connect deadline elapsed");
            }
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("poll PacketPort control");
            }
            let error = getsockopt(&fd, sockopt::SocketError)?;
            if error != 0 {
                return Err(std::io::Error::from_raw_os_error(error))
                    .context("connect PacketPort control");
            }
            break;
        },
        Err(error) => return Err(error).context("connect PacketPort control"),
    }
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// One absolute deadline covers connect, send, response and descriptor handling.
/// A missing ACK is ambiguous: reconcile TUNIO's durable current_binding before
/// repeating Attach; never assign the same epoch to a different worker.
pub fn exchange_packet_port(
    path: &Path,
    expected_tunio: ProcessIdentity,
    request: &PacketControlRequest,
    fd: Option<&OwnedFd>,
    deadline: Instant,
) -> Result<PacketControlResponse> {
    validate_endpoint(path)?;
    remaining(deadline)?;
    if request.process != expected_tunio || !process_is_current(expected_tunio) {
        bail!("PacketPort request expected TUNIO PID/startticks differs");
    }
    if usize::from(matches!(request.operation, PacketControlOperation::Attach))
        != usize::from(fd.is_some())
    {
        bail!("Attach requires exactly one descriptor; Revoke requires none");
    }
    let stream = connect_until(path, deadline)?;
    if peer_identity(&stream)? != expected_tunio {
        bail!("PacketPort control peer PID/startticks differs");
    }
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > CONTROL_BYTES {
        bail!("PacketPort control request too large");
    }
    candy_netd_client::send_descriptor_frame_until(
        &stream,
        &bytes,
        fd.map(AsRawFd::as_raw_fd),
        deadline,
    )?;
    let (bytes, descriptors) =
        candy_netd_client::receive_descriptor_frame_until(&stream, deadline)?;
    if !descriptors.is_empty() || bytes.len() > CONTROL_BYTES {
        bail!("PacketPort control response shape differs");
    }
    let reply: PacketControlResponse = serde_json::from_slice(&bytes)?;
    if reply.schema_version != 1
        || reply.process != expected_tunio
        || reply.nonce != request.nonce
        || reply.controller != request.controller
        || reply.controller_epoch != request.controller_epoch
        || peer_identity(&stream)? != expected_tunio
    {
        bail!("PacketPort control response fencing differs");
    }
    if !reply.accepted {
        bail!(
            "code={} module=tunio_control detail={}",
            reply.code,
            reply.detail
        );
    }
    if !fixed_binding_matches(reply.current_binding, request.binding)
        || reply.auth_deadline_unix > request.auth_deadline_unix
        || (!matches!(request.operation, PacketControlOperation::Probe)
            && reply.current_binding != request.binding)
    {
        bail!("PacketPort ACK did not commit requested binding/deadline");
    }
    Ok(reply)
}

fn fixed_binding_matches(actual: PacketPortBinding, original: PacketPortBinding) -> bool {
    actual.infrastructure_id == original.infrastructure_id
        && actual.routing_domain_id == original.routing_domain_id
        && actual.infrastructure_generation == original.infrastructure_generation
        && actual.io_epoch == original.io_epoch
        && actual.policy_generation == original.policy_generation
}

fn owner_deadline(
    request: &PacketControlRequest,
    original_unix: u64,
    original_mono: tokio::time::Instant,
) -> Result<tokio::time::Instant> {
    if request.auth_deadline_unix > original_unix {
        bail!("rebind cannot extend original signed deadline");
    }
    let anchor = tokio::time::Instant::now();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let duration = Duration::from_secs(request.auth_deadline_unix)
        .checked_sub(now)
        .filter(|duration| !duration.is_zero())
        .context("owner authorization expired")?;
    let deadline = (anchor + duration).min(original_mono);
    if deadline <= tokio::time::Instant::now() {
        bail!("original monotonic authorization expired");
    }
    Ok(deadline)
}

fn wait_applied(
    mut applied: oneshot::Receiver<std::result::Result<(), String>>,
    deadline: Instant,
) -> Result<()> {
    loop {
        remaining(deadline)?;
        match applied.try_recv() {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(detail)) => {
                bail!("code=packet_owner_rejected module=tunio_control detail={detail}")
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                bail!("PacketPort bridge closed before ACK")
            }
            Err(oneshot::error::TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_request(
    state: &mut crate::control::Controller,
    peer: ProcessIdentity,
    request: &PacketControlRequest,
    mut descriptors: Vec<OwnedFd>,
    updates: &mpsc::Sender<PacketPortOwnerUpdate>,
    runtime: &tokio::runtime::Handle,
    original: PacketPortBinding,
    original_deadline_unix: u64,
    original_deadline: tokio::time::Instant,
    original_authorization: Option<&candy_packet_port::packet_port_manager::AuthorizationCheck>,
    deadline: Instant,
) -> Result<()> {
    if request.schema_version != 1
        || request.process != state.process
        || request.controller != peer
        || peer != state.controller
        || request.controller_epoch != state.epoch
        || !process_is_current(peer)
        || request.token_sha256 != format!("{:x}", Sha256::digest(state.token.as_bytes()))
        || request.nonce.len() != 32
        || !request.nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("code=controller_fence_rejected module=tunio_control detail=PID/startticks/epoch/capability mismatch");
    }
    if !fixed_binding_matches(request.binding, original) {
        bail!("code=packet_binding_rejected module=tunio_control detail=infrastructure/domain/IO/policy identity mismatch");
    }
    if !state.registered && !matches!(request.operation, PacketControlOperation::Probe) {
        bail!("code=registration_incomplete module=tunio_control detail=initial durable record not confirmed");
    }
    if (state.authority.active.is_some() || state.authority.pending.is_some())
        && !matches!(request.operation, PacketControlOperation::Probe)
    {
        bail!("code=authority_schema_required module=tunio_control detail=renewed owner requires schema2 exact authorization transaction");
    }
    let change = match request.operation {
        PacketControlOperation::Probe => {
            if !descriptors.is_empty() {
                bail!("Probe cannot receive descriptors");
            }
            return Ok(());
        }
        PacketControlOperation::Attach => {
            if descriptors.len() != 1 || request.binding.owner_epoch <= state.binding.owner_epoch {
                bail!("Attach requires one descriptor and strictly advancing owner epoch");
            }
            let auth_deadline = owner_deadline(request, original_deadline_unix, original_deadline)?;
            let fd = descriptors.pop().expect("checked descriptor count");
            if nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::SockType)?
                != nix::sys::socket::SockType::Datagram
            {
                bail!("PacketPort descriptor must be a datagram socket");
            }
            nix::sys::socket::getsockname::<nix::sys::socket::UnixAddr>(fd.as_raw_fd())
                .context("PacketPort descriptor must belong to AF_UNIX")?;
            let socket = std::os::unix::net::UnixDatagram::from(fd);
            socket
                .peer_addr()
                .context("PacketPort requires a connected datagram socket")?;
            #[cfg(target_os = "linux")]
            {
                let credentials = nix::sys::socket::getsockopt(
                    &socket,
                    nix::sys::socket::sockopt::PeerCredentials,
                )?;
                if credentials.uid() != nix::unistd::geteuid().as_raw()
                    || credentials.pid() != peer.pid as i32
                {
                    bail!("PacketPort descriptor was not created by current controller");
                }
            }
            socket.set_nonblocking(true)?;
            let _runtime = runtime.enter();
            let port = UnixPacketPort::new(
                tokio::net::UnixDatagram::from_std(socket)?,
                request.binding,
                PacketPortRole::Infrastructure,
            )?;
            match original_authorization {
                Some(original_authorization) => {
                    let original_authorization = original_authorization.clone();
                    let replacement = crate::authority_control::bootstrap_check(auth_deadline)?;
                    let authorization = Arc::new(move || {
                        original_authorization()?;
                        if let Some(replacement) = &replacement {
                            replacement()?;
                        }
                        Ok(())
                    });
                    PacketPortOwnerChange::AttachAuthorized {
                        port,
                        auth_deadline,
                        authorization,
                    }
                }
                None => PacketPortOwnerChange::Attach {
                    port,
                    auth_deadline,
                },
            }
        }
        PacketControlOperation::Revoke => {
            if !descriptors.is_empty() || request.binding != state.binding {
                bail!("Revoke requires no descriptors and the exact current binding");
            }
            PacketPortOwnerChange::Revoke {
                owner_epoch: request.binding.owner_epoch,
            }
        }
    };
    remaining(deadline)?;
    if !process_is_current(peer) {
        bail!("controller exited before owner update");
    }
    let (acknowledgement, applied) = oneshot::channel();
    updates
        .try_send(PacketPortOwnerUpdate {
            change,
            acknowledgement,
            receipt: None,
        })
        .map_err(|error| anyhow::anyhow!("PacketPort owner queue unavailable: {error}"))?;
    wait_applied(applied, deadline)?;
    // ACK is now authoritative. Do not restore an obsolete binding if status
    // publication fails; the Agent must reconcile this state after ambiguity.
    state.binding = request.binding;
    state.owner_active = matches!(request.operation, PacketControlOperation::Attach);
    if state.owner_active {
        state.auth_deadline_unix = request.auth_deadline_unix;
    }
    state.publish()?;
    Ok(())
}

pub(crate) fn start(
    supervision_socket: PathBuf,
    state: Arc<Mutex<crate::control::Controller>>,
    updates: mpsc::Sender<PacketPortOwnerUpdate>,
    stop: watch::Sender<bool>,
    original_deadline: tokio::time::Instant,
) -> Result<()> {
    let socket = packet_control_path(&supervision_socket);
    crate::control::private_parent(&socket)?;
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let runtime = tokio::runtime::Handle::current();
    let original_authorization = crate::authority_control::bootstrap_check(original_deadline)?;
    let initial = state
        .lock()
        .map_err(|_| anyhow::anyhow!("controller state poisoned"))?;
    let original = initial.binding;
    let original_deadline_unix = initial.auth_deadline_unix;
    drop(initial);
    thread::spawn(move || {
        let shutdown = stop.subscribe();
        while !*shutdown.borrow() {
            match listener.accept() {
                Ok((stream, _)) => {
                    let deadline = Instant::now() + REQUEST_TIMEOUT;
                    let result = (|| -> Result<()> {
                        stream.set_nonblocking(false)?;
                        let peer = peer_identity(&stream)?;
                        let (bytes, descriptors) =
                            candy_netd_client::receive_descriptor_frame_until(&stream, deadline)?;
                        if bytes.len() > CONTROL_BYTES {
                            bail!("PacketPort control request too large");
                        }
                        let request: PacketControlRequest = serde_json::from_slice(&bytes)?;
                        let mut state = state
                            .lock()
                            .map_err(|_| anyhow::anyhow!("controller state poisoned"))?;
                        let result = apply_request(
                            &mut state,
                            peer,
                            &request,
                            descriptors,
                            &updates,
                            &runtime,
                            original,
                            original_deadline_unix,
                            original_deadline,
                            original_authorization.as_ref(),
                            deadline,
                        );
                        let reply = PacketControlResponse {
                            schema_version: 1,
                            process: state.process,
                            controller: state.controller,
                            controller_epoch: state.epoch,
                            nonce: request.nonce,
                            accepted: result.is_ok(),
                            code: if result.is_ok() {
                                if matches!(request.operation, PacketControlOperation::Probe) {
                                    "packet_owner_probed".into()
                                } else {
                                    "packet_owner_applied".into()
                                }
                            } else {
                                "packet_owner_rejected".into()
                            },
                            detail: result
                                .as_ref()
                                .err()
                                .map(|error| format!("{error:#}"))
                                .unwrap_or_default(),
                            current_binding: state.binding,
                            auth_deadline_unix: state.auth_deadline_unix,
                        };
                        drop(state);
                        candy_netd_client::send_descriptor_frame_until(
                            &stream,
                            &serde_json::to_vec(&reply)?,
                            None,
                            deadline,
                        )?;
                        result
                    })();
                    if let Err(error) = result {
                        eprintln!("level=warn code=packet_owner_request_failed module=tunio_control detail={error:#}");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) => {
                    eprintln!("level=error code=packet_control_accept_failed module=tunio_control detail={error}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        let _ = fs::remove_file(socket);
    });
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use candy_packet_port::{fd::InheritedPacketFd, packet_port::PacketPort};
    use std::os::fd::OwnedFd;
    use tokio::net::UnixDatagram;

    fn binding(epoch: u64) -> PacketPortBinding {
        PacketPortBinding {
            infrastructure_id: [1; 16],
            routing_domain_id: [2; 16],
            infrastructure_generation: 1,
            io_epoch: 1,
            owner_epoch: epoch,
            policy_generation: 1,
        }
    }

    fn pair(epoch: u64) -> (OwnedFd, UnixPacketPort) {
        let (io, worker) = UnixDatagram::pair().unwrap();
        (
            OwnedFd::from(io.into_std().unwrap()),
            UnixPacketPort::new(worker, binding(epoch), PacketPortRole::Worker).unwrap(),
        )
    }

    struct Harness {
        _dir: tempfile::TempDir,
        socket: PathBuf,
        state: Arc<Mutex<crate::control::Controller>>,
        kernel: UnixDatagram,
        initial: UnixPacketPort,
        stop: watch::Sender<bool>,
        task: tokio::task::JoinHandle<
            std::io::Result<candy_packet_port::packet_port_ipc::PacketBridgeCounters>,
        >,
    }

    impl Harness {
        async fn start(auth_seconds: u64) -> Self {
            let directory = tempfile::tempdir_in("/tmp").unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let (tun, kernel) = UnixDatagram::pair().unwrap();
            let tun = InheritedPacketFd::new(OwnedFd::from(tun.into_std().unwrap())).unwrap();
            let (io, initial) = pair(1);
            let io = std::os::unix::net::UnixDatagram::from(io);
            io.set_nonblocking(true).unwrap();
            let io = UnixPacketPort::new(
                UnixDatagram::from_std(io).unwrap(),
                binding(1),
                PacketPortRole::Infrastructure,
            )
            .unwrap();
            let (stop, shutdown) = watch::channel(false);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(auth_seconds);
            let managed = crate::start_managed_infrastructure(tun, io, shutdown, deadline)
                .await
                .unwrap();
            let process = candy_process_control::process_identity(std::process::id()).unwrap();
            let unix_deadline = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + auth_seconds;
            let state = Arc::new(Mutex::new(crate::control::Controller {
                process,
                controller: process,
                epoch: 1,
                token: "fixture-capability-0123456789abcdef".into(),
                status: directory.path().join("status.json"),
                generation: 1,
                auth_deadline_unix: unix_deadline,
                binding: binding(1),
                owner_active: true,
                registered: true,
                registration: None,
                authority: crate::authority_control::AuthorityState::default(),
            }));
            state.lock().unwrap().publish().unwrap();
            let supervision = directory.path().join("ctl.sock");
            start(
                supervision.clone(),
                Arc::clone(&state),
                managed.updates,
                stop.clone(),
                deadline,
            )
            .unwrap();
            Self {
                _dir: directory,
                socket: packet_control_path(&supervision),
                state,
                kernel,
                initial,
                stop,
                task: managed.task,
            }
        }

        fn request(&self, epoch: u64, operation: PacketControlOperation) -> PacketControlRequest {
            let state = self.state.lock().unwrap();
            PacketControlRequest {
                schema_version: 1,
                process: state.process,
                controller: state.controller,
                controller_epoch: state.epoch,
                token_sha256: format!("{:x}", Sha256::digest(state.token.as_bytes())),
                nonce: format!("{epoch:032x}"),
                operation,
                binding: binding(epoch),
                auth_deadline_unix: state.auth_deadline_unix,
            }
        }

        async fn exchange(
            &self,
            request: PacketControlRequest,
            fd: Option<OwnedFd>,
        ) -> Result<PacketControlResponse> {
            let path = self.socket.clone();
            let process = self.state.lock().unwrap().process;
            tokio::task::spawn_blocking(move || {
                exchange_packet_port(
                    &path,
                    process,
                    &request,
                    fd.as_ref(),
                    Instant::now() + Duration::from_secs(3),
                )
            })
            .await
            .unwrap()
        }

        async fn stop(self) -> candy_packet_port::packet_port_ipc::PacketBridgeCounters {
            self.stop.send_replace(true);
            let counters = tokio::time::timeout(Duration::from_secs(2), self.task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(1), async {
                while self.socket.exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            counters
        }
    }

    #[tokio::test]
    async fn actual_attach_keeps_physical_reader_and_revokes_old_owner_before_ack() {
        let harness = Harness::start(60).await;
        harness.initial.send_packet(&[0x45; 64]).await.unwrap();
        let mut packet = [0; 128];
        assert_eq!(harness.kernel.recv(&mut packet).await.unwrap(), 64);
        let (fd, replacement) = pair(2);
        let reply = harness
            .exchange(harness.request(2, PacketControlOperation::Attach), Some(fd))
            .await
            .unwrap();
        assert_eq!(reply.current_binding, binding(2));
        let probe = harness
            .exchange(harness.request(1, PacketControlOperation::Probe), None)
            .await
            .unwrap();
        assert_eq!(probe.current_binding, binding(2));
        assert!(harness.initial.send_packet(&[0x48; 64]).await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), harness.kernel.recv(&mut packet))
                .await
                .is_err()
        );
        harness.kernel.send(&[0x46; 64]).await.unwrap();
        assert_eq!(replacement.recv_packet().await.unwrap(), vec![0x46; 64]);
        replacement.send_packet(&[0x47; 64]).await.unwrap();
        assert_eq!(harness.kernel.recv(&mut packet).await.unwrap(), 64);
        assert_eq!(&packet[..64], &[0x47; 64]);
        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(&harness.state.lock().unwrap().status).unwrap())
                .unwrap();
        assert_eq!(status["packet_binding"]["owner_epoch"], 2);
        harness
            .exchange(harness.request(2, PacketControlOperation::Revoke), None)
            .await
            .unwrap();
        assert!(replacement.send_packet(&[0x48; 64]).await.is_err());
        assert!(!harness.task.is_finished());
        harness.kernel.send(&[0x49; 64]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let counters = harness.stop().await;
        assert_eq!(counters.to_tun_packets, 2);
        assert_eq!(counters.to_worker_packets, 1);
        assert!(counters.no_worker_drops >= 1);
    }

    #[tokio::test]
    async fn authenticated_fences_and_original_authority_reject_changed_scope() {
        let harness = Harness::start(60).await;
        for mutation in 0..8 {
            let (fd, _worker) = pair(2);
            let mut request = harness.request(2, PacketControlOperation::Attach);
            match mutation {
                0 => request.controller_epoch += 1,
                1 => request.controller.start_ticks += 1,
                2 => request.binding.routing_domain_id = [3; 16],
                3 => request.binding.io_epoch += 1,
                4 => request.binding.owner_epoch = 1,
                5 => request.auth_deadline_unix += 1,
                6 => request.binding.policy_generation += 1,
                _ => request.token_sha256 = "00".repeat(32),
            }
            assert!(
                harness.exchange(request, Some(fd)).await.is_err(),
                "mutation={mutation}"
            );
            assert_eq!(harness.state.lock().unwrap().binding.owner_epoch, 1);
        }
        let (fd, _worker) = pair(2);
        harness
            .exchange(harness.request(2, PacketControlOperation::Attach), Some(fd))
            .await
            .unwrap();
        harness.stop().await;
    }

    #[tokio::test]
    async fn missing_or_extra_descriptors_are_closed_and_later_attach_survives() {
        use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
        use std::io::IoSlice;
        let harness = Harness::start(60).await;
        let request = harness.request(2, PacketControlOperation::Attach);
        assert!(harness.exchange(request, None).await.is_err());
        let path = harness.socket.clone();
        let request = harness.request(2, PacketControlOperation::Attach);
        let (one, _) = pair(2);
        let (two, _) = pair(2);
        let result = tokio::task::spawn_blocking(move || -> Result<()> {
            let stream = UnixStream::connect(path)?;
            let payload = serde_json::to_vec(&request)?;
            let header = (payload.len() as u32).to_be_bytes();
            let descriptors = [one.as_raw_fd(), two.as_raw_fd()];
            sendmsg::<()>(
                stream.as_raw_fd(),
                &[IoSlice::new(&header), IoSlice::new(&payload)],
                &[ControlMessage::ScmRights(&descriptors)],
                MsgFlags::empty(),
                None,
            )?;
            let (bytes, received) = candy_netd_client::receive_descriptor_frame_until(
                &stream,
                Instant::now() + Duration::from_secs(3),
            )?;
            assert!(received.is_empty());
            let reply: PacketControlResponse = serde_json::from_slice(&bytes)?;
            assert!(!reply.accepted);
            Ok(())
        })
        .await
        .unwrap();
        result.unwrap();
        let (fd, _worker) = pair(2);
        harness
            .exchange(harness.request(2, PacketControlOperation::Attach), Some(fd))
            .await
            .unwrap();
        harness.stop().await;
    }

    #[test]
    fn wall_clock_shift_cannot_extend_original_monotonic_deadline() {
        let identity = ProcessIdentity {
            pid: 1,
            start_ticks: 1,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let request = PacketControlRequest {
            schema_version: 1,
            process: identity,
            controller: identity,
            controller_epoch: 1,
            token_sha256: String::new(),
            nonce: String::new(),
            operation: PacketControlOperation::Attach,
            binding: binding(2),
            auth_deadline_unix: now + 60,
        };
        let original = tokio::time::Instant::now() + Duration::from_millis(10);
        assert_eq!(
            owner_deadline(&request, now + 60, original).unwrap(),
            original
        );
        assert!(owner_deadline(&request, now + 60, tokio::time::Instant::now()).is_err());
    }

    #[tokio::test]
    async fn wrong_descriptor_type_and_expired_attach_preserve_live_infrastructure() {
        let harness = Harness::start(2).await;
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(harness
            .exchange(
                harness.request(2, PacketControlOperation::Attach),
                Some(OwnedFd::from(stream))
            )
            .await
            .is_err());
        assert_eq!(harness.state.lock().unwrap().binding, binding(1));
        tokio::time::sleep(Duration::from_secs(3)).await;
        let (fd, _) = pair(2);
        assert!(harness
            .exchange(harness.request(2, PacketControlOperation::Attach), Some(fd))
            .await
            .is_err());
        assert!(!harness.task.is_finished());
        harness.kernel.send(&[0x45; 64]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(harness.stop().await.no_worker_drops >= 1);
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    fn request() -> PacketControlRequest {
        PacketControlRequest {
            schema_version: 1,
            process: ProcessIdentity {
                pid: 42,
                start_ticks: 100,
            },
            controller: ProcessIdentity {
                pid: 43,
                start_ticks: 101,
            },
            controller_epoch: 2,
            token_sha256: "01".repeat(32),
            nonce: "02".repeat(16),
            operation: PacketControlOperation::Attach,
            binding: PacketPortBinding {
                infrastructure_id: [1; 16],
                routing_domain_id: [2; 16],
                infrastructure_generation: 3,
                io_epoch: 4,
                owner_epoch: 5,
                policy_generation: 6,
            },
            auth_deadline_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
        }
    }

    #[test]
    fn protocol_is_explicit_and_rejects_unknown_authority_fields() {
        let request = request();
        let mut json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["operation"], "attach");
        json["renew_authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PacketControlRequest>(json).is_err());
        let mut binding = serde_json::to_value(request.binding).unwrap();
        binding["tenant_override"] = serde_json::json!("other");
        assert!(serde_json::from_value::<PacketPortBinding>(binding).is_err());
    }

    #[test]
    fn probe_allows_old_owner_identity_but_preserves_scope_and_original_deadline() {
        let request = request();
        let mut reply_binding = request.binding;
        reply_binding.owner_epoch += 1;
        assert!(fixed_binding_matches(reply_binding, request.binding));
        reply_binding.io_epoch += 1;
        assert!(!fixed_binding_matches(reply_binding, request.binding));
        let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
        assert_eq!(
            owner_deadline(&request, request.auth_deadline_unix, deadline).unwrap(),
            deadline
        );
        assert!(owner_deadline(&request, request.auth_deadline_unix - 1, deadline).is_err());
        assert!(owner_deadline(
            &request,
            request.auth_deadline_unix,
            tokio::time::Instant::now()
        )
        .is_err());
    }
}
