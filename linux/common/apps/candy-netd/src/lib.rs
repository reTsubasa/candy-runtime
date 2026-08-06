#![cfg(unix)]

mod journal;
mod linux;
mod network;
#[cfg(target_os = "linux")]
mod nft;

pub use journal::FileNetworkJournal;
#[cfg(target_os = "linux")]
pub use linux::LinuxNetworkBackend;
pub use linux::{LinuxNetworkPlan, CANDY_POLICY_PRIORITY_MIN};
pub use network::{
    restore_sysctl_value, NetworkBackend, NetworkController, NetworkError, NetworkJournal,
    NetworkTransaction, SysctlChange, SysctlKey, TransactionPhase, TransactionRecord,
};

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use thiserror::Error;

use candy_netd_client::{recv_request, send_response, IpcError};
use candy_netd_proto::{
    ErrorCode, NetdOperation, NetdRequest, NetdResponse, NetdSession, NetdSessionError,
    ResponseBody,
};

#[derive(Debug, Error)]
pub enum SocketSecurityError {
    #[error("netd socket parent is missing or unsafe")]
    UnsafeParent,
    #[error("netd socket path already exists")]
    ExistingPath,
    #[error("netd socket operation failed")]
    Io(#[from] std::io::Error),
}

pub struct PrivateUnixListener {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl PrivateUnixListener {
    pub fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }

    pub fn accept(&self) -> std::io::Result<(UnixStream, std::os::unix::net::SocketAddr)> {
        self.listener.accept()
    }
}

impl Drop for PrivateUnixListener {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn bind_private_socket(path: &Path) -> Result<PrivateUnixListener, SocketSecurityError> {
    bind_private_socket_owned(
        path,
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    )
}

fn bind_private_socket_owned(
    path: &Path,
    socket_uid: u32,
    socket_gid: u32,
) -> Result<PrivateUnixListener, SocketSecurityError> {
    let parent = path.parent().ok_or(SocketSecurityError::UnsafeParent)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| SocketSecurityError::UnsafeParent)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.permissions().mode() & 0o022 != 0
        || parent_metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(SocketSecurityError::UnsafeParent);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket()
                || metadata.uid() != socket_uid
                || metadata.gid() != socket_gid
                || metadata.permissions().mode() & 0o177 != 0
            {
                return Err(SocketSecurityError::ExistingPath);
            }
            match UnixStream::connect(path) {
                Ok(_) => return Err(SocketSecurityError::ExistingPath),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                    ) => {}
                Err(error) => return Err(SocketSecurityError::Io(error)),
            }
            let current = fs::symlink_metadata(path)?;
            if !current.file_type().is_socket()
                || current.dev() != metadata.dev()
                || current.ino() != metadata.ino()
                || current.uid() != socket_uid
                || current.gid() != socket_gid
                || current.permissions().mode() & 0o177 != 0
            {
                return Err(SocketSecurityError::ExistingPath);
            }
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(SocketSecurityError::Io(error)),
    }
    let listener = UnixListener::bind(path)?;
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(path);
        return Err(SocketSecurityError::Io(error));
    }
    let socket_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            drop(listener);
            let _ = fs::remove_file(path);
            return Err(SocketSecurityError::Io(error));
        }
    };
    if socket_metadata.file_type().is_symlink() || !socket_metadata.file_type().is_socket() {
        drop(listener);
        let _ = fs::remove_file(path);
        return Err(SocketSecurityError::ExistingPath);
    }
    let socket_metadata = fs::symlink_metadata(path)?;
    Ok(PrivateUnixListener {
        listener,
        path: path.to_path_buf(),
        device: socket_metadata.dev(),
        inode: socket_metadata.ino(),
    })
}

pub fn bind_private_socket_for(
    path: &Path,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<PrivateUnixListener, SocketSecurityError> {
    let listener = bind_private_socket_owned(path, owner_uid, owner_gid)?;
    if let Err(error) = nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(owner_uid)),
        Some(nix::unistd::Gid::from_raw(owner_gid)),
    ) {
        drop(listener);
        let _ = fs::remove_file(path);
        return Err(SocketSecurityError::Io(std::io::Error::from_raw_os_error(
            error as i32,
        )));
    }
    Ok(listener)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("platform operation failed")]
    Io(#[from] std::io::Error),
    #[error("platform operation is unsupported")]
    Unsupported,
    #[error("peer credentials are invalid")]
    InvalidPeer,
}

#[cfg(target_os = "linux")]
pub fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, PlatformError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials as PeerCredentialsOption};

    let credentials = getsockopt(stream, PeerCredentialsOption)
        .map_err(|error| PlatformError::Io(std::io::Error::from_raw_os_error(error as i32)))?;
    Ok(PeerCredentials {
        pid: u32::try_from(credentials.pid()).map_err(|_| PlatformError::InvalidPeer)?,
        uid: credentials.uid(),
        gid: credentials.gid(),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn peer_credentials(_stream: &UnixStream) -> Result<PeerCredentials, PlatformError> {
    Err(PlatformError::Unsupported)
}

pub trait TunFactory {
    fn create(&mut self) -> Result<OwnedFd, PlatformError>;
}

#[derive(Debug, Default)]
pub struct SystemTunFactory;

impl TunFactory for SystemTunFactory {
    fn create(&mut self) -> Result<OwnedFd, PlatformError> {
        create_candy_tun()
    }
}

#[cfg(target_os = "linux")]
pub fn create_candy_tun() -> Result<OwnedFd, PlatformError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    #[repr(C)]
    struct TunIfReq {
        name: [nix::libc::c_char; nix::libc::IFNAMSIZ],
        flags: nix::libc::c_short,
        padding: [u8; 22],
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
        .open("/dev/net/tun")?;
    let mut request = TunIfReq {
        name: [0; nix::libc::IFNAMSIZ],
        flags: (nix::libc::IFF_TUN | nix::libc::IFF_NO_PI) as nix::libc::c_short,
        padding: [0; 22],
    };
    for (target, source) in request.name.iter_mut().zip(b"candy0\0") {
        *target = *source as nix::libc::c_char;
    }
    // The kernel reads this fixed-layout Linux ifreq and retains no pointer to it.
    let result = unsafe { nix::libc::ioctl(file.as_raw_fd(), nix::libc::TUNSETIFF, &mut request) };
    if result < 0 {
        return Err(PlatformError::Io(std::io::Error::last_os_error()));
    }
    Ok(file.into())
}

#[cfg(not(target_os = "linux"))]
pub fn create_candy_tun() -> Result<OwnedFd, PlatformError> {
    Err(PlatformError::Unsupported)
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("netd IPC failed")]
    Ipc(#[from] IpcError),
    #[error("netd platform operation failed")]
    Platform(#[from] PlatformError),
    #[error("netd descriptor duplication failed")]
    Descriptor(#[from] nix::Error),
    #[error("netd network transaction failed")]
    Network(#[from] NetworkError),
}

pub struct NetdService<T, N> {
    allowed_uid: u32,
    allowed_gid: u32,
    session: NetdSession,
    tun: Option<OwnedFd>,
    #[cfg(target_os = "linux")]
    owner_pidfd: Option<(u32, OwnedFd)>,
    tun_factory: T,
    network: N,
}

impl<T: TunFactory, N: NetworkController> NetdService<T, N> {
    pub fn with_network(allowed_uid: u32, allowed_gid: u32, tun_factory: T, network: N) -> Self {
        Self {
            allowed_uid,
            allowed_gid,
            session: NetdSession::new(),
            tun: None,
            #[cfg(target_os = "linux")]
            owner_pidfd: None,
            tun_factory,
            network,
        }
    }

    pub fn recover_orphan(&mut self, now_mono_ms: u64) -> Result<bool, ServiceError> {
        let retained_owner = self.network.retained_owner();
        let owner_is_alive = retained_owner.is_some_and(|owner| self.owner_is_alive(owner.pid));
        let recovered = self
            .network
            .recover_orphan(owner_is_alive, now_mono_ms)
            .map_err(ServiceError::Network)?;
        if recovered {
            self.tun = None;
            self.session = NetdSession::new();
            #[cfg(target_os = "linux")]
            {
                self.owner_pidfd = None;
            }
        }
        Ok(recovered)
    }

    pub fn shutdown(&mut self) -> Result<bool, ServiceError> {
        let Some(owner) = self.network.retained_owner() else {
            return Ok(false);
        };
        self.network
            .rollback(owner)
            .map_err(ServiceError::Network)?;
        self.tun = None;
        #[cfg(target_os = "linux")]
        {
            self.owner_pidfd = None;
        }
        self.session = NetdSession::new();
        Ok(true)
    }

    pub fn serve_once(&mut self, stream: &UnixStream) -> Result<(), ServiceError> {
        let peer = peer_credentials(stream)?;
        self.serve_authenticated_once(stream, peer)
    }

    pub fn serve_authenticated_once(
        &mut self,
        stream: &UnixStream,
        peer: PeerCredentials,
    ) -> Result<(), ServiceError> {
        let request = recv_request(stream)?;
        let request_id = request.request_id;
        let generation = request.owner.generation;
        let operation = match &request.operation {
            NetdOperation::Prepare(_) => "prepare",
            NetdOperation::Commit => "commit",
            NetdOperation::Rollback => "rollback",
            NetdOperation::Status => "status",
            NetdOperation::LeaseRenew => "lease_renew",
            NetdOperation::MtuUpdate { .. } => "mtu_update",
        };
        let (response, descriptor) = self.process(request, peer)?;
        match &response.body {
            ResponseBody::Error(code) => eprintln!(
                "level=warn component=candy-netd event=request_rejected request_id={request_id} generation={generation} operation={operation} code={code:?}"
            ),
            _ if !matches!(operation, "status" | "lease_renew") => eprintln!(
                "level=info component=candy-netd event=request_completed request_id={request_id} generation={generation} operation={operation}"
            ),
            _ => {}
        }
        send_response(
            stream,
            &response,
            descriptor.as_ref().map(AsRawFd::as_raw_fd),
        )?;
        Ok(())
    }

    fn process(
        &mut self,
        request: NetdRequest,
        peer: PeerCredentials,
    ) -> Result<(NetdResponse, Option<OwnedFd>), ServiceError> {
        if peer.uid != self.allowed_uid
            || peer.gid != self.allowed_gid
            || request.owner.pid != peer.pid
        {
            return Ok((
                error_response(request.request_id, ErrorCode::UnauthorizedPeer),
                None,
            ));
        }

        let mut next_session = self.session.clone();
        if let Err(error) = next_session.apply(&request) {
            return Ok((
                error_response(request.request_id, session_error_code(error)),
                None,
            ));
        }

        let mut transferred = None;
        let body = match &request.operation {
            NetdOperation::Prepare(declaration) => {
                if self.tun.is_none() {
                    let tun = match self.tun_factory.create() {
                        Ok(tun) => tun,
                        Err(_) => {
                            return Ok((
                                error_response(request.request_id, ErrorCode::SystemFailure),
                                None,
                            ));
                        }
                    };
                    self.tun = Some(tun);
                }
                if let Err(error) = self.network.prepare(request.owner, declaration.clone()) {
                    self.tun = None;
                    return Ok((
                        error_response(request.request_id, network_error_code(error)),
                        None,
                    ));
                }
                #[cfg(target_os = "linux")]
                if self.owner_pidfd.as_ref().map(|value| value.0) != Some(request.owner.pid) {
                    self.owner_pidfd = open_pidfd(request.owner.pid)
                        .ok()
                        .map(|descriptor| (request.owner.pid, descriptor));
                }
                let duplicate = match nix::fcntl::fcntl(
                    self.tun.as_ref().expect("TUN retained").as_raw_fd(),
                    nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(0),
                ) {
                    Ok(descriptor) => descriptor,
                    Err(_) => {
                        return Ok((
                            error_response(request.request_id, ErrorCode::SystemFailure),
                            None,
                        ));
                    }
                };
                // F_DUPFD_CLOEXEC returns a fresh descriptor owned by this process.
                transferred = Some(unsafe { OwnedFd::from_raw_fd(duplicate) });
                ResponseBody::Prepared {
                    generation: request.owner.generation,
                    tun_fd_attached: true,
                }
            }
            NetdOperation::Commit => {
                if let Err(error) = self.network.commit(request.owner) {
                    self.tun = None;
                    return Ok((
                        error_response(request.request_id, network_error_code(error)),
                        None,
                    ));
                }
                ResponseBody::Committed {
                    generation: request.owner.generation,
                }
            }
            NetdOperation::Rollback => {
                if let Err(error) = self.network.rollback(request.owner) {
                    return Ok((
                        error_response(request.request_id, network_error_code(error)),
                        None,
                    ));
                }
                self.tun = None;
                #[cfg(target_os = "linux")]
                {
                    self.owner_pidfd = None;
                }
                ResponseBody::RolledBack {
                    generation: request.owner.generation,
                }
            }
            NetdOperation::Status => ResponseBody::Status {
                phase: next_session.phase(),
                generation: request.owner.generation,
            },
            NetdOperation::LeaseRenew => {
                if let Err(error) = self.network.renew_lease(request.owner) {
                    return Ok((
                        error_response(request.request_id, network_error_code(error)),
                        None,
                    ));
                }
                ResponseBody::LeaseRenewed {
                    generation: request.owner.generation,
                }
            }
            NetdOperation::MtuUpdate { effective_mtu } => {
                if let Err(error) = self.network.update_mtu(request.owner, *effective_mtu) {
                    return Ok((
                        error_response(request.request_id, network_error_code(error)),
                        None,
                    ));
                }
                ResponseBody::MtuUpdated {
                    generation: request.owner.generation,
                    effective_mtu: *effective_mtu,
                }
            }
        };
        self.session = next_session;
        Ok((
            NetdResponse {
                request_id: request.request_id,
                body,
            },
            transferred,
        ))
    }

    fn owner_is_alive(&self, pid: u32) -> bool {
        #[cfg(target_os = "linux")]
        if let Some((retained_pid, descriptor)) = &self.owner_pidfd {
            if *retained_pid == pid {
                return !pidfd_is_ready(descriptor);
            }
        }
        process_is_alive(pid)
    }
}

#[cfg(target_os = "linux")]
fn process_is_alive(pid: u32) -> bool {
    if let Ok(descriptor) = open_pidfd(pid) {
        return !pidfd_is_ready(&descriptor);
    }
    // Older kernels may not support pidfd_open; lease expiry remains authoritative.
    let result = unsafe { nix::libc::kill(pid as nix::libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM)
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> Result<OwnedFd, std::io::Error> {
    let descriptor = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // pidfd_open returns a new close-on-exec descriptor when flags are zero.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as i32) })
}

#[cfg(target_os = "linux")]
fn pidfd_is_ready(descriptor: &OwnedFd) -> bool {
    let mut poll_fd = nix::libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { nix::libc::poll(&mut poll_fd, 1, 0) };
    result > 0 && poll_fd.revents & (nix::libc::POLLIN | nix::libc::POLLHUP) != 0
}

#[cfg(not(target_os = "linux"))]
fn process_is_alive(_pid: u32) -> bool {
    false
}

fn error_response(request_id: u64, code: ErrorCode) -> NetdResponse {
    NetdResponse {
        request_id,
        body: ResponseBody::Error(code),
    }
}

fn session_error_code(error: NetdSessionError) -> ErrorCode {
    match error {
        NetdSessionError::GenerationConflict | NetdSessionError::OwnerMismatch => {
            ErrorCode::GenerationConflict
        }
        NetdSessionError::InvalidTransition | NetdSessionError::InvalidDeclaration => {
            ErrorCode::InvalidRequest
        }
    }
}

fn network_error_code(error: NetworkError) -> ErrorCode {
    match error {
        NetworkError::Conflict => ErrorCode::GenerationConflict,
        NetworkError::InvalidTransition => ErrorCode::InvalidRequest,
        NetworkError::Backend => ErrorCode::PreflightFailed,
        NetworkError::Journal => ErrorCode::SystemFailure,
    }
}
