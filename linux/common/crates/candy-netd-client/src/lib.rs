#![cfg(unix)]

pub mod v2;

use candy_netd_proto::{
    ErrorCode, LeaseOwner, NetdOperation, NetdProtocolError, NetdRequest, NetdResponse,
    PrepareDeclaration, ResponseBody, SessionPhase, MAX_NETD_FRAME_LEN,
};
use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use std::io::{IoSlice, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use thiserror::Error;

const LENGTH_PREFIX_LEN: usize = 4;

/// Bounded descriptor framing; callers authenticate the peer before receiving.
pub fn send_descriptor_frame_until(
    stream: &UnixStream,
    payload: &[u8],
    descriptor: Option<RawFd>,
    deadline: std::time::Instant,
) -> Result<(), IpcError> {
    send_frame_until(stream, payload, descriptor, Some(deadline))
}

pub fn receive_descriptor_frame_until(
    stream: &UnixStream,
    deadline: std::time::Instant,
) -> Result<(Vec<u8>, Vec<OwnedFd>), IpcError> {
    recv_frame_until(stream, Some(deadline))
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("netd IPC I/O failed")]
    Io(#[from] std::io::Error),
    #[error("netd IPC descriptor transfer failed")]
    Socket(#[from] nix::Error),
    #[error("netd IPC frame length is invalid")]
    FrameLength,
    #[error("netd IPC frame is invalid")]
    Protocol(#[from] NetdProtocolError),
    #[error("netd IPC response descriptor does not match its declaration")]
    DescriptorMismatch,
    #[error("netd IPC request id space is exhausted")]
    RequestIdExhausted,
    #[error("netd rejected the request: {0:?}")]
    Remote(ErrorCode),
    #[error("netd response does not match the request")]
    UnexpectedResponse,
    #[error("netd request is invalid for the local transaction phase")]
    InvalidTransition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientPhase {
    Stopped,
    Prepared,
    Active,
    Suspended,
}

#[derive(Debug)]
pub struct PreparedNetwork {
    pub generation: u64,
    pub tun: OwnedFd,
}

#[derive(Debug)]
pub struct NetdClient {
    socket_path: PathBuf,
    owner: LeaseOwner,
    next_request_id: Option<u64>,
    phase: ClientPhase,
}

impl NetdClient {
    pub fn new(socket_path: impl Into<PathBuf>, owner: LeaseOwner) -> Self {
        Self {
            socket_path: socket_path.into(),
            owner,
            next_request_id: Some(1),
            phase: ClientPhase::Stopped,
        }
    }

    pub fn prepare(
        &mut self,
        declaration: PrepareDeclaration,
    ) -> Result<PreparedNetwork, IpcError> {
        if self.phase != ClientPhase::Stopped {
            return Err(IpcError::InvalidTransition);
        }
        let (body, descriptor) = self.exchange(NetdOperation::Prepare(declaration))?;
        let ResponseBody::Prepared {
            generation,
            tun_fd_attached: true,
        } = body
        else {
            return Err(IpcError::UnexpectedResponse);
        };
        if generation != self.owner.generation {
            return Err(IpcError::UnexpectedResponse);
        }
        let tun = descriptor.ok_or(IpcError::DescriptorMismatch)?;
        self.phase = ClientPhase::Prepared;
        Ok(PreparedNetwork { generation, tun })
    }

    pub fn commit(&mut self) -> Result<u64, IpcError> {
        if self.phase != ClientPhase::Prepared {
            return Err(IpcError::InvalidTransition);
        }
        let generation = self.exchange_generation(NetdOperation::Commit, |body| match body {
            ResponseBody::Committed { generation } => Some(generation),
            _ => None,
        })?;
        self.phase = ClientPhase::Active;
        Ok(generation)
    }

    pub fn rollback(&mut self) -> Result<u64, IpcError> {
        if self.phase == ClientPhase::Stopped {
            return Err(IpcError::InvalidTransition);
        }
        let generation = self.exchange_generation(NetdOperation::Rollback, |body| match body {
            ResponseBody::RolledBack { generation } => Some(generation),
            _ => None,
        })?;
        self.phase = ClientPhase::Stopped;
        Ok(generation)
    }

    /// Set the exact failed destination prefixes. An empty set restores all
    /// routes from the active declaration.
    pub fn set_failed_prefixes(
        &mut self,
        prefixes: Vec<candy_netd_proto::Ipv4Prefix>,
    ) -> Result<u64, IpcError> {
        // Peer-loss handling suspends policy steering before reconciling the
        // exact failed route set. The daemon accepts this operation while the
        // route table remains owned in either phase, so the client state
        // machine must preserve the same contract.
        if !matches!(self.phase, ClientPhase::Active | ClientPhase::Suspended) {
            return Err(IpcError::InvalidTransition);
        }
        self.exchange_generation(
            NetdOperation::WithdrawPrefixes { prefixes },
            |body| match body {
                ResponseBody::PrefixesWithdrawn { generation, .. } => Some(generation),
                _ => None,
            },
        )
    }

    pub fn renew_lease(&mut self, lease_deadline_mono_ms: u64) -> Result<u64, IpcError> {
        if self.phase == ClientPhase::Stopped || lease_deadline_mono_ms == 0 {
            return Err(IpcError::InvalidTransition);
        }
        let previous = self.owner.lease_deadline_mono_ms;
        self.owner.lease_deadline_mono_ms = lease_deadline_mono_ms;
        let result = self.exchange_generation(NetdOperation::LeaseRenew, |body| match body {
            ResponseBody::LeaseRenewed { generation } => Some(generation),
            _ => None,
        });
        if result.is_err() {
            self.owner.lease_deadline_mono_ms = previous;
        }
        result
    }

    pub fn update_mtu(&mut self, effective_mtu: u16) -> Result<u16, IpcError> {
        if self.phase != ClientPhase::Active {
            return Err(IpcError::InvalidTransition);
        }
        let (body, descriptor) = self.exchange(NetdOperation::MtuUpdate { effective_mtu })?;
        if descriptor.is_some() {
            return Err(IpcError::DescriptorMismatch);
        }
        let ResponseBody::MtuUpdated {
            generation,
            effective_mtu,
        } = body
        else {
            return Err(IpcError::UnexpectedResponse);
        };
        if generation != self.owner.generation {
            return Err(IpcError::UnexpectedResponse);
        }
        Ok(effective_mtu)
    }

    /// Atomically replace Candy-owned policy routes and firewall rules without
    /// changing the active tunnel generation or lease owner.
    pub fn update_policy(&mut self, declaration: PrepareDeclaration) -> Result<u64, IpcError> {
        if !matches!(self.phase, ClientPhase::Active | ClientPhase::Suspended) {
            return Err(IpcError::InvalidTransition);
        }
        self.exchange_generation(
            NetdOperation::PolicyUpdate(declaration),
            |body| match body {
                ResponseBody::PolicyUpdated { generation } => Some(generation),
                _ => None,
            },
        )
    }

    pub fn suspend(&mut self) -> Result<u64, IpcError> {
        if self.phase != ClientPhase::Active {
            return Err(IpcError::InvalidTransition);
        }
        let generation = self.exchange_generation(NetdOperation::Suspend, |body| match body {
            ResponseBody::Suspended { generation } => Some(generation),
            _ => None,
        })?;
        self.phase = ClientPhase::Suspended;
        Ok(generation)
    }

    pub fn reconfigure(&mut self, declaration: PrepareDeclaration) -> Result<u64, IpcError> {
        self.reconfigure_with_owner(
            declaration,
            self.owner.generation,
            self.owner.lease_deadline_mono_ms,
        )
    }

    /// Replace the declaration and advance the lease generation as one netd
    /// transaction. Hot activation keeps the prepared session suspended, but
    /// the netd owner must still move with the immutable Cloud generation.
    pub fn reconfigure_with_owner(
        &mut self,
        declaration: PrepareDeclaration,
        generation: u64,
        lease_deadline_mono_ms: u64,
    ) -> Result<u64, IpcError> {
        if self.phase != ClientPhase::Suspended && self.phase != ClientPhase::Active {
            return Err(IpcError::InvalidTransition);
        }
        if generation == 0 || lease_deadline_mono_ms == 0 {
            return Err(IpcError::InvalidTransition);
        }
        let previous_generation = self.owner.generation;
        let previous_deadline = self.owner.lease_deadline_mono_ms;
        self.owner.generation = generation;
        self.owner.lease_deadline_mono_ms = lease_deadline_mono_ms;
        let result =
            self.exchange_generation(NetdOperation::Reconfigure(declaration), |body| match body {
                ResponseBody::Reconfigured { generation } => Some(generation),
                _ => None,
            });
        if result.is_err() {
            // The request may have been committed by netd before an IPC
            // failure (or a malformed response) reached us. Reconcile the
            // retained generation before rolling back local owner state; an
            // unconditional rollback here creates a split-brain transaction
            // where netd accepts only the replacement owner.
            let committed = matches!(
                self.exchange(NetdOperation::Status),
                Ok((
                    ResponseBody::Status {
                        phase: SessionPhase::Suspended,
                        generation: observed,
                    },
                    None,
                )) if observed == generation
            );
            if committed {
                return Ok(generation);
            }
            self.owner.generation = previous_generation;
            self.owner.lease_deadline_mono_ms = previous_deadline;
        }
        result
    }

    /// Stage a new declaration while the current generation remains active.
    /// Netd retains the old owner until `commit_replacement` and `drain_old`.
    pub fn prepare_replacement_with_owner(
        &mut self,
        declaration: PrepareDeclaration,
        generation: u64,
        lease_deadline_mono_ms: u64,
    ) -> Result<u64, IpcError> {
        if self.phase != ClientPhase::Active {
            return Err(IpcError::InvalidTransition);
        }
        let previous_generation = self.owner.generation;
        let previous_deadline = self.owner.lease_deadline_mono_ms;
        self.owner.generation = generation;
        self.owner.lease_deadline_mono_ms = lease_deadline_mono_ms;
        let result =
            self.exchange_generation(NetdOperation::Reconfigure(declaration), |body| match body {
                ResponseBody::Reconfigured { generation } => Some(generation),
                _ => None,
            });
        if result.is_err() {
            self.owner.generation = previous_generation;
            self.owner.lease_deadline_mono_ms = previous_deadline;
        }
        result
    }

    pub fn commit_replacement(&mut self) -> Result<u64, IpcError> {
        if self.phase != ClientPhase::Active {
            return Err(IpcError::InvalidTransition);
        }
        self.exchange_generation(NetdOperation::Commit, |body| match body {
            ResponseBody::Committed { generation } => Some(generation),
            _ => None,
        })
    }

    pub fn drain_old(&mut self, now_mono_ms: u64) -> Result<u64, IpcError> {
        if self.phase != ClientPhase::Active {
            return Err(IpcError::InvalidTransition);
        }
        self.exchange_generation(NetdOperation::Drain { now_mono_ms }, |body| match body {
            ResponseBody::Drained { generation } => Some(generation),
            _ => None,
        })
    }

    pub fn resume(&mut self) -> Result<u64, IpcError> {
        if self.phase != ClientPhase::Suspended {
            return Err(IpcError::InvalidTransition);
        }
        let generation = self.exchange_generation(NetdOperation::Resume, |body| match body {
            ResponseBody::Resumed { generation } => Some(generation),
            _ => None,
        })?;
        self.phase = ClientPhase::Active;
        Ok(generation)
    }

    pub fn status(&mut self) -> Result<(SessionPhase, u64), IpcError> {
        let (body, descriptor) = self.exchange(NetdOperation::Status)?;
        if descriptor.is_some() {
            return Err(IpcError::DescriptorMismatch);
        }
        let ResponseBody::Status { phase, generation } = body else {
            return Err(IpcError::UnexpectedResponse);
        };
        if generation != self.owner.generation {
            return Err(IpcError::UnexpectedResponse);
        }
        Ok((phase, generation))
    }

    fn exchange_generation(
        &mut self,
        operation: NetdOperation,
        generation: impl FnOnce(ResponseBody) -> Option<u64>,
    ) -> Result<u64, IpcError> {
        let (body, descriptor) = self.exchange(operation)?;
        if descriptor.is_some() {
            return Err(IpcError::DescriptorMismatch);
        }
        let generation = generation(body).ok_or(IpcError::UnexpectedResponse)?;
        if generation != self.owner.generation {
            return Err(IpcError::UnexpectedResponse);
        }
        Ok(generation)
    }

    fn exchange(
        &mut self,
        operation: NetdOperation,
    ) -> Result<(ResponseBody, Option<OwnedFd>), IpcError> {
        let request_id = self.next_request_id.ok_or(IpcError::RequestIdExhausted)?;
        let request = NetdRequest {
            request_id,
            owner: self.owner,
            operation,
        };
        let stream = UnixStream::connect(Path::new(&self.socket_path))?;
        send_request(&stream, &request)?;
        let (response, descriptor) = recv_response(&stream)?;
        self.next_request_id = request_id.checked_add(1);
        if response.request_id != request_id {
            return Err(IpcError::UnexpectedResponse);
        }
        if let ResponseBody::Error(code) = response.body {
            if descriptor.is_some() {
                return Err(IpcError::DescriptorMismatch);
            }
            return Err(IpcError::Remote(code));
        }
        Ok((response.body, descriptor))
    }
}

impl Drop for NetdClient {
    fn drop(&mut self) {
        if self.phase != ClientPhase::Stopped {
            let _ = self.rollback();
        }
    }
}

pub fn send_request(stream: &UnixStream, request: &NetdRequest) -> Result<(), IpcError> {
    send_frame(stream, &request.encode()?, None)
}

pub fn recv_request(stream: &UnixStream) -> Result<NetdRequest, IpcError> {
    let (frame, descriptors) = recv_frame(stream)?;
    if !descriptors.is_empty() {
        return Err(IpcError::DescriptorMismatch);
    }
    Ok(NetdRequest::decode(&frame)?)
}

pub fn send_response(
    stream: &UnixStream,
    response: &NetdResponse,
    descriptor: Option<RawFd>,
) -> Result<(), IpcError> {
    let expects_descriptor = matches!(
        response.body,
        ResponseBody::Prepared {
            tun_fd_attached: true,
            ..
        }
    );
    if expects_descriptor != descriptor.is_some() {
        return Err(IpcError::DescriptorMismatch);
    }
    send_frame(stream, &response.encode()?, descriptor)
}

pub fn recv_response(stream: &UnixStream) -> Result<(NetdResponse, Option<OwnedFd>), IpcError> {
    let (frame, mut descriptors) = recv_frame(stream)?;
    let response = NetdResponse::decode(&frame)?;
    let expects_descriptor = matches!(
        response.body,
        ResponseBody::Prepared {
            tun_fd_attached: true,
            ..
        }
    );
    if descriptors.len() > 1 || expects_descriptor != (descriptors.len() == 1) {
        return Err(IpcError::DescriptorMismatch);
    }
    Ok((response, descriptors.pop()))
}

fn send_frame(
    stream: &UnixStream,
    payload: &[u8],
    descriptor: Option<RawFd>,
) -> Result<(), IpcError> {
    send_frame_until(stream, payload, descriptor, None)
}

fn send_frame_until(
    stream: &UnixStream,
    payload: &[u8],
    descriptor: Option<RawFd>,
    deadline: Option<std::time::Instant>,
) -> Result<(), IpcError> {
    if payload.is_empty() || payload.len() > MAX_NETD_FRAME_LEN {
        return Err(IpcError::FrameLength);
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| IpcError::FrameLength)?
        .to_be_bytes();
    let slices = [IoSlice::new(&length), IoSlice::new(payload)];
    let descriptors = descriptor.map(|fd| [fd]);
    let control = descriptors
        .as_ref()
        .map(|fds| vec![ControlMessage::ScmRights(fds)])
        .unwrap_or_default();
    let sent = loop {
        if let Some(deadline) = deadline {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "netd IPC response deadline exceeded",
                    )
                })?;
            stream.set_write_timeout(Some(remaining))?;
        }
        match sendmsg::<()>(
            stream.as_raw_fd(),
            &slices,
            &control,
            MsgFlags::empty(),
            None,
        ) {
            Err(Errno::EINTR) => continue,
            result => break result?,
        }
    };
    let frame_len = LENGTH_PREFIX_LEN + payload.len();
    if sent == 0 || sent > frame_len {
        return Err(IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "netd IPC write made no progress",
        )));
    }
    if sent < frame_len {
        if sent < LENGTH_PREFIX_LEN {
            write_all_until(stream, &length[sent..], deadline)?;
            write_all_until(stream, payload, deadline)?;
        } else {
            write_all_until(stream, &payload[sent - LENGTH_PREFIX_LEN..], deadline)?;
        }
    }
    Ok(())
}

fn write_all_until(
    mut stream: &UnixStream,
    mut bytes: &[u8],
    deadline: Option<std::time::Instant>,
) -> Result<(), IpcError> {
    while !bytes.is_empty() {
        if let Some(deadline) = deadline {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "netd IPC response deadline exceeded",
                    )
                })?;
            stream.set_write_timeout(Some(remaining))?;
        }
        match stream.write(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "netd IPC write made no progress",
                )
                .into())
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn recv_frame(stream: &UnixStream) -> Result<(Vec<u8>, Vec<OwnedFd>), IpcError> {
    recv_frame_until(stream, None)
}

fn read_exact_until(
    mut stream: &UnixStream,
    mut bytes: &mut [u8],
    deadline: Option<std::time::Instant>,
) -> Result<(), IpcError> {
    while !bytes.is_empty() {
        apply_read_deadline(stream, deadline)?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "netd IPC peer closed during frame",
                )
                .into())
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn apply_read_deadline(
    stream: &UnixStream,
    deadline: Option<std::time::Instant>,
) -> Result<(), IpcError> {
    if let Some(deadline) = deadline {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "netd IPC frame deadline exceeded",
                )
            })?;
        stream.set_read_timeout(Some(remaining))?;
    }
    Ok(())
}

fn recv_frame_until(
    stream: &UnixStream,
    deadline: Option<std::time::Instant>,
) -> Result<(Vec<u8>, Vec<OwnedFd>), IpcError> {
    let mut length = [0_u8; LENGTH_PREFIX_LEN];
    let mut first = [0_u8; LENGTH_PREFIX_LEN];
    // nix refuses cmsg iteration on MSG_CTRUNC, but partially delivered rights
    // are already installed in this process and must still be closed.
    // Darwin externalizes all rights before truncating copyout. Its control
    // mbuf is <=2048 bytes (UIPC_MAX_CMSG_FD=512); receive it in full so no
    // installed FD number is hidden from cleanup. Linux closes undisclosed FDs.
    #[cfg(target_vendor = "apple")]
    let mut control_space = [0_usize; 512];
    #[cfg(not(target_vendor = "apple"))]
    let mut control_space = [0_usize; 8];
    let mut iov = nix::libc::iovec {
        iov_base: first.as_mut_ptr().cast(),
        iov_len: first.len(),
    };
    let mut message: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control_space.as_mut_ptr().cast();
    let received = loop {
        apply_read_deadline(stream, deadline)?;
        message.msg_controllen = std::mem::size_of_val(&control_space) as _;
        let count = unsafe { nix::libc::recvmsg(stream.as_raw_fd(), &mut message, 0) };
        if count >= 0 {
            break count as usize;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    };
    let mut descriptors = Vec::new();
    // Kernel-generated cmsgs contain complete descriptor integers even when
    // their list was truncated. Adopt every delivered FD before any rejection.
    unsafe {
        let mut header = nix::libc::CMSG_FIRSTHDR(&message);
        #[allow(clippy::unnecessary_cast)] // libc length types vary across Unix platforms.
        let control_bytes =
            (message.msg_controllen as usize).min(std::mem::size_of_val(&control_space));
        let data_offset = nix::libc::CMSG_LEN(0) as usize;
        while !header.is_null() {
            let offset = header as usize - message.msg_control as usize;
            let available = control_bytes.saturating_sub(offset);
            if available < data_offset {
                break;
            }
            #[allow(clippy::unnecessary_cast)] // Darwin uses socklen_t, Linux uses size_t.
            let declared = (*header).cmsg_len as usize;
            if (*header).cmsg_level == nix::libc::SOL_SOCKET
                && (*header).cmsg_type == nix::libc::SCM_RIGHTS
            {
                let bytes = declared.min(available).saturating_sub(data_offset);
                let data = nix::libc::CMSG_DATA(header).cast::<RawFd>();
                for index in 0..bytes / std::mem::size_of::<RawFd>() {
                    descriptors.push(OwnedFd::from_raw_fd(data.add(index).read_unaligned()));
                }
            }
            if declared < data_offset || declared > available {
                break;
            }
            header = nix::libc::CMSG_NXTHDR(&message, header);
        }
    }
    if message.msg_flags & nix::libc::MSG_CTRUNC != 0 || descriptors.len() > 2 {
        return Err(IpcError::DescriptorMismatch);
    }
    for descriptor in &descriptors {
        fcntl(
            descriptor.as_raw_fd(),
            FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC),
        )?;
    }
    if received == 0 {
        return Err(IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "netd IPC peer closed before frame",
        )));
    }
    length[..received].copy_from_slice(&first[..received]);
    if received < LENGTH_PREFIX_LEN {
        read_exact_until(stream, &mut length[received..], deadline)?;
    }
    let payload_len =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| IpcError::FrameLength)?;
    if payload_len == 0 || payload_len > MAX_NETD_FRAME_LEN {
        return Err(IpcError::FrameLength);
    }
    let mut payload = vec![0_u8; payload_len];
    read_exact_until(stream, &mut payload, deadline)?;
    Ok((payload, descriptors))
}

#[cfg(test)]
mod frame_deadline_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn rejected_frame_closes_received_rights(count: usize, length: u32) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (mut probe, writer) = UnixStream::pair().unwrap();
        probe.set_nonblocking(true).unwrap();
        let rights = vec![writer.as_raw_fd(); count];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&length.to_be_bytes())],
            &[ControlMessage::ScmRights(&rights)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(writer);
        let error = recv_frame_until(&receiver, Some(Instant::now() + Duration::from_millis(100)))
            .unwrap_err();
        if count > 2 {
            assert!(matches!(error, IpcError::DescriptorMismatch));
        } else {
            assert!(matches!(error, IpcError::FrameLength));
        }
        assert_eq!(probe.read(&mut [0]).unwrap(), 0, "received FD leaked");
    }

    #[test]
    fn truncated_rights_are_closed_before_rejecting_frame() {
        rejected_frame_closes_received_rights(32, 1);
    }

    #[test]
    fn invalid_length_closes_received_rights() {
        rejected_frame_closes_received_rights(1, 0);
    }

    #[test]
    fn valid_descriptor_is_close_on_exec() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (_probe, descriptor) = UnixStream::pair().unwrap();
        send_frame(&sender, &[1], Some(descriptor.as_raw_fd())).unwrap();
        let (payload, descriptors) = recv_frame(&receiver).unwrap();
        assert_eq!(payload, [1]);
        assert_eq!(descriptors.len(), 1);
        assert_ne!(
            fcntl(descriptors[0].as_raw_fd(), FcntlArg::F_GETFD).unwrap()
                & FdFlag::FD_CLOEXEC.bits(),
            0
        );
    }

    #[test]
    fn slowly_arriving_header_cannot_renew_total_frame_deadline() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            for byte in [0, 0, 0, 1, 1] {
                if sender.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let started = Instant::now();
        assert!(recv_frame_until(&receiver, Some(started + Duration::from_millis(100))).is_err());
        assert!(started.elapsed() < Duration::from_millis(200));
        drop(receiver);
        writer.join().unwrap();
    }

    #[test]
    fn undrained_socket_has_a_total_response_write_deadline() {
        let (sender, _receiver) = UnixStream::pair().unwrap();
        let size: nix::libc::c_int = 1024;
        assert_eq!(
            unsafe {
                nix::libc::setsockopt(
                    sender.as_raw_fd(),
                    nix::libc::SOL_SOCKET,
                    nix::libc::SO_SNDBUF,
                    (&size as *const nix::libc::c_int).cast(),
                    std::mem::size_of_val(&size) as nix::libc::socklen_t,
                )
            },
            0
        );
        let started = Instant::now();
        assert!(send_frame_until(
            &sender,
            &vec![1; MAX_NETD_FRAME_LEN],
            None,
            Some(started + Duration::from_millis(100))
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_millis(300));
    }
}
