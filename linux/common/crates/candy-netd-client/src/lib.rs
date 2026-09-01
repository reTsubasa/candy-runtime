#![cfg(unix)]

use candy_netd_proto::{
    ErrorCode, LeaseOwner, NetdOperation, NetdProtocolError, NetdRequest, NetdResponse,
    PrepareDeclaration, ResponseBody, SessionPhase, MAX_NETD_FRAME_LEN,
};
use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use thiserror::Error;

const LENGTH_PREFIX_LEN: usize = 4;

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
        if self.phase != ClientPhase::Suspended {
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
        let mut stream = stream;
        if sent < LENGTH_PREFIX_LEN {
            stream.write_all(&length[sent..])?;
            stream.write_all(payload)?;
        } else {
            stream.write_all(&payload[sent - LENGTH_PREFIX_LEN..])?;
        }
    }
    Ok(())
}

fn recv_frame(stream: &UnixStream) -> Result<(Vec<u8>, Vec<OwnedFd>), IpcError> {
    let mut length = [0_u8; LENGTH_PREFIX_LEN];
    let mut first = [0_u8; LENGTH_PREFIX_LEN];
    let mut slices = [IoSliceMut::new(&mut first)];
    let mut control_space = nix::cmsg_space!([RawFd; 2]);
    let message = loop {
        match recvmsg::<()>(
            stream.as_raw_fd(),
            &mut slices,
            Some(&mut control_space),
            MsgFlags::empty(),
        ) {
            Err(Errno::EINTR) => continue,
            result => break result?,
        }
    };
    if message.bytes == 0 {
        return Err(IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "netd IPC peer closed before frame",
        )));
    }
    if message.flags.contains(MsgFlags::MSG_CTRUNC) {
        return Err(IpcError::DescriptorMismatch);
    }
    let received = message.bytes;
    let mut descriptors = Vec::new();
    for control in message.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = control {
            for fd in fds {
                fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
                // SCM_RIGHTS creates a new descriptor owned by this process.
                descriptors.push(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    length[..received].copy_from_slice(&first[..received]);
    if received < LENGTH_PREFIX_LEN {
        let mut stream = stream;
        stream.read_exact(&mut length[received..])?;
    }
    let payload_len =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| IpcError::FrameLength)?;
    if payload_len == 0 || payload_len > MAX_NETD_FRAME_LEN {
        return Err(IpcError::FrameLength);
    }
    let mut payload = vec![0_u8; payload_len];
    let mut stream = stream;
    stream.read_exact(&mut payload)?;
    Ok((payload, descriptors))
}
