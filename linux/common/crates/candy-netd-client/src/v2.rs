use crate::{recv_frame, send_frame, IpcError};
use candy_netd_proto::v2::{Body, Operation, Request, Response};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

pub fn recv_request(stream: &UnixStream) -> Result<Request, IpcError> {
    let (bytes, descriptors) = recv_frame(stream)?;
    if !descriptors.is_empty() {
        return Err(IpcError::DescriptorMismatch);
    }
    Ok(Request::decode(&bytes)?)
}

/// A total frame deadline bounds partial headers and slowly arriving payloads.
pub fn recv_request_until(
    stream: &UnixStream,
    deadline: std::time::Instant,
) -> Result<Request, IpcError> {
    let (bytes, descriptors) = crate::recv_frame_until(stream, Some(deadline))?;
    if !descriptors.is_empty() {
        return Err(IpcError::DescriptorMismatch);
    }
    Ok(Request::decode(&bytes)?)
}

pub fn send_response(
    stream: &UnixStream,
    response: &Response,
    fd: Option<&OwnedFd>,
) -> Result<(), IpcError> {
    if matches!(response.body, Body::IoFd { .. }) != fd.is_some() {
        return Err(IpcError::DescriptorMismatch);
    }
    send_frame(stream, &response.encode()?, fd.map(AsRawFd::as_raw_fd))
}

pub fn send_response_until(
    stream: &UnixStream,
    response: &Response,
    fd: Option<&OwnedFd>,
    deadline: std::time::Instant,
) -> Result<(), IpcError> {
    if matches!(response.body, Body::IoFd { .. }) != fd.is_some() {
        return Err(IpcError::DescriptorMismatch);
    }
    crate::send_frame_until(
        stream,
        &response.encode()?,
        fd.map(AsRawFd::as_raw_fd),
        Some(deadline),
    )
}

/// No local phase cache: callers reconcile the durable server state after ambiguous replies.
pub struct InfrastructureClient {
    socket: PathBuf,
    instance_id: [u8; 16],
    next_request_id: u64,
}

impl InfrastructureClient {
    pub fn new(socket: impl Into<PathBuf>, instance_id: [u8; 16]) -> Self {
        Self {
            socket: socket.into(),
            instance_id,
            next_request_id: 1,
        }
    }

    pub fn exchange(&mut self, operation: Operation) -> Result<(Body, Option<OwnedFd>), IpcError> {
        let request_id = self.next_request_id;
        self.next_request_id = request_id
            .checked_add(1)
            .ok_or(IpcError::RequestIdExhausted)?;
        let request = Request {
            request_id,
            caller_instance_id: self.instance_id,
            caller_pid: std::process::id(),
            operation,
        };
        let stream = UnixStream::connect(&self.socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        send_frame(&stream, &request.encode()?, None)?;
        let (bytes, mut descriptors) = recv_frame(&stream)?;
        let response = Response::decode(&bytes)?;
        if response.request_id != request_id {
            return Err(IpcError::UnexpectedResponse);
        }
        let attached = matches!(response.body, Body::IoFd { .. });
        if descriptors.len() != usize::from(attached) {
            return Err(IpcError::DescriptorMismatch);
        }
        Ok((response.body, descriptors.pop()))
    }

    pub fn exchange_in_domain(
        &mut self,
        domain_id: [u8; 16],
        infra_id: [u8; 16],
        operation: Operation,
    ) -> Result<(Body, Option<OwnedFd>), IpcError> {
        self.exchange(Operation::InDomain {
            domain_id,
            infra_id,
            operation: Box::new(operation),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_two_ipc_rejects_request_descriptors() {
        let (a, b) = UnixStream::pair().unwrap();
        let request = Request {
            request_id: 1,
            caller_instance_id: [1; 16],
            caller_pid: 1,
            operation: Operation::Capabilities,
        };
        send_frame(&a, &request.encode().unwrap(), Some(a.as_raw_fd())).unwrap();
        assert!(matches!(
            recv_request(&b),
            Err(IpcError::DescriptorMismatch)
        ));
    }

    #[test]
    fn version_two_ipc_preserves_request_and_response() {
        let (a, b) = UnixStream::pair().unwrap();
        let request = Request {
            request_id: 1,
            caller_instance_id: [1; 16],
            caller_pid: 1,
            operation: Operation::Capabilities,
        };
        send_frame(&a, &request.encode().unwrap(), None).unwrap();
        assert_eq!(recv_request(&b).unwrap(), request);
        let response = Response {
            request_id: 1,
            body: Body::Capabilities {
                version: 2,
                independent_infrastructure: true,
                multi_domain: false,
            },
        };
        send_response(&b, &response, None).unwrap();
        let (bytes, fds) = recv_frame(&a).unwrap();
        assert!(fds.is_empty());
        assert_eq!(Response::decode(&bytes).unwrap(), response);
    }
}
