use crate::{receive_descriptor_frame_until, send_descriptor_frame_until, IpcError};
use candy_netd_proto::{LeaseOwner, NetdOperation, NetdRequest, NetdResponse, ResponseBody};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    V1,
    V2,
}

/// Prove the configured protocol responds without acquiring resources or leases.
pub fn socket(path: &Path, protocol: Protocol, timeout: Duration) -> Result<(), IpcError> {
    let deadline = Instant::now() + timeout;
    let stream = UnixStream::connect(path)?;
    exchange(&stream, protocol, deadline)
}

fn exchange(stream: &UnixStream, protocol: Protocol, deadline: Instant) -> Result<(), IpcError> {
    let request_id = 1;
    let instance = *b"candy-netd-probe";
    let payload = match protocol {
        Protocol::V1 => NetdRequest {
            request_id,
            owner: LeaseOwner {
                instance_id: instance,
                pid: std::process::id(),
                generation: 1,
                lease_deadline_mono_ms: 1,
            },
            operation: NetdOperation::Status,
        }
        .encode()?,
        Protocol::V2 => candy_netd_proto::v2::Request {
            request_id,
            caller_instance_id: instance,
            caller_pid: std::process::id(),
            operation: candy_netd_proto::v2::Operation::Capabilities,
        }
        .encode()?,
    };
    send_descriptor_frame_until(stream, &payload, None, deadline)?;
    let (payload, descriptors) = receive_descriptor_frame_until(stream, deadline)?;
    if !descriptors.is_empty() {
        return Err(IpcError::DescriptorMismatch);
    }
    let valid = match protocol {
        Protocol::V1 => {
            let response = NetdResponse::decode(&payload)?;
            response.request_id == request_id
                && matches!(response.body, ResponseBody::Status { generation: 1, .. })
        }
        Protocol::V2 => {
            let response = candy_netd_proto::v2::Response::decode(&payload)?;
            response.request_id == request_id
                && matches!(
                    response.body,
                    candy_netd_proto::v2::Body::Capabilities {
                        version: 2,
                        independent_infrastructure: true,
                        ..
                    }
                )
        }
    };
    if !valid {
        return Err(IpcError::UnexpectedResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use candy_netd_proto::v2::{Body, Operation, Response};

    fn v2_response(response: Response) -> Result<(), IpcError> {
        let (client, server) = UnixStream::pair().unwrap();
        let (done, wait_done) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            let request = crate::v2::recv_request(&server).unwrap();
            assert_eq!(request.operation, Operation::Capabilities);
            assert_ne!(request.caller_instance_id, [0; 16]);
            assert_eq!(request.caller_pid, std::process::id());
            crate::v2::send_response(&server, &response, None).unwrap();
            // Darwin rejects SO_RCVTIMEO changes after the peer endpoint is closed.
            wait_done.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        let result = exchange(
            &client,
            Protocol::V2,
            Instant::now() + Duration::from_secs(1),
        );
        done.send(()).unwrap();
        task.join().unwrap();
        result
    }

    fn capabilities() -> Body {
        Body::Capabilities {
            version: 2,
            independent_infrastructure: true,
            multi_domain: false,
        }
    }

    #[test]
    fn v2_probe_requires_matching_capabilities() {
        assert!(v2_response(Response {
            request_id: 1,
            body: capabilities()
        })
        .is_ok());
        assert!(v2_response(Response {
            request_id: 2,
            body: capabilities()
        })
        .is_err());
        assert!(v2_response(Response {
            request_id: 1,
            body: Body::Ack
        })
        .is_err());
        assert!(v2_response(Response {
            request_id: 1,
            body: Body::Capabilities {
                version: 2,
                independent_infrastructure: false,
                multi_domain: false
            }
        })
        .is_err());
    }

    #[test]
    fn v1_probe_sends_read_only_status() {
        let (client, server) = UnixStream::pair().unwrap();
        let (done, wait_done) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            let request = crate::recv_request(&server).unwrap();
            assert_eq!(request.operation, NetdOperation::Status);
            crate::send_response(
                &server,
                &NetdResponse {
                    request_id: request.request_id,
                    body: ResponseBody::Status {
                        phase: candy_netd_proto::SessionPhase::Active,
                        generation: request.owner.generation,
                    },
                },
                None,
            )
            .unwrap();
            wait_done.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        let result = exchange(
            &client,
            Protocol::V1,
            Instant::now() + Duration::from_secs(1),
        );
        done.send(()).unwrap();
        task.join().unwrap();
        result.unwrap();
    }

    #[test]
    fn stalled_probe_obeys_total_deadline() {
        let (client, _server) = UnixStream::pair().unwrap();
        let start = Instant::now();
        assert!(exchange(&client, Protocol::V2, start + Duration::from_millis(30)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
