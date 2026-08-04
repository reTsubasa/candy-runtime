use candy_netd_client::{recv_request, send_response, IpcError, NetdClient};
use candy_netd_proto::{
    ErrorCode, FirewallPolicy, Ipv4Prefix, LeaseOwner, NetdOperation, NetdResponse,
    PrepareDeclaration, ResponseBody, RouteDeclaration, RouteKind, UnderlayExclusion, UnderlayKind,
    CANDY_TABLE_MIN,
};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

fn socket_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/cnd-{name}-{}.sock", std::process::id()))
}

fn owner() -> LeaseOwner {
    LeaseOwner {
        instance_id: [1; 16],
        pid: std::process::id(),
        generation: 7,
        lease_deadline_mono_ms: 50_000,
    }
}

fn declaration() -> PrepareDeclaration {
    PrepareDeclaration {
        table_id: CANDY_TABLE_MIN,
        overlay_router_ipv4: [100, 64, 0, 10],
        effective_mtu: 1180,
        routes: vec![RouteDeclaration {
            prefix: Ipv4Prefix::new([10, 1, 0, 0], 16).unwrap(),
            kind: RouteKind::Local,
        }],
        exclusions: vec![UnderlayExclusion {
            prefix: Ipv4Prefix::new([192, 0, 2, 10], 32).unwrap(),
            kind: UnderlayKind::CloudApi,
        }],
        firewall: FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    }
}

#[test]
fn transaction_requires_exact_responses_and_preserves_lifecycle_order() {
    let path = socket_path("lifecycle");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        for expected in 1..=5 {
            let (stream, _) = listener.accept().unwrap();
            let request = recv_request(&stream).unwrap();
            assert_eq!(request.request_id, expected);
            let (body, descriptor) = match request.operation {
                NetdOperation::Prepare(_) => (
                    ResponseBody::Prepared {
                        generation: 7,
                        tun_fd_attached: true,
                    },
                    Some(File::open("/dev/null").unwrap()),
                ),
                NetdOperation::Commit => (ResponseBody::Committed { generation: 7 }, None),
                NetdOperation::LeaseRenew => {
                    assert_eq!(request.owner.lease_deadline_mono_ms, 60_000);
                    (ResponseBody::LeaseRenewed { generation: 7 }, None)
                }
                NetdOperation::MtuUpdate { effective_mtu } => {
                    assert_eq!(effective_mtu, 1100);
                    (
                        ResponseBody::MtuUpdated {
                            generation: 7,
                            effective_mtu,
                        },
                        None,
                    )
                }
                NetdOperation::Rollback => (ResponseBody::RolledBack { generation: 7 }, None),
                NetdOperation::Status => panic!("unexpected status"),
            };
            let response = NetdResponse {
                request_id: request.request_id,
                body,
            };
            send_response(
                &stream,
                &response,
                descriptor.as_ref().map(AsRawFd::as_raw_fd),
            )
            .unwrap();
        }
    });

    let mut client = NetdClient::new(&path, owner());
    assert!(matches!(client.commit(), Err(IpcError::InvalidTransition)));
    let prepared = client.prepare(declaration()).unwrap();
    assert_eq!(prepared.generation, 7);
    assert!(matches!(
        client.prepare(declaration()),
        Err(IpcError::InvalidTransition)
    ));
    assert_eq!(client.commit().unwrap(), 7);
    assert_eq!(client.renew_lease(60_000).unwrap(), 7);
    assert_eq!(client.update_mtu(1100).unwrap(), 1100);
    assert_eq!(client.rollback().unwrap(), 7);
    assert!(matches!(
        client.rollback(),
        Err(IpcError::InvalidTransition)
    ));
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn remote_rejection_does_not_advance_the_local_phase() {
    let path = socket_path("rejection");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            let request = recv_request(&stream).unwrap();
            send_response(
                &stream,
                &NetdResponse {
                    request_id: request.request_id,
                    body: ResponseBody::Error(ErrorCode::PreflightFailed),
                },
                None,
            )
            .unwrap();
        }
    });

    let mut client = NetdClient::new(&path, owner());
    for _ in 0..2 {
        assert!(matches!(
            client.prepare(declaration()),
            Err(IpcError::Remote(ErrorCode::PreflightFailed))
        ));
    }
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn dropping_a_prepared_transaction_requests_rollback() {
    let path = socket_path("drop");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let prepare = recv_request(&stream).unwrap();
        let descriptor = File::open("/dev/null").unwrap();
        send_response(
            &stream,
            &NetdResponse {
                request_id: prepare.request_id,
                body: ResponseBody::Prepared {
                    generation: 7,
                    tun_fd_attached: true,
                },
            },
            Some(descriptor.as_raw_fd()),
        )
        .unwrap();

        let (stream, _) = listener.accept().unwrap();
        let rollback = recv_request(&stream).unwrap();
        assert!(matches!(rollback.operation, NetdOperation::Rollback));
        send_response(
            &stream,
            &NetdResponse {
                request_id: rollback.request_id,
                body: ResponseBody::RolledBack { generation: 7 },
            },
            None,
        )
        .unwrap();
    });

    {
        let mut client = NetdClient::new(&path, owner());
        let _prepared = client.prepare(declaration()).unwrap();
    }
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}
