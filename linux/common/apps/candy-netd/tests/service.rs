use candy_netd::{NetdService, PeerCredentials, PlatformError, TunFactory};
use candy_netd_client::{recv_response, send_request};
use candy_netd_proto::{
    ErrorCode, FirewallPolicy, Ipv4Prefix, LeaseOwner, NetdOperation, NetdRequest,
    PrepareDeclaration, ResponseBody, RouteDeclaration, RouteKind, UnderlayExclusion, UnderlayKind,
    CANDY_TABLE_MIN,
};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct FakeTunFactory(Arc<AtomicUsize>);

impl TunFactory for FakeTunFactory {
    fn create(&mut self) -> Result<OwnedFd, PlatformError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(File::open("/dev/null").unwrap().into())
    }
}

fn owner() -> LeaseOwner {
    LeaseOwner {
        instance_id: [1; 16],
        pid: 4242,
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

fn exchange(
    service: &mut NetdService<FakeTunFactory>,
    request: &NetdRequest,
    peer: PeerCredentials,
) -> (ResponseBody, bool) {
    let (server, client) = UnixStream::pair().unwrap();
    send_request(&client, request).unwrap();
    service.serve_authenticated_once(&server, peer).unwrap();
    let (response, descriptor) = recv_response(&client).unwrap();
    assert_eq!(response.request_id, request.request_id);
    (response.body, descriptor.is_some())
}

#[test]
fn authenticated_owner_runs_two_phase_lifecycle_and_gets_one_tun_fd() {
    let creates = Arc::new(AtomicUsize::new(0));
    let mut service = NetdService::new(1000, 1001, FakeTunFactory(creates.clone()));
    let peer = PeerCredentials {
        pid: 4242,
        uid: 1000,
        gid: 1001,
    };
    let prepare = NetdRequest {
        request_id: 1,
        owner: owner(),
        operation: NetdOperation::Prepare(declaration()),
    };
    assert_eq!(
        exchange(&mut service, &prepare, peer),
        (
            ResponseBody::Prepared {
                generation: 7,
                tun_fd_attached: true
            },
            true
        )
    );
    assert_eq!(creates.load(Ordering::SeqCst), 1);

    let commit = NetdRequest {
        request_id: 2,
        owner: owner(),
        operation: NetdOperation::Commit,
    };
    assert_eq!(
        exchange(&mut service, &commit, peer),
        (ResponseBody::Committed { generation: 7 }, false)
    );
}

#[test]
fn peer_identity_must_match_configuration_and_request_owner() {
    let creates = Arc::new(AtomicUsize::new(0));
    let mut service = NetdService::new(1000, 1001, FakeTunFactory(creates.clone()));
    let request = NetdRequest {
        request_id: 3,
        owner: owner(),
        operation: NetdOperation::Prepare(declaration()),
    };
    let unauthorized = PeerCredentials {
        pid: 9,
        uid: 1000,
        gid: 1001,
    };
    assert_eq!(
        exchange(&mut service, &request, unauthorized),
        (ResponseBody::Error(ErrorCode::UnauthorizedPeer), false)
    );
    assert_eq!(creates.load(Ordering::SeqCst), 0);
}
