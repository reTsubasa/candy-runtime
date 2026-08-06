use candy_netd::{
    NetdService, NetworkController, NetworkError, PeerCredentials, PlatformError, TunFactory,
};
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

struct ShutdownNetwork {
    owner: Option<LeaseOwner>,
    rollbacks: Arc<AtomicUsize>,
}

impl NetworkController for ShutdownNetwork {
    fn prepare(
        &mut self,
        _owner: LeaseOwner,
        _declaration: PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        Ok(())
    }

    fn commit(&mut self, _owner: LeaseOwner) -> Result<(), NetworkError> {
        Ok(())
    }

    fn rollback(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        assert_eq!(self.owner, Some(owner));
        self.rollbacks.fetch_add(1, Ordering::SeqCst);
        self.owner = None;
        Ok(())
    }

    fn renew_lease(&mut self, _owner: LeaseOwner) -> Result<(), NetworkError> {
        Ok(())
    }

    fn update_mtu(&mut self, _owner: LeaseOwner, _effective_mtu: u16) -> Result<(), NetworkError> {
        Ok(())
    }

    fn recover_orphan(
        &mut self,
        _owner_is_alive: bool,
        _now_mono_ms: u64,
    ) -> Result<bool, NetworkError> {
        Ok(false)
    }

    fn retained_owner(&self) -> Option<LeaseOwner> {
        self.owner
    }
}

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

fn exchange<N: NetworkController>(
    service: &mut NetdService<FakeTunFactory, N>,
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
    let mut service = NetdService::with_network(
        1000,
        1001,
        FakeTunFactory(creates.clone()),
        ShutdownNetwork {
            owner: None,
            rollbacks: Arc::new(AtomicUsize::new(0)),
        },
    );
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
    let mut service = NetdService::with_network(
        1000,
        1001,
        FakeTunFactory(creates.clone()),
        ShutdownNetwork {
            owner: None,
            rollbacks: Arc::new(AtomicUsize::new(0)),
        },
    );
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

#[test]
fn shutdown_rolls_back_the_retained_network_owner() {
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let network = ShutdownNetwork {
        owner: Some(owner()),
        rollbacks: Arc::clone(&rollbacks),
    };
    let mut service = NetdService::with_network(
        1000,
        1001,
        FakeTunFactory(Arc::new(AtomicUsize::new(0))),
        network,
    );

    assert!(service.shutdown().unwrap());
    assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
    assert!(!service.shutdown().unwrap());
    assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
}
