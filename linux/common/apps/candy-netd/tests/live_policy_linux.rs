#![cfg(target_os = "linux")]

use candy_netd::v2::{InfrastructureJournal, InfrastructureService};
use candy_netd::{LinuxNetworkBackend, PeerCredentials, SystemTunFactory};
use candy_netd_proto::v2::{Body, ForwardOwner, InfraSpec, Operation, Phase, Request};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, PrepareDeclaration, RouteDeclaration, RouteKind, UnderlayExclusion,
    UnderlayKind,
};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;

fn output(program: &str, args: &[&str]) -> String {
    let result = Command::new(program).args(args).output().unwrap();
    assert!(
        result.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

#[test]
#[ignore = "requires an isolated root Linux network namespace, TUN, iproute2 and nftables"]
fn real_live_policy_updates_routes_nft_without_changing_tun_or_owner() {
    let path = std::env::temp_dir().join(format!("candy-live-policy-linux-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut service = InfrastructureService::new(
        0,
        0,
        SystemTunFactory,
        LinuxNetworkBackend::new().unwrap(),
        InfrastructureJournal::new(path.join("infra.journal")).unwrap(),
    )
    .unwrap();
    let mut call = |operation, now| {
        service
            .process(
                Request {
                    request_id: now,
                    caller_instance_id: [1; 16],
                    caller_pid: std::process::id(),
                    operation,
                },
                PeerCredentials {
                    pid: std::process::id(),
                    uid: 0,
                    gid: 0,
                },
                now,
            )
            .unwrap()
            .0
    };
    let namespace = fs::metadata("/proc/self/ns/net").unwrap();
    call(
        Operation::InfraEnsure(InfraSpec {
            infra_id: [2; 16],
            generation: 1,
            netns_device: namespace.dev(),
            netns_inode: namespace.ino(),
            overlay_router_ipv4: [100, 64, 0, 10],
            mtu: 1398,
        }),
        1,
    );
    let owner = ForwardOwner {
        domain_id: [3; 16],
        signed_generation: 10,
        worker_epoch: 4,
        fencing_token: 8,
        auth_deadline_mono_ms: 2000,
        lease_deadline_mono_ms: 1000,
    };
    let mut declaration = PrepareDeclaration {
        table_id: 20000,
        overlay_router_ipv4: [100, 64, 0, 10],
        effective_mtu: 1398,
        routes: vec![
            RouteDeclaration {
                prefix: Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap(),
                kind: RouteKind::Remote,
            },
            RouteDeclaration {
                prefix: Ipv4Prefix::new([172, 31, 254, 0], 24).unwrap(),
                kind: RouteKind::Local,
            },
        ],
        exclusions: vec![UnderlayExclusion {
            prefix: Ipv4Prefix::new([192, 0, 2, 1], 32).unwrap(),
            kind: UnderlayKind::CloudApi,
        }],
        firewall: FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    };
    call(
        Operation::ForwardPrepare {
            infra_id: [2; 16],
            infra_generation: 1,
            owner: owner.clone(),
            declaration: declaration.clone(),
        },
        2,
    );
    call(
        Operation::ForwardCommit {
            owner: owner.clone(),
        },
        3,
    );
    let physical = output("ip", &["-j", "-d", "link", "show", "dev", "candy0"]);
    let addresses = output("ip", &["-j", "address", "show", "dev", "candy0"]);
    let policy = |revision, generation, declaration| Operation::ForwardPolicyUpdate {
        owner: owner.clone(),
        policy_revision: revision,
        policy_generation: generation,
        authorization_snapshot_sha256: "a".repeat(64),
        declaration,
    };
    for revision in 1..=20 {
        declaration.routes[0].prefix =
            Ipv4Prefix::new([10, if revision % 2 == 0 { 2 } else { 3 }, 0, 0], 16).unwrap();
        // Exercise a changing derived nft source set as well as destination routes.
        declaration.routes[1].prefix =
            Ipv4Prefix::new([172, 31, if revision % 2 == 0 { 254 } else { 253 }, 0], 24).unwrap();
        call(
            policy(revision, 10 + revision, declaration.clone()),
            4 + revision,
        );
        assert_eq!(
            output("ip", &["-j", "-d", "link", "show", "dev", "candy0"]),
            physical
        );
        assert_eq!(
            output("ip", &["-j", "address", "show", "dev", "candy0"]),
            addresses
        );
        let routes = output("ip", &["-4", "route", "show", "table", "20000"]);
        let expected = if revision % 2 == 0 {
            "10.2.0.0/16 dev candy0"
        } else {
            "10.3.0.0/16 dev candy0"
        };
        let stale = if revision % 2 == 0 {
            "10.3.0.0/16"
        } else {
            "10.2.0.0/16"
        };
        assert!(routes.contains(expected), "{routes}");
        assert!(!routes.contains(stale), "{routes}");
        let nft = output("nft", &["list", "table", "inet", "candy_sdwan_20000"]);
        let local = if revision % 2 == 0 {
            "0xac1ffe00"
        } else {
            "0xac1ffd00"
        };
        assert!(nft.contains(local), "{nft}");
        assert!(
            matches!(call(Operation::ForwardStatus,30+revision),Body::ForwardStatus {
            owner:Some(ref current),phase:Some(Phase::Active),active_policy_revision:r,pending_policy_revision:None,..}
            if *current==owner && r==revision)
        );
    }
    // Force the real backend to fail after publishing target routes: atomic
    // nft replacement refuses a missing/foreign table. Expiry must cancel this
    // durable intent, remove its new routes/selectors, and never replay it.
    output("nft", &["delete", "table", "inet", "candy_sdwan_20000"]);
    declaration.routes[0].prefix = Ipv4Prefix::new([10, 9, 0, 0], 16).unwrap();
    declaration.routes[1].prefix = Ipv4Prefix::new([172, 31, 252, 0], 24).unwrap();
    let pending_operation = policy(21, 31, declaration);
    let request = |operation, now| Request {
        request_id: now,
        caller_instance_id: [1; 16],
        caller_pid: std::process::id(),
        operation,
    };
    let credentials = || PeerCredentials {
        pid: std::process::id(),
        uid: 0,
        gid: 0,
    };
    assert!(service
        .process(request(pending_operation, 61), credentials(), 61)
        .is_err());
    let partial = output("ip", &["-4", "route", "show", "table", "20000"]);
    assert!(partial.contains("10.9.0.0/16 dev candy0"), "{partial}");
    assert!(matches!(
        service
            .process(request(Operation::ForwardStatus, 1001), credentials(), 1001)
            .unwrap()
            .0,
        Body::ForwardStatus {
            phase: Some(Phase::Revoked),
            pending_policy_revision: None,
            ..
        }
    ));
    let cancelled = output("ip", &["-4", "route", "show", "table", "20000"]);
    assert!(!cancelled.contains("10.9.0.0/16"), "{cancelled}");
    assert!(cancelled.contains("unreachable 10.2.0.0/16"), "{cancelled}");
    let rules = output("ip", &["-4", "rule", "show"]);
    assert!(
        !rules
            .lines()
            .any(|line| line.contains("lookup 20000") && line.contains("10.9.0.0/16")),
        "{rules}"
    );
    assert_eq!(
        output("ip", &["-j", "-d", "link", "show", "dev", "candy0"]),
        physical
    );
    let _ = fs::remove_dir_all(path);
}
