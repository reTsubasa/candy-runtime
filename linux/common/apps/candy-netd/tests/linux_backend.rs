#![cfg(target_os = "linux")]

use candy_netd::{create_candy_tun, FileNetworkJournal, LinuxNetworkBackend, NetworkTransaction};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, LeaseOwner, PrepareDeclaration, RouteDeclaration, RouteKind,
    UnderlayExclusion, UnderlayKind, CANDY_TABLE_MAX,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
#[ignore = "requires an isolated Linux network namespace with CAP_NET_ADMIN"]
fn real_linux_backend_prepares_commits_and_rolls_back() {
    let state =
        std::env::temp_dir().join(format!("candy-netd-linux-backend-{}", std::process::id()));
    let _ = fs::remove_dir_all(&state);
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();

    let tun = create_candy_tun().unwrap();
    let owner = LeaseOwner {
        instance_id: [9; 16],
        pid: std::process::id(),
        generation: 1,
        lease_deadline_mono_ms: u64::MAX - 1,
    };
    let declaration = PrepareDeclaration {
        table_id: CANDY_TABLE_MAX,
        overlay_router_ipv4: [100, 127, 255, 254],
        effective_mtu: 1180,
        routes: vec![
            RouteDeclaration {
                prefix: Ipv4Prefix::new([10, 255, 253, 0], 24).unwrap(),
                kind: RouteKind::Remote,
            },
            RouteDeclaration {
                prefix: Ipv4Prefix::new([10, 255, 254, 0], 24).unwrap(),
                kind: RouteKind::Remote,
            },
        ],
        exclusions: vec![UnderlayExclusion {
            prefix: Ipv4Prefix::new([192, 0, 2, 254], 32).unwrap(),
            kind: UnderlayKind::Management,
        }],
        firewall: FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    };
    let backend = LinuxNetworkBackend::new().unwrap();
    let journal = FileNetworkJournal::new(state.join("netd.journal")).unwrap();
    let mut transaction = NetworkTransaction::new(backend, journal).unwrap();
    transaction.prepare(owner, declaration).unwrap();
    transaction.commit(owner).unwrap();
    let output = Command::new("ip")
        .args(["-4", "route", "show", "table", "20999"])
        .output()
        .expect("execute ip route show");
    assert!(
        output.status.success(),
        "route table lookup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let routes = String::from_utf8(output.stdout).unwrap();
    assert!(routes.contains("10.255.253.0/24 dev candy0"));
    assert!(routes.contains("10.255.254.0/24 dev candy0"));
    assert!(routes.contains("throw 192.0.2.254"));

    let output = Command::new("nft")
        .args(["list", "table", "inet", "candy_sdwan_20999"])
        .output()
        .expect("execute nft list table");
    assert!(
        output.status.success(),
        "nft table lookup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ruleset = String::from_utf8(output.stdout).unwrap();
    assert!(ruleset.contains("candy_sdwan_20999"));
    assert!(ruleset.contains("tcp option maxseg size set rt mtu"));

    let output = Command::new("ip")
        .args(["-4", "rule", "show"])
        .output()
        .expect("execute ip rule show");
    assert!(
        output.status.success(),
        "policy rule lookup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rules = String::from_utf8(output.stdout).unwrap();
    let owned = rules
        .lines()
        .filter(|line| line.contains("lookup 20999"))
        .collect::<Vec<_>>();
    assert_eq!(owned.len(), 2);
    assert!(owned.iter().any(|line| line.contains("to 10.255.253.0/24")));
    assert!(owned.iter().any(|line| line.contains("to 10.255.254.0/24")));
    assert!(owned.iter().all(|line| !line.contains(" none ")));
    for destination in ["10.255.253.1", "10.255.254.1"] {
        let output = Command::new("ip")
            .args(["-4", "route", "get", destination])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "route lookup for {destination} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let route = String::from_utf8(output.stdout).unwrap();
        assert!(route.contains("dev candy0"), "unexpected route: {route}");
        assert!(route.contains("table 20999"), "unexpected route: {route}");
    }
    if let Ok(output) = Command::new("ip")
        .args(["-details", "-4", "rule", "show"])
        .output()
    {
        if output.status.success() {
            let rules = String::from_utf8(output.stdout).unwrap();
            for rule in rules.lines().filter(|line| line.contains("lookup 20999")) {
                assert!(
                    !rule.contains(" none "),
                    "policy rule has no action: {rule}"
                );
            }
        }
    }
    transaction.rollback(owner).unwrap();
    drop(tun);

    let output = Command::new("ip")
        .args(["-4", "rule", "show"])
        .output()
        .expect("execute post-rollback ip rule show");
    assert!(
        output.status.success(),
        "post-rollback policy rule lookup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rules = String::from_utf8(output.stdout).unwrap();
    assert!(!rules.lines().any(|line| line.contains("lookup 20999")));

    assert!(!state.join("netd.journal").exists());
    fs::remove_dir_all(state).unwrap();
}
