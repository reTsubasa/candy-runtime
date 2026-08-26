#![cfg(target_os = "linux")]

use candy_netd::{create_candy_tun, FileNetworkJournal, LinuxNetworkBackend, NetworkTransaction};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, LeaseOwner, PrepareDeclaration, RouteDeclaration, RouteKind,
    UnderlayExclusion, UnderlayKind, CANDY_TABLE_MAX,
};
use std::fs;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

struct NamespaceFixture;

impl Drop for NamespaceFixture {
    fn drop(&mut self) {
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", "candy_test_docker"])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "delete", "candy-test-ns"])
            .status();
        let _ = Command::new("ip")
            .args(["link", "delete", "candy-test-br"])
            .status();
    }
}

fn run(command: &str, args: &[&str]) {
    let output = Command::new(command).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{command} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn install_docker_style_source_namespace() -> NamespaceFixture {
    let fixture = NamespaceFixture;
    run("ip", &["link", "add", "candy-test-br", "type", "bridge"]);
    run(
        "ip",
        &["addr", "add", "172.31.254.1/24", "dev", "candy-test-br"],
    );
    run("ip", &["link", "set", "candy-test-br", "up"]);
    run("ip", &["netns", "add", "candy-test-ns"]);
    run(
        "ip",
        &[
            "link",
            "add",
            "candy-test-vh",
            "type",
            "veth",
            "peer",
            "name",
            "candy-test-vn",
        ],
    );
    run(
        "ip",
        &["link", "set", "candy-test-vh", "master", "candy-test-br"],
    );
    run("ip", &["link", "set", "candy-test-vh", "up"]);
    run(
        "ip",
        &["link", "set", "candy-test-vn", "netns", "candy-test-ns"],
    );
    run(
        "ip",
        &[
            "-n",
            "candy-test-ns",
            "addr",
            "add",
            "172.31.254.2/24",
            "dev",
            "candy-test-vn",
        ],
    );
    run(
        "ip",
        &["-n", "candy-test-ns", "link", "set", "candy-test-vn", "up"],
    );
    run("ip", &["-n", "candy-test-ns", "link", "set", "lo", "up"]);
    run(
        "ip",
        &[
            "-n",
            "candy-test-ns",
            "route",
            "add",
            "default",
            "via",
            "172.31.254.1",
        ],
    );
    run("nft", &["add", "table", "ip", "candy_test_docker"]);
    run(
        "nft",
        &[
            "add",
            "chain",
            "ip",
            "candy_test_docker",
            "postrouting",
            "{ type nat hook postrouting priority srcnat; policy accept; }",
        ],
    );
    run(
        "nft",
        &[
            "add",
            "rule",
            "ip",
            "candy_test_docker",
            "postrouting",
            "ip saddr 172.31.254.0/24 oifname != \"candy-test-br\" masquerade",
        ],
    );
    fixture
}

fn read_ipv4_source(tun: RawFd) -> [u8; 4] {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut packet = [0_u8; 2048];
    loop {
        match nix::unistd::read(tun, &mut packet) {
            Ok(length) if length >= 20 && packet[0] >> 4 == 4 => {
                return packet[12..16].try_into().unwrap();
            }
            Ok(_) | Err(nix::errno::Errno::EAGAIN) => {}
            Err(error) => panic!("read candy0 packet failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "no IPv4 packet arrived on candy0"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

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
            RouteDeclaration {
                prefix: Ipv4Prefix::new([172, 31, 254, 0], 24).unwrap(),
                kind: RouteKind::Local,
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
    assert!(
        ruleset.contains("oifname \"candy0\"")
            && ruleset.contains("@nh,96,32 & 0xffffff00 == 0xac1ffe00")
            && ruleset.contains("snat ip to @nh,96,32"),
        "identity-SNAT rule is missing: {ruleset}"
    );

    let namespace = install_docker_style_source_namespace();
    let mut ping = Command::new("ip")
        .args([
            "netns",
            "exec",
            "candy-test-ns",
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "10.255.253.1",
        ])
        .spawn()
        .expect("start namespace ping");
    assert_eq!(
        read_ipv4_source(tun.as_raw_fd()),
        [172, 31, 254, 2],
        "Docker-style masquerade changed a signed local source before candy0"
    );
    let _ = ping.kill();
    let _ = ping.wait();
    drop(namespace);

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
    assert!(owned
        .iter()
        .all(|line| line.contains("from 172.31.254.0/24")));
    assert!(owned.iter().all(|line| !line.contains(" none ")));
    for destination in ["10.255.253.1", "10.255.254.1"] {
        let output = Command::new("ip")
            .args(["-4", "route", "get", destination, "from", "172.31.254.2"])
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

        let output = Command::new("ip")
            .args(["-4", "route", "get", destination])
            .output()
            .unwrap();
        assert!(output.status.success());
        let route = String::from_utf8(output.stdout).unwrap();
        assert!(
            !route.contains("table 20999"),
            "router-originated traffic entered the client TUN: {route}"
        );
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

    let output = Command::new("nft")
        .args(["list", "table", "inet", "candy_sdwan_20999"])
        .output()
        .expect("execute post-rollback nft table lookup");
    assert!(
        !output.status.success(),
        "owned nft table survived rollback"
    );

    assert!(!state.join("netd.journal").exists());
    fs::remove_dir_all(state).unwrap();
}
