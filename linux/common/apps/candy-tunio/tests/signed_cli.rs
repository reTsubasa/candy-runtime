#![cfg(target_os = "linux")]
use candy_netd_client::v2::InfrastructureClient;
use candy_netd_proto::v2::{Body, InfraSpec, Operation};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, PrepareDeclaration, RouteDeclaration, RouteKind, UnderlayExclusion,
    UnderlayKind,
};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct FailedStateEvidence(PathBuf);
impl Drop for FailedStateEvidence {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") else {
            return;
        };
        let destination =
            PathBuf::from(destination).join(format!("failed-state-{}", std::process::id()));
        let _ = fs::create_dir_all(&destination);
        let Ok(entries) = fs::read_dir(&self.0) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("json" | "journal")
                )
            {
                let _ = fs::copy(&path, destination.join(entry.file_name()));
            }
        }
    }
}
struct Namespace(String);
impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
    }
}
struct ClientNetwork(u32);
impl Drop for ClientNetwork {
    fn drop(&mut self) {
        // This harness runs only in its own disconnected privileged container.
        let table = self.0.to_string();
        for args in [
            vec!["rule", "del", "priority", &table],
            vec!["route", "flush", "table", &table],
            vec!["link", "del", "candy0"],
            vec!["link", "del", "candy-test-lan"],
        ] {
            let _ = Command::new("ip").args(args).output();
        }
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", &format!("candy_sdwan_{table}")])
            .output();
    }
}
fn ip(args: &[&str]) {
    assert!(
        Command::new("ip").args(args).status().unwrap().success(),
        "{args:?}"
    );
}
fn private_json(path: &Path, value: &serde_json::Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn wait_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn status(path: &Path) -> Option<serde_json::Value> {
    fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}
fn core() -> String {
    std::env::var("CANDY_CORE_TEST_BINARY").unwrap()
}

struct ClientControl {
    client: InfrastructureClient,
    scoped: bool,
}
impl ClientControl {
    fn exchange(
        &mut self,
        operation: Operation,
    ) -> Result<(Body, Option<std::os::fd::OwnedFd>), candy_netd_client::IpcError> {
        if self.scoped {
            self.client.exchange_in_domain([2; 16], [3; 16], operation)
        } else {
            self.client.exchange(operation)
        }
    }
}

#[test]
#[ignore = "server helper execs actual Core inside private network namespace"]
fn signed_server_helper() {
    let root = PathBuf::from(std::env::var("CANDY_SIGNED_TEST_ROOT").unwrap());
    let epoch: u64 = std::env::var("CANDY_SIGNED_SERVER_EPOCH")
        .unwrap()
        .parse()
        .unwrap();
    let ns = fs::metadata("/proc/self/ns/net").unwrap();
    let spec = InfraSpec {
        infra_id: [8; 16],
        generation: 1,
        netns_device: ns.dev(),
        netns_inode: ns.ino(),
        overlay_router_ipv4: [100, 64, 0, 2],
        mtu: 1180,
    };
    let mut netd = InfrastructureClient::new(root.join("server-netd.sock"), [8; 16]);
    assert!(matches!(
        netd.exchange(Operation::InfraEnsure(spec.clone()))
            .unwrap()
            .0,
        Body::InfraStatus { spec: Some(_), .. }
    ));
    let (body, fd) = netd
        .exchange(Operation::InfraAcquireIoFd {
            infra_id: spec.infra_id,
            generation: 1,
            io_epoch: epoch,
        })
        .unwrap();
    assert!(matches!(body, Body::IoFd { .. }), "{body:?}");
    let fd = fd.unwrap();
    ip(&["route", "replace", "10.251.1.0/24", "dev", "candy0"]);
    nix::fcntl::fcntl(
        fd.as_raw_fd(),
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .unwrap();
    let error = Command::new(core())
        .arg("server")
        .arg("--config")
        .arg(root.join("fixture/server.toml"))
        .arg("--tun-fd")
        .arg(fd.as_raw_fd().to_string())
        .arg("--status")
        .arg(root.join("server-status.json"))
        .arg("--readiness-token")
        .arg("0123456789abcdef0123456789abcdef")
        .exec();
    panic!("Core exec failed: {error}");
}

#[test]
#[ignore = "single-process B0 helper execs actual Core with a real netd TUN in an isolated test namespace"]
fn signed_b0_client_helper() {
    let root = PathBuf::from(std::env::var("CANDY_SIGNED_TEST_ROOT").unwrap());
    let ns = fs::metadata("/proc/self/ns/net").unwrap();
    let spec = InfraSpec {
        infra_id: [3; 16],
        generation: 1,
        netns_device: ns.dev(),
        netns_inode: ns.ino(),
        overlay_router_ipv4: [100, 64, 0, 1],
        mtu: 1180,
    };
    let mut netd = InfrastructureClient::new(root.join("netd.sock"), [1; 16]);
    assert!(matches!(
        netd.exchange(Operation::InfraEnsure(spec.clone()))
            .unwrap()
            .0,
        Body::InfraStatus { spec: Some(_), .. }
    ));
    let (body, fd) = netd
        .exchange(Operation::InfraAcquireIoFd {
            infra_id: spec.infra_id,
            generation: 1,
            io_epoch: 1,
        })
        .unwrap();
    assert!(matches!(body, Body::IoFd { .. }), "{body:?}");
    let fd = fd.unwrap();
    ip(&["addr", "replace", "100.64.0.1/24", "dev", "candy0"]);
    ip(&["link", "set", "candy0", "up"]);
    ip(&["route", "replace", "10.251.2.0/24", "dev", "candy0"]);
    nix::fcntl::fcntl(
        fd.as_raw_fd(),
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .unwrap();
    let error = Command::new(core())
        .args(["client", "sdwan", "run", "--config"])
        .arg(root.join("fixture/client.toml"))
        .arg("--tun-fd")
        .arg(fd.as_raw_fd().to_string())
        .arg("--status")
        .arg(root.join("client-status.json"))
        .arg("--readiness-token")
        .arg("0123456789abcdef0123456789abcdef")
        .exec();
    panic!("Core exec failed: {error}");
}

#[test]
#[ignore = "strict signed CLI + real QUIC + two real Linux TUNs; isolated privileged namespace only"]
fn signed_cli_peer_loss_selfheals_same_policy_through_agent_and_netd() {
    run_signed_cli(
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        FaultMode::None,
    );
}

#[test]
#[ignore = "real signed Grant expiry and independent Core/IO takeover; isolated privileged namespace only"]
fn signed_cli_independent_worker_takeover_and_expiry_preserve_tun() {
    run_signed_cli(
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        FaultMode::None,
    );
}

#[test]
#[ignore = "strict signed Core+Agent+TUNIO in separate routing namespace; isolated privileged namespace only"]
fn signed_cli_scoped_namespace_peer_loss_selfheals() {
    run_signed_cli(
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        FaultMode::None,
    );
}

#[test]
#[ignore = "same-process Cloud failures and signed SD-WAN recovery; isolated privileged namespace only"]
fn signed_cli_unified_agent_isolates_cloud_failure_from_domain_recovery() {
    run_signed_cli(
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        FaultMode::None,
    );
}

#[test]
#[ignore = "authenticated original-Grant Core replacement and Agent takeover; isolated privileged namespace only"]
fn signed_cli_unified_agent_rebinds_crashed_core_preserving_original_tun() {
    run_signed_cli(
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        FaultMode::None,
    );
}

#[test]
#[ignore = "fresh actual signed Grant after expiry, same IO/TUN, Agent journal takeover; isolated privileged namespace only"]
fn signed_cli_fresh_grant_renews_expired_worker_on_original_tun() {
    run_signed_cli(
        false,
        false,
        true,
        false,
        true,
        false,
        false,
        FaultMode::None,
    );
}

#[test]
#[ignore = "real authorized commit reply loss, netd SIGKILL/restart and stale epoch; isolated privileged namespace only"]
fn signed_cli_lost_commit_reply_and_netd_restart_preserve_original_tun() {
    run_signed_cli(
        false,
        false,
        true,
        false,
        true,
        true,
        false,
        FaultMode::None,
    );
}

#[test]
#[ignore = "actual TUNIO SIGKILL twice and domain pair recovery; isolated privileged namespace only"]
fn signed_cli_io_sigkill_recovers_pair_without_replacing_original_tun() {
    run_signed_cli(
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        FaultMode::None,
    );
}

#[test]
#[ignore = "fresh signed Grant then actual TUNIO SIGKILL twice; isolated privileged namespace only"]
fn signed_cli_new_grant_and_io_sigkill_recover_same_infrastructure() {
    run_signed_cli(
        false,
        false,
        true,
        false,
        true,
        false,
        true,
        FaultMode::None,
    );
}

#[test]
#[ignore = "new signed Grant and dead IO simultaneously on Agent restart; isolated privileged namespace only"]
fn signed_cli_concurrent_new_grant_and_io_death_selfheal_original_tun() {
    run_signed_cli(
        false,
        false,
        true,
        false,
        true,
        false,
        false,
        FaultMode::ConcurrentGrantIo,
    );
}

#[test]
#[ignore = "actual netd and TUNIO simultaneous SIGKILL twice; isolated privileged namespace only"]
fn signed_cli_netd_and_io_sigkill_recover_original_infrastructure() {
    run_signed_cli(
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        FaultMode::NetdIo,
    );
}

#[test]
#[ignore = "actual duplicate public listener and server SIGKILL/restart; isolated privileged namespace only"]
fn signed_cli_listener_conflict_and_transport_exit_preserve_client_infrastructure() {
    run_signed_cli(
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        FaultMode::PublicListener,
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FaultMode {
    None,
    ConcurrentGrantIo,
    NetdIo,
    PublicListener,
}

#[allow(clippy::too_many_arguments)]
fn run_signed_cli(
    independent: bool,
    scoped: bool,
    unified: bool,
    rebind: bool,
    renewal: bool,
    reply_loss: bool,
    pair_recovery: bool,
    fault_mode: FaultMode,
) {
    let concurrent_renewal_io_death = fault_mode == FaultMode::ConcurrentGrantIo;
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1")
    );
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let _failed_state = FailedStateEvidence(root.to_path_buf());
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let ns = Namespace(format!("candy-signed-{}", std::process::id()));
    ip(&["netns", "add", &ns.0]);
    ip(&[
        "link",
        "add",
        "candy-test-host",
        "type",
        "veth",
        "peer",
        "name",
        "candy-test-peer",
    ]);
    ip(&["link", "set", "candy-test-peer", "netns", &ns.0]);
    ip(&["addr", "add", "10.200.0.1/24", "dev", "candy-test-host"]);
    ip(&["link", "set", "candy-test-host", "up"]);
    ip(&["-n", &ns.0, "link", "set", "lo", "up"]);
    ip(&[
        "-n",
        &ns.0,
        "addr",
        "add",
        "10.200.0.2/24",
        "dev",
        "candy-test-peer",
    ]);
    ip(&["-n", &ns.0, "link", "set", "candy-test-peer", "up"]);
    ip(&["link", "add", "candy-test-lan", "type", "dummy"]);
    ip(&["addr", "add", "10.251.1.10/24", "dev", "candy-test-lan"]);
    ip(&["link", "set", "candy-test-lan", "up"]);
    ip(&["-n", &ns.0, "link", "add", "candy-srv-lan", "type", "dummy"]);
    ip(&[
        "-n",
        &ns.0,
        "addr",
        "add",
        "10.251.2.10/24",
        "dev",
        "candy-srv-lan",
    ]);
    ip(&["-n", &ns.0, "link", "set", "candy-srv-lan", "up"]);
    let client_ns = if scoped {
        let client = Namespace(format!("candy-client-{}", std::process::id()));
        ip(&["netns", "add", &client.0]);
        ip(&["link", "set", "candy-test-host", "netns", &client.0]);
        ip(&["link", "set", "candy-test-lan", "netns", &client.0]);
        ip(&["-n", &client.0, "link", "set", "lo", "up"]);
        ip(&[
            "-n",
            &client.0,
            "addr",
            "replace",
            "10.200.0.1/24",
            "dev",
            "candy-test-host",
        ]);
        ip(&["-n", &client.0, "link", "set", "candy-test-host", "up"]);
        ip(&[
            "-n",
            &client.0,
            "addr",
            "replace",
            "10.251.1.10/24",
            "dev",
            "candy-test-lan",
        ]);
        ip(&["-n", &client.0, "link", "set", "candy-test-lan", "up"]);
        Some(client)
    } else {
        None
    };
    let fixture = Command::new(std::env::var("CANDY_SIGNED_FIXTURE_BINARY").unwrap())
        .arg(root.join("fixture"))
        .env("CANDY_SIGNED_FIXTURE_ENDPOINT", "10.200.0.2:18443")
        .env(
            "CANDY_SIGNED_FIXTURE_GRANT_TTL_SECS",
            if independent || renewal {
                "20"
            } else if rebind {
                "60"
            } else {
                "600"
            },
        )
        .output()
        .unwrap();
    assert!(
        fixture.status.success(),
        "{}",
        String::from_utf8_lossy(&fixture.stderr)
    );
    let compiled = Command::new(core())
        .args(["client", "sdwan", "compile-control", "--config"])
        .arg(root.join("fixture/client.toml"))
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let compiled: serde_json::Value = serde_json::from_slice(&compiled.stdout).unwrap();
    let _client_network = ClientNetwork(compiled["netd"]["table_id"].as_u64().unwrap() as u32);
    let expiry = compiled["authorization_expires_at_unix"].as_u64().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(expiry > now);
    assert!(
        expiry <= now + 600,
        "verified expiry did not honor shorter signed Grant"
    );
    let original_grant = fs::read(root.join("fixture/grant.bin")).unwrap();
    let mut tampered = original_grant.clone();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(root.join("fixture/grant.bin"), tampered).unwrap();
    let rejected = Command::new(core())
        .args(["client", "sdwan", "compile-control", "--config"])
        .arg(root.join("fixture/client.toml"))
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "tampered Grant accepted by real Core compile-control"
    );
    fs::write(root.join("fixture/grant.bin"), original_grant).unwrap();
    if rebind {
        verify_unregistered_core_cannot_outlive_agent(root);
    }
    let netd_binary = std::env::var("CANDY_NETD_TEST_BINARY").unwrap();
    let _server_netd = Process(
        Command::new("ip")
            .args(["netns", "exec", &ns.0])
            .arg(&netd_binary)
            .arg("--protocol-v2")
            .arg("--socket")
            .arg(root.join("server-netd.sock"))
            .args(["--allowed-uid", "0", "--allowed-gid", "0"])
            .arg("--infrastructure-journal")
            .arg(root.join("server-infra.journal"))
            .spawn()
            .unwrap(),
    );
    let mut client_netd_command = Command::new(if reply_loss {
        std::env::var("CANDY_NETD_REPLY_LOSS_FIXTURE_BINARY").unwrap()
    } else {
        netd_binary.clone()
    });
    client_netd_command
        .arg("--protocol-v2")
        .arg("--socket")
        .arg(root.join("netd.sock"))
        .args(["--allowed-uid", "0", "--allowed-gid", "0"])
        .arg("--infrastructure-journal")
        .arg(root.join("infra.journal"));
    if reply_loss {
        client_netd_command
            .arg("--fault-evidence")
            .arg(root.join("commit-reply-loss.json"));
    }
    let namespace_path = client_ns
        .as_ref()
        .map(|namespace| PathBuf::from(format!("/var/run/netns/{}", namespace.0)));
    if let Some(path) = &namespace_path {
        private_json(
            &root.join("domains.json"),
            &serde_json::json!({"budgets":{"max_domains":1,"front_control_threads":2,"max_control_threads":3,"thread_stack_bytes":262144,"max_total_stack_bytes":786432,"max_pending_control_requests":4,"max_pending_control_bytes":1048576,"max_reserved_fds":128},"domains":[{"domain_id":vec![2;16],"infra_id":vec![3;16],"namespace_path":path,"journal_path":root.join("domain.journal"),"table_id":compiled["netd"]["table_id"]}]}),
        );
        client_netd_command
            .arg("--domain-config")
            .arg(root.join("domains.json"));
    }
    let mut client_netd = Process(client_netd_command.spawn().unwrap());
    wait_socket(&root.join("netd.sock"));
    wait_socket(&root.join("server-netd.sock"));
    let spawn_server = |epoch: u64| {
        Process(
            Command::new("ip")
                .args(["netns", "exec", &ns.0])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "signed_server_helper",
                    "--ignored",
                    "--nocapture",
                ])
                .env("CANDY_SIGNED_TEST_ROOT", root)
                .env("CANDY_SIGNED_SERVER_EPOCH", epoch.to_string())
                .spawn()
                .unwrap(),
        )
    };
    let mut server = spawn_server(1);
    let namespace = fs::metadata(
        namespace_path
            .as_deref()
            .unwrap_or(Path::new("/proc/self/ns/net")),
    )
    .unwrap();
    let infra_generation = if rebind { 7 } else { 1 };
    let spec = InfraSpec {
        infra_id: [3; 16],
        generation: infra_generation,
        netns_device: namespace.dev(),
        netns_inode: namespace.ino(),
        overlay_router_ipv4: [100, 64, 0, 1],
        mtu: 1180,
    };
    let prefix = |ip: [u8; 4], len| Ipv4Prefix::new(ip, len).unwrap();
    let declaration = PrepareDeclaration {
        table_id: compiled["netd"]["table_id"].as_u64().unwrap() as u32,
        overlay_router_ipv4: spec.overlay_router_ipv4,
        effective_mtu: 1180,
        routes: vec![
            RouteDeclaration {
                prefix: prefix([10, 251, 1, 0], 24),
                kind: RouteKind::Local,
            },
            RouteDeclaration {
                prefix: prefix([10, 251, 2, 0], 24),
                kind: RouteKind::Remote,
            },
        ],
        exclusions: vec![UnderlayExclusion {
            prefix: prefix([10, 200, 0, 2], 32),
            kind: UnderlayKind::HubEndpoint,
        }],
        firewall: FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    };
    let mut plan = serde_json::json!({"schema_version":1,"netd_socket":root.join("netd.sock"),"tunio":env!("CARGO_BIN_EXE_candy-tunio"),"core":core(),"core_config":root.join("fixture/client.toml"),"core_status":root.join("client-status.json"),"binding_file":root.join("binding.json"),"instance_id":vec![1;16],"infrastructure":spec,"domain_id":vec![2;16],"io_epoch":1,"worker_epoch":1,"fencing_token":1,"signed_generation":1,"auth_deadline_unix":expiry+3600,"declaration":declaration,"independent_supervision":{"control_socket":root.join("io-control.sock"),"status":root.join("io-status.json"),"process_record":root.join("io-process.json")}});
    if independent || rebind || renewal || pair_recovery {
        plan["independent_worker"] = serde_json::json!({"control_socket":root.join("worker-control.sock"),"process_record":root.join("worker-process.json")});
    }
    if let Some(path) = &namespace_path {
        plan["routing_namespace"] = serde_json::json!(path);
    }
    private_json(&root.join("plan.json"), &plan);
    let mut agent_command = Command::new(std::env::var("CANDY_AGENT_TEST_BINARY").unwrap());
    if unified {
        fs::create_dir(root.join("cloud-state")).unwrap();
        fs::set_permissions(root.join("cloud-state"), fs::Permissions::from_mode(0o700)).unwrap();
        private_json(
            &root.join("runtime-agent.json"),
            &serde_json::json!({"schema_version":1,"status":root.join("runtime-agent-status.json"),"budgets":{"max_domain_supervisors":1,"max_managed_threads":2,"thread_stack_bytes":1048576,"max_managed_stack_bytes":2097152,"event_capacity":1,"cloud_iteration_deadline_ms":1000,"shutdown_timeout_ms":5000},"cloud":{"state_dir":root.join("cloud-state"),"run_dir":root,"interval_ms":100,"retry_initial_ms":100,"retry_max_ms":200},"domain_plans":[root.join("plan.json")]}),
        );
        agent_command
            .args([
                "experimental-runtime-agent",
                "--experimental-packet-port-ipc",
                "--config",
            ])
            .arg(root.join("runtime-agent.json"));
    } else {
        agent_command
            .args([
                "experimental-packet-port-run",
                "--experimental-packet-port-ipc",
                "--plan",
            ])
            .arg(root.join("plan.json"));
    }
    let mut agent = Process(agent_command.spawn().unwrap());
    let mut client = ClientControl {
        client: InfrastructureClient::new(root.join("netd.sock"), [1; 16]),
        scoped,
    };
    let wait = |client: &mut ClientControl, failed: bool, after: u64| -> u64 {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok((
                Body::ForwardStatus {
                    phase: Some(candy_netd_proto::v2::Phase::Active),
                    failed_prefixes,
                    failure_revision,
                    ..
                },
                _,
            )) = client.exchange(Operation::ForwardStatus)
            {
                if failure_revision > after && failed_prefixes.is_empty() != failed {
                    return failure_revision;
                }
            }
            assert!(
                Instant::now() < deadline,
                "signed Core/Agent/netd authoritative transition timed out failed={failed}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    let first = wait(&mut client, false, 0);
    let initial = status(&root.join("client-status.json")).unwrap();
    let pid = initial["pid"].clone();
    let io = status(&root.join("io-status.json")).unwrap();
    assert_eq!(io["auth_deadline_unix"], expiry);
    let link_state = || {
        let mut command = Command::new("ip");
        if let Some(namespace) = &client_ns {
            command.args(["-n", &namespace.0]);
        }
        command
            .args(["-j", "addr", "show", "dev", "candy0"])
            .output()
            .unwrap()
            .stdout
    };
    let link = link_state();
    let ping = || {
        let mut command = if let Some(namespace) = &client_ns {
            let mut command = Command::new("ip");
            command.args(["netns", "exec", &namespace.0, "ping"]);
            command
        } else {
            Command::new("ping")
        };
        command
            .args(["-I", "10.251.1.10", "-c", "1", "-W", "2", "10.251.2.10"])
            .status()
            .unwrap()
            .success()
    };
    assert!(ping(), "signed real TUN traffic failed before fault");
    if fault_mode == FaultMode::PublicListener {
        verify_public_listener_conflict(root, &ns.0, &ping, &link_state, &link);
    }
    if pair_recovery && !renewal {
        verify_io_pair_recovery(
            root,
            &mut client,
            &ping,
            &link_state,
            &link,
            (fault_mode == FaultMode::NetdIo).then_some(&mut client_netd),
        );
        unsafe {
            nix::libc::kill(agent.0.id() as i32, nix::libc::SIGTERM);
        }
        assert!(agent.0.wait().unwrap().success());
        assert!(matches!(
            client
                .exchange(Operation::InfraRetire {
                    infra_id: [3; 16],
                    generation: infra_generation,
                })
                .unwrap()
                .0,
            Body::Ack
        ));
        drop(server);
        return;
    }
    if independent {
        verify_independent_takeover(root, &mut agent, &mut client, &ping, &link, expiry);
        return;
    }
    if renewal {
        if concurrent_renewal_io_death {
            ip(&["link", "set", "candy-test-host", "down"]);
            assert!(!ping(), "underlay outage still forwarded test traffic");
            assert_eq!(link_state(), link);
        }
        verify_fresh_grant_renewal(
            root,
            &mut agent,
            &mut client,
            &ping,
            &link_state,
            &link,
            expiry,
            reply_loss.then_some(&mut client_netd),
            pair_recovery,
            concurrent_renewal_io_death,
        );
        unsafe {
            nix::libc::kill(agent.0.id() as i32, nix::libc::SIGTERM);
        }
        assert!(agent.0.wait().unwrap().success());
        assert!(matches!(
            client
                .exchange(Operation::InfraRetire {
                    infra_id: [3; 16],
                    generation: infra_generation
                })
                .unwrap()
                .0,
            Body::Ack
        ));
        drop(server);
        return;
    }
    server.0.kill().unwrap();
    server.0.wait().unwrap();
    let lost = wait(&mut client, true, first);
    if fault_mode == FaultMode::PublicListener {
        assert!(!ping(), "dead public Transport still forwarded traffic");
        let current_io = status(&root.join("io-status.json")).unwrap();
        assert_eq!(current_io["pid"], io["pid"]);
    }
    assert!(agent.0.try_wait().unwrap().is_none());
    let failed = status(&root.join("client-status.json")).unwrap();
    assert_eq!(failed["pid"], pid);
    assert_eq!(failed["policy_generation"], 1);
    assert_eq!(link_state(), link);
    let mut server_control = InfrastructureClient::new(root.join("server-netd.sock"), [8; 16]);
    assert!(matches!(
        server_control
            .exchange(Operation::InfraReleaseIo {
                infra_id: [8; 16],
                generation: 1,
                io_epoch: 1
            })
            .unwrap()
            .0,
        Body::Ack
    ));
    server = spawn_server(2);
    let restored = wait(&mut client, false, lost);
    assert!(ping(), "signed real TUN traffic did not recover");
    if fault_mode == FaultMode::PublicListener {
        if let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") {
            private_json(
                &PathBuf::from(destination).join("signed-public-listener-evidence.json"),
                &serde_json::json!({"scope":"current Core public server process, not a separated master implementation",
                "duplicate_bind_rejected":true,"existing_traffic_preserved_during_conflict":true,
                "server_sigkill_and_manual_restart":true,"client_core_pid":pid,"client_io_pid":io["pid"],
                "client_tun_preserved":true,"actual_icmp_restored":true,
                "initial_revision":first,"failed_revision":lost,"restored_revision":restored}),
            );
        }
    }
    if unified {
        let runtime = status(&root.join("runtime-agent-status.json")).unwrap();
        assert_eq!(runtime["pid"], agent.0.id());
        assert!(runtime["cloud_cancellation_supported"].as_bool().unwrap());
        assert!(runtime["tasks"][0]["iterations"].as_u64().unwrap() > 1);
        assert!(runtime["tasks"][0]["failures"].as_u64().unwrap() > 1);
        assert_eq!(runtime["tasks"][1]["phase"], "running");
        eprintln!("unified_agent_evidence same_agent_pid={} cloud_failed_iterations={} domain_recovered=true bounded_notifications=1",agent.0.id(),runtime["tasks"][0]["failures"]);
    }
    let recovered = status(&root.join("client-status.json")).unwrap();
    assert_eq!(recovered["pid"], pid);
    assert_eq!(recovered["policy_generation"], 1);
    assert_eq!(link_state(), link);
    eprintln!("signed_cli_chain_evidence policy_generation=1 core_pid={pid} initial_revision={first} failed_revision={lost} restored_revision={restored} authorization_expires_at_unix={expiry} same_tun=true real_icmp_before_and_after=true");
    if rebind {
        verify_core_rebind(
            root,
            &mut agent,
            &mut client,
            &ping,
            &link_state,
            &link,
            expiry,
        );
    }
    unsafe {
        nix::libc::kill(agent.0.id() as i32, nix::libc::SIGTERM);
    }
    assert!(agent.0.wait().unwrap().success());
    assert!(matches!(
        client
            .exchange(Operation::InfraRetire {
                infra_id: [3; 16],
                generation: infra_generation
            })
            .unwrap()
            .0,
        Body::Ack
    ));
    drop(server);
    if let Some(namespace) = &client_ns {
        ip(&["-n", &namespace.0, "link", "del", "candy-test-lan"]);
    } else {
        ip(&["link", "del", "candy-test-lan"]);
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_fresh_grant_renewal(
    root: &Path,
    agent: &mut Process,
    client: &mut ClientControl,
    ping: &impl Fn() -> bool,
    link: &impl Fn() -> Vec<u8>,
    original_link: &[u8],
    original_expiry: u64,
    reply_loss_netd: Option<&mut Process>,
    pair_recovery: bool,
    concurrent_renewal_io_death: bool,
) {
    use candy_process_control::{process_identity, process_is_current};
    let io_record = status(&root.join("io-process.json")).unwrap();
    let mut io = process_identity(io_record["pid"].as_u64().unwrap() as u32).unwrap();
    let first_core = process_identity(
        status(&root.join("worker-process.json")).unwrap()["pid"]
            .as_u64()
            .unwrap() as u32,
    )
    .unwrap();
    while SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        <= original_expiry
    {
        assert!(process_is_current(io));
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !ping(),
        "original expired Grant still forwarded actual traffic"
    );
    assert_eq!(link(), original_link);
    assert!(process_is_current(io));
    let original_grant = fs::read(root.join("fixture/grant.bin")).unwrap();
    let mut tampered = original_grant.clone();
    let index = tampered.len() / 2;
    tampered[index] ^= 1;
    fs::write(root.join("fixture/grant.bin"), tampered).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(process_identity(io.pid).unwrap(), io);
    assert!(!ping(), "tampered fresh Grant activated actual traffic");
    fs::write(root.join("fixture/grant.bin"), original_grant).unwrap();
    if concurrent_renewal_io_death {
        agent.0.kill().unwrap();
        agent.0.wait().unwrap();
    }
    let renew = Command::new(std::env::var("CANDY_SIGNED_FIXTURE_BINARY").unwrap())
        .env("CANDY_SIGNED_FIXTURE_RENEW_ROOT", root.join("fixture"))
        .env("CANDY_SIGNED_FIXTURE_GRANT_TTL_SECS", "60")
        .output()
        .unwrap();
    assert!(
        renew.status.success(),
        "{}",
        String::from_utf8_lossy(&renew.stderr)
    );
    let compiled = Command::new(core())
        .args(["client", "sdwan", "compile-control", "--config"])
        .arg(root.join("fixture/client.toml"))
        .output()
        .unwrap();
    assert!(compiled.status.success());
    let compiled: serde_json::Value = serde_json::from_slice(&compiled.stdout).unwrap();
    let expiry = compiled["authorization_expires_at_unix"].as_u64().unwrap();
    assert!(expiry > original_expiry);
    let prior_io = io;
    if concurrent_renewal_io_death {
        assert_eq!(
            unsafe { nix::libc::kill(io.pid as i32, nix::libc::SIGKILL) },
            0
        );
        let dead_io_deadline = Instant::now() + Duration::from_secs(5);
        while process_is_current(prior_io) {
            assert!(
                Instant::now() < dead_io_deadline,
                "old TUNIO remained alive after SIGKILL"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !process_is_current(prior_io),
            "old TUNIO must be confirmed dead before Agent restart"
        );
        ip(&["link", "set", "candy-test-host", "up"]);
        *agent = Process(
            Command::new(std::env::var("CANDY_AGENT_TEST_BINARY").unwrap())
                .args([
                    "experimental-runtime-agent",
                    "--experimental-packet-port-ipc",
                    "--config",
                ])
                .arg(root.join("runtime-agent.json"))
                .spawn()
                .unwrap(),
        );
    }
    let deadline =
        Instant::now() + Duration::from_secs(if concurrent_renewal_io_death { 45 } else { 25 });
    let mut renewed = loop {
        if let Some(record) = status(&root.join("worker-process.json")) {
            let pid = record["pid"].as_u64().unwrap() as u32;
            if pid != first_core.pid && record["auth_deadline_unix"] == expiry {
                if let Ok((
                    Body::ForwardStatus {
                        owner: Some(owner),
                        phase: Some(candy_netd_proto::v2::Phase::Active),
                        failed_prefixes,
                        ..
                    },
                    _,
                )) = client.exchange(Operation::ForwardStatus)
                {
                    if owner.worker_epoch > 1 && failed_prefixes.is_empty() {
                        break process_identity(pid).unwrap();
                    }
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "valid fresh signed Grant did not restore original TUN traffic"
        );
        if !concurrent_renewal_io_death {
            assert_eq!(process_identity(io.pid).unwrap(), io);
        }
        assert_eq!(link(), original_link);
        std::thread::sleep(Duration::from_millis(50));
    };
    if concurrent_renewal_io_death {
        io = process_identity(
            status(&root.join("io-process.json")).unwrap()["pid"]
                .as_u64()
                .unwrap() as u32,
        )
        .unwrap();
        assert_ne!(io, prior_io);
        assert!(!process_is_current(prior_io));
        assert!(
            status(&root.join("io-process.json")).unwrap()["io_epoch"]
                .as_u64()
                .unwrap()
                > io_record["io_epoch"].as_u64().unwrap()
        );
        if let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") {
            private_json(
                &PathBuf::from(destination).join("signed-concurrent-grant-io-evidence.json"),
                &serde_json::json!({"old_io":prior_io,"new_io":io,"new_core":renewed,
                    "new_signed_expiry":expiry,"original_expiry":original_expiry,
                    "original_tun":serde_json::from_slice::<serde_json::Value>(original_link).unwrap(),
                    "restored_tun":serde_json::from_slice::<serde_json::Value>(&link()).unwrap(),
                    "new_grant_prepared_before_agent_start":true,
                    "io_sigkill_confirmed_dead_before_agent_start":true,
                    "actual_underlay_down_across_original_grant_expiry":true,
                    "cloud_source":"local_signed_grant_fixture"}),
            );
        }
        eprintln!("signed_concurrent_grant_io_evidence old_io={} new_io={} new_core={} new_grant_before_agent_start=true io_dead_before_agent_start=true same_tun=true",prior_io.pid,io.pid,renewed.pid);
    }
    assert!(ping());
    let record = status(&root.join("worker-process.json")).unwrap();
    let core_status = PathBuf::from(record["status_path"].as_str().unwrap());
    let proof = status(&core_status).unwrap();
    assert_eq!(
        proof["worker_authority_sha256"],
        compiled["authorization_snapshot_sha256"]
    );
    assert!(proof["worker_authority_revision"].as_u64().unwrap() > 0);
    assert_eq!(
        status(&root.join("io-status.json")).unwrap()["auth_deadline_unix"],
        expiry
    );
    assert_eq!(link(), original_link);
    let fd_path = PathBuf::from(format!("/proc/{}/fd", io.pid));
    let tun_fds = fs::read_dir(fd_path)
        .unwrap()
        .filter_map(|entry| fs::read_link(entry.unwrap().path()).ok())
        .filter(|path| path.to_string_lossy().contains("tun"))
        .count();
    assert_eq!(tun_fds, 1);
    if let Some(netd) = reply_loss_netd {
        verify_commit_reply_loss_and_netd_restart(
            root,
            netd,
            client,
            ping,
            link,
            original_link,
            renewed,
            io,
        );
    }
    if pair_recovery {
        verify_io_pair_recovery(root, client, ping, link, original_link, None);
        io = process_identity(
            status(&root.join("io-process.json")).unwrap()["pid"]
                .as_u64()
                .unwrap() as u32,
        )
        .unwrap();
        renewed = process_identity(
            status(&root.join("worker-process.json")).unwrap()["pid"]
                .as_u64()
                .unwrap() as u32,
        )
        .unwrap();
    }
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();
    assert!(ping(), "renewed Core did not survive Agent loss");
    *agent = Process(
        Command::new(std::env::var("CANDY_AGENT_TEST_BINARY").unwrap())
            .args([
                "experimental-runtime-agent",
                "--experimental-packet-port-ipc",
                "--config",
            ])
            .arg(root.join("runtime-agent.json"))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let current = status(&root.join("io-status.json")).unwrap();
        if current["controller"]["pid"] == agent.0.id() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "renewed Core/IO takeover timed out"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(process_identity(renewed.pid).unwrap(), renewed);
    assert_eq!(process_identity(io.pid).unwrap(), io);
    assert_eq!(link(), original_link);
    assert!(ping());
    eprintln!("signed_fresh_grant_evidence expired_core={} renewed_core={} same_io={} original_expiry={} new_signed_expiry={} same_policy=true same_tun=true tun_fd_count={} tamper_denied=true agent_takeover=true real_icmp=true",first_core.pid,renewed.pid,io.pid,original_expiry,expiry,tun_fds);
}

fn verify_public_listener_conflict(
    root: &Path,
    namespace: &str,
    ping: &impl Fn() -> bool,
    link: &impl Fn() -> Vec<u8>,
    original_link: &[u8],
) {
    let path = root.join("duplicate-listener.toml");
    fs::write(&path, format!(
        "listen = \"10.200.0.2:18443\"\ncert_pem = {:?}\nkey_pem = {:?}\n[[users]]\nkey_id = \"isolated-fault-fixture\"\nsecret = \"0123456789abcdef\"\n",
        root.join("fixture/server.cert.pem"), root.join("fixture/server.key.pem")
    )).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let log_path = root.join("duplicate-listener.log");
    let log = fs::File::create(&log_path).unwrap();
    let mut duplicate = Process(
        Command::new("ip")
            .args(["netns", "exec", namespace])
            .arg(core())
            .args(["server", "--config"])
            .arg(path)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let exit = loop {
        if let Some(exit) = duplicate.0.try_wait().unwrap() {
            break exit;
        }
        assert!(
            Instant::now() < deadline,
            "duplicate public listener did not reject bind conflict"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = fs::read_to_string(&log_path).unwrap();
    assert!(
        !exit.success(),
        "duplicate public listener unexpectedly started: {output}"
    );
    assert!(
        output.contains("Address already in use") || output.contains("os error 98"),
        "duplicate listener failed before the public bind conflict: {output}"
    );
    assert_eq!(link(), original_link);
    assert!(
        ping(),
        "duplicate bind failure damaged the existing listener"
    );
    if let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") {
        fs::write(
            PathBuf::from(destination).join("signed-public-listener-conflict.log"),
            output,
        )
        .unwrap();
    }
}

fn verify_io_pair_recovery(
    root: &Path,
    client: &mut ClientControl,
    ping: &impl Fn() -> bool,
    link: &impl Fn() -> Vec<u8>,
    original_link: &[u8],
    mut simultaneous_netd: Option<&mut Process>,
) {
    use candy_process_control::{process_identity, process_is_current};
    let mut cycles = Vec::new();
    for cycle in 1..=2 {
        let old_io = status(&root.join("io-process.json")).unwrap();
        let old_core = status(&root.join("worker-process.json")).unwrap();
        let io_identity = process_identity(old_io["pid"].as_u64().unwrap() as u32).unwrap();
        let core_identity = process_identity(old_core["pid"].as_u64().unwrap() as u32).unwrap();
        let (before, _) = client.exchange(Operation::ForwardStatus).unwrap();
        let Body::ForwardStatus {
            owner: Some(old_owner),
            ..
        } = before
        else {
            panic!("owner absent before IO kill: {before:?}");
        };
        let started = Instant::now();
        let old_netd_pid = simultaneous_netd.as_ref().map(|netd| netd.0.id());
        if let Some(netd) = simultaneous_netd.as_mut() {
            netd.0.kill().unwrap();
        }
        assert_eq!(
            unsafe { nix::libc::kill(io_identity.pid as i32, nix::libc::SIGKILL) },
            0
        );
        if let Some(netd) = simultaneous_netd.as_mut() {
            netd.0.wait().unwrap();
            assert_same_tun_identity(&link(), original_link);
            **netd = Process(
                Command::new(std::env::var("CANDY_NETD_TEST_BINARY").unwrap())
                    .arg("--protocol-v2")
                    .arg("--socket")
                    .arg(root.join("netd.sock"))
                    .args(["--allowed-uid", "0", "--allowed-gid", "0"])
                    .arg("--infrastructure-journal")
                    .arg(root.join("infra.journal"))
                    .spawn()
                    .unwrap(),
            );
        }
        let deadline = Instant::now() + Duration::from_secs(45);
        let (new_io, new_core, new_owner) = loop {
            if simultaneous_netd.is_some() {
                assert_same_tun_identity(&link(), original_link);
            } else {
                assert_eq!(link(), original_link, "IO recovery changed TUN state");
            }
            let io = status(&root.join("io-process.json")).unwrap();
            let core = status(&root.join("worker-process.json")).unwrap();
            if io["pid"] != old_io["pid"] && core["pid"] != old_core["pid"] {
                if let Ok((
                    Body::ForwardStatus {
                        owner: Some(owner),
                        phase: Some(candy_netd_proto::v2::Phase::Active),
                        failed_prefixes,
                        ..
                    },
                    _,
                )) = client.exchange(Operation::ForwardStatus)
                {
                    if owner.worker_epoch > old_owner.worker_epoch
                        && failed_prefixes.is_empty()
                        && ping()
                    {
                        break (io, core, owner);
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "actual IO SIGKILL did not self-heal within 45s"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(!process_is_current(io_identity));
        assert!(
            !process_is_current(core_identity),
            "old Core remained alive after IO replacement"
        );
        assert!(new_io["io_epoch"].as_u64().unwrap() > old_io["io_epoch"].as_u64().unwrap());
        assert!(
            new_core["worker_epoch"].as_u64().unwrap() > old_core["worker_epoch"].as_u64().unwrap()
        );
        assert!(new_owner.auth_deadline_mono_ms <= old_owner.auth_deadline_mono_ms);
        assert!(
            matches!(client.exchange(Operation::ForwardRevoke { owner: old_owner.clone() }).unwrap(),
            (Body::Error { code, .. }, _) if code == "stale_forward_owner")
        );
        assert!(matches!(client.exchange(Operation::InfraAcquireIoFd {
            infra_id: [3; 16], generation: 1,
            io_epoch: new_io["io_epoch"].as_u64().unwrap() + 1,
        }).unwrap(), (Body::Error { code, .. }, _) if code == "io_owner_alive"));
        if simultaneous_netd.is_some() {
            let recovered_link = link();
            assert_same_tun_identity(&recovered_link, original_link);
            let recovered: serde_json::Value = serde_json::from_slice(&recovered_link).unwrap();
            let flags = recovered[0]["flags"].as_array().unwrap();
            assert!(flags.iter().any(|flag| flag == "UP"));
            assert!(flags.iter().any(|flag| flag == "LOWER_UP"));
            assert!(!flags.iter().any(|flag| flag == "NO-CARRIER"));
            assert!(matches!(
                recovered[0]["operstate"].as_str(),
                Some("UP" | "UNKNOWN")
            ));
        } else {
            assert_eq!(link(), original_link);
        }
        assert!(ping());
        let recovery = status(&root.join("client-status.pair-recovery.json")).unwrap();
        cycles.push(serde_json::json!({"cycle":cycle,"old_io":old_io,"new_io":new_io,
            "old_core":old_core,"new_core":new_core,"old_owner":old_owner,
            "new_owner":new_owner,"recovery_plan":recovery,"recovery_ms":started.elapsed().as_millis(),
            "simultaneous_netd_kill":old_netd_pid.is_some(),"old_netd_pid":old_netd_pid,
            "new_netd_pid":simultaneous_netd.as_ref().map(|netd|netd.0.id()),
            "same_tun":true,"icmp_restored":true,"stale_epoch_denied":true,"duplicate_reader_denied":true}));
    }
    if let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") {
        private_json(
            &PathBuf::from(destination).join(format!(
                "signed-{}-pair-recovery-{}-evidence.json",
                if simultaneous_netd.is_some() {
                    "netd-io"
                } else {
                    "io"
                },
                cycles[0]["old_io"]["pid"]
            )),
            &serde_json::json!({"original_tun":serde_json::from_slice::<serde_json::Value>(original_link).unwrap(),
                "final_tun":serde_json::from_slice::<serde_json::Value>(&link()).unwrap(),"cycles":cycles}),
        );
    }
    eprintln!("signed_io_pair_recovery_evidence real_io_sigkills=2 same_tun=true new_core_and_io=true monotonic_epochs=true original_auth_cap_preserved=true stale_epoch_denied=true duplicate_reader_denied=true real_icmp_restored=true");
}

fn assert_same_tun_identity(actual: &[u8], expected: &[u8]) {
    let actual: serde_json::Value = serde_json::from_slice(actual).unwrap();
    let expected: serde_json::Value = serde_json::from_slice(expected).unwrap();
    assert_eq!(actual.as_array().unwrap().len(), 1, "TUN disappeared");
    for key in [
        "ifindex",
        "ifname",
        "mtu",
        "addr_info",
        "link_type",
        "txqlen",
        "qdisc",
        "group",
    ] {
        assert_eq!(
            actual[0][key], expected[0][key],
            "TUN identity/config changed: {key}"
        );
    }
    // Closing every TUN FD changes carrier state even for a persistent interface.
    let stable_flags = |value: &serde_json::Value| {
        value[0]["flags"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|flag| flag.as_str() != Some("NO-CARRIER") && flag.as_str() != Some("LOWER_UP"))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(stable_flags(&actual), stable_flags(&expected));
}

#[allow(clippy::too_many_arguments)]
fn verify_commit_reply_loss_and_netd_restart(
    root: &Path,
    netd: &mut Process,
    client: &mut ClientControl,
    ping: &impl Fn() -> bool,
    link: &impl Fn() -> Vec<u8>,
    original_link: &[u8],
    core_identity: candy_process_control::ProcessIdentity,
    io_identity: candy_process_control::ProcessIdentity,
) {
    use candy_process_control::process_identity;
    let evidence = status(&root.join("commit-reply-loss.json")).unwrap();
    assert_eq!(evidence["committed_success_before_drop"], true);
    assert_eq!(evidence["reply_drops"], 1);
    assert_eq!(evidence["candidate_pid"], core_identity.pid);
    let (body, _) = client.exchange(Operation::ForwardStatus).unwrap();
    let Body::ForwardStatus {
        owner: Some(owner),
        phase: Some(candy_netd_proto::v2::Phase::Active),
        ..
    } = body
    else {
        panic!("lost commit reply did not recover committed owner: {body:?}");
    };
    let old_netd = netd.0.id();
    netd.0.kill().unwrap();
    netd.0.wait().unwrap();
    assert_eq!(link(), original_link);
    assert!(ping(), "netd SIGKILL interrupted healthy TUN/Core traffic");
    *netd = Process(
        Command::new(std::env::var("CANDY_NETD_TEST_BINARY").unwrap())
            .arg("--protocol-v2")
            .arg("--socket")
            .arg(root.join("netd.sock"))
            .args(["--allowed-uid", "0", "--allowed-gid", "0"])
            .arg("--infrastructure-journal")
            .arg(root.join("infra.journal"))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Ok((
            Body::ForwardStatus {
                owner: Some(current),
                phase: Some(candy_netd_proto::v2::Phase::Active),
                ..
            },
            _,
        )) = client.exchange(Operation::ForwardStatus)
        {
            assert_eq!(current, owner, "netd restart changed committed authority");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "restarted netd did not restore committed authority"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut stale = owner.clone();
    stale.worker_epoch -= 1;
    assert!(
        matches!(
            client.exchange(Operation::ForwardRevoke { owner: stale }).unwrap(),
            (Body::Error { code, .. }, _) if code == "stale_forward_owner"
        ),
        "old epoch revoked renewed owner"
    );
    assert!(
        matches!(
            client.exchange(Operation::InfraAcquireIoFd {
                infra_id: [3; 16],
                generation: 1,
                io_epoch: 2
            }).unwrap(),
            (Body::Error { code, .. }, _) if code == "io_owner_alive"
        ),
        "netd restart issued duplicate live TUN reader"
    );
    assert_eq!(process_identity(core_identity.pid).unwrap(), core_identity);
    assert_eq!(process_identity(io_identity.pid).unwrap(), io_identity);
    assert_eq!(link(), original_link);
    assert!(
        ping(),
        "netd restart or stale epoch disturbed healthy traffic"
    );
    let ifindex: serde_json::Value = serde_json::from_slice(original_link).unwrap();
    if let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") {
        let destination = PathBuf::from(destination);
        fs::create_dir_all(&destination).unwrap();
        private_json(
            &destination.join("signed-commit-restart-evidence.json"),
            &serde_json::json!({
                "commit_reply_loss": &evidence,
                "original_tun": &ifindex,
                "after_restart_tun": serde_json::from_slice::<serde_json::Value>(&link()).unwrap(),
                "old_netd_pid": old_netd,
                "new_netd_pid": netd.0.id(),
                "core_identity": core_identity,
                "io_identity": io_identity,
                "committed_owner": &owner,
                "stale_epoch_error": "stale_forward_owner",
                "duplicate_reader_error": "io_owner_alive",
                "icmp_before_during_after": true
            }),
        );
    }
    eprintln!("signed_commit_restart_evidence reply_drops=1 old_netd={} new_netd={} core_pid={} io_pid={} original_ifindex={} worker_epoch={} same_tun=true same_core=true same_io=true stale_epoch_denied=true duplicate_reader_denied=true real_icmp_before_during_after=true", old_netd, netd.0.id(), core_identity.pid, io_identity.pid, ifindex[0]["ifindex"], owner.worker_epoch);
}

#[test]
#[ignore = "child helper for actual signed Core registration death barrier"]
fn signed_registration_wait_helper() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::os::unix::process::CommandExt;
    let root = PathBuf::from(std::env::var("CANDY_SIGNED_REGISTRATION_ROOT").unwrap());
    let (io, worker) = UnixDatagram::pair().unwrap();
    let fd = worker.as_raw_fd();
    private_json(
        &root.join("unregistered-binding.json"),
        &serde_json::json!({
            "infrastructure_id":vec![3;16],"routing_domain_id":vec![2;16],"infrastructure_generation":7,
            "io_epoch":1,"owner_epoch":99,"policy_generation":1,
        }),
    );
    let compiled = Command::new(core())
        .args(["client", "sdwan", "compile-control", "--config"])
        .arg(root.join("fixture/client.toml"))
        .output()
        .unwrap();
    assert!(compiled.status.success());
    let compiled: serde_json::Value = serde_json::from_slice(&compiled.stdout).unwrap();
    let mut command = Command::new(core());
    command
        .args([
            "client",
            "sdwan",
            "run",
            "--experimental-packet-port-ipc",
            "--experimental-independent-worker",
        ])
        .arg("--config")
        .arg(root.join("fixture/client.toml"))
        .arg("--packet-port-fd")
        .arg(fd.to_string())
        .arg("--packet-port-binding-file")
        .arg(root.join("unregistered-binding.json"))
        .arg("--status")
        .arg(root.join("unregistered-status.json"))
        .arg("--readiness-token")
        .arg("44444444444444444444444444444444")
        .arg("--worker-control-socket")
        .arg(root.join("unregistered-control.sock"))
        .arg("--worker-auth-deadline-unix")
        .arg(
            compiled["authorization_expires_at_unix"]
                .as_u64()
                .unwrap()
                .to_string(),
        );
    unsafe {
        command.pre_exec(move || {
            if nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            nix::fcntl::fcntl(
                fd,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
            )
            .map(|_| ())
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
        });
    }
    let mut child = command.spawn().unwrap();
    drop(worker);
    wait_socket(&root.join("unregistered-control.sock"));
    private_json(
        &root.join("unregistered-process.json"),
        &serde_json::to_value(candy_process_control::process_identity(child.id()).unwrap())
            .unwrap(),
    );
    let result = child.wait().unwrap();
    drop(io);
    panic!("unregistered Core exited while helper Agent remained alive: {result}");
}

fn verify_unregistered_core_cannot_outlive_agent(root: &Path) {
    use candy_process_control::{process_is_current, ProcessIdentity};
    let mut helper = Process(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "signed_registration_wait_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("CANDY_SIGNED_REGISTRATION_ROOT", root)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let identity: ProcessIdentity = loop {
        if let Some(value) = status(&root.join("unregistered-process.json")) {
            break serde_json::from_value(value).unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "Core registration helper did not publish starting control"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(process_is_current(identity));
    helper.0.kill().unwrap();
    helper.0.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while process_is_current(identity) {
        assert!(
            Instant::now() < deadline,
            "unregistered Core survived dead Agent before authenticated Probe"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    eprintln!("signed_registration_barrier_evidence unregistered_core_pid={} dead_agent_before_probe_core_exited=true",identity.pid);
}

fn verify_core_rebind(
    root: &Path,
    agent: &mut Process,
    client: &mut ClientControl,
    ping: &impl Fn() -> bool,
    link_state: &impl Fn() -> Vec<u8>,
    original_link: &[u8],
    expiry: u64,
) {
    use candy_process_control::{process_identity, process_is_current};
    let original_core = process_identity(
        status(&root.join("client-status.json")).unwrap()["pid"]
            .as_u64()
            .unwrap() as u32,
    )
    .unwrap();
    let io = process_identity(
        status(&root.join("io-status.json")).unwrap()["pid"]
            .as_u64()
            .unwrap() as u32,
    )
    .unwrap();
    unsafe {
        assert_eq!(
            nix::libc::kill(original_core.pid as i32, nix::libc::SIGKILL),
            0
        );
    }
    let wait_replacement = |client: &mut ClientControl, old_pid: u32, after_epoch: u64| {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(current) = status(&root.join("client-status.json")) {
                let pid = current["pid"].as_u64().unwrap() as u32;
                if pid != old_pid && current["auth_deadline_unix"] == expiry {
                    if let Ok((
                        Body::ForwardStatus {
                            owner: Some(owner),
                            phase: Some(candy_netd_proto::v2::Phase::Active),
                            failed_prefixes,
                            ..
                        },
                        _,
                    )) = client.exchange(Operation::ForwardStatus)
                    {
                        if owner.worker_epoch > after_epoch && failed_prefixes.is_empty() {
                            return (pid, owner.worker_epoch, owner.fencing_token);
                        }
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "new signed Core did not rebind after original worker crash"
            );
            assert!(
                process_is_current(io),
                "Core crash stopped original TUNIO epoch"
            );
            assert_eq!(
                link_state(),
                original_link,
                "Core crash changed TUN infrastructure"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let (replacement_pid, owner_epoch, fence) = wait_replacement(client, original_core.pid, 1);
    assert_eq!(owner_epoch, 2);
    assert!(
        ping(),
        "real TUN traffic failed after authenticated Core replacement"
    );
    assert_eq!(process_identity(io.pid).unwrap(), io);
    assert_eq!(link_state(), original_link);
    let record = status(&root.join("worker-process.json")).unwrap();
    assert_eq!(record["pid"], replacement_pid);
    assert_eq!(record["worker_epoch"], owner_epoch);
    assert_eq!(record["infrastructure_generation"], 7);
    assert_eq!(record["status_generation"], 1);
    let binding = status(&root.join("io-status.json")).unwrap();
    assert_eq!(binding["packet_binding"]["owner_epoch"], owner_epoch);
    let replacement = process_identity(replacement_pid).unwrap();
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();
    assert!(ping(), "Agent loss interrupted rebound signed Core traffic");
    *agent = Process(
        Command::new(std::env::var("CANDY_AGENT_TEST_BINARY").unwrap())
            .args([
                "experimental-runtime-agent",
                "--experimental-packet-port-ipc",
                "--config",
            ])
            .arg(root.join("runtime-agent.json"))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok((
            Body::ForwardStatus {
                owner: Some(owner),
                phase: Some(candy_netd_proto::v2::Phase::Active),
                ..
            },
            _,
        )) = client.exchange(Operation::ForwardStatus)
        {
            if owner.worker_epoch == owner_epoch && owner.fencing_token > fence {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "replacement Agent could not adopt rebound Core owner epoch"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(process_identity(replacement.pid).unwrap(), replacement);
    assert_eq!(process_identity(io.pid).unwrap(), io);
    assert!(
        ping(),
        "rebound Core traffic failed after real unified Agent takeover"
    );
    unsafe {
        assert_eq!(
            nix::libc::kill(replacement.pid as i32, nix::libc::SIGKILL),
            0
        );
    }
    let (second_pid, second_epoch, _) = wait_replacement(client, replacement.pid, owner_epoch);
    assert_eq!(second_epoch, 3);
    assert!(
        ping(),
        "second Core crash did not recover original TUN traffic"
    );
    assert_eq!(link_state(), original_link);
    assert_eq!(process_identity(io.pid).unwrap(), io);
    assert_eq!(
        status(&root.join("client-status.json")).unwrap()["auth_deadline_unix"],
        expiry
    );
    eprintln!("signed_core_rebind_evidence original_pid={} replacement_pid={} second_pid={} owner_epochs=1,2,3 infrastructure_generation=7 signed_generation=1 io_pid={} original_signed_expiry={} original_tun_preserved=true agent_takeover_preserved=true real_icmp=true",original_core.pid,replacement_pid,second_pid,io.pid,expiry);
}

fn verify_independent_takeover(
    root: &Path,
    agent: &mut Process,
    client: &mut ClientControl,
    ping: &impl Fn() -> bool,
    original_link: &[u8],
    expiry: u64,
) {
    use candy_process_control::{process_identity, process_is_current};
    let original = status(&root.join("client-status.json")).unwrap();
    let worker = process_identity(original["pid"].as_u64().unwrap() as u32).unwrap();
    let io_status = status(&root.join("io-status.json")).unwrap();
    let io = process_identity(io_status["pid"].as_u64().unwrap() as u32).unwrap();
    assert_eq!(original["auth_deadline_unix"], expiry);
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        process_is_current(worker),
        "Agent loss killed independent Core"
    );
    assert!(
        process_is_current(io),
        "Agent loss killed infrastructure IO"
    );
    assert!(ping(), "Agent loss interrupted authorized Core traffic");
    let agent_binary = std::env::var("CANDY_AGENT_TEST_BINARY").unwrap();
    let mut adopted = Process(
        Command::new(&agent_binary)
            .args([
                "adopt-packet-port-worker",
                "--experimental-packet-port-ipc",
                "--plan",
            ])
            .arg(root.join("plan.json"))
            .spawn()
            .unwrap(),
    );
    let mut io_controller = Process(
        Command::new(&agent_binary)
            .args(["adopt-tunio", "--experimental-packet-port-ipc", "--record"])
            .arg(root.join("io-process.json"))
            .arg("--expected-executable")
            .arg(env!("CARGO_BIN_EXE_candy-tunio"))
            .arg("--control-socket")
            .arg(root.join("io-control.sock"))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let current = status(&root.join("client-status.json")).unwrap();
        if current["controller_epoch"] == 2 {
            if let Ok((
                Body::ForwardStatus {
                    owner: Some(owner), ..
                },
                _,
            )) = client.exchange(Operation::ForwardStatus)
            {
                if owner.fencing_token == 2 {
                    break;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "real Agent worker takeover did not complete"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(ping(), "actual Agent adoption did not retain traffic");
    assert_eq!(process_identity(worker.pid).unwrap(), worker);
    assert_eq!(process_identity(io.pid).unwrap(), io);
    assert_eq!(
        status(&root.join("client-status.json")).unwrap()["auth_deadline_unix"],
        expiry
    );
    let deadline = Instant::now() + Duration::from_secs(25);
    while process_is_current(worker) {
        assert!(
            Instant::now() < deadline,
            "Core continued beyond actual signed Grant expiry"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(adopted.0.wait().unwrap().success());
    assert!(
        process_is_current(io),
        "authorization expiry retired infrastructure IO"
    );
    assert!(
        !ping(),
        "traffic continued after signed authorization expiry"
    );
    let current_link = Command::new("ip")
        .args(["-j", "addr", "show", "dev", "candy0"])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(current_link, original_link);
    assert!(matches!(
        client.exchange(Operation::ForwardStatus).unwrap().0,
        Body::ForwardStatus {
            phase: Some(candy_netd_proto::v2::Phase::Revoked),
            ..
        }
    ));
    unsafe {
        nix::libc::kill(io_controller.0.id() as i32, nix::libc::SIGTERM);
    }
    assert!(io_controller.0.wait().unwrap().success());
    assert!(matches!(
        client
            .exchange(Operation::InfraReleaseIo {
                infra_id: [3; 16],
                generation: 1,
                io_epoch: 1
            })
            .unwrap()
            .0,
        Body::Ack
    ));
    assert!(matches!(
        client
            .exchange(Operation::InfraRetire {
                infra_id: [3; 16],
                generation: 1
            })
            .unwrap()
            .0,
        Body::Ack
    ));
    eprintln!("signed_independent_worker_evidence core_pid={} controller_epoch=2 original_signed_expiry={expiry} agent_loss_traffic_preserved=true after_expiry_traffic_denied=true tun_preserved=true io_pid={}",worker.pid,io.pid);
}
