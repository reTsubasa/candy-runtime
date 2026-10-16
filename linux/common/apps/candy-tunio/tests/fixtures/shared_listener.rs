//! Actual Runtime registrations and PacketPort supervisors behind one listener.
use super::*;
use std::io::{Read, Write};
use std::net::TcpStream;
#[path = "retained_io_record.rs"]
mod retained_io_record;

struct Link(String);
impl Drop for Link {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", &self.0]).status();
    }
}

struct Evidence(PathBuf);
impl Drop for Evidence {
    fn drop(&mut self) {
        let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") else {
            return;
        };
        fn copy(source: &Path, target: &Path) -> std::io::Result<()> {
            fs::create_dir_all(target)?;
            for entry in fs::read_dir(source)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    copy(&entry.path(), &target.join(entry.file_name()))?;
                } else if matches!(
                    entry.path().extension().and_then(|value| value.to_str()),
                    Some(
                        "json"
                            | "log"
                            | "journal"
                            | "domain"
                            | "activation"
                            | "reservation"
                            | "candidate"
                            | "candidate-admission"
                    )
                ) {
                    fs::copy(entry.path(), target.join(entry.file_name()))?;
                }
            }
            Ok(())
        }
        let _ = copy(
            &self.0,
            &PathBuf::from(destination).join("mixed-listener-state"),
        );
    }
}

fn spawn(command: &mut Command, path: &Path) -> Process {
    let log = fs::File::create(path).unwrap();
    Process(
        command
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    )
}

fn prefix(value: &str) -> Ipv4Prefix {
    let (address, length) = value.split_once('/').unwrap();
    Ipv4Prefix::new(
        address.parse::<std::net::Ipv4Addr>().unwrap().octets(),
        length.parse().unwrap(),
    )
    .unwrap()
}

pub(super) fn declaration(report: &serde_json::Value) -> PrepareDeclaration {
    let netd = &report["netd"];
    let mut routes = netd["local_prefixes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| RouteDeclaration {
            prefix: prefix(value.as_str().unwrap()),
            kind: RouteKind::Local,
        })
        .chain(
            netd["remote_routes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| RouteDeclaration {
                    prefix: prefix(value["destination"].as_str().unwrap()),
                    kind: RouteKind::Remote,
                }),
        )
        .collect::<Vec<_>>();
    routes.sort_by_key(|route| (route.prefix, route.kind as u64));
    PrepareDeclaration {
        table_id: netd["table_id"].as_u64().unwrap() as u32,
        overlay_router_ipv4: netd["overlay_router_ipv4"]
            .as_str()
            .unwrap()
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .octets(),
        effective_mtu: netd["max_inner_mtu"].as_u64().unwrap() as u16,
        routes,
        exclusions: netd["underlay_ipv4_exclusions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| UnderlayExclusion {
                prefix: prefix(value.as_str().unwrap()),
                kind: UnderlayKind::HubEndpoint,
            })
            .collect(),
        firewall: FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    }
}

fn probe_proxy() {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let success = (|| -> std::io::Result<()> {
            let mut stream = TcpStream::connect_timeout(
                &"127.0.0.1:19002".parse().unwrap(),
                Duration::from_millis(200),
            )?;
            stream.set_read_timeout(Some(Duration::from_secs(1)))?;
            stream.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
            let mut response = [0; 12];
            stream.read_exact(&mut response)?;
            if &response[..8] != b"HTTP/1.0" {
                return Err(std::io::Error::other("proxy HTTP response mismatch"));
            }
            Ok(())
        })()
        .is_ok();
        if success {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Proxy failed through the shared listener"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn committed_ack(registry: &Path, seed: u8) -> bool {
    let name = format!("{seed:02x}").repeat(16);
    let receipt = status(&registry.join(format!("{name}.domain")));
    let acknowledgement = status(&registry.join(format!("{name}.activation")));
    let master = status(&registry.join("listener-master.json"));
    receipt.is_some_and(|receipt| {
        receipt["prepared_ingress"] == false
            && master.is_some_and(|master| master["instance"] == receipt["master_instance"])
            && acknowledgement.as_ref() == Some(&receipt)
    })
}

fn master_workers(pid: u32) -> Vec<candy_process_control::ProcessIdentity> {
    let marker = format!("CANDY_WORKER_MANAGER_PID={pid}");
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let environment = fs::read(entry.path().join("environ")).ok()?;
            if !environment
                .split(|byte| *byte == 0)
                .any(|value| value == marker.as_bytes())
            {
                return None;
            }
            candy_process_control::process_identity(pid).ok()
        })
        .collect()
}

fn reload(socket: &Path, request: serde_json::Value) -> serde_json::Value {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(&serde_json::to_vec(&request).unwrap())
        .unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    serde_json::from_slice(&response).unwrap()
}

fn tun_identity(namespace: &str) -> serde_json::Value {
    let output = Command::new("ip")
        .args(["-n", namespace, "-j", "link", "show", "candy0"])
        .output()
        .unwrap();
    assert!(output.status.success(), "client infrastructure TUN missing");
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()[0]["ifindex"].clone()
}

fn verify_live_reload(
    root: &Path,
    clients: &[String],
    server_plans: &[PathBuf],
    client_pids: &[u32],
    restart_successor_server: bool,
) {
    let server_before: Vec<_> = server_plans
        .iter()
        .map(|path| {
            (
                status(&path.with_file_name("process.json")).unwrap(),
                status(&path.with_file_name("io-process.json")).unwrap(),
            )
        })
        .collect();
    let client_before: Vec<_> = client_pids
        .iter()
        .map(|pid| candy_process_control::process_identity(*pid).unwrap())
        .collect();
    let tuns_before: Vec<_> = clients.iter().map(|name| tun_identity(name)).collect();
    let mut traffic = Vec::new();
    for (domain, namespace) in clients.iter().enumerate() {
        traffic.push(spawn(
            Command::new("ip").args([
                "netns",
                "exec",
                namespace,
                "ping",
                "-D",
                "-O",
                "-I",
                "10.251.1.10",
                "-i",
                "0.05",
                "-c",
                "400",
                "-W",
                "1",
                "10.251.2.10",
            ]),
            &root.join(format!("mbb-ping-{domain}.log")),
        ));
    }
    let mut receipts = Vec::new();
    for round in 1..=2 {
        for domain in 0..clients.len() {
            let fixture = root.join(format!("domain-{domain}/fixture"));
            let generated = Command::new(std::env::var("CANDY_SIGNED_FIXTURE_BINARY").unwrap())
                .env("CANDY_SIGNED_FIXTURE_ADVANCE_POLICY_ROOT", &fixture)
                .env("CANDY_SIGNED_FIXTURE_POLICY_ROUND", round.to_string())
                .output()
                .unwrap();
            assert!(
                generated.status.success(),
                "{}",
                String::from_utf8_lossy(&generated.stderr)
            );
            let socket = root.join(format!("domain-{domain}/client/reload.sock"));
            let transaction = format!("{round:02x}{domain:02x}{}", "a".repeat(60));
            let prepared = reload(
                &socket,
                serde_json::json!({"schema_version":1,"action":"prepare",
                "transaction_id":transaction,"config":fixture.join(format!("client.next-{round}.toml")),
                "status":root.join(format!("domain-{domain}/client/core-status.json"))}),
            );
            assert_eq!(
                prepared["ok"], true,
                "candidate preparation failed: {prepared}"
            );
            probe_proxy();
            let committed = reload(
                &socket,
                serde_json::json!({"schema_version":1,"action":"commit","transaction_id":transaction}),
            );
            assert_eq!(
                committed["ok"], true,
                "bilateral candidate commit failed: {committed}"
            );
            let duplicate = reload(
                &socket,
                serde_json::json!({"schema_version":1,"action":"commit","transaction_id":transaction}),
            );
            assert_eq!(duplicate, committed, "exact commit retry changed outcome");
            receipts.push(serde_json::json!({"round":round,"domain":domain,"prepared":prepared,"committed":committed,"duplicate":duplicate}));
            probe_proxy();
        }
    }
    for (domain, process) in traffic.iter_mut().enumerate() {
        assert!(
            process.0.wait().unwrap().success(),
            "continuous ICMP failed domain={domain}"
        );
        let log = fs::read_to_string(root.join(format!("mbb-ping-{domain}.log"))).unwrap();
        assert!(
            log.contains("400 packets transmitted, 400 received, 0% packet loss"),
            "ICMP loss during candidate MBB domain={domain}: {log}"
        );
    }
    for ((pid, before), (name, tun)) in client_pids
        .iter()
        .zip(&client_before)
        .zip(clients.iter().zip(&tuns_before))
    {
        assert_eq!(
            candy_process_control::process_identity(*pid).unwrap(),
            *before,
            "client restarted during MBB"
        );
        assert_eq!(tun_identity(name), *tun, "MBB replaced client TUN");
    }
    for (plan, (worker, io)) in server_plans.iter().zip(&server_before) {
        assert_eq!(
            status(&plan.with_file_name("process.json")).unwrap(),
            *worker,
            "candidate MBB restarted server domain"
        );
        assert_eq!(
            status(&plan.with_file_name("io-process.json")).unwrap(),
            *io,
            "candidate MBB replaced server TUNIO"
        );
    }
    std::thread::sleep(Duration::from_secs(31));
    probe_proxy();
    let mut redial_server_before = server_before.clone();
    let mut recovered_server = None;
    if restart_successor_server {
        let process_path = server_plans[0].with_file_name("process.json");
        let before = status(&process_path).unwrap();
        let victim = candy_process_control::ProcessIdentity {
            pid: before["pid"].as_u64().unwrap() as u32,
            start_ticks: before["process_start_ticks"].as_u64().unwrap(),
        };
        assert!(candy_process_control::process_is_current(victim));
        assert_eq!(before["policy_generation"], 1);
        assert_eq!(
            unsafe { nix::libc::kill(victim.pid as i32, nix::libc::SIGKILL) },
            0
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(fresh) = status(&process_path) {
                if fresh["pid"] != before["pid"] && committed_ack(&root.join("registry"), 40) {
                    assert_eq!(
                        fresh["policy_generation"], 1,
                        "Cloud static catalog advanced unexpectedly"
                    );
                    let fresh_io = status(&server_plans[0].with_file_name("io-process.json"));
                    if !fresh_io.as_ref().is_some_and(|io| {
                        retained_io_record::matches_worker_recovery(
                            &server_before[0].1,
                            io,
                            fresh["worker_epoch"].as_u64().unwrap(),
                        )
                    }) {
                        assert!(Instant::now() < deadline,
                            "server recovery changed retained TUNIO beyond worker epoch: before={} after={fresh_io:?} worker={fresh}", server_before[0].1);
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    redial_server_before[0] = (fresh.clone(), fresh_io.unwrap());
                    recovered_server = Some(fresh);
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "successor server worker did not recover"
            );
            probe_proxy();
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    unsafe {
        nix::libc::kill(client_pids[0] as i32, nix::libc::SIGKILL);
    }
    unsafe {
        nix::libc::waitpid(client_pids[0] as i32, std::ptr::null_mut(), 0);
    }
    let client_plan = root.join("domain-0/client/plan.json");
    fs::remove_file(client_plan.with_file_name("reload.sock")).unwrap();
    let _redial = spawn(
        Command::new("ip")
            .args(["netns", "exec", &clients[0]])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "signed_mbb_client_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("CANDY_MBB_PLAN", &client_plan)
            .env(
                "CANDY_MBB_CONFIG",
                root.join("domain-0/fixture/client.next-2.toml"),
            )
            .env("CANDY_MBB_IO_EPOCH", "2"),
        &root.join("successor-ordinary-redial.log"),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Command::new("ip")
            .args([
                "netns",
                "exec",
                &clients[0],
                "ping",
                "-q",
                "-I",
                "10.251.1.10",
                "-c",
                "1",
                "-W",
                "1",
                "10.251.2.10",
            ])
            .status()
            .unwrap()
            .success()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ordinary successor Grant redial failed after original reservation expiry"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(tun_identity(&clients[0]), tuns_before[0]);
    for (plan, (worker, io)) in server_plans.iter().zip(&redial_server_before) {
        assert_eq!(
            status(&plan.with_file_name("process.json")).unwrap(),
            *worker,
            "ordinary successor redial replaced server Core"
        );
        assert_eq!(
            status(&plan.with_file_name("io-process.json")).unwrap(),
            *io,
            "ordinary successor redial replaced server TUNIO"
        );
    }
    probe_proxy();
    let mut post_restart_renewal = None;
    if restart_successor_server {
        let fixture = root.join("domain-0/fixture");
        let generated = Command::new(std::env::var("CANDY_SIGNED_FIXTURE_BINARY").unwrap())
            .env("CANDY_SIGNED_FIXTURE_ADVANCE_POLICY_ROOT", &fixture)
            .env("CANDY_SIGNED_FIXTURE_POLICY_ROUND", "3")
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let socket = client_plan.with_file_name("reload.sock");
        let transaction = format!("0300{}", "a".repeat(60));
        let prepared = reload(
            &socket,
            serde_json::json!({
                "schema_version":1,"action":"prepare","transaction_id":transaction,
                "config":fixture.join("client.next-3.toml"),
                "status":client_plan.with_file_name("core-status.json")
            }),
        );
        assert_eq!(
            prepared["ok"], true,
            "post-restart successor prepare failed: {prepared}"
        );
        let committed = reload(
            &socket,
            serde_json::json!({
                "schema_version":1,"action":"commit","transaction_id":transaction
            }),
        );
        assert_eq!(
            committed["ok"], true,
            "post-restart successor commit failed: {committed}"
        );
        assert_eq!(committed["generation"], 4);
        for namespace in clients {
            let output = Command::new("ip")
                .args([
                    "netns",
                    "exec",
                    namespace,
                    "ping",
                    "-q",
                    "-I",
                    "10.251.1.10",
                    "-c",
                    "20",
                    "-i",
                    "0.05",
                    "-W",
                    "1",
                    "10.251.2.10",
                ])
                .output()
                .unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout)
                        .contains("20 packets transmitted, 20 received, 0% packet loss"),
                "post-restart domain did not carry traffic namespace={namespace}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        assert_eq!(tun_identity(&clients[0]), tuns_before[0]);
        for (plan, (worker, io)) in server_plans.iter().zip(&redial_server_before) {
            assert_eq!(
                status(&plan.with_file_name("process.json")).unwrap(),
                *worker,
                "post-restart renewal replaced server Core"
            );
            assert_eq!(
                status(&plan.with_file_name("io-process.json")).unwrap(),
                *io
            );
        }
        assert_eq!(
            status(&server_plans[1].with_file_name("process.json")).unwrap(),
            server_before[1].0,
            "successor recovery restarted another domain"
        );
        probe_proxy();
        post_restart_renewal =
            Some(serde_json::json!({"prepared":prepared,"committed":committed,"icmp_received":20}));
    }
    private_json(
        &root.join("mbb-evidence.json"),
        &serde_json::json!({"gate":"PASS","scope":"bilateral Rust Core candidate protocol with real netd TUN clients and Runtime shared-listener server domains",
        "rounds":receipts,"client_processes":client_before,"client_tun_ifindices":tuns_before,
        "icmp_packets_per_domain":400,"icmp_loss":0,"proxy_survived":true,
        "successor_ordinary_redial_after_original_cap":true,"runtime_cross_process_candidate_handoff":"separate_gate",
        "post_recovery_exact_server_records":redial_server_before,
        "recovered_static_generation_one_server":recovered_server,"post_restart_generation_four_renewal":post_restart_renewal}),
    );
}

pub(super) fn verify() {
    verify_scenario(false, false);
}

pub(super) fn verify_mbb() {
    verify_scenario(true, false);
}

pub(super) fn verify_successor_restart() {
    verify_scenario(true, true);
}

fn verify_scenario(mbb: bool, restart_successor_server: bool) {
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1")
    );
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let _evidence = Evidence(root.to_owned());
    let bridge = Link(format!("cmx{}", std::process::id()));
    ip(&["link", "add", &bridge.0, "type", "bridge"]);
    ip(&["addr", "add", "10.200.0.2/24", "dev", &bridge.0]);
    ip(&["link", "set", &bridge.0, "up"]);
    let registry = root.join("registry");
    let master_directory = root.join("master");
    for directory in [&registry, &master_directory] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut processes = Vec::new();
    let mut namespaces = Vec::new();
    let mut client_names = Vec::new();
    let mut server_plans = Vec::new();
    let mut plans = Vec::new();
    for domain in 0..2 {
        let base = root.join(format!("domain-{domain}"));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = base.join("fixture");
        let mut generator = Command::new(std::env::var("CANDY_SIGNED_FIXTURE_BINARY").unwrap());
        generator
            .arg(&fixture)
            .env(
                "CANDY_SIGNED_FIXTURE_DOMAIN_SEED",
                (40 + domain).to_string(),
            )
            .env("CANDY_SIGNED_FIXTURE_ENDPOINT", "10.200.0.2:18443")
            .env("CANDY_SIGNED_FIXTURE_GRANT_TTL_SECS", "600");
        if mbb {
            generator.env("CANDY_SIGNED_FIXTURE_CONNECTION_LIMIT", "4");
        }
        if domain != 0 {
            generator.env(
                "CANDY_SIGNED_FIXTURE_CERT_SOURCE",
                root.join("domain-0/fixture"),
            );
        }
        let output = generator.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let client = fixture.join("client.toml");
        let text = fs::read_to_string(&client)
            .unwrap()
            .replace("[[peers]]", "[[peers]]\nshared_listener = true");
        fs::write(&client, &text).unwrap();
        let inbound = fixture.join("inbound.toml");
        let text = text
            .split("[[peers]]")
            .next()
            .unwrap()
            .replace("site.projection", "server.projection");
        fs::write(&inbound, text).unwrap();
        fs::set_permissions(&inbound, fs::Permissions::from_mode(0o600)).unwrap();
        for side in 0..2 {
            let path = base.join(if side == 0 { "client" } else { "server" });
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            let namespace = Namespace(format!("cmx-{}-{domain}-{side}", std::process::id()));
            ip(&["netns", "add", &namespace.0]);
            ip(&["-n", &namespace.0, "link", "set", "lo", "up"]);
            ip(&["-n", &namespace.0, "link", "add", "lan0", "type", "dummy"]);
            let lan = if side == 0 {
                "10.251.1.10/24"
            } else {
                "10.251.2.10/24"
            };
            ip(&["-n", &namespace.0, "addr", "add", lan, "dev", "lan0"]);
            ip(&["-n", &namespace.0, "link", "set", "lan0", "up"]);
            if side == 0 {
                let a = format!("cm{domain}a{}", std::process::id());
                let b = format!("cm{domain}b{}", std::process::id());
                ip(&["link", "add", &a, "type", "veth", "peer", "name", &b]);
                ip(&["link", "set", &a, "master", &bridge.0]);
                ip(&["link", "set", &a, "up"]);
                ip(&["link", "set", &b, "netns", &namespace.0]);
                ip(&[
                    "-n",
                    &namespace.0,
                    "addr",
                    "add",
                    &format!("10.200.0.{}/24", 10 + domain),
                    "dev",
                    &b,
                ]);
                ip(&["-n", &namespace.0, "link", "set", &b, "up"]);
                client_names.push(namespace.0.clone());
            }
            let config = if side == 0 { &client } else { &inbound };
            let output = Command::new(core())
                .args(["client", "sdwan", "compile-control", "--config"])
                .arg(config)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let compiled: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let declaration = declaration(&compiled);
            let domain_id = [40 + domain as u8; 16];
            let infra_id = [80 + domain as u8 * 2 + side as u8; 16];
            let ns_path = PathBuf::from(format!("/var/run/netns/{}", namespace.0));
            let ns = fs::metadata(&ns_path).unwrap();
            let spec = InfraSpec {
                infra_id,
                generation: 1,
                netns_device: ns.dev(),
                netns_inode: ns.ino(),
                overlay_router_ipv4: declaration.overlay_router_ipv4,
                mtu: declaration.effective_mtu,
            };
            private_json(
                &path.join("domains.json"),
                &serde_json::json!({"budgets":{"max_domains":1,"front_control_threads":2,"max_control_threads":3,"thread_stack_bytes":262144,"max_total_stack_bytes":786432,"max_pending_control_requests":4,"max_pending_control_bytes":16777216,"max_reserved_fds":128},"domains":[{"domain_id":domain_id,"infra_id":infra_id,"namespace_path":ns_path,"journal_path":path.join("domain.journal"),"table_id":declaration.table_id}]}),
            );
            processes.push(spawn(
                Command::new(std::env::var("CANDY_NETD_TEST_BINARY").unwrap())
                    .args(["--protocol-v2", "--socket"])
                    .arg(path.join("netd.sock"))
                    .args([
                        "--allowed-uid",
                        "0",
                        "--allowed-gid",
                        "0",
                        "--domain-config",
                    ])
                    .arg(path.join("domains.json")),
                &path.join("netd.log"),
            ));
            wait_socket(&path.join("netd.sock"));
            let mut plan = serde_json::json!({"schema_version":1,"netd_socket":path.join("netd.sock"),"tunio":env!("CARGO_BIN_EXE_candy-tunio"),"core":core(),"core_config":config,"core_status":path.join("core-status.json"),"binding_file":path.join("binding.json"),"instance_id":domain_id,"infrastructure":spec,"domain_id":domain_id,"io_epoch":1,"worker_epoch":1,"fencing_token":1,"signed_generation":1,"auth_deadline_unix":compiled["authorization_expires_at_unix"],"declaration":declaration,"routing_namespace":ns_path,"independent_supervision":{"control_socket":path.join("io.sock"),"status":path.join("io-status.json"),"process_record":path.join("io-process.json")},"independent_worker":{"control_socket":path.join("core.sock"),"process_record":path.join("process.json")}});
            if side == 1 {
                plan["shared_listener"] = serde_json::json!({"directory":registry,"server_config":fixture.join("server.toml"),"worker_id":domain+1});
                server_plans.push(path.join("plan.json"));
            }
            private_json(&path.join("plan.json"), &plan);
            plans.push(path.join("plan.json"));
            namespaces.push(namespace);
        }
    }
    let fixture = root.join("domain-0/fixture");
    let master = root.join("master.toml");
    // SIGKILL is a QUIC blackhole: negotiate an explicit bounded idle timeout
    // so the fault gate measures recovery rather than the Linux 120s default.
    fs::write(&master, format!("listen = \"10.200.0.2:18443\"\ncert_pem = {:?}\nkey_pem = {:?}\n[transport]\nkeep_alive_seconds = 1\nidle_timeout_seconds = 4\n[[users]]\nkey_id = \"alice\"\nsecret = \"shared-listener-test-secret-2026\"\n", fixture.join("server.cert.pem"), fixture.join("server.key.pem"))).unwrap();
    fs::set_permissions(&master, fs::Permissions::from_mode(0o600)).unwrap();
    let mut master_index = processes.len();
    processes.push(spawn(
        Command::new(core())
            .args(["server", "proxy-master", "--config"])
            .arg(&master)
            .arg("--directory")
            .arg(&master_directory)
            .arg("--sdwan-registry-directory")
            .arg(&registry),
        &root.join("master.log"),
    ));
    wait_socket(&registry.join("listener-master.json"));
    // Client and server are separate logical hosts. Each Agent owns one
    // supervisor per domain; their infrastructure identities are independent.
    for side in ["client", "server"] {
        if mbb && side == "client" {
            continue;
        }
        let cloud = root.join(format!("cloud-{side}"));
        fs::create_dir(&cloud).unwrap();
        fs::set_permissions(&cloud, fs::Permissions::from_mode(0o700)).unwrap();
        let agent = root.join(format!("agent-{side}.json"));
        let side_plans: Vec<_> = plans
            .iter()
            .filter(|path| path.parent().unwrap().file_name().unwrap() == side)
            .collect();
        private_json(
            &agent,
            &serde_json::json!({"schema_version":1,"status":root.join(format!("agent-{side}-status.json")),"budgets":{"max_domain_supervisors":2,"max_managed_threads":3,"thread_stack_bytes":1048576,"max_managed_stack_bytes":3145728,"event_capacity":8,"cloud_iteration_deadline_ms":1000,"shutdown_timeout_ms":10000},"cloud":{"state_dir":cloud,"run_dir":root,"interval_ms":100,"retry_initial_ms":100,"retry_max_ms":1000},"domain_plans":side_plans}),
        );
        processes.push(spawn(
            Command::new(std::env::var("CANDY_AGENT_TEST_BINARY").unwrap())
                .args([
                    "experimental-runtime-agent",
                    "--experimental-packet-port-ipc",
                    "--config",
                ])
                .arg(agent),
            &root.join(format!("agent-{side}.log")),
        ));
    }
    let mut mbb_client_pids = Vec::new();
    if mbb {
        for (domain, namespace) in client_names.iter().enumerate() {
            processes.push(spawn(
                Command::new("ip")
                    .args(["netns", "exec", namespace])
                    .arg(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "signed_mbb_client_helper",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env(
                        "CANDY_MBB_PLAN",
                        root.join(format!("domain-{domain}/client/plan.json")),
                    ),
                &root.join(format!("mbb-client-{domain}.log")),
            ));
            mbb_client_pids.push(processes.last().unwrap().0.id());
        }
    }
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        for process in processes.iter_mut().rev().take(2) {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "Runtime Agent exited during activation"
            );
        }
        let active = (40..42).all(|seed| committed_ack(&registry, seed));
        let traffic = client_names.iter().all(|namespace| {
            Command::new("ip")
                .args([
                    "netns",
                    "exec",
                    namespace,
                    "ping",
                    "-q",
                    "-I",
                    "10.251.1.10",
                    "-c",
                    "1",
                    "-W",
                    "1",
                    "10.251.2.10",
                ])
                .output()
                .unwrap()
                .status
                .success()
        });
        if active && traffic {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Runtime shared listener failed exact activation and real ICMP"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // Keep both actual Runtime workers alive while admitting Proxy work.
    let transport = fs::read_to_string(fixture.join("transport.toml")).unwrap();
    let pin = transport
        .lines()
        .find(|line| line.starts_with("server_pin ="))
        .unwrap();
    let proxy = root.join("proxy.toml");
    fs::write(&proxy, format!("server = \"10.200.0.2:18443\"\nserver_name = \"peer.candy.test\"\n{pin}\nkey_id = \"alice\"\nsecret = \"shared-listener-test-secret-2026\"\n[[forwards]]\nnetwork = \"tcp\"\nlocal = \"127.0.0.1:19002\"\ntarget = \"127.0.0.1:19001\"\n")).unwrap();
    fs::set_permissions(&proxy, fs::Permissions::from_mode(0o600)).unwrap();
    processes.push(spawn(
        Command::new("python3").args(["-m", "http.server", "19001", "--bind", "127.0.0.1"]),
        &root.join("http.log"),
    ));
    processes.push(spawn(
        Command::new(core())
            .args(["client", "--format", "carrier-toml", "--config"])
            .arg(proxy),
        &root.join("proxy.log"),
    ));
    probe_proxy();
    if mbb {
        verify_live_reload(
            root,
            &client_names,
            &server_plans,
            &mbb_client_pids,
            restart_successor_server,
        );
        return;
    }
    let before: Vec<_> = server_plans
        .iter()
        .map(|path| status(&path.with_file_name("io-process.json")).unwrap())
        .collect();
    let victim = status(&server_plans[0].with_file_name("process.json")).unwrap()["pid"]
        .as_u64()
        .unwrap();
    assert!(Command::new("kill")
        .args(["-KILL", &victim.to_string()])
        .status()
        .unwrap()
        .success());
    probe_proxy();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let record = status(&server_plans[0].with_file_name("process.json"));
        if record
            .as_ref()
            .is_some_and(|record| record["pid"].as_u64() != Some(victim))
            && (40..42).all(|seed| committed_ack(&registry, seed))
            && client_names.iter().all(|namespace| {
                Command::new("ip")
                    .args([
                        "netns",
                        "exec",
                        namespace,
                        "ping",
                        "-q",
                        "-I",
                        "10.251.1.10",
                        "-c",
                        "1",
                        "-W",
                        "1",
                        "10.251.2.10",
                    ])
                    .output()
                    .unwrap()
                    .status
                    .success()
            })
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Runtime failed to restore domain worker"
        );
    }
    for (path, before) in server_plans.iter().zip(before) {
        assert_eq!(
            status(&path.with_file_name("io-process.json")).unwrap()["pid"],
            before["pid"],
            "domain worker recovery replaced TUNIO"
        );
    }
    probe_proxy();
    for round in 0..2 {
        let master_identity = status(&registry.join("listener-master.json")).unwrap();
        let workers: Vec<_> = server_plans
            .iter()
            .map(|path| status(&path.with_file_name("process.json")).unwrap())
            .collect();
        let old_master_workers = master_workers(processes[master_index].0.id());
        assert_eq!(
            old_master_workers.len(),
            1,
            "initial Proxy worker population differs"
        );
        processes[master_index].0.kill().unwrap();
        processes[master_index].0.wait().unwrap();
        master_index = processes.len();
        processes.push(spawn(
            Command::new(core())
                .args(["server", "proxy-master", "--config"])
                .arg(&master)
                .arg("--directory")
                .arg(&master_directory)
                .arg("--sdwan-registry-directory")
                .arg(&registry),
            &root.join(format!("master-restarted-{round}.log")),
        ));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let fresh = status(&registry.join("listener-master.json"))
                .is_some_and(|value| value["instance"] != master_identity["instance"]);
            let traffic = client_names.iter().all(|namespace| {
                Command::new("ip")
                    .args([
                        "netns",
                        "exec",
                        namespace,
                        "ping",
                        "-q",
                        "-I",
                        "10.251.1.10",
                        "-c",
                        "1",
                        "-W",
                        "1",
                        "10.251.2.10",
                    ])
                    .output()
                    .unwrap()
                    .status
                    .success()
            });
            if fresh && (40..42).all(|seed| committed_ack(&registry, seed)) && traffic {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "master restart failed fresh exact ACK and real ICMP"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        for (path, worker) in server_plans.iter().zip(workers) {
            assert_eq!(
                status(&path.with_file_name("process.json")).unwrap()["pid"],
                worker["pid"],
                "master restart replaced Runtime worker"
            );
        }
        probe_proxy();
        let deadline = Instant::now() + Duration::from_secs(10);
        while old_master_workers
            .iter()
            .any(|identity| candy_process_control::process_is_current(*identity))
        {
            assert!(
                Instant::now() < deadline,
                "old master left a live orphan worker"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    eprintln!("runtime_shared_listener domains=2 exact_activation_ack=true real_icmp=true proxy_http=true worker_recovery=true tunio_preserved=true master_restarts=2 domain_workers_preserved=true no_live_orphan_workers=true");
    drop(processes);
    drop(namespaces);
}
