//! Real shared host lifecycle and signed four-domain data-plane gates.

use super::*;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct Host {
    child: Child,
    socket: PathBuf,
    slot: PathBuf,
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.socket);
    }
}

fn request(socket: &Path, operation: &str) -> serde_json::Value {
    request_for_domain(socket, operation, "")
}

fn request_for_domain(socket: &Path, operation: &str, instance: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    // The host protocol starts with a one-byte SCM_RIGHTS message. Probe and
    // retire carry no descriptors, so a normal byte write is sufficient for
    // this lifecycle-only gate.
    stream.write_all(&[0]).unwrap();
    let body = serde_json::json!({
        "schema_version": 1,
        "operation": operation,
        "instance": instance,
        "arguments": [],
        "namespace": false
    });
    stream
        .write_all(&serde_json::to_vec(&body).unwrap())
        .unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    serde_json::from_slice(&reply).unwrap()
}

fn verify_failed_domain_isolated(host: &Host) {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    use std::io::IoSlice;
    use std::os::unix::net::UnixDatagram;

    let (packet, _peer) = UnixDatagram::pair().unwrap();
    let descriptors = [packet.as_raw_fd()];
    let mut stream = UnixStream::connect(&host.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(
        sendmsg::<()>(
            stream.as_raw_fd(),
            &[IoSlice::new(&[0])],
            &[ControlMessage::ScmRights(&descriptors)],
            MsgFlags::empty(),
            None
        )
        .unwrap(),
        1
    );
    let body = serde_json::json!({"schema_version":1,"operation":"start",
        "instance":"invalid-domain-fixture","arguments":["run","--invalid-domain-fixture"],
        "namespace":false});
    stream
        .write_all(&serde_json::to_vec(&body).unwrap())
        .unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    let accepted: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(accepted["accepted"], true, "{accepted}");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let response = request_for_domain(&host.socket, "probe", "invalid-domain-fixture");
        if response["running"] == false {
            assert_eq!(response["exit_code"], 1, "{response}");
            assert_eq!(response["code"], "domain_failed", "{response}");
            assert!(response["detail"]
                .as_str()
                .unwrap()
                .contains("invalid-domain-fixture"));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "invalid domain failed to terminate"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        request_for_domain(&host.socket, "forget", "invalid-domain-fixture")["accepted"],
        true
    );
    let response = request(&host.socket, "probe");
    assert_eq!(response["live_domains"], 0);
    assert_eq!(response["completed_domains"], 0);
}

fn start(root: &Path, id: usize) -> Host {
    let socket = root.join(format!("host-{id}.sock"));
    let slot = root.join(format!("worker-{id}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&slot)
        .unwrap();
    let fd = file.as_raw_fd();
    assert_eq!(fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty())).unwrap(), 0);
    let mut command = Command::new(core());
    command
        .args(["client", "sdwan", "host", "--socket"])
        .arg(&socket)
        .args(["--worker-id", &id.to_string()])
        .args(["--worker-slot-fd", &fd.to_string()])
        .arg("--worker-slot-file")
        .arg(&slot)
        .args(["--max-domains", "64"]);
    unsafe {
        command.pre_exec(move || {
            nix::fcntl::fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty()))
                .map(|_| ())
                .map_err(|error| std::io::Error::other(error.to_string()))
        });
    }
    let child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "shared host socket readiness timeout"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let response = request(&socket, "probe");
    assert_eq!(response["accepted"], true, "{response}");
    Host {
        child,
        socket,
        slot,
    }
}

pub(super) fn verify() {
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1")
    );
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut hosts = Vec::new();
    for desired in [1usize, 2, 4, 2, 1] {
        while hosts.len() < desired {
            hosts.push(start(root.path(), hosts.len() + 1));
        }
        while hosts.len() > desired {
            let mut host = hosts.pop().unwrap();
            let response = request(&host.socket, "retire");
            assert_eq!(response["accepted"], true, "{response}");
            let deadline = Instant::now() + Duration::from_secs(3);
            while host.child.try_wait().unwrap().is_none() {
                assert!(Instant::now() < deadline, "shared host retire timeout");
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(!host.slot.as_os_str().is_empty());
        }
        assert_eq!(hosts.len(), desired);
        verify_failed_domain_isolated(&hosts[0]);
        for (index, host) in hosts.iter().enumerate() {
            let response = request(&host.socket, "probe");
            assert_eq!(response["accepted"], true, "host {index}: {response}");
            assert_eq!(response["live_domains"], 0);
            assert_eq!(response["completed_domains"], 0);
        }
    }
}

struct Domain {
    root: PathBuf,
    client: Namespace,
    server: Namespace,
    netd: InfrastructureClient,
    domain: [u8; 16],
    infra: [u8; 16],
    server_process: Process,
}

struct SharedEvidence(PathBuf);
impl Drop for SharedEvidence {
    fn drop(&mut self) {
        let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") else {
            return;
        };
        fn copy(source: &Path, destination: &Path) -> std::io::Result<()> {
            fs::create_dir_all(destination)?;
            for entry in fs::read_dir(source)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    copy(&entry.path(), &destination.join(entry.file_name()))?;
                } else if matches!(
                    entry.path().extension().and_then(|part| part.to_str()),
                    Some("json" | "log" | "journal")
                ) {
                    fs::copy(entry.path(), destination.join(entry.file_name()))?;
                }
            }
            Ok(())
        }
        let _ = copy(
            &self.0,
            &PathBuf::from(destination).join("shared-pool-state"),
        );
    }
}

fn in_namespace(namespace: &str, program: &str, arguments: &[&str]) -> Command {
    let mut command = Command::new("ip");
    command
        .args(["netns", "exec", namespace, program])
        .args(arguments);
    command
}

fn server(root: &Path, namespace: &str, epoch: u64) -> Process {
    let log = fs::File::create(root.join(format!("server-{epoch}.log"))).unwrap();
    Process(
        in_namespace(
            namespace,
            std::env::current_exe().unwrap().to_str().unwrap(),
            &[
                "--exact",
                "signed_server_helper",
                "--ignored",
                "--nocapture",
            ],
        )
        .env("CANDY_SIGNED_TEST_ROOT", root)
        .env("CANDY_SIGNED_SERVER_EPOCH", epoch.to_string())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap(),
    )
}

fn ping(domain: &Domain) -> bool {
    in_namespace(
        &domain.client.0,
        "ping",
        &[
            "-q",
            "-I",
            "10.251.1.10",
            "-c",
            "1",
            "-W",
            "1",
            "10.251.2.10",
        ],
    )
    .output()
    .unwrap()
    .status
    .success()
}

fn ready(domain: &mut Domain, worker: usize) -> Option<serde_json::Value> {
    let record = status(&domain.root.join("worker-process.json"))?;
    let desired = status(&domain.root.join("plan.json"))?;
    let current = candy_process_control::process_identity(record["pid"].as_u64()? as u32).ok()?;
    if current.start_ticks != record["process_start_ticks"].as_u64()?
        || desired["placement"]["shared"]["identity"]["pid"] != record["pid"]
    {
        return None;
    }
    let proof = status(Path::new(record["status_path"].as_str()?))?;
    if proof["lifecycle"] != "active"
        || proof["worker_placement"]["worker_id"] != worker
        || proof["worker_placement"]["revision"] != desired["placement"]["revision"]
    {
        return None;
    }
    let (body, _) = domain
        .netd
        .exchange_in_domain(domain.domain, domain.infra, Operation::ForwardStatus)
        .ok()?;
    if !matches!(body, Body::ForwardStatus { phase: Some(candy_netd_proto::v2::Phase::Active), failed_prefixes, .. } if failed_prefixes.is_empty())
    {
        return None;
    }
    Some(record)
}

fn wait_all(domains: &mut [Domain], workers: usize) -> Vec<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let snapshots = domains
            .iter_mut()
            .enumerate()
            .map(|(index, domain)| ready(domain, index % workers + 1))
            .collect::<Option<Vec<_>>>();
        if let Some(snapshots) = snapshots {
            if domains.iter().all(ping) {
                return snapshots;
            }
        }
        assert!(
            Instant::now() < deadline,
            "shared domains failed convergence workers={workers}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn link(domain: &Domain) -> serde_json::Value {
    serde_json::from_slice(
        &Command::new("ip")
            .args([
                "-n",
                &domain.client.0,
                "-j",
                "addr",
                "show",
                "dev",
                "candy0",
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
}

/// Real signed four-domain, four-client/four-server namespace gate. It uses
/// one Runtime Agent and one shared worker pool, never one manager per domain.
pub(super) fn verify_domains() {
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1")
    );
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let _evidence = SharedEvidence(root.to_owned());
    let pool = root.join("pool");
    fs::create_dir(&pool).unwrap();
    fs::set_permissions(&pool, fs::Permissions::from_mode(0o700)).unwrap();
    let desired = pool.join("desired.json");
    private_json(
        &desired,
        &serde_json::json!({"schema_version":1,"revision":1,"workers":1}),
    );
    let mut processes = Vec::new();
    let mut domains = Vec::new();
    let mut plans = Vec::new();
    for index in 0..4usize {
        let path = root.join(format!("domain-{index}"));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let client = Namespace(format!("csh-{}-{index}-c", std::process::id()));
        let remote = Namespace(format!("csh-{}-{index}-s", std::process::id()));
        for namespace in [&client.0, &remote.0] {
            ip(&["netns", "add", namespace]);
            ip(&["-n", namespace, "link", "set", "lo", "up"]);
        }
        let a = format!("cs{index}a");
        let b = format!("cs{index}b");
        ip(&["link", "add", &a, "type", "veth", "peer", "name", &b]);
        ip(&["link", "set", &a, "netns", &client.0]);
        ip(&["link", "set", &b, "netns", &remote.0]);
        for (namespace, interface, address, lan) in [
            (&client.0, a.as_str(), "10.200.0.1/24", "10.251.1.10/24"),
            (&remote.0, b.as_str(), "10.200.0.2/24", "10.251.2.10/24"),
        ] {
            ip(&["-n", namespace, "addr", "add", address, "dev", interface]);
            ip(&["-n", namespace, "link", "set", interface, "up"]);
            ip(&["-n", namespace, "link", "add", "lan0", "type", "dummy"]);
            ip(&["-n", namespace, "addr", "add", lan, "dev", "lan0"]);
            ip(&["-n", namespace, "link", "set", "lan0", "up"]);
        }
        let seed = 32 + index as u8;
        let output = Command::new(std::env::var("CANDY_SIGNED_FIXTURE_BINARY").unwrap())
            .arg(path.join("fixture"))
            .env("CANDY_SIGNED_FIXTURE_DOMAIN_SEED", seed.to_string())
            .env("CANDY_SIGNED_FIXTURE_ENDPOINT", "10.200.0.2:18443")
            .env("CANDY_SIGNED_FIXTURE_GRANT_TTL_SECS", "600")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(core())
            .args(["client", "sdwan", "compile-control", "--config"])
            .arg(path.join("fixture/client.toml"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let compiled: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let domain = [seed; 16];
        let infra = [64 + index as u8; 16];
        let ns_path = PathBuf::from(format!("/var/run/netns/{}", client.0));
        let ns = fs::metadata(&ns_path).unwrap();
        let spec = InfraSpec {
            infra_id: infra,
            generation: 1,
            netns_device: ns.dev(),
            netns_inode: ns.ino(),
            overlay_router_ipv4: [100, 64, 0, 1],
            mtu: 1180,
        };
        let table = compiled["netd"]["table_id"].as_u64().unwrap();
        private_json(
            &path.join("domains.json"),
            &serde_json::json!({"budgets":{"max_domains":1,"front_control_threads":2,"max_control_threads":3,"thread_stack_bytes":262144,"max_total_stack_bytes":786432,"max_pending_control_requests":4,"max_pending_control_bytes":16777216,"max_reserved_fds":128},"domains":[{"domain_id":domain,"infra_id":infra,"namespace_path":ns_path,"journal_path":path.join("domain.journal"),"table_id":table}]}),
        );
        let netd = std::env::var("CANDY_NETD_TEST_BINARY").unwrap();
        processes.push(Process(
            Command::new(&netd)
                .args(["--protocol-v2", "--socket"])
                .arg(path.join("netd.sock"))
                .args([
                    "--allowed-uid",
                    "0",
                    "--allowed-gid",
                    "0",
                    "--domain-config",
                ])
                .arg(path.join("domains.json"))
                .spawn()
                .unwrap(),
        ));
        processes.push(Process(
            in_namespace(&remote.0, &netd, &["--protocol-v2", "--socket"])
                .arg(path.join("server-netd.sock"))
                .args([
                    "--allowed-uid",
                    "0",
                    "--allowed-gid",
                    "0",
                    "--infrastructure-journal",
                ])
                .arg(path.join("server-infra.journal"))
                .spawn()
                .unwrap(),
        ));
        wait_socket(&path.join("netd.sock"));
        wait_socket(&path.join("server-netd.sock"));
        let server_process = server(&path, &remote.0, 1);
        let prefix = |address, len| Ipv4Prefix::new(address, len).unwrap();
        let declaration = PrepareDeclaration {
            table_id: table as u32,
            overlay_router_ipv4: [100, 64, 0, 1],
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
        let plan = path.join("plan.json");
        private_json(
            &plan,
            &serde_json::json!({"schema_version":1,"netd_socket":path.join("netd.sock"),"tunio":env!("CARGO_BIN_EXE_candy-tunio"),"core":core(),"core_config":path.join("fixture/client.toml"),"core_status":path.join("client-status.json"),"binding_file":path.join("binding.json"),"instance_id":domain,"infrastructure":spec,"domain_id":domain,"io_epoch":1,"worker_epoch":1,"fencing_token":1,"signed_generation":1,"auth_deadline_unix":compiled["authorization_expires_at_unix"],"declaration":declaration,"routing_namespace":ns_path,"independent_supervision":{"control_socket":path.join("io-control.sock"),"status":path.join("io-status.json"),"process_record":path.join("io-process.json")},"independent_worker":{"control_socket":path.join("worker-control.sock"),"process_record":path.join("worker-process.json")}}),
        );
        plans.push(plan);
        domains.push(Domain {
            root: path.clone(),
            client,
            server: remote,
            netd: InfrastructureClient::new(path.join("netd.sock"), [seed; 16]),
            domain,
            infra,
            server_process,
        });
    }
    fs::create_dir(root.join("cloud")).unwrap();
    fs::set_permissions(root.join("cloud"), fs::Permissions::from_mode(0o700)).unwrap();
    let config = root.join("agent.json");
    private_json(
        &config,
        &serde_json::json!({"schema_version":1,"status":root.join("agent-status.json"),"budgets":{"max_domain_supervisors":4,"max_managed_threads":5,"thread_stack_bytes":1048576,"max_managed_stack_bytes":5242880,"event_capacity":8,"cloud_iteration_deadline_ms":1000,"shutdown_timeout_ms":10000},"cloud":{"state_dir":root.join("cloud"),"run_dir":root,"interval_ms":100,"retry_initial_ms":100,"retry_max_ms":1000},"domain_plans":plans,"shared_pool":{"desired_file":desired,"directory":pool,"core":core(),"max_workers":4,"max_domains_per_worker":8,"max_domain_threads":24,"max_domain_stack_bytes":25165824,"max_reserved_fds":256}}),
    );
    let log = fs::File::create(root.join("agent.log")).unwrap();
    let mut agent = Process(
        Command::new(std::env::var("CANDY_AGENT_TEST_BINARY").unwrap())
            .args([
                "experimental-runtime-agent",
                "--experimental-packet-port-ipc",
                "--config",
            ])
            .arg(config)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let original = wait_all(&mut domains, 1);
    let mut traffic = domains
        .iter()
        .map(|domain| {
            let output = fs::File::create(domain.root.join("continuous-ping.log")).unwrap();
            Process(
                in_namespace(
                    &domain.client.0,
                    "ping",
                    &[
                        "-n",
                        "-D",
                        "-I",
                        "10.251.1.10",
                        "-i",
                        "0.05",
                        "-W",
                        "1",
                        "10.251.2.10",
                    ],
                )
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let io = domains
        .iter()
        .map(|domain| status(&domain.root.join("io-process.json")).unwrap())
        .collect::<Vec<_>>();
    let links = domains.iter().map(link).collect::<Vec<_>>();
    let mut evidence = Vec::new();
    for (revision, workers) in [1usize, 2, 4, 2, 1].into_iter().enumerate() {
        private_json(
            &desired,
            &serde_json::json!({"schema_version":1,"revision":revision+1,"workers":workers}),
        );
        let records = wait_all(&mut domains, workers);
        for process in &mut traffic {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "connected traffic process exited during scale"
            );
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let host_metrics = loop {
            let mut metrics = Vec::new();
            for id in 1..=4 {
                if let Some(receipt) = status(&pool.join(format!("host-{id}.json"))) {
                    let identity: candy_process_control::ProcessIdentity =
                        serde_json::from_value(receipt["host"]["identity"].clone()).unwrap();
                    if candy_process_control::process_is_current(identity) {
                        let reply = request(
                            Path::new(receipt["host"]["socket"].as_str().unwrap()),
                            "probe",
                        );
                        let fd_count = fs::read_dir(format!("/proc/{}/fd", identity.pid))
                            .unwrap()
                            .count();
                        let thread_count = fs::read_dir(format!("/proc/{}/task", identity.pid))
                            .unwrap()
                            .count();
                        assert!(
                            fd_count <= 256
                                && thread_count
                                    <= 1 + 3 * reply["live_domains"].as_u64().unwrap() as usize,
                            "host descriptor/thread budget exceeded"
                        );
                        metrics.push(serde_json::json!({"identity":identity,"domains":reply,"fds":fd_count,"threads":thread_count}));
                    }
                }
            }
            if metrics.len() == workers
                && metrics
                    .iter()
                    .all(|item| item["domains"]["completed_domains"] == 0)
            {
                break metrics;
            }
            assert!(
                Instant::now() < deadline,
                "shared host retirement or completed-domain credits leaked"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        let pids = records
            .iter()
            .map(|record| record["pid"].as_u64().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            pids.len(),
            workers,
            "domains did not share exact requested host count"
        );
        for (index, domain) in domains.iter().enumerate() {
            assert_eq!(link(domain), links[index], "scale replaced TUN");
            assert_eq!(
                status(&domain.root.join("io-process.json")).unwrap()["pid"],
                io[index]["pid"]
            );
            for field in [
                "policy_generation",
                "auth_deadline_unix",
                "authorization_snapshot_sha256",
            ] {
                assert_eq!(records[index][field], original[index][field]);
            }
        }
        evidence
            .push(serde_json::json!({"workers":workers,"records":records,"hosts":host_metrics}));
    }
    // One unavailable peer must not kill its shared host or affect other domains.
    domains[0].server_process.0.kill().unwrap();
    domains[0].server_process.0.wait().unwrap();
    std::thread::sleep(Duration::from_secs(2));
    for domain in &domains[1..] {
        assert!(ping(domain), "single-domain peer failure propagated");
    }
    domains[0].server_process = server(&domains[0].root, &domains[0].server.0, 2);
    wait_all(&mut domains, 1);
    private_json(
        &desired,
        &serde_json::json!({"schema_version":1,"revision":10,"workers":2}),
    );
    let before = wait_all(&mut domains, 2);
    unsafe {
        nix::libc::kill(
            before[0]["pid"].as_u64().unwrap() as i32,
            nix::libc::SIGKILL,
        );
    }
    assert!(ping(&domains[1]), "unrelated host failed with crashed host");
    let after = wait_all(&mut domains, 2);
    for process in &mut traffic {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "connected traffic process exited during fault recovery"
        );
    }
    assert_ne!(before[0]["pid"], after[0]["pid"]);
    assert_eq!(before[1]["pid"], after[1]["pid"]);
    for (index, domain) in domains.iter().enumerate() {
        assert_eq!(link(domain), links[index]);
        assert_eq!(
            status(&domain.root.join("io-process.json")).unwrap()["pid"],
            io[index]["pid"]
        );
    }
    evidence.push(serde_json::json!({"fault":"host_crash","before":before,"after":after}));
    if let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") {
        let destination = PathBuf::from(destination);
        fs::create_dir_all(&destination).unwrap();
        private_json(
            &destination.join("shared-pool.json"),
            &serde_json::json!(evidence),
        );
        fs::copy(
            root.join("agent.log"),
            destination.join("shared-pool-agent.log"),
        )
        .unwrap();
    }
    unsafe {
        nix::libc::kill(agent.0.id() as i32, nix::libc::SIGTERM);
    }
    assert!(agent.0.wait().unwrap().success());
    drop(processes);
}
