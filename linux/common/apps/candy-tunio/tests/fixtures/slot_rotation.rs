//! Real one-domain-per-slot rotation. This is not the shared multi-domain F08 gate.

use super::*;
use candy_netd_proto::v2::{ForwardOwner, Phase};
use candy_process_control::{process_identity, process_is_current, ProcessIdentity};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;

struct Snapshot {
    record: Value,
    proof: Value,
    io: Value,
    owner: ForwardOwner,
}

fn snapshot(root: &Path, client: &mut ClientControl) -> Option<Snapshot> {
    let record = status(&root.join("worker-process.json"))?;
    let proof = status(Path::new(record["status_path"].as_str()?))?;
    let io = status(&root.join("io-process.json"))?;
    let (
        Body::ForwardStatus {
            owner: Some(owner),
            phase: Some(Phase::Active),
            failed_prefixes,
            ..
        },
        _,
    ) = client.exchange(Operation::ForwardStatus).ok()?
    else {
        return None;
    };
    if !failed_prefixes.is_empty()
        || proof["lifecycle"] != "active"
        || proof["pid"] != record["pid"]
    {
        return None;
    }
    let current = process_identity(record["pid"].as_u64()? as u32).ok()?;
    if current.start_ticks != record["process_start_ticks"].as_u64()?
        || record["worker_epoch"] != owner.worker_epoch
        || proof["policy_generation"] != owner.signed_generation
    {
        return None;
    }
    Some(Snapshot {
        record,
        proof,
        io,
        owner,
    })
}

fn publish(root: &Path, plan: &Value) {
    let next = root.join("placement-next.json");
    private_json(&next, plan);
    fs::rename(next, root.join("plan.json")).unwrap();
}

fn assert_fixed(
    root: &Path,
    current: &Snapshot,
    original: &Snapshot,
    link: &impl Fn() -> Vec<u8>,
    original_link: &[u8],
) {
    assert_eq!(
        current.io["pid"], original.io["pid"],
        "domain rotation restarted TUNIO"
    );
    assert_eq!(
        current.io["process_start_ticks"],
        original.io["process_start_ticks"]
    );
    assert_eq!(current.io["io_epoch"], original.io["io_epoch"]);
    let io_identity = ProcessIdentity {
        pid: original.io["pid"].as_u64().unwrap() as u32,
        start_ticks: original.io["process_start_ticks"].as_u64().unwrap(),
    };
    assert!(process_is_current(io_identity));
    assert_eq!(
        link(),
        original_link,
        "domain rotation changed real kernel TUN identity/state"
    );
    assert_eq!(
        current.record["policy_generation"],
        original.record["policy_generation"]
    );
    assert_eq!(
        current.record["authorization_snapshot_sha256"],
        original.record["authorization_snapshot_sha256"]
    );
    assert_eq!(
        current.record["auth_deadline_unix"],
        original.record["auth_deadline_unix"]
    );
    assert_eq!(
        status(&root.join("io-status.json")).unwrap()["auth_deadline_unix"],
        original.record["auth_deadline_unix"]
    );
    assert!(
        current.owner.auth_deadline_mono_ms <= original.owner.auth_deadline_mono_ms,
        "same signed authority expanded the original monotonic cap"
    );
    let actual = &current.proof["worker_placement"];
    let effective = status(Path::new(
        current.record["effective_plan_file"].as_str().unwrap(),
    ))
    .unwrap();
    let desired = &effective["placement"];
    assert_eq!(actual["worker_id"], desired["target_worker_id"]);
    assert_eq!(actual["revision"], desired["revision"]);
    let worker_id = actual["worker_id"].as_u64().unwrap();
    let slot = Path::new(desired["pool_directory"].as_str().unwrap())
        .join(format!("worker-{worker_id}.lock"));
    let expected = fs::metadata(&slot).unwrap();
    let inherited = fs::metadata(format!(
        "/proc/{}/fd/{}",
        current.record["pid"].as_u64().unwrap(),
        actual["slot_fd"].as_i64().unwrap()
    ))
    .unwrap();
    assert_eq!(
        (inherited.dev(), inherited.ino()),
        (expected.dev(), expected.ino())
    );
    assert_eq!(actual["slot_device"], expected.dev());
    assert_eq!(actual["slot_inode"], expected.ino());
    let competitor = File::open(slot).unwrap();
    assert_eq!(
        unsafe {
            nix::libc::flock(
                competitor.as_raw_fd(),
                nix::libc::LOCK_EX | nix::libc::LOCK_NB,
            )
        },
        -1,
        "actual running Core does not hold the manager-selected exclusive slot"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(nix::libc::EWOULDBLOCK)
    );
}

struct Load {
    processes: Vec<Process>,
    logs: Vec<PathBuf>,
}

impl Load {
    fn start(root: &Path, namespace: &str) -> Self {
        let mut load = Self {
            processes: Vec::new(),
            logs: Vec::new(),
        };
        // Preserve the live kernel transition and ICMP error source even when
        // the original traffic-survival assertion fails. These collectors do
        // not send traffic or modify routes.
        for (label, remote) in [("client", false), ("server", true)] {
            for (kind, program, arguments) in [
                ("network", "ip", vec!["-ts", "monitor", "all"]),
                ("icmp", "python3", vec!["-u", "-c",
                    "import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); print('icmp_capture_started',time.time(),flush=True)\nwhile True:\n p,a=s.recvfrom(65535); h=(p[0]&15)*4; print('time=',time.time(),'source=',a[0],'type=',p[h] if len(p)>h else -1,'code=',p[h+1] if len(p)>h+1 else -1,'packet=',p.hex(),flush=True)"]),
            ] {
                let path = root.join(format!("placement-{label}-{kind}-monitor.log"));
                let log = File::create(&path).unwrap();
                let mut command = if remote {
                    let mut command = Command::new("ip");
                    command.args(["netns", "exec", namespace, program]);
                    command
                } else {
                    Command::new(program)
                };
                command.args(arguments).stdout(log.try_clone().unwrap()).stderr(log);
                load.processes.push(Process(command.spawn().unwrap()));
                load.logs.push(path);
            }
        }
        for (port, direction) in [(5207, "upload"), (5208, "download")] {
            let server_log = root.join(format!("placement-{direction}-server.log"));
            let log = File::create(&server_log).unwrap();
            load.processes.push(Process(
                Command::new("ip")
                    .args([
                        "netns",
                        "exec",
                        namespace,
                        "iperf3",
                        "-s",
                        "-B",
                        "10.251.2.10",
                        "-p",
                        &port.to_string(),
                    ])
                    .stdout(log.try_clone().unwrap())
                    .stderr(log)
                    .spawn()
                    .unwrap(),
            ));
            load.logs.push(server_log);
        }
        std::thread::sleep(Duration::from_millis(250));
        for (port, direction) in [(5207, "upload"), (5208, "download")] {
            let client_log = root.join(format!("placement-{direction}-client.log"));
            let log = File::create(&client_log).unwrap();
            let mut command = Command::new("iperf3");
            command.args([
                "-c",
                "10.251.2.10",
                "-B",
                "10.251.1.10",
                "-p",
                &port.to_string(),
                "-u",
                "-b",
                "8M",
                "-l",
                "1000",
                "-t",
                "180",
                "-i",
                "1",
                "--forceflush",
            ]);
            if direction == "download" {
                command.arg("-R");
            }
            load.processes.push(Process(
                command
                    .stdout(log.try_clone().unwrap())
                    .stderr(log)
                    .spawn()
                    .unwrap(),
            ));
            load.logs.push(client_log);
        }
        load
    }

    fn assert_alive(&mut self) {
        for process in &mut self.processes {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "continuous bidirectional test load stopped before gate completed"
            );
        }
    }
}

impl Drop for Load {
    fn drop(&mut self) {
        if let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") {
            let destination = PathBuf::from(destination);
            let _ = fs::create_dir_all(&destination);
            for log in &self.logs {
                let _ = fs::copy(log, destination.join(log.file_name().unwrap()));
            }
        }
    }
}

fn progress(
    root: &Path,
    client: &mut ClientControl,
    load: &mut Load,
    worker: &Snapshot,
) -> Snapshot {
    let before_rx = worker.proof["counters"]["tun_bytes_received"]
        .as_u64()
        .unwrap();
    let before_tx = worker.proof["counters"]["tun_bytes_sent"].as_u64().unwrap();
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        load.assert_alive();
        if let Some(current) = snapshot(root, client) {
            assert_eq!(
                current.record["pid"], worker.record["pid"],
                "unexpected extra worker replacement"
            );
            if current.proof["counters"]["tun_bytes_received"]
                .as_u64()
                .unwrap()
                >= before_rx + 65536
                && current.proof["counters"]["tun_bytes_sent"]
                    .as_u64()
                    .unwrap()
                    >= before_tx + 65536
            {
                return current;
            }
        }
        assert!(
            Instant::now() < deadline,
            "both real TUN directions did not advance at least 64 KiB under load"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[allow(clippy::too_many_arguments)]
fn rotate(
    root: &Path,
    client: &mut ClientControl,
    load: &mut Load,
    original: &Snapshot,
    previous: &Snapshot,
    worker_id: u64,
    revision: u64,
    link: &impl Fn() -> Vec<u8>,
    original_link: &[u8],
    ping: &impl Fn() -> bool,
) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        load.assert_alive();
        assert_eq!(link(), original_link);
        assert!(process_is_current(ProcessIdentity {
            pid: original.io["pid"].as_u64().unwrap() as u32,
            start_ticks: original.io["process_start_ticks"].as_u64().unwrap()
        }));
        if let Some(current) = snapshot(root, client) {
            if current.record["pid"] != previous.record["pid"]
                && current.proof["worker_placement"]["worker_id"] == worker_id
                && current.proof["worker_placement"]["revision"] == revision
                && ping()
            {
                assert_fixed(root, &current, original, link, original_link);
                assert!(current.owner.worker_epoch > previous.owner.worker_epoch);
                assert!(current.owner.fencing_token > previous.owner.fencing_token);
                assert!(
                    current.owner.auth_deadline_mono_ms <= previous.owner.auth_deadline_mono_ms
                );
                assert!(!process_is_current(ProcessIdentity {
                    pid: previous.record["pid"].as_u64().unwrap() as u32,
                    start_ticks: previous.record["process_start_ticks"].as_u64().unwrap()
                }));
                let progressed = progress(root, client, load, &current);
                assert!(
                    matches!(client.exchange(Operation::ForwardRevoke { owner: previous.owner.clone() }).unwrap().0, Body::Error { code, .. } if code == "stale_forward_owner")
                );
                assert_fixed(root, &progressed, original, link, original_link);
                return progressed;
            }
        }
        assert!(
            Instant::now() < deadline,
            "actual slot/revision rotation failed to restore loaded forwarding within 30s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[allow(clippy::too_many_arguments)]
fn rejected(
    root: &Path,
    client: &mut ClientControl,
    load: &mut Load,
    original: &Snapshot,
    previous: &Snapshot,
    expected_code: &str,
    link: &impl Fn() -> Vec<u8>,
    original_link: &[u8],
    ping: &impl Fn() -> bool,
) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        load.assert_alive();
        let current =
            snapshot(root, client).expect("rejected placement damaged the committed owner");
        assert_eq!(current.record["pid"], previous.record["pid"]);
        assert_eq!(current.owner.worker_epoch, previous.owner.worker_epoch);
        assert_fixed(root, &current, original, link, original_link);
        assert!(
            ping(),
            "invalid local placement interrupted committed data traffic"
        );
        if fs::read_to_string(root.join("placement-agent.log"))
            .unwrap()
            .contains(expected_code)
        {
            return progress(root, client, load, &current);
        }
        assert!(
            Instant::now() < deadline,
            "requested placement rejection was not observed: {expected_code}"
        );
    }
}

pub(super) fn verify(
    root: &Path,
    namespace: &str,
    agent: &mut Process,
    client: &mut ClientControl,
    ping: &impl Fn() -> bool,
    link: &impl Fn() -> Vec<u8>,
    original_link: &[u8],
) {
    let original = snapshot(root, client).unwrap();
    assert!(original.record["authorization_snapshot_sha256"]
        .as_str()
        .is_some_and(|hash| hash.len() == 64));
    assert_eq!(original.proof["worker_placement"]["worker_id"], 1);
    let mut desired = status(&root.join("plan.json")).unwrap();
    let mut load = Load::start(root, namespace);
    let first = progress(root, client, &mut load, &original);
    assert_fixed(root, &first, &original, link, original_link);
    let mut evidence = vec![
        json!({"phase":"initial_loaded","record":first.record,"proof":first.proof,"owner":first.owner}),
    ];

    desired["placement"]["revision"] = json!(2);
    desired["placement"]["target_worker_id"] = json!(2);
    publish(root, &desired);
    let second = rotate(
        root,
        client,
        &mut load,
        &original,
        &first,
        2,
        2,
        link,
        original_link,
        ping,
    );
    evidence.push(json!({"phase":"different_slot","record":second.record,"proof":second.proof,"owner":second.owner}));

    let busy_path = root.join("worker-pool/worker-3.lock");
    let occupied = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(busy_path)
        .unwrap();
    assert_eq!(
        unsafe {
            nix::libc::flock(
                occupied.as_raw_fd(),
                nix::libc::LOCK_EX | nix::libc::LOCK_NB,
            )
        },
        0
    );
    desired["placement"]["revision"] = json!(3);
    desired["placement"]["target_worker_id"] = json!(3);
    publish(root, &desired);
    let preserved = rejected(
        root,
        client,
        &mut load,
        &original,
        &second,
        "code=worker_slot_busy",
        link,
        original_link,
        ping,
    );
    evidence.push(json!({"phase":"occupied_slot_isolated","record":preserved.record,"proof":preserved.proof,"owner":preserved.owner}));
    drop(occupied);
    let third = rotate(
        root,
        client,
        &mut load,
        &original,
        &preserved,
        3,
        3,
        link,
        original_link,
        ping,
    );
    evidence.push(json!({"phase":"occupied_slot_retry_recovered","record":third.record,"proof":third.proof,"owner":third.owner}));

    desired["placement"]["revision"] = json!(4);
    publish(root, &desired);
    let fourth = rotate(
        root,
        client,
        &mut load,
        &original,
        &third,
        3,
        4,
        link,
        original_link,
        ping,
    );
    evidence.push(json!({"phase":"same_slot_new_revision","record":fourth.record,"proof":fourth.proof,"owner":fourth.owner}));
    let committed = desired.clone();

    desired["placement"]["target_worker_id"] = json!(4);
    desired["placement"]["revision"] = json!(3);
    publish(root, &desired);
    let preserved = rejected(
        root,
        client,
        &mut load,
        &original,
        &fourth,
        "code=worker_placement_stale",
        link,
        original_link,
        ping,
    );
    desired.as_object_mut().unwrap().remove("placement");
    publish(root, &desired);
    let preserved = rejected(
        root,
        client,
        &mut load,
        &original,
        &preserved,
        "code=worker_placement_downgrade",
        link,
        original_link,
        ping,
    );
    evidence.push(json!({"phase":"stale_and_removed_placement_rejected","record":preserved.record,"proof":preserved.proof,"owner":preserved.owner}));
    publish(root, &committed);

    let old_agent = agent.0.id();
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();
    let live_without_agent = progress(root, client, &mut load, &preserved);
    assert_fixed(root, &live_without_agent, &original, link, original_link);
    assert!(ping());
    let log = OpenOptions::new()
        .append(true)
        .open(root.join("placement-agent.log"))
        .unwrap();
    *agent = Process(
        Command::new(std::env::var("CANDY_AGENT_TEST_BINARY").unwrap())
            .args([
                "experimental-runtime-agent",
                "--experimental-packet-port-ipc",
                "--config",
            ])
            .arg(root.join("runtime-agent.json"))
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    assert_ne!(agent.0.id(), old_agent);
    let deadline = Instant::now() + Duration::from_secs(12);
    let adopted = loop {
        load.assert_alive();
        if let Some(current) = snapshot(root, client) {
            assert_eq!(
                current.record["pid"], fourth.record["pid"],
                "Agent restart re-created the committed worker"
            );
            assert_fixed(root, &current, &original, link, original_link);
            if status(&root.join("io-status.json")).unwrap()["controller"]["pid"] == agent.0.id()
                && current.proof["controller"]["pid"] == agent.0.id()
                && current.owner.fencing_token > fourth.owner.fencing_token
                && ping()
            {
                break progress(root, client, &mut load, &current);
            }
        }
        assert!(
            Instant::now() < deadline,
            "restarted Agent did not adopt existing actual slot/Core/TUNIO"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    evidence.push(json!({"phase":"agent_restart_adopted_existing_slot","old_agent_pid":old_agent,"new_agent_pid":agent.0.id(),"record":adopted.record,"proof":adopted.proof,"owner":adopted.owner}));
    let report = json!({"scope":"real isolated Linux one-domain-per-exclusive-slot loaded rotation; shared multi-domain F08 not completed", "load":"actual continuous bidirectional iperf3 UDP, 8 Mbps per direction", "same_tun":true,"same_tunio":true,"same_signed_hash_and_expiry":true,"monotonic_cap_never_expanded":true,"late_old_owner_rejected":true,"steps":evidence});
    private_json(
        &root.join("signed-domain-slot-rotation-evidence.json"),
        &report,
    );
    if let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") {
        let destination = PathBuf::from(destination);
        fs::create_dir_all(&destination).unwrap();
        private_json(
            &destination.join("signed-domain-slot-rotation-evidence.json"),
            &report,
        );
        fs::copy(
            root.join("placement-agent.log"),
            destination.join("placement-agent.log"),
        )
        .unwrap();
    }
    eprintln!("signed_domain_slot_rotation_evidence {report}");
}
