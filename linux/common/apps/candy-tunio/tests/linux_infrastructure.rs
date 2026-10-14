#![cfg(target_os = "linux")]
use candy_netd_client::v2::InfrastructureClient;
use candy_netd_proto::v2::{Body, InfraSpec, Operation};
use candy_packet_port::packet_port::PacketPort;
use candy_packet_port::packet_port_ipc::{PacketPortBinding, PacketPortRole, UnixPacketPort};
use candy_process_control::{
    exchange, process_identity, process_is_current, ControlOperation, ControlRequest,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UnixDatagram;

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "private helper launched only by the isolated takeover test"]
fn takeover_original_supervisor_helper() {
    let root = std::path::PathBuf::from(std::env::var("CANDY_TAKEOVER_HELPER_ROOT").unwrap());
    let (io, _worker) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let fd = io.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_candy-tunio"));
    unsafe {
        command.pre_exec(move || {
            nix::fcntl::fcntl(
                fd,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
            )
            .map(|_| ())
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
        });
    }
    let mut child = command
        .arg("--experimental-packet-port-ipc")
        .arg("--socket")
        .arg(root.join("netd.sock"))
        .arg("--instance-id")
        .arg("02".repeat(16))
        .arg("--packet-port-fd")
        .arg(fd.to_string())
        .arg("--packet-port-binding-file")
        .arg(root.join("binding.json"))
        .arg("--auth-deadline-unix")
        .arg(std::env::var("CANDY_TAKEOVER_DEADLINE").unwrap())
        .arg("--control-socket")
        .arg(root.join("control.sock"))
        .arg("--status")
        .arg(root.join("status.json"))
        .arg("--readiness-token")
        .arg("test-capability-01234567890123456789")
        .spawn()
        .unwrap();
    drop(io);
    for _ in 0..200 {
        assert!(child.try_wait().unwrap().is_none());
        if root.join("release-supervisor").exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("takeover helper was not released");
}

#[test]
#[ignore = "requires privileged isolated Linux namespace and actual Runtime Agent binary"]
fn actual_agent_adopts_existing_tunio_without_reacquiring_tun_or_renewing_authorization() {
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1")
    );
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("netd.sock");
    let mut netd = Process(
        Command::new(std::env::var("CANDY_NETD_TEST_BINARY").unwrap())
            .arg("--protocol-v2")
            .arg("--socket")
            .arg(&socket)
            .args(["--allowed-uid", "0", "--allowed-gid", "0"])
            .arg("--infrastructure-journal")
            .arg(root.join("infra.journal"))
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        assert!(netd.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(20));
    }
    let ns = fs::metadata("/proc/self/ns/net").unwrap();
    let spec = InfraSpec {
        infra_id: [3; 16],
        generation: 1,
        netns_device: ns.dev(),
        netns_inode: ns.ino(),
        overlay_router_ipv4: [100, 64, 0, 1],
        mtu: 1180,
    };
    let mut client = InfrastructureClient::new(&socket, [1; 16]);
    let (body, fd) = client
        .exchange(Operation::InfraEnsure(spec.clone()))
        .unwrap();
    assert!(
        matches!(body, Body::InfraStatus { spec: Some(_), .. }),
        "{body:?}"
    );
    assert!(fd.is_none());
    let binding = PacketPortBinding {
        infrastructure_id: spec.infra_id,
        routing_domain_id: [4; 16],
        infrastructure_generation: 1,
        io_epoch: 1,
        owner_epoch: 1,
        policy_generation: 1,
    };
    fs::write(
        root.join("binding.json"),
        serde_json::to_vec(&binding).unwrap(),
    )
    .unwrap();
    fs::set_permissions(root.join("binding.json"), fs::Permissions::from_mode(0o600)).unwrap();
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 7;
    let mut helper = Process(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "takeover_original_supervisor_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("CANDY_TAKEOVER_HELPER_ROOT", root)
            .env("CANDY_TAKEOVER_DEADLINE", expires.to_string())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if root.join("status.json").exists() {
            break;
        }
        assert!(helper.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(20));
    }
    let status: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("status.json")).unwrap()).unwrap();
    let pid = status["pid"].as_u64().unwrap() as u32;
    let managed = process_identity(pid).unwrap();
    let capability = format!(
        "{:x}",
        Sha256::digest(b"test-capability-01234567890123456789")
    );
    let request = |operation, token: String| ControlRequest {
        schema_version: 1,
        operation,
        token_sha256: token,
        nonce: "0123456789abcdef0123456789abcdef".into(),
    };
    assert!(exchange(
        &root.join("control.sock"),
        managed,
        &request(ControlOperation::Takeover, capability.clone())
    )
    .unwrap_err()
    .to_string()
    .contains("previous_controller_alive"));
    assert!(exchange(
        &root.join("control.sock"),
        managed,
        &request(ControlOperation::Probe, "0".repeat(64))
    )
    .is_err());
    let identity = link_identity();
    fs::write(root.join("release-supervisor"), b"exit").unwrap();
    assert!(helper.0.wait().unwrap().success());
    let exe = fs::metadata(format!("/proc/{pid}/exe")).unwrap();
    let tunio_path = fs::read_link(format!("/proc/{pid}/exe")).unwrap();
    let record = serde_json::json!({"schema_version":1,"pid":pid,"process_start_ticks":managed.start_ticks,"uid":0,"executable_device":exe.dev(),"executable_inode":exe.ino(),"executable":tunio_path,"status_path":root.join("status.json"),"readiness_token_sha256":capability,"infrastructure_generation":1,"policy_generation":1,"auth_deadline_unix":expires});
    fs::write(
        root.join("record.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    fs::set_permissions(root.join("record.json"), fs::Permissions::from_mode(0o600)).unwrap();
    let mut agent = Process(
        Command::new(std::env::var("CANDY_AGENT_TEST_BINARY").unwrap())
            .arg("adopt-tunio")
            .arg("--experimental-packet-port-ipc")
            .arg("--record")
            .arg(root.join("record.json"))
            .arg("--expected-executable")
            .arg(&tunio_path)
            .arg("--control-socket")
            .arg(root.join("control.sock"))
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        assert!(agent.0.try_wait().unwrap().is_none());
        let probe = exchange(
            &root.join("control.sock"),
            managed,
            &request(ControlOperation::Probe, capability.clone()),
        )
        .unwrap();
        if probe.controller.pid == agent.0.id() {
            assert_eq!(probe.controller_epoch, 2);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(process_identity(pid).unwrap(), managed);
    assert_eq!(link_identity(), identity);
    let tun_count = fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            fs::read_link(e.path()).is_ok_and(|p| p == std::path::Path::new("/dev/net/tun"))
        })
        .count();
    assert_eq!(tun_count, 1, "takeover acquired another TUN queue");
    assert!(Command::new("ip")
        .args(["route", "add", "100.64.0.2/32", "dev", "candy0"])
        .status()
        .unwrap()
        .success());
    let _ = Command::new("ping")
        .args(["-I", "candy0", "-c", "1", "-W", "1", "100.64.0.2"])
        .status()
        .unwrap();
    assert!(
        process_is_current(managed),
        "missing worker packet output killed adopted TUN I/O"
    );
    let memory = fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .unwrap()
        .to_owned();
    std::thread::sleep(Duration::from_secs(8));
    assert!(process_is_current(managed));
    assert!(agent.0.try_wait().unwrap().is_none());
    let after: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("status.json")).unwrap()).unwrap();
    assert_eq!(after["auth_deadline_unix"], expires);
    assert_eq!(after["controller"]["pid"], agent.0.id());
    assert_eq!(after["controller_epoch"], 2);
    assert_eq!(link_identity(), identity);
    eprintln!("tunio_takeover_evidence pid={pid} start_ticks={} controller_epoch=2 tun_fds={tun_count} auth_deadline_unix={expires} memory={memory} identity={identity}",managed.start_ticks);
    assert_eq!(
        unsafe { nix::libc::kill(agent.0.id() as i32, nix::libc::SIGTERM) },
        0
    );
    assert!(agent.0.wait().unwrap().success());
    assert!(!process_is_current(managed));
    assert_eq!(link_identity(), identity);
    assert!(matches!(
        client
            .exchange(Operation::InfraReleaseIo {
                infra_id: spec.infra_id,
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
                infra_id: spec.infra_id,
                generation: 1
            })
            .unwrap()
            .0,
        Body::Ack
    ));
}

fn link_identity() -> serde_json::Value {
    let output = Command::new("ip")
        .args(["-j", "addr", "show", "dev", "candy0"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    serde_json::json!({"ifindex":value[0]["ifindex"],"ifname":value[0]["ifname"],"flags":value[0]["flags"],"mtu":value[0]["mtu"],"addresses":value[0]["addr_info"]})
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires isolated Linux CAP_NET_ADMIN + /dev/net/tun and explicit acknowledgement"]
async fn actual_tunio_cli_survives_worker_loss_and_owner_expiry_without_retiring_tun() {
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1")
    );
    let netd_binary =
        std::env::var("CANDY_NETD_TEST_BINARY").expect("real netd test binary required");
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().join("netd.sock");
    let mut netd = Process(
        Command::new(netd_binary)
            .arg("--protocol-v2")
            .arg("--socket")
            .arg(&socket)
            .args(["--allowed-uid", "0", "--allowed-gid", "0"])
            .arg("--infrastructure-journal")
            .arg(directory.path().join("infra.journal"))
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        assert!(netd.0.try_wait().unwrap().is_none());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let namespace = fs::metadata("/proc/self/ns/net").unwrap();
    let spec = InfraSpec {
        infra_id: [3; 16],
        generation: 1,
        netns_device: namespace.dev(),
        netns_inode: namespace.ino(),
        overlay_router_ipv4: [100, 64, 0, 1],
        mtu: 1180,
    };
    let mut client = InfrastructureClient::new(&socket, [1; 16]);
    let (body, fd) = client
        .exchange(Operation::InfraEnsure(spec.clone()))
        .unwrap();
    assert!(
        matches!(body, Body::InfraStatus { spec: Some(_), .. }),
        "{body:?}"
    );
    assert!(fd.is_none());
    let binding = PacketPortBinding {
        infrastructure_id: spec.infra_id,
        routing_domain_id: [4; 16],
        infrastructure_generation: 1,
        io_epoch: 1,
        owner_epoch: 1,
        policy_generation: 1,
    };
    let binding_path = directory.path().join("binding.json");
    fs::write(&binding_path, serde_json::to_vec(&binding).unwrap()).unwrap();
    fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o600)).unwrap();
    let (io, worker) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let inherited_fd = io.as_raw_fd();
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    let mut command = Command::new(env!("CARGO_BIN_EXE_candy-tunio"));
    unsafe {
        command.pre_exec(move || {
            nix::fcntl::fcntl(
                inherited_fd,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
            )
            .map(|_| ())
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
        });
    }
    command
        .arg("--experimental-packet-port-ipc")
        .arg("--socket")
        .arg(&socket)
        .arg("--instance-id")
        .arg("02".repeat(16))
        .arg("--packet-port-fd")
        .arg(inherited_fd.to_string())
        .arg("--packet-port-binding-file")
        .arg(&binding_path)
        .arg("--auth-deadline-unix")
        .arg(expires.to_string());
    let mut tunio = Process(command.spawn().unwrap());
    drop(io);
    worker.set_nonblocking(true).unwrap();
    let worker = UnixPacketPort::new(
        UnixDatagram::from_std(worker).unwrap(),
        binding,
        PacketPortRole::Worker,
    )
    .unwrap();
    for _ in 0..50 {
        assert!(tunio.0.try_wait().unwrap().is_none());
        let (body, _) = client.exchange(Operation::InfraStatus).unwrap();
        if matches!(
            body,
            Body::InfraStatus {
                io_epoch: Some(1),
                ..
            }
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let identity = link_identity();
    assert!(Command::new("ip")
        .args(["route", "add", "100.64.0.2/32", "dev", "candy0"])
        .status()
        .unwrap()
        .success());
    let owns_tun = fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| entry.ok())
        .any(|entry| {
            fs::read_link(entry.path())
                .ok()
                .is_some_and(|path| path == std::path::Path::new("/dev/net/tun"))
        });
    assert!(!owns_tun, "business worker test process received a TUN fd");
    let memory = fs::read_to_string(format!("/proc/{}/status", tunio.0.id()))
        .unwrap()
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .unwrap()
        .to_owned();
    eprintln!(
        "tunio_kernel_evidence pid={} memory={memory} identity={identity}",
        tunio.0.id()
    );
    let mut ping = Process(
        Command::new("ping")
            .args(["-I", "candy0", "-c", "1", "-W", "1", "100.64.0.2"])
            .spawn()
            .unwrap(),
    );
    let packet = tokio::time::timeout(Duration::from_secs(1), worker.recv_packet())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(packet[0] >> 4, 4);
    ping.0.wait().unwrap();
    drop(worker);
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        tunio.0.try_wait().unwrap().is_none(),
        "worker loss or expired owner killed infrastructure process"
    );
    assert_eq!(link_identity(), identity);
    tunio.0.kill().unwrap();
    tunio.0.wait().unwrap();
    let (body, fd) = client
        .exchange(Operation::InfraReleaseIo {
            infra_id: spec.infra_id,
            generation: 1,
            io_epoch: 1,
        })
        .unwrap();
    assert!(matches!(body, Body::Ack), "{body:?}");
    assert!(fd.is_none());
    assert_eq!(
        link_identity(),
        identity,
        "I/O process stop retired persistent TUN"
    );
    let (body, _) = client
        .exchange(Operation::InfraRetire {
            infra_id: spec.infra_id,
            generation: 1,
        })
        .unwrap();
    assert!(matches!(body, Body::Ack), "{body:?}");
}
