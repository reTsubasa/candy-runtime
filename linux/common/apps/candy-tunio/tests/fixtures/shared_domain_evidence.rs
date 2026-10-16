//! Actual Linux shared-host evidence control. Submitted owner/checksum tuples
//! are controller associations, never master lease or installation proofs.
use super::*;
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use std::io::IoSlice;
use std::os::unix::net::UnixDatagram;

const READINESS_TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn register_domain(host: &Host, control: &Path, index: u8) -> serde_json::Value {
    use candy_process_control::{exchange, process_identity, ControlOperation, ControlRequest};
    use sha2::{Digest, Sha256};
    let process = process_identity(host.child.id()).unwrap();
    let controller = process_identity(std::process::id()).unwrap();
    let request = ControlRequest {
        schema_version: 1,
        operation: ControlOperation::Probe,
        token_sha256: format!("{:x}", Sha256::digest(READINESS_TOKEN.as_bytes())),
        nonce: format!("{index:032x}"),
    };
    // This authenticates the actual host PID/start ticks using SO_PEERCRED,
    // then acknowledges this domain's registration as its original controller.
    // A shared-host lifecycle probe cannot substitute for this handshake.
    let response = exchange(control, process, &request).unwrap();
    assert!(response.accepted, "{response:?}");
    assert_eq!(response.code, "process_probed");
    assert_eq!(response.process, process);
    assert_eq!(response.controller, controller);
    assert_eq!(response.controller_epoch, 1);
    assert_eq!(response.nonce, request.nonce);
    serde_json::to_value(response).unwrap()
}

fn exchange(
    socket: &Path,
    operation: &str,
    instance: &str,
    arguments: &[String],
    descriptor: Option<i32>,
) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let rights = descriptor.into_iter().collect::<Vec<_>>();
    let controls = if rights.is_empty() {
        Vec::new()
    } else {
        vec![ControlMessage::ScmRights(&rights)]
    };
    assert_eq!(
        sendmsg::<()>(
            stream.as_raw_fd(),
            &[IoSlice::new(&[0])],
            &controls,
            MsgFlags::empty(),
            None
        )
        .unwrap(),
        1
    );
    let request = serde_json::json!({"schema_version":1,"operation":operation,
        "instance":instance,"arguments":arguments,"namespace":false});
    stream
        .write_all(&serde_json::to_vec(&request).unwrap())
        .unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut bytes = Vec::new();
    stream.take(65_537).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 65_536);
    serde_json::from_slice(&bytes).unwrap()
}

fn evidence(
    socket: &Path,
    instance: &str,
    action: &str,
    incarnation: serde_json::Value,
    binding: serde_json::Value,
) -> serde_json::Value {
    exchange(socket, "domain_evidence", instance, &[serde_json::to_string(
        &serde_json::json!({"action":action,"domain_incarnation":incarnation,"binding":binding})).unwrap()], None)
}

fn rejected(reply: &serde_json::Value, code: &str) {
    assert_eq!(reply["schema_version"], 1, "{reply}");
    assert_eq!(reply["accepted"], false, "{reply}");
    assert!(reply["code"].as_str().unwrap().contains(code), "{reply}");
    assert!(reply.get("joined_completion").is_none(), "{reply}");
}

struct RunningDomain {
    instance: String,
    status: PathBuf,
    registration: serde_json::Value,
    _packet_peer: UnixDatagram,
}

fn start_domain(host: &Host, root: &Path, index: u8) -> RunningDomain {
    let directory = root.join(format!("domain-{index}"));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = directory.join("fixture");
    let output = Command::new(std::env::var("CANDY_SIGNED_FIXTURE_BINARY").unwrap())
        .arg(&fixture)
        .env("CANDY_SIGNED_FIXTURE_DOMAIN_SEED", index.to_string())
        .env("CANDY_SIGNED_FIXTURE_GRANT_TTL_SECS", "600")
        .env("CANDY_SIGNED_FIXTURE_ENDPOINT", "127.0.0.1:18443")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // A valid signed domain dials only a private loopback test endpoint. This
    // gate verifies actual local task lifecycle/IPC and does not claim forwarding.
    let inbound = directory.join("inbound.toml");
    let config = fs::read_to_string(fixture.join("client.toml")).unwrap();
    fs::write(&inbound, config).unwrap();
    fs::set_permissions(&inbound, fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(core())
        .args(["client", "sdwan", "compile-control", "--config"])
        .arg(&inbound)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let compiled: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let segment_hex = compiled["segment_id"].as_str().unwrap();
    assert_eq!(segment_hex.len(), 32, "compiled signed segment ID");
    let routing_domain = (0..16)
        .map(|offset| u8::from_str_radix(&segment_hex[offset * 2..offset * 2 + 2], 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(routing_domain, vec![index; 16], "fixture domain seed");
    let policy_generation = compiled["projection_generation"].as_u64().unwrap();
    assert_ne!(policy_generation, 0);
    let binding_path = directory.join("binding.json");
    private_json(
        &binding_path,
        &serde_json::json!({"infrastructure_id":vec![index;16],
        "routing_domain_id":routing_domain,"infrastructure_generation":1,
        "io_epoch":1,"owner_epoch":1,"policy_generation":policy_generation}),
    );
    let status = directory.join("status.json");
    let control = directory.join("control.sock");
    let instance = control.to_str().unwrap().to_owned();
    let arguments = vec![
        "run".into(),
        "--config".into(),
        inbound.to_str().unwrap().into(),
        "--experimental-packet-port-ipc".into(),
        "--packet-port-binding-file".into(),
        binding_path.to_str().unwrap().into(),
        "--experimental-independent-worker".into(),
        "--worker-control-socket".into(),
        instance.clone(),
        "--worker-auth-deadline-unix".into(),
        compiled["authorization_expires_at_unix"]
            .as_u64()
            .unwrap()
            .to_string(),
        "--worker-placement-revision".into(),
        "1".into(),
        "--status".into(),
        status.to_str().unwrap().into(),
        "--readiness-token".into(),
        READINESS_TOKEN.into(),
    ];
    let (packet, peer) = UnixDatagram::pair().unwrap();
    let response = exchange(
        &host.socket,
        "start",
        &instance,
        &arguments,
        Some(packet.as_raw_fd()),
    );
    assert_eq!(response["accepted"], true, "{response}");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut registration = None;
    loop {
        let probe = request_for_domain(&host.socket, "probe", &instance);
        assert_eq!(probe["running"], true, "real Core domain failed: {probe}");
        if registration.is_none() && control.exists() {
            registration = Some(register_domain(host, &control, index));
        }
        if super::super::status(&status).is_some_and(|status| status["packet_binding"].is_object())
            && registration.is_some()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "real domain status/control not ready: {probe}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    RunningDomain {
        instance,
        status,
        registration: registration.unwrap(),
        _packet_peer: peer,
    }
}

fn wait_stopped(host: &Host, instance: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let probe = request_for_domain(&host.socket, "probe", instance);
        if probe["running"] == false {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "actual domain task did not stop: {probe}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn other_controller_helper() {
    let request_path = PathBuf::from(std::env::var_os("CANDY_DOMAIN_EVIDENCE_REQUEST").unwrap());
    let request: serde_json::Value =
        serde_json::from_slice(&fs::read(request_path).unwrap()).unwrap();
    let response = evidence(
        Path::new(request["socket"].as_str().unwrap()),
        request["instance"].as_str().unwrap(),
        "query",
        request["incarnation"].clone(),
        request["binding"].clone(),
    );
    rejected(&response, "domain_evidence_controller_mismatch");
    private_json(Path::new(request["response"].as_str().unwrap()), &response);
}

pub(super) fn verify() {
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1")
    );
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut host = start(root.path(), 1);
    let first = start_domain(&host, root.path(), 32);
    let second = start_domain(&host, root.path(), 33);
    let inspected = evidence(
        &host.socket,
        &first.instance,
        "inspect",
        serde_json::Value::Null,
        serde_json::Value::Null,
    );
    assert_eq!(inspected["schema_version"], 2, "{inspected}");
    assert_eq!(inspected["host"]["process"]["pid"], host.child.id());
    let original_process = candy_process_control::process_identity(std::process::id()).unwrap();
    assert_eq!(
        inspected["controller"],
        serde_json::to_value(original_process).unwrap()
    );
    assert!(inspected["joined_completion"].is_null());
    let incarnation = inspected["domain_incarnation"].clone();
    assert_ne!(incarnation, serde_json::json!(vec![0; 32]));
    let binding = serde_json::json!({"candidate_record_sha256":vec![3;32],"owner":{
        "role":"Sdwan","transport_id":4,"connection_id":5,"worker_id":1,"owner_epoch":1}});
    let bound = evidence(
        &host.socket,
        &first.instance,
        "bind",
        incarnation.clone(),
        binding.clone(),
    );
    assert_eq!(bound["binding"], binding, "{bound}");
    assert_eq!(bound["domain_incarnation"], incarnation);
    assert!(bound["joined_completion"].is_null());
    assert_eq!(
        evidence(
            &host.socket,
            &first.instance,
            "query",
            incarnation.clone(),
            binding.clone()
        ),
        bound
    );
    let mut wrong_owner = binding.clone();
    wrong_owner["owner"]["owner_epoch"] = 2.into();
    rejected(
        &evidence(
            &host.socket,
            &first.instance,
            "query",
            incarnation.clone(),
            wrong_owner,
        ),
        "domain_evidence_binding_conflict",
    );
    let mut wrong_owner = binding.clone();
    wrong_owner["owner"]["owner_epoch"] = 2.into();
    rejected(
        &evidence(
            &host.socket,
            &first.instance,
            "bind",
            incarnation.clone(),
            wrong_owner,
        ),
        "domain_evidence_binding_conflict",
    );
    let mut wrong_checksum = binding.clone();
    wrong_checksum["candidate_record_sha256"] = serde_json::json!(vec![9; 32]);
    rejected(
        &evidence(
            &host.socket,
            &first.instance,
            "query",
            incarnation.clone(),
            wrong_checksum,
        ),
        "domain_evidence_original_binding_missing",
    );
    let mut wrong_checksum = binding.clone();
    wrong_checksum["candidate_record_sha256"] = serde_json::json!(vec![9; 32]);
    rejected(
        &evidence(
            &host.socket,
            &first.instance,
            "bind",
            incarnation.clone(),
            wrong_checksum,
        ),
        "domain_evidence_owner_rebound",
    );
    rejected(
        &evidence(
            &host.socket,
            &first.instance,
            "query",
            serde_json::json!(vec![9; 32]),
            binding.clone(),
        ),
        "domain_evidence_incarnation_mismatch",
    );
    let request_path = root.path().join("other-controller.json");
    let response_path = root.path().join("other-controller-response.json");
    private_json(
        &request_path,
        &serde_json::json!({"socket":host.socket,"instance":first.instance,
        "incarnation":incarnation,"binding":binding,"response":response_path}),
    );
    let result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "signed_shared_domain_evidence_other_controller_helper",
            "--nocapture",
        ])
        .env("CANDY_DOMAIN_EVIDENCE_REQUEST", &request_path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        response_path.exists(),
        "other controller helper did not execute"
    );
    let other_before: serde_json::Value =
        serde_json::from_slice(&fs::read(&second.status).unwrap()).unwrap();
    let cancelled = request_for_domain(&host.socket, "cancel", &first.instance);
    assert_eq!(cancelled["accepted"], true, "{cancelled}");
    wait_stopped(&host, &first.instance);
    let completed = evidence(
        &host.socket,
        &first.instance,
        "query",
        incarnation.clone(),
        binding.clone(),
    );
    assert_eq!(completed["binding"], binding);
    assert_eq!(
        completed["joined_completion"]["outcome"], "returned",
        "{completed}"
    );
    assert_eq!(
        completed["joined_completion"]["exit_code"], 0,
        "{completed}"
    );
    assert_eq!(
        evidence(
            &host.socket,
            &first.instance,
            "query",
            incarnation.clone(),
            binding.clone()
        ),
        completed
    );
    let mut retrospective = binding.clone();
    retrospective["candidate_record_sha256"] = serde_json::json!(vec![10; 32]);
    retrospective["owner"]["connection_id"] = 10.into();
    rejected(
        &evidence(
            &host.socket,
            &first.instance,
            "bind",
            incarnation.clone(),
            retrospective,
        ),
        "domain_evidence_original_binding_missing",
    );
    let forgotten = request_for_domain(&host.socket, "forget", &first.instance);
    rejected(&forgotten, "domain_candidate_evidence_retained");
    assert_eq!(
        evidence(
            &host.socket,
            &first.instance,
            "query",
            incarnation.clone(),
            binding.clone()
        ),
        completed
    );
    let second_probe = request_for_domain(&host.socket, "probe", &second.instance);
    assert_eq!(second_probe["running"], true, "{second_probe}");
    let other_after: serde_json::Value =
        serde_json::from_slice(&fs::read(&second.status).unwrap()).unwrap();
    for field in [
        "pid",
        "packet_binding",
        "worker_authority_sha256",
        "policy_generation",
        "auth_deadline_unix",
    ] {
        assert_eq!(
            other_after[field], other_before[field],
            "unrelated domain identity changed: {field}"
        );
    }
    // An unbound task may be forgotten; even when its instance path is reused,
    // the new actual task receives another incarnation.
    let second_original = evidence(
        &host.socket,
        &second.instance,
        "inspect",
        serde_json::Value::Null,
        serde_json::Value::Null,
    );
    request_for_domain(&host.socket, "cancel", &second.instance);
    wait_stopped(&host, &second.instance);
    assert_eq!(
        request_for_domain(&host.socket, "forget", &second.instance)["accepted"],
        true
    );
    rejected(
        &evidence(
            &host.socket,
            &second.instance,
            "inspect",
            serde_json::Value::Null,
            serde_json::Value::Null,
        ),
        "domain_evidence_task_absent",
    );
    // Start the same valid configuration again under the same instance path.
    let previous_dir = root.path().join("domain-33");
    fs::rename(&previous_dir, root.path().join("domain-33-previous")).unwrap();
    let second_reused = start_domain(&host, root.path(), 33);
    assert_eq!(second_reused.instance, second.instance);
    let reused = evidence(
        &host.socket,
        &second_reused.instance,
        "inspect",
        serde_json::Value::Null,
        serde_json::Value::Null,
    );
    assert_ne!(
        reused["domain_incarnation"],
        second_original["domain_incarnation"]
    );
    rejected(
        &evidence(
            &host.socket,
            &second_reused.instance,
            "query",
            second_original["domain_incarnation"].clone(),
            binding.clone(),
        ),
        "domain_evidence_incarnation_mismatch",
    );
    if let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") {
        let destination = PathBuf::from(destination);
        fs::create_dir_all(&destination).unwrap();
        private_json(
            &destination.join("domain-task-evidence.json"),
            &serde_json::json!({
            "scope":"actual Linux host/task socket; controller association only; no terminal authority",
            "registrations":[first.registration,second.registration,second_reused.registration],
            "inspected":inspected,"bound":bound,"completed":completed,"forget_rejected":forgotten,
            "other_controller_rejected":serde_json::from_slice::<serde_json::Value>(&fs::read(response_path).unwrap()).unwrap(),
            "unrelated_domain":second_probe,"reused_task":reused}),
        );
    }
    host.child.kill().unwrap();
    host.child.wait().unwrap();
    // A gone host cannot be queried and no cached record is converted to a
    // newly issued completion or owner-retirement receipt.
    assert!(UnixStream::connect(&host.socket).is_err());
}
