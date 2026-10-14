//! Real endpoint failover; two distinct signed paths share one server process.
use super::*;
use serde_json::{json, Value};
use std::io::Write;
use std::process::Stdio;

fn nft(namespace: &str, script: &str) {
    let mut child = Command::new("ip")
        .args(["netns", "exec", namespace, "nft", "-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "nft injection failed");
}

pub(super) fn install_alternate_endpoint(namespace: &str) {
    nft(namespace, "table ip candy_candidate_nat {\n chain incoming {\n type nat hook prerouting priority dstnat; policy accept;\n udp dport 18444 redirect to :18443;\n }\n}\n");
}

fn primary_block(namespace: &str, enabled: bool) {
    if enabled {
        // Block both directions of the primary while leaving translated alternate traffic intact.
        nft(namespace, "table inet candy_candidate_fault {\n chain input {\n type filter hook input priority -200; policy accept;\n meta l4proto udp ct original proto-dst 18443 drop;\n }\n chain output {\n type filter hook output priority -200; policy accept;\n udp sport 18443 ct original proto-dst 18443 drop;\n }\n}\n");
    } else {
        nft(namespace, "delete table inet candy_candidate_fault\n");
    }
}

fn alternate_block(namespace: &str, enabled: bool) {
    if enabled {
        nft(namespace, "table inet candy_alternate_fault {\n chain input {\n type filter hook input priority -200; policy accept;\n meta l4proto udp ct original proto-dst 18444 drop;\n }\n chain output {\n type filter hook output priority -200; policy accept;\n udp sport 18443 ct original proto-dst 18444 drop;\n }\n}\n");
    } else {
        nft(namespace, "delete table inet candy_alternate_fault\n");
    }
}

fn current(root: &Path) -> Value {
    let mut value = status(&root.join("client-status.json")).unwrap();
    value.as_object_mut().unwrap().remove("readiness_token");
    value
}

fn wait_candidate(root: &Path, candidate: &str, ping: &impl Fn() -> bool) -> Value {
    let started = Instant::now();
    loop {
        let value = current(root);
        if value["paths"].as_array().is_some_and(|paths| {
            paths.iter().any(|path| {
                path["candidate_id"] == candidate && path["ready_streams"].as_u64().unwrap_or(0) > 0
            })
        }) && value["failed_prefixes"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && ping()
        {
            return json!({"elapsed_ms":started.elapsed().as_millis(),"status":value});
        }
        assert!(
            started.elapsed() < Duration::from_secs(45),
            "candidate {candidate} did not carry actual traffic: {value}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn echo_servers(root: &Path, namespace: &str) -> Vec<Process> {
    let script = root.join("candidate-probe.py");
    fs::write(
        &script,
        include_str!("../../../../../../scripts/sdwan-perf/candy-perf-probe.py"),
    )
    .unwrap();
    let mut children = Vec::new();
    for (address, side) in [("10.251.1.10", "client"), ("10.251.2.10", "server")] {
        let mut command = if side == "server" {
            let mut command = Command::new("ip");
            command.args(["netns", "exec", namespace, "python3"]);
            command
        } else {
            Command::new("python3")
        };
        let ready = root.join(format!("candidate-{side}-ready.json"));
        children.push(Process(
            command
                .arg(&script)
                .args(["server", "--address", address, "--output"])
                .arg(&ready)
                .spawn()
                .unwrap(),
        ));
        wait_socket(&ready);
    }
    children
}

fn load(root: &Path, namespace: &str, seconds: u64, label: &str) -> Vec<(Process, PathBuf)> {
    let mut children = Vec::new();
    for (address, bind, side) in [
        ("10.251.2.10", "10.251.1.10", "upload"),
        ("10.251.1.10", "10.251.2.10", "download"),
    ] {
        let mut command = if side == "download" {
            let mut command = Command::new("ip");
            command.args(["netns", "exec", namespace, "python3"]);
            command
        } else {
            Command::new("python3")
        };
        let output = root.join(format!("candidate-{label}-{side}.json"));
        children.push((
            Process(
                command
                    .arg(root.join("candidate-probe.py"))
                    .args([
                        "udp-client",
                        "--address",
                        address,
                        "--bind",
                        bind,
                        "--size",
                        "512",
                        "--pps",
                        "100",
                        "--seconds",
                        &seconds.to_string(),
                        "--output",
                    ])
                    .arg(&output)
                    .spawn()
                    .unwrap(),
            ),
            output,
        ));
    }
    children
}

fn finish(children: Vec<(Process, PathBuf)>, allow_loss: bool) -> Vec<Value> {
    children
        .into_iter()
        .map(|(mut child, output)| {
            assert!(child.0.wait().unwrap().success());
            let value = status(&output).unwrap();
            assert_eq!(value["corrupt_packets"], 0);
            assert_eq!(value["duplicate_packets"], 0);
            assert!(value["received_unique_packets"].as_u64().unwrap() > 0);
            if !allow_loss {
                assert_eq!(value["lost_packets"], 0);
                assert_eq!(value["send_errors"], 0);
            }
            value
        })
        .collect()
}

pub(super) fn verify(
    root: &Path,
    namespace: &str,
    ping: &impl Fn() -> bool,
    link: &impl Fn() -> Vec<u8>,
    original_link: &[u8],
) {
    let primary = "0c".repeat(16);
    let alternate = "0d".repeat(16);
    let initial = wait_candidate(root, &primary, ping);
    let io = status(&root.join("io-status.json")).unwrap();
    let compiled: Value = serde_json::from_slice(
        &Command::new(core())
            .args(["client", "sdwan", "compile-control", "--config"])
            .arg(root.join("fixture/client.toml"))
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    // These are independently signed path candidates, not repeated aliases of one candidate.
    let config = fs::read_to_string(root.join("fixture/client.toml")).unwrap();
    assert_eq!(config.matches("[[peers]]").count(), 2);
    let _echo = echo_servers(root, namespace);
    let before = finish(load(root, namespace, 3, "before"), false);
    let traffic = load(root, namespace, 80, "fault");
    std::thread::sleep(Duration::from_secs(1));
    let fault_started = Instant::now();
    primary_block(namespace, true);
    let failed_over = wait_candidate(root, &alternate, ping);
    assert_eq!(failed_over["status"]["pid"], initial["status"]["pid"]);
    assert_eq!(link(), original_link);
    let after_failover = finish(load(root, namespace, 3, "after-failover"), false);
    primary_block(namespace, false);
    // Do not require preempting a healthy alternate; force its loss to prove primary recovery.
    alternate_block(namespace, true);
    let recovered = wait_candidate(root, &primary, ping);
    alternate_block(namespace, false);
    assert_eq!(recovered["status"]["pid"], initial["status"]["pid"]);
    assert_eq!(link(), original_link);
    let current_io = status(&root.join("io-status.json")).unwrap();
    for field in [
        "pid",
        "process_start_ticks",
        "infrastructure_generation",
        "packet_binding",
        "auth_deadline_unix",
    ] {
        assert_eq!(
            current_io[field], io[field],
            "candidate failure changed IO {field}"
        );
    }
    assert_eq!(
        current_io["auth_deadline_unix"],
        compiled["authorization_expires_at_unix"]
    );
    let after = finish(load(root, namespace, 3, "after"), false);
    let fault_load = finish(traffic, true);
    let evidence = json!({"schema_version":1,"scope":"isolated signed two-endpoint real QUIC path failover; one shared server process, not independent server/worker failure","distinct_candidate_ids":[primary,alternate],"distinct_endpoints":["10.200.0.2:18443","10.200.0.2:18444"],"actual_bidirectional_validated_udp":true,"same_core":true,"same_tunio":true,"same_tun":true,"authorization_not_extended":true,"fault_elapsed_ms":fault_started.elapsed().as_millis(),"initial":initial,"failed_over":failed_over,"recovered":recovered,"load_before":before,"load_during_fault":fault_load,"load_after_failover":after_failover,"load_after_recovery":after});
    if let Some(destination) = std::env::var_os("CANDY_SIGNED_EVIDENCE_DIR") {
        private_json(
            &PathBuf::from(destination).join("two-candidate-failover-evidence.json"),
            &evidence,
        );
    }
    eprintln!("two_candidate_failover_evidence {evidence}");
}
