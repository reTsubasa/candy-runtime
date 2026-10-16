use super::*;

fn fixture() -> (
    EvidenceClient,
    ControllerCandidateAssociation,
    DomainEvidence,
) {
    let host_process = ProcessIdentity {
        pid: 1,
        start_ticks: 2,
    };
    let original = DomainEvidence {
        schema_version: 2,
        host: HostIdentity {
            boot_id: uuid::Uuid::from_bytes([3; 16]),
            instance: [4; 32],
            process: host_process,
        },
        controller: ProcessIdentity {
            pid: 5,
            start_ticks: 6,
        },
        instance: "domain".into(),
        domain_incarnation: [7; 32],
        binding: None,
        joined_completion: None,
    };
    let binding = ControllerCandidateAssociation {
        candidate_record_sha256: [8; 32],
        owner: SdwanTransportOwner {
            role: "Sdwan".into(),
            transport_id: 9,
            connection_id: 10,
            worker_id: 11,
            owner_epoch: 12,
        },
    };
    let mut response = original.clone();
    response.binding = Some(binding.clone());
    let client = EvidenceClient {
        host: SharedWorker {
            socket: "missing.sock".into(),
            identity: host_process,
        },
        original,
    };
    (client, binding, response)
}

#[test]
fn exact_host_task_controller_and_checksum_owner_must_match_original() {
    let (client, binding, response) = fixture();
    client.verify_exact(&response, &binding).unwrap();
    assert!(response.joined_completion.is_none());
    for case in 0..9 {
        let mut changed = response.clone();
        match case {
            0 => changed.host.instance = [99; 32],
            1 => changed.host.boot_id = uuid::Uuid::from_bytes([99; 16]),
            2 => changed.host.process.start_ticks += 1,
            3 => changed.controller.start_ticks += 1,
            4 => changed.instance = "reused-path".into(),
            5 => changed.domain_incarnation = [99; 32],
            6 => changed.binding.as_mut().unwrap().candidate_record_sha256 = [99; 32],
            7 => changed.binding.as_mut().unwrap().owner.owner_epoch += 1,
            _ => changed.schema_version = 1,
        }
        assert!(client.verify_exact(&changed, &binding).is_err());
    }
}

#[test]
fn missing_domain_old_schema_or_unknown_reply_cannot_create_completion() {
    let (client, binding, mut response) = fixture();
    response.binding = None;
    assert!(client.verify_exact(&response, &binding).is_err());
    let missing = serde_json::json!({"schema_version":1,"pid":1,"instance":"domain",
        "accepted":true,"running":false,"code":"domain_stopped",
        "live_domains":0,"completed_domains":0,"max_domains":1});
    assert!(serde_json::from_value::<DomainEvidence>(missing).is_err());
    let mut response = fixture().2;
    response.joined_completion = Some(JoinedCompletion::Returned {
        exit_code: 256,
        detail: None,
    });
    assert!(client.verify_exact(&response, &binding).is_err());
    response.joined_completion = Some(JoinedCompletion::Panicked);
    client.verify_exact(&response, &binding).unwrap();
    response.joined_completion = Some(JoinedCompletion::ResultUnavailable);
    client.verify_exact(&response, &binding).unwrap();
}

#[test]
fn failed_authenticated_exchange_remains_error_instead_of_completion() {
    let (client, binding, _) = fixture();
    assert!(client.query(&binding).is_err());
}
