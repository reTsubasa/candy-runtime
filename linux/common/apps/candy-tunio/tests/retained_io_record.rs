#[path = "fixtures/retained_io_record.rs"]
mod retained_io_record;

fn record() -> serde_json::Value {
    serde_json::json!({
        "pid":154,"process_start_ticks":9268717,"executable_inode":302197,
        "worker_epoch":2,"io_epoch":1,"auth_deadline_unix":1792139478,
        "packet_binding_file":"binding.json","readiness_token_sha256":"original",
        "policy_generation":1,"infrastructure_generation":1
    })
}

#[test]
fn recovery_changes_only_the_business_worker_epoch() {
    let before = record();
    let mut after = before.clone();
    after["worker_epoch"] = 3.into();
    assert!(retained_io_record::matches_worker_recovery(
        &before, &after, 3
    ));
    assert!(!retained_io_record::matches_worker_recovery(
        &before, &before, 3
    ));
    assert!(!retained_io_record::matches_worker_recovery(
        &before, &after, 2
    ));
}

#[test]
fn recovery_rejects_infrastructure_and_authorization_mutations() {
    let before = record();
    for (field, value) in [
        ("pid", serde_json::json!(155)),
        ("process_start_ticks", serde_json::json!(9268718)),
        ("executable_inode", serde_json::json!(302198)),
        ("io_epoch", serde_json::json!(2)),
        ("auth_deadline_unix", serde_json::json!(1792139479)),
        ("packet_binding_file", serde_json::json!("other.json")),
        ("readiness_token_sha256", serde_json::json!("replacement")),
        ("policy_generation", serde_json::json!(2)),
        ("infrastructure_generation", serde_json::json!(2)),
    ] {
        let mut after = before.clone();
        after["worker_epoch"] = 3.into();
        after[field] = value;
        assert!(
            !retained_io_record::matches_worker_recovery(&before, &after, 3),
            "accepted changed {field}"
        );
    }
}
