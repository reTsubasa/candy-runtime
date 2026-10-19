pub(super) fn matches_worker_recovery(
    before: &serde_json::Value,
    after: &serde_json::Value,
    worker_epoch: u64,
) -> bool {
    let Some(previous_epoch) = before["worker_epoch"].as_u64() else {
        return false;
    };
    if worker_epoch <= previous_epoch || !before.is_object() {
        return false;
    }
    let mut expected = before.clone();
    expected["worker_epoch"] = worker_epoch.into();
    *after == expected
}
