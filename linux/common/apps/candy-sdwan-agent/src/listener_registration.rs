//! Prepared ingress permits authentication, while netd retains the forwarding fence.
use super::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListenerPlan {
    pub directory: PathBuf,
    pub server_config: PathBuf,
    pub worker_id: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Master {
    schema_version: u8,
    instance: String,
    process: candy_process_control::ProcessIdentity,
    transport_id: u64,
    uid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Registration {
    schema_version: u8,
    master_instance: String,
    routing_domain_id: [u8; 16],
    worker_id: u64,
    worker_epoch: u64,
    pid: u32,
    process_start_ticks: u64,
    uid: u32,
    dispatch: PathBuf,
    process_record: PathBuf,
    effective_plan: PathBuf,
    authorization_sha256: String,
    policy_generation: u64,
    #[serde(default)]
    policy_revision: u64,
    auth_deadline_unix: u64,
    #[serde(default)]
    prepared_ingress: bool,
}

fn stale_registration(current: &Registration, proposed: &Registration) -> bool {
    let same_owner = current.worker_epoch == proposed.worker_epoch
        && current.worker_id == proposed.worker_id
        && current.pid == proposed.pid
        && current.process_start_ticks == proposed.process_start_ticks
        && current.routing_domain_id == proposed.routing_domain_id;
    current.worker_epoch > proposed.worker_epoch
        || (current.worker_epoch == proposed.worker_epoch && !same_owner)
        || current.policy_generation > proposed.policy_generation
        || (same_owner
            && (current.policy_revision > proposed.policy_revision
                || (current.policy_revision == proposed.policy_revision
                    && (current.policy_generation != proposed.policy_generation
                        || current.authorization_sha256 != proposed.authorization_sha256))))
}

pub(super) fn validate(plan: &Plan) -> Result<()> {
    let Some(listener) = &plan.shared_listener else {
        return Ok(());
    };
    if !cfg!(all(
        feature = "experimental-tunio-rebind",
        target_os = "linux"
    )) || plan.independent_worker.is_none()
        || !listener.directory.is_absolute()
        || !listener.server_config.is_absolute()
        || listener.worker_id == 0
    {
        bail!("code=listener_plan_invalid module=listener_registry detail=Linux experimental-tunio-rebind, independent worker and absolute paths required");
    }
    Ok(())
}

pub(super) fn arguments(plan: &Plan) -> Result<Vec<String>> {
    validate(plan)?;
    let Some(listener) = &plan.shared_listener else {
        return Ok(Vec::new());
    };
    if plan.authority.is_none()
        || plan.effective_plan_file.is_none()
        || plan.authorization_snapshot_sha256.is_none()
    {
        bail!("code=listener_authority_unprepared module=listener_registry detail=spawn requires verified signed candidate plan");
    }
    Ok(vec![
        "--shared-listener-master-directory".into(),
        listener.directory.display().to_string(),
        "--shared-listener-server-config".into(),
        listener.server_config.display().to_string(),
        "--shared-listener-worker-id".into(),
        listener.worker_id.to_string(),
        "--shared-listener-owner-epoch".into(),
        plan.worker_epoch.to_string(),
    ])
}

fn private_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > 16384
    {
        bail!("code=listener_receipt_invalid module=listener_registry detail=private bounded regular file required");
    }
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        bail!("listener receipt exceeds limit");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn publish_registration(plan: &Plan, owner_path: &Path, prepared_ingress: bool) -> Result<()> {
    validate(plan)?;
    let Some(listener) = &plan.shared_listener else {
        return Ok(());
    };
    let metadata = fs::symlink_metadata(&listener.directory)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        bail!("code=listener_registry_directory_invalid module=listener_registry");
    }
    let master: Master = private_json(&listener.directory.join("listener-master.json"))?;
    if master.schema_version != 1
        || master.transport_id == 0
        || master.uid != metadata.uid()
        || !candy_process_control::process_is_current_confirmed(master.process).context(
            "code=listener_master_liveness_unconfirmed module=listener_registry action=retry_preserve_domain",
        )?
    {
        bail!("code=listener_master_unavailable module=listener_registry action=retry_preserve_domain");
    }
    let record = crate::process_record::read(owner_path)?;
    let status = record.validate_bound_status(&plan.core, unix_time()?)?;
    if !listener_available(&status) {
        bail!("code=listener_worker_unavailable module=listener_registry detail=bound transport listener is unavailable");
    }
    if record.worker_epoch != Some(plan.worker_epoch)
        || record.policy_generation != plan.signed_generation
        || record.authorization_snapshot_sha256 != plan.authorization_snapshot_sha256
        || record.auth_deadline_unix != plan.auth_deadline_unix
    {
        bail!("code=listener_owner_mismatch module=listener_registry");
    }
    if plan.policy_revision != 0
        && (status["authorization_snapshot_sha256"].as_str()
            != plan.authorization_snapshot_sha256.as_deref()
            || status["policy_revision"] != plan.policy_revision)
    {
        bail!("code=listener_active_policy_unacknowledged module=listener_registry action=await_exact_core_policy_receipt");
    }
    let registration = Registration {
        schema_version: 1,
        master_instance: master.instance,
        routing_domain_id: plan.domain_id,
        worker_id: listener.worker_id,
        worker_epoch: plan.worker_epoch,
        pid: record.pid,
        process_start_ticks: record.process_start_ticks,
        uid: record.uid,
        dispatch: plan
            .independent_worker
            .as_ref()
            .context("independent worker absent")?
            .control_socket
            .with_extension("transport.sock"),
        process_record: owner_path.to_owned(),
        effective_plan: plan
            .effective_plan_file
            .clone()
            .context("effective plan absent")?,
        authorization_sha256: plan
            .authorization_snapshot_sha256
            .clone()
            .context("signed authorization absent")?,
        policy_generation: plan.signed_generation,
        policy_revision: plan.policy_revision,
        auth_deadline_unix: plan.auth_deadline_unix,
        prepared_ingress,
    };
    let domain = plan
        .domain_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let destination = listener.directory.join(format!("{domain}.domain"));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(listener.directory.join(format!("{domain}.lock")))?;
    let metadata = lock.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "code=listener_registration_lock_invalid module=listener_registry detail=private regular lock required"
    );
    // SAFETY: this is an owned regular descriptor and flock does not access memory.
    if unsafe { nix::libc::flock(lock.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("code=listener_registration_busy module=listener_registry action=retry_preserve_active_owner");
    }
    match private_json::<Registration>(&destination) {
        Ok(current) => {
            if current == registration {
                return verify_activation(listener, &registration);
            }
            if is_committed_equivalent(&current, &registration) {
                return verify_activation(listener, &current);
            }
            if stale_registration(&current, &registration) {
                bail!("code=listener_epoch_stale module=listener_registry action=preserve_newer_owner");
            }
        }
        Err(error) => match fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(error.context(
                    "code=listener_registration_unconfirmed module=listener_registry action=preserve_active_owner_and_retry",
                ));
            }
            Err(metadata_error) if metadata_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(metadata_error) => {
                return Err(anyhow::Error::from(metadata_error).context(
                    "code=listener_registration_unconfirmed module=listener_registry action=preserve_active_owner_and_retry",
                ));
            }
        },
    }
    let temporary = listener
        .directory
        .join(format!(".{domain}-{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(&registration)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        File::open(&listener.directory)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result?;
    verify_activation(listener, &registration)
}

pub(super) fn listener_available(status: &serde_json::Value) -> bool {
    matches!(status["lifecycle"].as_str(), Some("active" | "starting"))
        || status["lifecycle"] == "failed" && status["registered_listener_ready"] == true
}

fn is_committed_equivalent(current: &Registration, proposed: &Registration) -> bool {
    if !proposed.prepared_ingress || current.prepared_ingress {
        return false;
    }
    let mut committed = proposed.clone();
    committed.prepared_ingress = false;
    *current == committed
}

fn verify_activation(listener: &ListenerPlan, expected: &Registration) -> Result<()> {
    let master_path = listener.directory.join("listener-master.json");
    let master: Master = private_json(&master_path)
        .context("code=listener_master_unavailable module=listener_registry action=retry_preserve_active_owner")?;
    anyhow::ensure!(
        master.schema_version == 1
            && master.instance == expected.master_instance
            && master.transport_id != 0
            && master.uid == expected.uid
            && candy_process_control::process_is_current_confirmed(master.process).context(
                "code=listener_master_liveness_unconfirmed module=listener_registry action=retry_preserve_active_owner",
            )?,
        "code=listener_master_stale module=listener_registry action=retry_preserve_active_owner"
    );
    let domain = expected
        .routing_domain_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let active: Registration = private_json(&listener.directory.join(format!("{domain}.activation")))
        .context("code=listener_activation_ack_pending module=listener_registry detail=master has not acknowledged the exact domain generation")?;
    if active != *expected {
        bail!("code=listener_activation_ack_mismatch module=listener_registry action=retry_preserve_forwarding_state");
    }
    let current: Master = private_json(&master_path)
        .context("code=listener_master_unavailable module=listener_registry action=retry_preserve_active_owner")?;
    anyhow::ensure!(
        current == master
            && candy_process_control::process_is_current_confirmed(current.process).context(
                "code=listener_master_liveness_unconfirmed module=listener_registry action=retry_preserve_active_owner",
            )?,
        "code=listener_master_changed module=listener_registry action=retry_preserve_active_owner"
    );
    Ok(())
}

#[derive(Serialize)]
struct PendingActivation<'a> {
    schema_version: u8,
    routing_domain_id: [u8; 16],
    worker_epoch: u64,
    process_record: &'a Path,
    effective_plan: &'a Path,
    prepared_ingress: bool,
}

fn publish_with_pending(plan: &Plan, owner_path: &Path, prepared: bool) -> Result<()> {
    if plan.shared_listener.is_none() {
        return Ok(());
    }
    let path = owner_path.with_extension("listener-pending.json");
    let failure = match publish_registration(plan, owner_path, prepared) {
        Ok(()) => {
            match fs::remove_file(&path) {
                Ok(()) => {
                    File::open(path.parent().context("pending parent absent")?)?.sync_all()?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
            return Ok(());
        }
        Err(error) => error,
    };
    let temporary =
        owner_path.with_extension(format!("listener-{}.tmp", uuid::Uuid::new_v4().simple()));
    let pending = PendingActivation {
        schema_version: 1,
        routing_domain_id: plan.domain_id,
        worker_epoch: plan.worker_epoch,
        process_record: owner_path,
        effective_plan: plan
            .effective_plan_file
            .as_deref()
            .context("listener candidate plan absent")?,
        prepared_ingress: prepared,
    };
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(&pending)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        File::open(path.parent().context("pending parent absent")?)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result?;
    Err(failure)
}

pub(super) fn publish_pending(plan: &Plan, owner_path: &Path) {
    if let Err(error) = publish_with_pending(plan, owner_path, false) {
        eprintln!("level=warn code=listener_registration_pending module=listener_registry detail={error:#} action=retry_preserve_committed_domain_and_infrastructure");
    }
}

pub(super) fn publish_prepared_pending(plan: &Plan) {
    let Some(worker) = &plan.independent_worker else {
        return;
    };
    if let Err(error) = publish_with_pending(plan, &worker.process_record, true) {
        eprintln!("level=warn code=listener_prepared_registration_pending module=listener_registry detail={error:#} action=retry_keep_forwarding_fenced");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn failed_packet_lane_preserves_only_an_explicitly_live_listener() {
        for lifecycle in ["active", "starting"] {
            assert!(listener_available(
                &serde_json::json!({"lifecycle": lifecycle})
            ));
        }
        assert!(listener_available(&serde_json::json!({
            "lifecycle": "failed", "registered_listener_ready": true
        })));
        for lifecycle in ["failed", "stopped", "unknown"] {
            assert!(!listener_available(
                &serde_json::json!({"lifecycle": lifecycle})
            ));
            assert!(!listener_available(&serde_json::json!({
                "lifecycle": lifecycle, "registered_listener_ready": false
            })));
        }
        assert!(!listener_available(&serde_json::json!({
            "lifecycle": "stopped", "registered_listener_ready": true
        })));
    }

    #[test]
    fn activation_ack_requires_exact_master_owner_authority_and_phase() {
        let root = tempfile::tempdir().unwrap();
        let listener = ListenerPlan {
            directory: root.path().to_owned(),
            server_config: root.path().join("server.toml"),
            worker_id: 1,
        };
        let process = candy_process_control::process_identity(std::process::id()).unwrap();
        let master = Master {
            schema_version: 1,
            instance: "master-generation".into(),
            process,
            transport_id: 1,
            uid: nix::unistd::geteuid().as_raw(),
        };
        let mut master_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join("listener-master.json"))
            .unwrap();
        master_file
            .write_all(&serde_json::to_vec(&master).unwrap())
            .unwrap();
        master_file.sync_all().unwrap();
        let expected = Registration {
            schema_version: 1,
            master_instance: "master-generation".into(),
            routing_domain_id: [1; 16],
            worker_id: 1,
            worker_epoch: 7,
            pid: 123,
            process_start_ticks: 456,
            uid: nix::unistd::geteuid().as_raw(),
            dispatch: root.path().join("transport.sock"),
            process_record: root.path().join("process.json"),
            effective_plan: root.path().join("plan.json"),
            authorization_sha256: "ab".repeat(32),
            policy_generation: 9,
            policy_revision: 0,
            auth_deadline_unix: 9999999999,
            prepared_ingress: false,
        };
        let path = root.path().join(format!("{}.activation", "01".repeat(16)));
        let mut prepared = expected.clone();
        let mut refreshed = expected.clone();
        refreshed.policy_revision = 1;
        refreshed.authorization_sha256 = "cd".repeat(32);
        assert!(!stale_registration(&expected, &refreshed));
        assert!(stale_registration(&refreshed, &expected));
        let mut conflict = refreshed.clone();
        conflict.authorization_sha256 = "ef".repeat(32);
        assert!(stale_registration(&refreshed, &conflict));
        conflict.policy_generation += 1;
        assert!(stale_registration(&refreshed, &conflict));
        conflict.policy_revision += 1;
        assert!(!stale_registration(&refreshed, &conflict));
        let mut successor = refreshed.clone();
        successor.worker_epoch += 1;
        successor.pid += 1;
        successor.process_start_ticks += 1;
        successor.policy_revision = 0;
        successor.authorization_sha256 = "ef".repeat(32);
        // A new signed physical authority may renew a Grant in the same policy generation.
        assert!(!stale_registration(&refreshed, &successor));
        assert!(stale_registration(&successor, &refreshed));
        let mut reused_epoch = successor.clone();
        reused_epoch.worker_epoch = refreshed.worker_epoch;
        assert!(stale_registration(&refreshed, &reused_epoch));
        prepared.prepared_ingress = true;
        assert!(is_committed_equivalent(&expected, &prepared));
        for fault in 0..6 {
            let mut changed = prepared.clone();
            match fault {
                0 => changed.master_instance = "old-master".into(),
                1 => changed.worker_epoch += 1,
                2 => changed.authorization_sha256 = "cd".repeat(32),
                3 => changed.policy_generation += 1,
                4 => changed.dispatch = root.path().join("wrong.sock"),
                _ => changed.auth_deadline_unix -= 1,
            }
            assert!(!is_committed_equivalent(&expected, &changed));
        }
        assert!(verify_activation(&listener, &expected).is_err());
        for fault in 0..6 {
            let mut changed = expected.clone();
            match fault {
                0 => changed.master_instance = "old-master".into(),
                1 => changed.worker_epoch += 1,
                2 => changed.process_start_ticks += 1,
                3 => changed.authorization_sha256 = "cd".repeat(32),
                4 => changed.prepared_ingress = true,
                _ => changed.policy_generation += 1,
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(&serde_json::to_vec(&changed).unwrap())
                .unwrap();
            assert!(verify_activation(&listener, &expected).is_err());
        }
        fs::write(&path, serde_json::to_vec(&expected).unwrap()).unwrap();
        verify_activation(&listener, &expected).unwrap();
        let master_path = root.path().join("listener-master.json");
        // An exact ACK from the previous incarnation cannot prove activation by
        // a replacement master, even while the old PID is still alive.
        for fault in 0..5 {
            let mut changed = master.clone();
            match fault {
                0 => changed.instance = "replacement-master".into(),
                1 => changed.process.start_ticks += 1,
                2 => changed.process.pid = 0,
                3 => changed.transport_id = 0,
                _ => changed.uid = changed.uid.wrapping_add(1),
            }
            fs::write(&master_path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(verify_activation(&listener, &expected).is_err());
        }
        fs::write(&master_path, serde_json::to_vec(&master).unwrap()).unwrap();
        verify_activation(&listener, &expected).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verify_activation(&listener, &expected).is_err());
    }
}
