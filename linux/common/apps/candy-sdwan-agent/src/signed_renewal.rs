use super::*;

#[cfg(any(test, all(feature = "experimental-tunio-rebind", target_os = "linux")))]
fn next_authority_epochs(binding_epoch: u64, epochs: &[u64], fences: &[u64]) -> Result<(u64, u64)> {
    Ok((
        next_recovery_epoch(std::iter::once(binding_epoch).chain(epochs.iter().copied()))?,
        next_recovery_epoch(fences.iter().copied())?,
    ))
}

#[cfg(any(test, all(feature = "experimental-tunio-rebind", target_os = "linux")))]
fn authorization_clock_sample(
    expiry_unix: u64,
    verified_mono_ms: u64,
    verified_wall: Duration,
) -> Result<(u64, u64)> {
    let remaining = Duration::from_secs(expiry_unix)
        .checked_sub(verified_wall)
        .filter(|value| !value.is_zero())
        .context("new signed authority expired")?;
    if remaining > Duration::from_secs(3600) {
        bail!("experimental detached authority is limited to one hour");
    }
    let cap = verified_mono_ms
        .checked_add(u64::try_from(remaining.as_millis())?)
        .context("authority deadline overflow")?;
    // Keep the wall timestamp associated with this exact monotonic cap. The
    // stop/spawn barrier can cross a wall second before the envelope is sent.
    Ok((verified_wall.as_secs(), cap))
}

#[cfg(not(all(feature = "experimental-tunio-rebind", target_os = "linux")))]
pub(super) fn run(_: &Path) -> Result<()> {
    bail!("code=signed_renewal_feature_required module=sdwan_activation detail=signed authority renewal requires Linux experimental-tunio-rebind");
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
mod linux {
    use super::*;
    use crate::signed_snapshot::Snapshot;
    use candy_netd_proto::v2::{ForwardAuthority, ForwardAuthorityReceipt};
    use candy_process_control::{
        exchange, process_identity, process_is_current_confirmed, ControlOperation, ControlRequest,
        ProcessIdentity,
    };
    use candy_tunio::authority_control::{
        authority_control_path, exchange_authority, AuthorityControlRequest, AuthorityEnvelope,
        AuthorityOperation as AuthorityControlOperation,
    };
    use sha2::{Digest, Sha256};

    // Journal embeds one bounded Plan for crash recovery, plus snapshot and receipt metadata.
    const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Journal {
        schema_version: u8,
        phase: String,
        snapshot: Snapshot,
        envelope: Option<AuthorityEnvelope>,
        candidate_plan: PathBuf,
        #[serde(default)]
        candidate_plan_snapshot: Option<Plan>,
        candidate_record: PathBuf,
        owner: ForwardOwner,
        old_worker: Option<crate::process_record::ManagedProcessRecord>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        candidate_owner: Option<super::super::candidate_ownership::CandidateOwner>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mbb_reservation: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mbb_failed_retirement: Option<super::super::candidate_ownership::CandidateProof>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mbb_outcome: Option<String>,
    }

    fn publish<T: Serialize>(path: &Path, object: &T) -> Result<()> {
        publish_with_limit(path, object, MAX_JOURNAL_BYTES)
    }

    fn publish_with_limit<T: Serialize>(path: &Path, object: &T, limit: u64) -> Result<()> {
        let bytes = serde_json::to_vec(object)?;
        if bytes.len() as u64 > limit {
            bail!("code=renewal_state_size_exceeded module=sdwan_activation detail=serialized renewal state exceeds explicit budget");
        }
        let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            OpenOptions::new()
                .read(true)
                .open(path.parent().context("missing journal parent")?)?
                .sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    pub(in crate::experimental_tunio) fn publish_plan(plan: &Plan) -> Result<()> {
        publish_with_limit(
            plan.effective_plan_file
                .as_ref()
                .context("effective immutable plan path absent")?,
            plan,
            MAX_SIGNED_CONFIG_BYTES,
        )
    }

    fn read_private<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() > MAX_JOURNAL_BYTES
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
        {
            bail!("renewal journal must be private bounded regular file");
        }
        Ok(serde_json::from_reader(file.take(MAX_JOURNAL_BYTES + 1))?)
    }

    fn stop_record(
        record: &crate::process_record::ManagedProcessRecord,
        plan: &Plan,
    ) -> Result<()> {
        let identity = ProcessIdentity {
            pid: record.pid,
            start_ticks: record.process_start_ticks,
        };
        if !record.business_is_current().context(ManagedProofPending)? {
            if let (Some(host), Some(instance)) =
                (&record.shared_worker, &record.shared_domain_instance)
            {
                if process_is_current_confirmed(host.identity).context(ManagedProofPending)? {
                    crate::shared_worker::forget_domain(host, instance)?;
                }
            }
            return Ok(());
        }
        record.validate_infrastructure_identity(&plan.core)?;
        let worker = plan
            .independent_worker
            .as_ref()
            .context("recorded Core private control absent")?;
        for operation in [ControlOperation::Takeover, ControlOperation::Stop] {
            exchange(
                &worker.control_socket,
                identity,
                &ControlRequest {
                    schema_version: 1,
                    operation,
                    token_sha256: record.readiness_token_sha256.clone(),
                    nonce: uuid::Uuid::new_v4().simple().to_string(),
                },
            )?;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while record.business_is_current().context(ManagedProofPending)?
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(20));
        }
        if record.business_is_current().context(ManagedProofPending)? {
            bail!("code=renewal_old_core_stop_pending module=process_supervisor detail=authenticated stop did not retire old Core within deadline");
        }
        if let (Some(host), Some(instance)) =
            (&record.shared_worker, &record.shared_domain_instance)
        {
            crate::shared_worker::forget_domain(host, instance)?;
        }
        if record.shared_worker.is_none() {
            unsafe {
                nix::libc::waitpid(
                    identity.pid as i32,
                    std::ptr::null_mut(),
                    nix::libc::WNOHANG,
                );
            }
        }
        Ok(())
    }

    fn retire_plan(plan: &Plan, parent: &Path) -> Result<()> {
        let directory = plan
            .core_config
            .parent()
            .context("snapshot directory absent")?;
        if directory.parent() != Some(parent)
            || !directory
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("signed-snapshot-"))
        {
            bail!("retirement is restricted to an owned generated snapshot");
        }
        if directory.try_exists()? {
            match fs::read(directory.join("manifest.json")) {
                Ok(bytes) => {
                    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
                    if snapshot.directory != directory || snapshot.config != plan.core_config {
                        bail!("retirement snapshot binding differs");
                    }
                    snapshot.retire()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let metadata = fs::symlink_metadata(directory)?;
                    if !metadata.is_dir()
                        || metadata.file_type().is_symlink()
                        || metadata.uid() != nix::unistd::geteuid().as_raw()
                        || metadata.mode() & 0o777 != 0o700
                        || fs::read_dir(directory)?.next().is_some()
                    {
                        bail!("generated snapshot without manifest is not an empty private retirement remainder");
                    }
                    fs::remove_dir(directory)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        for path in [&plan.binding_file, &plan.core_status] {
            let _ = fs::remove_file(path);
        }
        if let Some(worker) = &plan.independent_worker {
            let _ = fs::remove_file(&worker.control_socket);
        }
        if let Some(path) = &plan.effective_plan_file {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }

    fn retire_old_worker(journal: &Journal, desired: &Plan, parent: &Path) -> Result<()> {
        let Some(old) = &journal.old_worker else {
            return Ok(());
        };
        let old_plan = match &old.effective_plan_file {
            Some(path) if path.try_exists()? => read_plan(path)?,
            Some(_) => {
                if old.business_is_current().context(ManagedProofPending)? {
                    bail!("code=renewal_old_core_cleanup_pending module=process_supervisor detail=old Core remains alive but immutable plan is absent");
                }
                return Ok(());
            }
            None => desired.clone(),
        };
        stop_record(old, &old_plan)?;
        if old.effective_plan_file.is_some() {
            retire_plan(&old_plan, parent)?;
        }
        Ok(())
    }

    fn exact_ready(
        plan: &Plan,
        record: &crate::process_record::ManagedProcessRecord,
        envelope: &AuthorityEnvelope,
    ) -> Result<()> {
        let status = record.validate_bound_status(&plan.core, unix_time()?)?;
        validate_worker_placement(plan, record, &status)?;
        if status["worker_authority_revision"] != envelope.authority_revision
            || status["worker_authority_sha256"] != envelope.signed_control_hash
            || status["worker_transaction_id"] != envelope.transaction_id
            || status["packet_binding"] != serde_json::to_value(envelope.binding)?
        {
            bail!("code=signed_candidate_proof_mismatch module=sdwan_activation detail=fresh Core authority revision/hash/transaction/binding differs");
        }
        match status["lifecycle"].as_str() {
            Some("active" | "starting") => {}
            Some("failed")
                if plan.shared_listener.is_some()
                    && listener_registration::listener_available(&status) => {}
            Some("failed" | "stopped") => {
                eprintln!("level=warn code=signed_candidate_unavailable module=sdwan_activation pid={} lifecycle={} detail=authenticated_candidate_reported_terminal_lifecycle action=retry_verified_authority_preserve_infrastructure", record.pid, status["lifecycle"]);
                return Err(CoreRecoveryRequired.into());
            }
            _ => bail!("code=signed_candidate_lifecycle_invalid module=sdwan_activation detail=authenticated candidate has unknown lifecycle"),
        }
        Ok(())
    }

    fn finish_records(
        plan: &mut Plan,
        journal: &mut Journal,
        journal_path: &Path,
        owner_record: &Path,
        io_record_path: &Path,
        io_record: &crate::process_record::ManagedProcessRecord,
    ) -> Result<()> {
        let envelope = journal
            .envelope
            .as_ref()
            .context("renewal envelope absent")?;
        let mut record = crate::process_record::read(&journal.candidate_record)?;
        exact_ready(plan, &record, envelope)?;
        record.effective_plan_file = Some(journal.candidate_plan.clone());
        plan.independent_worker
            .as_mut()
            .context("candidate worker absent")?
            .process_record = owner_record.to_owned();
        publish(&journal.candidate_plan, plan)?;
        journal.candidate_plan_snapshot = Some(plan.clone());
        crate::process_record::publish(owner_record, &record)?;
        let mut updated_io = io_record.clone();
        updated_io.policy_generation = plan.signed_generation;
        updated_io.auth_deadline_unix = plan.auth_deadline_unix;
        updated_io.status_generation = io_record.private_status()?["generation"].as_u64();
        updated_io.worker_epoch = Some(plan.worker_epoch);
        crate::process_record::publish(io_record_path, &updated_io)?;
        journal.phase = "committed".into();
        publish(journal_path, journal)?;
        listener_registration::publish_pending(plan, owner_record);
        retire_candidate_record(journal, owner_record)?;
        Ok(())
    }

    fn retire_candidate_record(journal: &Journal, owner_record: &Path) -> Result<()> {
        if journal.candidate_record == owner_record {
            return Ok(());
        }
        match fs::remove_file(&journal.candidate_record) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn forward_authority(envelope: &AuthorityEnvelope, io: ProcessIdentity) -> ForwardAuthority {
        ForwardAuthority {
            transaction_id: envelope.transaction_id.clone(),
            authority_revision: envelope.authority_revision,
            signed_control_hash: envelope.signed_control_hash.clone(),
            declaration_hash: envelope.declaration_hash.clone(),
            snapshot_closure_hash: envelope.snapshot_closure_hash.clone(),
            io_epoch: envelope.binding.io_epoch,
            io_pid: io.pid,
            io_start_ticks: io.start_ticks,
            candidate_pid: envelope.candidate.pid,
            candidate_start_ticks: envelope.candidate.start_ticks,
        }
    }

    pub(in crate::experimental_tunio) fn commit_authorized(
        plan: &Plan,
        record: &crate::process_record::ManagedProcessRecord,
        owner: &ForwardOwner,
        netd: &mut NetdControl,
    ) -> Result<()> {
        let io = plan
            .independent_supervision
            .as_ref()
            .context("authorized commit IO absent")?;
        let io_record = crate::process_record::read(&io.process_record)?;
        io_record.validate_infrastructure_current(&plan.tunio)?;
        let identity = ProcessIdentity {
            pid: io_record.pid,
            start_ticks: io_record.process_start_ticks,
        };
        let controller = process_identity(std::process::id())?;
        let takeover = exchange(
            &io.control_socket,
            identity,
            &ControlRequest {
                schema_version: 1,
                operation: ControlOperation::Takeover,
                token_sha256: io_record.readiness_token_sha256.clone(),
                nonce: uuid::Uuid::new_v4().simple().to_string(),
            },
        )?;
        let proof = plan
            .authority
            .as_ref()
            .context("candidate authority proof absent")?;
        let actual = exchange_authority(
            &authority_control_path(&io.control_socket),
            identity,
            &AuthorityControlRequest {
                schema_version: 2,
                process: identity,
                controller,
                controller_epoch: takeover.controller_epoch,
                token_sha256: io_record.readiness_token_sha256.clone(),
                nonce: uuid::Uuid::new_v4().simple().to_string(),
                operation: AuthorityControlOperation::ProbeTransaction,
                envelope: None,
                transaction_id: proof.transaction_id.clone(),
            },
            None,
            Instant::now() + Duration::from_secs(2),
        )?;
        let envelope = actual
            .active
            .context("IO actual current authorization absent")?;
        if !actual.owner_active
            || actual.applied_transaction_id.as_deref() != Some(proof.transaction_id.as_str())
            || actual.authority_revision != Some(proof.revision)
            || envelope.signed_control_hash != proof.sha256
            || envelope.candidate.pid != record.pid
            || envelope.candidate.start_ticks != record.process_start_ticks
            || envelope.binding.owner_epoch != plan.worker_epoch
            || actual.current_binding != envelope.binding
            || actual
                .actual_deadline_mono_ms
                .is_none_or(|cap| cap < owner.auth_deadline_mono_ms)
        {
            bail!("actual applied authority does not prove current candidate owner/cap");
        }
        exact_ready(plan, record, &envelope)?;
        let status = record.private_status()?;
        let reported = status["reported_at_mono_ms"]
            .as_u64()
            .context("fresh packet report clock absent")?;
        expect_ack(
            netd,
            Operation::ForwardAuthorize {
                owner: owner.clone(),
                authority: forward_authority(&envelope, identity),
            },
        )?;
        expect_ack(
            netd,
            Operation::ForwardCommitAuthorized {
                owner: owner.clone(),
                receipt: ForwardAuthorityReceipt {
                    authority: forward_authority(&envelope, identity),
                    owner_active: true,
                    authorization_deadline_mono_ms: owner.auth_deadline_mono_ms,
                    packet_proof_reported_mono_ms: reported,
                },
            },
        )
    }

    pub(in crate::experimental_tunio) fn run(path: &Path) -> Result<()> {
        let desired = recovery_plan(verified_plan(path)?)?;
        run_with_plan(path, desired)
    }

    pub(in crate::experimental_tunio) fn archive_retired_io_transaction(
        desired: &Plan,
        retired_io: &crate::process_record::ManagedProcessRecord,
    ) -> Result<Option<PathBuf>> {
        let identity = ProcessIdentity {
            pid: retired_io.pid,
            start_ticks: retired_io.process_start_ticks,
        };
        if process_is_current_confirmed(identity).context(ManagedProofPending)? {
            bail!("cannot archive a live IO transaction");
        }
        let path = desired
            .independent_worker
            .as_ref()
            .context("original worker record absent")?
            .process_record
            .with_extension("renewal.json");
        if !path.try_exists()? {
            return Ok(None);
        }
        let journal: Journal = read_private(&path)?;
        let candidate = journal
            .candidate_plan_snapshot
            .as_ref()
            .context("retired IO journal scope absent")?;
        if journal.schema_version != 1
            || candidate.infrastructure != desired.infrastructure
            || candidate.domain_id != desired.domain_id
            || Some(candidate.io_epoch) != retired_io.io_epoch
        {
            bail!("retired IO transaction scope differs; refusing unsafe journal replacement");
        }
        if let Some(record) = crate::process_record::read_optional(&journal.candidate_record)
            .context(ManagedProofPending)?
        {
            if record.business_is_current().context(ManagedProofPending)? {
                bail!("retired IO transaction has a live candidate Core");
            }
        } else if let Some(worker) = &candidate.independent_worker {
            preserve_unrecorded_endpoint(&worker.control_socket)?;
        }
        let archived = path.with_extension(format!(
            "retired-io-{}-{}.json",
            retired_io.pid,
            uuid::Uuid::new_v4().simple()
        ));
        fs::rename(&path, &archived)?;
        OpenOptions::new()
            .read(true)
            .open(path.parent().context("journal parent absent")?)?
            .sync_all()?;
        Ok(Some(archived))
    }

    pub(in crate::experimental_tunio) fn run_with_plan(path: &Path, desired: Plan) -> Result<()> {
        let io = desired
            .independent_supervision
            .as_ref()
            .context("renewal requires independent I/O")?
            .clone();
        let original_worker = desired
            .independent_worker
            .as_ref()
            .context("renewal requires independent Core")?
            .clone();
        let io_record = crate::process_record::read(&io.process_record)?;
        io_record.validate_infrastructure_current(&desired.tunio)?;
        let io_identity = ProcessIdentity {
            pid: io_record.pid,
            start_ticks: io_record.process_start_ticks,
        };
        if io_record.infrastructure_generation != desired.infrastructure.generation
            || io_record
                .io_epoch
                .is_some_and(|epoch| epoch != desired.io_epoch)
        {
            bail!("renewal cannot change infrastructure/IO identity");
        }
        let io_status = io_record.private_status()?;
        let binding: candy_tunio::attach_control::PacketPortBinding =
            serde_json::from_value(io_status["packet_binding"].clone())?;
        if binding.infrastructure_id != desired.infrastructure.infra_id
            || binding.routing_domain_id != desired.domain_id
            || binding.infrastructure_generation != desired.infrastructure.generation
            || binding.io_epoch != desired.io_epoch
            || desired.signed_generation < binding.policy_generation
        {
            bail!("new authority domain/infrastructure/policy is incompatible");
        }
        let controller = process_identity(std::process::id())?;
        let takeover = exchange(
            &io.control_socket,
            io_identity,
            &ControlRequest {
                schema_version: 1,
                operation: ControlOperation::Takeover,
                token_sha256: io_record.readiness_token_sha256.clone(),
                nonce: uuid::Uuid::new_v4().simple().to_string(),
            },
        )?;
        if takeover.controller != controller || takeover.controller_epoch == 0 {
            bail!("renewal IO controller fence differs");
        }
        let authority_path = authority_control_path(&io.control_socket);
        let request = |operation, envelope, transaction_id| AuthorityControlRequest {
            schema_version: 2,
            process: io_identity,
            controller,
            controller_epoch: takeover.controller_epoch,
            token_sha256: io_record.readiness_token_sha256.clone(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            operation,
            envelope,
            transaction_id,
        };
        let mut actual = exchange_authority(
            &authority_path,
            io_identity,
            &request(
                AuthorityControlOperation::ProbeTransaction,
                None,
                uuid::Uuid::new_v4().simple().to_string(),
            ),
            None,
            Instant::now() + Duration::from_secs(2),
        )?;
        let parent = original_worker
            .process_record
            .parent()
            .context("missing private owner directory")?;
        let old_worker = crate::process_record::read_optional(&original_worker.process_record)
            .context(ManagedProofPending)?;
        let journal_path = original_worker
            .process_record
            .with_extension("renewal.json");
        let mut consumed_epoch = desired.worker_epoch;
        let mut consumed_fence = desired.fencing_token;
        if journal_path.try_exists()? {
            let mut previous_journal: Journal = read_private(&journal_path)?;
            if previous_journal.schema_version != 1 {
                bail!("renewal journal schema differs");
            }
            if previous_journal.phase != "committed"
                && (previous_journal.mbb_reservation.is_some()
                    || previous_journal.phase.starts_with("mbb_"))
            {
                let mut previous_plan = read_plan(&previous_journal.candidate_plan)?;
                let context = MbbContext::new(
                    path,
                    &desired,
                    &io_record,
                    takeover.controller_epoch,
                    binding,
                )?;
                return run_mbb_transaction(
                    &context,
                    &mut previous_plan,
                    &mut previous_journal,
                    &journal_path,
                    None,
                )
                .map_err(|error| error.context(ManagedProofPending));
            }
            consumed_epoch = consumed_epoch.max(previous_journal.owner.worker_epoch);
            consumed_fence = consumed_fence.max(previous_journal.owner.fencing_token);
            if previous_journal.phase == "committed" {
                retire_candidate_record(&previous_journal, &original_worker.process_record)?;
                retire_old_worker(&previous_journal, &desired, parent)?;
                let new_plan = read_plan(&previous_journal.candidate_plan)?;
                let (_, desired_report) = compile_verified_plan(desired.clone())?;
                let candidate = crate::process_record::read(&original_worker.process_record)?;
                if actual.owner_active
                    && previous_journal.envelope.as_ref() == actual.active.as_ref()
                    && desired_report["authorization_snapshot_sha256"]
                        == new_plan
                            .authorization_snapshot_sha256
                            .as_deref()
                            .unwrap_or("")
                    && new_plan.auth_deadline_unix == desired.auth_deadline_unix
                    && new_plan.placement == desired.placement
                    && candidate.authorization_snapshot_sha256
                        == new_plan.authorization_snapshot_sha256
                    && candidate
                        .business_is_current()
                        .context(ManagedProofPending)?
                {
                    return adopt_worker_with_io(path, true, true);
                }
            }
            if previous_journal.phase != "committed" {
                let mut previous_plan = match read_plan(&previous_journal.candidate_plan) {
                    Ok(plan) => plan,
                    Err(error) if previous_journal.phase == "retiring" => previous_journal
                        .candidate_plan_snapshot
                        .clone()
                        .ok_or(error)?,
                    Err(error) => return Err(error),
                };
                if previous_journal.phase != "retiring" {
                    previous_journal.snapshot.verify()?;
                }
                if previous_plan.infrastructure != desired.infrastructure
                    || previous_plan.domain_id != desired.domain_id
                    || previous_plan.io_epoch != desired.io_epoch
                {
                    bail!("renewal journal scope differs");
                }
                if previous_journal.envelope.is_none() {
                    if let Some(record) =
                        crate::process_record::read_optional(&previous_journal.candidate_record)
                            .context(ManagedProofPending)?
                    {
                        stop_record(&record, &previous_plan)?;
                    } else {
                        preserve_unrecorded_endpoint(
                            &previous_plan
                                .independent_worker
                                .as_ref()
                                .context("candidate control absent")?
                                .control_socket,
                        )?;
                    }
                }
                if let Some(envelope) = previous_journal.envelope.as_ref() {
                    let record =
                        crate::process_record::read_optional(&previous_journal.candidate_record)
                            .context(ManagedProofPending)?;
                    let business_current = record
                        .as_ref()
                        .map(|record| record.business_is_current())
                        .transpose()
                        .context(ManagedProofPending)?
                        .unwrap_or(false);
                    if actual.active.as_ref() == Some(envelope)
                        && actual.owner_active
                        && business_current
                    {
                        let record = record.unwrap();
                        let (verified, report) = compile_verified_plan(previous_plan.clone())?;
                        if report["authorization_snapshot_sha256"] != envelope.signed_control_hash {
                            bail!("journal signed snapshot hash differs from actual authority");
                        }
                        previous_plan = verified;
                        let candidate = ProcessIdentity {
                            pid: record.pid,
                            start_ticks: record.process_start_ticks,
                        };
                        exchange(
                            &previous_plan
                                .independent_worker
                                .as_ref()
                                .unwrap()
                                .control_socket,
                            candidate,
                            &ControlRequest {
                                schema_version: 1,
                                operation: ControlOperation::Takeover,
                                token_sha256: record.readiness_token_sha256.clone(),
                                nonce: uuid::Uuid::new_v4().simple().to_string(),
                            },
                        )?;
                        let token = record.private_status()?["readiness_token"]
                            .as_str()
                            .context("candidate token absent")?
                            .to_owned();
                        let mut netd = NetdControl::new(&previous_plan);
                        let (state, _) = netd.exchange(Operation::ForwardStatus)?;
                        if !matches!(state,Body::ForwardStatus {owner:Some(ref owner),..} if owner==&previous_journal.owner)
                            && !matches!(state,Body::ForwardStatus {candidate_owner:Some(ref owner),..} if owner==&previous_journal.owner)
                        {
                            if let Body::ForwardStatus {
                                owner: Some(owner),
                                phase,
                                candidate_owner: None,
                                ..
                            } = state
                            {
                                // Keep the route-to-TUN path while recovering a
                                // live owner. Revoke is reserved for expired or
                                // already-fenced owners because it installs
                                // unreachable routes and can surface EHOSTUNREACH
                                // to existing UDP sockets.
                                if matches!(
                                    phase,
                                    Some(
                                        candy_netd_proto::v2::Phase::Active
                                            | candy_netd_proto::v2::Phase::Guarded
                                    )
                                ) {
                                    if let Err(error) = expect_ack(
                                        &mut netd,
                                        Operation::ForwardGuard {
                                            owner: owner.clone(),
                                        },
                                    ) {
                                        eprintln!("level=warn code=forward_guard_failed module=sdwan_activation detail={error:#} action=preserve_live_owner_abort_recovery_retry");
                                        return Err(error.context(
                                            "live forwarding owner could not be guarded; preserving it and retrying recovery",
                                        ));
                                    }
                                } else {
                                    expect_ack(&mut netd, Operation::ForwardRevoke { owner })?;
                                }
                            }
                            let actual_cap = actual
                                .actual_deadline_mono_ms
                                .context("actual candidate cap absent during recovery")?;
                            previous_journal.owner.auth_deadline_mono_ms = previous_journal
                                .owner
                                .auth_deadline_mono_ms
                                .min(actual_cap.saturating_sub(1));
                            previous_journal.owner.lease_deadline_mono_ms = previous_journal
                                .owner
                                .lease_deadline_mono_ms
                                .min(previous_journal.owner.auth_deadline_mono_ms);
                            expect_ack(
                                &mut netd,
                                Operation::ForwardPrepare {
                                    infra_id: previous_plan.infrastructure.infra_id,
                                    infra_generation: previous_plan.infrastructure.generation,
                                    owner: previous_journal.owner.clone(),
                                    declaration: previous_plan.declaration.clone(),
                                },
                            )?;
                            // Recovery can recreate a prepared forwarding record after a
                            // daemon restart. Rebind the exact signed IO authority before
                            // probing readiness; without this, the subsequent authorized
                            // commit is rejected as an unauthorised candidate.
                            expect_ack(
                                &mut netd,
                                Operation::ForwardAuthorize {
                                    owner: previous_journal.owner.clone(),
                                    authority: forward_authority(envelope, io_identity),
                                },
                            )?;
                            publish(&journal_path, &previous_journal)?;
                        }
                        let deadline = Instant::now() + Duration::from_secs(20);
                        let mut failed = None;
                        loop {
                            listener_registration::publish_prepared_pending(&previous_plan);
                            exact_ready(&previous_plan, &record, envelope)?;
                            if matches!(
                                read_core_readiness_with_policy(
                                    &previous_plan.core_status,
                                    previous_plan.signed_generation,
                                    candidate.pid,
                                    &token,
                                    ReadinessPolicy::Strict
                                )?,
                                Some(ReadinessState::Ready)
                            ) {
                                sync_failed_prefixes(
                                    &mut netd,
                                    &previous_plan,
                                    candidate.pid,
                                    &token,
                                    &previous_journal.owner,
                                    candidate,
                                    &mut failed,
                                )?;
                                if failed.is_some() {
                                    break;
                                }
                            }
                            if Instant::now() >= deadline {
                                return Err(ManagedProofPending.into());
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        let (state, _) = netd.exchange(Operation::ForwardStatus)?;
                        if !matches!(state,Body::ForwardStatus {owner:Some(ref owner),phase:Some(candy_netd_proto::v2::Phase::Active),..} if owner==&previous_journal.owner)
                        {
                            commit_authorized(
                                &previous_plan,
                                &record,
                                &previous_journal.owner,
                                &mut netd,
                            )?;
                        }
                        finish_records(
                            &mut previous_plan,
                            &mut previous_journal,
                            &journal_path,
                            &original_worker.process_record,
                            &io.process_record,
                            &io_record,
                        )?;
                        retire_old_worker(&previous_journal, &desired, parent)?;
                        return adopt_worker_with_io(path, true, true);
                    }
                    if let Some(record) = record {
                        stop_record(&record, &previous_plan)?;
                    }
                    if actual.pending.as_ref() == Some(envelope) {
                        actual = exchange_authority(
                            &authority_path,
                            io_identity,
                            &request(
                                AuthorityControlOperation::DiscardAuthority,
                                None,
                                envelope.transaction_id.clone(),
                            ),
                            None,
                            Instant::now() + Duration::from_secs(2),
                        )?;
                    }
                    if actual.active.as_ref() == Some(envelope) {
                        actual = exchange_authority(
                            &authority_path,
                            io_identity,
                            &request(
                                AuthorityControlOperation::RevokeExact,
                                None,
                                envelope.transaction_id.clone(),
                            ),
                            None,
                            Instant::now() + Duration::from_secs(2),
                        )?;
                    }
                    let mut netd = NetdControl::new(&previous_plan);
                    let (state, _) = netd.exchange(Operation::ForwardStatus)?;
                    if matches!(state,Body::ForwardStatus {owner:Some(ref owner),..} if owner==&previous_journal.owner)
                        || matches!(state,Body::ForwardStatus {candidate_owner:Some(ref owner),..} if owner==&previous_journal.owner)
                    {
                        expect_ack(
                            &mut netd,
                            Operation::ForwardRevoke {
                                owner: previous_journal.owner.clone(),
                            },
                        )?;
                    }
                }
                previous_journal.phase = "retiring".into();
                previous_journal.candidate_plan_snapshot = Some(previous_plan.clone());
                publish(&journal_path, &previous_journal)?;
                previous_journal.snapshot.retire()?;
                for generated in [
                    &previous_plan.binding_file,
                    &previous_plan.core_status,
                    &previous_journal.candidate_plan,
                    &previous_journal.candidate_record,
                ] {
                    match fs::remove_file(generated) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if let Some(worker) = &previous_plan.independent_worker {
                    let _ = fs::remove_file(&worker.control_socket);
                }
                fs::remove_file(&journal_path)?;
            }
        }
        if actual.pending.is_some() {
            bail!("unknown pending signed authority requires scoped reconciliation");
        }
        let old_plan = old_worker
            .as_ref()
            .map(|old| match &old.effective_plan_file {
                Some(path) => read_plan(path),
                None => Ok(desired.clone()),
            })
            .transpose()?;
        if let Some(old) = &old_plan {
            placement_changed(old.placement.as_ref(), desired.placement.as_ref())?;
        }
        let snapshot = Snapshot::capture(&desired.core_config, parent)?;
        let mut snapshot_cleanup = crate::signed_snapshot::CleanupGuard::new(&snapshot);
        let mut plan = desired.clone();
        plan.core_config = snapshot.config.clone();
        let (mut plan, report) = compile_verified_plan(plan)?;
        let signed_hash = report["authorization_snapshot_sha256"]
            .as_str()
            .context("Core compile report lacks exact authorization snapshot hash")?
            .to_owned();
        if signed_hash.len() != 64 || !signed_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invalid Core authorization snapshot hash");
        }
        let mut netd = NetdControl::new(&desired);
        let (status, fd) = netd.exchange(Operation::ForwardStatus)?;
        if fd.is_some() {
            bail!("unexpected FD in renewal status");
        }
        let Body::ForwardStatus {
            owner: previous,
            phase: previous_phase,
            candidate_owner,
            last_fencing_token,
            ..
        } = status
        else {
            bail!("missing forwarding status");
        };
        if candidate_owner.is_some() {
            bail!("retained netd candidate requires exact renewal journal reconciliation");
        }
        if previous.as_ref().is_some_and(|owner| {
            owner.domain_id != plan.domain_id || owner.signed_generation > plan.signed_generation
        }) {
            bail!("new signed authority cannot downgrade existing owner");
        }
        let (epoch, fence) = next_authority_epochs(
            binding.owner_epoch,
            &[
                desired.worker_epoch,
                consumed_epoch,
                previous.as_ref().map_or(0, |owner| owner.worker_epoch),
            ],
            &[
                desired.fencing_token,
                consumed_fence,
                last_fencing_token,
                previous.as_ref().map_or(0, |owner| owner.fencing_token),
            ],
        )?;
        let revision = actual
            .highest_revision
            .checked_add(1)
            .context("authority revision exhausted")?;
        let transaction = uuid::Uuid::new_v4().simple().to_string();
        let now = candy_tunio::authority_control::monotonic_ms()?;
        // Sample monotonic time before wall time so descheduling can only
        // shorten the deadline; never resample either clock after the barrier.
        let (verified_at_unix, mut cap) = authorization_clock_sample(
            plan.auth_deadline_unix,
            now,
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?,
        )?;
        if let Some(active) = &actual.active {
            if active.signed_control_hash == signed_hash {
                cap = cap.min(active.effective_deadline_mono_ms);
                if let Some(actual_cap) = actual.actual_deadline_mono_ms {
                    cap = cap.min(actual_cap);
                }
            }
        }
        if old_worker.as_ref().is_some_and(|record| {
            record.authorization_snapshot_sha256.as_deref() == Some(signed_hash.as_str())
        }) {
            if let Some(previous) = &previous {
                cap = cap.min(previous.auth_deadline_mono_ms);
            }
        }
        if let Some(recovery) = &desired.pair_recovery {
            if recovery.authorization_snapshot_sha256.as_deref() == Some(signed_hash.as_str()) {
                cap = cap.min(recovery.auth_deadline_mono_ms);
            }
        }
        if cap <= monotonic_ms()? {
            bail!("original pair recovery authorization expired");
        }
        if let Some(recovery) = &mut plan.pair_recovery {
            recovery.auth_deadline_mono_ms = cap;
            recovery.authorization_snapshot_sha256 = Some(signed_hash.clone());
        }
        let mut owner = ForwardOwner {
            domain_id: plan.domain_id,
            signed_generation: plan.signed_generation,
            worker_epoch: epoch,
            fencing_token: fence,
            auth_deadline_mono_ms: cap,
            lease_deadline_mono_ms: (now + 30000).min(cap),
        };
        plan.worker_epoch = epoch;
        plan.fencing_token = fence;
        plan.binding_file = parent.join(format!("renewal-{transaction}-binding.json"));
        plan.core_status = parent.join(format!("renewal-{transaction}-core-status.json"));
        plan.independent_worker = Some(IndependentWorker {
            control_socket: parent.join(format!("renewal-{transaction}-core.sock")),
            process_record: parent.join(format!("renewal-{transaction}-core-record.json")),
        });
        plan.authority = Some(AuthorityProof {
            revision,
            sha256: signed_hash.clone(),
            transaction_id: transaction.clone(),
        });
        plan.authorization_snapshot_sha256 = Some(signed_hash.clone());
        let candidate_plan = parent.join(format!("renewal-{transaction}-plan.json"));
        plan.effective_plan_file = Some(candidate_plan.clone());
        snapshot_cleanup.track_file(candidate_plan.clone());
        publish(&candidate_plan, &plan)?;
        let mut journal = Journal {
            schema_version: 1,
            phase: "verified".into(),
            snapshot: snapshot.clone(),
            envelope: None,
            candidate_plan: candidate_plan.clone(),
            candidate_plan_snapshot: Some(plan.clone()),
            candidate_record: plan
                .independent_worker
                .as_ref()
                .unwrap()
                .process_record
                .clone(),
            owner: owner.clone(),
            old_worker: old_worker.clone(),
            candidate_owner: None,
            mbb_reservation: None,
            mbb_failed_retirement: None,
            mbb_outcome: None,
        };
        if let Err(error) = publish(&journal_path, &journal) {
            if read_private::<Journal>(&journal_path).is_ok_and(|persisted| {
                persisted.candidate_plan == journal.candidate_plan
                    && persisted.snapshot.closure_sha256 == journal.snapshot.closure_sha256
                    && persisted.snapshot.directory == journal.snapshot.directory
            }) {
                snapshot_cleanup.transfer();
                eprintln!("level=warn code=renewal_journal_durability_pending module=sdwan_activation detail={error:#} action=reconcile_exact_persisted_candidate");
                return Err(ManagedProofPending.into());
            }
            return Err(error);
        }
        snapshot_cleanup.transfer();
        let old_worker_current = old_worker
            .as_ref()
            .map(|record| record.business_is_current())
            .transpose()
            .context(ManagedProofPending)?
            .unwrap_or(false);
        if plan.shared_listener.is_some() && actual.owner_active && old_worker_current {
            journal.phase = "mbb_reserving".into();
            publish(&journal_path, &journal)?;
            let context = MbbContext::new(
                path,
                &desired,
                &io_record,
                takeover.controller_epoch,
                binding,
            )?;
            return run_mbb_transaction(
                &context,
                &mut plan,
                &mut journal,
                &journal_path,
                Some(report),
            )
            .map_err(|error| error.context(ManagedProofPending));
        }
        create_binding(&plan)?;
        let (io_socket, worker_socket) = UnixDatagram::pair()?;
        snapshot.verify()?;
        let same_slot = plan.placement.as_ref().is_some_and(|placement| {
            old_plan
                .as_ref()
                .and_then(|old| old.placement.as_ref())
                .is_some_and(|old| {
                    old.pool_directory == placement.pool_directory
                        && old.target_worker_id == placement.target_worker_id
                })
        });
        let mut slot = if same_slot {
            None
        } else {
            reserve_worker_slot(&plan)?
        };
        // A candidate must be running before the old worker is retired whenever
        // its placement can overlap safely. This is the local half of
        // make-before-break: the old owner remains authenticated and the TUN/
        // PacketPort infrastructure stays intact while the candidate performs
        // its listener registration, authority attach and reciprocal probe.
        // Only the shared listener has an authenticated ingress handoff that
        // can accept both generations concurrently. Dedicated workers retain
        // an exclusive slot (and ordinary workers may bind the same endpoint),
        // so those paths use the bounded stop-then-spawn compatibility barrier.
        let overlap_candidate = plan.shared_listener.is_some();
        let token = uuid::Uuid::new_v4().simple().to_string();
        let mut child = if overlap_candidate {
            eprintln!("level=info code=mbb_candidate_spawned_before_retire module=sdwan_activation transaction_id={} old_worker_present={} placement_overlap=true", transaction, old_worker.is_some());
            Some(spawn_business_worker_with_slot(
                &plan,
                &worker_socket,
                &token,
                slot,
            )?)
        } else {
            None
        };
        // Quiesce the live routing owner before committing the replacement.
        // Guarding retains the route-to-TUN path and lets TUNIO discard packets
        // for a briefly unavailable lane without injecting EHOSTUNREACH into
        // existing UDP sockets.
        if let Some(previous) = &previous {
            if matches!(
                previous_phase,
                Some(candy_netd_proto::v2::Phase::Active | candy_netd_proto::v2::Phase::Guarded)
            ) {
                if let Err(error) = expect_ack(
                    &mut netd,
                    Operation::ForwardGuard {
                        owner: previous.clone(),
                    },
                ) {
                    eprintln!("level=warn code=forward_guard_failed module=sdwan_activation owner_epoch={} detail={error:#} action=preserve_live_owner_abort_handoff_retry", previous.worker_epoch);
                    if let Some(ref mut candidate) = child {
                        stop_business(candidate);
                    }
                    return Err(error.context(
                        "live forwarding owner could not be guarded; preserving it and retrying handoff",
                    ));
                }
                journal.phase = "old_worker_guarded".into();
                publish(&journal_path, &journal)?;
            }
        }
        // A non-shared worker cannot be spawned while its endpoint or slot is
        // owned by the old process. Retire that worker only after the guard has
        // succeeded; shared-listener domains already have a live candidate.
        if !overlap_candidate {
            eprintln!("level=info code=mbb_slot_overlap_unavailable module=sdwan_activation transaction_id={transaction} detail=dedicated_worker_slot_is_exclusive action=bounded_stop_spawn_fallback");
            if let Some(old) = &old_worker {
                if let Err(error) = stop_record(old, old_plan.as_ref().unwrap()) {
                    eprintln!("level=warn code=renewal_old_worker_barrier_pending module=sdwan_activation old_pid={} detail={error:#} action=retry_authenticated_stop_preserve_infrastructure", old.pid);
                    return Err(error.context(ManagedProofPending));
                }
            }
            journal.phase = "old_worker_retired".into();
            publish(&journal_path, &journal)?;
            slot = reserve_worker_slot(&plan)?;
            child = Some(spawn_business_worker_with_slot(
                &plan,
                &worker_socket,
                &token,
                slot,
            )?);
        }
        let mut child = child.context("candidate worker was not spawned")?;
        drop(worker_socket);
        let candidate = process_identity(child.id())?;
        let new_binding = candy_tunio::attach_control::PacketPortBinding {
            owner_epoch: epoch,
            policy_generation: plan.signed_generation,
            ..binding
        };
        let envelope = AuthorityEnvelope {
            transaction_id: transaction.clone(),
            authority_revision: revision,
            binding: new_binding,
            candidate,
            controller,
            controller_epoch: takeover.controller_epoch,
            signed_control_hash: signed_hash,
            declaration_hash: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&plan.declaration)?)
            ),
            verification_report_hash: format!("{:x}", Sha256::digest(serde_json::to_vec(&report)?)),
            snapshot_closure_hash: snapshot.closure_sha256.clone(),
            signed_min_expiry_unix: report["authorization_expires_at_unix"]
                .as_u64()
                .context("signed expiry absent")?,
            effective_expiry_unix: plan.auth_deadline_unix,
            verified_at_unix,
            verified_at_mono_ms: now,
            effective_deadline_mono_ms: cap,
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .to_owned(),
        };
        journal.envelope = Some(envelope.clone());
        let mut attached = false;
        let result = (|| -> Result<()> {
            publish_worker_record(&plan, child.id(), &token)?;
            journal.phase = "registered".into();
            publish(&journal_path, &journal)?;
            exchange_authority(
                &authority_path,
                io_identity,
                &request(
                    AuthorityControlOperation::StageAuthority,
                    Some(envelope.clone()),
                    transaction.clone(),
                ),
                None,
                Instant::now() + Duration::from_secs(2),
            )?;
            journal.phase = "staged".into();
            publish(&journal_path, &journal)?;
            journal.phase = "barrier".into();
            publish(&journal_path, &journal)?;
            snapshot.verify()?;
            let fd: std::os::fd::OwnedFd = io_socket.into();
            let attach = exchange_authority(
                &authority_path,
                io_identity,
                &request(
                    AuthorityControlOperation::AttachAuthorized,
                    Some(envelope.clone()),
                    transaction.clone(),
                ),
                Some(&fd),
                Instant::now() + Duration::from_secs(2),
            );
            let actual = match attach {
                Ok(actual) => actual,
                Err(error) => {
                    let probe = exchange_authority(
                        &authority_path,
                        io_identity,
                        &request(
                            AuthorityControlOperation::ProbeTransaction,
                            None,
                            transaction.clone(),
                        ),
                        None,
                        Instant::now() + Duration::from_secs(2),
                    )?;
                    if probe.active.as_ref() != Some(&envelope) {
                        return Err(error.context(
                            "authorized Attach receipt absent and actual transaction differs",
                        ));
                    }
                    probe
                }
            };
            if actual.active.as_ref() != Some(&envelope) || actual.current_binding != new_binding {
                bail!("IO actual signed authority receipt differs");
            }
            attached = true;
            let actual_cap = actual
                .actual_deadline_mono_ms
                .context("IO actual applied deadline absent")?;
            owner.auth_deadline_mono_ms = owner
                .auth_deadline_mono_ms
                .min(actual_cap.saturating_sub(1));
            owner.lease_deadline_mono_ms = owner
                .lease_deadline_mono_ms
                .min(owner.auth_deadline_mono_ms);
            journal.owner = owner.clone();
            expect_ack(
                &mut netd,
                Operation::ForwardPrepare {
                    infra_id: plan.infrastructure.infra_id,
                    infra_generation: plan.infrastructure.generation,
                    owner: owner.clone(),
                    declaration: plan.declaration.clone(),
                },
            )?;
            expect_ack(
                &mut netd,
                Operation::ForwardAuthorize {
                    owner: owner.clone(),
                    authority: forward_authority(&envelope, io_identity),
                },
            )?;
            journal.phase = "attached".into();
            publish(&journal_path, &journal)?;
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut failed_snapshot = None;
            loop {
                listener_registration::publish_prepared_pending(&plan);
                if shutdown_requested() || monotonic_ms()? > cap {
                    bail!("renewal candidate cancelled/expired");
                }
                if !process_is_current_confirmed(io_identity).context(ManagedProofPending)? {
                    return Err(PairRecoveryRequired.into());
                }
                if !business_is_current(&plan, candidate)? {
                    return Err(CoreRecoveryRequired.into());
                }
                snapshot.verify()?;
                let record = crate::process_record::read(&journal.candidate_record)?;
                exact_ready(&plan, &record, &envelope)?;
                if matches!(
                    read_core_readiness_with_policy(
                        &plan.core_status,
                        plan.signed_generation,
                        child.id(),
                        &token,
                        ReadinessPolicy::Strict
                    )?,
                    Some(ReadinessState::Ready)
                ) {
                    sync_failed_prefixes(
                        &mut netd,
                        &plan,
                        child.id(),
                        &token,
                        &owner,
                        candidate,
                        &mut failed_snapshot,
                    )?;
                    if failed_snapshot.is_some() {
                        break;
                    }
                }
                if Instant::now() >= deadline {
                    return Err(ManagedProofPending.into());
                }
                thread::sleep(Duration::from_millis(100));
            }
            journal.phase = "proved".into();
            publish(&journal_path, &journal)?;
            let io_receipt = exchange_authority(
                &authority_path,
                io_identity,
                &request(
                    AuthorityControlOperation::ProbeTransaction,
                    None,
                    transaction.clone(),
                ),
                None,
                Instant::now() + Duration::from_secs(2),
            )?;
            if io_receipt.active.as_ref() != Some(&envelope)
                || !io_receipt.owner_active
                || io_receipt.applied_transaction_id.as_deref() != Some(transaction.as_str())
                || io_receipt.authority_revision != Some(revision)
                || io_receipt.current_binding != new_binding
                || io_receipt
                    .actual_deadline_mono_ms
                    .is_none_or(|actual| actual < owner.auth_deadline_mono_ms)
            {
                bail!("IO fresh actual applied authority proof differs before commit");
            }
            let record = crate::process_record::read(&journal.candidate_record)?;
            exact_ready(&plan, &record, &envelope)?;
            let fresh_status = record.private_status()?;
            let reported = fresh_status["reported_at_mono_ms"]
                .as_u64()
                .context("fresh packet report clock absent")?;
            journal.phase = "commit_pending".into();
            publish(&journal_path, &journal)?;
            expect_ack(
                &mut netd,
                Operation::ForwardCommitAuthorized {
                    owner: owner.clone(),
                    receipt: ForwardAuthorityReceipt {
                        authority: forward_authority(&envelope, io_identity),
                        owner_active: true,
                        authorization_deadline_mono_ms: owner.auth_deadline_mono_ms,
                        packet_proof_reported_mono_ms: reported,
                    },
                },
            )?;
            let (committed, fd) = netd.exchange(Operation::ForwardStatus)?;
            if fd.is_some()
                || !matches!(committed,Body::ForwardStatus {owner:Some(ref current),phase:Some(candy_netd_proto::v2::Phase::Active),..} if current==&owner)
            {
                bail!("netd exact renewal commit unconfirmed");
            }
            finish_records(
                &mut plan,
                &mut journal,
                &journal_path,
                &original_worker.process_record,
                &io.process_record,
                &io_record,
            )?;
            retire_old_worker(&journal, &desired, parent)?;
            eprintln!("level=info code=signed_authority_committed module=sdwan_activation transaction_id={} authority_revision={} core_pid={} io_pid={} policy_generation={} action=preserve_original_tun",transaction,revision,child.id(),io_record.pid,plan.signed_generation);
            adopt_worker_with_io(path, true, true)
        })();
        if result.as_ref().err().is_some_and(|error| {
            error.is::<DesiredStateChanged>()
                || error.is::<candy_process_control::ProcessLivenessUnconfirmed>()
        }) {
            return result;
        }
        if matches!(journal.phase.as_str(), "committed" | "commit_pending") {
            if result.is_err() {
                if result.as_ref().err().is_some_and(|error| {
                    error.is::<PairRecoveryRequired>() || error.is::<CoreRecoveryRequired>()
                }) {
                    return result;
                }
                return result.map_err(|error| error.context(ManagedProofPending));
            }
            return result;
        }
        stop_business(&mut child);
        let _ = expect_ack(&mut netd, Operation::ForwardRevoke { owner });
        let operation = if attached {
            AuthorityControlOperation::RevokeExact
        } else {
            AuthorityControlOperation::DiscardAuthority
        };
        let _ = exchange_authority(
            &authority_path,
            io_identity,
            &request(operation, None, transaction),
            None,
            Instant::now() + Duration::from_secs(2),
        );
        journal.phase = "retry_wait".into();
        let _ = publish(&journal_path, &journal);
        result
    }

    include!("signed_mbb.rs");
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
pub(super) use linux::run;

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
pub(super) use linux::{archive_retired_io_transaction, run_with_plan};

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
pub(super) use linux::commit_authorized;

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
pub(super) use linux::publish_plan;

#[cfg(not(all(feature = "experimental-tunio-rebind", target_os = "linux")))]
pub(super) fn commit_authorized(
    _: &Plan,
    _: &crate::process_record::ManagedProcessRecord,
    _: &ForwardOwner,
    _: &mut NetdControl,
) -> Result<()> {
    bail!("signed authorized commit requires Linux experimental-tunio-rebind");
}

#[cfg(test)]
mod epoch_tests {
    use super::*;

    #[test]
    fn signed_renewal_clock_sample_survives_stop_spawn_crossing_wall_seconds() {
        let expiry = 2_000;
        let verification_mono = 50_000;
        let verification_wall = Duration::from_millis(1_000_975);
        let (verified_unix, sampled_cap) =
            authorization_clock_sample(expiry, verification_mono, verification_wall).unwrap();
        // The old worker stop and fresh Core spawn complete 75 ms later,
        // crossing a wall second. This must not change the verified duration.
        let envelope_wall = verification_wall + Duration::from_millis(75);
        let duration_with_late_wall = (expiry - envelope_wall.as_secs()) * 1_000;
        assert!(sampled_cap - verification_mono > duration_with_late_wall);
        assert!(sampled_cap - verification_mono <= (expiry - verified_unix) * 1_000);
        assert_eq!(sampled_cap, 1_049_025);
        // Any receipt retained from the previous owner can only shorten it.
        for retained_cap in [sampled_cap - 500, sampled_cap, sampled_cap + 500] {
            let effective = sampled_cap.min(retained_cap);
            assert!(effective <= sampled_cap);
            assert!(effective <= retained_cap);
        }
        assert!(
            authorization_clock_sample(expiry, verification_mono, Duration::from_secs(expiry))
                .is_err()
        );
        assert!(authorization_clock_sample(
            expiry + 3_601,
            verification_mono,
            Duration::from_secs(expiry)
        )
        .is_err());
        assert!(authorization_clock_sample(expiry, u64::MAX, verification_wall).is_err());
    }

    #[test]
    fn signed_renewal_advances_all_consumed_identity_receipts() {
        for (name, binding, epochs, fences, expected) in [
            ("fresh grant", 1, [1, 1, 0], [1, 1, 0], (2, 2)),
            ("ordinary renewal", 2, [1, 1, 2], [1, 1, 3], (3, 4)),
            (
                "pair recovery after revoked candidate",
                3,
                [3, 3, 2],
                [4, 4, 2],
                (4, 5),
            ),
            (
                "first reconciliation after recovery",
                4,
                [4, 4, 4],
                [5, 5, 5],
                (5, 6),
            ),
            (
                "restart retaining failed journal",
                4,
                [4, 7, 4],
                [5, 9, 5],
                (8, 10),
            ),
        ] {
            assert_eq!(
                next_authority_epochs(binding, &epochs, &fences).unwrap(),
                expected,
                "{name}"
            );
        }
        assert!(next_authority_epochs(u64::MAX, &[1], &[1]).is_err());
        assert!(next_authority_epochs(1, &[1], &[u64::MAX]).is_err());
    }
}
