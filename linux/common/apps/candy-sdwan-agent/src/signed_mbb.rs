// Included in signed_renewal::linux to share its immutable journal and fsync API.
struct MbbContext<'a> {
    path: &'a Path,
    desired: &'a Plan,
    io_record: &'a crate::process_record::ManagedProcessRecord,
    io_identity: ProcessIdentity,
    controller: ProcessIdentity,
    controller_epoch: u64,
    authority_path: PathBuf,
    original_binding: candy_tunio::attach_control::PacketPortBinding,
}

impl<'a> MbbContext<'a> {
    fn new(
        path: &'a Path,
        desired: &'a Plan,
        io_record: &'a crate::process_record::ManagedProcessRecord,
        controller_epoch: u64,
        original_binding: candy_tunio::attach_control::PacketPortBinding,
    ) -> Result<Self> {
        Ok(Self {
            path,
            desired,
            io_record,
            controller_epoch,
            original_binding,
            io_identity: ProcessIdentity {
                pid: io_record.pid,
                start_ticks: io_record.process_start_ticks,
            },
            controller: process_identity(std::process::id())?,
            authority_path: authority_control_path(
                &desired
                    .independent_supervision
                    .as_ref()
                    .context("MBB requires independent I/O")?
                    .control_socket,
            ),
        })
    }

    fn request(
        &self,
        operation: AuthorityControlOperation,
        envelope: Option<AuthorityEnvelope>,
        transaction_id: &str,
    ) -> AuthorityControlRequest {
        AuthorityControlRequest {
            schema_version: 3,
            process: self.io_identity,
            controller: self.controller,
            controller_epoch: self.controller_epoch,
            token_sha256: self.io_record.readiness_token_sha256.clone(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            operation,
            envelope,
            transaction_id: transaction_id.to_owned(),
        }
    }

    fn authority(
        &self,
        request: &AuthorityControlRequest,
        fd: Option<&std::os::fd::OwnedFd>,
    ) -> Result<candy_tunio::authority_control::AuthorityControlResponse> {
        exchange_authority(
            &self.authority_path,
            self.io_identity,
            request,
            fd,
            Instant::now() + Duration::from_secs(2),
        )
    }
}

fn mbb_core_exchange(
    plan: &Plan,
    record: &crate::process_record::ManagedProcessRecord,
    operation: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value> {
    record.validate_infrastructure_identity(&plan.core)?;
    super::super::candidate_core_control::exchange_candidate(
        &plan
            .independent_worker
            .as_ref()
            .context("MBB Core control absent")?
            .control_socket,
        ProcessIdentity {
            pid: record.pid,
            start_ticks: record.process_start_ticks,
        },
        &record.readiness_token_sha256,
        operation,
        payload,
    )
}

fn mbb_proof(
    value: serde_json::Value,
) -> Result<super::super::candidate_ownership::CandidateProof> {
    serde_json::from_value(value["worker_candidate_transaction"].clone())
        .context("code=candidate_core_proof_missing module=sdwan_handoff")
}

fn mbb_original_cap(reservation: &serde_json::Value, boot_id: &str) -> Result<u64> {
    let cap = reservation["original_deadline_mono_ms"]
        .as_u64()
        .context("code=mbb_original_clock_cap_missing module=sdwan_handoff")?;
    anyhow::ensure!(cap != 0 && reservation["boot_id"] == boot_id
        && reservation["plan"]["original_deadline_mono_ms"] == cap
        && reservation["plan"]["boot_id"] == boot_id,
        "code=mbb_original_clock_cap_mismatch module=sdwan_handoff action=preserve_original_transaction");
    Ok(cap)
}

fn mbb_old_drained(
    receipt: &serde_json::Value,
    expected: &[super::super::candidate_ownership::PeerExpectation],
    transaction: &str,
) -> Result<bool> {
    anyhow::ensure!(
        receipt["transaction_id"] == transaction,
        "code=predecessor_transaction_mismatch module=sdwan_handoff"
    );
    let peers = receipt["peers"]
        .as_array()
        .context("predecessor peer receipts absent")?;
    anyhow::ensure!(
        peers.len() == expected.len(),
        "code=predecessor_peer_coverage_mismatch module=sdwan_handoff"
    );
    let mut drained = true;
    for peer in expected {
        let matches: Vec<_> = peers
            .iter()
            .filter(|value| {
                value["predecessor"]["attachment_id"] == serde_json::json!(peer.attachment_id)
            })
            .collect();
        anyhow::ensure!(
            matches.len() == 1,
            "code=predecessor_peer_coverage_mismatch module=sdwan_handoff"
        );
        let value = matches[0];
        anyhow::ensure!(
            value["transaction_id"] == serde_json::json!(peer.barrier.id),
            "code=predecessor_barrier_mismatch module=sdwan_handoff"
        );
        drained &= value["marker_written"] == true
            && value["marker_received"] == true
            && value["output_drained"] == true;
    }
    Ok(drained)
}

fn run_mbb_transaction(
    context: &MbbContext<'_>,
    plan: &mut Plan,
    journal: &mut Journal,
    journal_path: &Path,
    report: Option<serde_json::Value>,
) -> Result<()> {
    use super::super::candidate_ownership::{CandidateOwner, OwnerState, PeerExpectation};
    let original_worker = context
        .desired
        .independent_worker
        .as_ref()
        .context("MBB owner record absent")?;
    let parent = original_worker
        .process_record
        .parent()
        .context("MBB private directory absent")?;
    if journal.phase == "committed" {
        retire_old_worker(journal, context.desired, parent)?;
        return adopt_worker_with_io(context.path, true, true);
    }
    journal.snapshot.verify()?;
    let report = match report {
        Some(report) => report,
        None => compile_verified_plan(plan.clone())?.1,
    };
    let authority = plan
        .authority
        .as_ref()
        .context("MBB authority absent")?
        .clone();
    anyhow::ensure!(
        report["authorization_snapshot_sha256"] == authority.sha256,
        "code=mbb_authority_snapshot_changed module=sdwan_handoff action=preserve_old_owner"
    );
    let old = journal
        .old_worker
        .as_ref()
        .context("MBB predecessor record absent")?
        .clone();
    let old_plan = match &old.effective_plan_file {
        Some(path) => read_plan(path)?,
        None => context.desired.clone(),
    };
    if journal.mbb_reservation.is_none() {
        let reserve = mbb_core_exchange(
            &old_plan,
            &old,
            "candidate_reserve",
            &serde_json::json!({
                "transaction_id": authority.transaction_id, "config": plan.core_config,
                "expected_authority_sha256": authority.sha256, "owner_epoch": plan.worker_epoch,
                "authorization_deadline_mono_ms": journal.owner.auth_deadline_mono_ms,
            }),
        )?;
        let expected: Vec<PeerExpectation> =
            serde_json::from_value(reserve["expected_peers"].clone())?;
        let deadline = reserve["original_deadline_unix"]
            .as_u64()
            .context("reservation deadline absent")?;
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let original_cap = mbb_original_cap(&reserve, boot_id.trim())?;
        anyhow::ensure!(
            reserve["schema_version"] == 1
                && reserve["phase"] == "reserved"
                && reserve["transaction_id"] == authority.transaction_id
                && !expected.is_empty()
                && deadline > unix_time()?
                && deadline <= plan.auth_deadline_unix
                && original_cap > monotonic_ms()?
                && original_cap <= journal.owner.auth_deadline_mono_ms
                && reserve["plan"]["transaction_id"] == authority.transaction_id
                && reserve["plan"]["authorization_sha256"] == authority.sha256
                && reserve["plan"]["owner_epoch"] == plan.worker_epoch,
            "code=mbb_reservation_identity_mismatch module=sdwan_handoff action=preserve_old_owner"
        );
        journal.mbb_reservation = Some(reserve);
        journal.phase = "mbb_reserved".into();
        publish(journal_path, journal)?;
    }
    let reservation = journal.mbb_reservation.as_ref().unwrap().clone();
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let reservation_cap = mbb_original_cap(&reservation, boot_id.trim())?;
    let expected: Vec<PeerExpectation> =
        serde_json::from_value(reservation["expected_peers"].clone())?;
    let candidate_plan_path = parent.join(format!(
        "renewal-{}-candidate.json",
        authority.transaction_id
    ));
    if plan.worker_candidate_plan.as_ref() != Some(&candidate_plan_path) {
        publish_with_limit(&candidate_plan_path, &reservation["plan"], 1024 * 1024)?;
        plan.worker_candidate_plan = Some(candidate_plan_path);
        publish(&journal.candidate_plan, plan)?;
        journal.candidate_plan_snapshot = Some(plan.clone());
        publish(journal_path, journal)?;
    }
    let mut new_fd = None;
    if journal.envelope.is_none() {
        if let Some(unprepared) = crate::process_record::read_optional(&journal.candidate_record)
            .context(ManagedProofPending)?
        {
            // No authority operation can precede the durable envelope. This
            // recorded process therefore cannot own the TUNIO candidate slot.
            stop_record(&unprepared, plan)?;
            fs::remove_file(&journal.candidate_record)?;
        } else {
            preserve_unrecorded_endpoint(
                &plan
                    .independent_worker
                    .as_ref()
                    .context("MBB candidate control absent")?
                    .control_socket,
            )?;
        }
        if monotonic_ms()? >= reservation_cap {
            journal.mbb_reservation = None;
            plan.worker_candidate_plan = None;
            journal.candidate_plan_snapshot = Some(plan.clone());
            journal.phase = "retry_wait".into();
            publish(journal_path, journal)?;
            return Err(CoreRecoveryRequired.into());
        }
        create_binding(plan)?;
        let (io_socket, worker_socket) = UnixDatagram::pair()?;
        let same_slot = plan.placement.as_ref().is_some_and(|placement| {
            old_plan.placement.as_ref().is_some_and(|old| {
                old.pool_directory == placement.pool_directory
                    && old.target_worker_id == placement.target_worker_id
            })
        });
        let slot = if same_slot {
            None
        } else {
            reserve_worker_slot(plan)?
        };
        let token = uuid::Uuid::new_v4().simple().to_string();
        let child = spawn_business_worker_with_slot(plan, &worker_socket, &token, slot)?;
        drop(worker_socket);
        let candidate = process_identity(child.id())?;
        publish_worker_record(plan, child.id(), &token)?;
        let now = monotonic_ms()?;
        let verified_at_unix = unix_time()?;
        anyhow::ensure!(
            reservation_cap > now,
            "code=mbb_original_prepare_expired module=sdwan_handoff action=preserve_old_owner"
        );
        let envelope = AuthorityEnvelope {
            transaction_id: authority.transaction_id.clone(),
            authority_revision: authority.revision,
            binding: candy_tunio::attach_control::PacketPortBinding {
                owner_epoch: plan.worker_epoch,
                policy_generation: plan.signed_generation,
                ..context.original_binding
            },
            candidate,
            controller: context.controller,
            controller_epoch: context.controller_epoch,
            signed_control_hash: authority.sha256.clone(),
            declaration_hash: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&plan.declaration)?)
            ),
            verification_report_hash: format!("{:x}", Sha256::digest(serde_json::to_vec(&report)?)),
            snapshot_closure_hash: journal.snapshot.closure_sha256.clone(),
            signed_min_expiry_unix: report["authorization_expires_at_unix"]
                .as_u64()
                .context("signed expiry absent")?,
            effective_expiry_unix: plan.auth_deadline_unix,
            verified_at_unix,
            verified_at_mono_ms: now,
            effective_deadline_mono_ms: journal.owner.auth_deadline_mono_ms,
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .to_owned(),
        };
        let prepare_cap = reservation_cap
            .min(now + 30_000)
            .min(envelope.effective_deadline_mono_ms);
        journal.candidate_owner = Some(CandidateOwner::new(
            envelope.clone(),
            Some(context.original_binding),
            prepare_cap,
            expected.clone(),
        )?);
        journal.envelope = Some(envelope);
        journal.phase = "mbb_registered".into();
        publish(journal_path, journal)?;
        new_fd = Some(std::os::fd::OwnedFd::from(io_socket));
        // Runtime owns independent workers by authenticated records. Dropping
        // this local handle must not terminate a transaction being reconciled.
        drop(child);
    }
    let envelope = journal.envelope.as_ref().unwrap().clone();
    let record = crate::process_record::read(&journal.candidate_record)?;
    let mut candidate_owner = journal
        .candidate_owner
        .clone()
        .context("MBB owner transaction absent")?;
    let base = context.request(
        AuthorityControlOperation::ProbeTransaction,
        None,
        &envelope.transaction_id,
    );
    let mut actual = context.authority(&base, None)?;
    let mut owner_state = candidate_owner.observe(&actual)?;
    let candidate_current = record.business_is_current().context(ManagedProofPending)?;
    if !candidate_current && owner_state == OwnerState::Committed {
        journal.mbb_reservation = None;
        journal.candidate_owner = None;
        journal.phase = "retry_wait".into();
        publish(journal_path, journal)?;
        return Err(CoreRecoveryRequired.into());
    }
    if owner_state != OwnerState::Committed
        && !candidate_owner.commit_is_uncertain()
        && (!candidate_current || monotonic_ms()? >= candidate_owner.prepare_deadline_mono_ms)
        && actual.actual_owner_binding == candidate_owner.expected_active
        && actual.active.as_ref() != Some(&envelope)
    {
        if owner_state == OwnerState::Prepared {
            context.authority(
                &candidate_owner.abort_request(context.request(
                    AuthorityControlOperation::ProbeTransaction,
                    None,
                    &envelope.transaction_id,
                ))?,
                None,
            )?;
        } else if actual.pending.as_ref() == Some(&envelope) {
            context.authority(
                &context.request(
                    AuthorityControlOperation::DiscardAuthority,
                    None,
                    &envelope.transaction_id,
                ),
                None,
            )?;
        }
        stop_record(&record, plan)?;
        journal.mbb_reservation = None;
        journal.candidate_owner = None;
        journal.phase = "retry_wait".into();
        publish(journal_path, journal)?;
        return Err(CoreRecoveryRequired.into());
    }
    exact_ready(plan, &record, &envelope)?;
    listener_registration::publish_prepared_pending(plan);
    if owner_state == OwnerState::Unknown {
        let fd = new_fd.as_ref().context("code=mbb_prepare_receipt_unknown module=sdwan_handoff action=preserve_original_candidate_until_exact_reconciliation")?;
        context.authority(
            &context.request(
                AuthorityControlOperation::StageAuthority,
                Some(envelope.clone()),
                &envelope.transaction_id,
            ),
            None,
        )?;
        journal.phase = "mbb_prepare_pending".into();
        publish(journal_path, journal)?;
        owner_state = candidate_owner.prepare_with(
            context.request(
                AuthorityControlOperation::ProbeTransaction,
                None,
                &envelope.transaction_id,
            ),
            fd,
            monotonic_ms()?,
            |candidate| {
                journal.candidate_owner = Some(candidate.clone());
                publish(journal_path, journal)
            },
            |request, descriptor| context.authority(request, descriptor),
        )?;
    }
    anyhow::ensure!(
        matches!(owner_state, OwnerState::Prepared | OwnerState::Committed),
        "code=mbb_owner_not_prepared module=sdwan_handoff action=preserve_original_transaction"
    );
    let payload = serde_json::json!({"transaction_id": envelope.transaction_id});
    if owner_state == OwnerState::Prepared {
        mbb_core_exchange(plan, &record, "candidate_prepare", &payload)?;
        let proof = mbb_proof(mbb_core_exchange(
            plan,
            &record,
            "candidate_install",
            &payload,
        )?)?;
        proof.require_installed(&envelope, &expected)?;
        candidate_owner.read_installed_proof(plan, &record, monotonic_ms()?)?;
        let committed = candidate_owner.promote_with(
            context.request(
                AuthorityControlOperation::ProbeTransaction,
                None,
                &envelope.transaction_id,
            ),
            &proof,
            |candidate| {
                journal.candidate_owner = Some(candidate.clone());
                journal.phase = "mbb_commit_pending".into();
                publish(journal_path, journal)
            },
            |request, descriptor| context.authority(request, descriptor),
        )?;
        anyhow::ensure!(committed == OwnerState::Committed,
            "code=mbb_owner_commit_unknown module=sdwan_handoff action=reconcile_original_transaction");
        actual = context.authority(&base, None)?;
    } else {
        let proof = mbb_proof(mbb_core_exchange(
            plan,
            &record,
            "candidate_status",
            &payload,
        )?)?;
        if journal.mbb_failed_retirement.is_some() {
            proof.require_failed_retirement(&envelope, &expected)?;
        } else if monotonic_ms()? < candidate_owner.prepare_deadline_mono_ms {
            proof.require_installed(&envelope, &expected)?;
        }
    }
    journal.phase = "mbb_outbound_committed".into();
    publish(journal_path, journal)?;
    if actual.old_owner_drained
        && !actual.forced_retirement
        && actual.retained_owner_binding.is_none()
    {
        mbb_proof(mbb_core_exchange(
            plan,
            &record,
            "candidate_status",
            &payload,
        )?)?
        .require_drained(&envelope, &expected)?;
        return mbb_finalize(
            context,
            plan,
            journal,
            journal_path,
            &record,
            &actual,
            false,
        );
    }
    if journal.mbb_failed_retirement.is_some()
        || monotonic_ms()? >= candidate_owner.prepare_deadline_mono_ms
    {
        return mbb_retire_failed(
            context,
            plan,
            journal,
            journal_path,
            &candidate_owner,
            &record,
        );
    }
    let retire = serde_json::json!({"transaction_id": envelope.transaction_id,
        "plan": reservation["plan"], "complete": false});
    mbb_core_exchange(&old_plan, &old, "candidate_retire_old", &retire)?;
    mbb_core_exchange(plan, &record, "candidate_activate", &payload)?;
    let old_receipt = loop {
        if monotonic_ms()? >= candidate_owner.prepare_deadline_mono_ms {
            return mbb_retire_failed(
                context,
                plan,
                journal,
                journal_path,
                &candidate_owner,
                &record,
            );
        }
        let receipt = mbb_core_exchange(&old_plan, &old, "candidate_retire_old", &retire)?;
        if mbb_old_drained(&receipt, &expected, &envelope.transaction_id)? {
            break receipt;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let proof = mbb_proof(mbb_core_exchange(
        plan,
        &record,
        "candidate_drain",
        &serde_json::json!({
            "transaction_id": envelope.transaction_id, "old_drain_receipts": old_receipt["peers"],
        }),
    )?)?;
    proof.require_drained(&envelope, &expected)?;
    journal.phase = "mbb_bilateral_drained".into();
    publish(journal_path, journal)?;
    mbb_core_exchange(
        &old_plan,
        &old,
        "candidate_retire_old",
        &serde_json::json!({
            "transaction_id": envelope.transaction_id, "plan": reservation["plan"], "complete": true,
        }),
    )?;
    let finish = context.request(
        AuthorityControlOperation::FinishOwnerDrain,
        Some(envelope.clone()),
        &envelope.transaction_id,
    );
    loop {
        let reply = match context.authority(&finish, None) {
            Ok(reply) => reply,
            Err(error) => {
                let probe = context.authority(&base, None)?;
                if !probe.old_owner_drained
                    && !error.to_string().contains("owner_drain_queue_pending")
                {
                    return Err(error.context(ManagedProofPending));
                }
                probe
            }
        };
        anyhow::ensure!(
            candidate_owner.observe(&reply)? == OwnerState::Committed,
            "code=mbb_finish_owner_changed module=sdwan_handoff"
        );
        if reply.old_owner_drained && reply.retained_owner_binding.is_none() {
            break;
        }
        if monotonic_ms()? >= candidate_owner.prepare_deadline_mono_ms {
            return mbb_retire_failed(
                context,
                plan,
                journal,
                journal_path,
                &candidate_owner,
                &record,
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
    mbb_finalize(
        context,
        plan,
        journal,
        journal_path,
        &record,
        &actual,
        false,
    )
}

fn mbb_retire_failed(
    context: &MbbContext<'_>,
    plan: &mut Plan,
    journal: &mut Journal,
    journal_path: &Path,
    candidate: &super::super::candidate_ownership::CandidateOwner,
    record: &crate::process_record::ManagedProcessRecord,
) -> Result<()> {
    use super::super::candidate_ownership::OwnerState;
    let envelope = &candidate.envelope;
    anyhow::ensure!(
        monotonic_ms()? >= candidate.prepare_deadline_mono_ms,
        "code=mbb_failed_retirement_before_cap module=sdwan_handoff"
    );
    let actual = context.authority(
        &context.request(
            AuthorityControlOperation::ProbeTransaction,
            None,
            &envelope.transaction_id,
        ),
        None,
    )?;
    anyhow::ensure!(candidate.observe(&actual)? == OwnerState::Committed,
        "code=mbb_failed_retirement_commit_unknown module=sdwan_handoff action=preserve_original_transaction");
    let proof = mbb_proof(mbb_core_exchange(
        plan,
        record,
        "candidate_retire_after_failure",
        &serde_json::json!({"transaction_id": envelope.transaction_id}),
    )?)?;
    proof.require_failed_retirement(envelope, &candidate.expected_peers)?;
    journal.mbb_failed_retirement = Some(proof);
    journal.phase = "mbb_failed_retirement_pending".into();
    publish(journal_path, journal)?;
    let actual = context.authority(
        &context.request(
            AuthorityControlOperation::RetireOwnerAfterFailure,
            Some(envelope.clone()),
            &envelope.transaction_id,
        ),
        None,
    )?;
    anyhow::ensure!(candidate.observe(&actual)? == OwnerState::Committed
        && actual.forced_retirement && !actual.old_owner_drained
        && actual.retained_owner_binding.is_none(),
        "code=mbb_failed_retirement_receipt_mismatch module=sdwan_handoff action=preserve_current_owner");
    journal.phase = "mbb_failed_drain_preserved".into();
    publish(journal_path, journal)?;
    mbb_finalize(context, plan, journal, journal_path, record, &actual, true)
}

fn mbb_finalize(
    context: &MbbContext<'_>,
    plan: &mut Plan,
    journal: &mut Journal,
    journal_path: &Path,
    record: &crate::process_record::ManagedProcessRecord,
    actual: &candy_tunio::authority_control::AuthorityControlResponse,
    drain_failed: bool,
) -> Result<()> {
    let original_worker = context
        .desired
        .independent_worker
        .as_ref()
        .context("MBB owner absent")?;
    let io = context
        .desired
        .independent_supervision
        .as_ref()
        .context("MBB I/O absent")?;
    let parent = original_worker
        .process_record
        .parent()
        .context("MBB directory absent")?;
    let envelope = journal
        .envelope
        .as_ref()
        .context("MBB envelope absent")?
        .clone();
    let old = journal
        .old_worker
        .as_ref()
        .context("MBB predecessor absent")?
        .clone();
    // A future worker restart uses the committed signed configuration. Its
    // short-lived reservation is solely for this handoff, never a boot target.
    plan.worker_candidate_plan = None;
    let mut netd = NetdControl::new(plan);
    let mut owner = journal.owner.clone();
    owner.auth_deadline_mono_ms = owner.auth_deadline_mono_ms.min(
        actual
            .actual_deadline_mono_ms
            .context("MBB actual authority cap absent")?
            .saturating_sub(1),
    );
    owner.lease_deadline_mono_ms = monotonic_ms()?
        .saturating_add(30_000)
        .min(owner.auth_deadline_mono_ms);
    journal.owner = owner.clone();
    publish(journal_path, journal)?;
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
            authority: forward_authority(&envelope, context.io_identity),
        },
    )?;
    let status = record.private_status()?;
    let token = status["readiness_token"]
        .as_str()
        .context("MBB readiness token absent")?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut failed_snapshot = None;
    loop {
        exact_ready(plan, record, &envelope)?;
        if matches!(
            read_core_readiness_with_policy(
                &plan.core_status,
                plan.signed_generation,
                record.pid,
                token,
                ReadinessPolicy::Strict
            )?,
            Some(ReadinessState::Ready)
        ) {
            sync_failed_prefixes(
                &mut netd,
                plan,
                record.pid,
                token,
                &owner,
                ProcessIdentity {
                    pid: record.pid,
                    start_ticks: record.process_start_ticks,
                },
                &mut failed_snapshot,
            )?;
            if failed_snapshot.is_some() {
                break;
            }
        }
        anyhow::ensure!(
            Instant::now() < deadline && monotonic_ms()? < owner.lease_deadline_mono_ms,
            "code=mbb_forward_readiness_pending module=sdwan_handoff action=preserve_current_owner"
        );
        thread::sleep(Duration::from_millis(50));
    }
    commit_authorized(plan, record, &owner, &mut netd)?;
    finish_records(
        plan,
        journal,
        journal_path,
        &original_worker.process_record,
        &io.process_record,
        context.io_record,
    )?;
    retire_old_worker(journal, context.desired, parent)?;
    if drain_failed {
        eprintln!("level=warn code=mbb_failed_drain_preserved module=sdwan_handoff transaction_id={} old_pid={} new_pid={} old_owner_drained=false forced_retirement=true action=preserve_healthy_candidate_and_original_tun", envelope.transaction_id, old.pid, record.pid);
    } else {
        eprintln!("level=info code=mbb_transaction_drained module=sdwan_handoff transaction_id={} old_pid={} new_pid={} action=preserve_original_tun", envelope.transaction_id, old.pid, record.pid);
    }
    adopt_worker_with_io(context.path, true, true)
}

#[cfg(test)]
mod mbb_tests {
    use super::*;

    #[test]
    fn original_cap_requires_same_boot_and_persisted_monotonic_witness() {
        let original = serde_json::json!({"boot_id":"same", "original_deadline_mono_ms":123,
            "original_deadline_unix":9999999999_u64,
            "plan":{"boot_id":"same","original_deadline_mono_ms":123}});
        assert_eq!(mbb_original_cap(&original, "same").unwrap(), 123);
        assert!(mbb_original_cap(&original, "new").is_err());
        let mut changed = original.clone();
        changed["plan"]["original_deadline_mono_ms"] = 124.into();
        assert!(mbb_original_cap(&changed, "same").is_err());
        changed = original;
        changed["original_deadline_mono_ms"] = serde_json::Value::Null;
        assert!(mbb_original_cap(&changed, "same").is_err());
    }

    #[test]
    fn predecessor_drain_requires_exact_peers_transaction_and_both_markers() {
        use super::super::super::candidate_ownership::{
            BarrierIdentity, PeerExpectation, RoutingCandidate,
        };
        let peer = PeerExpectation {
            attachment_id: [1; 16],
            selector: RoutingCandidate {
                transaction_id: [2; 32],
                owner_epoch: 2,
                policy_generation: 3,
                authorization_sha256: [3; 32],
                candidate_id: [4; 16],
                local_attachment_epoch: 1,
                peer_attachment_epoch: 1,
                tunnel_id: 1,
            },
            barrier: BarrierIdentity {
                id: [2; 32],
                generation: 3,
                fence: 4,
                hash: [5; 32],
            },
        };
        let receipt = serde_json::json!({"transaction_id":"exact", "peers":[{
            "transaction_id":peer.barrier.id,"predecessor":{"attachment_id":peer.attachment_id},
            "marker_written":true,"marker_received":true,"output_drained":true}]});
        assert!(mbb_old_drained(&receipt, std::slice::from_ref(&peer), "exact").unwrap());
        for marker in ["marker_written", "marker_received", "output_drained"] {
            let mut changed = receipt.clone();
            changed["peers"][0][marker] = false.into();
            assert!(!mbb_old_drained(&changed, std::slice::from_ref(&peer), "exact").unwrap());
        }
        assert!(mbb_old_drained(&receipt, std::slice::from_ref(&peer), "other").is_err());
        let mut changed = receipt.clone();
        changed["peers"][0]["transaction_id"] = serde_json::to_value([9; 32]).unwrap();
        assert!(mbb_old_drained(&changed, std::slice::from_ref(&peer), "exact").is_err());
        changed["peers"] = serde_json::json!([]);
        assert!(mbb_old_drained(&changed, &[peer], "exact").is_err());
    }
}
