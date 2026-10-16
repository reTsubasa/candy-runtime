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

fn mbb_precommit_peer_outcome_pending(
    journal: &mut Journal,
    journal_path: &Path,
    reason: &str,
) -> Result<()> {
    // TUNIO cancellation or expiry proves only the local PacketPort outcome.
    // The peer actor may already have installed the same candidate. Preserve
    // its immutable reservation, epoch and process until both ends reconcile;
    // no subsequent Reserve may overtake this original transaction.
    journal.phase = "mbb_peer_reconciliation_pending".into();
    publish(journal_path, journal)?;
    anyhow::bail!("code=mbb_precommit_peer_outcome_unknown module=sdwan_handoff reason={reason} action=reconcile_original_transaction_preserve_candidate");
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
    // Reconcile the original committed owner before compiling signed inputs:
    // expired business authorization must not block failure isolation forever.
    if let Some(mut candidate) = journal
        .candidate_owner
        .clone()
        .filter(|owner| owner.commit_is_uncertain())
    {
        let actual = context.authority(
            &context.request(
                AuthorityControlOperation::ProbeTransaction,
                None,
                &candidate.envelope.transaction_id,
            ),
            None,
        )?;
        if actual
            .owner_transaction
            .as_ref()
            .is_some_and(|receipt| receipt.phase == "expired")
        {
            candidate.retire_expired_commit_with(
                context.request(
                    AuthorityControlOperation::ProbeTransaction,
                    None,
                    &candidate.envelope.transaction_id,
                ),
                |owner| {
                    journal.candidate_owner = Some(owner.clone());
                    journal.phase = "mbb_expired_commit_retiring".into();
                    publish(journal_path, journal)
                },
                |request| context.authority(request, None),
            )?;
            let evidence = journal
                .snapshot
                .directory
                .join("mbb-expired-commit-recovery.json");
            publish(&evidence, journal)?;
            journal.mbb_outcome = Some("local_expired_remote_unknown".into());
            publish(&evidence, journal)?;
            return mbb_precommit_peer_outcome_pending(
                journal,
                journal_path,
                "local_expired_commit_retired_remote_actor_outcome_unconfirmed",
            );
        }
        if candidate.require_committed_outcome(&actual).is_ok() {
            let record = crate::process_record::read(&journal.candidate_record)?;
            let failed = candidate.committed_isolation_needed(
                &actual,
                record.business_is_current().context(ManagedProofPending),
            )?;
            if failed {
                return mbb_isolate_failed_commit(
                    context,
                    plan,
                    journal,
                    journal_path,
                    &mut candidate,
                    &record,
                    &actual,
                );
            }
            if monotonic_ms()? >= candidate.prepare_deadline_mono_ms {
                if actual.old_owner_drained
                    && !actual.forced_retirement
                    && actual.retained_owner_binding.is_none()
                {
                    let confirmation = mbb_core_exchange(
                        plan,
                        &record,
                        "candidate_status",
                        &serde_json::json!({"transaction_id": candidate.envelope.transaction_id}),
                    )
                    .and_then(mbb_proof)
                    .and_then(|proof| {
                        proof.require_drained(&candidate.envelope, &candidate.expected_peers)
                    });
                    confirmation.context(ManagedProofPending)?;
                    journal.snapshot.verify()?;
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
                let retirement = mbb_core_exchange(
                    plan,
                    &record,
                    "candidate_retire_after_failure",
                    &serde_json::json!({"transaction_id": candidate.envelope.transaction_id}),
                )
                .and_then(mbb_proof)
                .and_then(|proof| {
                    proof.require_failed_retirement(&candidate.envelope, &candidate.expected_peers)
                });
                retirement.context(ManagedProofPending)?;
                journal.snapshot.verify()?;
                return mbb_retire_failed(
                    context,
                    plan,
                    journal,
                    journal_path,
                    &candidate,
                    &record,
                );
            }
        }
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
            return mbb_precommit_peer_outcome_pending(
                journal,
                journal_path,
                "original_reservation_cap_elapsed_before_owner_prepare",
            );
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
    if let Some(fd) = new_fd.as_ref() {
        // A newly registered candidate has no PacketPort transaction to probe.
        // Transfer its live descriptor before probing or waiting for readiness;
        // a deferred readiness check must not discard the only descriptor.
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
        candidate_owner.prepare_with(
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
    let mut recovered = None;
    let owner_state = if new_fd.is_none() && !candidate_owner.commit_is_uncertain() {
        candidate_owner.recover_precommit_with(
            context.request(
                AuthorityControlOperation::ProbeTransaction,
                None,
                &envelope.transaction_id,
            ),
            |candidate| {
                journal.candidate_owner = Some(candidate.clone());
                publish(journal_path, journal)
            },
            |request| {
                let reply = context.authority(request, None)?;
                recovered = Some(reply.clone());
                Ok(reply)
            },
        )?
    } else {
        let reply = context.authority(&base, None)?;
        let state = candidate_owner.observe(&reply)?;
        recovered = Some(reply);
        state
    };
    let mut actual = recovered.context("MBB exact recovery receipt absent")?;
    if owner_state == OwnerState::CancelledBeforePrepare {
        return mbb_precommit_peer_outcome_pending(
            journal,
            journal_path,
            "local_owner_cancelled_remote_actor_outcome_unconfirmed",
        );
    }
    let candidate_current = record.business_is_current().context(ManagedProofPending)?;
    if !candidate_current && owner_state == OwnerState::Committed {
        return mbb_isolate_failed_commit(
            context,
            plan,
            journal,
            journal_path,
            &mut candidate_owner,
            &record,
            &actual,
        );
    }
    if owner_state != OwnerState::Committed
        && !candidate_owner.commit_is_uncertain()
        && (!candidate_current || monotonic_ms()? >= candidate_owner.prepare_deadline_mono_ms)
        && actual.actual_owner_binding == candidate_owner.expected_active
        && actual.active.as_ref() != Some(&envelope)
    {
        return mbb_precommit_peer_outcome_pending(
            journal,
            journal_path,
            "candidate_unavailable_or_prepare_cap_elapsed_remote_actor_outcome_unconfirmed",
        );
    }
    exact_ready(plan, &record, &envelope)?;
    listener_registration::publish_prepared_pending(plan);
    if owner_state == OwnerState::Unknown {
        anyhow::bail!("code=mbb_prepare_receipt_unknown module=sdwan_handoff action=preserve_original_candidate_until_exact_reconciliation");
    }
    anyhow::ensure!(
        matches!(owner_state, OwnerState::Prepared | OwnerState::Committed),
        "code=mbb_owner_not_prepared module=sdwan_handoff action=preserve_original_transaction"
    );
    let payload = serde_json::json!({"transaction_id": envelope.transaction_id});
    if owner_state == OwnerState::Prepared {
        // Freeze the operation before dispatch. If Core executed Install but
        // publishing its status failed, the exact Install must be retried;
        // re-entering Prepare would overtake its retained completion.
        if journal.phase != "mbb_peer_install_pending" {
            journal.phase = "mbb_peer_prepare_pending".into();
            publish(journal_path, journal)?;
            mbb_core_exchange(plan, &record, "candidate_prepare", &payload)?;
            journal.phase = "mbb_peer_install_pending".into();
            publish(journal_path, journal)?;
        }
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

fn mbb_isolate_failed_commit(
    context: &MbbContext<'_>,
    plan: &mut Plan,
    journal: &mut Journal,
    journal_path: &Path,
    candidate: &mut super::super::candidate_ownership::CandidateOwner,
    record: &crate::process_record::ManagedProcessRecord,
    actual: &candy_tunio::authority_control::AuthorityControlResponse,
) -> Result<()> {
    candidate.record_committed_failure(actual, |owner| {
        journal.candidate_owner = Some(owner.clone());
        journal.phase = "mbb_committed_isolating".into();
        publish(journal_path, journal)
    })?;
    // Retain the signed closure and original participant identities as failure
    // evidence even when normal renewal later retires its generated files.
    let evidence = journal.snapshot.directory.join("mbb-failure-recovery.json");
    publish(&evidence, journal)?;
    stop_record(record, plan)?;
    let isolated = context.authority(
        &context.request(
            AuthorityControlOperation::IsolateCommittedOwner {
                expected_active: candidate
                    .expected_active
                    .context("committed isolation original binding absent")?,
            },
            Some(candidate.envelope.clone()),
            &candidate.envelope.transaction_id,
        ),
        None,
    )?;
    candidate.record_committed_isolation(&isolated, |owner| {
        journal.candidate_owner = Some(owner.clone());
        publish(journal_path, journal)
    })?;
    publish(&evidence, journal)?;
    let old = journal
        .old_worker
        .as_ref()
        .context("failed MBB predecessor absent")?;
    let old_plan = match &old.effective_plan_file {
        Some(path) => read_plan(path)?,
        None => context.desired.clone(),
    };
    stop_record(old, &old_plan)?;
    journal.mbb_reservation = None;
    journal.phase = "committed_owner_isolated".into();
    publish(journal_path, journal)?;
    publish(&evidence, journal)?;
    eprintln!("level=warn code=mbb_committed_owner_isolated module=sdwan_handoff transaction_id={} outcome=failed_owner_isolated action=fresh_authorization_preserve_tun", candidate.envelope.transaction_id);
    Err(CoreRecoveryRequired.into())
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
    candidate.require_failed_retirement_receipt(&actual, context.io_identity, monotonic_ms()?)?;
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
    let owner_frozen = journal.mbb_outcome.is_some();
    let outcome = if drain_failed {
        "failed_drain_preserved"
    } else {
        "drained"
    };
    anyhow::ensure!(
        journal
            .mbb_outcome
            .as_deref()
            .is_none_or(|previous| previous == outcome),
        "code=mbb_terminal_outcome_changed module=sdwan_handoff action=preserve_original_evidence"
    );
    journal.mbb_outcome = Some(outcome.into());
    // A future worker restart uses the committed signed configuration. Its
    // short-lived reservation is solely for this handoff, never a boot target.
    plan.worker_candidate_plan = None;
    let mut netd = NetdControl::new(plan);
    // The owner is a transaction identity, not a lease suggestion.  Once the
    // first finalization attempt is journaled, every retry must replay this
    // exact owner.  Recomputing the deadlines here used to mutate the same
    // fencing token after netd had accepted it, producing a permanent
    // stale_forward_owner/forward_candidate_pending loop when an IPC reply
    // was lost after the backend committed.
    let mut owner = mbb_final_owner(
        &journal.owner,
        owner_frozen,
        actual
            .actual_deadline_mono_ms
            .context("MBB actual authority cap absent")?,
        monotonic_ms()?,
    )?;
    if !owner_frozen {
        journal.owner = owner.clone();
        publish(journal_path, journal)?;
    }
    let (forward_state, fd) = netd.exchange(Operation::ForwardStatus)?;
    if fd.is_some() {
        bail!("unexpected FD in forwarding status");
    }
    let repaired = mbb_repair_expired_lease(&owner, &forward_state, monotonic_ms()?)?;
    if repaired != owner {
        let old_fence = owner.fencing_token;
        owner = repaired;
        journal.owner = owner.clone();
        publish(journal_path, journal)?;
        eprintln!("level=warn code=mbb_forward_expired_lease_repaired module=sdwan_handoff transaction_id={} old_fence={} new_fence={} auth_deadline_mono_ms={} action=retain_exact_business_io_and_authority", envelope.transaction_id, old_fence, owner.fencing_token, owner.auth_deadline_mono_ms);
    }
    plan.fencing_token = plan.fencing_token.max(owner.fencing_token);
    let replay = forward_replay(forward_state, &owner)?;
    if replay == ForwardReplay::Prepare {
        expect_ack(
            &mut netd,
            Operation::ForwardPrepare {
                infra_id: plan.infrastructure.infra_id,
                infra_generation: plan.infrastructure.generation,
                owner: owner.clone(),
                declaration: plan.declaration.clone(),
            },
        )?;
    }
    if replay != ForwardReplay::Active {
        expect_ack(
            &mut netd,
            Operation::ForwardAuthorize {
                owner: owner.clone(),
                authority: forward_authority(&envelope, context.io_identity),
            },
        )?;
    }
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
    if drain_failed {
        journal
            .candidate_owner
            .as_ref()
            .context("MBB candidate owner absent")?
            .require_failed_retirement_receipt(actual, context.io_identity, monotonic_ms()?)?;
        retire_old_worker(journal, context.desired, parent)?;
        anyhow::ensure!(
            !old.business_is_current().context(ManagedProofPending)?,
            "code=mbb_failed_predecessor_still_active module=sdwan_handoff"
        );
        let finalized = mbb_core_exchange(
            plan,
            record,
            "candidate_finalize_failure",
            &serde_json::json!({"transaction_id":envelope.transaction_id,
                "retirement_evidence":actual,
                "predecessor_retired":true,
                "predecessor_process":{"pid":old.pid,"start_ticks":old.process_start_ticks},
                "predecessor_domain_instance":old.shared_domain_instance}),
        )?;
        anyhow::ensure!(
            finalized["transaction_id"] == envelope.transaction_id
                && finalized["phase"] == "failed_retirement_finalized"
                && finalized["forced_retirement"] == true
                && finalized["old_owner_drained"] == false,
            "code=mbb_failed_finalization_unconfirmed module=sdwan_handoff"
        );
        journal.phase = "mbb_failed_retirement_finalized".into();
        publish(journal_path, journal)?;
    }
    finish_records(
        plan,
        journal,
        journal_path,
        &original_worker.process_record,
        &io.process_record,
        context.io_record,
    )?;
    if !drain_failed {
        retire_old_worker(journal, context.desired, parent)?;
    }
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
    fn unresolved_precommit_retains_original_reservation_and_epoch_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["segment", "projection"] {
            fs::write(directory.path().join(name), name).unwrap();
        }
        let config = directory.path().join("config.toml");
        fs::write(
            &config,
            format!(
                "segment_snapshot = {:?}\nsite_projection = {:?}\n",
                directory.path().join("segment"),
                directory.path().join("projection")
            ),
        )
        .unwrap();
        let snapshot = Snapshot::capture(&config, directory.path()).unwrap();
        let owner = ForwardOwner {
            domain_id: [1; 16],
            signed_generation: 1,
            worker_epoch: 3,
            fencing_token: 8,
            auth_deadline_mono_ms: 100_000,
            lease_deadline_mono_ms: 30_000,
        };
        let original = serde_json::json!({"transaction_id":"original", "owner_epoch":3,
            "original_deadline_mono_ms":1234,"peers":[{"tuple":"immutable"}]});
        let mut journal = Journal {
            schema_version: 1,
            phase: "mbb_reserved".into(),
            snapshot,
            envelope: None,
            candidate_plan: directory.path().join("original-plan.json"),
            candidate_plan_snapshot: None,
            candidate_record: directory.path().join("original-process.json"),
            owner: owner.clone(),
            old_worker: None,
            candidate_owner: None,
            mbb_reservation: Some(original.clone()),
            mbb_failed_retirement: None,
            mbb_outcome: None,
        };
        let path = directory.path().join("renewal.json");
        let expected_record = journal.candidate_record.clone();
        for reason in ["cap_elapsed", "owner_cancelled", "candidate_unavailable"] {
            assert!(mbb_precommit_peer_outcome_pending(&mut journal, &path, reason).is_err());
            let recovered: Journal = read_private(&path).unwrap();
            assert_eq!(recovered.phase, "mbb_peer_reconciliation_pending");
            assert_eq!(recovered.mbb_reservation, Some(original.clone()));
            assert_eq!(recovered.owner, owner);
            assert_eq!(recovered.candidate_record, expected_record);
            recovered.snapshot.verify().unwrap();
            journal = recovered;
        }
        // Failed publication also leaves the in-memory original transaction
        // intact, so it cannot turn into an empty journal on the next retry.
        assert!(mbb_precommit_peer_outcome_pending(
            &mut journal,
            &directory.path().join("missing/renewal.json"),
            "fsync_failed"
        )
        .is_err());
        assert_eq!(journal.mbb_reservation, Some(original));
        assert_eq!(journal.owner, owner);
    }

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
