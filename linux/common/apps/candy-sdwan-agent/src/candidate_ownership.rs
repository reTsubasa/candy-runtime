//! Exact candidate-owner receipts. Transport health is not an installation proof.
use anyhow::{ensure, Context, Result};
use candy_tunio::{
    attach_control::PacketPortBinding,
    authority_control::{
        AuthorityControlRequest, AuthorityControlResponse, AuthorityEnvelope, AuthorityOperation,
    },
};
use serde::{Deserialize, Serialize};
use std::os::fd::OwnedFd;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoutingCandidate {
    pub transaction_id: [u8; 32],
    pub owner_epoch: u64,
    pub policy_generation: u64,
    pub authorization_sha256: [u8; 32],
    pub candidate_id: [u8; 16],
    pub local_attachment_epoch: u64,
    pub peer_attachment_epoch: u64,
    pub tunnel_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BarrierIdentity {
    pub id: [u8; 32],
    pub generation: u64,
    pub fence: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerExpectation {
    pub attachment_id: [u8; 16],
    pub selector: RoutingCandidate,
    pub barrier: BarrierIdentity,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerProof {
    pub attachment_id: [u8; 16],
    pub selector: RoutingCandidate,
    pub barrier: BarrierIdentity,
    pub prepared: bool,
    pub installed: bool,
    pub probe_sent: bool,
    pub probe_received: bool,
    pub drain_complete: bool,
    #[serde(default)]
    pub drain_failed: bool,
    #[serde(default)]
    pub activation_confirmed: bool,
    #[serde(default)]
    pub transport_live: bool,
    #[serde(default)]
    pub recovery_action: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalProof {
    pub domain: [u8; 16],
    pub owner_epoch: u64,
    pub authorization_sha256: String,
    pub packet_slot: PacketPortBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidateProof {
    pub schema_version: u8,
    pub transaction_id: String,
    pub phase: String,
    pub local: LocalProof,
    pub peers: Vec<PeerProof>,
    #[serde(default)]
    pub forced_retirement: bool,
    #[serde(default)]
    pub old_owner_drained: bool,
}

impl CandidateProof {
    pub(super) fn require_installed(
        &self,
        envelope: &AuthorityEnvelope,
        expected: &[PeerExpectation],
    ) -> Result<()> {
        ensure!(
            self.phase == "installed"
                && !self.forced_retirement
                && self.peers.iter().all(|peer| !peer.drain_failed),
            "code=candidate_install_phase_mismatch module=sdwan_handoff"
        );
        self.require_identity(envelope, expected)
    }

    fn require_identity(
        &self,
        envelope: &AuthorityEnvelope,
        expected: &[PeerExpectation],
    ) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.transaction_id == envelope.transaction_id
                && self.local.domain == envelope.binding.routing_domain_id
                && self.local.owner_epoch == envelope.binding.owner_epoch
                && self.local.authorization_sha256 == envelope.signed_control_hash
                && self.local.packet_slot == envelope.binding,
            "code=candidate_local_proof_mismatch module=sdwan_handoff action=preserve_old_owner"
        );
        ensure!(
            !expected.is_empty() && expected.len() == self.peers.len(),
            "code=candidate_peer_coverage_mismatch module=sdwan_handoff action=preserve_old_owner"
        );
        for (index, peer) in expected.iter().enumerate() {
            ensure!(
                expected[..index]
                    .iter()
                    .all(|other| other.attachment_id != peer.attachment_id),
                "code=candidate_duplicate_expected_peer module=sdwan_handoff"
            );
            let matches: Vec<_> = self
                .peers
                .iter()
                .filter(|proof| proof.attachment_id == peer.attachment_id)
                .collect();
            ensure!(matches.len() == 1,
                "code=candidate_peer_coverage_mismatch module=sdwan_handoff action=preserve_old_owner");
            let proof = matches[0];
            ensure!(proof.selector == peer.selector && proof.barrier == peer.barrier
                && peer.attachment_id != [0; 16]
                && peer.selector.transaction_id == peer.barrier.id
                && peer.selector.transaction_id != [0; 32]
                && peer.selector.owner_epoch != 0
                && peer.selector.policy_generation != 0
                && peer.selector.authorization_sha256 != [0; 32]
                && peer.selector.candidate_id != [0; 16]
                && peer.selector.local_attachment_epoch != 0
                && peer.selector.peer_attachment_epoch != 0
                && peer.selector.tunnel_id != 0
                && peer.barrier.generation != 0
                && peer.barrier.fence != 0
                && peer.barrier.hash != [0; 32]
                && proof.prepared && proof.installed && proof.probe_sent && proof.probe_received,
                "code=candidate_peer_installation_unconfirmed module=sdwan_handoff action=preserve_old_owner");
        }
        Ok(())
    }

    pub(super) fn require_failed_retirement(
        &self,
        envelope: &AuthorityEnvelope,
        expected: &[PeerExpectation],
    ) -> Result<()> {
        self.require_identity(envelope, expected)?;
        ensure!(self.phase == "failed_drain_preserved" && self.forced_retirement
            && !self.old_owner_drained
            && self.peers.iter().all(|peer| peer.drain_complete != peer.drain_failed)
            && self.peers.iter().any(|peer| peer.drain_failed)
            && self.peers.iter().all(|peer| {
                if peer.activation_confirmed && peer.transport_live {
                    peer.recovery_action == "preserve_active_peer"
                } else {
                    peer.recovery_action == "redial_affected_peer"
                }
            }),
            "code=candidate_failed_retirement_unconfirmed module=sdwan_handoff action=preserve_original_transaction");
        Ok(())
    }

    pub(super) fn require_drained(
        &self,
        envelope: &AuthorityEnvelope,
        expected: &[PeerExpectation],
    ) -> Result<()> {
        self.require_installed(envelope, expected)?;
        ensure!(
            self.peers.iter().all(|peer| peer.drain_complete),
            "code=candidate_peer_drain_unconfirmed module=sdwan_handoff action=preserve_old_worker"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OwnerState {
    Prepared,
    Committed,
    Aborted,
    Expired,
    Unknown,
    CancelledBeforePrepare,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidateOwner {
    pub envelope: AuthorityEnvelope,
    pub expected_active: Option<PacketPortBinding>,
    pub prepare_deadline_mono_ms: u64,
    pub expected_peers: Vec<PeerExpectation>,
    commit_intent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    precommit_cancellation: Option<AuthorityControlResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    committed_failure: Option<AuthorityControlResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    committed_isolation: Option<AuthorityControlResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expired_commit_retirement: Option<AuthorityControlResponse>,
}

impl CandidateOwner {
    /// Verify a historical peer result obtained through the original worker's
    /// authenticated control endpoint. This deliberately does not authorize a
    /// PacketPort commit or turn local actor state into a remote installation.
    pub(super) fn require_peer_reconciliation(
        &self,
        value: &serde_json::Value,
        reservation: &serde_json::Value,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        ensure!(
            value["schema_version"] == 1
                && value["read_only"] == true
                && value["phase"] == "reconciled_original_candidate"
                && value["transaction_id"] == self.envelope.transaction_id
                && value["authorization_sha256"] == self.envelope.signed_control_hash
                && value["owner_epoch"] == self.envelope.binding.owner_epoch
                && value["original_deadline_mono_ms"] == reservation["original_deadline_mono_ms"]
                && value["original_deadline_mono_ms"]
                    .as_u64()
                    .is_some_and(|cap| cap != 0)
                && value["boot_id"] == reservation["boot_id"]
                && value["boot_id"] == self.envelope.boot_id,
            "code=candidate_reconciliation_identity_mismatch module=sdwan_handoff"
        );
        let peers = value["peers"]
            .as_array()
            .context("candidate reconciliation peers absent")?;
        let originals = reservation["plan"]["peers"]
            .as_array()
            .context("candidate original reservation peers absent")?;
        ensure!(
            !peers.is_empty()
                && peers.len() == self.expected_peers.len()
                && originals.len() == peers.len(),
            "code=candidate_reconciliation_coverage_mismatch module=sdwan_handoff"
        );
        for (index, expected) in self.expected_peers.iter().enumerate() {
            ensure!(
                self.expected_peers[..index]
                    .iter()
                    .all(|other| other.attachment_id != expected.attachment_id),
                "code=candidate_reconciliation_duplicate_expected_peer module=sdwan_handoff"
            );
            let matches: Vec<_> = peers
                .iter()
                .filter(|peer| peer["attachment_id"] == serde_json::json!(expected.attachment_id))
                .collect();
            ensure!(
                matches.len() == 1,
                "candidate reconciliation duplicate or missing peer"
            );
            let peer = matches[0];
            ensure!(
                peer["selector"] == serde_json::to_value(&expected.selector)?
                    && peer["barrier"] == serde_json::to_value(&expected.barrier)?,
                "code=candidate_reconciliation_peer_mismatch module=sdwan_handoff"
            );
            let original: Vec<_> = originals
                .iter()
                .filter(|original| original["expected"]["attachment_id"] == peer["attachment_id"])
                .collect();
            ensure!(
                original.len() == 1
                    && original[0]["expected"]["selector"] == peer["selector"]
                    && original[0]["expected"]["barrier"] == peer["barrier"],
                "candidate reconciliation original peer missing"
            );
            let remote = &peer["remote_installation"];
            if remote.is_null() {
                ensure!(
                    peer["remote_outcome"] == "unknown",
                    "code=candidate_reconciliation_remote_unproven module=sdwan_handoff"
                );
                continue;
            }
            let request: Vec<u8> =
                serde_json::from_value(original[0]["reservation"]["intent"]["request"].clone())?;
            let response: Vec<u8> =
                serde_json::from_value(original[0]["reservation"]["response"]["response"].clone())?;
            let request_hash: [u8; 32] = Sha256::digest(request).into();
            let response_hash: [u8; 32] = Sha256::digest(response).into();
            ensure!(
                remote["schema_version"] == 1
                    && peer["remote_outcome"] == "installed_ack_recorded"
                    && peer["commit_intent"] == true
                    && remote["selector"] == peer["selector"]
                    && remote["barrier"] == peer["barrier"]
                    && remote["peer_attachment_id"] == peer["attachment_id"]
                    && remote["request_sha256"] == serde_json::json!(request_hash)
                    && remote["response_sha256"] == serde_json::json!(response_hash)
                    && remote["commit_ack"]
                        .as_array()
                        .is_some_and(|ack| !ack.is_empty())
                    && !remote["connection"].is_null(),
                "code=candidate_reconciliation_remote_receipt_mismatch module=sdwan_handoff"
            );
        }
        Ok(())
    }

    pub(super) fn new(
        envelope: AuthorityEnvelope,
        expected_active: Option<PacketPortBinding>,
        prepare_deadline_mono_ms: u64,
        expected_peers: Vec<PeerExpectation>,
    ) -> Result<Self> {
        if let Some(old) = expected_active {
            ensure!(old.infrastructure_id == envelope.binding.infrastructure_id
                && old.routing_domain_id == envelope.binding.routing_domain_id
                && old.infrastructure_generation == envelope.binding.infrastructure_generation
                && old.io_epoch == envelope.binding.io_epoch
                && old.owner_epoch < envelope.binding.owner_epoch
                && old.policy_generation <= envelope.binding.policy_generation,
                "code=candidate_owner_infrastructure_mismatch module=sdwan_handoff action=preserve_old_owner");
        }
        ensure!(
            !expected_peers.is_empty(),
            "code=candidate_peer_coverage_missing module=sdwan_handoff action=preserve_old_owner"
        );
        Ok(Self {
            envelope,
            expected_active,
            prepare_deadline_mono_ms,
            expected_peers,
            commit_intent: false,
            precommit_cancellation: None,
            committed_failure: None,
            committed_isolation: None,
            expired_commit_retirement: None,
        })
    }

    pub(super) fn read_installed_proof(
        &self,
        plan: &super::Plan,
        record: &crate::process_record::ManagedProcessRecord,
        now_mono_ms: u64,
    ) -> Result<CandidateProof> {
        let status = record.validate_bound_status(&plan.core, super::unix_time()?)?;
        super::validate_worker_placement(plan, record, &status)?;
        ensure!(
            record.pid == self.envelope.candidate.pid
                && record.process_start_ticks == self.envelope.candidate.start_ticks
                && record.status_path == plan.core_status
                && status["worker_authority_revision"] == self.envelope.authority_revision
                && status["worker_authority_sha256"] == self.envelope.signed_control_hash
                && status["worker_transaction_id"] == self.envelope.transaction_id
                && status["packet_binding"] == serde_json::to_value(self.envelope.binding)?,
            "code=candidate_worker_proof_mismatch module=sdwan_handoff action=preserve_old_owner"
        );
        self.proof_from_status(&status, now_mono_ms)
    }

    fn proof_from_status(
        &self,
        status: &serde_json::Value,
        now_mono_ms: u64,
    ) -> Result<CandidateProof> {
        ensure!(
            status["reported_at_mono_ms"]
                .as_u64()
                .is_some_and(|reported| reported != 0
                    && reported <= now_mono_ms.saturating_add(50)
                    && now_mono_ms.saturating_sub(reported) <= 5000)
                && now_mono_ms < self.envelope.effective_deadline_mono_ms,
            "code=candidate_worker_proof_stale module=sdwan_handoff action=preserve_old_owner"
        );
        let proof: CandidateProof = serde_json::from_value(
            status["worker_candidate_transaction"].clone(),
        )
        .context(
            "code=candidate_worker_proof_missing module=sdwan_handoff action=preserve_old_owner",
        )?;
        proof.require_installed(&self.envelope, &self.expected_peers)?;
        Ok(proof)
    }

    fn probe_request(request: &AuthorityControlRequest) -> AuthorityControlRequest {
        AuthorityControlRequest {
            schema_version: 3,
            process: request.process,
            controller: request.controller,
            controller_epoch: request.controller_epoch,
            token_sha256: request.token_sha256.clone(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            operation: AuthorityOperation::ProbeTransaction,
            envelope: None,
            transaction_id: request.transaction_id.clone(),
        }
    }

    pub(super) fn prepare_with(
        &self,
        base: AuthorityControlRequest,
        port: &OwnedFd,
        now_mono_ms: u64,
        persist: impl FnOnce(&Self) -> Result<()>,
        mut exchange: impl FnMut(
            &AuthorityControlRequest,
            Option<&OwnedFd>,
        ) -> Result<AuthorityControlResponse>,
    ) -> Result<OwnerState> {
        let request = self.prepare_request(base, now_mono_ms)?;
        persist(self)?;
        let reply = match exchange(&request, Some(port)) {
            Ok(reply) => reply,
            Err(error) => exchange(&Self::probe_request(&request), None)
                .with_context(|| format!("code=candidate_owner_prepare_unknown module=sdwan_handoff detail={error:#} action=preserve_old_owner_reconcile_original_transaction"))?,
        };
        self.observe(&reply)
    }

    pub(super) fn promote_with(
        &mut self,
        base: AuthorityControlRequest,
        proof: &CandidateProof,
        persist: impl FnOnce(&Self) -> Result<()>,
        mut exchange: impl FnMut(
            &AuthorityControlRequest,
            Option<&OwnedFd>,
        ) -> Result<AuthorityControlResponse>,
    ) -> Result<OwnerState> {
        let request = self.begin_commit(base, proof, persist)?;
        let reply = match exchange(&request, None) {
            Ok(reply) => reply,
            Err(error) => exchange(&Self::probe_request(&request), None)
                .with_context(|| format!("code=candidate_owner_commit_unknown module=sdwan_handoff detail={error:#} action=reconcile_original_transaction"))?,
        };
        self.observe(&reply)
    }

    pub(super) fn prepare_request(
        &self,
        mut base: AuthorityControlRequest,
        now_mono_ms: u64,
    ) -> Result<AuthorityControlRequest> {
        ensure!(
            !self.commit_intent
                && self.precommit_cancellation.is_none()
                && self.expired_commit_retirement.is_none()
                && self.committed_isolation.is_none()
                && self.prepare_deadline_mono_ms > now_mono_ms
                && self.prepare_deadline_mono_ms <= self.envelope.effective_deadline_mono_ms
                && self.prepare_deadline_mono_ms - now_mono_ms <= 30_000,
            "code=candidate_owner_prepare_invalid module=sdwan_handoff action=preserve_old_owner"
        );
        base.schema_version = 3;
        base.operation = AuthorityOperation::PrepareOwner {
            expected_active_epoch: self.expected_active.map(|binding| binding.owner_epoch),
            prepare_deadline_mono_ms: self.prepare_deadline_mono_ms,
        };
        base.envelope = Some(self.envelope.clone());
        base.transaction_id = self.envelope.transaction_id.clone();
        Ok(base)
    }

    pub(super) fn observe(&self, reply: &AuthorityControlResponse) -> Result<OwnerState> {
        let Some(receipt) = reply.owner_transaction.as_ref() else {
            return Ok(OwnerState::Unknown);
        };
        if receipt.transaction_id != self.envelope.transaction_id {
            return Ok(OwnerState::Unknown);
        }
        ensure!(reply.schema_version == 3 && reply.accepted
            && receipt.authority_revision == self.envelope.authority_revision
            && receipt.binding == self.envelope.binding
            && receipt.expected_active_epoch == self.expected_active.map(|binding| binding.owner_epoch)
            && receipt.authorization_cap_mono_ms == self.envelope.effective_deadline_mono_ms
            && receipt.requested_prepare_deadline_mono_ms == self.prepare_deadline_mono_ms,
            "code=candidate_owner_receipt_mismatch module=sdwan_handoff action=reconcile_original_transaction");
        match receipt.phase.as_str() {
            "prepared" => {
                ensure!(reply.pending.as_ref() == Some(&self.envelope)
                    && reply.actual_owner_binding == self.expected_active
                    && (self.expected_active.is_none() || reply.owner_active),
                    "code=candidate_owner_active_changed module=sdwan_handoff action=preserve_old_owner");
                Ok(OwnerState::Prepared)
            }
            "committed" => {
                ensure!(reply.active.as_ref() == Some(&self.envelope)
                    && reply.owner_active
                    && reply.applied_transaction_id.as_deref() == Some(self.envelope.transaction_id.as_str())
                    && reply.authority_revision == Some(self.envelope.authority_revision)
                    && reply.actual_owner_binding == Some(self.envelope.binding)
                    && reply.actual_deadline_mono_ms.is_some_and(|cap| cap <= self.envelope.effective_deadline_mono_ms),
                    "code=candidate_owner_commit_unconfirmed module=sdwan_handoff action=reconcile_original_transaction");
                Ok(OwnerState::Committed)
            }
            "aborted" | "expired" => {
                ensure!(reply.active.as_ref() != Some(&self.envelope)
                    && reply.actual_owner_binding != Some(self.envelope.binding),
                    "code=candidate_owner_terminal_mismatch module=sdwan_handoff action=reconcile_original_transaction");
                Ok(if receipt.phase == "aborted" {
                    OwnerState::Aborted
                } else {
                    OwnerState::Expired
                })
            }
            _ => Ok(OwnerState::Unknown),
        }
    }

    pub(super) fn begin_commit(
        &mut self,
        base: AuthorityControlRequest,
        proof: &CandidateProof,
        persist: impl FnOnce(&Self) -> Result<()>,
    ) -> Result<AuthorityControlRequest> {
        ensure!(
            self.precommit_cancellation.is_none()
                && self.expired_commit_retirement.is_none()
                && self.committed_isolation.is_none(),
            "code=candidate_owner_cancelled module=sdwan_handoff action=retire_original_candidate"
        );
        proof.require_installed(&self.envelope, &self.expected_peers)?;
        // An fsync failure may still have persisted the intent. Keep the
        // uncertainty fence until the original transaction is reconciled.
        self.commit_intent = true;
        persist(self)?;
        self.commit_request(base, proof)
    }

    pub(super) fn require_failed_retirement_receipt(
        &self,
        reply: &AuthorityControlResponse,
        io_identity: candy_process_control::ProcessIdentity,
        now_mono_ms: u64,
    ) -> Result<()> {
        ensure!(self.observe(reply)? == OwnerState::Committed
            && reply.process == io_identity && reply.current_binding == self.envelope.binding
            && reply.forced_retirement && !reply.old_owner_drained
            && reply.retained_owner_binding.is_none() && reply.pending.is_none()
            && now_mono_ms >= self.prepare_deadline_mono_ms
            && reply.actual_deadline_mono_ms.is_some_and(|cap|
                now_mono_ms < cap && cap <= self.envelope.effective_deadline_mono_ms),
            "code=mbb_failed_retirement_receipt_mismatch module=sdwan_handoff action=preserve_current_owner");
        Ok(())
    }

    pub(super) fn commit_is_uncertain(&self) -> bool {
        self.commit_intent
    }

    pub(super) fn require_committed_outcome(&self, reply: &AuthorityControlResponse) -> Result<()> {
        let receipt = reply
            .owner_transaction
            .as_ref()
            .context("code=candidate_committed_receipt_missing module=sdwan_handoff")?;
        ensure!(self.commit_intent && reply.schema_version == 3 && reply.accepted
            && receipt.transaction_id == self.envelope.transaction_id
            && receipt.authority_revision == self.envelope.authority_revision
            && receipt.phase == "committed" && receipt.binding == self.envelope.binding
            && receipt.expected_active_epoch == self.expected_active.map(|binding| binding.owner_epoch)
            && receipt.authorization_cap_mono_ms == self.envelope.effective_deadline_mono_ms
            && receipt.requested_prepare_deadline_mono_ms == self.prepare_deadline_mono_ms
            && reply.owner_highest_revision == Some(self.envelope.authority_revision)
            && reply.pending.is_none()
            && reply.actual_owner_binding.is_none_or(|binding| binding == self.envelope.binding)
            && reply.retained_owner_binding.is_none_or(|binding| Some(binding) == self.expected_active),
            "code=candidate_committed_recovery_mismatch module=sdwan_handoff action=preserve_original_transaction");
        Ok(())
    }

    pub(super) fn record_committed_failure(
        &mut self,
        reply: &AuthorityControlResponse,
        persist: impl FnOnce(&Self) -> Result<()>,
    ) -> Result<()> {
        self.require_committed_outcome(reply)?;
        if self.committed_failure.is_none() {
            self.committed_failure = Some(reply.clone());
        }
        persist(self)
    }

    pub(super) fn committed_isolation_needed(
        &self,
        reply: &AuthorityControlResponse,
        business_current: Result<bool>,
    ) -> Result<bool> {
        self.require_committed_outcome(reply)?;
        // Unknown process/domain state cannot become proof of business death.
        if !reply.owner_active {
            return Ok(true);
        }
        Ok(!business_current?)
    }

    pub(super) fn record_committed_isolation(
        &mut self,
        reply: &AuthorityControlResponse,
        persist: impl FnOnce(&Self) -> Result<()>,
    ) -> Result<()> {
        self.require_committed_outcome(reply)?;
        ensure!(self.committed_failure.is_some()
            && reply.isolated_committed.as_ref() == Some(&self.envelope)
            && !reply.owner_active && reply.actual_owner_binding.is_none()
            && reply.retained_owner_binding.is_none(),
            "code=candidate_committed_isolation_unconfirmed module=sdwan_handoff action=preserve_original_transaction");
        self.committed_isolation = Some(reply.clone());
        persist(self)
    }

    pub(super) fn recover_precommit_with(
        &mut self,
        mut request: AuthorityControlRequest,
        persist: impl FnOnce(&Self) -> Result<()>,
        mut exchange: impl FnMut(&AuthorityControlRequest) -> Result<AuthorityControlResponse>,
    ) -> Result<OwnerState> {
        ensure!(!self.commit_intent,
            "code=candidate_owner_commit_unknown module=sdwan_handoff action=reconcile_original_transaction");
        let expected = self
            .expected_active
            .context("code=candidate_precommit_original_owner_missing module=sdwan_handoff")?;
        request.schema_version = 3;
        request.operation = AuthorityOperation::RecoverPrecommit {
            expected_active: expected,
        };
        request.envelope = Some(self.envelope.clone());
        request.transaction_id = self.envelope.transaction_id.clone();
        let reply = exchange(&request)?;
        ensure!(
            reply.process == request.process
                && reply.controller == request.controller
                && reply.controller_epoch == request.controller_epoch
                && reply.nonce == request.nonce,
            "code=candidate_precommit_response_fence_mismatch module=sdwan_handoff"
        );
        if reply.precommit_cancelled.is_none() {
            return self.observe(&reply);
        }
        ensure!(reply.precommit_cancelled.as_ref() == Some(&self.envelope)
            && reply.schema_version == 3 && reply.accepted && reply.owner_active
            && reply.actual_owner_binding == Some(expected) && reply.current_binding == expected
            && reply.active.as_ref() != Some(&self.envelope) && reply.pending.is_none()
            && reply.retained_owner_binding.is_none() && reply.owner_transaction.is_none()
            && reply.owner_highest_revision.is_some_and(|revision| revision < self.envelope.authority_revision)
            && reply.highest_revision == self.envelope.authority_revision
            && reply.highest_owner_epoch == self.envelope.binding.owner_epoch
            && reply.highest_policy_generation == self.envelope.binding.policy_generation,
            "code=candidate_precommit_cancellation_unconfirmed module=sdwan_handoff action=preserve_original_candidate");
        self.precommit_cancellation = Some(reply);
        persist(self)?;
        Ok(OwnerState::CancelledBeforePrepare)
    }

    pub(super) fn retire_expired_commit_with(
        &mut self,
        mut request: AuthorityControlRequest,
        persist: impl FnOnce(&Self) -> Result<()>,
        exchange: impl FnOnce(&AuthorityControlRequest) -> Result<AuthorityControlResponse>,
    ) -> Result<()> {
        ensure!(
            self.commit_intent,
            "code=candidate_commit_intent_missing module=sdwan_handoff"
        );
        let expected = self
            .expected_active
            .context("expired commit original binding absent")?;
        request.schema_version = 3;
        request.operation = AuthorityOperation::RetireExpiredCommit {
            expected_active: expected,
        };
        request.envelope = Some(self.envelope.clone());
        request.transaction_id = self.envelope.transaction_id.clone();
        let reply = exchange(&request)?;
        ensure!(reply.process == request.process && reply.controller == request.controller
            && reply.controller_epoch == request.controller_epoch && reply.nonce == request.nonce
            && reply.retired_expired_commit.as_ref() == Some(&self.envelope)
            && self.observe(&reply)? == OwnerState::Expired
            && reply.owner_active && reply.actual_owner_binding == Some(expected)
            && reply.current_binding == expected && reply.pending.is_none()
            && reply.retained_owner_binding.is_none()
            && reply.owner_highest_revision == Some(self.envelope.authority_revision),
            "code=candidate_expired_commit_retirement_unconfirmed module=sdwan_handoff action=preserve_original_transaction");
        self.expired_commit_retirement = Some(reply);
        persist(self)
    }

    pub(super) fn commit_request(
        &self,
        mut base: AuthorityControlRequest,
        proof: &CandidateProof,
    ) -> Result<AuthorityControlRequest> {
        proof.require_installed(&self.envelope, &self.expected_peers)?;
        ensure!(self.commit_intent,
            "code=candidate_owner_commit_intent_missing module=sdwan_handoff action=persist_original_transaction");
        ensure!(
            self.expired_commit_retirement.is_none() && self.committed_isolation.is_none(),
            "code=candidate_owner_retired module=sdwan_handoff action=use_fresh_transaction"
        );
        base.schema_version = 3;
        base.operation = AuthorityOperation::CommitOwner;
        base.envelope = Some(self.envelope.clone());
        base.transaction_id = self.envelope.transaction_id.clone();
        Ok(base)
    }

    #[cfg(test)]
    pub(super) fn abort_request(
        &self,
        mut base: AuthorityControlRequest,
    ) -> Result<AuthorityControlRequest> {
        ensure!(!self.commit_intent,
            "code=candidate_owner_commit_unknown module=sdwan_handoff action=reconcile_original_transaction");
        base.schema_version = 3;
        base.operation = AuthorityOperation::AbortOwner;
        base.envelope = Some(self.envelope.clone());
        base.transaction_id = self.envelope.transaction_id.clone();
        Ok(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> CandidateOwner {
        let binding = PacketPortBinding {
            infrastructure_id: [1; 16],
            routing_domain_id: [2; 16],
            infrastructure_generation: 1,
            io_epoch: 1,
            owner_epoch: 2,
            policy_generation: 3,
        };
        let envelope = AuthorityEnvelope {
            transaction_id: "a".repeat(32),
            authority_revision: 4,
            binding,
            candidate: candy_process_control::ProcessIdentity {
                pid: 100,
                start_ticks: 200,
            },
            controller: candy_process_control::ProcessIdentity {
                pid: 101,
                start_ticks: 201,
            },
            controller_epoch: 1,
            signed_control_hash: "b".repeat(64),
            declaration_hash: "c".repeat(64),
            verification_report_hash: "d".repeat(64),
            snapshot_closure_hash: "e".repeat(64),
            signed_min_expiry_unix: 100,
            effective_expiry_unix: 100,
            verified_at_unix: 50,
            verified_at_mono_ms: 1000,
            effective_deadline_mono_ms: 50_000,
            boot_id: "boot".into(),
        };
        CandidateOwner {
            envelope,
            expected_active: Some(PacketPortBinding {
                owner_epoch: 1,
                ..binding
            }),
            prepare_deadline_mono_ms: 20_000,
            expected_peers: vec![PeerExpectation {
                attachment_id: [3; 16],
                selector: RoutingCandidate {
                    transaction_id: [4; 32],
                    owner_epoch: 5,
                    policy_generation: 6,
                    authorization_sha256: [7; 32],
                    candidate_id: [8; 16],
                    local_attachment_epoch: 9,
                    peer_attachment_epoch: 10,
                    tunnel_id: 11,
                },
                barrier: BarrierIdentity {
                    id: [4; 32],
                    generation: 6,
                    fence: 12,
                    hash: [13; 32],
                },
            }],
            commit_intent: false,
            precommit_cancellation: None,
            committed_failure: None,
            committed_isolation: None,
            expired_commit_retirement: None,
        }
    }

    fn base(owner: &CandidateOwner) -> AuthorityControlRequest {
        AuthorityControlRequest {
            schema_version: 2,
            process: owner.envelope.candidate,
            controller: owner.envelope.controller,
            controller_epoch: 1,
            token_sha256: "f".repeat(64),
            nonce: "0".repeat(32),
            operation: AuthorityOperation::ProbeTransaction,
            envelope: None,
            transaction_id: owner.envelope.transaction_id.clone(),
        }
    }

    fn reconciliation(owner: &CandidateOwner) -> (serde_json::Value, serde_json::Value) {
        use sha2::{Digest, Sha256};
        let peer = &owner.expected_peers[0];
        let request = vec![1_u8, 2, 3];
        let response = vec![4_u8, 5, 6];
        let request_hash: [u8; 32] = Sha256::digest(&request).into();
        let response_hash: [u8; 32] = Sha256::digest(&response).into();
        let original = serde_json::json!({
            "original_deadline_mono_ms":20_000,"boot_id":"boot",
            "plan":{"peers":[{"expected":peer,"reservation":{
                "intent":{"request":request},"response":{"response":response}}}]}});
        let result = serde_json::json!({
            "schema_version":1,"read_only":true,"phase":"reconciled_original_candidate",
            "transaction_id":owner.envelope.transaction_id,
            "authorization_sha256":owner.envelope.signed_control_hash,
            "owner_epoch":owner.envelope.binding.owner_epoch,
            "original_deadline_mono_ms":20_000,"boot_id":"boot",
            "peers":[{"attachment_id":peer.attachment_id,"selector":peer.selector,
                "barrier":peer.barrier,"commit_intent":true,"local_actor_phase":"Installed",
                "remote_outcome":"installed_ack_recorded","remote_installation":{
                    "schema_version":1,"selector":peer.selector,"barrier":peer.barrier,
                    "connection":{"Direct":90},"local_attachment_id":vec![2_u8;16],
                    "peer_attachment_id":peer.attachment_id,
                    "request_sha256":request_hash,"response_sha256":response_hash,
                    "commit_ack":[1,2,3]}}]});
        (result, original)
    }

    #[test]
    fn historical_peer_reconciliation_binds_original_tuple_and_reservation() {
        let owner = candidate();
        let (result, original) = reconciliation(&owner);
        owner
            .require_peer_reconciliation(&result, &original)
            .unwrap();
        for (pointer, changed) in [
            ("/read_only", serde_json::json!(false)),
            ("/transaction_id", serde_json::json!("different")),
            ("/authorization_sha256", serde_json::json!("different")),
            ("/owner_epoch", serde_json::json!(3)),
            ("/original_deadline_mono_ms", serde_json::json!(20_001)),
            ("/boot_id", serde_json::json!("other")),
            ("/peers/0/attachment_id", serde_json::json!(vec![9_u8; 16])),
            ("/peers/0/selector/owner_epoch", serde_json::json!(99)),
            ("/peers/0/barrier/fence", serde_json::json!(99)),
            ("/peers/0/commit_intent", serde_json::json!(false)),
            (
                "/peers/0/remote_installation/request_sha256",
                serde_json::json!(vec![0_u8; 32]),
            ),
            (
                "/peers/0/remote_installation/response_sha256",
                serde_json::json!(vec![0_u8; 32]),
            ),
            (
                "/peers/0/remote_installation/peer_attachment_id",
                serde_json::json!(vec![9_u8; 16]),
            ),
            (
                "/peers/0/remote_installation/selector/tunnel_id",
                serde_json::json!(99),
            ),
            (
                "/peers/0/remote_installation/barrier/hash",
                serde_json::json!(vec![0_u8; 32]),
            ),
            (
                "/peers/0/remote_installation/commit_ack",
                serde_json::json!([]),
            ),
            (
                "/peers/0/remote_installation/connection",
                serde_json::Value::Null,
            ),
        ] {
            let mut forged = result.clone();
            *forged.pointer_mut(pointer).unwrap() = changed;
            assert!(
                owner
                    .require_peer_reconciliation(&forged, &original)
                    .is_err(),
                "accepted {pointer}"
            );
        }
        let mut altered = original.clone();
        altered["plan"]["peers"][0]["reservation"]["intent"]["request"] = serde_json::json!([7]);
        assert!(owner
            .require_peer_reconciliation(&result, &altered)
            .is_err());
        let mut duplicate = result.clone();
        duplicate["peers"]
            .as_array_mut()
            .unwrap()
            .push(result["peers"][0].clone());
        assert!(owner
            .require_peer_reconciliation(&duplicate, &original)
            .is_err());
    }

    #[test]
    fn local_installed_without_authenticated_peer_ack_remains_unknown() {
        let owner = candidate();
        let (mut result, original) = reconciliation(&owner);
        result["peers"][0]["remote_installation"] = serde_json::Value::Null;
        result["peers"][0]["remote_outcome"] = "unknown".into();
        owner
            .require_peer_reconciliation(&result, &original)
            .unwrap();
        assert!(!owner.commit_intent);
        result["peers"][0]["remote_outcome"] = "installed_ack_recorded".into();
        assert!(owner
            .require_peer_reconciliation(&result, &original)
            .is_err());
        result["peers"][0]["remote_outcome"] = "unknown".into();
        let mut changed_original = original;
        changed_original["plan"]["peers"][0]["expected"]["barrier"]["fence"] = 99.into();
        assert!(owner
            .require_peer_reconciliation(&result, &changed_original)
            .is_err());
    }

    fn proof(owner: &CandidateOwner) -> CandidateProof {
        let peer = &owner.expected_peers[0];
        CandidateProof {
            schema_version: 1,
            transaction_id: owner.envelope.transaction_id.clone(),
            phase: "installed".into(),
            local: LocalProof {
                domain: owner.envelope.binding.routing_domain_id,
                owner_epoch: owner.envelope.binding.owner_epoch,
                authorization_sha256: owner.envelope.signed_control_hash.clone(),
                packet_slot: owner.envelope.binding,
            },
            peers: vec![PeerProof {
                attachment_id: peer.attachment_id,
                selector: peer.selector.clone(),
                barrier: peer.barrier.clone(),
                prepared: true,
                installed: true,
                probe_sent: true,
                probe_received: true,
                drain_complete: false,
                drain_failed: false,
                activation_confirmed: false,
                transport_live: false,
                recovery_action: String::new(),
            }],
            forced_retirement: false,
            old_owner_drained: false,
        }
    }

    fn reply(owner: &CandidateOwner, phase: &str) -> AuthorityControlResponse {
        let committed = phase == "committed";
        AuthorityControlResponse {
            schema_version: 3,
            process: owner.envelope.candidate,
            controller: owner.envelope.controller,
            controller_epoch: 1,
            nonce: "0".repeat(32),
            accepted: true,
            code: "ok".into(),
            detail: String::new(),
            active: committed.then(|| owner.envelope.clone()),
            pending: (!committed).then(|| owner.envelope.clone()),
            highest_revision: 4,
            highest_owner_epoch: 2,
            highest_policy_generation: 3,
            applied_transaction_id: committed.then(|| owner.envelope.transaction_id.clone()),
            authority_revision: committed.then_some(4),
            current_binding: owner.envelope.binding,
            auth_deadline_unix: 100,
            owner_active: true,
            actual_deadline_mono_ms: Some(50_000),
            owner_transaction: Some(candy_tunio::authority_control::AuthorityOwnerReceipt {
                transaction_id: owner.envelope.transaction_id.clone(),
                authority_revision: 4,
                phase: phase.into(),
                binding: owner.envelope.binding,
                expected_active_epoch: Some(1),
                authorization_cap_mono_ms: 50_000,
                requested_prepare_deadline_mono_ms: 20_000,
            }),
            actual_owner_binding: if committed {
                Some(owner.envelope.binding)
            } else {
                owner.expected_active
            },
            owner_highest_revision: Some(4),
            retained_owner_binding: committed.then_some(owner.expected_active).flatten(),
            old_owner_drained: false,
            forced_retirement: false,
            precommit_cancelled: None,
            isolated_committed: None,
            retired_expired_commit: None,
        }
    }

    fn cancelled_reply(owner: &CandidateOwner) -> AuthorityControlResponse {
        let mut response = reply(owner, "prepared");
        response.owner_transaction = None;
        response.pending = None;
        response.current_binding = owner.expected_active.unwrap();
        response.owner_highest_revision = Some(owner.envelope.authority_revision - 1);
        response.precommit_cancelled = Some(owner.envelope.clone());
        response
    }

    fn expired_retirement_reply(owner: &CandidateOwner) -> AuthorityControlResponse {
        let mut response = reply(owner, "expired");
        response.pending = None;
        response.current_binding = owner.expected_active.unwrap();
        response.retired_expired_commit = Some(owner.envelope.clone());
        response
    }

    #[test]
    fn expired_commit_retirement_preserves_intent_and_exact_receipt_across_restart() {
        let mut owner = candidate();
        assert!(owner
            .retire_expired_commit_with(
                base(&owner),
                |_| panic!("no intent"),
                |_| panic!("no RPC without intent")
            )
            .is_err());
        owner.commit_intent = true;
        let response = expired_retirement_reply(&owner);
        let expected = owner.clone();
        let mut saved = Vec::new();
        owner.retire_expired_commit_with(base(&owner), |candidate| {
            saved = serde_json::to_vec(candidate)?;
            Ok(())
        }, |request| {
                    assert_eq!(request.envelope, Some(expected.envelope.clone()));
            assert!(matches!(request.operation, AuthorityOperation::RetireExpiredCommit { expected_active }
                        if Some(expected_active) == expected.expected_active));
            Ok(response.clone())
        }).unwrap();
        let mut restored: CandidateOwner = serde_json::from_slice(&saved).unwrap();
        assert!(restored.commit_intent);
        assert_eq!(
            restored
                .expired_commit_retirement
                .as_ref()
                .unwrap()
                .owner_transaction
                .as_ref()
                .unwrap()
                .phase,
            "expired"
        );
        assert!(restored.abort_request(base(&restored)).is_err());
        assert!(restored.prepare_request(base(&restored), 1000).is_err());
        assert!(restored
            .commit_request(base(&restored), &proof(&restored))
            .is_err());
        let installed = proof(&restored);
        assert!(restored
            .begin_commit(base(&restored), &installed, |_| panic!("retired"))
            .is_err());
        restored
            .retire_expired_commit_with(base(&restored), |_| Ok(()), |_| Ok(response.clone()))
            .unwrap();
        assert!(restored.commit_intent);
    }

    #[test]
    fn expired_commit_retirement_rejects_unknown_or_changed_evidence() {
        for mutation in 0..14 {
            let mut owner = candidate();
            owner.commit_intent = true;
            let mut response = expired_retirement_reply(&owner);
            match mutation {
                0 => response.accepted = false,
                1 => response.schema_version = 2,
                2 => response.process.start_ticks += 1,
                3 => response.controller.start_ticks += 1,
                4 => response.controller_epoch += 1,
                5 => response.nonce = "1".repeat(32),
                6 => {
                    response
                        .retired_expired_commit
                        .as_mut()
                        .unwrap()
                        .signed_control_hash = "9".repeat(64)
                }
                7 => {
                    response
                        .actual_owner_binding
                        .as_mut()
                        .unwrap()
                        .routing_domain_id = [9; 16]
                }
                8 => response.current_binding.policy_generation += 1,
                9 => response.owner_active = false,
                10 => response.owner_highest_revision = Some(owner.envelope.authority_revision + 1),
                11 => response.pending = Some(owner.envelope.clone()),
                12 => response.retained_owner_binding = owner.expected_active,
                _ => response.owner_transaction.as_mut().unwrap().phase = "aborted".into(),
            }
            assert!(
                owner
                    .retire_expired_commit_with(
                        base(&owner),
                        |_| panic!("invalid evidence cannot persist"),
                        |_| Ok(response)
                    )
                    .is_err(),
                "accepted mutation {mutation}"
            );
            assert!(owner.expired_commit_retirement.is_none());
            assert!(owner.commit_intent);
        }
        let mut owner = candidate();
        owner.commit_intent = true;
        assert!(owner
            .retire_expired_commit_with(
                base(&owner),
                |_| panic!("unknown cannot persist"),
                |_| anyhow::bail!("manager timeout")
            )
            .is_err());
        assert!(owner.expired_commit_retirement.is_none());
        let response = expired_retirement_reply(&owner);
        assert!(owner
            .retire_expired_commit_with(
                base(&owner),
                |_| anyhow::bail!("fsync failed"),
                |_| Ok(response)
            )
            .is_err());
        assert!(owner.commit_intent && owner.expired_commit_retirement.is_some());
        assert!(owner.commit_request(base(&owner), &proof(&owner)).is_err());
    }

    #[test]
    fn precommit_recovery_requires_durable_exact_cancellation_and_original_owner() {
        let mut owner = candidate();
        let response = cancelled_reply(&owner);
        let expected = owner.clone();
        let mut persisted = false;
        assert_eq!(owner.recover_precommit_with(base(&expected), |candidate| {
            assert!(candidate.precommit_cancellation.is_some());
            persisted = true;
            Ok(())
        }, |request| {
            assert!(matches!(request.operation, AuthorityOperation::RecoverPrecommit { expected_active }
                if Some(expected_active) == expected.expected_active));
            assert_eq!(request.envelope, Some(expected.envelope.clone()));
            Ok(response.clone())
        }).unwrap(), OwnerState::CancelledBeforePrepare);
        assert!(persisted);
        assert!(owner.prepare_request(base(&owner), 1000).is_err());
        let installed = proof(&owner);
        assert!(owner
            .begin_commit(base(&expected), &installed, |_| Ok(()))
            .is_err());
        let saved = serde_json::to_vec(&owner).unwrap();
        let mut restored: CandidateOwner = serde_json::from_slice(&saved).unwrap();
        assert_eq!(
            restored
                .recover_precommit_with(base(&expected), |_| Ok(()), |_| Ok(response.clone()))
                .unwrap(),
            OwnerState::CancelledBeforePrepare
        );
    }

    #[test]
    fn committed_failure_keeps_actual_outcome_and_requires_durable_exact_isolation() {
        let mut owner = candidate();
        owner.commit_intent = true;
        let mut committed = reply(&owner, "committed");
        assert!(!owner
            .committed_isolation_needed(&committed, Ok(true))
            .unwrap());
        assert!(owner
            .committed_isolation_needed(&committed, Ok(false))
            .unwrap());
        assert!(owner
            .committed_isolation_needed(&committed, Err(anyhow::anyhow!("domain RPC timed out")))
            .is_err());
        // A closed candidate port does not change the transaction's actual
        // Committed outcome into Abort or Unknown.
        committed.owner_active = false;
        committed.actual_owner_binding = None;
        committed.active = None;
        assert!(owner
            .committed_isolation_needed(&committed, Ok(true))
            .unwrap());
        assert!(owner
            .committed_isolation_needed(&committed, Err(anyhow::anyhow!("domain RPC timed out")))
            .unwrap());
        assert!(owner
            .record_committed_failure(&committed, |_| anyhow::bail!("fsync failed"))
            .is_err());
        assert!(owner.committed_failure.is_some());
        let mut isolated = committed.clone();
        isolated.isolated_committed = Some(owner.envelope.clone());
        isolated.retained_owner_binding = None;
        let mut saved = Vec::new();
        owner
            .record_committed_isolation(&isolated, |candidate| {
                saved = serde_json::to_vec(candidate)?;
                Ok(())
            })
            .unwrap();
        let restored: CandidateOwner = serde_json::from_slice(&saved).unwrap();
        assert!(restored.commit_is_uncertain());
        assert!(restored.committed_failure.is_some() && restored.committed_isolation.is_some());
        assert_eq!(
            restored
                .committed_failure
                .unwrap()
                .owner_transaction
                .unwrap()
                .phase,
            "committed"
        );
        for mutation in 0..5 {
            let mut owner = candidate();
            owner.commit_intent = true;
            owner
                .record_committed_failure(&committed, |_| Ok(()))
                .unwrap();
            let mut invalid = isolated.clone();
            match mutation {
                0 => invalid.owner_active = true,
                1 => invalid.actual_owner_binding = Some(owner.envelope.binding),
                2 => invalid.isolated_committed = None,
                3 => invalid.owner_highest_revision = Some(owner.envelope.authority_revision + 1),
                _ => invalid.retained_owner_binding = owner.expected_active,
            }
            assert!(owner
                .record_committed_isolation(&invalid, |_| panic!(
                    "unknown isolation cannot persist"
                ))
                .is_err());
        }
    }

    #[test]
    fn precommit_recovery_preserves_prepared_committed_and_uncertain_outcomes() {
        for phase in ["prepared", "committed"] {
            let mut owner = candidate();
            let response = reply(&owner, phase);
            let expected = if phase == "prepared" {
                OwnerState::Prepared
            } else {
                OwnerState::Committed
            };
            assert_eq!(
                owner
                    .recover_precommit_with(
                        base(&owner),
                        |_| panic!("actual outcome is not cancellation"),
                        |_| Ok(response.clone())
                    )
                    .unwrap(),
                expected
            );
            assert!(owner.precommit_cancellation.is_none());
        }
        let mut owner = candidate();
        assert!(owner
            .recover_precommit_with(
                base(&owner),
                |_| panic!("manager failure is not absence"),
                |_| anyhow::bail!("manager disconnected")
            )
            .is_err());
        assert!(owner.precommit_cancellation.is_none());
        owner.commit_intent = true;
        assert!(owner
            .recover_precommit_with(
                base(&owner),
                |_| panic!("uncertain commit cannot cancel"),
                |_| panic!("no cancellation RPC after intent")
            )
            .is_err());
    }

    #[test]
    fn precommit_recovery_rejects_weak_absence_forged_scope_and_lost_persistence() {
        for mutation in 0..9 {
            let mut owner = candidate();
            let mut response = cancelled_reply(&owner);
            match mutation {
                0 => response.owner_active = false,
                1 => {
                    response
                        .actual_owner_binding
                        .as_mut()
                        .unwrap()
                        .routing_domain_id = [9; 16]
                }
                2 => response.owner_highest_revision = Some(owner.envelope.authority_revision),
                3 => {
                    response
                        .precommit_cancelled
                        .as_mut()
                        .unwrap()
                        .signed_control_hash = "9".repeat(64)
                }
                4 => response.retained_owner_binding = owner.expected_active,
                5 => response.accepted = false,
                6 => response.nonce = "9".repeat(32),
                7 => response.highest_policy_generation += 1,
                _ => response.pending = Some(owner.envelope.clone()),
            }
            assert!(owner
                .recover_precommit_with(
                    base(&owner),
                    |_| panic!("invalid absence cannot persist"),
                    |_| Ok(response.clone())
                )
                .is_err());
            assert!(owner.precommit_cancellation.is_none());
        }
        let mut owner = candidate();
        let response = cancelled_reply(&owner);
        assert!(owner
            .recover_precommit_with(
                base(&owner),
                |_| anyhow::bail!("uncertain directory fsync"),
                |_| Ok(response.clone())
            )
            .is_err());
        // The in-memory cancellation fence remains, but no caller received a
        // retirement decision until an exact recovery publication succeeds.
        assert!(owner.precommit_cancellation.is_some());
        assert_eq!(
            owner
                .recover_precommit_with(base(&owner), |_| Ok(()), |_| Ok(response.clone()))
                .unwrap(),
            OwnerState::CancelledBeforePrepare
        );
    }

    #[test]
    fn prepared_owner_keeps_old_binding_and_rejects_changed_receipts() {
        let owner = candidate();
        let request = owner.prepare_request(base(&owner), 1000).unwrap();
        assert_eq!(request.schema_version, 3);
        assert!(matches!(
            request.operation,
            AuthorityOperation::PrepareOwner {
                expected_active_epoch: Some(1),
                prepare_deadline_mono_ms: 20_000
            }
        ));
        assert_eq!(
            owner.observe(&reply(&owner, "prepared")).unwrap(),
            OwnerState::Prepared
        );
        let mut changed = reply(&owner, "prepared");
        changed.actual_owner_binding = Some(owner.envelope.binding);
        assert!(owner.observe(&changed).is_err());
        let mut changed = reply(&owner, "prepared");
        changed
            .owner_transaction
            .as_mut()
            .unwrap()
            .requested_prepare_deadline_mono_ms += 1;
        assert!(owner.observe(&changed).is_err());
        assert!(owner.prepare_request(base(&owner), 20_000).is_err());
    }

    #[test]
    fn lost_prepare_reply_keeps_original_fd_and_queries_exact_receipt() {
        let owner = candidate();
        let port: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        let mut prepared = Some(reply(&owner, "prepared"));
        let mut calls = 0;
        let durable = std::cell::Cell::new(false);
        let outcome = owner
            .prepare_with(
                base(&owner),
                &port,
                1000,
                |_| {
                    durable.set(true);
                    Ok(())
                },
                |request, fd| {
                    calls += 1;
                    assert!(durable.get());
                    assert_eq!(request.transaction_id, owner.envelope.transaction_id);
                    if calls == 1 {
                        assert!(fd.is_some());
                        anyhow::bail!("prepare reply lost");
                    }
                    assert!(fd.is_none());
                    assert!(matches!(
                        request.operation,
                        AuthorityOperation::ProbeTransaction
                    ));
                    Ok(prepared.take().unwrap())
                },
            )
            .unwrap();
        assert_eq!(outcome, OwnerState::Prepared);
        assert_eq!(calls, 2);
        assert!(!owner.commit_is_uncertain());
    }

    #[test]
    fn stale_or_missing_status_never_substitutes_for_actor_installation() {
        let owner = candidate();
        let status = serde_json::json!({"reported_at_mono_ms": 1000,
            "worker_candidate_transaction": proof(&owner)});
        assert!(owner.proof_from_status(&status, 1000).is_ok());
        assert!(owner.proof_from_status(&status, 6001).is_err());
        assert!(owner.proof_from_status(&status, 900).is_err());
        assert!(owner
            .proof_from_status(
                &serde_json::json!({
                    "reported_at_mono_ms":1000,"lifecycle":"active","ready":true
                }),
                1000
            )
            .is_err());
        assert!(owner.proof_from_status(&status, 50_000).is_err());
    }

    #[test]
    fn missing_or_changed_actor_proof_never_promotes_candidate() {
        let mut owner = candidate();
        let exact = proof(&owner);
        assert!(owner.commit_request(base(&owner), &exact).is_err());
        owner.commit_intent = true;
        assert!(owner.commit_request(base(&owner), &exact).is_ok());
        for field in 0..12 {
            let mut changed = exact.clone();
            match field {
                0 => changed.transaction_id.push('a'),
                1 => changed.local.owner_epoch += 1,
                2 => changed.local.authorization_sha256.push('b'),
                3 => changed.local.packet_slot.io_epoch += 1,
                4 => changed.phase = "healthy".into(),
                5 => changed.peers[0].installed = false,
                6 => changed.peers[0].prepared = false,
                7 => changed.peers[0].probe_sent = false,
                8 => changed.peers[0].probe_received = false,
                9 => changed.peers[0].selector.owner_epoch += 1,
                10 => changed.peers[0].barrier.fence += 1,
                _ => changed.peers.push(changed.peers[0].clone()),
            }
            assert!(
                owner.commit_request(base(&owner), &changed).is_err(),
                "accepted field {field}"
            );
        }
        let encoded = serde_json::to_vec(&exact).unwrap();
        let decoded: CandidateProof = serde_json::from_slice(&encoded).unwrap();
        decoded
            .require_installed(&owner.envelope, &owner.expected_peers)
            .unwrap();
    }

    #[test]
    fn uncertain_commit_cannot_abort_or_prepare_another_owner() {
        let mut owner = candidate();
        assert!(owner.abort_request(base(&owner)).is_ok());
        owner.commit_intent = true;
        let restored: CandidateOwner =
            serde_json::from_slice(&serde_json::to_vec(&owner).unwrap()).unwrap();
        assert!(restored.abort_request(base(&restored)).is_err());
        assert!(restored.prepare_request(base(&restored), 1000).is_err());
        let mut unknown = reply(&restored, "prepared");
        unknown.owner_transaction = None;
        assert_eq!(restored.observe(&unknown).unwrap(), OwnerState::Unknown);
        assert_eq!(
            restored.observe(&reply(&restored, "committed")).unwrap(),
            OwnerState::Committed
        );
        let mut changed = reply(&restored, "committed");
        changed.actual_deadline_mono_ms = Some(50_001);
        assert!(restored.observe(&changed).is_err());
    }

    #[test]
    fn failed_intent_persistence_preserves_unknown_fence_without_sending_commit() {
        let mut owner = candidate();
        let exact = proof(&owner);
        let result = owner.begin_commit(base(&owner), &exact, |_| anyhow::bail!("fsync failed"));
        assert!(result.is_err());
        assert!(owner.commit_is_uncertain());
        assert!(owner.abort_request(base(&owner)).is_err());
        assert!(owner.commit_request(base(&owner), &exact).is_ok());
    }

    #[test]
    fn lost_commit_reply_probes_original_transaction_after_durable_intent() {
        let mut owner = candidate();
        let exact = proof(&owner);
        let committed = reply(&owner, "committed");
        let transaction = owner.envelope.transaction_id.clone();
        let mut committed = Some(committed);
        let mut calls = 0;
        let durable = std::cell::Cell::new(false);
        let outcome = owner
            .promote_with(
                base(&owner),
                &exact,
                |saved| {
                    assert!(saved.commit_is_uncertain());
                    durable.set(true);
                    Ok(())
                },
                |request, fd| {
                    calls += 1;
                    assert!(durable.get());
                    assert_eq!(request.transaction_id, transaction);
                    assert!(fd.is_none());
                    if calls == 1 {
                        assert!(matches!(request.operation, AuthorityOperation::CommitOwner));
                        anyhow::bail!("control reply lost");
                    }
                    assert!(matches!(
                        request.operation,
                        AuthorityOperation::ProbeTransaction
                    ));
                    Ok(committed.take().unwrap())
                },
            )
            .unwrap();
        assert_eq!(outcome, OwnerState::Committed);
        assert_eq!(calls, 2);
    }

    #[test]
    fn pending_owner_queue_retries_original_commit_without_replacing_candidate() {
        let mut owner = candidate();
        let exact = proof(&owner);
        let prepared = reply(&owner, "prepared");
        let committed = reply(&owner, "committed");
        let mut first_request = None;
        let mut calls = 0;
        let outcome = owner
            .promote_with(
                base(&owner),
                &exact,
                |_| Ok(()),
                |request, fd| {
                    assert!(fd.is_none());
                    calls += 1;
                    if calls == 1 {
                        first_request = Some(serde_json::to_value(request).unwrap());
                        anyhow::bail!("code=owner_commit_queue_pending module=packet_port_manager");
                    }
                    assert!(matches!(
                        request.operation,
                        AuthorityOperation::ProbeTransaction
                    ));
                    Ok(prepared.clone())
                },
            )
            .unwrap();
        assert_eq!(outcome, OwnerState::Prepared);
        assert!(owner.commit_is_uncertain());
        let mut owner: CandidateOwner =
            serde_json::from_slice(&serde_json::to_vec(&owner).unwrap()).unwrap();
        assert!(owner.abort_request(base(&owner)).is_err());
        assert!(owner.prepare_request(base(&owner), 1000).is_err());
        let outcome = owner
            .promote_with(
                base(&owner),
                &exact,
                |_| Ok(()),
                |request, fd| {
                    assert!(fd.is_none());
                    assert_eq!(Some(serde_json::to_value(request).unwrap()), first_request);
                    Ok(committed.clone())
                },
            )
            .unwrap();
        assert_eq!(outcome, OwnerState::Committed);
    }

    #[test]
    fn retirement_requires_every_peer_drain_receipt() {
        let owner = candidate();
        let mut exact = proof(&owner);
        assert!(exact
            .require_drained(&owner.envelope, &owner.expected_peers)
            .is_err());
        exact.peers[0].drain_complete = true;
        exact
            .require_drained(&owner.envelope, &owner.expected_peers)
            .unwrap();
    }

    #[test]
    fn failed_retirement_is_exact_and_never_installation_or_successful_drain() {
        let owner = candidate();
        let mut exact = proof(&owner);
        exact.phase = "failed_drain_preserved".into();
        exact.forced_retirement = true;
        exact.peers[0].drain_failed = true;
        exact.peers[0].activation_confirmed = true;
        exact.peers[0].transport_live = true;
        exact.peers[0].recovery_action = "preserve_active_peer".into();
        exact
            .require_failed_retirement(&owner.envelope, &owner.expected_peers)
            .unwrap();
        assert!(exact
            .require_installed(&owner.envelope, &owner.expected_peers)
            .is_err());
        assert!(exact
            .require_drained(&owner.envelope, &owner.expected_peers)
            .is_err());
        for field in 0..6 {
            let mut changed = exact.clone();
            match field {
                0 => changed.old_owner_drained = true,
                1 => changed.forced_retirement = false,
                2 => changed.peers[0].drain_complete = true,
                3 => changed.peers[0].drain_failed = false,
                4 => changed.peers[0].selector.owner_epoch += 1,
                _ => changed.peers[0].probe_received = false,
            }
            assert!(changed
                .require_failed_retirement(&owner.envelope, &owner.expected_peers)
                .is_err());
        }
    }

    #[test]
    fn partial_failed_retirement_preserves_each_peers_original_outcome() {
        let mut owner = candidate();
        let mut second = owner.expected_peers[0].clone();
        second.attachment_id = [8; 16];
        second.selector.transaction_id = [9; 32];
        second.barrier.id = [9; 32];
        owner.expected_peers.push(second.clone());
        let mut exact = proof(&owner);
        let mut completed = exact.peers[0].clone();
        completed.attachment_id = second.attachment_id;
        completed.selector = second.selector;
        completed.barrier = second.barrier;
        completed.drain_complete = true;
        exact.peers.push(completed);
        exact.phase = "failed_drain_preserved".into();
        exact.forced_retirement = true;
        exact.peers[0].drain_failed = true;
        for peer in &mut exact.peers {
            peer.activation_confirmed = true;
            peer.transport_live = true;
            peer.recovery_action = "preserve_active_peer".into();
        }
        exact
            .require_failed_retirement(&owner.envelope, &owner.expected_peers)
            .unwrap();
        exact.peers[1].drain_failed = true;
        assert!(exact
            .require_failed_retirement(&owner.envelope, &owner.expected_peers)
            .is_err());
        exact.peers[1].drain_failed = false;
        exact.peers[1].transport_live = false;
        exact.peers[1].recovery_action = "redial_affected_peer".into();
        exact
            .require_failed_retirement(&owner.envelope, &owner.expected_peers)
            .unwrap();
        exact.peers[0].activation_confirmed = false;
        exact.peers[0].transport_live = false;
        exact.peers[0].recovery_action = "redial_affected_peer".into();
        exact
            .require_failed_retirement(&owner.envelope, &owner.expected_peers)
            .unwrap();
        exact.peers[0].recovery_action = "preserve_active_peer".into();
        assert!(exact
            .require_failed_retirement(&owner.envelope, &owner.expected_peers)
            .is_err());
        exact.peers[0].recovery_action = "redial_affected_peer".into();
        exact.peers[0].drain_failed = false;
        assert!(exact
            .require_failed_retirement(&owner.envelope, &owner.expected_peers)
            .is_err());
    }

    #[test]
    fn failed_finalization_requires_exact_io_new_owner_and_original_cap() {
        let owner = candidate();
        let io = candy_process_control::ProcessIdentity {
            pid: 7,
            start_ticks: 8,
        };
        let mut exact = reply(&owner, "committed");
        exact.process = io;
        exact.forced_retirement = true;
        exact.old_owner_drained = false;
        exact.retained_owner_binding = None;
        exact.pending = None;
        owner
            .require_failed_retirement_receipt(&exact, io, 20_001)
            .unwrap();
        assert!(owner
            .require_failed_retirement_receipt(&exact, io, 19_999)
            .is_err());
        assert!(owner
            .require_failed_retirement_receipt(&exact, io, 50_000)
            .is_err());
        for field in 0..8 {
            let mut changed: AuthorityControlResponse =
                serde_json::from_value(serde_json::to_value(&exact).unwrap()).unwrap();
            match field {
                0 => changed.process.start_ticks += 1,
                1 => changed.current_binding.owner_epoch += 1,
                2 => changed.forced_retirement = false,
                3 => changed.old_owner_drained = true,
                4 => changed.retained_owner_binding = owner.expected_active,
                5 => changed.pending = Some(owner.envelope.clone()),
                6 => changed.actual_deadline_mono_ms = Some(50_001),
                _ => changed.active.as_mut().unwrap().transaction_id.push('f'),
            }
            assert!(owner
                .require_failed_retirement_receipt(&changed, io, 20_001)
                .is_err());
        }
    }
}
