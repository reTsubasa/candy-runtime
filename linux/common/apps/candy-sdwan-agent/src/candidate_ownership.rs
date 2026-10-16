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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidateOwner {
    pub envelope: AuthorityEnvelope,
    pub expected_active: Option<PacketPortBinding>,
    pub prepare_deadline_mono_ms: u64,
    pub expected_peers: Vec<PeerExpectation>,
    commit_intent: bool,
}

impl CandidateOwner {
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
        proof.require_installed(&self.envelope, &self.expected_peers)?;
        // An fsync failure may still have persisted the intent. Keep the
        // uncertainty fence until the original transaction is reconciled.
        self.commit_intent = true;
        persist(self)?;
        self.commit_request(base, proof)
    }

    pub(super) fn commit_is_uncertain(&self) -> bool {
        self.commit_intent
    }

    pub(super) fn commit_request(
        &self,
        mut base: AuthorityControlRequest,
        proof: &CandidateProof,
    ) -> Result<AuthorityControlRequest> {
        proof.require_installed(&self.envelope, &self.expected_peers)?;
        ensure!(self.commit_intent,
            "code=candidate_owner_commit_intent_missing module=sdwan_handoff action=persist_original_transaction");
        base.schema_version = 3;
        base.operation = AuthorityOperation::CommitOwner;
        base.envelope = Some(self.envelope.clone());
        base.transaction_id = self.envelope.transaction_id.clone();
        Ok(base)
    }

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
        }
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
}
