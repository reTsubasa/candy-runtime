//! Standalone authenticated task evidence client. The association is supplied by
//! the original Runtime controller; it is not an independent master owner proof.
//! No current Prepare/terminal path consumes this API.
use super::{exchange_bytes, SharedWorker};
use anyhow::{ensure, Context, Result};
use candy_process_control::ProcessIdentity;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdwanTransportOwner {
    pub role: String,
    pub transport_id: u64,
    pub connection_id: u64,
    pub worker_id: u64,
    pub owner_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerCandidateAssociation {
    pub candidate_record_sha256: [u8; 32],
    pub owner: SdwanTransportOwner,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentity {
    pub boot_id: uuid::Uuid,
    pub instance: [u8; 32],
    pub process: ProcessIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum JoinedCompletion {
    Returned {
        exit_code: i32,
        detail: Option<String>,
    },
    Panicked,
    ResultUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainEvidence {
    pub schema_version: u8,
    pub host: HostIdentity,
    pub controller: ProcessIdentity,
    pub instance: String,
    pub domain_incarnation: [u8; 32],
    pub binding: Option<ControllerCandidateAssociation>,
    pub joined_completion: Option<JoinedCompletion>,
}

pub struct EvidenceClient {
    host: SharedWorker,
    original: DomainEvidence,
}

fn verify(
    response: &DomainEvidence,
    host: &SharedWorker,
    controller: ProcessIdentity,
    instance: &str,
) -> Result<()> {
    ensure!(
        response.schema_version == 2
            && response.host.process == host.identity
            && !response.host.boot_id.is_nil()
            && response.host.instance != [0; 32]
            && response.domain_incarnation != [0; 32]
            && response.controller == controller
            && response.instance == instance,
        "code=domain_evidence_identity_mismatch module=sdwan_host action=preserve_unknown"
    );
    if let Some(binding) = &response.binding {
        ensure!(
            binding.candidate_record_sha256 != [0; 32]
                && binding.owner.role == "Sdwan"
                && [
                    binding.owner.transport_id,
                    binding.owner.connection_id,
                    binding.owner.worker_id,
                    binding.owner.owner_epoch
                ]
                .into_iter()
                .all(|id| id != 0),
            "code=domain_evidence_binding_invalid module=sdwan_host"
        );
    }
    if let Some(JoinedCompletion::Returned { exit_code, .. }) = &response.joined_completion {
        ensure!(
            (0..=255).contains(exit_code),
            "code=domain_evidence_exit_invalid module=sdwan_host"
        );
    }
    Ok(())
}

impl EvidenceClient {
    pub fn inspect(host: SharedWorker, instance: String) -> Result<Self> {
        let bytes = exchange_bytes(
            &host,
            &instance,
            "domain_evidence",
            &[serde_json::to_string(
                &serde_json::json!({"action":"inspect","domain_incarnation":null,"binding":null}),
            )?],
            &[],
        )?;
        let original: DomainEvidence = serde_json::from_slice(&bytes).context(
            "code=domain_evidence_response_invalid module=sdwan_host action=preserve_unknown",
        )?;
        verify(
            &original,
            &host,
            candy_process_control::process_identity(std::process::id())?,
            &instance,
        )?;
        ensure!(
            original.binding.is_none(),
            "code=domain_evidence_inspect_invalid module=sdwan_host"
        );
        Ok(Self { host, original })
    }

    /// Must receive the exact checksum/owner from authenticated Core control;
    /// generating it from current Runtime state is not an original binding.
    pub fn bind(&self, binding: &ControllerCandidateAssociation) -> Result<DomainEvidence> {
        self.exchange("bind", binding)
    }
    pub fn query(&self, binding: &ControllerCandidateAssociation) -> Result<DomainEvidence> {
        self.exchange("query", binding)
    }
    fn exchange(
        &self,
        action: &str,
        binding: &ControllerCandidateAssociation,
    ) -> Result<DomainEvidence> {
        let request = serde_json::to_string(&serde_json::json!({"action":action,
            "domain_incarnation":self.original.domain_incarnation,"binding":binding}))?;
        let bytes = exchange_bytes(
            &self.host,
            &self.original.instance,
            "domain_evidence",
            &[request],
            &[],
        )?;
        let response: DomainEvidence = serde_json::from_slice(&bytes).context(
            "code=domain_evidence_response_invalid module=sdwan_host action=preserve_unknown",
        )?;
        self.verify_exact(&response, binding)?;
        Ok(response)
    }
    fn verify_exact(
        &self,
        response: &DomainEvidence,
        binding: &ControllerCandidateAssociation,
    ) -> Result<()> {
        verify(
            response,
            &self.host,
            self.original.controller,
            &self.original.instance,
        )?;
        ensure!(
            response.host == self.original.host
                && response.domain_incarnation == self.original.domain_incarnation
                && response.binding.as_ref() == Some(binding),
            "code=domain_evidence_original_mismatch module=sdwan_host action=preserve_unknown"
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "shared_domain_evidence_tests.rs"]
mod tests;
