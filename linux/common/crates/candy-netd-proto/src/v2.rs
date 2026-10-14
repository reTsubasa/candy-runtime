//! Explicit infrastructure/forwarding ABI. Version 1 retains its original lifecycle semantics.

use crate::{Ipv4Prefix, NetdProtocolError, PrepareDeclaration, MAX_NETD_FRAME_LEN, MAX_ROUTES};
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfraSpec {
    pub infra_id: [u8; 16],
    pub generation: u64,
    pub netns_device: u64,
    pub netns_inode: u64,
    pub overlay_router_ipv4: [u8; 4],
    pub mtu: u16,
}

impl InfraSpec {
    pub fn validate(&self) -> Result<(), NetdProtocolError> {
        if self.infra_id == [0; 16]
            || self.generation == 0
            || self.netns_inode == 0
            || !(576..=1400).contains(&self.mtu)
            || self.overlay_router_ipv4 == [0; 4]
            || self.overlay_router_ipv4[0] >= 224
        {
            return Err(NetdProtocolError::InvalidDeclaration);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardOwner {
    pub domain_id: [u8; 16],
    pub signed_generation: u64,
    pub worker_epoch: u64,
    pub fencing_token: u64,
    pub auth_deadline_mono_ms: u64,
    pub lease_deadline_mono_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardAuthority {
    pub transaction_id: String,
    pub authority_revision: u64,
    pub signed_control_hash: String,
    pub declaration_hash: String,
    pub snapshot_closure_hash: String,
    pub io_epoch: u64,
    pub io_pid: u32,
    pub io_start_ticks: u64,
    pub candidate_pid: u32,
    pub candidate_start_ticks: u64,
}

impl ForwardAuthority {
    pub fn validate(&self) -> Result<(), NetdProtocolError> {
        let hex = |value: &str, length: usize| {
            value.len() == length
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !hex(&self.transaction_id, 32)
            || self.authority_revision == 0
            || !hex(&self.signed_control_hash, 64)
            || !hex(&self.declaration_hash, 64)
            || !hex(&self.snapshot_closure_hash, 64)
            || self.io_epoch == 0
            || self.io_pid == 0
            || self.io_start_ticks == 0
            || self.candidate_pid == 0
            || self.candidate_start_ticks == 0
        {
            return Err(NetdProtocolError::InvalidOwner);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardAuthorityReceipt {
    pub authority: ForwardAuthority,
    pub owner_active: bool,
    pub authorization_deadline_mono_ms: u64,
    pub packet_proof_reported_mono_ms: u64,
}

impl ForwardOwner {
    pub fn validate(&self) -> Result<(), NetdProtocolError> {
        if self.domain_id == [0; 16]
            || self.signed_generation == 0
            || self.worker_epoch == 0
            || self.fencing_token == 0
            || self.auth_deadline_mono_ms == 0
            || self.lease_deadline_mono_ms == 0
            || self.lease_deadline_mono_ms > self.auth_deadline_mono_ms
        {
            return Err(NetdProtocolError::InvalidOwner);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "parameters", rename_all = "snake_case")]
pub enum Operation {
    Capabilities,
    InDomain {
        domain_id: [u8; 16],
        infra_id: [u8; 16],
        operation: Box<Operation>,
    },
    InfraEnsure(InfraSpec),
    InfraStatus,
    InfraAcquireIoFd {
        infra_id: [u8; 16],
        generation: u64,
        io_epoch: u64,
    },
    InfraReleaseIo {
        infra_id: [u8; 16],
        generation: u64,
        io_epoch: u64,
    },
    InfraRetire {
        infra_id: [u8; 16],
        generation: u64,
    },
    ForwardPrepare {
        infra_id: [u8; 16],
        infra_generation: u64,
        owner: ForwardOwner,
        declaration: PrepareDeclaration,
    },
    ForwardCommit {
        owner: ForwardOwner,
    },
    ForwardAuthorize {
        owner: ForwardOwner,
        authority: ForwardAuthority,
    },
    ForwardCommitAuthorized {
        owner: ForwardOwner,
        receipt: ForwardAuthorityReceipt,
    },
    ForwardRevoke {
        owner: ForwardOwner,
    },
    /// Temporarily quiesce packet IO while retaining the route-to-TUN path.
    /// Unlike revoke, this must not install kernel reject routes.
    ForwardGuard {
        owner: ForwardOwner,
    },
    ForwardLeaseRenew {
        owner: ForwardOwner,
    },
    ForwardFailedPrefixes {
        owner: ForwardOwner,
        failure_revision: u64,
        failed_prefixes: Vec<Ipv4Prefix>,
    },
    ForwardStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: u64,
    pub caller_instance_id: [u8; 16],
    pub caller_pid: u32,
    pub operation: Operation,
}

impl Request {
    pub fn validate(&self) -> Result<(), NetdProtocolError> {
        if self.request_id == 0 || self.caller_instance_id == [0; 16] || self.caller_pid == 0 {
            return Err(NetdProtocolError::InvalidRequest);
        }
        match &self.operation {
            Operation::InDomain {
                domain_id,
                infra_id,
                operation,
            } => {
                if *domain_id == [0; 16]
                    || *infra_id == [0; 16]
                    || matches!(operation.as_ref(), Operation::InDomain { .. })
                {
                    return Err(NetdProtocolError::InvalidRequest);
                }
                let mut scoped = self.clone();
                scoped.operation = *operation.clone();
                scoped.validate()?;
            }
            Operation::InfraEnsure(spec) => spec.validate()?,
            Operation::InfraAcquireIoFd {
                infra_id,
                generation,
                io_epoch,
            }
            | Operation::InfraReleaseIo {
                infra_id,
                generation,
                io_epoch,
            } => {
                if *infra_id == [0; 16] || *generation == 0 || *io_epoch == 0 {
                    return Err(NetdProtocolError::InvalidRequest);
                }
            }
            Operation::InfraRetire {
                infra_id,
                generation,
            } => {
                if *infra_id == [0; 16] || *generation == 0 {
                    return Err(NetdProtocolError::InvalidRequest);
                }
            }
            Operation::ForwardPrepare {
                infra_id,
                infra_generation,
                owner,
                declaration,
            } => {
                if *infra_id == [0; 16] || *infra_generation == 0 {
                    return Err(NetdProtocolError::InvalidRequest);
                }
                owner.validate()?;
                declaration.validate()?;
                for prefix in declaration
                    .routes
                    .iter()
                    .map(|r| r.prefix)
                    .chain(declaration.exclusions.iter().map(|e| e.prefix))
                {
                    crate::Ipv4Prefix::new(prefix.network, prefix.prefix_len)?;
                }
            }
            Operation::ForwardCommit { owner }
            | Operation::ForwardRevoke { owner }
            | Operation::ForwardGuard { owner }
            | Operation::ForwardLeaseRenew { owner } => owner.validate()?,
            Operation::ForwardAuthorize { owner, authority } => {
                owner.validate()?;
                authority.validate()?;
            }
            Operation::ForwardCommitAuthorized { owner, receipt } => {
                owner.validate()?;
                receipt.authority.validate()?;
                if !receipt.owner_active
                    || receipt.authorization_deadline_mono_ms != owner.auth_deadline_mono_ms
                    || receipt.packet_proof_reported_mono_ms == 0
                {
                    return Err(NetdProtocolError::InvalidOwner);
                }
            }
            Operation::ForwardFailedPrefixes {
                owner,
                failure_revision,
                failed_prefixes,
            } => {
                owner.validate()?;
                if *failure_revision == 0 || failed_prefixes.len() > MAX_ROUTES {
                    return Err(NetdProtocolError::InvalidDeclaration);
                }
                let mut unique = std::collections::HashSet::new();
                for prefix in failed_prefixes {
                    crate::Ipv4Prefix::new(prefix.network, prefix.prefix_len)?;
                    if !unique.insert(*prefix) {
                        return Err(NetdProtocolError::InvalidDeclaration);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, NetdProtocolError> {
        self.validate()?;
        encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NetdProtocolError> {
        let request: Self = decode(bytes)?;
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preparing,
    Prepared,
    Active,
    Guarded,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
pub enum Body {
    Capabilities {
        version: u8,
        independent_infrastructure: bool,
        multi_domain: bool,
    },
    InfraStatus {
        spec: Option<InfraSpec>,
        ifindex: Option<u32>,
        io_epoch: Option<u64>,
    },
    IoFd {
        spec: InfraSpec,
        ifindex: u32,
        io_epoch: u64,
    },
    ForwardStatus {
        owner: Option<ForwardOwner>,
        phase: Option<Phase>,
        candidate_owner: Option<ForwardOwner>,
        failure_revision: u64,
        failed_prefixes: Vec<Ipv4Prefix>,
        pending_failure_revision: Option<u64>,
        pending_failed_prefixes: Option<Vec<Ipv4Prefix>>,
    },
    Ack,
    Error {
        code: String,
        module: String,
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub request_id: u64,
    pub body: Body,
}

impl Response {
    pub fn encode(&self) -> Result<Vec<u8>, NetdProtocolError> {
        encode(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, NetdProtocolError> {
        decode(bytes)
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, NetdProtocolError> {
    let mut bytes = vec![VERSION];
    bytes.extend(serde_json::to_vec(value).map_err(|_| NetdProtocolError::InvalidRequest)?);
    if bytes.len() > MAX_NETD_FRAME_LEN {
        return Err(NetdProtocolError::InvalidRequest);
    }
    Ok(bytes)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, NetdProtocolError> {
    if bytes.first() != Some(&VERSION) {
        return Err(NetdProtocolError::UnsupportedVersion);
    }
    if bytes.len() > MAX_NETD_FRAME_LEN {
        return Err(NetdProtocolError::InvalidRequest);
    }
    serde_json::from_slice(&bytes[1..]).map_err(|_| NetdProtocolError::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_two_is_explicit_and_never_decodes_as_version_one() {
        let request = Request {
            request_id: 1,
            caller_instance_id: [1; 16],
            caller_pid: 1,
            operation: Operation::Capabilities,
        };
        let bytes = request.encode().unwrap();
        assert_eq!(Request::decode(&bytes).unwrap(), request);
        assert_eq!(
            crate::NetdRequest::decode(&bytes),
            Err(NetdProtocolError::UnsupportedVersion)
        );
        let mut wrong = bytes;
        wrong[0] = 1;
        assert_eq!(
            Request::decode(&wrong),
            Err(NetdProtocolError::UnsupportedVersion)
        );
    }

    #[test]
    fn lease_cannot_outlive_auth_and_epochs_are_required() {
        let mut owner = ForwardOwner {
            domain_id: [1; 16],
            signed_generation: 1,
            worker_epoch: 1,
            fencing_token: 1,
            auth_deadline_mono_ms: 20,
            lease_deadline_mono_ms: 10,
        };
        owner.validate().unwrap();
        owner.lease_deadline_mono_ms = 21;
        assert!(owner.validate().is_err());
    }

    #[test]
    fn explicit_domain_scope_round_trips_and_rejects_nested_or_empty_identity() {
        let mut request = Request {
            request_id: 1,
            caller_instance_id: [1; 16],
            caller_pid: 1,
            operation: Operation::InDomain {
                domain_id: [2; 16],
                infra_id: [3; 16],
                operation: Box::new(Operation::InfraStatus),
            },
        };
        assert_eq!(
            Request::decode(&request.encode().unwrap()).unwrap(),
            request
        );
        request.operation = Operation::InDomain {
            domain_id: [2; 16],
            infra_id: [3; 16],
            operation: Box::new(request.operation.clone()),
        };
        assert!(request.validate().is_err());
        request.operation = Operation::InDomain {
            domain_id: [0; 16],
            infra_id: [3; 16],
            operation: Box::new(Operation::InfraStatus),
        };
        assert!(request.validate().is_err());
    }
}
