//! A separate opt-in service; version 1 rollback and orphan recovery are unchanged.

use crate::{
    NetworkBackend, NetworkError, PeerCredentials, PlatformError, SysctlChange, TunFactory,
};
use candy_netd_proto::v2::{Body, ForwardOwner, InfraSpec, Operation, Phase, Request, Response};
use candy_netd_proto::{Ipv4Prefix, PrepareDeclaration, RouteKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use thiserror::Error;

pub mod clock;
#[cfg(target_os = "linux")]
pub mod domains;

pub trait InfrastructureBackend: NetworkBackend {
    fn interface_identity(&mut self) -> Result<Option<u32>, NetworkError>;
    fn interface_ownership_marker(&mut self) -> Result<Option<String>, NetworkError>;
    fn stamp_infrastructure_ownership(&mut self, marker: &str) -> Result<(), NetworkError>;
    fn ensure_infrastructure(&mut self, spec: &InfraSpec) -> Result<u32, NetworkError>;
    fn retire_infrastructure(&mut self) -> Result<(), NetworkError>;
    fn reject_forwarding(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    /// Retain the exact kernel policy while IO quiesces the live owner.
    fn guard_forwarding(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        Ok(())
    }
    fn restore_forwarding(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    fn restore_forwarding_with_failures(
        &mut self,
        declaration: &PrepareDeclaration,
        failed: &[Ipv4Prefix],
    ) -> Result<(), NetworkError>;
    fn update_failed_forward_prefixes(
        &mut self,
        declaration: &PrepareDeclaration,
        previous: &[Ipv4Prefix],
        failed: &[Ipv4Prefix],
    ) -> Result<(), NetworkError>;
    fn validate_forwarding_replacement(
        &mut self,
        previous: &PrepareDeclaration,
        candidate: &PrepareDeclaration,
    ) -> Result<(), NetworkError>;
    fn retire_forwarding(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.remove_policy_rule(declaration)?;
        self.remove_routes(declaration)
    }
    fn remove_stale_forwarding(
        &mut self,
        _old: &PrepareDeclaration,
        _retained: &PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ForwardRecord {
    owner: ForwardOwner,
    declaration: PrepareDeclaration,
    phase: Phase,
    #[serde(default)]
    failure_revision: u64,
    #[serde(default)]
    failed_prefixes: Vec<Ipv4Prefix>,
    #[serde(default)]
    pending_failed_prefixes: Option<Vec<Ipv4Prefix>>,
    #[serde(default)]
    pending_failure_revision: Option<u64>,
    #[serde(default)]
    authority: Option<candy_netd_proto::v2::ForwardAuthority>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct IoOwner {
    instance_id: [u8; 16],
    pid: u32,
    io_epoch: u64,
    boot_id: String,
    start_ticks: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    #[serde(default)]
    boot_id: String,
    spec: Option<InfraSpec>,
    ifindex: Option<u32>,
    #[serde(default)]
    ownership_marker: Option<String>,
    #[serde(default)]
    creation_pending: bool,
    administrator: Option<[u8; 16]>,
    io_owner: Option<IoOwner>,
    last_io_epoch: u64,
    forward: Option<ForwardRecord>,
    #[serde(default)]
    candidate: Option<ForwardRecord>,
    #[serde(default)]
    last_fencing_token: u64,
    sysctls: Vec<SysctlChange>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u8,
    sha256: String,
    state: State,
}

pub struct InfrastructureJournal {
    path: PathBuf,
}

impl InfrastructureJournal {
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("journal parent missing"))?;
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(io::Error::other("unsafe infrastructure journal parent"));
        }
        Ok(Self { path })
    }

    fn load(&self) -> io::Result<State> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(State::default()),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::other("unsafe journal file"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(65_537)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 65_536 {
            return Err(io::Error::other("oversized journal"));
        }
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        if envelope.schema_version != 2 || state_hash(&envelope.state)? != envelope.sha256 {
            return Err(io::Error::other("journal version/checksum mismatch"));
        }
        if let Some(spec) = &envelope.state.spec {
            spec.validate()
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        for forward in envelope
            .state
            .forward
            .iter()
            .chain(envelope.state.candidate.iter())
        {
            forward
                .owner
                .validate()
                .map_err(|error| io::Error::other(error.to_string()))?;
            forward
                .declaration
                .validate()
                .map_err(|error| io::Error::other(error.to_string()))?;
            validate_failed_prefixes(&forward.declaration, &forward.failed_prefixes)
                .map_err(|error| io::Error::other(error.to_string()))?;
            if let Some(pending) = &forward.pending_failed_prefixes {
                validate_failed_prefixes(&forward.declaration, pending)
                    .map_err(|error| io::Error::other(error.to_string()))?;
            }
            if forward.pending_failed_prefixes.is_some()
                != forward.pending_failure_revision.is_some()
                || forward
                    .pending_failure_revision
                    .is_some_and(|revision| revision <= forward.failure_revision)
            {
                return Err(io::Error::other("invalid failure revision intent"));
            }
        }
        Ok(envelope.state)
    }

    fn store(&self, state: &State) -> io::Result<()> {
        let temporary = self
            .path
            .with_extension(format!("v2-tmp-{}", std::process::id()));
        let envelope = Envelope {
            schema_version: 2,
            sha256: state_hash(state)?,
            state: state.clone(),
        };
        let bytes = serde_json::to_vec(&envelope)?;
        if bytes.len() > 65_536 {
            return Err(io::Error::other("oversized journal"));
        }
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            fs::File::open(self.path.parent().unwrap())?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn state_hash(state: &State) -> io::Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(state)?)))
}

#[derive(Debug, Error)]
pub enum InfrastructureError {
    #[error("code={code} module=netd_v2 reason={reason}")]
    Rejected {
        code: &'static str,
        reason: &'static str,
    },
    #[error("infrastructure journal failed: {0}")]
    Journal(#[from] io::Error),
    #[error("infrastructure backend failed: {0}")]
    Backend(#[from] NetworkError),
    #[error("infrastructure descriptor failed: {0}")]
    Platform(#[from] PlatformError),
    #[error("infrastructure IPC failed: {0}")]
    Ipc(#[from] candy_netd_client::IpcError),
    #[error("code=forward_transition_failed module=netd_v2 stage={stage} reason={cause}")]
    Transition {
        stage: &'static str,
        cause: NetworkError,
    },
    #[error("code=forward_repair_pending module=netd_v2 commit_reason={commit} recovery_reason={recovery}")]
    RepairPending { commit: String, recovery: String },
    #[error("code=domain_resource_budget_exceeded module=netd_domains resource={resource} required={required} allowed={allowed}")]
    ResourceBudget {
        resource: &'static str,
        required: u64,
        allowed: u64,
    },
}

fn reject(code: &'static str, reason: &'static str) -> InfrastructureError {
    InfrastructureError::Rejected { code, reason }
}

pub struct InfrastructureService<T, B> {
    allowed_uid: u32,
    allowed_gid: u32,
    factory: T,
    backend: B,
    journal: InfrastructureJournal,
    state: State,
    lifecycle_fd: Option<OwnedFd>,
    restart_recovery_pending: bool,
}

impl<T: TunFactory, B: InfrastructureBackend> InfrastructureService<T, B> {
    pub fn new(
        allowed_uid: u32,
        allowed_gid: u32,
        factory: T,
        backend: B,
        journal: InfrastructureJournal,
    ) -> Result<Self, InfrastructureError> {
        let state = journal.load()?;
        Ok(Self {
            allowed_uid,
            allowed_gid,
            factory,
            backend,
            journal,
            state,
            lifecycle_fd: None,
            restart_recovery_pending: true,
        })
    }

    fn persist(&mut self, state: State) -> Result<(), InfrastructureError> {
        self.journal.store(&state)?;
        self.state = state;
        Ok(())
    }

    fn administrator(&self, request: &Request) -> Result<(), InfrastructureError> {
        if self.state.administrator != Some(request.caller_instance_id) {
            return Err(reject(
                "infra_owner_conflict",
                "only the retained infrastructure administrator may mutate forwarding",
            ));
        }
        Ok(())
    }

    fn identity(
        &mut self,
        infra_id: [u8; 16],
        generation: u64,
    ) -> Result<InfraSpec, InfrastructureError> {
        let spec = self
            .state
            .spec
            .clone()
            .ok_or_else(|| reject("infra_missing", "infrastructure has not been ensured"))?;
        if spec.infra_id != infra_id || spec.generation != generation {
            return Err(reject(
                "infra_generation_conflict",
                "infrastructure identity does not match",
            ));
        }
        if self.backend.interface_identity()? != self.state.ifindex {
            return Err(reject(
                "infra_identity_conflict",
                "kernel interface identity changed; explicit recovery is required",
            ));
        }
        self.verify_device_ownership()?;
        Ok(spec)
    }

    fn verify_device_ownership(&mut self) -> Result<(), InfrastructureError> {
        if self.state.ownership_marker.is_none()
            || self.backend.interface_ownership_marker()? != self.state.ownership_marker
        {
            return Err(reject(
                "infra_ownership_conflict",
                "kernel TUN marker does not match the durable creation intent",
            ));
        }
        Ok(())
    }

    fn complete_creation(&mut self) -> Result<(), InfrastructureError> {
        if !self.state.creation_pending {
            return Ok(());
        }
        let spec = self.state.spec.clone().ok_or_else(|| {
            reject(
                "infra_intent_invalid",
                "creation intent has no infrastructure spec",
            )
        })?;
        let marker = self.state.ownership_marker.clone().ok_or_else(|| {
            reject(
                "infra_intent_invalid",
                "creation intent has no ownership marker",
            )
        })?;
        #[cfg(target_os = "linux")]
        {
            let namespace = fs::metadata("/proc/thread-self/ns/net")?;
            if spec.netns_device != namespace.dev() || spec.netns_inode != namespace.ino() {
                return Err(reject(
                    "infra_namespace_conflict",
                    "creation recovery requires the original network namespace",
                ));
            }
        }
        if self.backend.interface_identity()?.is_none() {
            let descriptor = self.factory.create_exclusive()?;
            // Until marker publication, an exclusive nonpersistent device dies with this fd.
            self.lifecycle_fd = Some(descriptor);
            if let Err(error) = self.backend.stamp_infrastructure_ownership(&marker) {
                self.lifecycle_fd = None;
                return Err(error.into());
            }
        } else {
            self.verify_device_ownership()?;
            if self.lifecycle_fd.is_none() {
                self.lifecycle_fd = Some(self.factory.create_persistent()?);
            }
        }
        self.verify_device_ownership()?;
        self.factory
            .enable_persistence(self.lifecycle_fd.as_ref().unwrap())?;
        let ifindex = self.backend.ensure_infrastructure(&spec)?;
        let mut next = self.state.clone();
        next.ifindex = Some(ifindex);
        next.creation_pending = false;
        next.boot_id = current_boot_id()?;
        self.persist(next)?;
        crate::eprintln!("level=info code=infra_creation_completed module=netd_v2 infra_generation={} ifindex={ifindex}", spec.generation);
        Ok(())
    }

    pub fn serve_once(&mut self, stream: &UnixStream, now: u64) -> Result<(), InfrastructureError> {
        let peer = crate::peer_credentials(stream)?;
        let request = candy_netd_client::v2::recv_request(stream)?;
        let request_id = request.request_id;
        let (body, descriptor) = match self.process(request, peer, now) {
            Ok(result) => result,
            Err(error) => {
                let code = match &error {
                    InfrastructureError::Rejected { code, .. } => *code,
                    InfrastructureError::Transition { .. } => "forward_transition_failed",
                    InfrastructureError::RepairPending { .. } => "forward_repair_pending",
                    _ => "infra_system_failure",
                };
                let reason = error.to_string();
                crate::eprintln!("level=warn code={code} module=netd_v2 reason={reason}");
                (
                    Body::Error {
                        code: code.into(),
                        module: "netd_v2".into(),
                        reason,
                    },
                    None,
                )
            }
        };
        candy_netd_client::v2::send_response(
            stream,
            &Response { request_id, body },
            descriptor.as_ref(),
        )?;
        Ok(())
    }

    pub fn process(
        &mut self,
        mut request: Request,
        peer: PeerCredentials,
        now: u64,
    ) -> Result<(Body, Option<OwnedFd>), InfrastructureError> {
        request
            .validate()
            .map_err(|_| reject("invalid_request", "invalid v2 request"))?;
        if peer.uid != self.allowed_uid
            || peer.gid != self.allowed_gid
            || peer.pid != request.caller_pid
        {
            return Err(reject(
                "unauthorized_peer",
                "socket credentials do not match request",
            ));
        }
        // A readiness probe must not execute expiry recovery or mutate durable state.
        if request.operation == Operation::Capabilities {
            return Ok((
                Body::Capabilities {
                    version: 2,
                    independent_infrastructure: true,
                    multi_domain: false,
                },
                None,
            ));
        }
        self.recover_expired(now)?;
        let authenticated_commit =
            if let Operation::ForwardCommitAuthorized { owner, receipt } = &request.operation {
                self.administrator(&request)?;
                let current = self
                    .state
                    .candidate
                    .as_ref()
                    .filter(|record| record.owner == *owner)
                    .or_else(|| {
                        self.state
                            .forward
                            .as_ref()
                            .filter(|record| record.owner == *owner)
                    })
                    .ok_or_else(|| {
                        reject(
                            "forward_authority_missing",
                            "authorized commit has no exact prepared owner",
                        )
                    })?;
                let io = self.state.io_owner.as_ref().ok_or_else(|| {
                    reject(
                        "io_owner_missing",
                        "authorized commit requires actual IO holder",
                    )
                })?;
                if current.authority.as_ref() != Some(&receipt.authority)
                    || receipt.authority.io_epoch != io.io_epoch
                    || receipt.authority.io_pid != io.pid
                    || Some(receipt.authority.io_start_ticks) != io.start_ticks
                    || !io_owner_alive(io)
                    || !receipt.owner_active
                    || receipt.authorization_deadline_mono_ms != owner.auth_deadline_mono_ms
                    || !clock::proof_is_fresh(now, receipt.packet_proof_reported_mono_ms)
                    || !business_process_epoch_alive(
                        receipt.authority.candidate_pid,
                        receipt.authority.candidate_start_ticks,
                    )?
                {
                    return Err(reject(
                        "forward_authority_receipt_mismatch",
                        "actual IO/candidate/transaction/authority/cap/fresh packet proof differs",
                    ));
                }
                let owner = owner.clone();
                request.operation = Operation::ForwardCommit { owner };
                true
            } else {
                false
            };
        if self
            .state
            .forward
            .as_ref()
            .is_some_and(|forward| forward.pending_failed_prefixes.is_some())
            && matches!(
                request.operation,
                Operation::ForwardPrepare { .. } | Operation::ForwardCommit { .. }
            )
        {
            return Err(reject(
                "forward_prefix_repair_pending",
                "retry the pending scoped route update before replacing forwarding",
            ));
        }
        let mut next = self.state.clone();
        match &request.operation {
            Operation::InDomain { .. } => {
                return Err(reject(
                    "domain_router_required",
                    "scoped requests require configured namespace domain routing",
                ));
            }
            Operation::Capabilities => unreachable!("capabilities returned before recovery"),
            Operation::InfraStatus => {
                return Ok((
                    Body::InfraStatus {
                        spec: next.spec,
                        ifindex: next.ifindex,
                        io_epoch: next.io_owner.as_ref().map(|owner| owner.io_epoch),
                    },
                    None,
                ))
            }
            Operation::InfraEnsure(spec) => {
                #[cfg(target_os = "linux")]
                {
                    let namespace = fs::metadata("/proc/thread-self/ns/net")?;
                    if spec.netns_device != namespace.dev() || spec.netns_inode != namespace.ino() {
                        return Err(reject(
                            "infra_namespace_conflict",
                            "request namespace differs from the netd network namespace",
                        ));
                    }
                }
                if let Some(existing) = &next.spec {
                    self.administrator(&request)?;
                    if existing != spec {
                        return Err(reject("infra_generation_conflict", "immutable infrastructure requires explicit retirement before replacement"));
                    }
                    if self.backend.interface_identity()?.is_none() {
                        if next.io_owner.as_ref().is_some_and(io_owner_alive) {
                            return Err(reject(
                                "io_owner_alive",
                                "missing interface repair requires the old I/O owner to exit",
                            ));
                        }
                        if let Some(forward) = next.forward.as_mut() {
                            self.backend.reject_forwarding(&forward.declaration)?;
                            self.backend.remove_firewall(&forward.declaration)?;
                            forward.phase = Phase::Revoked;
                        }
                        next.candidate = None;
                        next.creation_pending = true;
                        next.ownership_marker = Some(new_ownership_marker()?);
                        next.ifindex = None;
                        next.io_owner = None;
                        next.boot_id = current_boot_id()?;
                        self.persist(next)?;
                        self.complete_creation()?;
                        next = self.state.clone();
                        let ifindex = next.ifindex.unwrap();
                        crate::eprintln!("level=warn code=infra_device_recovered module=netd_v2 reason=owned_device_missing infra_generation={} ifindex={ifindex} forwarding=revoked", spec.generation);
                        return Ok((
                            Body::InfraStatus {
                                spec: next.spec,
                                ifindex: next.ifindex,
                                io_epoch: None,
                            },
                            None,
                        ));
                    }
                    self.identity(spec.infra_id, spec.generation)?;
                    return Ok((
                        Body::InfraStatus {
                            spec: next.spec,
                            ifindex: next.ifindex,
                            io_epoch: next.io_owner.as_ref().map(|owner| owner.io_epoch),
                        },
                        None,
                    ));
                }
                if self.backend.interface_identity()?.is_some() {
                    return Err(reject(
                        "infra_unowned_interface",
                        "refusing an existing interface without owned journal",
                    ));
                }
                next.spec = Some(spec.clone());
                next.ownership_marker = Some(new_ownership_marker()?);
                next.creation_pending = true;
                next.administrator = Some(request.caller_instance_id);
                next.boot_id = current_boot_id()?;
                // No persistent device exists before its creation intent is durable.
                self.persist(next)?;
                self.complete_creation()?;
                return Ok((
                    Body::InfraStatus {
                        spec: self.state.spec.clone(),
                        ifindex: self.state.ifindex,
                        io_epoch: None,
                    },
                    None,
                ));
            }
            Operation::InfraAcquireIoFd {
                infra_id,
                generation,
                io_epoch,
            } => {
                let spec = self.identity(*infra_id, *generation)?;
                if next.io_owner.as_ref().is_some_and(io_owner_alive) {
                    return Err(reject("io_owner_alive", "an existing I/O owner may still hold the queue; no second descriptor is issued"));
                }
                if *io_epoch <= next.last_io_epoch {
                    return Err(reject("stale_io_epoch", "I/O epoch must advance"));
                }
                if self.lifecycle_fd.is_none() {
                    self.lifecycle_fd = Some(self.factory.create_persistent()?);
                }
                let fd = nix::fcntl::fcntl(
                    self.lifecycle_fd.as_ref().unwrap().as_raw_fd(),
                    nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(0),
                )
                .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
                // fcntl returned a fresh descriptor owned by this process.
                let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
                next.io_owner = Some(IoOwner {
                    instance_id: request.caller_instance_id,
                    pid: request.caller_pid,
                    io_epoch: *io_epoch,
                    boot_id: current_boot_id()?,
                    start_ticks: process_start_ticks(request.caller_pid)?,
                });
                next.last_io_epoch = *io_epoch;
                self.persist(next)?;
                return Ok((
                    Body::IoFd {
                        spec,
                        ifindex: self.state.ifindex.unwrap(),
                        io_epoch: *io_epoch,
                    },
                    Some(descriptor),
                ));
            }
            Operation::InfraReleaseIo {
                infra_id,
                generation,
                io_epoch,
            } => {
                self.identity(*infra_id, *generation)?;
                self.administrator(&request)?;
                if next
                    .io_owner
                    .as_ref()
                    .is_some_and(|owner| owner.io_epoch == *io_epoch && !io_owner_alive(owner))
                {
                    next.io_owner = None;
                } else {
                    return Err(reject("io_owner_alive", "release requires proof the I/O process exited; caller cannot revoke its duplicate fd"));
                }
            }
            Operation::InfraRetire {
                infra_id,
                generation,
            } => {
                self.administrator(&request)?;
                self.identity(*infra_id, *generation)?;
                if next.io_owner.as_ref().is_some_and(io_owner_alive) {
                    return Err(reject(
                        "io_owner_alive",
                        "stop the I/O owner before explicit infrastructure retirement",
                    ));
                }
                if let Some(forward) = &next.forward {
                    if forward.phase != Phase::Revoked {
                        return Err(reject(
                            "forwarding_active",
                            "revoke forwarding before infrastructure retirement",
                        ));
                    }
                    self.backend.retire_forwarding(&forward.declaration)?;
                    self.backend
                        .restore_sysctls(&forward.declaration, &next.sysctls)?;
                }
                self.backend.retire_infrastructure()?;
                self.lifecycle_fd = None;
                self.persist(State::default())?;
                return Ok((Body::Ack, None));
            }
            Operation::ForwardPrepare {
                infra_id,
                infra_generation,
                owner,
                declaration,
            } => {
                self.administrator(&request)?;
                let spec = self.identity(*infra_id, *infra_generation)?;
                ensure_live(owner, now)?;
                if declaration.overlay_router_ipv4 != spec.overlay_router_ipv4
                    || declaration.effective_mtu != spec.mtu
                {
                    return Err(reject(
                        "infra_config_conflict",
                        "forwarding cannot change interface address or MTU",
                    ));
                }
                if let Some(candidate) = &next.candidate {
                    if candidate.owner == *owner && candidate.declaration == *declaration {
                        return Ok((Body::Ack, None));
                    }
                    return Err(reject(
                        "forward_candidate_pending",
                        "commit or revoke the retained candidate before preparing another",
                    ));
                }
                if let Some(previous) = &next.forward {
                    if previous.owner == *owner
                        && previous.declaration == *declaration
                        && previous.phase == Phase::Prepared
                    {
                        return Ok((Body::Ack, None));
                    }
                    if previous.owner.domain_id != owner.domain_id {
                        return Err(reject(
                            "unsupported_multi_domain",
                            "this backend has one routing domain; another domain cannot preempt it",
                        ));
                    }
                    let retry_preparation =
                        previous.owner == *owner && previous.phase == Phase::Preparing;
                    if owner.signed_generation < previous.owner.signed_generation
                        || (owner.signed_generation == previous.owner.signed_generation
                            && declaration != &previous.declaration)
                        || owner.worker_epoch < previous.owner.worker_epoch
                        || (owner.fencing_token
                            <= previous.owner.fencing_token.max(next.last_fencing_token)
                            && !retry_preparation)
                    {
                        return Err(reject(
                            "stale_forward_owner",
                            "generation or fencing token does not advance",
                        ));
                    }
                    if !matches!(
                        previous.phase,
                        Phase::Active | Phase::Guarded | Phase::Revoked
                    ) && !retry_preparation
                    {
                        return Err(reject(
                            "forward_preparation_pending",
                            "finish or revoke initial preparation before replacing it",
                        ));
                    }
                    if previous.declaration.table_id != declaration.table_id
                        || previous.declaration.firewall.require_ipv4_forwarding
                            != declaration.firewall.require_ipv4_forwarding
                        || previous.declaration.firewall.manage_rp_filter
                            != declaration.firewall.manage_rp_filter
                    {
                        return Err(reject("infra_policy_attribute_conflict", "routing table and shared sysctl requirements belong to retained infrastructure"));
                    }
                    if !retry_preparation {
                        self.backend
                            .validate_forwarding_replacement(&previous.declaration, declaration)?;
                        // Candidate preparation never mutates an existing active kernel policy.
                        next.candidate = Some(ForwardRecord {
                            owner: owner.clone(),
                            declaration: declaration.clone(),
                            phase: Phase::Prepared,
                            failure_revision: 0,
                            failed_prefixes: Vec::new(),
                            pending_failed_prefixes: None,
                            pending_failure_revision: None,
                            authority: None,
                        });
                        next.last_fencing_token = owner.fencing_token;
                        self.persist(next)?;
                        return Ok((Body::Ack, None));
                    }
                } else {
                    next.sysctls = self
                        .backend
                        .preflight(declaration)
                        .map_err(|_| NetworkError::BackendStage(crate::BackendStage::Preflight))?;
                }
                // Persist intent before privileged mutations. Recovery fail-closes the exact declaration.
                next.forward = Some(ForwardRecord {
                    owner: owner.clone(),
                    declaration: declaration.clone(),
                    phase: Phase::Preparing,
                    failure_revision: 0,
                    failed_prefixes: Vec::new(),
                    pending_failed_prefixes: None,
                    pending_failure_revision: None,
                    authority: None,
                });
                next.last_fencing_token = owner.fencing_token;
                self.persist(next.clone())?;
                self.backend
                    .prepare_sysctls(declaration, &next.sysctls)
                    .map_err(|_| NetworkError::BackendStage(crate::BackendStage::SysctlPrepare))?;
                self.backend
                    .reject_forwarding(declaration)
                    .map_err(|_| NetworkError::BackendStage(crate::BackendStage::RoutePrepare))?;
                // A lost preparation reply may leave the owned firewall table installed.
                self.backend.remove_firewall(declaration)?;
                self.backend.prepare_firewall(declaration).map_err(|_| {
                    NetworkError::BackendStage(crate::BackendStage::FirewallPrepare)
                })?;
                next.forward.as_mut().unwrap().phase = Phase::Prepared;
            }
            Operation::ForwardAuthorize { owner, authority } => {
                self.administrator(&request)?;
                ensure_live(owner, now)?;
                let io = next.io_owner.as_ref().ok_or_else(|| {
                    reject("io_owner_missing", "authority requires actual IO holder")
                })?;
                if authority.io_pid != io.pid
                    || authority.io_epoch != io.io_epoch
                    || Some(authority.io_start_ticks) != io.start_ticks
                    || !io_owner_alive(io)
                {
                    return Err(reject(
                        "forward_authority_io_mismatch",
                        "authority does not belong to actual IO holder",
                    ));
                }
                let current = if next
                    .candidate
                    .as_ref()
                    .is_some_and(|record| record.owner == *owner)
                {
                    next.candidate.as_mut().unwrap()
                } else {
                    same_owner(next.forward.as_mut(), owner)?
                };
                let hash = format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(&current.declaration).map_err(io::Error::other)?
                    )
                );
                if current.phase != Phase::Prepared
                    || authority.declaration_hash != hash
                    || current
                        .authority
                        .as_ref()
                        .is_some_and(|old| old != authority)
                {
                    return Err(reject(
                        "forward_authority_conflict",
                        "authority only binds an exact prepared declaration once",
                    ));
                }
                current.authority = Some(authority.clone());
            }
            Operation::ForwardCommitAuthorized { .. } => {
                unreachable!("normalized authenticated commit")
            }
            Operation::ForwardCommit { owner } => {
                self.administrator(&request)?;
                ensure_live(owner, now)?;
                let spec = next
                    .spec
                    .as_ref()
                    .ok_or_else(|| reject("infra_missing", "infrastructure unavailable"))?;
                self.identity(spec.infra_id, spec.generation)?;
                let record = next
                    .candidate
                    .as_ref()
                    .filter(|record| record.owner == *owner)
                    .or_else(|| {
                        next.forward
                            .as_ref()
                            .filter(|record| record.owner == *owner)
                    });
                if record.is_some_and(|record| record.authority.is_some()) && !authenticated_commit
                {
                    return Err(reject(
                        "forward_authority_receipt_required",
                        "signed authority candidate requires exact applied IO and fresh Core proof",
                    ));
                }
                if next
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.owner == *owner)
                {
                    let mut candidate = next.candidate.clone().unwrap();
                    let previous = next.forward.clone().ok_or_else(|| {
                        reject("forward_missing", "candidate has no retained policy")
                    })?;
                    candidate.phase = Phase::Preparing;
                    next.candidate = Some(candidate.clone());
                    self.backend.validate_forwarding_replacement(
                        &previous.declaration,
                        &candidate.declaration,
                    )?;
                    // Persist commit intent so a crash repairs the previous policy, never TUN.
                    self.persist(next.clone())?;
                    let result = self.install_replacement(&previous, &candidate, &next.sysctls);
                    if let Err(error) = result {
                        if let Err(recovery) = self.rollback_replacement(&previous, &candidate, now)
                        {
                            return Err(InfrastructureError::RepairPending {
                                commit: error.to_string(),
                                recovery: recovery.to_string(),
                            });
                        }
                        crate::eprintln!("level=warn code=forward_commit_rolled_back module=netd_v2 signed_generation={} worker_epoch={} fencing_token={} cause={error}", owner.signed_generation, owner.worker_epoch, owner.fencing_token);
                        return Err(error);
                    }
                    candidate.phase = Phase::Active;
                    next.forward = Some(candidate.clone());
                    next.candidate = None;
                    if let Err(error) = self.persist(next) {
                        if let Err(recovery) = self.rollback_replacement(&previous, &candidate, now)
                        {
                            return Err(InfrastructureError::RepairPending {
                                commit: error.to_string(),
                                recovery: recovery.to_string(),
                            });
                        }
                        return Err(error);
                    }
                    return Ok((Body::Ack, None));
                }
                let current = same_owner(next.forward.as_mut(), owner)?;
                if current.phase == Phase::Active {
                    return Ok((Body::Ack, None));
                }
                if current.phase != Phase::Prepared {
                    return Err(reject(
                        "invalid_forward_phase",
                        "only prepared forwarding may commit",
                    ));
                }
                // Receiver epoch/snapshot commit is coordinated by Agent before enabling steering.
                if let Err(error) = self.backend.restore_forwarding_with_failures(
                    &current.declaration,
                    &current.failed_prefixes,
                ) {
                    self.backend.reject_forwarding(&current.declaration)?;
                    return Err(error.into());
                }
                current.phase = Phase::Active;
            }
            Operation::ForwardGuard { owner } => {
                self.administrator(&request)?;
                ensure_live(owner, now)?;
                let declaration = {
                    let current = same_owner(next.forward.as_mut(), owner)?;
                    if current.phase == Phase::Guarded {
                        return Ok((Body::Ack, None));
                    }
                    if current.phase != Phase::Active {
                        return Err(reject(
                            "invalid_forward_phase",
                            "only active forwarding may be guarded",
                        ));
                    }
                    current.declaration.clone()
                };
                // Persist the guarded phase before the backend call. A crash must
                // not recover this transient handoff as an ordinary active owner.
                next.forward.as_mut().unwrap().phase = Phase::Guarded;
                self.persist(next.clone())?;
                self.backend.guard_forwarding(&declaration)?;
                return Ok((Body::Ack, None));
            }
            Operation::ForwardRevoke { owner } => {
                self.administrator(&request)?;
                if let Some(candidate) = &next.candidate {
                    if candidate.owner == *owner {
                        if candidate.phase == Phase::Preparing {
                            let previous = next.forward.clone().unwrap();
                            self.rollback_replacement(&previous, candidate, now)?;
                        } else {
                            next.candidate = None;
                            self.persist(next)?;
                        }
                        return Ok((Body::Ack, None));
                    }
                }
                let current = same_owner(next.forward.as_mut(), owner)?;
                self.backend.reject_forwarding(&current.declaration)?;
                self.backend.remove_firewall(&current.declaration)?;
                current.phase = Phase::Revoked;
                current.pending_failed_prefixes = None;
                current.pending_failure_revision = None;
                next.candidate = None;
            }
            Operation::ForwardLeaseRenew { owner } => {
                self.administrator(&request)?;
                ensure_live(owner, now)?;
                let current = next
                    .forward
                    .as_mut()
                    .ok_or_else(|| reject("forward_missing", "no forwarding owner"))?;
                if current.owner.domain_id != owner.domain_id
                    || current.owner.signed_generation != owner.signed_generation
                    || current.owner.worker_epoch != owner.worker_epoch
                    || current.owner.fencing_token != owner.fencing_token
                    || current.owner.auth_deadline_mono_ms != owner.auth_deadline_mono_ms
                    || owner.lease_deadline_mono_ms > current.owner.auth_deadline_mono_ms
                    || owner.lease_deadline_mono_ms < current.owner.lease_deadline_mono_ms
                    || current.phase == Phase::Revoked
                {
                    return Err(reject(
                        "stale_forward_owner",
                        "renewal must retain the unrevoked owner's authorization cap and advance its lease within that cap",
                    ));
                }
                current.owner = owner.clone();
            }
            Operation::ForwardFailedPrefixes {
                owner,
                failure_revision,
                failed_prefixes,
            } => {
                self.administrator(&request)?;
                ensure_live(owner, now)?;
                let spec = next
                    .spec
                    .clone()
                    .ok_or_else(|| reject("infra_missing", "infrastructure unavailable"))?;
                self.identity(spec.infra_id, spec.generation)?;
                let is_candidate = next
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.owner == *owner);
                let current = same_owner(
                    if is_candidate {
                        next.candidate.as_mut()
                    } else {
                        next.forward.as_mut()
                    },
                    owner,
                )?;
                validate_failed_prefixes(&current.declaration, failed_prefixes)?;
                let mut target = failed_prefixes.clone();
                target.sort_unstable();
                let latest_revision = current
                    .pending_failure_revision
                    .unwrap_or(current.failure_revision);
                let latest_prefixes = current
                    .pending_failed_prefixes
                    .as_ref()
                    .unwrap_or(&current.failed_prefixes);
                if *failure_revision < latest_revision
                    || (*failure_revision == latest_revision && target != *latest_prefixes)
                {
                    return Err(reject(
                        "stale_failure_revision",
                        "failure snapshot must advance revision or repeat its exact contents",
                    ));
                }
                if current.pending_failed_prefixes.is_some() {
                    return Err(reject(
                        "forward_prefix_repair_pending",
                        "retained failure snapshot must finish before another snapshot",
                    ));
                }
                if *failure_revision == latest_revision {
                    return Ok((Body::Ack, None));
                }
                if current.phase == Phase::Prepared {
                    current.failure_revision = *failure_revision;
                    current.failed_prefixes = target;
                    self.persist(next)?;
                    return Ok((Body::Ack, None));
                }
                if current.phase != Phase::Active {
                    return Err(reject(
                        "forward_not_active",
                        "failed-prefix update requires active or prepared forwarding",
                    ));
                }
                if current.failed_prefixes == target {
                    current.failure_revision = *failure_revision;
                    self.persist(next)?;
                    return Ok((Body::Ack, None));
                }
                let previous = current.failed_prefixes.clone();
                let declaration = current.declaration.clone();
                current.pending_failed_prefixes = Some(target.clone());
                current.pending_failure_revision = Some(*failure_revision);
                self.persist(next.clone())?;
                self.backend
                    .update_failed_forward_prefixes(&declaration, &previous, &target)
                    .map_err(|cause| InfrastructureError::Transition {
                        stage: "failed_prefix_routes",
                        cause,
                    })?;
                let current = next.forward.as_mut().unwrap();
                current.failed_prefixes = target;
                current.failure_revision = *failure_revision;
                current.pending_failed_prefixes = None;
                current.pending_failure_revision = None;
                self.persist(next)?;
                return Ok((Body::Ack, None));
            }
            Operation::ForwardStatus => {
                return Ok((
                    Body::ForwardStatus {
                        owner: next.forward.as_ref().map(|forward| forward.owner.clone()),
                        phase: next.forward.as_ref().map(|forward| forward.phase),
                        candidate_owner: next
                            .candidate
                            .as_ref()
                            .map(|candidate| candidate.owner.clone()),
                        failure_revision: next
                            .forward
                            .as_ref()
                            .map(|forward| forward.failure_revision)
                            .unwrap_or_default(),
                        failed_prefixes: next
                            .forward
                            .as_ref()
                            .map(|forward| forward.failed_prefixes.clone())
                            .unwrap_or_default(),
                        pending_failure_revision: next
                            .forward
                            .as_ref()
                            .and_then(|forward| forward.pending_failure_revision),
                        pending_failed_prefixes: next
                            .forward
                            .as_ref()
                            .and_then(|forward| forward.pending_failed_prefixes.clone()),
                    },
                    None,
                ))
            }
        }
        if let Err(error) = self.persist(next) {
            if let Some(forward) = &self.state.forward {
                if forward.phase == Phase::Guarded {
                    let _ = self.backend.guard_forwarding(&forward.declaration);
                } else {
                    let _ = self.backend.reject_forwarding(&forward.declaration);
                }
            }
            return Err(error);
        }
        Ok((Body::Ack, None))
    }

    pub fn recover_expired(&mut self, now: u64) -> Result<bool, InfrastructureError> {
        self.complete_creation()?;
        let mut candidate_recovered = false;
        if let Some(candidate) = self.state.candidate.clone() {
            if candidate.phase == Phase::Preparing {
                let previous = self.state.forward.clone().ok_or_else(|| {
                    reject("forward_missing", "commit recovery has no previous policy")
                })?;
                self.rollback_replacement(&previous, &candidate, now)?;
                candidate_recovered = true;
            } else if self.restart_recovery_pending || ensure_live(&candidate.owner, now).is_err() {
                let mut next = self.state.clone();
                next.candidate = None;
                self.persist(next)?;
                candidate_recovered = true;
            }
        }
        if let Some(forward) = self.state.forward.clone() {
            if forward.phase == Phase::Active
                && ensure_live(&forward.owner, now).is_ok()
                && self.state.boot_id == current_boot_id()?
            {
                if let Some(target) = forward.pending_failed_prefixes {
                    let spec = self.state.spec.clone().unwrap();
                    self.identity(spec.infra_id, spec.generation)?;
                    if let Err(error) = self.backend.update_failed_forward_prefixes(
                        &forward.declaration,
                        &forward.failed_prefixes,
                        &target,
                    ) {
                        crate::eprintln!("level=warn code=forward_prefix_repair_pending module=netd_v2 signed_generation={} worker_epoch={} fencing_token={} reason={error}", forward.owner.signed_generation, forward.owner.worker_epoch, forward.owner.fencing_token);
                    } else {
                        let mut next = self.state.clone();
                        let retained = next.forward.as_mut().unwrap();
                        retained.failed_prefixes = target;
                        retained.failure_revision = retained.pending_failure_revision.unwrap();
                        retained.pending_failed_prefixes = None;
                        retained.pending_failure_revision = None;
                        self.persist(next)?;
                        candidate_recovered = true;
                    }
                }
            }
        }
        let Some(forward) = &self.state.forward else {
            self.restart_recovery_pending = false;
            return Ok(candidate_recovered);
        };
        if forward.phase == Phase::Revoked {
            self.restart_recovery_pending = false;
            return Ok(candidate_recovered);
        }
        let ambiguous_preparation = self.restart_recovery_pending
            && matches!(forward.phase, Phase::Preparing | Phase::Prepared);
        let boot_changed = self.state.boot_id != current_boot_id()?;
        if forward.phase == Phase::Guarded
            && !boot_changed
            && clock::owner_is_live(&forward.owner, now)
        {
            self.backend.guard_forwarding(&forward.declaration)?;
            self.restart_recovery_pending = false;
            return Ok(true);
        }
        if !ambiguous_preparation && !boot_changed && clock::owner_is_live(&forward.owner, now) {
            self.restart_recovery_pending = false;
            return Ok(candidate_recovered);
        }
        self.backend.reject_forwarding(&forward.declaration)?;
        self.backend.remove_firewall(&forward.declaration)?;
        let mut next = self.state.clone();
        next.forward.as_mut().unwrap().phase = Phase::Revoked;
        next.forward.as_mut().unwrap().pending_failed_prefixes = None;
        next.forward.as_mut().unwrap().pending_failure_revision = None;
        self.persist(next)?;
        self.restart_recovery_pending = false;
        Ok(true)
    }

    fn install_replacement(
        &mut self,
        previous: &ForwardRecord,
        candidate: &ForwardRecord,
        sysctls: &[SysctlChange],
    ) -> Result<(), InfrastructureError> {
        if previous.phase == Phase::Guarded {
            self.backend
                .guard_forwarding(&previous.declaration)
                .map_err(|cause| InfrastructureError::Transition {
                    stage: "guard_previous",
                    cause,
                })?;
        } else {
            self.backend
                .reject_forwarding(&previous.declaration)
                .map_err(|cause| InfrastructureError::Transition {
                    stage: "guard_previous",
                    cause,
                })?;
        }
        if previous.phase != Phase::Guarded {
            self.backend
                .reject_forwarding(&candidate.declaration)
                .map_err(|cause| InfrastructureError::Transition {
                    stage: "guard_candidate",
                    cause,
                })?;
        }
        self.backend
            .remove_firewall(&previous.declaration)
            .map_err(|cause| InfrastructureError::Transition {
                stage: "remove_previous_firewall",
                cause,
            })?;
        self.backend
            .prepare_sysctls(&candidate.declaration, sysctls)
            .map_err(|cause| InfrastructureError::Transition {
                stage: "candidate_sysctls",
                cause,
            })?;
        self.backend
            .prepare_firewall(&candidate.declaration)
            .map_err(|cause| InfrastructureError::Transition {
                stage: "candidate_firewall",
                cause,
            })?;
        self.backend
            .remove_stale_forwarding(&previous.declaration, &candidate.declaration)
            .map_err(|cause| InfrastructureError::Transition {
                stage: "remove_previous_routes",
                cause,
            })?;
        // Remove stale throw exclusions before publishing new unicast routes.
        self.backend
            .restore_forwarding_with_failures(&candidate.declaration, &candidate.failed_prefixes)
            .map_err(|cause| InfrastructureError::Transition {
                stage: "candidate_routes",
                cause,
            })?;
        Ok(())
    }

    fn rollback_replacement(
        &mut self,
        previous: &ForwardRecord,
        candidate: &ForwardRecord,
        now: u64,
    ) -> Result<(), InfrastructureError> {
        // Keep durable commit intent until every repair succeeds. Later requests retry recovery.
        let guarded_live = previous.phase == Phase::Guarded
            && ensure_live(&previous.owner, now).is_ok()
            && self.state.boot_id == current_boot_id()?;
        if guarded_live {
            // Candidate and previous declarations may share destinations. Never
            // inject a transient reject route before restoring the retained plan.
            self.backend.guard_forwarding(&previous.declaration)?;
        } else {
            self.backend.reject_forwarding(&candidate.declaration)?;
            self.backend.reject_forwarding(&previous.declaration)?;
        }
        self.backend.remove_firewall(&candidate.declaration)?;
        let mut retained = previous.clone();
        let old_live = matches!(previous.phase, Phase::Active | Phase::Guarded)
            && ensure_live(&previous.owner, now).is_ok()
            && self.state.boot_id == current_boot_id()?;
        if old_live {
            self.backend.prepare_firewall(&previous.declaration)?;
        } else {
            retained.phase = Phase::Revoked;
        }
        self.backend
            .remove_stale_forwarding(&candidate.declaration, &previous.declaration)?;
        if old_live {
            self.backend.restore_forwarding_with_failures(
                &previous.declaration,
                &previous.failed_prefixes,
            )?;
        }
        let mut next = self.state.clone();
        next.forward = Some(retained);
        next.candidate = None;
        self.persist(next)?;
        Ok(())
    }
}

fn ensure_live(owner: &ForwardOwner, now: u64) -> Result<(), InfrastructureError> {
    if !clock::owner_is_live(owner, now) {
        return Err(reject(
            "forward_owner_expired",
            "authorization or forwarding lease expired",
        ));
    }
    Ok(())
}

fn validate_failed_prefixes(
    declaration: &PrepareDeclaration,
    failed: &[Ipv4Prefix],
) -> Result<(), InfrastructureError> {
    let authorized = declaration
        .routes
        .iter()
        .filter(|route| route.kind == RouteKind::Remote)
        .map(|route| route.prefix)
        .collect::<std::collections::HashSet<_>>();
    let mut unique = std::collections::HashSet::new();
    for prefix in failed {
        if !unique.insert(*prefix) || !authorized.contains(prefix) {
            return Err(reject(
                "invalid_failed_prefix",
                "failures must be unique exact signed remote prefixes",
            ));
        }
    }
    Ok(())
}

fn current_boot_id() -> io::Result<String> {
    #[cfg(target_os = "linux")]
    {
        Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok("non_linux_protocol_test".to_string())
    }
}

fn new_ownership_marker() -> io::Result<String> {
    let mut nonce = [0; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let mut marker = String::from("candy-infra-v2:");
    for byte in nonce {
        use std::fmt::Write;
        write!(&mut marker, "{byte:02x}").unwrap();
    }
    Ok(marker)
}

fn process_start_ticks(pid: u32) -> io::Result<Option<u64>> {
    #[cfg(target_os = "linux")]
    {
        linux_process_identity(pid).map(|(_, ticks)| Some(ticks))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Ok(None)
    }
}

fn business_process_epoch_alive(pid: u32, ticks: u64) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        match linux_process_identity(pid) {
            Ok((state, current)) => Ok(!matches!(state, 'Z' | 'X' | 'x') && current == ticks),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, ticks);
        Ok(false)
    }
}

#[cfg(target_os = "linux")]
fn linux_process_identity(pid: u32) -> io::Result<(char, u64)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let suffix = stat
        .rsplit_once(')')
        .ok_or_else(|| io::Error::other("invalid process stat"))?
        .1;
    let mut fields = suffix.split_whitespace();
    let state = fields
        .next()
        .and_then(|field| field.chars().next())
        .ok_or_else(|| io::Error::other("missing process state"))?;
    let ticks = fields
        .nth(18)
        .ok_or_else(|| io::Error::other("missing process start time"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    Ok((state, ticks))
}

fn io_owner_alive(owner: &IoOwner) -> bool {
    if current_boot_id().is_ok_and(|boot_id| boot_id != owner.boot_id) {
        return false;
    }
    #[cfg(target_os = "linux")]
    match linux_process_identity(owner.pid) {
        Ok((state, ticks)) if matches!(state, 'Z' | 'X') || Some(ticks) != owner.start_ticks => {
            return false
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        Err(_) => return true,
        _ => {}
    }
    #[cfg(not(target_os = "linux"))]
    match process_start_ticks(owner.pid) {
        Ok(current) if current != owner.start_ticks => return false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        Err(_) => return true,
        _ => {}
    }
    // Uncertain permission failures retain ownership; never create a second reader.
    let result = unsafe { nix::libc::kill(owner.pid as nix::libc::pid_t, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM)
}

fn same_owner<'a>(
    record: Option<&'a mut ForwardRecord>,
    owner: &ForwardOwner,
) -> Result<&'a mut ForwardRecord, InfrastructureError> {
    let current = record.ok_or_else(|| reject("forward_missing", "no forwarding owner"))?;
    if current.owner != *owner {
        return Err(reject(
            "stale_forward_owner",
            "request does not match committed generation, epoch, fence and deadlines",
        ));
    }
    Ok(current)
}

#[cfg(all(test, target_os = "linux"))]
mod identity_tests {
    use super::*;

    #[test]
    fn process_ownership_uses_boot_and_start_time_in_addition_to_pid() {
        let mut owner = IoOwner {
            instance_id: [1; 16],
            pid: std::process::id(),
            io_epoch: 1,
            boot_id: current_boot_id().unwrap(),
            start_ticks: process_start_ticks(std::process::id()).unwrap(),
        };
        assert!(owner.start_ticks.is_some());
        assert!(io_owner_alive(&owner));
        owner.start_ticks = owner.start_ticks.map(|ticks| ticks + 1);
        assert!(
            !io_owner_alive(&owner),
            "a reused PID is not the retained process"
        );
        owner.start_ticks = process_start_ticks(owner.pid).unwrap();
        owner.boot_id.push_str("-previous-boot");
        assert!(!io_owner_alive(&owner));
    }

    #[test]
    fn unreaped_zombie_has_closed_descriptors_and_is_not_a_live_io_owner() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if linux_process_identity(child.id()).is_ok_and(|(state, _)| state == 'Z') {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let (state, ticks) = linux_process_identity(child.id()).unwrap();
        assert_eq!(state, 'Z');
        let owner = IoOwner {
            instance_id: [1; 16],
            pid: child.id(),
            io_epoch: 1,
            boot_id: current_boot_id().unwrap(),
            start_ticks: Some(ticks),
        };
        assert!(!io_owner_alive(&owner));
        child.wait().unwrap();
    }
}
