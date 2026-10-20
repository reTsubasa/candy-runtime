//! Control-only namespace dispatch. Each thread permanently owns one network namespace.

use super::*;
use crate::{LinuxNetworkBackend, SystemTunFactory};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainConfig {
    pub domain_id: [u8; 16],
    pub infra_id: [u8; 16],
    pub namespace_path: PathBuf,
    pub journal_path: PathBuf,
    pub table_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainsConfig {
    pub budgets: DomainBudgets,
    pub domains: Vec<DomainConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainBudgets {
    pub max_domains: usize,
    pub front_control_threads: usize,
    pub max_control_threads: usize,
    pub thread_stack_bytes: usize,
    pub max_total_stack_bytes: usize,
    pub max_pending_control_requests: usize,
    pub max_pending_control_bytes: usize,
    pub max_reserved_fds: usize,
}

const MIN_CONTROL_THREAD_STACK_BYTES: usize = 256 * 1024;
const RESERVED_DOMAIN_FDS: usize = 12;
const CONTROL_FD_SAFETY_MARGIN: usize = 8;
const FRONT_REQUEST_BYTES: usize = 4 * candy_netd_proto::MAX_NETD_FRAME_LEN;

fn budget(
    resource: &'static str,
    required: usize,
    allowed: usize,
) -> Result<(), InfrastructureError> {
    if required > allowed {
        return Err(InfrastructureError::ResourceBudget {
            resource,
            required: required as u64,
            allowed: allowed as u64,
        });
    }
    Ok(())
}

impl DomainBudgets {
    fn admit(&self, domains: usize) -> Result<(), InfrastructureError> {
        budget("domains", domains, self.max_domains)?;
        budget(
            "minimum_front_control_threads",
            2,
            self.front_control_threads,
        )?;
        let threads = domains
            .checked_add(self.front_control_threads)
            .ok_or_else(|| reject("domain_resource_budget_invalid", "thread count overflow"))?;
        budget("control_threads", threads, self.max_control_threads)?;
        budget(
            "minimum_thread_stack_bytes",
            MIN_CONTROL_THREAD_STACK_BYTES,
            self.thread_stack_bytes,
        )?;
        let stack_bytes = threads
            .checked_mul(self.thread_stack_bytes)
            .ok_or_else(|| {
                reject(
                    "domain_resource_budget_invalid",
                    "thread stack budget overflow",
                )
            })?;
        budget(
            "total_thread_stack_bytes",
            stack_bytes,
            self.max_total_stack_bytes,
        )?;
        budget(
            "pending_control_requests",
            self.front_control_threads,
            self.max_pending_control_requests,
        )?;
        budget(
            "pending_control_bytes",
            self.front_control_threads
                .checked_mul(FRONT_REQUEST_BYTES)
                .ok_or_else(|| {
                    reject(
                        "domain_resource_budget_invalid",
                        "front allocation budget overflow",
                    )
                })?,
            self.max_pending_control_bytes,
        )?;
        let pending = self
            .max_pending_control_requests
            .min(domains.saturating_mul(2));
        let descriptors =
            fs::read_dir("/proc/self/fd")?
                .count()
                .checked_add(domains.checked_mul(RESERVED_DOMAIN_FDS).ok_or_else(|| {
                    reject("domain_resource_budget_invalid", "FD budget overflow")
                })?)
                .and_then(|value| value.checked_add(pending.checked_mul(2)?))
                .and_then(|value| value.checked_add(CONTROL_FD_SAFETY_MARGIN))
                .and_then(|value| value.checked_add(self.max_pending_control_requests))
                .ok_or_else(|| reject("domain_resource_budget_invalid", "FD budget overflow"))?;
        budget("reserved_fds", descriptors, self.max_reserved_fds)?;
        let mut limit = nix::libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { nix::libc::getrlimit(nix::libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // rlim_t differs across Linux ABIs, including supported 32-bit targets.
        #[allow(clippy::unnecessary_cast)]
        let soft_limit = limit.rlim_cur as u64;
        if descriptors as u64 > soft_limit {
            return Err(InfrastructureError::ResourceBudget {
                resource: "rlimit_nofile_soft",
                required: descriptors as u64,
                allowed: soft_limit,
            });
        }
        Ok(())
    }
}

#[derive(Default)]
struct PendingBudget {
    requests: usize,
    bytes: usize,
}

struct ControlBudget {
    limits: DomainBudgets,
    pending: Mutex<PendingBudget>,
}

impl ControlBudget {
    fn reserve(self: &Arc<Self>, bytes: usize) -> Result<ControlPermit, InfrastructureError> {
        let mut pending = self.pending.lock().map_err(|_| {
            reject(
                "domain_control_budget_unavailable",
                "control admission state is unavailable",
            )
        })?;
        let requests = pending
            .requests
            .checked_add(1)
            .ok_or_else(|| reject("domain_control_budget_invalid", "control count overflow"))?;
        let total_bytes = pending
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| reject("domain_control_budget_invalid", "control bytes overflow"))?;
        budget(
            "pending_control_requests",
            requests,
            self.limits.max_pending_control_requests,
        )?;
        budget(
            "pending_control_bytes",
            total_bytes,
            self.limits.max_pending_control_bytes,
        )?;
        pending.requests = requests;
        pending.bytes = total_bytes;
        Ok(ControlPermit {
            lease: Arc::new(ControlLease {
                budget: self.clone(),
                bytes: AtomicUsize::new(bytes),
            }),
        })
    }
}

struct ControlLease {
    budget: Arc<ControlBudget>,
    bytes: AtomicUsize,
}

#[derive(Clone)]
struct ControlPermit {
    lease: Arc<ControlLease>,
}

impl ControlPermit {
    fn resize(&mut self, bytes: usize) -> Result<(), InfrastructureError> {
        let mut pending = self.lease.budget.pending.lock().map_err(|_| {
            reject(
                "domain_control_budget_unavailable",
                "control admission state is unavailable",
            )
        })?;
        let total = pending
            .bytes
            .checked_sub(self.lease.bytes.load(Ordering::Relaxed))
            .and_then(|value| value.checked_add(bytes))
            .ok_or_else(|| reject("domain_control_budget_invalid", "control bytes overflow"))?;
        budget(
            "pending_control_bytes",
            total,
            self.lease.budget.limits.max_pending_control_bytes,
        )?;
        pending.bytes = total;
        self.lease.bytes.store(bytes, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for ControlLease {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.budget.pending.lock() {
            pending.requests -= 1;
            pending.bytes -= self.bytes.load(Ordering::Relaxed);
        }
    }
}

fn request_queue_bytes(request: &Request) -> Result<usize, InfrastructureError> {
    let heap = match &request.operation {
        Operation::ForwardPrepare { declaration, .. }
        | Operation::ForwardPolicyUpdate { declaration, .. } => declaration
            .routes
            .capacity()
            .checked_mul(std::mem::size_of::<candy_netd_proto::RouteDeclaration>())
            .and_then(|bytes| {
                declaration
                    .exclusions
                    .capacity()
                    .checked_mul(std::mem::size_of::<candy_netd_proto::UnderlayExclusion>())
                    .and_then(|exclusions| bytes.checked_add(exclusions))
            }),
        Operation::ForwardFailedPrefixes {
            failed_prefixes, ..
        } => failed_prefixes
            .capacity()
            .checked_mul(std::mem::size_of::<Ipv4Prefix>()),
        Operation::ForwardAuthorize { authority, .. } => Some(
            authority.transaction_id.capacity()
                + authority.signed_control_hash.capacity()
                + authority.declaration_hash.capacity()
                + authority.snapshot_closure_hash.capacity(),
        ),
        Operation::ForwardCommitAuthorized { receipt, .. } => Some(
            receipt.authority.transaction_id.capacity()
                + receipt.authority.signed_control_hash.capacity()
                + receipt.authority.declaration_hash.capacity()
                + receipt.authority.snapshot_closure_hash.capacity(),
        ),
        Operation::InDomain { .. } => {
            return Err(reject(
                "domain_scope_nested",
                "queue accounting requires an unwrapped operation",
            ))
        }
        _ => Some(0),
    }
    .ok_or_else(|| {
        reject(
            "domain_control_budget_invalid",
            "control allocation size overflow",
        )
    })?;
    let heap = if let Operation::ForwardPolicyUpdate {
        authorization_snapshot_sha256,
        ..
    } = &request.operation
    {
        heap.checked_add(authorization_snapshot_sha256.capacity())
            .ok_or_else(|| {
                reject(
                    "domain_control_budget_invalid",
                    "control allocation size overflow",
                )
            })?
    } else {
        heap
    };
    std::mem::size_of::<DomainRequest>()
        .checked_add(heap)
        .ok_or_else(|| {
            reject(
                "domain_control_budget_invalid",
                "control allocation size overflow",
            )
        })
}

impl DomainsConfig {
    pub fn validate_resource_admission(&self) -> Result<(), InfrastructureError> {
        if self.domains.is_empty() {
            return Err(reject(
                "domain_configuration_empty",
                "at least one domain is required",
            ));
        }
        self.budgets.admit(self.domains.len())
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::other(
                "domain configuration must be a root-owned private regular file",
            ));
        }
        let mut bytes = Vec::new();
        file.take(65_537).read_to_end(&mut bytes)?;
        if bytes.len() > 65_536 {
            return Err(io::Error::other(
                "domain configuration exceeds frame budget",
            ));
        }
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }
}

#[derive(Clone)]
struct DomainIdentity {
    config: DomainConfig,
    netns_device: u64,
    netns_inode: u64,
}

impl DomainIdentity {
    fn validate_operation(&self, operation: &Operation) -> Result<(), InfrastructureError> {
        let invalid = || {
            reject(
                "domain_identity_conflict",
                "operation must match configured domain, infrastructure, namespace and table",
            )
        };
        match operation {
            Operation::InfraEnsure(spec) => {
                if spec.infra_id != self.config.infra_id
                    || spec.netns_device != self.netns_device
                    || spec.netns_inode != self.netns_inode
                {
                    return Err(invalid());
                }
            }
            Operation::InfraAcquireIoFd { infra_id, .. }
            | Operation::InfraReleaseIo { infra_id, .. }
            | Operation::InfraRetire { infra_id, .. } => {
                if *infra_id != self.config.infra_id {
                    return Err(invalid());
                }
            }
            Operation::ForwardPrepare {
                infra_id,
                owner,
                declaration,
                ..
            } => {
                if *infra_id != self.config.infra_id
                    || owner.domain_id != self.config.domain_id
                    || declaration.table_id != self.config.table_id
                {
                    return Err(invalid());
                }
            }
            Operation::ForwardPolicyUpdate {
                owner, declaration, ..
            } => {
                if owner.domain_id != self.config.domain_id
                    || declaration.table_id != self.config.table_id
                {
                    return Err(invalid());
                }
            }
            Operation::ForwardCommit { owner }
            | Operation::ForwardAuthorize { owner, .. }
            | Operation::ForwardCommitAuthorized { owner, .. }
            | Operation::ForwardRevoke { owner }
            | Operation::ForwardGuard { owner }
            | Operation::ForwardLeaseRenew { owner }
            | Operation::ForwardFailedPrefixes { owner, .. } => {
                if owner.domain_id != self.config.domain_id {
                    return Err(invalid());
                }
            }
            Operation::InDomain { .. } => return Err(invalid()),
            Operation::Capabilities | Operation::InfraStatus | Operation::ForwardStatus => {}
        }
        Ok(())
    }

    fn validate_journal(&self, state: &State) -> Result<(), InfrastructureError> {
        if let Some(spec) = &state.spec {
            self.validate_operation(&Operation::InfraEnsure(spec.clone()))?;
        }
        for record in state.forward.iter().chain(state.candidate.iter()) {
            if let Some(pending) = &record.pending_policy {
                self.validate_operation(&Operation::ForwardPolicyUpdate {
                    owner: record.owner.clone(),
                    policy_revision: pending.revision,
                    policy_generation: pending.generation,
                    authorization_snapshot_sha256: pending.authorization_snapshot_sha256.clone(),
                    declaration: pending.declaration.clone(),
                })?;
            }
            self.validate_operation(&Operation::ForwardPrepare {
                infra_id: self.config.infra_id,
                infra_generation: state.spec.as_ref().map_or(1, |spec| spec.generation),
                owner: record.owner.clone(),
                declaration: record.declaration.clone(),
            })?;
        }
        Ok(())
    }
}

type ProcessResult = Result<(Body, Option<OwnedFd>), InfrastructureError>;

struct DomainRequest {
    request: Request,
    peer: PeerCredentials,
    now: u64,
    reply: SyncSender<ProcessResult>,
    _permit: ControlPermit,
    _domain_permit: DomainPermit,
    rollback: Option<IoRollback>,
}

struct DomainPermit(Arc<AtomicBool>);

impl Drop for DomainPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct DomainWorker {
    identity: DomainIdentity,
    sender: Option<SyncSender<DomainRequest>>,
    thread: Option<JoinHandle<()>>,
    _journal_lock: fs::File,
    inflight: Arc<AtomicBool>,
}

impl Drop for DomainWorker {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub struct MultiDomainService {
    allowed_uid: u32,
    allowed_gid: u32,
    domains: HashMap<[u8; 16], DomainWorker>,
    io_bindings: Arc<Mutex<HashMap<[u8; 16], IoBinding>>>,
    next_binding_token: AtomicU64,
    front_attached: AtomicBool,
    control_budget: Arc<ControlBudget>,
}

#[derive(Clone)]
struct IoBinding {
    owner: IoOwner,
    token: u64,
}

#[derive(Clone)]
struct IoRollback {
    bindings: Arc<Mutex<HashMap<[u8; 16], IoBinding>>>,
    domain_id: [u8; 16],
    token: u64,
    previous: Option<IoBinding>,
}

impl IoRollback {
    fn apply(&self) -> Result<(), InfrastructureError> {
        let mut bindings = self.bindings.lock().map_err(|_| {
            reject(
                "domain_io_binding_unavailable",
                "I/O binding lock is unavailable",
            )
        })?;
        if bindings
            .get(&self.domain_id)
            .is_some_and(|binding| binding.token == self.token)
        {
            if let Some(previous) = &self.previous {
                bindings.insert(self.domain_id, previous.clone());
            } else {
                bindings.remove(&self.domain_id);
            }
        }
        Ok(())
    }
}

impl MultiDomainService {
    pub fn new(
        allowed_uid: u32,
        allowed_gid: u32,
        config: DomainsConfig,
    ) -> Result<Self, InfrastructureError> {
        if config.domains.is_empty() {
            return Err(reject(
                "domain_configuration_empty",
                "at least one domain is required",
            ));
        }
        config.validate_resource_admission()?;
        let control_budget = Arc::new(ControlBudget {
            limits: config.budgets.clone(),
            pending: Mutex::new(PendingBudget::default()),
        });
        // Validate all mappings before any domain starts recovery or creates a kernel object.
        let mut domain_ids = HashSet::new();
        let mut infra_ids = HashSet::new();
        let mut namespaces = HashSet::new();
        let mut journals = HashSet::new();
        let mut prepared = Vec::new();
        let mut io_bindings = HashMap::new();
        let current_ns = fs::metadata("/proc/thread-self/ns/net")?;
        for domain in config.domains {
            if domain.domain_id == [0; 16]
                || domain.infra_id == [0; 16]
                || !(candy_netd_proto::CANDY_TABLE_MIN..=candy_netd_proto::CANDY_TABLE_MAX)
                    .contains(&domain.table_id)
                || !domain.namespace_path.is_absolute()
                || !domain.journal_path.is_absolute()
                || !domain_ids.insert(domain.domain_id)
                || !infra_ids.insert(domain.infra_id)
            {
                return Err(reject(
                    "domain_configuration_invalid",
                    "domain IDs, infra IDs, paths and tables must be explicit and unique",
                ));
            }
            let namespace = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open(&domain.namespace_path)?;
            let metadata = namespace.metadata()?;
            let mut filesystem = std::mem::MaybeUninit::<nix::libc::statfs>::uninit();
            if unsafe { nix::libc::fstatfs(namespace.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            let filesystem = unsafe { filesystem.assume_init() };
            if metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || filesystem.f_type as u64 != 0x6e736673
                || (metadata.dev(), metadata.ino()) == (current_ns.dev(), current_ns.ino())
                || !namespaces.insert((metadata.dev(), metadata.ino()))
            {
                return Err(reject("domain_namespace_conflict", "each domain requires a distinct pinned root-owned namespace, excluding the host namespace"));
            }
            let parent = domain
                .journal_path
                .parent()
                .ok_or_else(|| io::Error::other("journal parent missing"))?;
            let canonical = parent.canonicalize()?.join(
                domain
                    .journal_path
                    .file_name()
                    .ok_or_else(|| io::Error::other("journal filename missing"))?,
            );
            if !journals.insert(canonical) {
                return Err(reject(
                    "domain_journal_conflict",
                    "each domain requires a separate journal",
                ));
            }
            let identity = DomainIdentity {
                netns_device: metadata.dev(),
                netns_inode: metadata.ino(),
                config: domain,
            };
            let journal = InfrastructureJournal::new(&identity.config.journal_path)?;
            let state = journal.load()?;
            identity.validate_journal(&state)?;
            if let Some(owner) = state.io_owner.filter(io_owner_alive) {
                validate_io_binding(&io_bindings, identity.config.domain_id, &owner)?;
                io_bindings.insert(identity.config.domain_id, IoBinding { owner, token: 0 });
            }
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open(identity.config.journal_path.with_extension("domain-lock"))?;
            let lock_metadata = lock.metadata()?;
            if !lock_metadata.is_file()
                || lock_metadata.uid() != 0
                || lock_metadata.mode() & 0o077 != 0
                || unsafe {
                    nix::libc::flock(lock.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB)
                } != 0
            {
                return Err(reject(
                    "domain_journal_busy",
                    "journal lock is unsafe or another namespace domain controller owns it",
                ));
            }
            prepared.push((identity, namespace, journal, lock));
        }
        let mut domains = HashMap::new();
        for (identity, namespace, journal, lock) in prepared {
            let (sender, receiver) = mpsc::sync_channel(1);
            let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
            let worker_identity = identity.clone();
            let thread = thread::Builder::new()
                .stack_size(config.budgets.thread_stack_bytes)
                .name(format!(
                    "netd-domain-{:02x}{:02x}",
                    identity.config.domain_id[0], identity.config.domain_id[1]
                ))
                .spawn(move || {
                    let service = (|| {
                        if unsafe {
                            nix::libc::setns(namespace.as_raw_fd(), nix::libc::CLONE_NEWNET)
                        } != 0
                        {
                            return Err(InfrastructureError::Journal(io::Error::last_os_error()));
                        }
                        let actual = fs::metadata("/proc/thread-self/ns/net")?;
                        if (actual.dev(), actual.ino())
                            != (worker_identity.netns_device, worker_identity.netns_inode)
                        {
                            return Err(reject(
                                "domain_namespace_conflict",
                                "thread namespace does not match the pinned identity",
                            ));
                        }
                        InfrastructureService::new(
                            allowed_uid,
                            allowed_gid,
                            SystemTunFactory,
                            LinuxNetworkBackend::new()?,
                            journal,
                        )
                    })();
                    match service {
                        Ok(service) => {
                            if ready_sender.send(Ok(())).is_ok() {
                                run_domain(service, receiver, worker_identity);
                            }
                        }
                        Err(error) => {
                            let _ = ready_sender.send(Err(error));
                        }
                    }
                })?;
            let worker = DomainWorker {
                identity,
                sender: Some(sender),
                thread: Some(thread),
                _journal_lock: lock,
                inflight: Arc::new(AtomicBool::new(false)),
            };
            ready_receiver.recv().map_err(|_| {
                reject(
                    "domain_worker_failed",
                    "namespace worker exited during startup",
                )
            })??;
            domains.insert(worker.identity.config.domain_id, worker);
        }
        Ok(Self {
            allowed_uid,
            allowed_gid,
            domains,
            io_bindings: Arc::new(Mutex::new(io_bindings)),
            next_binding_token: AtomicU64::new(1),
            front_attached: AtomicBool::new(false),
            control_budget,
        })
    }

    pub fn process(&self, request: Request, peer: PeerCredentials, now: u64) -> ProcessResult {
        self.process_admitted(request, peer, now, None)
    }

    fn process_admitted(
        &self,
        mut request: Request,
        peer: PeerCredentials,
        now: u64,
        admitted: Option<ControlPermit>,
    ) -> ProcessResult {
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
        if request.operation == Operation::Capabilities {
            return Ok((
                Body::Capabilities {
                    version: 2,
                    independent_infrastructure: true,
                    multi_domain: true,
                },
                None,
            ));
        }
        let Operation::InDomain {
            domain_id,
            infra_id,
            operation,
        } = request.operation
        else {
            return Err(reject(
                "domain_scope_required",
                "multi-domain requests must specify domain and infrastructure identity",
            ));
        };
        let worker = self
            .domains
            .get(&domain_id)
            .ok_or_else(|| reject("domain_unknown", "domain is not configured"))?;
        if infra_id != worker.identity.config.infra_id {
            return Err(reject(
                "domain_identity_conflict",
                "scoped infrastructure does not match configured domain",
            ));
        }
        worker.identity.validate_operation(&operation)?;
        let io_owner = if let Operation::InfraAcquireIoFd { io_epoch, .. } = operation.as_ref() {
            Some(IoOwner {
                instance_id: request.caller_instance_id,
                pid: request.caller_pid,
                io_epoch: *io_epoch,
                boot_id: current_boot_id()?,
                start_ticks: process_start_ticks(request.caller_pid)?,
            })
        } else {
            None
        };
        if let Some(owner) = &io_owner {
            let bindings = self.io_bindings.lock().map_err(|_| {
                reject(
                    "domain_io_binding_unavailable",
                    "I/O binding lock is unavailable",
                )
            })?;
            validate_io_binding(&bindings, domain_id, owner)?;
        }
        if io_owner.is_some() {
            let namespace = fs::metadata(format!("/proc/{}/ns/net", request.caller_pid))?;
            if (namespace.dev(), namespace.ino())
                != (worker.identity.netns_device, worker.identity.netns_inode)
            {
                return Err(reject(
                    "domain_io_namespace_conflict",
                    "TUNIO process must execute in the configured routing namespace",
                ));
            }
        }
        request.operation = *operation;
        worker
            .inflight
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| {
                reject(
                    "domain_worker_busy",
                    "domain already has an active or pending operation; retry",
                )
            })?;
        let domain_permit = DomainPermit(worker.inflight.clone());
        let bytes = request_queue_bytes(&request)?;
        let permit = if let Some(mut permit) = admitted {
            permit.resize(bytes.max(FRONT_REQUEST_BYTES))?;
            permit
        } else {
            self.control_budget.reserve(bytes)?
        };
        // Reserve before dispatch: a timed-out acquisition can still complete in its thread.
        let reservation = if let Some(owner) = io_owner {
            let token = self
                .next_binding_token
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| {
                    reject(
                        "domain_io_binding_unavailable",
                        "reservation token exhausted",
                    )
                })?;
            let mut bindings = self.io_bindings.lock().map_err(|_| {
                reject(
                    "domain_io_binding_unavailable",
                    "I/O binding lock is unavailable",
                )
            })?;
            validate_io_binding(&bindings, domain_id, &owner)?;
            let previous = bindings.insert(domain_id, IoBinding { owner, token });
            Some(IoRollback {
                bindings: self.io_bindings.clone(),
                domain_id,
                token,
                previous,
            })
        } else {
            None
        };
        let result = (|| {
            let (reply, response) = mpsc::sync_channel(1);
            worker
                .sender
                .as_ref()
                .unwrap()
                .try_send(DomainRequest {
                    request,
                    peer,
                    now,
                    reply,
                    _permit: permit,
                    _domain_permit: domain_permit,
                    rollback: reservation.clone(),
                })
                .map_err(|_| {
                    reject(
                        "domain_worker_busy",
                        "domain worker queue is occupied or unavailable; retry",
                    )
                })?;
            response.recv_timeout(Duration::from_secs(2)).map_err(|_| {
                reject(
                    "domain_operation_pending",
                    "domain operation has not completed; query scoped status before retrying",
                )
            })?
        })();
        if result.is_err()
            && !matches!(
                &result,
                Err(InfrastructureError::Rejected {
                    code: "domain_operation_pending",
                    ..
                })
            )
        {
            if let Some(reservation) = reservation {
                reservation.apply()?;
            }
        }
        result
    }

    pub fn serve_once(&self, stream: &UnixStream, now: u64) -> Result<(), InfrastructureError> {
        let peer = crate::peer_credentials(stream)?;
        let request = candy_netd_client::v2::recv_request(stream)?;
        let request_id = request.request_id;
        let (body, descriptor) = match self.process(request, peer, now) {
            Ok(result) => result,
            Err(error) => {
                let code = match &error {
                    InfrastructureError::Rejected { code, .. } => *code,
                    InfrastructureError::ResourceBudget { .. } => "domain_resource_budget_exceeded",
                    _ => "domain_system_failure",
                };
                (
                    Body::Error {
                        code: code.into(),
                        module: "netd_domains".into(),
                        reason: error.to_string(),
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

    fn serve_admitted(&self, admitted: FrontRequest) -> Result<(), InfrastructureError> {
        let FrontRequest {
            stream,
            permit,
            deadline,
        } = admitted;
        // Keep ingress/socket/response allocation charged until both the real operation
        // and response handling finish, including operation timeout or lost response.
        let _response_permit = permit.clone();
        let peer = crate::peer_credentials(&stream)?;
        let request = candy_netd_client::v2::recv_request_until(&stream, deadline)?;
        let request_id = request.request_id;
        let (body, descriptor) =
            match self.process_admitted(request, peer, monotonic_millis()?, Some(permit)) {
                Ok(result) => result,
                Err(error) => {
                    let code = match &error {
                        InfrastructureError::Rejected { code, .. } => *code,
                        InfrastructureError::ResourceBudget { .. } => {
                            "domain_resource_budget_exceeded"
                        }
                        _ => "domain_system_failure",
                    };
                    (
                        Body::Error {
                            code: code.into(),
                            module: "netd_domains".into(),
                            reason: error.to_string(),
                        },
                        None,
                    )
                }
            };
        candy_netd_client::v2::send_response_until(
            &stream,
            &Response { request_id, body },
            descriptor.as_ref(),
            std::time::Instant::now() + Duration::from_secs(2),
        )?;
        Ok(())
    }
}

struct FrontRequest {
    stream: UnixStream,
    permit: ControlPermit,
    deadline: std::time::Instant,
}

pub struct FrontDispatcher {
    sender: Option<SyncSender<FrontRequest>>,
    threads: Vec<JoinHandle<()>>,
    control_budget: Arc<ControlBudget>,
    service: Arc<MultiDomainService>,
}

impl FrontDispatcher {
    pub fn new(service: Arc<MultiDomainService>) -> Result<Self, InfrastructureError> {
        service
            .front_attached
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| {
                reject(
                    "domain_front_already_attached",
                    "one bounded ingress pool is allowed per service",
                )
            })?;
        let limits = &service.control_budget.limits;
        let (sender, receiver) = mpsc::sync_channel::<FrontRequest>(limits.front_control_threads);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut front = Self {
            sender: Some(sender),
            threads: Vec::new(),
            control_budget: service.control_budget.clone(),
            service: service.clone(),
        };
        for index in 0..limits.front_control_threads {
            let receiver = receiver.clone();
            let service = service.clone();
            front.threads.push(thread::Builder::new().name(format!("netd-front-{index}"))
                .stack_size(limits.thread_stack_bytes).spawn(move || loop {
                    let admitted = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => break,
                    };
                    let Ok(admitted) = admitted else { break };
                    if let Err(error) = service.serve_admitted(admitted) {
                        let reason = format!("{:#}", anyhow::Error::new(error)).chars()
                            .map(|character| if character.is_control() { ' ' } else { character }).collect::<String>();
                        crate::eprintln!("level=warn code=domain_front_request_failed module=netd_domains reason={reason}");
                    }
                })?);
        }
        Ok(front)
    }

    pub fn dispatch(&self, stream: UnixStream) -> Result<(), InfrastructureError> {
        let permit = self.control_budget.reserve(FRONT_REQUEST_BYTES)?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let request = FrontRequest {
            stream,
            permit,
            deadline: std::time::Instant::now() + Duration::from_secs(2),
        };
        self.sender
            .as_ref()
            .unwrap()
            .try_send(request)
            .map_err(|_| {
                reject(
                    "domain_front_busy",
                    "bounded control ingress is full; retry",
                )
            })
    }
}

impl Drop for FrontDispatcher {
    fn drop(&mut self) {
        self.sender.take();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        self.service.front_attached.store(false, Ordering::Release);
    }
}

fn validate_io_binding(
    bindings: &HashMap<[u8; 16], IoBinding>,
    domain_id: [u8; 16],
    owner: &IoOwner,
) -> Result<(), InfrastructureError> {
    if bindings.iter().any(|(domain, binding)| {
        let retained = &binding.owner;
        *domain != domain_id
            && io_owner_alive(retained)
            && (retained.instance_id == owner.instance_id
                || (retained.pid == owner.pid
                    && retained.start_ticks == owner.start_ticks
                    && retained.boot_id == owner.boot_id))
    }) {
        return Err(reject(
            "domain_io_owner_conflict",
            "each domain requires its own TUNIO process and caller instance",
        ));
    }
    if bindings
        .get(&domain_id)
        .is_some_and(|binding| io_owner_alive(&binding.owner))
    {
        return Err(reject(
            "io_owner_alive",
            "domain already has a live or pending I/O owner; reconcile status before retrying",
        ));
    }
    Ok(())
}

fn run_domain(
    mut service: InfrastructureService<SystemTunFactory, LinuxNetworkBackend>,
    receiver: Receiver<DomainRequest>,
    identity: DomainIdentity,
) {
    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(request) => {
                let result = service.process(request.request, request.peer, request.now);
                if result.is_err() {
                    if let Some(rollback) = &request.rollback {
                        if let Err(error) = rollback.apply() {
                            crate::eprintln!("level=error code=domain_io_rollback_failed module=netd_domains reason={error}");
                        }
                    }
                }
                drop(request._permit);
                drop(request._domain_permit);
                let _ = request.reply.send(result);
            }
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
        let result = monotonic_millis()
            .map_err(InfrastructureError::Journal)
            .and_then(|now| service.recover_expired(now));
        if let Err(error) = result {
            crate::eprintln!("level=error code=domain_recovery_pending module=netd_domains domain_id={:?} infra_id={:?} reason={error}", identity.config.domain_id, identity.config.infra_id);
        }
    }
}

pub fn monotonic_millis() -> io::Result<u64> {
    super::clock::now_ms()
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    fn limits() -> DomainBudgets {
        DomainBudgets {
            max_domains: 4,
            front_control_threads: 2,
            max_control_threads: 6,
            thread_stack_bytes: MIN_CONTROL_THREAD_STACK_BYTES,
            max_total_stack_bytes: 6 * MIN_CONTROL_THREAD_STACK_BYTES,
            max_pending_control_requests: 2,
            // The front dispatcher reserves one full worst-case frame per
            // front-control thread. Keep the fixture aligned with the
            // protocol's 2 MiB frame cap (and the two-thread front budget),
            // otherwise every dispatch test is rejected before exercising the
            // domain lifecycle.
            max_pending_control_bytes: 2 * FRONT_REQUEST_BYTES,
            max_reserved_fds: 4096,
        }
    }

    fn fake_domains() -> (Arc<MultiDomainService>, Vec<Receiver<DomainRequest>>) {
        let namespace = fs::metadata("/proc/thread-self/ns/net").unwrap();
        let mut domains = HashMap::new();
        let mut receivers = Vec::new();
        for index in 1..=2 {
            let (sender, receiver) = mpsc::sync_channel(1);
            receivers.push(receiver);
            domains.insert(
                [index; 16],
                DomainWorker {
                    identity: DomainIdentity {
                        config: DomainConfig {
                            domain_id: [index; 16],
                            infra_id: [index + 10; 16],
                            namespace_path: "/unused".into(),
                            journal_path: "/unused".into(),
                            table_id: 20_000,
                        },
                        netns_device: namespace.dev(),
                        netns_inode: namespace.ino(),
                    },
                    sender: Some(sender),
                    thread: None,
                    _journal_lock: fs::File::open("/dev/null").unwrap(),
                    inflight: Arc::new(AtomicBool::new(false)),
                },
            );
        }
        (
            Arc::new(MultiDomainService {
                allowed_uid: unsafe { nix::libc::geteuid() },
                allowed_gid: unsafe { nix::libc::getegid() },
                domains,
                io_bindings: Arc::default(),
                next_binding_token: AtomicU64::new(1),
                front_attached: AtomicBool::new(false),
                control_budget: Arc::new(ControlBudget {
                    limits: limits(),
                    pending: Mutex::default(),
                }),
            }),
            receivers,
        )
    }

    fn scoped(index: u8, operation: Operation) -> Request {
        Request {
            request_id: 1,
            caller_instance_id: [index; 16],
            caller_pid: std::process::id(),
            operation: Operation::InDomain {
                domain_id: [index; 16],
                infra_id: [index + 10; 16],
                operation: Box::new(operation),
            },
        }
    }

    fn peer() -> PeerCredentials {
        PeerCredentials {
            pid: std::process::id(),
            uid: unsafe { nix::libc::geteuid() },
            gid: unsafe { nix::libc::getegid() },
        }
    }

    fn finish(request: DomainRequest, result: ProcessResult) {
        if result.is_err() {
            if let Some(rollback) = &request.rollback {
                rollback.apply().unwrap();
            }
        }
        drop(request._permit);
        drop(request._domain_permit);
        let _ = request.reply.send(result);
    }

    fn send_request(stream: &mut UnixStream, request: &Request) {
        let bytes = request.encode().unwrap();
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&bytes).unwrap();
    }

    #[test]
    fn slow_io_domain_releases_binding_lock_and_cas_rollback_preserves_newer_reservation() {
        let (service, mut receivers) = fake_domains();
        let first_receiver = receivers.remove(0);
        let healthy_receiver = receivers.remove(0);
        let worker_service = service.clone();
        let slow = thread::spawn(move || {
            worker_service.process(
                scoped(
                    1,
                    Operation::InfraAcquireIoFd {
                        infra_id: [11; 16],
                        generation: 1,
                        io_epoch: 1,
                    },
                ),
                peer(),
                1,
            )
        });
        let pending = first_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        let mut bindings = service
            .io_bindings
            .try_lock()
            .expect("pending I/O must not hold the global binding lock");
        let previous = bindings.get(&[1; 16]).unwrap().clone();
        let newer_token = previous.token + 1;
        bindings.insert(
            [1; 16],
            IoBinding {
                owner: previous.owner,
                token: newer_token,
            },
        );
        drop(bindings);
        assert!(matches!(
            service.process(scoped(1, Operation::InfraStatus), peer(), 1),
            Err(InfrastructureError::Rejected {
                code: "domain_worker_busy",
                ..
            })
        ));
        let healthy_service = service.clone();
        let healthy = thread::spawn(move || {
            healthy_service.process(scoped(2, Operation::InfraStatus), peer(), 1)
        });
        let request = healthy_receiver
            .recv_timeout(Duration::from_millis(500))
            .unwrap();
        finish(request, Ok((Body::Ack, None)));
        healthy.join().unwrap().unwrap();
        finish(
            pending,
            Err(reject(
                "injected_io_failure",
                "controlled slow domain failure",
            )),
        );
        assert!(slow.join().unwrap().is_err());
        assert_eq!(
            service
                .io_bindings
                .lock()
                .unwrap()
                .get(&[1; 16])
                .unwrap()
                .token,
            newer_token
        );
    }

    #[test]
    fn bounded_front_dispatch_keeps_healthy_domain_running_while_other_domain_is_slow() {
        let (service, mut receivers) = fake_domains();
        let first_receiver = receivers.remove(0);
        let healthy_receiver = receivers.remove(0);
        let front = FrontDispatcher::new(service.clone()).unwrap();
        assert!(FrontDispatcher::new(service.clone()).is_err());
        let (mut first_client, first_server) = UnixStream::pair().unwrap();
        send_request(
            &mut first_client,
            &scoped(
                1,
                Operation::InfraAcquireIoFd {
                    infra_id: [11; 16],
                    generation: 1,
                    io_epoch: 1,
                },
            ),
        );
        front.dispatch(first_server).unwrap();
        let pending = first_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        let (mut healthy_client, healthy_server) = UnixStream::pair().unwrap();
        send_request(&mut healthy_client, &scoped(2, Operation::InfraStatus));
        front.dispatch(healthy_server).unwrap();
        let request = healthy_receiver
            .recv_timeout(Duration::from_millis(500))
            .expect("slow domain must not serialize front dispatch");
        finish(request, Ok((Body::Ack, None)));
        finish(
            pending,
            Err(reject(
                "injected_io_failure",
                "controlled slow domain failure",
            )),
        );
        drop(front);
        assert_eq!(service.control_budget.pending.lock().unwrap().requests, 0);
    }

    #[test]
    fn timed_out_domain_operation_keeps_its_domain_slot_and_global_permit() {
        let (service, mut receivers) = fake_domains();
        let first_receiver = receivers.remove(0);
        let worker_service = service.clone();
        let worker = thread::spawn(move || {
            worker_service.process(scoped(1, Operation::InfraStatus), peer(), 1)
        });
        let pending = first_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            Err(InfrastructureError::Rejected {
                code: "domain_operation_pending",
                ..
            })
        ));
        assert_eq!(service.control_budget.pending.lock().unwrap().requests, 1);
        assert!(matches!(
            service.process(scoped(1, Operation::InfraStatus), peer(), 1),
            Err(InfrastructureError::Rejected {
                code: "domain_worker_busy",
                ..
            })
        ));
        finish(pending, Ok((Body::Ack, None)));
        assert_eq!(service.control_budget.pending.lock().unwrap().requests, 0);
        assert!(!service
            .domains
            .get(&[1; 16])
            .unwrap()
            .inflight
            .load(Ordering::Acquire));
    }

    #[test]
    fn io_failure_after_caller_timeout_rolls_back_only_its_own_live_reservation() {
        let (service, mut receivers) = fake_domains();
        let first_receiver = receivers.remove(0);
        let worker_service = service.clone();
        let worker = thread::spawn(move || {
            worker_service.process(
                scoped(
                    1,
                    Operation::InfraAcquireIoFd {
                        infra_id: [11; 16],
                        generation: 1,
                        io_epoch: 1,
                    },
                ),
                peer(),
                1,
            )
        });
        let pending = first_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            Err(InfrastructureError::Rejected {
                code: "domain_operation_pending",
                ..
            })
        ));
        assert!(service.io_bindings.lock().unwrap().contains_key(&[1; 16]));
        finish(
            pending,
            Err(reject("injected_io_failure", "late operation failure")),
        );
        assert!(!service.io_bindings.lock().unwrap().contains_key(&[1; 16]));
    }

    fn assert_budget(result: Result<(), InfrastructureError>, expected: &str) {
        assert!(
            matches!(result, Err(InfrastructureError::ResourceBudget { resource, .. }) if resource == expected)
        );
    }

    #[test]
    fn resource_admission_accepts_boundaries_and_rejects_each_exhausted_resource() {
        let base = limits();
        base.admit(4).unwrap();
        assert_budget(base.admit(5), "domains");
        let mut candidate = base.clone();
        candidate.max_control_threads = 3;
        assert_budget(candidate.admit(4), "control_threads");
        candidate = base.clone();
        candidate.thread_stack_bytes -= 1;
        assert_budget(candidate.admit(1), "minimum_thread_stack_bytes");
        candidate = base.clone();
        candidate.max_total_stack_bytes -= 1;
        assert_budget(candidate.admit(4), "total_thread_stack_bytes");
        candidate = base.clone();
        candidate.max_pending_control_requests = 0;
        assert_budget(candidate.admit(1), "pending_control_requests");
        candidate = base.clone();
        candidate.max_pending_control_bytes = 2 * FRONT_REQUEST_BYTES - 1;
        assert_budget(candidate.admit(1), "pending_control_bytes");
        candidate = base;
        candidate.max_reserved_fds = 0;
        assert_budget(candidate.admit(1), "reserved_fds");
    }

    #[test]
    fn resource_admission_rejects_checked_stack_overflow() {
        let mut candidate = limits();
        candidate.thread_stack_bytes = usize::MAX;
        candidate.max_total_stack_bytes = usize::MAX;
        assert!(matches!(
            candidate.admit(2),
            Err(InfrastructureError::Rejected {
                code: "domain_resource_budget_invalid",
                ..
            })
        ));
    }

    #[test]
    fn pending_budget_is_global_and_rejection_preserves_existing_permits() {
        let mut configured = limits();
        configured.max_pending_control_bytes = 4096;
        let gate = Arc::new(ControlBudget {
            limits: configured,
            pending: Mutex::default(),
        });
        let first = gate.reserve(2048).unwrap();
        assert!(matches!(
            gate.reserve(2049),
            Err(InfrastructureError::ResourceBudget {
                resource: "pending_control_bytes",
                required: 4097,
                allowed: 4096
            })
        ));
        let second = gate.reserve(2048).unwrap();
        assert!(matches!(
            gate.reserve(0),
            Err(InfrastructureError::ResourceBudget {
                resource: "pending_control_requests",
                required: 3,
                allowed: 2
            })
        ));
        drop(first);
        drop(second);
        let pending = gate.pending.lock().unwrap();
        assert_eq!((pending.requests, pending.bytes), (0, 0));
    }

    #[test]
    fn timed_out_reply_keeps_permit_until_real_work_completes() {
        let mut configured = limits();
        configured.max_pending_control_requests = 1;
        let gate = Arc::new(ControlBudget {
            limits: configured,
            pending: Mutex::default(),
        });
        let permit = gate.reserve(128).unwrap();
        let (finish, unblock) = mpsc::channel();
        let (reply, response) = mpsc::sync_channel::<()>(1);
        let worker = thread::spawn(move || {
            unblock.recv().unwrap();
            drop(permit);
            let _ = reply.send(());
        });
        assert_eq!(
            response.recv_timeout(Duration::from_millis(1)),
            Err(RecvTimeoutError::Timeout)
        );
        assert!(matches!(
            gate.reserve(128),
            Err(InfrastructureError::ResourceBudget {
                resource: "pending_control_requests",
                ..
            })
        ));
        drop(response);
        finish.send(()).unwrap();
        worker.join().unwrap();
        gate.reserve(128).unwrap();
    }

    #[test]
    fn policy_queue_accounts_declaration_and_hash_allocations() {
        let mut request = Request {
            request_id: 1,
            caller_instance_id: [1; 16],
            caller_pid: 1,
            operation: Operation::ForwardFailedPrefixes {
                owner: ForwardOwner {
                    domain_id: [1; 16],
                    signed_generation: 1,
                    worker_epoch: 1,
                    fencing_token: 1,
                    auth_deadline_mono_ms: 10,
                    lease_deadline_mono_ms: 10,
                },
                failure_revision: 1,
                failed_prefixes: vec![],
            },
        };
        let Operation::ForwardFailedPrefixes { owner, .. } = request.operation else {
            unreachable!()
        };
        let routes = Vec::with_capacity(32);
        let exclusions = Vec::with_capacity(16);
        let hash = String::with_capacity(128);
        let expected = std::mem::size_of::<DomainRequest>()
            + routes.capacity() * std::mem::size_of::<candy_netd_proto::RouteDeclaration>()
            + exclusions.capacity() * std::mem::size_of::<candy_netd_proto::UnderlayExclusion>()
            + hash.capacity();
        request.operation = Operation::ForwardPolicyUpdate {
            owner,
            policy_revision: 1,
            policy_generation: 2,
            authorization_snapshot_sha256: hash,
            declaration: candy_netd_proto::PrepareDeclaration {
                table_id: 20000,
                overlay_router_ipv4: [100, 64, 0, 1],
                effective_mtu: 1398,
                routes,
                exclusions,
                firewall: candy_netd_proto::FirewallPolicy {
                    allow_forward: true,
                    clamp_tcp_mss: true,
                    require_ipv4_forwarding: true,
                    manage_rp_filter: true,
                },
            },
        };
        assert_eq!(request_queue_bytes(&request).unwrap(), expected);
    }

    #[test]
    fn queue_bytes_account_retained_vector_capacity() {
        let failed_prefixes = Vec::with_capacity(64);
        let capacity = failed_prefixes.capacity();
        let request = Request {
            request_id: 1,
            caller_instance_id: [1; 16],
            caller_pid: 1,
            operation: Operation::ForwardFailedPrefixes {
                owner: ForwardOwner {
                    domain_id: [1; 16],
                    signed_generation: 1,
                    worker_epoch: 1,
                    fencing_token: 1,
                    auth_deadline_mono_ms: 10,
                    lease_deadline_mono_ms: 10,
                },
                failure_revision: 1,
                failed_prefixes,
            },
        };
        assert_eq!(
            request_queue_bytes(&request).unwrap(),
            std::mem::size_of::<DomainRequest>() + capacity * std::mem::size_of::<Ipv4Prefix>()
        );
    }
}
