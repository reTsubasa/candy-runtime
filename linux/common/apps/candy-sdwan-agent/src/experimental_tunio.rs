use crate::{
    install_shutdown_handlers, monotonic_ms, protect_child_lifetime,
    read_core_readiness_with_policy, shutdown_requested, ReadinessPolicy, ReadinessState,
};
use anyhow::{bail, Context, Result};
use candy_netd_client::v2::InfrastructureClient;
use candy_netd_proto::v2::{Body, ForwardOwner, InfraSpec, Operation};
use candy_netd_proto::Ipv4Prefix;
use candy_netd_proto::PrepareDeclaration;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_SIGNED_CONFIG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RECOVERY_INPUT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u8,
    netd_socket: PathBuf,
    tunio: PathBuf,
    core: PathBuf,
    core_config: PathBuf,
    core_status: PathBuf,
    binding_file: PathBuf,
    instance_id: [u8; 16],
    infrastructure: InfraSpec,
    domain_id: [u8; 16],
    io_epoch: u64,
    worker_epoch: u64,
    fencing_token: u64,
    signed_generation: u64,
    auth_deadline_unix: u64,
    declaration: PrepareDeclaration,
    #[serde(default)]
    routing_namespace: Option<PathBuf>,
    #[serde(default)]
    independent_supervision: Option<IndependentSupervision>,
    #[serde(default)]
    independent_worker: Option<IndependentWorker>,
    #[serde(default)]
    authority: Option<AuthorityProof>,
    #[serde(default)]
    effective_plan_file: Option<PathBuf>,
    #[serde(default)]
    authorization_snapshot_sha256: Option<String>,
    #[serde(default)]
    pair_recovery: Option<PairRecovery>,
    #[serde(default)]
    placement: Option<WorkerPlacement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerPlacement {
    revision: u64,
    target_worker_id: u64,
    pool_directory: PathBuf,
    #[serde(default)]
    shared: Option<crate::shared_worker::SharedWorker>,
}

impl WorkerPlacement {
    fn slot_file(&self) -> PathBuf {
        self.pool_directory
            .join(format!("worker-{}.lock", self.target_worker_id))
    }
}

fn placement_changed(
    current: Option<&WorkerPlacement>,
    desired: Option<&WorkerPlacement>,
) -> Result<bool> {
    if current == desired {
        return Ok(false);
    }
    let desired = desired.context("code=worker_placement_downgrade module=runtime_agent detail=committed placement cannot be removed")?;
    if current.is_some_and(|current| desired.revision <= current.revision) {
        bail!("code=worker_placement_stale module=runtime_agent detail=target slot change requires a strictly newer local placement revision");
    }
    Ok(true)
}

fn validate_worker_placement(
    plan: &Plan,
    record: &crate::process_record::ManagedProcessRecord,
    status: &serde_json::Value,
) -> Result<()> {
    let Some(placement) = &plan.placement else {
        return Ok(());
    };
    let expected = fs::symlink_metadata(placement.slot_file())?;
    let actual = &status["worker_placement"];
    let fd = actual["slot_fd"].as_i64().filter(|fd| *fd > 2 && *fd <= i32::MAX as i64)
        .context("code=worker_slot_proof_missing module=runtime_agent detail=Core live inherited OS slot descriptor absent")?;
    let inherited = fs::metadata(format!("/proc/{}/fd/{fd}", record.pid))?;
    if !expected.is_file()
        || expected.uid() != nix::unistd::geteuid().as_raw()
        || expected.mode() & 0o777 != 0o600
        || actual["worker_id"] != placement.target_worker_id
        || actual["revision"] != placement.revision
        || actual["slot_device"] != expected.dev()
        || actual["slot_inode"] != expected.ino()
        || (inherited.dev(), inherited.ino()) != (expected.dev(), expected.ino())
    {
        bail!("code=worker_slot_proof_mismatch module=runtime_agent detail=actual Core PID descriptor or authenticated live slot/revision differs from selected worker");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PairRecovery {
    original_io_epoch: u64,
    boot_id: String,
    auth_deadline_mono_ms: u64,
    #[serde(default)]
    retired_renewal_journal: Option<PathBuf>,
    #[serde(default)]
    authorization_snapshot_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuthorityProof {
    revision: u64,
    sha256: String,
    transaction_id: String,
}

#[path = "signed_renewal.rs"]
mod signed_renewal;

pub(super) fn renew_authority(path: &Path) -> Result<()> {
    signed_renewal::run(path)
}

pub(super) fn static_identity(path: &Path) -> Result<([u8; 16], [u8; 16], Vec<PathBuf>)> {
    if !path.is_absolute() {
        bail!("domain plan path must be absolute");
    }
    let plan = read_plan(path)?;
    let mut paths = vec![plan.binding_file, plan.core_status];
    if let Some(io) = plan.independent_supervision {
        paths.extend([io.control_socket, io.status, io.process_record]);
    }
    if let Some(worker) = plan.independent_worker {
        paths.extend([worker.control_socket, worker.process_record]);
    }
    if let Some(namespace) = plan.routing_namespace {
        paths.push(namespace);
    }
    Ok((plan.domain_id, plan.infrastructure.infra_id, paths))
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RecoveryDisposition {
    Start,
    Adopt,
    RecoverPair,
    RebindCore,
    RenewAuthority,
}

pub(super) fn recovery_disposition(path: &Path) -> Result<RecoveryDisposition> {
    use candy_process_control::{process_is_current, ProcessIdentity};
    let plan = recovery_plan(verified_plan(path)?)?;
    let Some(worker) = &plan.independent_worker else {
        if plan.binding_file.try_exists()? {
            bail!("existing packet binding requires independent process records before recovery");
        }
        return Ok(RecoveryDisposition::Start);
    };
    let io = plan.independent_supervision.as_ref().unwrap();
    if cfg!(feature = "experimental-tunio-rebind") {
        if let Ok(record) = crate::process_record::read(&io.process_record) {
            let io_alive = process_is_current(ProcessIdentity {
                pid: record.pid,
                start_ticks: record.process_start_ticks,
            });
            let pair_recorded = crate::process_record::read(&worker.process_record).is_ok();
            if pair_recovery_precedes_renewal(io_alive, pair_recorded) {
                preserve_unrecorded_endpoint(&io.control_socket)?;
                return Ok(RecoveryDisposition::RecoverPair);
            }
        }
        if let Ok(record) = crate::process_record::read(&io.process_record) {
            if process_is_current(ProcessIdentity {
                pid: record.pid,
                start_ticks: record.process_start_ticks,
            }) {
                record.validate_infrastructure_current(&plan.tunio)?;
                if record.infrastructure_generation != plan.infrastructure.generation
                    || record.io_epoch.is_some_and(|epoch| epoch != plan.io_epoch)
                {
                    bail!("live I/O differs from immutable infrastructure identity");
                }
                if record.policy_generation != plan.signed_generation
                    || record.auth_deadline_unix != plan.auth_deadline_unix
                {
                    return Ok(RecoveryDisposition::RenewAuthority);
                }
            }
        }
        if let Ok(record) = crate::process_record::read(&worker.process_record) {
            if let Some(effective) = &record.effective_plan_file {
                let current = read_plan(effective)?;
                if current.infrastructure != plan.infrastructure
                    || current.domain_id != plan.domain_id
                    || !same_io_lineage(&current, &plan)
                {
                    bail!("code=worker_placement_scope_mismatch module=runtime_agent detail=committed local worker scope differs from verified desired infrastructure");
                }
                if placement_changed(current.placement.as_ref(), plan.placement.as_ref())? {
                    return Ok(RecoveryDisposition::RenewAuthority);
                }
            }
            if let Some(hash) = record.authorization_snapshot_sha256 {
                let (_, report) = compile_verified_plan(plan.clone())?;
                if report["authorization_snapshot_sha256"] != hash {
                    return Ok(RecoveryDisposition::RenewAuthority);
                }
            }
        }
    }
    let mut live = Vec::new();
    let mut records = 0;
    for (record_path, executable, endpoint) in [
        (&worker.process_record, &plan.core, &worker.control_socket),
        (&io.process_record, &plan.tunio, &io.control_socket),
    ] {
        let record = match crate::process_record::read(record_path) {
            Ok(record) => record,
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
                }) =>
            {
                preserve_unrecorded_endpoint(endpoint)?;
                live.push(false);
                continue;
            }
            Err(error) => {
                return Err(error.context("cannot safely inspect existing process record"))
            }
        };
        records += 1;
        let current = record.business_is_current()?;
        if current {
            record.validate_identity(executable, unix_time()?)?;
            if record.policy_generation != plan.signed_generation
                || record.infrastructure_generation != plan.infrastructure.generation
                || record.auth_deadline_unix != plan.auth_deadline_unix
            {
                bail!("existing process binding differs from verified recovery plan");
            }
            if record.validate_current(executable, unix_time()?).is_err() {
                return Err(ManagedProofPending.into());
            }
        } else {
            preserve_unrecorded_endpoint(endpoint)?;
        }
        live.push(current);
    }
    match (live[0], live[1]) {
        (true, true) => Ok(RecoveryDisposition::Adopt),
        (false, true) => Ok(RecoveryDisposition::RebindCore),
        (true, false) => Ok(RecoveryDisposition::RecoverPair),
        (false, false) => {
            if records == 2 && cfg!(feature = "experimental-tunio-rebind") {
                return Ok(RecoveryDisposition::RecoverPair);
            }
            if plan.binding_file.try_exists()? {
                if records != 2 {
                    bail!("existing binding lacks both process records; refusing duplicate activation");
                }
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                    .open(&plan.binding_file)?;
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != nix::unistd::geteuid().as_raw()
                    || metadata.mode() & 0o777 != 0o600
                    || metadata.len() > 4096
                {
                    bail!("stale binding is not a private bounded regular file");
                }
                let binding: serde_json::Value = serde_json::from_reader(file.take(4097))?;
                if binding["infrastructure_id"] != serde_json::json!(plan.infrastructure.infra_id)
                    || binding["routing_domain_id"] != serde_json::json!(plan.domain_id)
                    || binding["policy_generation"] != plan.signed_generation
                    || binding["owner_epoch"] != plan.worker_epoch
                    || binding["io_epoch"] != plan.io_epoch
                {
                    bail!("stale binding differs from recovery plan");
                }
                fs::remove_file(&plan.binding_file)?;
            }
            Ok(RecoveryDisposition::Start)
        }
    }
}

fn pair_recovery_precedes_renewal(io_alive: bool, pair_recorded: bool) -> bool {
    !io_alive && pair_recorded
}

fn preserve_unrecorded_endpoint(endpoint: &Path) -> Result<()> {
    match candy_process_control::inspect_endpoint_process(endpoint) {
        Ok(identity) if candy_process_control::process_is_current(identity) => {
            // A kernel-authenticated live endpoint is a reason to wait, never adoption proof.
            Err(ManagedProofPending.into())
        }
        Ok(_) => Ok(()),
        Err(error)
            if error.chain().any(|cause| {
                cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                    matches!(
                        io.raw_os_error(),
                        Some(nix::libc::ENOENT | nix::libc::ECONNREFUSED)
                    )
                }) || cause
                    .downcast_ref::<nix::errno::Errno>()
                    .is_some_and(|errno| {
                        matches!(
                            errno,
                            nix::errno::Errno::ENOENT | nix::errno::Errno::ECONNREFUSED
                        )
                    })
            }) =>
        {
            Ok(())
        }
        Err(error) => Err(error.context("cannot safely inspect an unrecorded control endpoint")),
    }
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
fn remove_retired_control_endpoint(endpoint: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    preserve_unrecorded_endpoint(endpoint)?;
    match fs::symlink_metadata(endpoint) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == nix::unistd::geteuid().as_raw() =>
        {
            fs::remove_file(endpoint).with_context(|| {
                format!("code=retired_control_remove_failed module=process_supervisor path={} detail=remove proven-dead private socket", endpoint.display())
            })
        }
        Ok(_) => bail!("retired control endpoint is not an owned Unix socket"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn recovery_inputs(path: &Path) -> Result<Vec<u8>> {
    let plan = read_plan(path)?;
    let mut inputs = Vec::new();
    for (path, limit) in [
        (path, MAX_SIGNED_CONFIG_BYTES),
        (plan.core_config.as_path(), MAX_SIGNED_CONFIG_BYTES),
    ] {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > limit {
            bail!("recovery inputs require bounded regular files");
        }
        let before = inputs.len();
        file.take(limit + 1).read_to_end(&mut inputs)?;
        if inputs.len() as u64 > MAX_RECOVERY_INPUT_BYTES {
            bail!("code=recovery_input_budget_exceeded module=sdwan_activation detail=plan and signed inputs exceed 32 MiB");
        }
        if (inputs.len() - before) as u64 > limit {
            bail!("code=recovery_input_file_limit module=sdwan_activation detail=plan or Core config exceeds 8 MiB");
        }
        inputs.push(0);
    }
    #[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
    inputs.extend(crate::signed_snapshot::fingerprint(&plan.core_config)?);
    if inputs.len() as u64 > MAX_RECOVERY_INPUT_BYTES {
        bail!("code=recovery_input_budget_exceeded module=sdwan_activation detail=plan and signed inputs exceed 32 MiB");
    }
    Ok(inputs)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IndependentSupervision {
    control_socket: PathBuf,
    status: PathBuf,
    process_record: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IndependentWorker {
    control_socket: PathBuf,
    process_record: PathBuf,
}

fn read_plan(path: &Path) -> Result<Plan> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.len() > MAX_SIGNED_CONFIG_BYTES
    {
        bail!("experimental plan requires private bounded 0600 regular file");
    }
    let mut bytes = Vec::new();
    file.take(MAX_SIGNED_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SIGNED_CONFIG_BYTES {
        bail!("experimental plan too large");
    }
    let plan: Plan = serde_json::from_slice(&bytes)?;
    if plan.schema_version != 1
        || plan.instance_id == [0; 16]
        || plan.domain_id == [0; 16]
        || plan.io_epoch == 0
        || plan.worker_epoch == 0
        || plan.signed_generation == 0
    {
        bail!("experimental plan identity invalid");
    }
    for path in [
        &plan.netd_socket,
        &plan.tunio,
        &plan.core,
        &plan.core_config,
        &plan.core_status,
        &plan.binding_file,
    ] {
        if !path.is_absolute() {
            bail!("experimental paths must be absolute");
        }
    }
    plan.infrastructure.validate()?;
    plan.declaration.validate()?;
    if let Some(supervision) = &plan.independent_supervision {
        for path in [
            &supervision.control_socket,
            &supervision.status,
            &supervision.process_record,
        ] {
            if !path.is_absolute() {
                bail!("independent supervision paths must be absolute");
            }
        }
    }
    if let Some(worker) = &plan.independent_worker {
        if plan.independent_supervision.is_none()
            || !worker.control_socket.is_absolute()
            || !worker.process_record.is_absolute()
        {
            bail!("independent worker requires independent TUN I/O and absolute private paths");
        }
    }
    if let Some(placement) = &plan.placement {
        if !cfg!(all(
            feature = "experimental-tunio-rebind",
            target_os = "linux"
        )) || plan.independent_worker.is_none()
            || placement.revision == 0
            || placement.target_worker_id == 0
            || !placement.pool_directory.is_absolute()
        {
            bail!("code=worker_placement_invalid module=runtime_agent detail=Linux independent domain worker, nonzero slot/revision and private absolute pool directory required");
        }
        let directory = fs::symlink_metadata(&placement.pool_directory)?;
        if !directory.is_dir()
            || directory.uid() != nix::unistd::geteuid().as_raw()
            || directory.mode() & 0o077 != 0
        {
            bail!("code=worker_pool_directory_invalid module=runtime_agent detail=worker slot manager requires current-user private directory");
        }
    }
    if plan.infrastructure.overlay_router_ipv4 != plan.declaration.overlay_router_ipv4
        || plan.infrastructure.mtu != plan.declaration.effective_mtu
    {
        bail!("infrastructure and forwarding declaration disagree");
    }
    Ok(plan)
}

struct NetdControl {
    client: InfrastructureClient,
    scope: Option<([u8; 16], [u8; 16])>,
}
impl NetdControl {
    fn new(plan: &Plan) -> Self {
        Self {
            client: InfrastructureClient::new(&plan.netd_socket, plan.instance_id),
            scope: plan
                .routing_namespace
                .as_ref()
                .map(|_| (plan.domain_id, plan.infrastructure.infra_id)),
        }
    }
    fn exchange(&mut self, operation: Operation) -> Result<(Body, Option<std::os::fd::OwnedFd>)> {
        let result = if !matches!(operation, Operation::Capabilities) {
            if let Some((domain, infra)) = self.scope {
                self.client.exchange_in_domain(domain, infra, operation)
            } else {
                self.client.exchange(operation)
            }
        } else {
            self.client.exchange(operation)
        };
        result.map_err(|error| {
            let error = anyhow::Error::new(error);
            if error.chain().any(|cause| {
                cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                    matches!(
                        io.kind(),
                        std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::TimedOut
                    )
                })
            }) {
                error.context(NetdUnavailable)
            } else {
                error
            }
        })
    }
}

fn enter_routing_namespace(command: &mut Command, plan: &Plan) -> Result<()> {
    let Some(path) = &plan.routing_namespace else {
        return Ok(());
    };
    if !path.is_absolute() {
        bail!("routing namespace path must be absolute");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.dev() != plan.infrastructure.netns_device
        || metadata.ino() != plan.infrastructure.netns_inode
    {
        bail!("routing namespace differs from configured infrastructure identity");
    }
    #[cfg(target_os = "linux")]
    {
        unsafe {
            command.pre_exec(move || {
                if nix::libc::setns(file.as_raw_fd(), nix::libc::CLONE_NEWNET) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
        bail!("multi-domain namespace execution requires Linux");
    }
}

fn expect_ack(client: &mut NetdControl, operation: Operation) -> Result<()> {
    let (body, fd) = client.exchange(operation)?;
    if fd.is_some() {
        bail!("Agent must never receive the TUN fd in packet-port mode");
    }
    match body {
        Body::Ack => Ok(()),
        Body::InfraStatus { spec: Some(_), .. } => Ok(()),
        Body::Error {
            code,
            module,
            reason,
        } => Err(NetdActivationFailure {
            code,
            module,
            reason,
        }
        .into()),
        _ => bail!("unexpected netd control reply"),
    }
}

#[derive(Debug)]
pub(super) struct NetdActivationFailure {
    code: String,
    module: String,
    reason: String,
}

impl NetdActivationFailure {
    pub(super) fn retryable(&self) -> bool {
        matches!(
            self.code.as_str(),
            "domain_worker_busy" | "domain_front_busy" | "domain_operation_pending"
        )
    }
}

impl std::fmt::Display for NetdActivationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "code={} module={} detail={}",
            self.code, self.module, self.reason
        )
    }
}

impl std::error::Error for NetdActivationFailure {}

#[derive(Debug)]
pub(super) struct CoreRecoveryRequired;
impl std::fmt::Display for CoreRecoveryRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("code=business_worker_exited module=process_supervisor detail=original Core exited before authorization; preserve live TUNIO and retry authenticated rebind")
    }
}
impl std::error::Error for CoreRecoveryRequired {}

#[derive(Debug)]
pub(super) struct PairRecoveryRequired;
impl std::fmt::Display for PairRecoveryRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("code=packet_pair_recovery_required module=process_supervisor detail=TUNIO exited; retry this domain's Core and IO pair while preserving netd infrastructure")
    }
}
impl std::error::Error for PairRecoveryRequired {}

#[derive(Debug)]
pub(super) struct NetdUnavailable;
impl std::fmt::Display for NetdUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("code=netd_temporarily_unavailable module=sdwan_activation detail=control transport interrupted; retry with original infrastructure identity")
    }
}
impl std::error::Error for NetdUnavailable {}

#[derive(Debug)]
pub(super) struct ManagedProofPending;
impl std::fmt::Display for ManagedProofPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("code=managed_process_proof_pending module=process_supervisor detail=original recorded process epoch remains; await its bound status before adopting or replacing")
    }
}
impl std::error::Error for ManagedProofPending {}

#[derive(Debug)]
pub(super) struct DesiredStateChanged;
impl std::fmt::Display for DesiredStateChanged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("code=desired_authority_changed module=runtime_agent detail=desired signed plan changed; preserve current Core/IO while verifying the candidate")
    }
}
impl std::error::Error for DesiredStateChanged {}

#[cfg(target_os = "linux")]
fn publish_worker_record(plan: &Plan, pid: u32, token: &str) -> Result<()> {
    let Some(worker) = &plan.independent_worker else {
        return Ok(());
    };
    let mut record = crate::process_record::ManagedProcessRecord::capture(
        pid,
        &plan.core,
        &plan.core_status,
        token,
        plan.infrastructure.generation,
        plan.signed_generation,
        plan.auth_deadline_unix,
    )?;
    record.worker_epoch = Some(plan.worker_epoch);
    record.io_epoch = Some(plan.io_epoch);
    record.packet_binding_file = Some(plan.binding_file.clone());
    record.effective_plan_file = plan.effective_plan_file.clone();
    record.authorization_snapshot_sha256 = plan.authorization_snapshot_sha256.clone();
    bind_shared_record(plan, &mut record);
    crate::process_record::publish(&worker.process_record, &record)?;
    confirm_registration(&record, &worker.control_socket, plan.auth_deadline_unix)?;
    if plan.placement.is_some() {
        validate_worker_placement(plan, &record, &record.private_status()?)?;
    }
    Ok(())
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
fn bind_shared_record(plan: &Plan, record: &mut crate::process_record::ManagedProcessRecord) {
    record.shared_worker = plan
        .placement
        .as_ref()
        .and_then(|placement| placement.shared.clone());
    record.shared_domain_instance = record.shared_worker.as_ref().and_then(|_| {
        plan.independent_worker
            .as_ref()
            .map(|worker| worker.control_socket.clone())
    });
}

fn business_is_current(
    plan: &Plan,
    identity: candy_process_control::ProcessIdentity,
) -> Result<bool> {
    if !candy_process_control::process_is_current(identity) {
        return Ok(false);
    }
    if let Some(host) = plan
        .placement
        .as_ref()
        .and_then(|placement| placement.shared.as_ref())
    {
        anyhow::ensure!(
            host.identity == identity,
            "shared worker live identity differs"
        );
        return crate::shared_worker::domain_running(
            host,
            &plan
                .independent_worker
                .as_ref()
                .context("shared worker domain control absent")?
                .control_socket,
        );
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn confirm_registration(
    record: &crate::process_record::ManagedProcessRecord,
    socket: &Path,
    auth_deadline_unix: u64,
) -> Result<()> {
    let managed = candy_process_control::ProcessIdentity {
        pid: record.pid,
        start_ticks: record.process_start_ticks,
    };
    let controller = candy_process_control::process_identity(std::process::id())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if shutdown_requested() || unix_time()? >= auth_deadline_unix {
            bail!("managed process registration cancelled or authorization expired");
        }
        if !candy_process_control::process_is_current(managed) {
            return Err(CoreRecoveryRequired.into());
        }
        let request = candy_process_control::ControlRequest {
            schema_version: 1,
            operation: candy_process_control::ControlOperation::Probe,
            token_sha256: record.readiness_token_sha256.clone(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
        };
        match candy_process_control::exchange(socket, managed, &request) {
            Ok(reply) if reply.controller == controller && reply.controller_epoch != 0 => {
                return Ok(())
            }
            Ok(_) => bail!("managed process registration controller mismatch"),
            Err(error) if Instant::now() >= deadline => {
                return Err(error.context("bounded process registration handshake expired"))
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_io_registration(
    record: &crate::process_record::ManagedProcessRecord,
    executable: &Path,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if shutdown_requested() || unix_time()? >= record.auth_deadline_unix {
            bail!("code=io_registration_cancelled module=process_supervisor detail=shutdown or authorization expiry while awaiting active IO proof");
        }
        match record.validate_infrastructure_current(executable) {
            Ok(()) => return Ok(()),
            Err(error) if Instant::now() >= deadline => {
                return Err(error.context(format!("code=io_registration_timeout module=process_supervisor pid={} status={} detail=registration ACK preceded active infrastructure publication", record.pid,record.status_path.display())));
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn inherit_packet_socket(command: &mut Command, socket: &UnixDatagram) {
    let fd = socket.as_raw_fd();
    // Clear only the selected socket in the child, leaving every other parent fd CLOEXEC.
    unsafe {
        command.pre_exec(move || {
            nix::fcntl::fcntl(
                fd,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
            )
            .map(|_| ())
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
        });
    }
}

fn reserve_worker_slot(plan: &Plan) -> Result<Option<File>> {
    let Some(placement) = &plan.placement else {
        return Ok(None);
    };
    if placement.shared.is_some() {
        return Ok(None);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(placement.slot_file())?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        bail!("code=worker_slot_file_invalid module=runtime_agent detail=selected OS worker slot is not a private regular file");
    }
    // The child inherits this same open file description; it owns the lock
    // after the manager drops its copy, until the actual process exits.
    let locked =
        unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) };
    if locked != 0 {
        return Err(std::io::Error::last_os_error()).context("code=worker_slot_busy module=runtime_agent detail=selected worker already belongs to another live domain");
    }
    Ok(Some(file))
}

fn spawn_business_worker(
    plan: &Plan,
    socket: &UnixDatagram,
    token: &str,
) -> Result<crate::shared_worker::BusinessWorker> {
    spawn_business_worker_with_slot(plan, socket, token, reserve_worker_slot(plan)?)
}

fn spawn_business_worker_with_slot(
    plan: &Plan,
    socket: &UnixDatagram,
    token: &str,
    slot: Option<File>,
) -> Result<crate::shared_worker::BusinessWorker> {
    if let Some(placement) = &plan.placement {
        if let Some(host) = &placement.shared {
            let worker = plan
                .independent_worker
                .as_ref()
                .context("shared worker requires private domain control")?;
            let mut arguments = vec![
                "run".to_owned(),
                "--experimental-packet-port-ipc".to_owned(),
                "--experimental-independent-worker".to_owned(),
            ];
            for (name, value) in [
                ("--config", plan.core_config.display().to_string()),
                (
                    "--packet-port-binding-file",
                    plan.binding_file.display().to_string(),
                ),
                ("--status", plan.core_status.display().to_string()),
                ("--readiness-token", token.to_owned()),
                (
                    "--worker-control-socket",
                    worker.control_socket.display().to_string(),
                ),
                (
                    "--worker-auth-deadline-unix",
                    plan.auth_deadline_unix.to_string(),
                ),
                (
                    "--worker-placement-revision",
                    placement.revision.to_string(),
                ),
            ] {
                arguments.extend([name.to_owned(), value]);
            }
            if let Some(recovery) = &plan.pair_recovery {
                arguments.extend([
                    "--worker-auth-deadline-mono-ms".to_owned(),
                    recovery.auth_deadline_mono_ms.to_string(),
                ]);
            }
            if let Some(authority) = &plan.authority {
                arguments.extend([
                    "--worker-authority-revision".to_owned(),
                    authority.revision.to_string(),
                    "--worker-authority-sha256".to_owned(),
                    authority.sha256.clone(),
                    "--worker-transaction-id".to_owned(),
                    authority.transaction_id.clone(),
                ]);
            }
            let namespace = plan
                .routing_namespace
                .as_ref()
                .map(File::open)
                .transpose()?
                .map(std::os::fd::OwnedFd::from);
            return Ok(crate::shared_worker::BusinessWorker::Shared(
                crate::shared_worker::SharedDomain::start(
                    host.clone(),
                    &worker.control_socket,
                    token,
                    &arguments,
                    socket.as_raw_fd(),
                    namespace.as_ref(),
                )?,
            ));
        }
    }
    let mut command = Command::new(&plan.core);
    enter_routing_namespace(&mut command, plan)?;
    protect_child_lifetime(&mut command);
    inherit_packet_socket(&mut command, socket);
    command
        .args(["client", "sdwan", "run", "--experimental-packet-port-ipc"])
        .arg("--config")
        .arg(&plan.core_config)
        .arg("--packet-port-fd")
        .arg(socket.as_raw_fd().to_string())
        .arg("--packet-port-binding-file")
        .arg(&plan.binding_file)
        .arg("--status")
        .arg(&plan.core_status)
        .arg("--readiness-token")
        .arg(token);
    if let Some(worker) = &plan.independent_worker {
        command
            .arg("--experimental-independent-worker")
            .arg("--worker-control-socket")
            .arg(&worker.control_socket)
            .arg("--worker-auth-deadline-unix")
            .arg(plan.auth_deadline_unix.to_string());
        if let Some(recovery) = &plan.pair_recovery {
            command
                .arg("--worker-auth-deadline-mono-ms")
                .arg(recovery.auth_deadline_mono_ms.to_string());
        }
        if let Some(authority) = &plan.authority {
            command
                .arg("--worker-authority-revision")
                .arg(authority.revision.to_string())
                .arg("--worker-authority-sha256")
                .arg(&authority.sha256)
                .arg("--worker-transaction-id")
                .arg(&authority.transaction_id);
        }
    }
    if let Some(placement) = &plan.placement {
        let slot = slot.as_ref().context("reserved worker slot absent")?;
        let fd = slot.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                nix::fcntl::fcntl(
                    fd,
                    nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
                )
                .map(|_| ())
                .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
            });
        }
        command
            .arg("--worker-id")
            .arg(placement.target_worker_id.to_string())
            .arg("--worker-placement-revision")
            .arg(placement.revision.to_string())
            .arg("--worker-slot-fd")
            .arg(fd.to_string())
            .arg("--worker-slot-file")
            .arg(placement.slot_file());
    }
    command
        .spawn()
        .map(crate::shared_worker::BusinessWorker::Dedicated)
        .context("spawn packet-port business worker")
}

fn create_binding(plan: &Plan) -> Result<()> {
    let binding = serde_json::json!({"infrastructure_id":plan.infrastructure.infra_id,"routing_domain_id":plan.domain_id,"infrastructure_generation":plan.infrastructure.generation,"io_epoch":plan.io_epoch,"owner_epoch":plan.worker_epoch,"policy_generation":plan.signed_generation});
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&plan.binding_file)
        .context("create immutable packet binding (new path required per activation)")?;
    file.write_all(&serde_json::to_vec(&binding)?)?;
    file.sync_all()?;
    Ok(())
}

fn stop(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn stop_business(child: &mut crate::shared_worker::BusinessWorker) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn unix_time() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

#[cfg(test)]
fn bounded_compile_control(command: &mut Command, timeout: Duration) -> Result<Output> {
    bounded_compile_control_inner(command, timeout, false)
}

fn bounded_compile_control_inner(
    command: &mut Command,
    timeout: Duration,
    cancel_shutdown: bool,
) -> Result<Output> {
    const MAX_OUTPUT: usize = MAX_SIGNED_CONFIG_BYTES as usize;
    fn drain(pipe: &mut impl Read, bytes: &mut Vec<u8>) -> Result<()> {
        let mut chunk = [0_u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    if bytes.len().saturating_add(count) > MAX_OUTPUT {
                        bail!("code=signed_control_output_limit module=sdwan_activation detail=Core verification output exceeds eight MiB");
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let result = (|| {
        let mut stdout_pipe = child.stdout.take().context("Core compile stdout absent")?;
        let mut stderr_pipe = child.stderr.take().context("Core compile stderr absent")?;
        for fd in [stdout_pipe.as_raw_fd(), stderr_pipe.as_raw_fd()] {
            let flags = nix::fcntl::OFlag::from_bits_truncate(nix::fcntl::fcntl(
                fd,
                nix::fcntl::FcntlArg::F_GETFL,
            )?);
            nix::fcntl::fcntl(
                fd,
                nix::fcntl::FcntlArg::F_SETFL(flags | nix::fcntl::OFlag::O_NONBLOCK),
            )?;
        }
        let deadline = Instant::now() + timeout;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            drain(&mut stdout_pipe, &mut stdout)?;
            drain(&mut stderr_pipe, &mut stderr)?;
            if let Some(status) = child.try_wait()? {
                drain(&mut stdout_pipe, &mut stdout)?;
                drain(&mut stderr_pipe, &mut stderr)?;
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            if Instant::now() >= deadline {
                bail!("code=signed_control_compile_timeout module=sdwan_activation detail=Core signature verification exceeded its deadline");
            }
            if cancel_shutdown && shutdown_requested() {
                bail!("code=signed_control_compile_cancelled module=sdwan_activation detail=supervisor shutdown cancelled signature verification");
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        stop(&mut child);
    }
    result
}

#[derive(Debug, Clone)]
struct FailureSnapshot {
    revision: u64,
    reported_at_mono_ms: u64,
    prefixes: Vec<Ipv4Prefix>,
}

fn validate_failure_snapshot(
    snapshot: &FailureSnapshot,
    previous: Option<&FailureSnapshot>,
    now: u64,
) -> Result<()> {
    if snapshot.revision == 0
        || snapshot.reported_at_mono_ms == 0
        || snapshot.reported_at_mono_ms > now.saturating_add(50)
        || now.saturating_sub(snapshot.reported_at_mono_ms) > 5000
    {
        bail!("code=forward_snapshot_stale module=sdwan_activation detail=missing, future or older than five seconds");
    }
    if let Some(previous) = previous {
        if snapshot.revision < previous.revision
            || snapshot.reported_at_mono_ms < previous.reported_at_mono_ms
        {
            bail!("code=forward_snapshot_replayed module=sdwan_activation detail=revision or report time went backwards");
        }
        if snapshot.revision == previous.revision && snapshot.prefixes != previous.prefixes {
            bail!("code=forward_snapshot_conflict module=sdwan_activation detail=same revision contains a different failed set");
        }
    }
    Ok(())
}

fn validate_compiled_declaration(report: &serde_json::Value, plan: &Plan) -> Result<()> {
    let domain_hex = plan
        .domain_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if report["segment_id"] != domain_hex {
        bail!("experimental routing domain differs from verified signed control");
    }
    let netd = &report["netd"];
    if netd["table_id"] != plan.declaration.table_id
        || netd["max_inner_mtu"] != plan.declaration.effective_mtu
        || netd["overlay_router_ipv4"]
            != std::net::Ipv4Addr::from(plan.declaration.overlay_router_ipv4).to_string()
    {
        bail!("experimental declaration identity differs from verified signed control");
    }
    let mut routes = Vec::new();
    for prefix in netd["local_prefixes"]
        .as_array()
        .context("signed local prefixes absent")?
    {
        routes.push(candy_netd_proto::RouteDeclaration {
            prefix: crate::parse_prefix(prefix.as_str().context("invalid signed prefix")?)?,
            kind: candy_netd_proto::RouteKind::Local,
        });
    }
    for route in netd["remote_routes"]
        .as_array()
        .context("signed remote routes absent")?
    {
        let kind = match route["kind"].as_str() {
            Some("remote") => candy_netd_proto::RouteKind::Remote,
            Some("remote-egress") => candy_netd_proto::RouteKind::RemoteEgress,
            Some("remote-egress-gateway") => candy_netd_proto::RouteKind::RemoteEgressGateway,
            _ => bail!("unknown signed route kind"),
        };
        routes.push(candy_netd_proto::RouteDeclaration {
            prefix: crate::parse_prefix(
                route["destination"]
                    .as_str()
                    .context("invalid signed remote prefix")?,
            )?,
            kind,
        });
    }
    routes.sort_by_key(|route| (route.prefix, route.kind as u64));
    if routes != plan.declaration.routes {
        bail!("experimental routes differ from verified signed control");
    }
    for prefix in netd["underlay_ipv4_exclusions"]
        .as_array()
        .context("signed underlay exclusions absent")?
    {
        let prefix = crate::parse_prefix(prefix.as_str().context("invalid signed exclusion")?)?;
        if !plan
            .declaration
            .exclusions
            .iter()
            .any(|entry| entry.prefix == prefix)
        {
            bail!("experimental plan omits a signed underlay exclusion");
        }
    }
    Ok(())
}

fn sync_failed_prefixes(
    netd: &mut NetdControl,
    plan: &Plan,
    worker_pid: u32,
    token: &str,
    owner: &ForwardOwner,
    worker_identity: candy_process_control::ProcessIdentity,
    previous: &mut Option<FailureSnapshot>,
) -> Result<()> {
    if !candy_process_control::process_is_current(worker_identity) {
        bail!("code=forward_snapshot_process_changed module=sdwan_activation detail=Core PID epoch no longer current");
    }
    let Some(status) =
        crate::read_core_status(&plan.core_status, plan.signed_generation, worker_pid, token)?
    else {
        return Ok(());
    };
    if status.policy_generation != 0 && status.policy_generation != plan.signed_generation {
        bail!("immutable packet-port binding cannot use a newer policy generation");
    }
    if !status.ready_report_verified {
        bail!("code=forward_snapshot_unverified module=sdwan_activation detail=Core route-owner snapshot lacks verified packet-path proof");
    }
    let Some(reported) = crate::parse_failed_prefixes(&status, &plan.declaration)? else {
        return Ok(());
    };
    let mut reported = reported;
    reported.sort_unstable();
    reported.dedup();
    let snapshot = FailureSnapshot {
        revision: status
            .failure_revision
            .context("Core lacks authoritative failure revision")?,
        reported_at_mono_ms: status
            .reported_at_mono_ms
            .context("Core lacks authoritative report clock")?,
        prefixes: reported,
    };
    validate_failure_snapshot(&snapshot, previous.as_ref(), monotonic_ms()?)?;
    if previous
        .as_ref()
        .is_none_or(|old| old.revision != snapshot.revision)
    {
        expect_ack(
            netd,
            Operation::ForwardFailedPrefixes {
                owner: owner.clone(),
                failed_prefixes: snapshot.prefixes.clone(),
                failure_revision: snapshot.revision,
            },
        )?;
        eprintln!("level=info code=forward_prefix_snapshot_applied module=sdwan_activation generation={} failure_revision={} failed_prefixes={} action=restore_verified_routes_preserve_unaffected_routes",plan.signed_generation,snapshot.revision,snapshot.prefixes.len());
    }
    *previous = Some(snapshot);
    Ok(())
}

fn verified_plan(path: &Path) -> Result<Plan> {
    Ok(compile_verified_plan(read_plan(path)?)?.0)
}

fn effective_worker_plan(
    desired: Plan,
    record: &crate::process_record::ManagedProcessRecord,
) -> Result<Plan> {
    let Some(path) = &record.effective_plan_file else {
        return Ok(desired);
    };
    let (current, current_report) = compile_verified_plan(read_plan(path)?)?;
    let (desired, desired_report) = compile_verified_plan(desired)?;
    if current_report["authorization_snapshot_sha256"]
        != desired_report["authorization_snapshot_sha256"]
        || current.infrastructure != desired.infrastructure
        || current.domain_id != desired.domain_id
        || !same_io_lineage(&current, &desired)
        || current.auth_deadline_unix != desired.auth_deadline_unix
    {
        return Err(DesiredStateChanged.into());
    }
    if placement_changed(current.placement.as_ref(), desired.placement.as_ref())? {
        return Err(DesiredStateChanged.into());
    }
    Ok(current)
}

fn same_io_lineage(current: &Plan, desired: &Plan) -> bool {
    match &current.pair_recovery {
        Some(recovery) => {
            let original = desired
                .pair_recovery
                .as_ref()
                .map_or(desired.io_epoch, |desired| desired.original_io_epoch);
            recovery.original_io_epoch == original
                && current.io_epoch > original
                && (desired.pair_recovery.is_none() || current.io_epoch == desired.io_epoch)
        }
        None => current.io_epoch == desired.io_epoch,
    }
}

#[cfg(not(all(feature = "experimental-tunio-rebind", target_os = "linux")))]
fn recovery_plan(plan: Plan) -> Result<Plan> {
    Ok(plan)
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
fn recovery_plan(desired: Plan) -> Result<Plan> {
    let path = desired.core_status.with_extension("pair-recovery.json");
    if !path.try_exists()? {
        if let Some(worker) = &desired.independent_worker {
            if let Ok(record) = crate::process_record::read(&worker.process_record) {
                if let Some(effective) = &record.effective_plan_file {
                    if read_plan(effective)?.pair_recovery.is_some() {
                        let current = read_plan(effective)?;
                        return project_recovered_io(desired, current);
                    }
                }
            }
        }
        return Ok(desired);
    }
    let mut candidate = read_plan(&path)?;
    if let Some(worker) = &desired.independent_worker {
        if let Ok(record) = crate::process_record::read(&worker.process_record) {
            if let Some(effective) = &record.effective_plan_file {
                let committed = read_plan(effective)?;
                if committed.io_epoch == candidate.io_epoch
                    && committed.worker_epoch >= candidate.worker_epoch
                    && committed.pair_recovery.is_some()
                    && committed.infrastructure == candidate.infrastructure
                    && committed.domain_id == candidate.domain_id
                {
                    candidate = committed;
                }
            }
        }
    }
    project_recovered_io(desired, candidate)
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
fn project_recovered_io(mut desired: Plan, candidate: Plan) -> Result<Plan> {
    let recovery = candidate
        .pair_recovery
        .as_ref()
        .context("pair recovery receipt absent")?;
    if recovery.boot_id != fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() {
        bail!("code=pair_recovery_authorization_expired module=process_supervisor detail=original boot authorization cap expired or boot changed");
    }
    if candidate.infrastructure != desired.infrastructure
        || candidate.domain_id != desired.domain_id
        || !same_io_lineage(&candidate, &desired)
    {
        bail!("pair recovery receipt differs from immutable desired infrastructure");
    }
    // Policy and authorization remain the newly verified desired values. Only local IO identity
    // survives recovery, so signed renewal can advance a grant on that same infrastructure.
    desired.io_epoch = candidate.io_epoch;
    desired.worker_epoch = desired.worker_epoch.max(candidate.worker_epoch);
    desired.fencing_token = desired.fencing_token.max(candidate.fencing_token);
    desired.pair_recovery = Some(recovery.clone());
    Ok(desired)
}

fn compile_verified_plan(plan: Plan) -> Result<(Plan, serde_json::Value)> {
    compile_verified_plan_bounded(plan, Duration::from_secs(10), false)
}

fn compile_verified_plan_bounded(
    mut plan: Plan,
    timeout: Duration,
    cancel_shutdown: bool,
) -> Result<(Plan, serde_json::Value)> {
    let compiled = bounded_compile_control_inner(
        Command::new(&plan.core)
            .args(["client", "sdwan", "compile-control", "--config"])
            .arg(&plan.core_config),
        timeout.min(Duration::from_secs(10)),
        cancel_shutdown,
    )
    .context("verify signed control before infrastructure activation")?;
    if !compiled.status.success() || compiled.stdout.len() as u64 > MAX_SIGNED_CONFIG_BYTES {
        bail!(
            "code=signed_control_compile_failed module=sdwan_activation detail={}",
            String::from_utf8_lossy(&compiled.stderr)
        );
    }
    let report: serde_json::Value = serde_json::from_slice(&compiled.stdout)?;
    validate_compiled_declaration(&report, &plan)?;
    let verified_deadline = report["authorization_expires_at_unix"]
        .as_u64()
        .filter(|v| *v > 0)
        .context("Core compile report lacks verified authorization expiry")?;
    if report["projection_generation"] != plan.signed_generation {
        bail!("experimental plan policy generation differs from verified signed control");
    }
    plan.auth_deadline_unix = plan.auth_deadline_unix.min(verified_deadline);
    Ok((plan, report))
}

pub(super) fn cloud_activation_plan(
    template: &Path,
    core_config: &Path,
    declaration: PrepareDeclaration,
    generation: u64,
    private_parent: &Path,
    deadline: Instant,
) -> Result<Vec<u8>> {
    #[cfg(not(all(feature = "experimental-tunio-rebind", target_os = "linux")))]
    {
        let _ = (
            template,
            core_config,
            declaration,
            generation,
            private_parent,
            deadline,
        );
        bail!("code=cloud_plan_feature_required module=cloud_plan_bridge detail=verified Cloud plans require Linux experimental-tunio-rebind");
    }
    #[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
    {
        let mut plan = read_plan(template)?;
        if plan.independent_worker.is_none()
            || plan.independent_supervision.is_none()
            || plan.authority.is_some()
            || plan.pair_recovery.is_some()
            || plan.effective_plan_file.is_some()
            || plan.authorization_snapshot_sha256.is_some()
        {
            bail!("code=cloud_plan_template_rejected module=cloud_plan_bridge detail=template must declare independent Core/IO and contain no consumed authority receipts");
        }
        if declaration.table_id != plan.declaration.table_id
            || declaration.overlay_router_ipv4 != plan.infrastructure.overlay_router_ipv4
            || declaration.effective_mtu != plan.infrastructure.mtu
            || declaration.firewall != plan.declaration.firewall
        {
            bail!("code=cloud_plan_infrastructure_mismatch module=cloud_plan_bridge detail=Cloud declaration cannot replace local table, TUN address/MTU or firewall contract");
        }
        let mut declaration = declaration;
        for local in &plan.declaration.exclusions {
            if !declaration
                .exclusions
                .iter()
                .any(|entry| entry.prefix == local.prefix)
            {
                declaration.exclusions.push(*local);
            }
        }
        declaration
            .exclusions
            .sort_by_key(|entry| (entry.prefix, entry.kind as u64));
        plan.declaration = declaration;
        plan.signed_generation = generation;
        // Verify an immutable copy before publishing a plan pinned to Cloud's immutable generation.
        let snapshot = crate::signed_snapshot::Snapshot::capture(core_config, private_parent)?;
        let _cleanup = crate::signed_snapshot::CleanupGuard::new(&snapshot);
        plan.core_config = snapshot.config.clone();
        plan.auth_deadline_unix = u64::MAX;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .context("Cloud plan iteration deadline reached")?;
        let (mut verified, _) = compile_verified_plan_bounded(plan, remaining, true)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        if verified.auth_deadline_unix <= now {
            bail!("code=cloud_plan_authority_expired module=cloud_plan_bridge detail=verified signed authority is already expired");
        }
        verified.core_config = core_config.to_path_buf();
        Ok(serde_json::to_vec(&verified)?)
    }
}

pub fn run(path: &Path, gate: bool) -> Result<()> {
    if !gate {
        bail!("explicit experimental-packet-port-ipc gate required");
    }
    let plan = verified_plan(path)?;
    run_plan(path, plan)
}

fn run_plan(path: &Path, plan: Plan) -> Result<()> {
    let initial_inputs = recovery_inputs(path)?;
    #[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
    let mut plan = plan;
    #[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
    if plan.independent_worker.is_some() && plan.pair_recovery.is_none() {
        let parent = plan
            .core_status
            .parent()
            .context("missing private plan directory")?
            .to_owned();
        let snapshot = crate::signed_snapshot::Snapshot::capture(&plan.core_config, &parent)?;
        let mut snapshot_cleanup = crate::signed_snapshot::CleanupGuard::new(&snapshot);
        plan.core_config = snapshot.config.clone();
        let (verified, report) = compile_verified_plan(plan)?;
        plan = verified;
        plan.authorization_snapshot_sha256 = report["authorization_snapshot_sha256"]
            .as_str()
            .map(str::to_owned);
        if plan.authorization_snapshot_sha256.is_none() {
            bail!("Core snapshot hash absent during immutable startup");
        }
        plan.effective_plan_file = Some(parent.join(format!(
            "initial-{}-plan.json",
            uuid::Uuid::new_v4().simple()
        )));
        snapshot_cleanup.track_file(plan.effective_plan_file.as_ref().unwrap().clone());
        signed_renewal::publish_plan(&plan)?;
        snapshot_cleanup.transfer();
    }
    install_shutdown_handlers()?;
    let authority_anchor = monotonic_ms()?;
    let remaining = Duration::from_secs(plan.auth_deadline_unix)
        .checked_sub(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?)
        .filter(|v| !v.is_zero())
        .context("experimental authorization expired")?;
    if plan.independent_supervision.is_some() && remaining > Duration::from_secs(3600) {
        bail!("experimental detached owner authorization is limited to one hour");
    }
    let auth_deadline = authority_anchor
        .checked_add(
            u64::try_from(remaining.as_millis()).context("authorization duration overflow")?,
        )
        .context("authorization deadline overflow")?;
    let auth_deadline = plan
        .pair_recovery
        .as_ref()
        .map_or(auth_deadline, |recovery| {
            auth_deadline.min(recovery.auth_deadline_mono_ms)
        });
    if auth_deadline <= monotonic_ms()? {
        bail!("original pair recovery authorization expired");
    }
    let mut owner = ForwardOwner {
        domain_id: plan.domain_id,
        signed_generation: plan.signed_generation,
        worker_epoch: plan.worker_epoch,
        fencing_token: plan.fencing_token,
        auth_deadline_mono_ms: auth_deadline,
        lease_deadline_mono_ms: (monotonic_ms()? + 30000).min(auth_deadline),
    };
    owner.validate()?;
    let mut netd = NetdControl::new(&plan);
    let (capabilities, _) = netd.exchange(Operation::Capabilities)?;
    if !matches!(
        capabilities,
        Body::Capabilities {
            version: 2,
            independent_infrastructure: true,
            multi_domain
        } if multi_domain == plan.routing_namespace.is_some()
    ) {
        bail!("experimental mode requires netd v2 with matching namespace capability");
    }
    expect_ack(
        &mut netd,
        Operation::InfraEnsure(plan.infrastructure.clone()),
    )?;
    if plan.authority.is_none() && plan.pair_recovery.is_none() {
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
    let (io_socket, worker_socket) = UnixDatagram::pair()?;
    create_binding(&plan)?;
    let instance_hex = plan
        .instance_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut io_command = Command::new(&plan.tunio);
    enter_routing_namespace(&mut io_command, &plan)?;
    if plan.independent_supervision.is_none() {
        protect_child_lifetime(&mut io_command);
    }
    inherit_packet_socket(&mut io_command, &io_socket);
    io_command
        .arg("--experimental-packet-port-ipc")
        .arg("--socket")
        .arg(&plan.netd_socket)
        .arg("--instance-id")
        .arg(&instance_hex)
        .arg("--packet-port-fd")
        .arg(io_socket.as_raw_fd().to_string())
        .arg("--packet-port-binding-file")
        .arg(&plan.binding_file)
        .arg("--auth-deadline-unix")
        .arg(plan.auth_deadline_unix.to_string());
    if let Some(recovery) = &plan.pair_recovery {
        io_command
            .arg("--auth-deadline-mono-ms")
            .arg(recovery.auth_deadline_mono_ms.to_string());
    }
    if plan.routing_namespace.is_some() {
        let domain_hex = plan
            .domain_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        io_command.arg("--routing-domain-id").arg(domain_hex);
    }
    let io_token = uuid::Uuid::new_v4().simple().to_string();
    if let Some(supervision) = &plan.independent_supervision {
        io_command
            .arg("--control-socket")
            .arg(&supervision.control_socket)
            .arg("--status")
            .arg(&supervision.status)
            .arg("--readiness-token")
            .arg(&io_token);
    }
    let mut io_child = match io_command.spawn().context("spawn independent TUN I/O") {
        Ok(child) => child,
        Err(error) => {
            let _ = expect_ack(&mut netd, Operation::ForwardRevoke { owner });
            let _ = fs::remove_file(&plan.binding_file);
            return Err(error);
        }
    };
    drop(io_socket);
    #[cfg(target_os = "linux")]
    if let Some(io) = &plan.independent_supervision {
        let registration = (|| -> Result<()> {
            let mut record = crate::process_record::ManagedProcessRecord::capture(
                io_child.id(),
                &plan.tunio,
                &io.status,
                &io_token,
                plan.infrastructure.generation,
                plan.signed_generation,
                plan.auth_deadline_unix,
            )?;
            record.worker_epoch = Some(plan.worker_epoch);
            record.io_epoch = Some(plan.io_epoch);
            record.packet_binding_file = Some(plan.binding_file.clone());
            crate::process_record::publish(&io.process_record, &record)?;
            confirm_registration(&record, &io.control_socket, plan.auth_deadline_unix)?;
            // Probe ACK publishes registration intent; the IO task publishes active proof later.
            wait_io_registration(&record, &plan.tunio)
        })();
        if let Err(error) = registration {
            stop(&mut io_child);
            let _ = expect_ack(
                &mut netd,
                Operation::ForwardRevoke {
                    owner: owner.clone(),
                },
            );
            let _ = expect_ack(
                &mut netd,
                Operation::InfraReleaseIo {
                    infra_id: plan.infrastructure.infra_id,
                    generation: plan.infrastructure.generation,
                    io_epoch: plan.io_epoch,
                },
            );
            let _ = fs::remove_file(&plan.binding_file);
            return Err(error);
        }
    }
    #[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
    if plan.pair_recovery.is_some() {
        // Every new IO epoch needs a fresh signed transaction, including a legacy bootstrap.
        drop(worker_socket);
        let result = signed_renewal::run_with_plan(path, plan.clone());
        if result.as_ref().err().is_some_and(|error| {
            error.is::<DesiredStateChanged>()
                || error.is::<CoreRecoveryRequired>()
                || error.is::<ManagedProofPending>()
        }) {
            return result;
        }
        stop(&mut io_child);
        let _ = expect_ack(
            &mut netd,
            Operation::InfraReleaseIo {
                infra_id: plan.infrastructure.infra_id,
                generation: plan.infrastructure.generation,
                io_epoch: plan.io_epoch,
            },
        );
        return result;
    }
    let token = uuid::Uuid::new_v4().simple().to_string();
    let mut preserve_io = false;
    let mut preserve_worker = false;
    let result = (|| {
        let mut worker = spawn_business_worker(&plan, &worker_socket, &token)?;
        drop(worker_socket);
        let result = (|| {
            let worker_identity = candy_process_control::process_identity(worker.id())?;
            #[cfg(target_os = "linux")]
            publish_worker_record(&plan, worker.id(), &token)?;
            let readiness_deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if shutdown_requested() {
                    return Ok(());
                }
                if io_child.try_wait()?.is_some() {
                    return Err(PairRecoveryRequired.into());
                }
                if worker.try_wait()?.is_some() {
                    return Err(CoreRecoveryRequired.into());
                }
                if Instant::now() >= readiness_deadline {
                    bail!("experimental worker readiness deadline");
                }
                let state = read_core_readiness_with_policy(
                    &plan.core_status,
                    plan.signed_generation,
                    worker.id(),
                    &token,
                    ReadinessPolicy::Strict,
                )?;
                if matches!(state, Some(ReadinessState::Ready)) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            expect_ack(
                &mut netd,
                Operation::ForwardCommit {
                    owner: owner.clone(),
                },
            )?;
            #[cfg(target_os = "linux")]
            {
                let mut record = crate::process_record::ManagedProcessRecord::capture(
                    worker.id(),
                    &plan.core,
                    &plan.core_status,
                    &token,
                    plan.infrastructure.generation,
                    plan.signed_generation,
                    plan.auth_deadline_unix,
                )?;
                record.worker_epoch = Some(plan.worker_epoch);
                record.io_epoch = Some(plan.io_epoch);
                record.packet_binding_file = Some(plan.binding_file.clone());
                record.effective_plan_file = plan.effective_plan_file.clone();
                record.authorization_snapshot_sha256 = plan.authorization_snapshot_sha256.clone();
                bind_shared_record(&plan, &mut record);
                let record_path = plan.independent_worker.as_ref().map_or_else(
                    || plan.core_status.with_extension("process.json"),
                    |worker| worker.process_record.clone(),
                );
                if let Some(worker) = &plan.independent_worker {
                    let request = candy_process_control::ControlRequest {
                        schema_version: 1,
                        operation: candy_process_control::ControlOperation::Probe,
                        token_sha256: record.readiness_token_sha256.clone(),
                        nonce: uuid::Uuid::new_v4().simple().to_string(),
                    };
                    let reply = candy_process_control::exchange(
                        &worker.control_socket,
                        worker_identity,
                        &request,
                    )?;
                    if reply.controller
                        != candy_process_control::process_identity(std::process::id())?
                    {
                        bail!("independent Core initial controller mismatch");
                    }
                    record.validate_current(&plan.core, unix_time()?)?;
                    if record.private_status()?["auth_deadline_unix"] != plan.auth_deadline_unix {
                        bail!("independent Core omitted its verified authorization deadline");
                    }
                }
                if let Err(error) = crate::process_record::publish(&record_path, &record) {
                    if plan.independent_worker.is_some() {
                        return Err(error);
                    }
                    eprintln!("level=warn code=managed_process_record_write module=process_supervisor detail={error:#}");
                }
            }
            eprintln!("level=info code=packet_port_activation_committed module=sdwan_activation worker_pid={} tunio_pid={} tunfd_in_worker=false",worker.id(),io_child.id());
            let mut next_renewal = Instant::now();
            let mut next_prefix_check = Instant::now();
            let mut failure_snapshot = None;
            let mut active = true;
            let mut revoke_pending = false;
            let mut next_revoke = Instant::now();
            let mut next_plan_check = Instant::now();
            while !shutdown_requested() {
                if Instant::now() >= next_plan_check {
                    next_plan_check = Instant::now() + Duration::from_secs(1);
                    if plan.independent_worker.is_some()
                        && recovery_inputs(path).is_ok_and(|inputs| inputs != initial_inputs)
                    {
                        preserve_io = true;
                        preserve_worker = true;
                        return Err(DesiredStateChanged.into());
                    }
                }
                let expired = monotonic_ms()? >= owner.auth_deadline_mono_ms;
                let worker_dead = worker.try_wait()?.is_some();
                if active && (expired || worker_dead) {
                    active = false;
                    revoke_pending = true;
                    eprintln!("level=warn code=packet_port_owner_unavailable module=sdwan_activation worker_dead={worker_dead} authorization_expired={expired} action=keep_tunio_revoke_owned_forwarding");
                }
                if worker_dead
                    && !expired
                    && plan.independent_worker.is_some()
                    && cfg!(feature = "experimental-tunio-rebind")
                {
                    preserve_io = true;
                    return Err(CoreRecoveryRequired.into());
                }
                if revoke_pending && Instant::now() >= next_revoke {
                    match expect_ack(&mut netd,Operation::ForwardRevoke{owner:owner.clone()}) {
                        Ok(())=>revoke_pending=false,
                        Err(error)=>eprintln!("level=warn code=forward_revoke_pending module=sdwan_activation detail={error:#} action=retry_preserve_tunio"),
                    }
                    next_revoke = Instant::now() + Duration::from_secs(1);
                }
                if io_child.try_wait()?.is_some() {
                    if !expired
                        && plan.independent_worker.is_some()
                        && cfg!(feature = "experimental-tunio-rebind")
                    {
                        return Err(PairRecoveryRequired.into());
                    }
                    bail!("independent TUN I/O exited (infrastructure remains in netd)");
                }
                if active && Instant::now() >= next_renewal {
                    owner.lease_deadline_mono_ms =
                        (monotonic_ms()? + 30000).min(owner.auth_deadline_mono_ms);
                    let renewal = expect_ack(
                        &mut netd,
                        Operation::ForwardLeaseRenew {
                            owner: owner.clone(),
                        },
                    );
                    let delay = match renewal {
                        Ok(()) => Duration::from_secs(10),
                        Err(error) => {
                            eprintln!("level=warn code=forward_lease_renew_pending module=sdwan_activation detail={error:#} action=retry_preserve_live_processes");
                            Duration::from_secs(1)
                        }
                    };
                    next_renewal = Instant::now() + delay;
                }
                if active && Instant::now() >= next_prefix_check {
                    if let Err(error) = sync_failed_prefixes(
                        &mut netd,
                        &plan,
                        worker.id(),
                        &token,
                        &owner,
                        worker_identity,
                        &mut failure_snapshot,
                    ) {
                        eprintln!("level=warn code=forward_prefix_update_pending module=sdwan_activation detail={error:#} action=retry_preserve_live_processes");
                    }
                    next_prefix_check = Instant::now() + Duration::from_secs(1);
                }
                thread::sleep(Duration::from_millis(100));
            }
            Ok(())
        })();
        if !preserve_worker {
            stop_business(&mut worker);
        }
        result
    })();
    if preserve_worker {
        return result;
    }
    let revoke = expect_ack(&mut netd, Operation::ForwardRevoke { owner });
    let release = if preserve_io {
        Ok(())
    } else {
        stop(&mut io_child);
        expect_ack(
            &mut netd,
            Operation::InfraReleaseIo {
                infra_id: plan.infrastructure.infra_id,
                generation: plan.infrastructure.generation,
                io_epoch: plan.io_epoch,
            },
        )
    };
    if let Err(error) = revoke {
        eprintln!(
            "level=warn code=forward_revoke_pending module=sdwan_activation detail={error:#}"
        );
    }
    if let Err(error) = release {
        eprintln!("level=warn code=io_release_pending module=tunio detail={error:#}");
    }
    // The infrastructure is never retired implicitly by worker/process shutdown.
    if !preserve_io {
        let _ = fs::remove_file(&plan.binding_file);
    }
    result
}

pub fn adopt(record_path: &Path, executable: &Path, socket: &Path, gate: bool) -> Result<()> {
    use candy_process_control::{
        exchange, process_identity, process_is_current, ControlOperation, ControlRequest,
        ProcessIdentity,
    };
    if !gate {
        bail!("explicit experimental-packet-port-ipc gate required");
    }
    let record = crate::process_record::read(record_path)?;
    record.validate_current(executable, unix_time()?)?;
    let managed = ProcessIdentity {
        pid: record.pid,
        start_ticks: record.process_start_ticks,
    };
    let controller = process_identity(std::process::id())?;
    let request = |operation| ControlRequest {
        schema_version: 1,
        operation,
        token_sha256: record.readiness_token_sha256.clone(),
        nonce: uuid::Uuid::new_v4().simple().to_string(),
    };
    let adopted = exchange(socket, managed, &request(ControlOperation::Takeover))?;
    if adopted.controller != controller || adopted.controller_epoch == 0 {
        bail!("TUN I/O takeover ownership mismatch");
    }
    install_shutdown_handlers()?;
    eprintln!("level=info code=tunio_supervision_adopted module=process_supervisor pid={} controller_epoch={} auth_deadline_unix={} action=preserve_existing_authorization",managed.pid,adopted.controller_epoch,record.auth_deadline_unix);
    while !shutdown_requested() {
        if !process_is_current(managed) {
            bail!("code=tunio_process_exited module=process_supervisor detail=managed process epoch no longer exists");
        }
        let reply = exchange(socket, managed, &request(ControlOperation::Probe))?;
        if reply.controller != controller || reply.controller_epoch != adopted.controller_epoch {
            bail!("code=tunio_controller_changed module=process_supervisor detail=supervision ownership changed");
        }
        thread::sleep(Duration::from_millis(250));
    }
    exchange(socket, managed, &request(ControlOperation::Stop))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while process_is_current(managed) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if process_is_current(managed) {
        bail!("code=tunio_stop_pending module=process_supervisor detail=authenticated stop acknowledged but process still live");
    }
    Ok(())
}

pub fn adopt_worker(path: &Path, gate: bool) -> Result<()> {
    adopt_worker_with_io(path, gate, false)
}

pub(super) fn adopt_worker_with_io(path: &Path, gate: bool, supervise_io: bool) -> Result<()> {
    use candy_process_control::{
        exchange, process_identity, process_is_current, ControlOperation, ControlRequest,
        ProcessIdentity,
    };
    if !gate {
        bail!("explicit experimental-packet-port-ipc gate required");
    }
    let mut plan = verified_plan(path)?;
    let initial_inputs = recovery_inputs(path)?;
    let supervision = plan
        .independent_worker
        .as_ref()
        .context("independent worker plan absent")?;
    let record = crate::process_record::read(&supervision.process_record)?;
    plan = effective_worker_plan(plan, &record)?;
    let supervision = plan
        .independent_worker
        .as_ref()
        .context("effective independent Core plan absent")?;
    record.validate_current(&plan.core, unix_time()?)?;
    let status = record.private_status()?;
    validate_worker_placement(&plan, &record, &status)?;
    if record.status_path != plan.core_status
        || record.policy_generation != plan.signed_generation
        || record.auth_deadline_unix != plan.auth_deadline_unix
        || status["auth_deadline_unix"] != record.auth_deadline_unix
    {
        bail!("independent Core signed authorization differs from immutable activation plan");
    }
    plan.worker_epoch = record.worker_epoch.unwrap_or(plan.worker_epoch);
    let token = status["readiness_token"]
        .as_str()
        .context("Core capability absent")?
        .to_owned();
    let managed = ProcessIdentity {
        pid: record.pid,
        start_ticks: record.process_start_ticks,
    };
    let controller = process_identity(std::process::id())?;
    let io = if supervise_io {
        let io = plan
            .independent_supervision
            .as_ref()
            .context("independent I/O plan absent")?;
        let io_record = crate::process_record::read(&io.process_record)?;
        io_record.validate_current(&plan.tunio, unix_time()?)?;
        let identity = ProcessIdentity {
            pid: io_record.pid,
            start_ticks: io_record.process_start_ticks,
        };
        let request = ControlRequest {
            schema_version: 1,
            operation: ControlOperation::Takeover,
            token_sha256: io_record.readiness_token_sha256.clone(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
        };
        let reply = exchange(&io.control_socket, identity, &request)?;
        if reply.controller != controller || reply.controller_epoch == 0 {
            bail!("independent I/O takeover ownership mismatch");
        }
        Some((
            identity,
            io_record.readiness_token_sha256,
            reply.controller_epoch,
            io.control_socket.clone(),
        ))
    } else {
        None
    };
    let request = |operation| ControlRequest {
        schema_version: 1,
        operation,
        token_sha256: record.readiness_token_sha256.clone(),
        nonce: uuid::Uuid::new_v4().simple().to_string(),
    };
    let adopted = exchange(
        &supervision.control_socket,
        managed,
        &request(ControlOperation::Takeover),
    )?;
    if adopted.controller != controller || adopted.controller_epoch == 0 {
        bail!("independent Core takeover ownership mismatch");
    }
    let mut netd = NetdControl::new(&plan);
    let (body, fd) = netd.exchange(Operation::ForwardStatus)?;
    if fd.is_some() {
        bail!("Agent received unexpected packet fd");
    }
    let Body::ForwardStatus {
        owner: Some(previous),
        candidate_owner,
        phase: previous_phase,
        ..
    } = body
    else {
        bail!("independent Core forwarding receipt absent");
    };
    let retained_owner = previous.clone();
    let previous = if let Some(candidate) = candidate_owner {
        if candidate.worker_epoch != plan.worker_epoch
            || candidate.domain_id != plan.domain_id
            || candidate.signed_generation != plan.signed_generation
        {
            bail!("unrelated pending forwarding candidate prevents safe Core takeover");
        }
        expect_ack(
            &mut netd,
            Operation::ForwardRevoke {
                owner: candidate.clone(),
            },
        )?;
        candidate
    } else {
        previous
    };
    if previous.domain_id != plan.domain_id
        || previous.signed_generation != plan.signed_generation
        || previous.worker_epoch != plan.worker_epoch
    {
        bail!("independent Core forwarding owner differs from managed binding");
    }
    let now = monotonic_ms()?;
    let remaining = Duration::from_secs(record.auth_deadline_unix)
        .checked_sub(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?)
        .filter(|value| !value.is_zero())
        .context("independent Core authorization expired")?;
    let auth_deadline = now
        .checked_add(u64::try_from(remaining.as_millis())?)
        .context("authorization overflow")?;
    // A new controller gets a new fence, while the signed generation and packet binding remain fixed.
    let mut owner = ForwardOwner {
        fencing_token: previous
            .fencing_token
            .checked_add(1)
            .context("owner fence exhausted")?,
        auth_deadline_mono_ms: previous.auth_deadline_mono_ms.min(auth_deadline),
        lease_deadline_mono_ms: (now + 30000)
            .min(previous.auth_deadline_mono_ms.min(auth_deadline)),
        ..previous
    };
    // Controller adoption changes the fence, not the live business or I/O
    // owner. Preserve its route-to-TUN policy through this bookkeeping commit;
    // an ordinary active replacement briefly installs unreachable routes and
    // can terminate existing connected UDP application sockets.
    if matches!(
        previous_phase,
        Some(candy_netd_proto::v2::Phase::Active | candy_netd_proto::v2::Phase::Guarded)
    ) {
        if let Err(error) = expect_ack(
            &mut netd,
            Operation::ForwardGuard {
                owner: retained_owner,
            },
        ) {
            eprintln!("level=warn code=forward_guard_failed module=process_supervisor worker_pid={} detail={error:#} action=preserve_live_owner_retry_adoption", managed.pid);
            return Err(error.context(ManagedProofPending));
        }
    }
    let mut snapshot = None;
    let preparation = (|| -> Result<()> {
        expect_ack(
            &mut netd,
            Operation::ForwardPrepare {
                infra_id: plan.infrastructure.infra_id,
                infra_generation: plan.infrastructure.generation,
                owner: owner.clone(),
                declaration: plan.declaration.clone(),
            },
        )?;
        let ready_deadline = Instant::now() + Duration::from_secs(20);
        while snapshot.is_none() {
            sync_failed_prefixes(
                &mut netd,
                &plan,
                managed.pid,
                &token,
                &owner,
                managed,
                &mut snapshot,
            )?;
            if snapshot.is_none() {
                if shutdown_requested()
                    || !business_is_current(&plan, managed)?
                    || Instant::now() >= ready_deadline
                {
                    return Err(ManagedProofPending.into());
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        if plan.authority.is_some() {
            signed_renewal::commit_authorized(&plan, &record, &owner, &mut netd)?;
        } else {
            expect_ack(
                &mut netd,
                Operation::ForwardCommit {
                    owner: owner.clone(),
                },
            )?;
        }
        Ok(())
    })();
    if let Err(error) = preparation {
        // Adoption has no renewal journal. Retire only its exact uncommitted
        // candidate so a dead business process cannot poison later recovery.
        match netd.exchange(Operation::ForwardStatus) {
            Ok((
                Body::ForwardStatus {
                    candidate_owner: Some(candidate),
                    ..
                },
                None,
            )) if candidate == owner => {
                if let Err(cleanup) = expect_ack(
                    &mut netd,
                    Operation::ForwardRevoke {
                        owner: owner.clone(),
                    },
                ) {
                    return Err(cleanup.context(format!(
                        "adoption candidate cleanup pending after {error:#}"
                    )));
                }
            }
            Ok(_) => (),
            Err(cleanup) => {
                return Err(cleanup.context(format!(
                    "adoption candidate inspection pending after {error:#}"
                )))
            }
        }
        return Err(error);
    }
    install_shutdown_handlers()?;
    eprintln!("level=info code=core_supervision_adopted module=process_supervisor pid={} controller_epoch={} fencing_token={} auth_deadline_unix={} action=preserve_existing_signed_authorization",managed.pid,adopted.controller_epoch,owner.fencing_token,record.auth_deadline_unix);
    let mut next_renewal = Instant::now();
    let mut next_plan_check = Instant::now();
    while !shutdown_requested()
        && business_is_current(&plan, managed)?
        && monotonic_ms()? < owner.auth_deadline_mono_ms
    {
        if Instant::now() >= next_plan_check {
            next_plan_check = Instant::now() + Duration::from_secs(1);
            if recovery_inputs(path).is_ok_and(|inputs| inputs != initial_inputs) {
                return Err(DesiredStateChanged.into());
            }
        }
        if Instant::now() >= next_renewal {
            owner.lease_deadline_mono_ms =
                (monotonic_ms()? + 30000).min(owner.auth_deadline_mono_ms);
            if let Err(error) = expect_ack(
                &mut netd,
                Operation::ForwardLeaseRenew {
                    owner: owner.clone(),
                },
            ) {
                eprintln!("level=warn code=forward_lease_renew_pending module=process_supervisor detail={error:#} action=retry_preserve_worker");
            }
            next_renewal = Instant::now() + Duration::from_secs(1);
        }
        if let Err(error) = sync_failed_prefixes(
            &mut netd,
            &plan,
            managed.pid,
            &token,
            &owner,
            managed,
            &mut snapshot,
        ) {
            eprintln!("level=warn code=forward_prefix_update_pending module=process_supervisor detail={error:#} action=retry_preserve_worker");
        }
        match exchange(&supervision.control_socket,managed,&request(ControlOperation::Probe)) {
            Ok(reply) if reply.controller != controller || reply.controller_epoch != adopted.controller_epoch => {
                bail!("independent Core controller changed");
            }
            Err(error) => eprintln!("level=warn code=worker_probe_pending module=process_supervisor detail={error:#} action=retry_preserve_worker"),
            _ => (),
        }
        if let Some((identity, token, epoch, socket)) = &io {
            if !process_is_current(*identity) {
                return Err(PairRecoveryRequired.into());
            }
            let probe = ControlRequest {
                schema_version: 1,
                operation: ControlOperation::Probe,
                token_sha256: token.clone(),
                nonce: uuid::Uuid::new_v4().simple().to_string(),
            };
            match exchange(socket, *identity, &probe) {
                Ok(reply) if reply.controller != controller || reply.controller_epoch != *epoch => bail!("adopted I/O controller changed"),
                Err(error) => eprintln!("level=warn code=tunio_probe_pending module=process_supervisor detail={error:#} action=retry_preserve_io"),
                _ => (),
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
    if !shutdown_requested()
        && !business_is_current(&plan, managed)?
        && unix_time()? < record.auth_deadline_unix
        && cfg!(feature = "experimental-tunio-rebind")
    {
        return Err(CoreRecoveryRequired.into());
    }
    expect_ack(&mut netd, Operation::ForwardRevoke { owner })?;
    if business_is_current(&plan, managed)? {
        exchange(
            &supervision.control_socket,
            managed,
            &request(ControlOperation::Stop),
        )?;
    }
    if shutdown_requested() {
        if let Some((identity, token, _, socket)) = io {
            let stop = ControlRequest {
                schema_version: 1,
                operation: ControlOperation::Stop,
                token_sha256: token,
                nonce: uuid::Uuid::new_v4().simple().to_string(),
            };
            if process_is_current(identity) {
                exchange(&socket, identity, &stop)?;
                let deadline = Instant::now() + Duration::from_secs(2);
                while process_is_current(identity) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(20));
                }
                if process_is_current(identity) {
                    bail!("adopted I/O stop remains pending");
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(all(feature = "experimental-tunio-rebind", target_os = "linux")))]
pub(super) fn recover_pair(_: &Path) -> Result<()> {
    bail!("code=packet_pair_recovery_feature_required module=runtime_agent detail=pair recovery requires Linux experimental-tunio-rebind")
}

#[cfg(any(test, all(feature = "experimental-tunio-rebind", target_os = "linux")))]
fn next_recovery_epoch(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values
        .into_iter()
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .context("packet recovery epoch exhausted")
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
pub(super) fn recover_pair(path: &Path) -> Result<()> {
    use candy_process_control::{
        exchange, process_is_current, ControlOperation, ControlRequest, ProcessIdentity,
    };
    let desired = verified_plan(path)?;
    let recovered = recovery_plan(desired.clone())?;
    let worker = desired
        .independent_worker
        .as_ref()
        .context("pair recovery requires independent Core")?;
    let old_worker = crate::process_record::read(&worker.process_record)?;
    let retired = match &old_worker.effective_plan_file {
        Some(path) => read_plan(path)?,
        None => desired.clone(),
    };
    if retired.infrastructure != desired.infrastructure
        || retired.domain_id != desired.domain_id
        || !same_io_lineage(&retired, &desired)
    {
        bail!("retired pair differs from desired immutable infrastructure");
    }
    let (_, desired_report) = compile_verified_plan(desired.clone())?;
    let desired_hash = desired_report["authorization_snapshot_sha256"]
        .as_str()
        .context("desired signed hash absent")?
        .to_owned();
    let new_grant =
        old_worker.authorization_snapshot_sha256.as_deref() != Some(desired_hash.as_str());
    let mut plan = if new_grant {
        recovered.clone()
    } else {
        retired.clone()
    };
    // A changed grant is verified independently; its new IO still needs a fresh signed transaction.
    if new_grant {
        plan.authority = retired.authority.clone();
        plan.authorization_snapshot_sha256 = Some(desired_hash.clone());
    }
    let io = retired
        .independent_supervision
        .as_ref()
        .context("pair recovery requires independent IO")?;
    let old_io = crate::process_record::read(&io.process_record)?;
    let io_identity = ProcessIdentity {
        pid: old_io.pid,
        start_ticks: old_io.process_start_ticks,
    };
    if process_is_current(io_identity) {
        bail!("code=pair_recovery_io_alive module=process_supervisor detail=refusing replacement while original IO process is live");
    }
    preserve_unrecorded_endpoint(&io.control_socket)?;
    if old_io.infrastructure_generation != retired.infrastructure.generation
        || old_worker.infrastructure_generation != retired.infrastructure.generation
        || old_io.policy_generation != retired.signed_generation
        || old_worker.policy_generation != retired.signed_generation
        || old_io.auth_deadline_unix != retired.auth_deadline_unix
        || old_worker.auth_deadline_unix != retired.auth_deadline_unix
    {
        bail!("pair recovery process records differ from verified domain authorization");
    }
    let mut netd = NetdControl::new(&plan);
    let (infra, fd) = netd.exchange(Operation::InfraStatus)?;
    if fd.is_some() {
        bail!("unexpected descriptor during pair recovery");
    }
    let Body::InfraStatus {
        spec: Some(spec),
        io_epoch: actual_io_epoch,
        ..
    } = infra
    else {
        bail!("pair recovery original infrastructure receipt absent");
    };
    if spec != plan.infrastructure {
        bail!("pair recovery cannot replace immutable infrastructure");
    }
    let (status, fd) = netd.exchange(Operation::ForwardStatus)?;
    if fd.is_some() {
        bail!("unexpected forwarding descriptor during pair recovery");
    }
    let Body::ForwardStatus {
        owner: Some(previous),
        candidate_owner,
        ..
    } = status
    else {
        bail!("pair recovery original forwarding authorization receipt absent");
    };
    for owner in std::iter::once(&previous).chain(candidate_owner.iter()) {
        if owner.domain_id != retired.domain_id
            || owner.signed_generation != retired.signed_generation
        {
            bail!("pair recovery cannot revoke another domain or signed generation");
        }
    }
    let old_cap = std::iter::once(previous.auth_deadline_mono_ms)
        .chain(
            candidate_owner
                .iter()
                .map(|owner| owner.auth_deadline_mono_ms),
        )
        .chain(
            recovered
                .pair_recovery
                .iter()
                .map(|recovery| recovery.auth_deadline_mono_ms),
        )
        .min()
        .unwrap();
    let remaining = Duration::from_secs(plan.auth_deadline_unix)
        .checked_sub(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?)
        .filter(|remaining| !remaining.is_zero())
        .context("verified pair recovery grant expired")?;
    let verified_cap = monotonic_ms()?
        .checked_add(u64::try_from(remaining.as_millis())?)
        .context("pair recovery deadline overflow")?;
    let cap = if new_grant {
        recovered
            .pair_recovery
            .as_ref()
            .filter(|recovery| {
                recovery.authorization_snapshot_sha256.as_deref() == Some(desired_hash.as_str())
            })
            .map_or(verified_cap, |recovery| {
                verified_cap.min(recovery.auth_deadline_mono_ms)
            })
    } else {
        verified_cap.min(old_cap)
    };
    if cap <= monotonic_ms()? || unix_time()? >= plan.auth_deadline_unix {
        bail!("pair recovery original authorization expired");
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let original_io_epoch = plan
        .pair_recovery
        .as_ref()
        .map_or(desired.io_epoch, |recovery| recovery.original_io_epoch);
    plan.io_epoch = next_recovery_epoch([
        plan.io_epoch,
        recovered.io_epoch,
        old_io.io_epoch.context("recorded IO epoch absent")?,
        actual_io_epoch.unwrap_or(0),
    ])?;
    plan.worker_epoch = next_recovery_epoch([
        plan.worker_epoch,
        recovered.worker_epoch,
        old_worker
            .worker_epoch
            .context("recorded worker epoch absent")?,
        previous.worker_epoch,
        candidate_owner
            .as_ref()
            .map_or(0, |owner| owner.worker_epoch),
    ])?;
    plan.fencing_token = next_recovery_epoch([
        plan.fencing_token,
        recovered.fencing_token,
        previous.fencing_token,
        candidate_owner
            .as_ref()
            .map_or(0, |owner| owner.fencing_token),
    ])?;
    plan.pair_recovery = Some(PairRecovery {
        original_io_epoch,
        boot_id,
        auth_deadline_mono_ms: cap,
        retired_renewal_journal: None,
        authorization_snapshot_sha256: plan.authorization_snapshot_sha256.clone(),
    });
    plan.effective_plan_file = Some(desired.core_status.with_extension("pair-recovery.json"));
    plan.binding_file = desired.binding_file.with_extension(format!(
        "pair-{}-{}.json",
        plan.io_epoch,
        uuid::Uuid::new_v4().simple()
    ));
    plan.core_status = desired.core_status.clone();
    plan.independent_worker = desired.independent_worker.clone();
    let mut snapshot_cleanup = if new_grant && plan.authority.is_none() {
        let snapshot = crate::signed_snapshot::Snapshot::capture(
            &plan.core_config,
            plan.core_status
                .parent()
                .context("pair snapshot parent absent")?,
        )?;
        let cleanup = crate::signed_snapshot::CleanupGuard::new(&snapshot);
        plan.core_config = snapshot.config;
        Some(cleanup)
    } else {
        None
    };
    // Persist consumed epochs and the original clock cap before any destructive transition.
    signed_renewal::publish_plan(&plan)?;
    if let Some(cleanup) = &mut snapshot_cleanup {
        cleanup.transfer();
    }
    let worker_identity = ProcessIdentity {
        pid: old_worker.pid,
        start_ticks: old_worker.process_start_ticks,
    };
    if old_worker.business_is_current()? {
        old_worker.validate_infrastructure_identity(&plan.core)?;
        let endpoint = old_worker
            .effective_plan_file
            .as_ref()
            .map(|path| read_plan(path))
            .transpose()?
            .unwrap_or_else(|| plan.clone());
        let endpoint = endpoint
            .independent_worker
            .as_ref()
            .context("old Core control endpoint absent")?;
        for operation in [ControlOperation::Takeover, ControlOperation::Stop] {
            exchange(
                &endpoint.control_socket,
                worker_identity,
                &ControlRequest {
                    schema_version: 1,
                    operation,
                    token_sha256: old_worker.readiness_token_sha256.clone(),
                    nonce: uuid::Uuid::new_v4().simple().to_string(),
                },
            )?;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while old_worker.business_is_current()? && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        if old_worker.business_is_current()? {
            return Err(ManagedProofPending.into());
        }
    }
    // A surviving Core can retain the old socket. Retire it before releasing any queue lease.
    if process_is_current(io_identity) || old_worker.business_is_current()? {
        return Err(ManagedProofPending.into());
    }
    // Core cannot bind over a socket left by an abrupt exit. Only unlink a proven dead,
    // same-owner Unix endpoint after both process epochs have retired.
    remove_retired_control_endpoint(&desired.independent_worker.as_ref().unwrap().control_socket)?;
    let io_control = &desired
        .independent_supervision
        .as_ref()
        .unwrap()
        .control_socket;
    for endpoint in [
        io_control.clone(),
        candy_tunio::attach_control::packet_control_path(io_control),
        candy_tunio::authority_control::authority_control_path(io_control),
    ] {
        remove_retired_control_endpoint(&endpoint)?;
    }
    if plan.authority.is_some() {
        let archived = signed_renewal::archive_retired_io_transaction(&desired, &old_io)?;
        plan.pair_recovery.as_mut().unwrap().retired_renewal_journal = archived;
        signed_renewal::publish_plan(&plan)?;
    }
    // Revoking the committed owner also clears its candidate in netd. Retire the
    // candidate first so a pending takeover does not turn the second revoke stale.
    if let Some(owner) = candidate_owner {
        expect_ack(&mut netd, Operation::ForwardRevoke { owner: owner.clone() }).with_context(|| {
            format!("code=pair_candidate_revoke_failed module=process_supervisor worker_epoch={} fence={} auth_deadline_mono_ms={} lease_deadline_mono_ms={} detail=retire pending owner before committed owner",owner.worker_epoch,owner.fencing_token,owner.auth_deadline_mono_ms,owner.lease_deadline_mono_ms)
        })?;
    }
    expect_ack(&mut netd, Operation::ForwardRevoke { owner: previous.clone() }).with_context(|| {
        format!("code=pair_committed_revoke_failed module=process_supervisor worker_epoch={} fence={} auth_deadline_mono_ms={} lease_deadline_mono_ms={} detail=retire committed owner after candidate",previous.worker_epoch,previous.fencing_token,previous.auth_deadline_mono_ms,previous.lease_deadline_mono_ms)
    })?;
    if let Some(io_epoch) = actual_io_epoch {
        expect_ack(
            &mut netd,
            Operation::InfraReleaseIo {
                infra_id: plan.infrastructure.infra_id,
                generation: plan.infrastructure.generation,
                io_epoch,
            },
        )?;
    }
    eprintln!("level=warn code=packet_pair_recovery_started module=process_supervisor domain_id={:?} old_worker_pid={} old_io_pid={} io_epoch={} worker_epoch={} auth_deadline_mono_ms={} action=replace_affected_domain_pair_preserve_tun_other_domains_and_proxy",plan.domain_id,old_worker.pid,old_io.pid,plan.io_epoch,plan.worker_epoch,cap);
    run_plan(path, plan)
}

#[cfg(not(all(feature = "experimental-tunio-rebind", target_os = "linux")))]
pub(super) fn rebind_core(_: &Path) -> Result<()> {
    bail!("code=packet_port_rebind_feature_required module=runtime_agent detail=live I/O preserved; authenticated Core replacement requires Linux and experimental-tunio-rebind")
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
pub(super) fn rebind_core(path: &Path) -> Result<()> {
    use candy_process_control::{
        exchange, process_identity, process_is_current, ControlOperation, ControlRequest,
        ProcessIdentity,
    };
    use candy_tunio::attach_control::{
        exchange_packet_port, packet_control_path, PacketControlOperation, PacketControlRequest,
        PacketPortBinding,
    };
    let mut plan = verified_plan(path)?;
    if let Some(worker) = &plan.independent_worker {
        let record = crate::process_record::read(&worker.process_record)?;
        if let Some(effective_path) = &record.effective_plan_file {
            if read_plan(effective_path)?.authority.is_some() {
                return signed_renewal::run(path);
            }
        }
    }
    let io = plan
        .independent_supervision
        .as_ref()
        .context("independent I/O plan absent")?;
    let worker = plan
        .independent_worker
        .as_ref()
        .context("independent worker plan absent")?;
    let io_record = crate::process_record::read(&io.process_record)?;
    io_record.validate_current(&plan.tunio, unix_time()?)?;
    let old_worker = crate::process_record::read(&worker.process_record)?;
    plan = effective_worker_plan(plan, &old_worker)?;
    let io = plan
        .independent_supervision
        .as_ref()
        .context("effective IO plan absent")?;
    let worker = plan
        .independent_worker
        .as_ref()
        .context("effective Core plan absent")?;
    if old_worker.business_is_current()? {
        bail!("refusing replacement of a live Core process epoch");
    }
    if io_record.policy_generation != plan.signed_generation
        || io_record.infrastructure_generation != plan.infrastructure.generation
        || io_record.auth_deadline_unix != plan.auth_deadline_unix
        || old_worker.policy_generation != plan.signed_generation
        || old_worker.auth_deadline_unix != plan.auth_deadline_unix
    {
        bail!("Core recovery differs from original signed infrastructure/authorization");
    }
    let managed_io = ProcessIdentity {
        pid: io_record.pid,
        start_ticks: io_record.process_start_ticks,
    };
    let controller = process_identity(std::process::id())?;
    let takeover = exchange(
        &io.control_socket,
        managed_io,
        &ControlRequest {
            schema_version: 1,
            operation: ControlOperation::Takeover,
            token_sha256: io_record.readiness_token_sha256.clone(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
        },
    )?;
    if takeover.controller != controller || takeover.controller_epoch == 0 {
        bail!("Core recovery I/O controller ownership mismatch");
    }
    let mut netd = NetdControl::new(&plan);
    let (status, descriptor) = netd.exchange(Operation::ForwardStatus)?;
    if descriptor.is_some() {
        bail!("unexpected packet fd during Core recovery");
    }
    let Body::ForwardStatus {
        owner: Some(previous),
        candidate_owner,
        ..
    } = status
    else {
        bail!("original forwarding record absent during Core recovery");
    };
    if previous.domain_id != plan.domain_id || previous.signed_generation != plan.signed_generation
    {
        bail!("Core recovery forwarding ownership differs from verified signed domain");
    }
    let io_status = io_record.private_status()?;
    let io_binding: PacketPortBinding = serde_json::from_value(io_status["packet_binding"].clone())
        .context("I/O current binding absent during Core recovery")?;
    if io_binding.infrastructure_id != plan.infrastructure.infra_id
        || io_binding.routing_domain_id != plan.domain_id
        || io_binding.infrastructure_generation != plan.infrastructure.generation
        || io_binding.io_epoch != plan.io_epoch
        || io_binding.policy_generation != plan.signed_generation
    {
        bail!("I/O current binding differs from signed Core recovery domain");
    }
    let probe = exchange_packet_port(
        &packet_control_path(&io.control_socket),
        managed_io,
        &PacketControlRequest {
            schema_version: 1,
            process: managed_io,
            controller,
            controller_epoch: takeover.controller_epoch,
            token_sha256: io_record.readiness_token_sha256.clone(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            operation: PacketControlOperation::Probe,
            binding: io_binding,
            auth_deadline_unix: plan.auth_deadline_unix,
        },
        None,
        Instant::now() + Duration::from_secs(2),
    )?;
    let greatest_epoch = candidate_owner
        .as_ref()
        .map_or(previous.worker_epoch, |candidate| {
            candidate.worker_epoch.max(previous.worker_epoch)
        })
        .max(probe.current_binding.owner_epoch);
    let greatest_fence = candidate_owner
        .as_ref()
        .map_or(previous.fencing_token, |candidate| {
            candidate.fencing_token.max(previous.fencing_token)
        });
    plan.worker_epoch = greatest_epoch
        .checked_add(1)
        .context("worker epoch exhausted")?;
    let now = monotonic_ms()?;
    let remaining = Duration::from_secs(plan.auth_deadline_unix)
        .checked_sub(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?)
        .filter(|remaining| !remaining.is_zero())
        .context("Core recovery authorization expired")?;
    let auth_deadline = now
        .checked_add(u64::try_from(remaining.as_millis())?)
        .context("Core recovery deadline overflow")?
        .min(previous.auth_deadline_mono_ms);
    let owner = ForwardOwner {
        domain_id: plan.domain_id,
        signed_generation: plan.signed_generation,
        worker_epoch: plan.worker_epoch,
        fencing_token: greatest_fence
            .checked_add(1)
            .context("owner fencing exhausted")?,
        auth_deadline_mono_ms: auth_deadline,
        lease_deadline_mono_ms: (now + 30000).min(auth_deadline),
    };
    expect_ack(&mut netd, Operation::ForwardRevoke { owner: previous })?;
    if let Some(candidate) = candidate_owner {
        expect_ack(&mut netd, Operation::ForwardRevoke { owner: candidate })?;
    }
    expect_ack(
        &mut netd,
        Operation::ForwardPrepare {
            infra_id: plan.infrastructure.infra_id,
            infra_generation: plan.infrastructure.generation,
            owner: owner.clone(),
            declaration: plan.declaration.clone(),
        },
    )?;
    plan.binding_file = plan.binding_file.with_extension(format!(
        "rebind-{}-{}.json",
        plan.worker_epoch,
        uuid::Uuid::new_v4().simple()
    ));
    create_binding(&plan)?;
    let binding = PacketPortBinding {
        infrastructure_id: plan.infrastructure.infra_id,
        routing_domain_id: plan.domain_id,
        infrastructure_generation: plan.infrastructure.generation,
        io_epoch: plan.io_epoch,
        owner_epoch: plan.worker_epoch,
        policy_generation: plan.signed_generation,
    };
    let (io_socket, worker_socket) = UnixDatagram::pair()?;
    let token = uuid::Uuid::new_v4().simple().to_string();
    let mut child = spawn_business_worker(&plan, &worker_socket, &token)?;
    drop(worker_socket);
    let request = |operation| PacketControlRequest {
        schema_version: 1,
        process: managed_io,
        controller,
        controller_epoch: takeover.controller_epoch,
        token_sha256: io_record.readiness_token_sha256.clone(),
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        operation,
        binding,
        auth_deadline_unix: plan.auth_deadline_unix,
    };
    let mut attached = false;
    let result = (|| -> Result<()> {
        #[cfg(target_os = "linux")]
        publish_worker_record(&plan, child.id(), &token)?;
        let fd: std::os::fd::OwnedFd = io_socket.into();
        if let Err(error) = exchange_packet_port(
            &packet_control_path(&io.control_socket),
            managed_io,
            &request(PacketControlOperation::Attach),
            Some(&fd),
            Instant::now() + Duration::from_secs(2),
        ) {
            let current = exchange_packet_port(
                &packet_control_path(&io.control_socket),
                managed_io,
                &request(PacketControlOperation::Probe),
                None,
                Instant::now() + Duration::from_secs(2),
            )?;
            if current.current_binding != binding {
                return Err(
                    error.context("PacketPort attach failed and actual current binding differs")
                );
            }
            eprintln!("level=warn code=packet_port_attach_receipt_reconciled module=process_supervisor owner_epoch={} detail={error:#} action=retain_confirmed_original_attachment",binding.owner_epoch);
        }
        attached = true;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if shutdown_requested() || unix_time()? >= plan.auth_deadline_unix {
                bail!("Core recovery cancelled or authorization expired");
            }
            if child.try_wait()?.is_some() {
                return Err(CoreRecoveryRequired.into());
            }
            if !process_is_current(managed_io) {
                bail!("I/O epoch exited during Core recovery");
            }
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
                break;
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into());
            }
            thread::sleep(Duration::from_millis(100));
        }
        let mut record = crate::process_record::ManagedProcessRecord::capture(
            child.id(),
            &plan.core,
            &plan.core_status,
            &token,
            plan.infrastructure.generation,
            plan.signed_generation,
            plan.auth_deadline_unix,
        )?;
        record.worker_epoch = Some(plan.worker_epoch);
        record.io_epoch = Some(plan.io_epoch);
        record.packet_binding_file = Some(plan.binding_file.clone());
        record.effective_plan_file = plan.effective_plan_file.clone();
        record.authorization_snapshot_sha256 = plan.authorization_snapshot_sha256.clone();
        bind_shared_record(&plan, &mut record);
        if plan.effective_plan_file.is_some() {
            signed_renewal::publish_plan(&plan)?;
        }
        record.validate_current(&plan.core, unix_time()?)?;
        crate::process_record::publish(&worker.process_record, &record)?;
        let identity = process_identity(child.id())?;
        let mut snapshot = None;
        sync_failed_prefixes(
            &mut netd,
            &plan,
            child.id(),
            &token,
            &owner,
            identity,
            &mut snapshot,
        )?;
        if snapshot.is_none() {
            bail!("new Core verified route-owner snapshot absent");
        }
        expect_ack(
            &mut netd,
            Operation::ForwardCommit {
                owner: owner.clone(),
            },
        )?;
        eprintln!("level=info code=core_rebind_committed module=process_supervisor old_pid={} new_pid={} tunio_pid={} owner_epoch={} signed_generation={} auth_deadline_unix={} action=keep_original_tun_and_authorization",old_worker.pid,child.id(),managed_io.pid,plan.worker_epoch,plan.signed_generation,plan.auth_deadline_unix);
        // The shared adoption loop owns lease renewal and complete failure snapshots.
        adopt_worker_with_io(path, true, true)
    })();
    if result
        .as_ref()
        .err()
        .is_some_and(|error| error.is::<DesiredStateChanged>())
    {
        return result;
    }
    stop_business(&mut child);
    if result.is_err() {
        let _ = expect_ack(&mut netd, Operation::ForwardRevoke { owner });
        if attached {
            if let Err(error) = exchange_packet_port(
                &packet_control_path(&io.control_socket),
                managed_io,
                &request(PacketControlOperation::Revoke),
                None,
                Instant::now() + Duration::from_secs(2),
            ) {
                eprintln!("level=warn code=packet_port_revoke_pending module=process_supervisor detail={error:#} action=preserve_tunio_original_deadline");
            }
        }
    }
    let _ = fs::remove_file(&plan.binding_file);
    result
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[cfg(feature = "experimental-tunio-rebind")]
    #[test]
    fn retired_core_control_is_removed_only_after_kernel_proves_no_live_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("core.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(remove_retired_control_endpoint(&path)
            .unwrap_err()
            .is::<ManagedProofPending>());
        assert!(path.exists());
        drop(listener);
        remove_retired_control_endpoint(&path).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        drop(replacement);
        remove_retired_control_endpoint(&path).unwrap();
        fs::write(&path, "unrelated").unwrap();
        assert!(remove_retired_control_endpoint(&path).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "unrelated");
    }

    #[cfg(feature = "experimental-tunio-rebind")]
    #[test]
    fn failed_pair_start_retains_consumed_worker_epoch_and_fence_for_next_attempt() {
        let desired: Plan = serde_json::from_value(serde_json::json!({
            "schema_version":1,"netd_socket":"/tmp/netd","tunio":"/tmp/tunio","core":"/tmp/core",
            "core_config":"/tmp/core.toml","core_status":"/tmp/core-status","binding_file":"/tmp/binding",
            "instance_id":vec![1u8;16],"domain_id":vec![2u8;16],"io_epoch":1,"worker_epoch":1,"fencing_token":1,
            "signed_generation":1,"auth_deadline_unix":9999999999u64,
            "infrastructure":{"infra_id":vec![3u8;16],"generation":1,"netns_device":1,"netns_inode":1,"overlay_router_ipv4":[10,0,0,1],"mtu":1398},
            "declaration":{"table_id":20001,"overlay_router_ipv4":[10,0,0,1],"effective_mtu":1398,"routes":[],"exclusions":[],"firewall":{"allow_forward":true,"clamp_tcp_mss":false,"require_ipv4_forwarding":true,"manage_rp_filter":false}}
        })).unwrap();
        let mut failed = desired.clone();
        failed.io_epoch = 2;
        failed.worker_epoch = 7;
        failed.fencing_token = 9;
        failed.pair_recovery = Some(PairRecovery {
            original_io_epoch: 1,
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim()
                .into(),
            auth_deadline_mono_ms: monotonic_ms().unwrap() + 60000,
            retired_renewal_journal: None,
            authorization_snapshot_sha256: None,
        });
        let persisted: Plan =
            serde_json::from_slice(&serde_json::to_vec(&failed).unwrap()).unwrap();
        let recovered = project_recovered_io(desired, persisted).unwrap();
        assert_eq!(next_recovery_epoch([recovered.io_epoch, 1]).unwrap(), 3);
        assert_eq!(next_recovery_epoch([recovered.worker_epoch, 1]).unwrap(), 8);
        assert_eq!(
            next_recovery_epoch([recovered.fencing_token, 1]).unwrap(),
            10
        );
    }

    #[test]
    fn unrecorded_live_endpoint_blocks_replacement_without_granting_adoption() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("worker.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = preserve_unrecorded_endpoint(&path).unwrap_err();
        assert!(error.is::<ManagedProofPending>());
        drop(listener);
        preserve_unrecorded_endpoint(&path).unwrap();
        fs::remove_file(&path).unwrap();
        preserve_unrecorded_endpoint(&path).unwrap();
    }

    #[test]
    fn invalid_unrecorded_endpoint_is_never_treated_as_absent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("not-a-socket");
        fs::write(&path, "unrelated").unwrap();
        assert!(preserve_unrecorded_endpoint(&path).is_err());
    }

    #[test]
    fn worker_inherits_only_its_ipc_socket() {
        let (io, worker) = UnixDatagram::pair().unwrap();
        let selected = worker.as_raw_fd();
        let excluded = io.as_raw_fd();
        let mut command = Command::new("/bin/sh");
        inherit_packet_socket(&mut command, &worker);
        command.arg("-c").arg(format!(
            "test -S /proc/self/fd/{selected} && test ! -e /proc/self/fd/{excluded}"
        ));
        assert!(command.status().unwrap().success());
        assert!(nix::fcntl::FdFlag::from_bits_truncate(
            nix::fcntl::fcntl(selected, nix::fcntl::FcntlArg::F_GETFD).unwrap()
        )
        .contains(nix::fcntl::FdFlag::FD_CLOEXEC));
    }

    #[test]
    fn ungated_experimental_launch_performs_no_plan_or_netd_access() {
        assert!(run(Path::new("/does-not-exist"), false)
            .unwrap_err()
            .to_string()
            .contains("explicit experimental"));
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    #[test]
    fn local_placement_rotation_is_independent_monotonic_and_cannot_downgrade() {
        let current = WorkerPlacement {
            revision: 3,
            target_worker_id: 1,
            pool_directory: "/private/pool".into(),
            shared: None,
        };
        assert!(!placement_changed(Some(&current), Some(&current)).unwrap());
        let mut next = current.clone();
        next.target_worker_id = 2;
        assert!(placement_changed(Some(&current), Some(&next)).is_err());
        next.revision = 4;
        assert!(placement_changed(Some(&current), Some(&next)).unwrap());
        assert!(placement_changed(Some(&current), None).is_err());
        assert!(placement_changed(None, Some(&current)).unwrap());
        next.target_worker_id = 1;
        assert!(placement_changed(Some(&current), Some(&next)).unwrap());
    }
    #[test]
    fn io_death_takes_priority_even_when_new_authority_is_waiting() {
        assert!(pair_recovery_precedes_renewal(false, true));
        assert!(!pair_recovery_precedes_renewal(true, true));
        assert!(!pair_recovery_precedes_renewal(false, false));
    }
    #[test]
    fn recovery_epoch_advances_all_consumed_receipts_and_never_wraps() {
        assert_eq!(next_recovery_epoch([1, 9, 3, 2]).unwrap(), 10);
        assert_eq!(next_recovery_epoch([10, 9, 3, 2]).unwrap(), 11);
        assert!(next_recovery_epoch([1, u64::MAX]).is_err());
    }
    #[test]
    fn fresh_authoritative_snapshot_restores_routes_in_the_same_policy_generation() {
        let prefix = crate::parse_prefix("10.2.0.0/16").unwrap();
        let failed = FailureSnapshot {
            revision: 7,
            reported_at_mono_ms: 1000,
            prefixes: vec![prefix],
        };
        validate_failure_snapshot(&failed, None, 1000).unwrap();
        let recovered = FailureSnapshot {
            revision: 8,
            reported_at_mono_ms: 2000,
            prefixes: vec![],
        };
        validate_failure_snapshot(&recovered, Some(&failed), 2000).unwrap();
        let refreshed = FailureSnapshot {
            reported_at_mono_ms: 3000,
            ..recovered.clone()
        };
        validate_failure_snapshot(&refreshed, Some(&recovered), 3000).unwrap();
    }

    #[test]
    fn stale_replayed_and_conflicting_snapshots_cannot_restore_routes() {
        let prefix = crate::parse_prefix("10.2.0.0/16").unwrap();
        let current = FailureSnapshot {
            revision: 7,
            reported_at_mono_ms: 1000,
            prefixes: vec![prefix],
        };
        let recovered = FailureSnapshot {
            revision: 8,
            reported_at_mono_ms: 2000,
            prefixes: vec![],
        };
        assert!(validate_failure_snapshot(&recovered, Some(&current), 7001).is_err());
        assert!(validate_failure_snapshot(&recovered, Some(&current), 1949).is_err());
        assert!(validate_failure_snapshot(
            &FailureSnapshot {
                revision: 6,
                ..recovered.clone()
            },
            Some(&current),
            2000
        )
        .is_err());
        assert!(validate_failure_snapshot(
            &FailureSnapshot {
                revision: 7,
                ..recovered.clone()
            },
            Some(&current),
            2000
        )
        .is_err());
        assert!(validate_failure_snapshot(
            &FailureSnapshot {
                reported_at_mono_ms: 999,
                ..recovered.clone()
            },
            Some(&current),
            2000
        )
        .is_err());
        assert!(validate_failure_snapshot(
            &FailureSnapshot {
                revision: 0,
                ..recovered
            },
            Some(&current),
            2000
        )
        .is_err());
    }
}

#[cfg(test)]
mod compile_tests {
    use super::*;

    #[test]
    fn plan_accepts_eight_mib_and_rejects_excess_before_replacing_active_plan() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("desired.json");
        let active = directory.path().join("active.json");
        let mut value = serde_json::json!({
            "schema_version":1,"netd_socket":"/tmp/netd","tunio":"/tmp/tunio","core":"/tmp/core",
            "core_config":"/tmp/core.toml","core_status":"/tmp/core-status","binding_file":"/tmp/binding",
            "instance_id":vec![1u8;16],"domain_id":vec![2u8;16],"io_epoch":1,"worker_epoch":1,"fencing_token":1,
            "signed_generation":1,"auth_deadline_unix":9999999999u64,
            "infrastructure":{"infra_id":vec![3u8;16],"generation":1,"netns_device":1,"netns_inode":1,"overlay_router_ipv4":[10,0,0,1],"mtu":1398},
            "declaration":{"table_id":20001,"overlay_router_ipv4":[10,0,0,1],"effective_mtu":1398,"routes":[],"exclusions":[],"firewall":{"allow_forward":true,"clamp_tcp_mss":false,"require_ipv4_forwarding":true,"manage_rp_filter":false}}
        });
        value["declaration"]["routes"] =
            serde_json::to_value(vec![candy_netd_proto::RouteDeclaration {
                prefix: crate::parse_prefix("10.2.0.0/16").unwrap(),
                kind: candy_netd_proto::RouteKind::Remote,
            }])
            .unwrap();
        value["declaration"]["exclusions"] =
            serde_json::to_value(vec![candy_netd_proto::UnderlayExclusion {
                prefix: crate::parse_prefix("192.0.2.1/32").unwrap(),
                kind: candy_netd_proto::UnderlayKind::HubEndpoint,
            }])
            .unwrap();
        let original = serde_json::to_vec(&value).unwrap();
        fs::write(&active, &original).unwrap();
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
        for size in [(1024 * 1024) + 1, MAX_SIGNED_CONFIG_BYTES as usize] {
            let mut bytes = original.clone();
            bytes.resize(size, b' ');
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(read_plan(&path).unwrap().signed_generation, 1);
        }
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_SIGNED_CONFIG_BYTES + 1)
            .unwrap();
        assert!(read_plan(&path).is_err());
        assert_eq!(read_plan(&active).unwrap().signed_generation, 1);
        assert_eq!(fs::read(active).unwrap(), original);
    }

    #[test]
    fn signed_preflight_accepts_large_output_through_eight_mib() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report");
        for size in [(1024 * 1024) + 1, MAX_SIGNED_CONFIG_BYTES as usize] {
            fs::write(&path, vec![b' '; size]).unwrap();
            let output = bounded_compile_control(
                Command::new("/bin/cat").arg(&path),
                Duration::from_secs(2),
            )
            .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout.len(), size);
        }
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_SIGNED_CONFIG_BYTES + 1)
            .unwrap();
        assert!(bounded_compile_control(
            Command::new("/bin/cat").arg(path),
            Duration::from_secs(2)
        )
        .unwrap_err()
        .to_string()
        .contains("signed_control_output_limit"));
    }

    #[test]
    fn signed_preflight_timeout_stops_the_compiler_process() {
        let start = Instant::now();
        let error = bounded_compile_control(
            Command::new("/bin/sleep").arg("30"),
            Duration::from_millis(30),
        )
        .unwrap_err();
        assert!(error.to_string().contains("signed_control_compile_timeout"));
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn signed_preflight_rejects_unbounded_output_without_blocking() {
        let error =
            bounded_compile_control(&mut Command::new("/usr/bin/yes"), Duration::from_secs(2))
                .unwrap_err();
        assert!(error.to_string().contains("signed_control_output_limit"));
    }
    #[test]
    fn signed_preflight_collects_output_and_exit_status() {
        let output = bounded_compile_control(
            Command::new("/bin/echo").arg("verified"),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"verified\n");
        assert!(output.stderr.is_empty());
    }
}
