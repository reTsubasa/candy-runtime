use anyhow::{bail, Context, Result};
use candy_cloud_sync::{SyncControl, SyncOnceOptions};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudConfig {
    state_dir: PathBuf,
    run_dir: PathBuf,
    identity_dir: Option<PathBuf>,
    ca_certificate: Option<PathBuf>,
    core: Option<PathBuf>,
    server_config: Option<PathBuf>,
    proxy_config: Option<PathBuf>,
    #[serde(default)]
    public_endpoints: Vec<SocketAddr>,
    interval_ms: u64,
    retry_initial_ms: u64,
    retry_max_ms: u64,
}
impl CloudConfig {
    fn options(&self) -> SyncOnceOptions {
        SyncOnceOptions {
            state_dir: self.state_dir.clone(),
            run_dir: self.run_dir.clone(),
            identity_dir: self.identity_dir.clone(),
            ca_certificate: self.ca_certificate.clone(),
            core: self.core.clone(),
            server_config: self.server_config.clone(),
            proxy_config: self.proxy_config.clone(),
            public_endpoints: self.public_endpoints.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Budgets {
    max_domain_supervisors: usize,
    max_managed_threads: usize,
    thread_stack_bytes: usize,
    max_managed_stack_bytes: usize,
    event_capacity: usize,
    cloud_iteration_deadline_ms: u64,
    shutdown_timeout_ms: u64,
}
impl Budgets {
    fn admit(&self, domains: usize) -> Result<()> {
        let threads = domains
            .checked_add(1)
            .context("managed thread count overflow")?;
        let bytes = threads
            .checked_mul(self.thread_stack_bytes)
            .context("managed stack budget overflow")?;
        if domains > self.max_domain_supervisors
            || threads > self.max_managed_threads
            || self.thread_stack_bytes < 256 * 1024
            || bytes > self.max_managed_stack_bytes
            || self.event_capacity == 0
            || self.cloud_iteration_deadline_ms == 0
            || self.cloud_iteration_deadline_ms > 600000
            || self.shutdown_timeout_ms == 0
        {
            bail!("code=runtime_agent_budget_rejected module=runtime_agent detail=static tasks exceed declared managed thread, stack or notification budget");
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema_version: u8,
    status: PathBuf,
    budgets: Budgets,
    cloud: CloudConfig,
    #[serde(default)]
    domain_plans: Vec<PathBuf>,
    #[serde(default)]
    cloud_activation_bindings: Vec<crate::cloud_plan_bridge::Binding>,
    #[serde(default)]
    shared_pool: Option<crate::shared_pool::Config>,
}

fn private_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("runtime Agent paths must be absolute");
    }
    let metadata =
        fs::symlink_metadata(path.parent().context("runtime Agent path has no parent")?)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        bail!("runtime Agent status requires current-user 0700 parent directory");
    }
    Ok(())
}

fn read_config(path: &Path) -> Result<Config> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > 64 * 1024
    {
        bail!("runtime Agent config requires current-user bounded 0600 regular file");
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        bail!("runtime Agent config exceeds size budget");
    }
    let mut config: Config = serde_json::from_slice(&bytes)?;
    if config.schema_version != 1
        || (config.domain_plans.is_empty() && config.cloud_activation_bindings.is_empty())
        || config.cloud.interval_ms == 0
        || config.cloud.retry_initial_ms == 0
        || config.cloud.retry_initial_ms > config.cloud.retry_max_ms
    {
        bail!("runtime Agent requires valid static domain plans and Cloud retry intervals");
    }
    config
        .budgets
        .admit(config.domain_plans.len() + config.cloud_activation_bindings.len())?;
    private_parent(&config.status)?;
    for path in [&config.cloud.state_dir, &config.cloud.run_dir]
        .into_iter()
        .chain(
            [
                config.cloud.identity_dir.as_ref(),
                config.cloud.ca_certificate.as_ref(),
                config.cloud.core.as_ref(),
                config.cloud.server_config.as_ref(),
                config.cloud.proxy_config.as_ref(),
            ]
            .into_iter()
            .flatten(),
        )
    {
        if !path.is_absolute() {
            bail!("embedded Cloud paths must be absolute");
        }
    }
    let mut domains = HashSet::new();
    let mut infrastructures = HashSet::new();
    let mut process_paths = HashSet::new();
    let mut plan_paths = HashSet::new();
    for (plan, published) in config.domain_plans.iter().map(|plan| (plan, None)).chain(
        config
            .cloud_activation_bindings
            .iter()
            .map(|binding| (&binding.template_plan, Some(&binding.published_plan))),
    ) {
        if !plan_paths.insert(plan.clone()) {
            bail!("runtime Agent domain plan paths cannot overlap");
        }
        if let Some(published) = published {
            private_parent(published)?;
            if plan == published || !plan_paths.insert(published.clone()) {
                bail!("Cloud template and published plan paths cannot overlap");
            }
        }
        let (domain, infra, paths) = crate::experimental_tunio::static_identity(plan)?;
        if !domains.insert(domain) || !infrastructures.insert(infra) {
            bail!("runtime Agent static domain/infrastructure identities must be unique");
        }
        for path in paths {
            if path == config.status || !process_paths.insert(path) {
                bail!("runtime Agent process/binding/namespace paths cannot overlap");
            }
        }
    }
    config.domain_plans.extend(
        config
            .cloud_activation_bindings
            .iter()
            .map(|binding| binding.published_plan.clone()),
    );
    Ok(config)
}

fn owner_lock(status: &Path) -> Result<std::fs::File> {
    let path = status.with_extension("owner.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        bail!("runtime Agent owner lock requires current-user 0600 regular file");
    }
    if unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("runtime Agent already owns this status/configuration");
    }
    Ok(file)
}

#[derive(Clone, Debug, Serialize)]
struct TaskState {
    kind: &'static str,
    slot: usize,
    revision: u64,
    phase: &'static str,
    iterations: u64,
    failures: u64,
    started_at_mono_ms: u64,
    deadline_exceeded: bool,
    code: Option<&'static str>,
}
impl TaskState {
    fn new(kind: &'static str, slot: usize) -> Self {
        Self {
            kind,
            slot,
            revision: 0,
            phase: "scheduled",
            iterations: 0,
            failures: 0,
            started_at_mono_ms: 0,
            deadline_exceeded: false,
            code: None,
        }
    }
}
type States = Arc<Mutex<Vec<TaskState>>>;

fn update(
    states: &States,
    slot: usize,
    notifications: &SyncSender<()>,
    change: impl FnOnce(&mut TaskState),
) {
    let mut all = states.lock().unwrap_or_else(|poison| poison.into_inner());
    change(&mut all[slot]);
    all[slot].revision = all[slot].revision.saturating_add(1);
    // The latest complete state is retained; full notifications are safely coalesced.
    let _ = notifications.try_send(());
}

fn publish(path: &Path, states: &States) -> Result<()> {
    let all = states
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    let bytes = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"pid":std::process::id(),"reported_at_mono_ms":crate::monotonic_ms()?,"cloud_cancellation_supported":true,"tasks":all}),
    )?;
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn interruptible_wait(duration: Duration) {
    let deadline = Instant::now() + duration;
    while !crate::shutdown_requested() && Instant::now() < deadline {
        thread::sleep(
            Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

type CloudInvocation = Arc<Mutex<Option<SyncControl>>>;
fn reconcile_cloud_plans(
    config: &CloudConfig,
    bindings: &[crate::cloud_plan_bridge::Binding],
    deadline: Instant,
) -> Result<()> {
    let mut first_error = None;
    for binding in bindings {
        if Instant::now() >= deadline || crate::shutdown_requested() {
            if first_error.is_none() {
                first_error = Some(anyhow::anyhow!("code=cloud_plan_deadline module=cloud_plan_bridge detail=iteration budget exhausted; preserve previous plan"));
            }
            break;
        }
        if let Err(error) =
            crate::cloud_plan_bridge::reconcile(&config.state_dir, binding, deadline)
        {
            eprintln!("level=warn code=cloud_plan_rejected module=cloud_plan_bridge plan={} detail={error:#} action=preserve_previous_plan_and_other_domains", binding.published_plan.display());
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn cloud_loop(
    config: CloudConfig,
    bindings: Vec<crate::cloud_plan_bridge::Binding>,
    states: States,
    notifications: SyncSender<()>,
    invocation: CloudInvocation,
    timeout: Duration,
) {
    let mut backoff = config.retry_initial_ms;
    while !crate::shutdown_requested() {
        update(&states, 0, &notifications, |state| {
            state.phase = "running";
            state.iterations += 1;
            state.started_at_mono_ms = crate::monotonic_ms().unwrap_or(0);
            state.deadline_exceeded = false;
            state.code = None;
        });
        let result = catch_unwind(AssertUnwindSafe(|| {
            let deadline = Instant::now() + timeout;
            let control = SyncControl::new(timeout)?;
            *invocation
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(control.clone());
            if crate::shutdown_requested() {
                control.cancel();
            }
            // Restore cached verified authority before a stalled/offline Cloud can consume the budget.
            if config.state_dir.join("candidate").symlink_metadata().is_ok() {
                let _ = reconcile_cloud_plans(&config, &bindings, deadline);
            }
            let sync_result = candy_cloud_sync::synchronize_once_controlled(config.options(), control);
            let plans_result = reconcile_cloud_plans(&config, &bindings, deadline);
            sync_result?;
            plans_result
        }))
        .unwrap_or_else(|_| Err(anyhow::anyhow!("code=cloud_iteration_panicked module=runtime_agent detail=unwound Cloud invocation; retry after collecting cancellation state")));
        if let Some(control) = invocation
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
        {
            control.cancel();
        }
        let delay = match &result {
            Ok(()) => {
                backoff = config.retry_initial_ms;
                config.interval_ms
            }
            Err(error) => {
                eprintln!("level=warn code=cloud_iteration_failed module=runtime_agent detail={error:#} action=retry_preserve_domain_tasks");
                let delay = backoff;
                backoff = backoff.saturating_mul(2).min(config.retry_max_ms);
                delay
            }
        };
        update(&states, 0, &notifications, |state| {
            state.phase = "waiting";
            if result.is_err() {
                state.failures += 1;
                state.code = Some("cloud_iteration_failed");
            }
        });
        interruptible_wait(Duration::from_millis(delay));
    }
    update(&states, 0, &notifications, |state| state.phase = "stopped");
}

pub(super) fn transient_error(error: &anyhow::Error) -> bool {
    // These failures describe a signed/deployment contract mismatch. Wrapping
    // them in ManagedProofPending must preserve the active owner, but retrying
    // the identical plan cannot make progress. The supervisor will wait for a
    // changed plan fingerprint and leave the current owner serving meanwhile.
    let chain = format!("{error:#}");
    // The forwarding authority reports an active owner, but Runtime could not
    // confirm the exact predecessor process identity. This is an uncertain
    // local proof outcome, not a stable signed-contract mismatch: retain the
    // owner and retry reconciliation until the process record and authority
    // agree (or the supervisor's bounded retry/recovery policy intervenes).
    if chain.contains("code=renewal_active_owner_unconfirmed") {
        return true;
    }
    if [
        "code=candidate_shared_listener_required",
        "code=candidate_grant_policy_mismatch",
        "code=listener_activation_ack_mismatch",
        "code=listener_master_stale",
    ]
    .iter()
    .any(|code| chain.contains(code))
    {
        return false;
    }
    // anyhow context values participate in Error::is/downcast_ref, but are
    // not exposed as their original type by std::error::Error::source.
    if error.is::<crate::experimental_tunio::NetdUnavailable>()
        || error.is::<crate::experimental_tunio::CoreRecoveryRequired>()
        || error.is::<crate::experimental_tunio::PairRecoveryRequired>()
        || error.is::<crate::experimental_tunio::ManagedProofPending>()
        || error.is::<candy_process_control::ProcessLivenessUnconfirmed>()
        || error.is::<crate::experimental_tunio::DesiredStateChanged>()
        || error
            .downcast_ref::<crate::experimental_tunio::NetdActivationFailure>()
            .is_some_and(|error| error.retryable())
    {
        return true;
    }
    transient_cause(error.as_ref())
}

fn transient_cause(cause: &(dyn std::error::Error + 'static)) -> bool {
    cause
        .downcast_ref::<nix::errno::Errno>()
        .is_some_and(|error| {
            matches!(
                *error,
                nix::errno::Errno::EINTR
                    | nix::errno::Errno::EAGAIN
                    | nix::errno::Errno::ENOMEM
                    | nix::errno::Errno::EBUSY
                    | nix::errno::Errno::ECONNRESET
                    | nix::errno::Errno::ECONNREFUSED
                    | nix::errno::Errno::EPIPE
                    | nix::errno::Errno::ETIMEDOUT
            )
        })
        || cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::OutOfMemory
                ) || error.raw_os_error() == Some(nix::libc::EBUSY)
                    // io::Error::source skips an inner error itself. Inspect
                    // that typed value before following its source chain.
                    || error.get_ref().is_some_and(|inner| transient_cause(inner))
        })
        || cause.source().is_some_and(transient_cause)
}

fn inputs(path: &Path) -> Result<Vec<u8>> {
    // A transient read/permission/format error must not become an
    // indistinguishable "unchanged" fingerprint. The supervisor treats this
    // error as unknown, keeps the current owner, and retries the same plan.
    crate::experimental_tunio::recovery_inputs(path).with_context(|| {
        format!(
            "code=recovery_inputs_unconfirmed module=runtime_agent path={} action=preserve_owner_and_retry",
            path.display()
        )
    })
}

fn domain_loop(
    plan: PathBuf,
    slot: usize,
    states: States,
    notifications: SyncSender<()>,
    retry_initial_ms: u64,
    retry_max_ms: u64,
    shutdown_timeout_ms: u64,
) {
    let mut backoff = retry_initial_ms;
    while !crate::shutdown_requested() {
        let fingerprint = match inputs(&plan) {
            Ok(fingerprint) => fingerprint,
            Err(error) => {
                eprintln!(
                    "level=warn code=recovery_inputs_unconfirmed module=runtime_agent slot={} detail={} action=preserve_owner_and_retry",
                    slot,
                    crate::sanitize_log_value(&format!("{error:#}")),
                );
                interruptible_wait(Duration::from_millis(backoff));
                backoff = backoff.saturating_mul(2).min(retry_max_ms);
                continue;
            }
        };
        update(&states, slot, &notifications, |state| {
            state.phase = "running";
            state.iterations += 1;
            state.started_at_mono_ms = crate::monotonic_ms().unwrap_or(0);
            state.code = None;
        });
        let result = catch_unwind(AssertUnwindSafe(|| {
            let (_, _, paths) = crate::experimental_tunio::static_identity(&plan)?;
            private_parent(&paths[1])?;
            let _domain_lock = owner_lock(&paths[1])?;
            match crate::experimental_tunio::recovery_disposition(&plan)? {
                crate::experimental_tunio::RecoveryDisposition::Start => {
                    crate::experimental_tunio::run(&plan, true)
                }
                crate::experimental_tunio::RecoveryDisposition::Adopt => {
                    crate::experimental_tunio::adopt_worker_with_io(&plan, true, true)
                }
                crate::experimental_tunio::RecoveryDisposition::RebindCore => {
                    crate::experimental_tunio::rebind_core(&plan)
                }
                crate::experimental_tunio::RecoveryDisposition::RenewAuthority => {
                    crate::experimental_tunio::renew_authority(&plan)
                }
                crate::experimental_tunio::RecoveryDisposition::RecoverPair => {
                    crate::experimental_tunio::recover_pair(&plan)
                }
            }
        }));
        if crate::shutdown_requested() {
            break;
        }
        let (retry, code, detail) = match result {
            Err(_) => (
                true,
                "domain_supervisor_panicked",
                "unwound supervisor; reinspect original process records before recovery".to_owned(),
            ),
            Ok(Err(error)) => (
                transient_error(&error),
                "domain_supervisor_failed",
                format!("{error:#}"),
            ),
            Ok(Ok(())) => (
                false,
                "domain_authorization_completed",
                "supervision completed; wait for a new signed activation plan".to_owned(),
            ),
        };
        eprintln!("level=warn code={code} module=runtime_agent slot={slot} detail={detail} retry={retry} action=preserve_other_tasks_reinspect_records");
        update(&states, slot, &notifications, |state| {
            state.phase = if retry { "retry_wait" } else { "waiting_plan" };
            state.failures += 1;
            state.code = Some(code);
        });
        if retry {
            interruptible_wait(Duration::from_millis(backoff));
            backoff = backoff.saturating_mul(2).min(retry_max_ms);
        } else {
            loop {
                if crate::shutdown_requested() {
                    break;
                }
                match inputs(&plan) {
                    Ok(current) if current == fingerprint => {
                        interruptible_wait(Duration::from_millis(250));
                    }
                    Ok(_) => break,
                    Err(error) => {
                        eprintln!(
                            "level=warn code=recovery_inputs_unconfirmed module=runtime_agent slot={} detail={} action=preserve_owner_and_retry",
                            slot,
                            crate::sanitize_log_value(&format!("{error:#}")),
                        );
                        break;
                    }
                }
            }
            backoff = retry_initial_ms;
        }
    }
    let deadline = Instant::now() + Duration::from_millis(shutdown_timeout_ms);
    loop {
        match crate::experimental_tunio::shutdown_recorded_domain(&plan) {
            Ok(()) => break,
            Err(error) => {
                eprintln!("level=warn code=domain_shutdown_pending module=runtime_agent slot={slot} detail={error:#} action=retry_authenticated_cleanup");
                if Instant::now() >= deadline {
                    update(&states, slot, &notifications, |state| {
                        state.phase = "shutdown_failed";
                        state.code = Some("domain_shutdown_failed");
                    });
                    return;
                }
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
    update(&states, slot, &notifications, |state| {
        state.phase = "stopped"
    });
}

fn spawn_task(
    name: String,
    stack: usize,
    task: impl FnOnce() + Send + 'static,
) -> Result<JoinHandle<()>> {
    Ok(thread::Builder::new()
        .name(name)
        .stack_size(stack)
        .spawn(task)?)
}

pub(super) fn run(path: &Path, gate: bool) -> Result<()> {
    if !gate {
        bail!("explicit experimental-packet-port-ipc gate required");
    }
    let mut config = read_config(path)?;
    let _owner_lock = owner_lock(&config.status)?;
    let pool_plans = config.domain_plans.clone();
    let mut shared_pool = config
        .shared_pool
        .take()
        .map(crate::shared_pool::Manager::new)
        .transpose()?;
    if let Some(pool) = &mut shared_pool {
        pool.reconcile(&pool_plans)?;
    }
    crate::install_shutdown_handlers()?;
    let states = Arc::new(Mutex::new(
        std::iter::once(TaskState::new("cloud", 0))
            .chain((1..=config.domain_plans.len()).map(|slot| TaskState::new("domain", slot)))
            .collect(),
    ));
    let (notifications, events) = mpsc::sync_channel(config.budgets.event_capacity);
    let invocation = Arc::new(Mutex::new(None));
    let retry_initial_ms = config.cloud.retry_initial_ms;
    let retry_max_ms = config.cloud.retry_max_ms;
    let shutdown_timeout_ms = config.budgets.shutdown_timeout_ms;
    let mut workers = Vec::new();
    workers.push((
        0,
        spawn_task(
            "candy-agent-cloud".into(),
            config.budgets.thread_stack_bytes,
            {
                let states = states.clone();
                let notifications = notifications.clone();
                let invocation = invocation.clone();
                let timeout = Duration::from_millis(config.budgets.cloud_iteration_deadline_ms);
                move || {
                    cloud_loop(
                        config.cloud,
                        config.cloud_activation_bindings,
                        states,
                        notifications,
                        invocation,
                        timeout,
                    )
                }
            },
        )?,
    ));
    let mut startup_error = None;
    for (index, plan) in config.domain_plans.into_iter().enumerate() {
        let states = states.clone();
        let notifications = notifications.clone();
        let slot = index + 1;
        match spawn_task(
            format!("candy-agent-domain-{slot}"),
            config.budgets.thread_stack_bytes,
            move || {
                domain_loop(
                    plan,
                    slot,
                    states,
                    notifications,
                    retry_initial_ms,
                    retry_max_ms,
                    shutdown_timeout_ms,
                )
            },
        ) {
            Ok(worker) => workers.push((slot, worker)),
            Err(error) => {
                crate::SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
                eprintln!("level=error code=domain_supervisor_spawn_failed module=runtime_agent detail={error:#} action=stop_started_tasks");
                startup_error = Some(error);
                break;
            }
        }
    }
    eprintln!("level=info code=runtime_agent_started module=runtime_agent pid={} managed_threads={} cloud_execution=in_process independent_task_supervision=true",std::process::id(),workers.len());
    let mut shutdown_deadline = None;
    let mut next_publish = Instant::now();
    let mut published_revision = Vec::new();
    loop {
        let now = crate::monotonic_ms()?;
        if !crate::shutdown_requested() {
            if let Some(pool) = &mut shared_pool {
                if let Err(error) = pool.reconcile(&pool_plans) {
                    eprintln!("level=warn code=shared_pool_reconcile_pending module=runtime_agent detail={error:#} action=retry_preserve_healthy_domains");
                }
            }
        }
        {
            let mut all = states.lock().unwrap_or_else(|poison| poison.into_inner());
            for (slot, worker) in &workers {
                if worker.is_finished() && all[*slot].phase == "running" {
                    all[*slot].phase = "failed";
                    all[*slot].code = Some("managed_task_panicked");
                    all[*slot].revision = all[*slot].revision.saturating_add(1);
                    eprintln!("level=error code=managed_task_panicked module=runtime_agent slot={slot} action=preserve_other_tasks");
                }
            }
            let cloud = &mut all[0];
            if cloud.phase == "running"
                && !cloud.deadline_exceeded
                && now.saturating_sub(cloud.started_at_mono_ms)
                    > config.budgets.cloud_iteration_deadline_ms
            {
                cloud.deadline_exceeded = true;
                cloud.code = Some("cloud_iteration_deadline_exceeded");
                cloud.revision = cloud.revision.saturating_add(1);
                eprintln!("level=warn code=cloud_iteration_deadline_exceeded module=runtime_agent action=preserve_domains_no_parallel_reentry cancellation_supported=true");
            }
        }
        let revision = states
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .iter()
            .map(|state| state.revision)
            .collect::<Vec<_>>();
        if revision != published_revision || Instant::now() >= next_publish {
            match publish(&config.status,&states) {
                Ok(())=>published_revision=revision,
                Err(error)=>eprintln!("level=warn code=runtime_agent_status_pending module=runtime_agent detail={error:#} action=retry_preserve_tasks"),
            }
            next_publish = Instant::now() + Duration::from_secs(1);
        }
        if crate::shutdown_requested() {
            if let Some(control) = invocation
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .as_ref()
            {
                control.cancel();
            }
            let deadline = *shutdown_deadline.get_or_insert_with(|| {
                Instant::now() + Duration::from_millis(config.budgets.shutdown_timeout_ms)
            });
            if workers.iter().all(|(_, worker)| worker.is_finished()) {
                break;
            }
            if Instant::now() >= deadline {
                bail!("code=runtime_agent_shutdown_incomplete module=runtime_agent detail=bounded shutdown expired with live task; CLI must exit the entire process, not start replacement tasks");
            }
        }
        let _ = events.recv_timeout(Duration::from_millis(100));
    }
    for (_, worker) in workers {
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("runtime Agent managed task panicked"))?;
    }
    anyhow::ensure!(!states.lock().unwrap_or_else(|poison| poison.into_inner()).iter()
        .any(|state| state.code == Some("domain_shutdown_failed")),
        "code=runtime_agent_shutdown_incomplete module=runtime_agent detail=recorded domain cleanup remains unconfirmed");
    if let Some(pool) = &mut shared_pool {
        pool.retire_empty()?;
    }
    if let Some(error) = startup_error {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn budgets() -> Budgets {
        Budgets {
            max_domain_supervisors: 2,
            max_managed_threads: 3,
            thread_stack_bytes: 262144,
            max_managed_stack_bytes: 786432,
            event_capacity: 1,
            cloud_iteration_deadline_ms: 100,
            shutdown_timeout_ms: 1000,
        }
    }
    #[test]
    fn admission_counts_cloud_and_domains_before_spawning() {
        budgets().admit(2).unwrap();
        assert!(budgets().admit(3).is_err());
        let mut budget = budgets();
        budget.max_managed_stack_bytes -= 1;
        assert!(budget.admit(2).is_err());
    }
    #[test]
    fn full_notification_queue_retains_latest_terminal_state() {
        let states = Arc::new(Mutex::new(vec![TaskState::new("cloud", 0)]));
        let (sender, receiver) = mpsc::sync_channel(1);
        update(&states, 0, &sender, |state| state.phase = "running");
        update(&states, 0, &sender, |state| state.phase = "failed");
        assert_eq!(states.lock().unwrap()[0].phase, "failed");
        assert_eq!(states.lock().unwrap()[0].revision, 2);
        receiver.recv().unwrap();
        assert!(receiver.try_recv().is_err());
    }
    #[test]
    fn ungated_runtime_agent_does_not_read_config() {
        assert!(run(Path::new("/absent"), false)
            .unwrap_err()
            .to_string()
            .contains("explicit experimental"));
    }
    #[test]
    fn only_transient_io_errors_retry_without_new_policy() {
        assert!(transient_error(
            &anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                .context(candy_process_control::ProcessLivenessUnconfirmed {
                    identity: candy_process_control::ProcessIdentity {
                        pid: 42,
                        start_ticks: 1234
                    },
                })
        ));
        assert!(transient_error(
            &std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into()
        ));
        assert!(transient_error(
            &std::io::Error::from_raw_os_error(nix::libc::EBUSY).into()
        ));
        assert!(!transient_error(
            &std::io::Error::from(std::io::ErrorKind::InvalidInput).into()
        ));
        assert!(!transient_error(&anyhow::anyhow!(
            "invalid signed authorization"
        )));
        assert!(transient_error(
            &crate::experimental_tunio::PairRecoveryRequired.into()
        ));
        assert!(transient_error(
            &anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound))
                .context(crate::experimental_tunio::NetdUnavailable)
        ));
        assert!(!transient_error(
            &std::io::Error::from(std::io::ErrorKind::NotFound).into()
        ));
    }
    #[test]
    fn contextual_business_control_errors_retain_typed_retry_classification() {
        for errno in [
            nix::libc::EAGAIN,
            nix::libc::ECONNRESET,
            nix::libc::ETIMEDOUT,
        ] {
            let wrapped = anyhow::Error::from(std::io::Error::from_raw_os_error(errno))
                .context("shared domain completion");
            assert!(
                transient_error(&wrapped),
                "errno {errno} lost its retry type"
            );
        }
        let permanent =
            anyhow::anyhow!("invalid signed authorization").context("shared domain completion");
        assert!(!transient_error(&permanent));
        let unsupported_listener =
            anyhow::anyhow!("code=candidate_shared_listener_required module=sdwan_initiator")
                .context(crate::experimental_tunio::ManagedProofPending)
                .context("signed renewal recovery");
        assert!(!transient_error(&unsupported_listener));
        let unconfirmed_owner = anyhow::anyhow!(
            "code=renewal_active_owner_unconfirmed module=sdwan_activation"
        )
        .context("signed renewal recovery");
        assert!(transient_error(&unconfirmed_owner));
    }
    #[test]
    fn typed_nested_io_errors_keep_retry_classification() {
        let temporary = anyhow::Error::from(std::io::Error::other(
            std::io::Error::from_raw_os_error(nix::libc::EAGAIN),
        ));
        assert!(transient_error(&temporary));
        let permanent = anyhow::Error::from(std::io::Error::other(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid signed authorization",
        )));
        assert!(!transient_error(&permanent));
    }
    #[test]
    fn context_wrapped_recovery_signals_keep_the_existing_bounded_retry() {
        use crate::experimental_tunio::{
            CoreRecoveryRequired, DesiredStateChanged, ManagedProofPending, NetdUnavailable,
            PairRecoveryRequired,
        };
        let signals: Vec<anyhow::Error> = vec![
            anyhow::anyhow!("original proof failure").context(ManagedProofPending),
            anyhow::anyhow!("original core failure").context(CoreRecoveryRequired),
            anyhow::anyhow!("original pair failure").context(PairRecoveryRequired),
            anyhow::anyhow!("original netd failure").context(NetdUnavailable),
            anyhow::anyhow!("original desired state").context(DesiredStateChanged),
        ];
        for error in signals {
            assert!(transient_error(&error.context("renewal recovery")));
        }
        assert!(!transient_error(
            &anyhow::anyhow!("invalid signed authorization").context("renewal recovery")
        ));
    }
    #[test]
    fn agent_owner_lock_rejects_duplicate_owner_and_can_be_reacquired() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let status = directory.path().join("status.json");
        let lock = owner_lock(&status).unwrap();
        assert!(owner_lock(&status).is_err());
        drop(lock);
        owner_lock(&status).unwrap();
    }
}
