//! Single-domain infrastructure ownership control, independent of peer/worker lifecycle.

use crate::packet_port::{PacketOutput, PacketPort};
use crate::packet_port_ipc::{
    PacketBridgeCounters, PacketPortBinding, PacketPortRole, UnixPacketPort,
};
use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct PacketOutputStatus {
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub queue_slot_exhausted: u64,
    pub queue_byte_exhausted: u64,
    pub queue_channel_full: u64,
    pub backpressure_drops: u64,
    pub deadline_drops: u64,
    pub stale_drops: u64,
    pub queue_depth: u64,
    pub queue_high_watermark: u64,
    pub write_blocked_events: u64,
    pub queued_write_attempts: u64,
    pub queue_wait_micros: u64,
    pub queue_wait_max_micros: u64,
    pub send_elapsed_micros: u64,
    pub send_elapsed_max_micros: u64,
}

impl PacketOutputStatus {
    fn accumulate(&mut self, delta: &crate::packet_port::OutputDelta) {
        self.sent_packets = self.sent_packets.saturating_add(delta.sent_packets);
        self.sent_bytes = self.sent_bytes.saturating_add(delta.sent_bytes);
        self.queue_slot_exhausted = self
            .queue_slot_exhausted
            .saturating_add(delta.queue_slot_exhausted);
        self.queue_byte_exhausted = self
            .queue_byte_exhausted
            .saturating_add(delta.queue_byte_exhausted);
        self.queue_channel_full = self
            .queue_channel_full
            .saturating_add(delta.queue_channel_full);
        self.backpressure_drops = self
            .backpressure_drops
            .saturating_add(delta.backpressure_drops);
        self.deadline_drops = self.deadline_drops.saturating_add(delta.deadline_drops);
        self.stale_drops = self.stale_drops.saturating_add(delta.stale_drops);
        self.queue_depth = delta.queue_depth;
        self.queue_high_watermark = self.queue_high_watermark.max(delta.queue_high_watermark);
        self.write_blocked_events = self
            .write_blocked_events
            .saturating_add(delta.write_blocked_events);
        self.queued_write_attempts = self
            .queued_write_attempts
            .saturating_add(delta.queued_write_attempts);
        self.queue_wait_micros = self
            .queue_wait_micros
            .saturating_add(delta.queue_wait_micros);
        self.queue_wait_max_micros = self.queue_wait_max_micros.max(delta.queue_wait_max_micros);
        self.send_elapsed_micros = self
            .send_elapsed_micros
            .saturating_add(delta.send_elapsed_micros);
        self.send_elapsed_max_micros = self
            .send_elapsed_max_micros
            .max(delta.send_elapsed_max_micros);
    }
}

/// Lifetime counters are retained across worker replacement; binding identifies
/// the current owner. These direction diagnostics overlap aggregate counters.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct PacketBridgeOutputStatus {
    pub binding: Option<PacketPortBinding>,
    pub revision: u64,
    pub sampled_elapsed_millis: u64,
    pub to_worker: PacketOutputStatus,
    pub to_tun: PacketOutputStatus,
}

pub type AuthorizationCheck = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

#[derive(Debug)]
struct AuthorizationFailure(io::Error);

impl std::fmt::Display for AuthorizationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, formatter)
    }
}

impl std::error::Error for AuthorizationFailure {}

fn authorization_failure(error: io::Error) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, AuthorizationFailure(error))
}

fn is_authorization_failure(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<AuthorizationFailure>())
}

pub enum PacketPortOwnerChange {
    /// Stage one inbound candidate while retaining the sole active outbound owner.
    PrepareOwner {
        transaction: OwnerTransaction,
        port: UnixPacketPort,
        authorization: AuthorizationCheck,
    },
    CommitOwner {
        transaction: OwnerTransaction,
    },
    FinishOwnerDrain {
        transaction: OwnerTransaction,
    },
    RetireOwnerAfterFailure {
        transaction: OwnerTransaction,
    },
    AbortOwner {
        transaction: OwnerTransaction,
    },
    ProbeTransaction {
        transaction_id: [u8; 16],
        revision: u64,
    },
    Attach {
        port: UnixPacketPort,
        auth_deadline: Instant,
    },
    AttachAuthorized {
        port: UnixPacketPort,
        auth_deadline: Instant,
        authorization: AuthorizationCheck,
    },
    Renew {
        owner_epoch: u64,
        policy_generation: u64,
        auth_deadline: Instant,
    },
    Revoke {
        owner_epoch: u64,
    },
    Probe,
}

/// Immutable transaction identity, scoped to this infrastructure/domain bridge.
/// Revisions are monotonic for the lifetime of the bridge. A restarted caller
/// probes the watermark before choosing its next revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerTransaction {
    pub transaction_id: [u8; 16],
    pub revision: u64,
    pub expected_active_epoch: Option<u64>,
    pub binding: PacketPortBinding,
    pub auth_deadline: Instant,
    pub prepare_deadline: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerTransactionPhase {
    Prepared,
    Committed,
    Aborted,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerTransactionReceipt {
    pub transaction: OwnerTransaction,
    pub phase: OwnerTransactionPhase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketPortReceipt {
    pub binding: Option<PacketPortBinding>,
    pub auth_deadline: Option<Instant>,
    pub owner_epoch: u64,
    pub policy_generation: u64,
    /// At most one pending and one most recent terminal result are retained.
    pub pending: Option<OwnerTransactionReceipt>,
    pub last_transaction: Option<OwnerTransactionReceipt>,
    pub highest_transaction_revision: u64,
    pub retained_owner_binding: Option<PacketPortBinding>,
    pub old_owner_drained: bool,
    pub forced_retirement: bool,
}

/// Only the authenticated local Agent may supply these changes. It must verify
/// the signed domain authorization before extending its monotonic deadline.
pub struct PacketPortOwnerUpdate {
    pub change: PacketPortOwnerChange,
    pub acknowledgement: oneshot::Sender<Result<(), String>>,
    /// Optional actual-state receipt. This is sent only after the requested
    /// operation has been applied (or rejected); callers use Probe to recover
    /// the state when an ACK was lost after a side effect.
    pub receipt: Option<oneshot::Sender<PacketPortReceipt>>,
}

struct Owner {
    port: Arc<UnixPacketPort>,
    auth_deadline: Instant,
    /// Two-phase owners cannot extend the immutable Prepare authorization cap.
    transaction_cap: Option<Instant>,
    deadline: watch::Sender<Instant>,
    fence: Arc<OwnerFence>,
    inbound_fence: Arc<OwnerFence>,
    to_worker: PacketOutput,
    to_tun: PacketOutput,
}

impl Owner {
    fn new<P: PacketPort>(
        port: UnixPacketPort,
        tun: Arc<P>,
        auth_deadline: Instant,
        transaction_cap: Option<Instant>,
        authorization: Option<AuthorizationCheck>,
    ) -> Self {
        let port = Arc::new(port);
        let (deadline, deadline_rx) = watch::channel(auth_deadline);
        let fence = Arc::new(OwnerFence::new());
        let inbound_fence = Arc::new(OwnerFence::new());
        Self {
            to_worker: PacketOutput::new(Arc::new(DeadlinePort {
                port: port.clone(),
                deadline: deadline_rx.clone(),
                authorization: authorization.clone(),
                fence: fence.clone(),
            })),
            to_tun: PacketOutput::new(Arc::new(DeadlinePort {
                port: tun,
                deadline: deadline_rx,
                authorization,
                fence: inbound_fence.clone(),
            })),
            port,
            auth_deadline,
            transaction_cap,
            deadline,
            fence,
            inbound_fence,
        }
    }

    fn retire(&self) {
        self.fence.retire();
        self.inbound_fence.retire();
        self.to_worker.cancel();
        self.to_tun.cancel();
    }
}

/// The mutex covers only one nonblocking send poll. Retiring under the same
/// lock is a send fence even when an output task runs on another executor thread.
struct OwnerFence {
    active: Mutex<bool>,
    retired: watch::Sender<bool>,
    diagnostics: Option<crate::executor_diagnostics::Diagnostics>,
}

impl OwnerFence {
    fn new() -> Self {
        Self {
            active: Mutex::new(true),
            retired: watch::channel(false).0,
            diagnostics: crate::executor_diagnostics::configured(),
        }
    }

    fn while_active<T>(&self, operation: impl FnOnce() -> T) -> io::Result<T> {
        let active = crate::executor_diagnostics::observe_sync(
            self.diagnostics.as_ref(),
            "packet_owner_lock",
            || {
                self.active
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            },
        );
        if !*active {
            return Err(authorization_failure(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "packet-port owner retired",
            )));
        }
        Ok(operation())
    }

    fn retire(&self) {
        *self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        self.retired.send_replace(true);
    }
}

struct PendingOwner {
    transaction: OwnerTransaction,
    owner: Owner,
    authorization: AuthorizationCheck,
}

fn matches_infrastructure(port: &UnixPacketPort, infrastructure: PacketPortBinding) -> bool {
    let binding = port.binding();
    port.role() == PacketPortRole::Infrastructure
        && binding.infrastructure_id == infrastructure.infrastructure_id
        && binding.infrastructure_generation == infrastructure.infrastructure_generation
        && binding.io_epoch == infrastructure.io_epoch
        && binding.routing_domain_id == infrastructure.routing_domain_id
}

fn active_epoch(owner: Option<&Owner>) -> Option<u64> {
    owner.map(|owner| owner.port.binding().owner_epoch)
}

async fn owner_packet<P: PacketPort>(port: Option<&P>) -> io::Result<Vec<u8>> {
    match port {
        Some(port) => port.recv_packet().await,
        None => std::future::pending().await,
    }
}

async fn admitted_owner_packet<P: PacketPort>(
    port: Option<&P>,
    admission: Option<super::packet_port::OutputAdmission>,
) -> io::Result<Vec<u8>> {
    if let Some(admission) = admission {
        admission.ready().await;
    }
    owner_packet(port).await
}

enum DataPacket {
    Tun(io::Result<Vec<u8>>),
    Worker(io::Result<Vec<u8>>),
    Retained(io::Result<Vec<u8>>),
    Candidate(io::Result<Vec<u8>>),
}

async fn next_data_packet<T: PacketPort, W: PacketPort>(
    tun: &T,
    worker: Option<&W>,
    retained: Option<&W>,
    candidate: Option<&W>,
    prefer_worker: bool,
    to_worker: Option<super::packet_port::OutputAdmission>,
    to_tun: [Option<super::packet_port::OutputAdmission>; 3],
) -> DataPacket {
    let from_tun = async {
        if let Some(admission) = to_worker {
            admission.ready().await;
        }
        tun.recv_packet().await
    };
    let from_worker = async {
        let [active_admission, retained_admission, candidate_admission] = to_tun;
        tokio::select! {
            packet = admitted_owner_packet(worker, active_admission) => DataPacket::Worker(packet),
            packet = admitted_owner_packet(retained, retained_admission) => DataPacket::Retained(packet),
            packet = admitted_owner_packet(candidate, candidate_admission) => DataPacket::Candidate(packet),
        }
    };
    // Control stays in the outer select; only the two data directions rotate.
    if prefer_worker {
        tokio::select! {
            biased;
            packet = from_worker => packet,
            packet = from_tun => DataPacket::Tun(packet),
        }
    } else {
        tokio::select! {
            biased;
            packet = from_tun => DataPacket::Tun(packet),
            packet = from_worker => packet,
        }
    }
}

async fn owner_failure(owner: &mut Option<Owner>) -> (bool, io::Error) {
    match owner {
        Some(owner) => tokio::select! {
            error = owner.to_worker.failed() => (false, error),
            error = owner.to_tun.failed() => (true, error),
        },
        None => std::future::pending().await,
    }
}

async fn inbound_failure(owner: Option<&mut Owner>) -> io::Error {
    match owner {
        Some(owner) => owner.to_tun.failed().await,
        None => std::future::pending().await,
    }
}

async fn owner_expiry(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn collect(
    owner: &Owner,
    counters: &mut PacketBridgeCounters,
    outputs: &mut PacketBridgeOutputStatus,
) {
    let tx = owner.to_worker.take_delta();
    let rx = owner.to_tun.take_delta();
    counters.to_worker_packets += tx.sent_packets;
    counters.to_tun_packets += rx.sent_packets;
    counters.to_worker_bytes += tx.sent_bytes;
    counters.to_tun_bytes += rx.sent_bytes;
    counters.backpressure_drops += tx.backpressure_drops + rx.backpressure_drops;
    counters.deadline_drops += tx.deadline_drops + rx.deadline_drops;
    counters.stale_drops += tx.stale_drops + rx.stale_drops;
    outputs.to_worker.accumulate(&tx);
    outputs.to_tun.accumulate(&rx);
}

fn receipt(
    owner: Option<&Owner>,
    highest_owner_epoch: u64,
    highest_policy_generation: u64,
    pending: Option<&PendingOwner>,
    last_transaction: Option<&OwnerTransactionReceipt>,
    highest_transaction_revision: u64,
    drain: (Option<&Owner>, bool, bool),
) -> PacketPortReceipt {
    PacketPortReceipt {
        binding: owner.map(|owner| owner.port.binding()),
        auth_deadline: owner.map(|owner| owner.auth_deadline),
        owner_epoch: highest_owner_epoch,
        policy_generation: highest_policy_generation,
        pending: pending.map(|pending| OwnerTransactionReceipt {
            transaction: pending.transaction.clone(),
            phase: OwnerTransactionPhase::Prepared,
        }),
        last_transaction: last_transaction.cloned(),
        highest_transaction_revision,
        retained_owner_binding: drain.0.map(|owner| owner.port.binding()),
        old_owner_drained: drain.1,
        forced_retirement: drain.2,
    }
}

async fn revoke(
    owner: &mut Option<Owner>,
    counters: &mut PacketBridgeCounters,
    outputs: &mut PacketBridgeOutputStatus,
) {
    if let Some(mut previous) = owner.take() {
        previous.retire();
        tokio::join!(previous.to_worker.stop(), previous.to_tun.stop());
        collect(&previous, counters, outputs);
    }
    outputs.binding = None;
}

fn retire(owner: Owner, retired: &mut tokio::task::JoinSet<Owner>) {
    owner.retire();
    retired.spawn(async move {
        let mut owner = owner;
        tokio::join!(owner.to_worker.stop(), owner.to_tun.stop());
        owner
    });
}

struct DeadlinePort<P> {
    port: Arc<P>,
    deadline: watch::Receiver<Instant>,
    authorization: Option<AuthorizationCheck>,
    fence: Arc<OwnerFence>,
}

impl<P: PacketPort> PacketPort for DeadlinePort<P> {
    fn max_packet_size(&self) -> usize {
        self.port.max_packet_size()
    }
    fn try_send_packet(&self, packet: &[u8]) -> io::Result<bool> {
        self.fence.while_active(|| {
            if let Some(authorization) = &self.authorization {
                crate::executor_diagnostics::observe_sync(
                    self.fence.diagnostics.as_ref(),
                    "packet_owner_authorization",
                    || authorization(),
                )
                .map_err(authorization_failure)?;
            }
            if Instant::now() >= *self.deadline.borrow() {
                return Ok(false);
            }
            crate::executor_diagnostics::observe_sync(
                self.fence.diagnostics.as_ref(),
                "packet_owner_nonblocking_write",
                || self.port.try_send_packet(packet),
            )
        })?
    }
    async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        self.port.recv_packet().await
    }
    async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        let mut deadline_rx = self.deadline.clone();
        let mut retired_rx = self.fence.retired.subscribe();
        let send = self.port.send_packet(packet);
        tokio::pin!(send);
        loop {
            let deadline = *deadline_rx.borrow_and_update();
            if Instant::now() >= deadline {
                return Err(authorization_failure(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "routing-domain authorization expired",
                )));
            }
            tokio::select! {
                biased;
                _ = retired_rx.changed() => return Err(authorization_failure(io::Error::new(io::ErrorKind::PermissionDenied, "packet-port owner retired during output"))),
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(authorization_failure(io::Error::new(io::ErrorKind::PermissionDenied, "routing-domain authorization expired during output")));
                }
                changed = deadline_rx.changed() => {
                    if changed.is_err() { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "authorization publisher closed")); }
                }
                result = std::future::poll_fn(|cx| {
                    self.fence.while_active(|| {
                        if let Some(authorization) = &self.authorization {
                            if let Err(error) = crate::executor_diagnostics::observe_sync(
                                self.fence.diagnostics.as_ref(), "packet_owner_authorization", || authorization(),
                            ) {
                                return std::task::Poll::Ready(Err(authorization_failure(error)));
                            }
                        }
                        crate::executor_diagnostics::observe_sync(
                            self.fence.diagnostics.as_ref(), "packet_owner_send_poll", || send.as_mut().poll(cx),
                        )
                    }).unwrap_or_else(|error| std::task::Poll::Ready(Err(error)))
                }) => return result,
            }
        }
    }
}

/// Retain the same physical packet reader across owner replacement, expiration
/// and crash. One routing domain per instance; no routing logic is duplicated.
/// The caller owns the authenticated control channel and global pool budget.
pub async fn run_managed_packet_port_bridge<P: PacketPort>(
    tun: P,
    infrastructure: PacketPortBinding,
    updates: mpsc::Receiver<PacketPortOwnerUpdate>,
    shutdown: watch::Receiver<bool>,
) -> io::Result<PacketBridgeCounters> {
    run_observed_packet_port_bridge(tun, infrastructure, updates, shutdown, None).await
}

pub async fn run_observed_packet_port_bridge<P: PacketPort>(
    tun: P,
    infrastructure: PacketPortBinding,
    updates: mpsc::Receiver<PacketPortOwnerUpdate>,
    shutdown: watch::Receiver<bool>,
    diagnostics: Option<watch::Sender<PacketBridgeOutputStatus>>,
) -> io::Result<PacketBridgeCounters> {
    let executor = crate::executor_diagnostics::configured();
    let _heartbeat = executor
        .as_ref()
        .map(|probe| probe.heartbeat("managed_packet_bridge"));
    crate::executor_diagnostics::Observed::new(
        executor,
        "managed_packet_bridge",
        run_packet_port_bridge_inner(tun, infrastructure, updates, shutdown, diagnostics),
    )
    .await
}

async fn run_packet_port_bridge_inner<P: PacketPort>(
    tun: P,
    infrastructure: PacketPortBinding,
    mut updates: mpsc::Receiver<PacketPortOwnerUpdate>,
    mut shutdown: watch::Receiver<bool>,
    diagnostics: Option<watch::Sender<PacketBridgeOutputStatus>>,
) -> io::Result<PacketBridgeCounters> {
    let tun = Arc::new(tun);
    let mut owner: Option<Owner> = None;
    let mut retained: Option<Owner> = None;
    let mut old_owner_drained = true;
    let mut forced_retirement = false;
    let mut pending: Option<PendingOwner> = None;
    let mut last_transaction: Option<OwnerTransactionReceipt> = None;
    let mut highest_transaction_revision = 0;
    let mut highest_owner_epoch = 0;
    let mut highest_policy_generation = 0;
    let mut retired = tokio::task::JoinSet::new();
    let mut control_available = true;
    let mut prefer_worker = false;
    let mut counters = PacketBridgeCounters::default();
    let mut outputs = PacketBridgeOutputStatus::default();
    let started = Instant::now();
    let period = std::time::Duration::from_secs(1);
    let mut sample_tick = tokio::time::interval_at(started + period, period);
    sample_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result = loop {
        if *shutdown.borrow() {
            break Ok(());
        }
        let worker = owner.as_ref().map(|owner| owner.port.clone());
        let retained_worker = retained.as_ref().map(|owner| owner.port.clone());
        let candidate = pending
            .as_ref()
            .map(|candidate| candidate.owner.port.clone());
        let expiry = owner.as_ref().map(|owner| owner.auth_deadline);
        let retained_expiry = retained.as_ref().map(|owner| owner.auth_deadline);
        let pending_expiry = pending.as_ref().map(|candidate| {
            candidate
                .transaction
                .prepare_deadline
                .min(candidate.transaction.auth_deadline)
        });
        let to_worker = owner.as_ref().map(|owner| owner.to_worker.admission());
        let to_tun = [
            owner.as_ref().map(|owner| owner.to_tun.admission()),
            retained.as_ref().map(|owner| owner.to_tun.admission()),
            pending
                .as_ref()
                .map(|candidate| candidate.owner.to_tun.admission()),
        ];
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break Ok(()); }
            }
            Some(joined) = retired.join_next(), if !retired.is_empty() => {
                let previous = joined.map_err(io::Error::other)?;
                collect(&previous, &mut counters, &mut outputs);
                if let Some(owner) = &owner { collect(owner, &mut counters, &mut outputs); }
            }
            _ = owner_expiry(expiry) => {
                tracing::warn!(code = "packet_port_owner_expired", module = "sdwan_tun_io",
                    owner_epoch = highest_owner_epoch, action = "revoke_domain_keep_infrastructure");
                revoke(&mut owner, &mut counters, &mut outputs).await;
            }
            _ = owner_expiry(retained_expiry) => {
                if let Some(previous) = retained.take() { retire(previous, &mut retired); }
                // Expiry is forced retirement, not an acknowledged drain.
                old_owner_drained = false;
                forced_retirement = true;
            }
            _ = owner_expiry(pending_expiry) => {
                let expired = pending.take().expect("pending expiry requires candidate");
                retire(expired.owner, &mut retired);
                last_transaction = Some(OwnerTransactionReceipt {
                    transaction: expired.transaction, phase: OwnerTransactionPhase::Expired,
                });
            }
            update = updates.recv(), if control_available => {
                let Some(update) = update else {
                    control_available = false;
                    // Control outage keeps the current owner only through its existing deadline.
                    continue;
                };
                if update.acknowledgement.is_closed() {
                    // Queued requests abandoned by the controller cannot
                    // replace a healthy owner later or consume its epoch.
                    continue;
                }
                let (change, authorization) = match update.change {
                    PacketPortOwnerChange::AttachAuthorized { port, auth_deadline, authorization } =>
                        (PacketPortOwnerChange::Attach { port, auth_deadline }, Some(authorization)),
                    change => (change, None),
                };
                let result = match change {
                    PacketPortOwnerChange::PrepareOwner { transaction, port, authorization } => {
                        let now = Instant::now();
                        let duplicate = pending.as_ref().is_some_and(|candidate| candidate.transaction == transaction)
                            || last_transaction.as_ref().is_some_and(|last| last.transaction == transaction && last.phase == OwnerTransactionPhase::Committed);
                        let identity_conflict = pending.as_ref().is_some_and(|candidate| candidate.transaction.transaction_id == transaction.transaction_id && candidate.transaction != transaction)
                            || last_transaction.as_ref().is_some_and(|last| last.transaction.transaction_id == transaction.transaction_id && last.transaction != transaction);
                        if !matches_infrastructure(&port, infrastructure) || port.binding() != transaction.binding || identity_conflict {
                            Err("code=owner_prepare_identity_mismatch module=packet_port_manager reason=FD_binding_or_transaction_payload_differs".into())
                        } else if duplicate {
                            // Retain the original FD, deadlines and authorization callback.
                            Ok(())
                        } else if transaction.transaction_id == [0; 16] || transaction.revision == 0 {
                            Err("code=owner_prepare_invalid_identity module=packet_port_manager reason=transaction_ID_and_revision_must_be_nonzero".into())
                        } else if transaction.revision <= highest_transaction_revision {
                            Err(format!("code=owner_prepare_stale_revision module=packet_port_manager revision={} highest_revision={highest_transaction_revision}", transaction.revision))
                        } else if retired.len() >= 8 {
                            Err("code=owner_prepare_cleanup_busy module=packet_port_manager reason=retired_writer_cleanup_pending limit=8 action=retry_prepare".into())
                        } else if pending.is_some() {
                            Err("code=owner_prepare_capacity module=packet_port_manager reason=pending_candidate_exists limit=1 action=commit_or_abort_existing_candidate".into())
                        } else if retained.is_some() {
                            Err("code=owner_prepare_drain_pending module=packet_port_manager reason=old_inbound_owner_retained action=finish_owner_drain".into())
                        } else if active_epoch(owner.as_ref()) != transaction.expected_active_epoch {
                            Err(format!("code=owner_prepare_active_changed module=packet_port_manager expected={:?} actual={:?}", transaction.expected_active_epoch, active_epoch(owner.as_ref())))
                        } else if transaction.binding.owner_epoch <= highest_owner_epoch
                            || transaction.binding.policy_generation < highest_policy_generation {
                            Err(format!("code=owner_prepare_stale_epoch module=packet_port_manager owner_epoch={} highest_owner_epoch={highest_owner_epoch} policy_generation={} highest_policy_generation={highest_policy_generation}", transaction.binding.owner_epoch, transaction.binding.policy_generation))
                        } else if transaction.prepare_deadline <= now || transaction.auth_deadline <= now
                            || transaction.prepare_deadline > transaction.auth_deadline
                            || transaction.prepare_deadline.duration_since(now) > std::time::Duration::from_secs(30) {
                            Err("code=owner_prepare_invalid_deadline module=packet_port_manager reason=prepare_must_be_live_within_authorization_and_30s_cap".into())
                        } else if let Err(error) = authorization() {
                            Err(format!("code=owner_prepare_unauthorized module=packet_port_manager detail={error}"))
                        } else {
                            highest_transaction_revision = transaction.revision;
                            let staged = Owner::new(port, tun.clone(), transaction.prepare_deadline, Some(transaction.auth_deadline), Some(authorization.clone()));
                            pending = Some(PendingOwner { transaction, owner: staged, authorization });
                            Ok(())
                        }
                    }
                    PacketPortOwnerChange::CommitOwner { transaction } => {
                        if last_transaction.as_ref().is_some_and(|last| last.transaction == transaction && last.phase == OwnerTransactionPhase::Committed) {
                            Ok(())
                        } else if !pending.as_ref().is_some_and(|candidate| candidate.transaction == transaction) {
                            Err("code=owner_commit_not_prepared module=packet_port_manager reason=exact_prepared_transaction_required".into())
                        } else if retired.len() >= 8 {
                            Err("code=owner_commit_cleanup_busy module=packet_port_manager reason=retired_writer_cleanup_pending limit=8 action=retry_commit".into())
                        } else if active_epoch(owner.as_ref()) != transaction.expected_active_epoch
                            || transaction.binding.owner_epoch <= highest_owner_epoch
                            || transaction.binding.policy_generation < highest_policy_generation {
                            Err(format!("code=owner_commit_active_changed module=packet_port_manager expected={:?} actual={:?} owner_epoch={} highest_owner_epoch={highest_owner_epoch} policy_generation={} highest_policy_generation={highest_policy_generation} action=preserve_active_owner", transaction.expected_active_epoch, active_epoch(owner.as_ref()), transaction.binding.owner_epoch, transaction.binding.policy_generation))
                        } else if transaction.auth_deadline <= Instant::now()
                            || transaction.prepare_deadline <= Instant::now() {
                            Err("code=owner_commit_expired module=packet_port_manager reason=prepare_or_authorization_deadline_elapsed action=preserve_active_owner".into())
                        } else if let Err(error) = (pending.as_ref().expect("validated pending transaction").authorization)() {
                            Err(format!("code=owner_commit_unauthorized module=packet_port_manager detail={error} action=preserve_active_owner"))
                        } else if owner.as_ref().is_some_and(|previous| previous.to_worker.pending_packets() != 0) {
                            // This actor is the only producer. No await separates
                            // this check from the send fence and owner swap, so
                            // accepted old output cannot be cancelled by commit.
                            Err("code=owner_commit_queue_pending module=packet_port_manager reason=predecessor_outbound_packets_pending action=retry_exact_commit".into())
                        } else {
                            let candidate = pending.take().expect("validated pending transaction");
                            let mut replacement = candidate.owner;
                            replacement.auth_deadline = transaction.auth_deadline;
                            replacement.deadline.send_replace(transaction.auth_deadline);
                            forced_retirement = false;
                            old_owner_drained = true;
                            // The fence is the linearization point. No await
                            // separates it from installing the prepared owner.
                            if let Some(previous) = owner.take() {
                                previous.fence.retire();
                                previous.to_worker.cancel();
                                retained = Some(previous);
                                old_owner_drained = false;
                            }
                            highest_owner_epoch = transaction.binding.owner_epoch;
                            highest_policy_generation = transaction.binding.policy_generation;
                            owner = Some(replacement);
                            outputs.binding = Some(transaction.binding);
                            last_transaction = Some(OwnerTransactionReceipt { transaction, phase: OwnerTransactionPhase::Committed });
                            Ok(())
                        }
                    }
                    PacketPortOwnerChange::FinishOwnerDrain { transaction } => {
                        if !last_transaction.as_ref().is_some_and(|last| last.transaction == transaction && last.phase == OwnerTransactionPhase::Committed) {
                            Err("code=owner_drain_not_committed module=packet_port_manager reason=exact_committed_transaction_required".into())
                        } else if forced_retirement {
                            Err("code=owner_drain_forced_retirement module=packet_port_manager reason=predecessor_expired_or_failed_without_acknowledged_drain".into())
                        } else if let Some(previous) = &retained {
                            match previous.port.has_pending_input().and_then(|pending| {
                                previous.to_tun.drained_through(previous.to_tun.checkpoint()).map(|drained| !pending && drained)
                            }) {
                                Ok(true) => {
                                    let previous = retained.take().expect("checked retained owner");
                                    retire(previous, &mut retired);
                                    old_owner_drained = true;
                                    Ok(())
                                }
                                Ok(false) => Err("code=owner_drain_queue_pending module=packet_port_manager reason=predecessor_packets_still_in_ipc_or_tun_output action=retry_exact_finish".into()),
                                Err(error) => Err(format!("code=owner_drain_probe_failed module=packet_port_manager detail={error}")),
                            }
                        } else {
                            old_owner_drained = true;
                            Ok(())
                        }
                    }
                    PacketPortOwnerChange::RetireOwnerAfterFailure { transaction } => {
                        if !last_transaction.as_ref().is_some_and(|last| last.transaction == transaction && last.phase == OwnerTransactionPhase::Committed)
                            || owner.as_ref().is_none_or(|owner| owner.port.binding() != transaction.binding) {
                            Err("code=owner_failure_retirement_not_committed module=packet_port_manager reason=exact_current_committed_transaction_required".into())
                        } else if transaction.prepare_deadline > Instant::now() {
                            Err("code=owner_failure_retirement_unexpired module=packet_port_manager reason=original_prepare_cap_still_valid action=retry_exact_drain".into())
                        } else if old_owner_drained && retained.is_none() && !forced_retirement {
                            Err("code=owner_failure_retirement_already_drained module=packet_port_manager reason=successful_drain_receipt_is_immutable".into())
                        } else {
                            if let Some(previous) = retained.take() {
                                let known_queued_packets = previous.to_tun.pending_packets();
                                tracing::warn!(code="owner_predecessor_retired_after_failure", module="packet_port_manager", known_queued_packets,
                                    reason="original_prepare_deadline_elapsed", old_owner_drained=false,
                                    "failed predecessor retired while preserving active owner and TUN");
                                retire(previous, &mut retired);
                            }
                            forced_retirement = true;
                            old_owner_drained = false;
                            Ok(())
                        }
                    }
                    PacketPortOwnerChange::AbortOwner { transaction } => {
                        if pending.as_ref().is_some_and(|candidate| candidate.transaction == transaction) {
                            let candidate = pending.take().expect("validated candidate");
                            retire(candidate.owner, &mut retired);
                            last_transaction = Some(OwnerTransactionReceipt { transaction, phase: OwnerTransactionPhase::Aborted });
                            Ok(())
                        } else if last_transaction.as_ref().is_some_and(|last| last.transaction == transaction && matches!(last.phase, OwnerTransactionPhase::Aborted | OwnerTransactionPhase::Expired)) {
                            Ok(())
                        } else if last_transaction.as_ref().is_some_and(|last| last.transaction == transaction && last.phase == OwnerTransactionPhase::Committed) {
                            Err("code=owner_transaction_committed module=packet_port_manager reason=committed_transaction_cannot_be_aborted action=inspect_receipt".into())
                        } else {
                            Err("code=owner_abort_not_prepared module=packet_port_manager reason=exact_pending_or_terminal_transaction_required action=preserve_active_owner".into())
                        }
                    }
                    PacketPortOwnerChange::ProbeTransaction { transaction_id, revision } => {
                        if pending.as_ref().is_some_and(|candidate| candidate.transaction.transaction_id == transaction_id && candidate.transaction.revision == revision)
                            || last_transaction.as_ref().is_some_and(|last| last.transaction.transaction_id == transaction_id && last.transaction.revision == revision) {
                            Ok(())
                        } else { Err("code=owner_transaction_unknown module=packet_port_manager reason=unknown_or_superseded action=inspect_actual_state_and_revision_watermark".into()) }
                    }
                    PacketPortOwnerChange::Attach { port, auth_deadline } => {
                        let binding = port.binding();
                        if port.role() != PacketPortRole::Infrastructure
                            || binding.infrastructure_id != infrastructure.infrastructure_id
                            || binding.infrastructure_generation != infrastructure.infrastructure_generation
                            || binding.io_epoch != infrastructure.io_epoch
                            || binding.routing_domain_id != infrastructure.routing_domain_id {
                            Err("packet port infrastructure or domain identity mismatch".into())
                        } else if retired.len() >= 8 {
                            Err("code=owner_attach_cleanup_busy module=packet_port_manager reason=retired_writer_cleanup_pending limit=8 action=retry_attach".into())
                        } else if retained.is_some() {
                            Err("code=owner_attach_drain_pending module=packet_port_manager reason=predecessor_inbound_retained action=finish_owner_drain".into())
                        } else if authorization.as_ref().is_some_and(|check| check().is_err())
                            || auth_deadline <= Instant::now() || binding.owner_epoch <= highest_owner_epoch
                            || binding.policy_generation < highest_policy_generation {
                            Err("expired authorization or stale owner/policy epoch".into())
                        } else {
                            // Check and construct the replacement before fencing the
                            // old owner. There is no await or failure branch afterwards.
                            let replacement = Owner::new(port, tun.clone(), auth_deadline, None, authorization);
                            if let Some(previous) = owner.take() { retire(previous, &mut retired); }
                            highest_owner_epoch = binding.owner_epoch;
                            highest_policy_generation = binding.policy_generation;
                            owner = Some(replacement);
                            outputs.binding = Some(binding);
                            Ok(())
                        }
                    }
                    PacketPortOwnerChange::Renew { owner_epoch, policy_generation, auth_deadline } => {
                        match owner.as_mut() {
                            Some(owner) if owner_epoch == highest_owner_epoch
                                && policy_generation == highest_policy_generation
                                && auth_deadline > owner.auth_deadline
                                && owner.transaction_cap.is_none_or(|cap| auth_deadline <= cap) => {
                                owner.auth_deadline = auth_deadline;
                                owner.deadline.send_replace(auth_deadline);
                                Ok(())
                            }
                            _ => Err("renewal requires matching live owner and advancing deadline".into()),
                        }
                    }
                    PacketPortOwnerChange::Revoke { owner_epoch } => {
                        if owner_epoch != highest_owner_epoch {
                            Err("revocation refers to stale owner epoch".into())
                        } else {
                            revoke(&mut owner, &mut counters, &mut outputs).await;
                            if let Some(previous) = retained.take() {
                                retire(previous, &mut retired);
                                forced_retirement = true;
                                old_owner_drained = false;
                            }
                            Ok(())
                        }
                    }
                    PacketPortOwnerChange::Probe => Ok(()),
                    PacketPortOwnerChange::AttachAuthorized { .. } => unreachable!("normalized authorized attach"),
                };
                if let Some(receipt_sender) = update.receipt {
                    let _ = receipt_sender.send(receipt(
                        owner.as_ref(),
                        highest_owner_epoch,
                        highest_policy_generation,
                        pending.as_ref(), last_transaction.as_ref(), highest_transaction_revision,
                        (retained.as_ref(), old_owner_drained, forced_retirement),
                    ));
                }
                let _ = update.acknowledgement.send(result);
            }
            (infrastructure_failure, error) = owner_failure(&mut owner) => {
                if infrastructure_failure && !is_authorization_failure(&error) {
                    tracing::error!(code = "tun_write_failed", module = "sdwan_tun_io",
                        detail = %error, action = "report_infrastructure_recovery_required");
                    break Err(error);
                }
                tracing::warn!(code = "packet_port_owner_failed", module = "sdwan_tun_io",
                    owner_epoch = highest_owner_epoch, detail = %error,
                    action = "revoke_domain_keep_infrastructure");
                counters.worker_failures += 1;
                revoke(&mut owner, &mut counters, &mut outputs).await;
            }
            error = inbound_failure(pending.as_mut().map(|candidate| &mut candidate.owner)) => {
                if !is_authorization_failure(&error) { break Err(error); }
                if let Some(candidate) = pending.take() {
                    retire(candidate.owner, &mut retired);
                    last_transaction = Some(OwnerTransactionReceipt { transaction: candidate.transaction, phase: OwnerTransactionPhase::Aborted });
                }
            }
            error = inbound_failure(retained.as_mut()) => {
                if !is_authorization_failure(&error) { break Err(error); }
                if let Some(previous) = retained.take() { retire(previous, &mut retired); }
                forced_retirement = true;
                old_owner_drained = false;
            }
            _ = sample_tick.tick(), if diagnostics.is_some() => {
                if let Some(owner) = &owner {
                    collect(owner, &mut counters, &mut outputs);
                }
                if let Some(previous) = &retained { collect(previous, &mut counters, &mut outputs); }
                if let Some(candidate) = &pending { collect(&candidate.owner, &mut counters, &mut outputs); }
                outputs.revision = outputs.revision.saturating_add(1);
                outputs.sampled_elapsed_millis = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                if let Some(sender) = &diagnostics { sender.send_replace(outputs.clone()); }
            }
            packet = next_data_packet(tun.as_ref(), worker.as_deref(), retained_worker.as_deref(), candidate.as_deref(), prefer_worker, to_worker, to_tun) => {
                prefer_worker = matches!(&packet, DataPacket::Tun(_));
                match packet {
                    DataPacket::Tun(Ok(packet)) => match &owner {
                        Some(owner) => { counters.record_enqueue(owner.to_worker.enqueue(packet)); }
                        None => counters.no_worker_drops += 1,
                    },
                    DataPacket::Tun(Err(error)) => break Err(error),
                    DataPacket::Worker(Ok(packet)) => {
                        if let Some(owner) = &owner { counters.record_enqueue(owner.to_tun.enqueue(packet)); }
                    }
                    DataPacket::Retained(Ok(packet)) => {
                        if let Some(old) = &retained { counters.record_enqueue(old.to_tun.enqueue(packet)); }
                    }
                    DataPacket::Candidate(Ok(packet)) => {
                        if let Some(candidate) = &pending { counters.record_enqueue(candidate.owner.to_tun.enqueue(packet)); }
                    }
                    DataPacket::Worker(Err(error)) => {
                        tracing::warn!(code = "packet_port_owner_failed", module = "sdwan_tun_io",
                            owner_epoch = highest_owner_epoch, detail = %error,
                            action = "revoke_domain_keep_infrastructure");
                        counters.worker_failures += 1;
                        revoke(&mut owner, &mut counters, &mut outputs).await;
                    }
                    DataPacket::Retained(Err(error)) => {
                        tracing::warn!(code = "packet_port_retained_inbound_failed", module = "sdwan_tun_io", detail = %error, action = "force_retire_without_drain_receipt");
                        if let Some(mut old) = retained.take() { old.retire(); old.to_worker.stop().await; old.to_tun.stop().await; collect(&old, &mut counters, &mut outputs); }
                        old_owner_drained = false;
                        forced_retirement = true;
                    }
                    DataPacket::Candidate(Err(error)) => {
                        tracing::warn!(code = "packet_port_candidate_inbound_failed", module = "sdwan_tun_io", detail = %error, action = "abort_owner_prepare");
                        if let Some(candidate) = pending.take() {
                            retire(candidate.owner, &mut retired);
                            last_transaction = Some(OwnerTransactionReceipt { transaction: candidate.transaction, phase: OwnerTransactionPhase::Aborted });
                        }
                    }
                }
            },
        }
    };
    revoke(&mut owner, &mut counters, &mut outputs).await;
    if let Some(candidate) = pending.take() {
        retire(candidate.owner, &mut retired);
    }
    if let Some(mut old) = retained.take() {
        old.retire();
        old.to_worker.stop().await;
        old.to_tun.stop().await;
        collect(&old, &mut counters, &mut outputs);
    }
    while let Some(joined) = retired.join_next().await {
        let previous = joined.map_err(io::Error::other)?;
        collect(&previous, &mut counters, &mut outputs);
    }
    if let Some(sender) = diagnostics {
        sender.send_replace(outputs);
    }
    result.map(|_| counters)
}

#[cfg(test)]
#[path = "packet_port_transaction_tests.rs"]
mod transaction_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fd::InheritedPacketFd;
    use crate::packet_port_ipc::PacketPortRole;
    use std::os::fd::OwnedFd;
    use std::time::Duration;
    use tokio::net::UnixDatagram;

    #[test]
    fn output_status_keeps_lifetime_counters_without_counting_admission_twice() {
        let mut status = PacketOutputStatus::default();
        status.accumulate(&crate::packet_port::OutputDelta {
            sent_packets: 2,
            queue_slot_exhausted: 3,
            deadline_drops: 1,
            queue_depth: 4,
            queue_high_watermark: 7,
            queued_write_attempts: 2,
            queue_wait_micros: 10,
            queue_wait_max_micros: 6,
            send_elapsed_micros: 8,
            send_elapsed_max_micros: 5,
            ..Default::default()
        });
        status.accumulate(&crate::packet_port::OutputDelta {
            sent_packets: 1,
            queue_slot_exhausted: 2,
            queue_high_watermark: 5,
            queue_wait_max_micros: 4,
            send_elapsed_max_micros: 3,
            ..Default::default()
        });
        assert_eq!(status.sent_packets, 3);
        assert_eq!(status.queue_slot_exhausted, 5);
        assert_eq!(status.deadline_drops, 1);
        assert_eq!(status.queue_depth, 0);
        assert_eq!(status.queue_high_watermark, 7);
        assert_eq!(status.queue_wait_max_micros, 6);
        assert_eq!(status.send_elapsed_max_micros, 5);
    }

    #[tokio::test]
    async fn observed_bridge_reports_actual_output_and_final_counters_once() {
        let (tun_socket, host) = UnixDatagram::pair().unwrap();
        let tun = InheritedPacketFd::new(OwnedFd::from(tun_socket.into_std().unwrap())).unwrap();
        let (io, worker) = ports(1);
        let (updates, receiver) = mpsc::channel(4);
        let (stop, shutdown) = watch::channel(false);
        let (diagnostics, mut snapshots) = watch::channel(PacketBridgeOutputStatus::default());
        let task = tokio::spawn(run_observed_packet_port_bridge(
            tun,
            binding(1),
            receiver,
            shutdown,
            Some(diagnostics),
        ));
        update(
            &updates,
            PacketPortOwnerChange::Attach {
                port: io,
                auth_deadline: Instant::now() + Duration::from_secs(60),
            },
        )
        .await
        .unwrap();
        worker.send_packet(&[0x45; 64]).await.unwrap();
        let mut packet = [0; 64];
        tokio::time::timeout(Duration::from_secs(2), host.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), snapshots.changed())
            .await
            .unwrap()
            .unwrap();
        let snapshot = snapshots.borrow().clone();
        assert_eq!(snapshot.to_tun.sent_packets, 1);
        assert_eq!(snapshot.to_tun.sent_bytes, 64);
        assert_eq!(snapshot.to_worker.sent_packets, 0);
        assert_eq!(snapshot.binding, Some(binding(1)));
        stop.send_replace(true);
        let counters = task.await.unwrap().unwrap();
        assert_eq!(counters.to_tun_packets, 1);
        assert_eq!(snapshots.borrow().to_tun.sent_packets, 1);
        assert_eq!(snapshots.borrow().binding, None);
    }

    #[tokio::test]
    async fn owner_replacement_retains_output_not_yet_sampled() {
        let (tun_socket, host) = UnixDatagram::pair().unwrap();
        let tun = InheritedPacketFd::new(OwnedFd::from(tun_socket.into_std().unwrap())).unwrap();
        let (updates, receiver) = mpsc::channel(4);
        let (stop, shutdown) = watch::channel(false);
        let (diagnostics, snapshots) = watch::channel(PacketBridgeOutputStatus::default());
        let task = tokio::spawn(run_observed_packet_port_bridge(
            tun,
            binding(1),
            receiver,
            shutdown,
            Some(diagnostics),
        ));
        for epoch in 1..=2 {
            let (io, worker) = ports(epoch);
            update(
                &updates,
                PacketPortOwnerChange::Attach {
                    port: io,
                    auth_deadline: Instant::now() + Duration::from_secs(60),
                },
            )
            .await
            .unwrap();
            worker.send_packet(&[0x45; 64]).await.unwrap();
            let mut packet = [0; 64];
            tokio::time::timeout(Duration::from_secs(2), host.recv(&mut packet))
                .await
                .unwrap()
                .unwrap();
            update(
                &updates,
                PacketPortOwnerChange::Revoke { owner_epoch: epoch },
            )
            .await
            .unwrap();
        }
        stop.send_replace(true);
        let counters = task.await.unwrap().unwrap();
        let final_status = snapshots.borrow();
        assert_eq!(counters.to_tun_packets, 2);
        assert_eq!(final_status.to_tun.sent_packets, 2);
        assert_eq!(final_status.to_tun.sent_bytes, 128);
        assert_eq!(final_status.to_tun.queue_depth, 0);
        assert_eq!(final_status.binding, None);
    }

    struct FloodTun {
        reads: Arc<std::sync::atomic::AtomicUsize>,
        writes: Arc<std::sync::atomic::AtomicUsize>,
        max_reads: usize,
        stop: watch::Sender<bool>,
    }

    impl PacketPort for FloodTun {
        fn try_send_packet(&self, packet: &[u8]) -> io::Result<bool> {
            assert_eq!(packet, &[0x46; 64]);
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.stop.send_replace(true);
            Ok(true)
        }
        async fn recv_packet(&self) -> io::Result<Vec<u8>> {
            let reads = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if reads >= self.max_reads {
                return Err(io::Error::other("worker output starved by ready TUN input"));
            }
            Ok(vec![0x45; 64])
        }
        async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
            self.try_send_packet(packet).map(|_| ())
        }
    }

    fn flood_tun(max_reads: usize) -> (FloodTun, watch::Receiver<bool>) {
        let (stop, shutdown) = watch::channel(false);
        (
            FloodTun {
                reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                writes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                max_reads,
                stop,
            },
            shutdown,
        )
    }

    #[tokio::test]
    async fn byte_backpressure_does_not_block_reverse_data_or_control_cancellation() {
        struct ReadyPort;
        impl PacketPort for ReadyPort {
            async fn recv_packet(&self) -> io::Result<Vec<u8>> {
                Ok(vec![7; 64])
            }
            async fn send_packet(&self, _: &[u8]) -> io::Result<()> {
                std::future::pending().await
            }
        }
        let mut full = PacketOutput::new(Arc::new(ReadyPort));
        for _ in 0..8 {
            full.enqueue(vec![1; 65_535]).unwrap();
        }
        let reverse = PacketOutput::new(Arc::new(ReadyPort));
        let packet = tokio::time::timeout(
            Duration::from_millis(20),
            next_data_packet(
                &ReadyPort,
                Some(&ReadyPort),
                None,
                None,
                false,
                Some(full.admission()),
                [Some(reverse.admission()), None, None],
            ),
        )
        .await
        .expect("one direction blocked reverse ingress");
        assert!(matches!(packet, DataPacket::Worker(Ok(data)) if data == vec![7; 64]));
        let mut cancelled = Box::pin(next_data_packet(
            &ReadyPort,
            Some(&ReadyPort),
            None,
            None,
            false,
            Some(full.admission()),
            [Some(full.admission()), None, None],
        ));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(cancelled.as_mut().poll(&mut context).is_pending());
        drop(cancelled); // Owner change/shutdown cancels the direction waits.
        let started = Instant::now();
        full.stop().await;
        assert!(started.elapsed() < Duration::from_millis(50));
        let mut reverse = reverse;
        reverse.stop().await;
    }

    #[tokio::test]
    async fn continuous_tun_input_cannot_starve_ready_worker_output() {
        use std::sync::atomic::Ordering;
        let (tun, shutdown) = flood_tun(32);
        let reads = tun.reads.clone();
        let writes = tun.writes.clone();
        let (socket, worker_socket) = UnixDatagram::pair().unwrap();
        let worker =
            UnixPacketPort::new(worker_socket, binding(1), PacketPortRole::Worker).unwrap();
        worker.send_packet(&[0x46; 64]).await.unwrap();
        // Establish readiness before the always-ready flood begins; no timer race.
        socket.readable().await.unwrap();
        let io = UnixPacketPort::new(socket, binding(1), PacketPortRole::Infrastructure).unwrap();
        let (updates, receiver) = mpsc::channel(4);
        let (acknowledgement, applied) = oneshot::channel();
        updates
            .try_send(PacketPortOwnerUpdate {
                change: PacketPortOwnerChange::Attach {
                    port: io,
                    auth_deadline: Instant::now() + Duration::from_secs(60),
                },
                acknowledgement,
                receipt: None,
            })
            .unwrap();
        let counters = run_managed_packet_port_bridge(tun, binding(1), receiver, shutdown)
            .await
            .unwrap();
        applied.await.unwrap().unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(counters.to_tun_packets, 1);
    }

    #[tokio::test]
    async fn queued_control_and_shutdown_keep_priority_over_tun_flood() {
        use std::sync::atomic::Ordering;
        let (tun, shutdown) = flood_tun(0);
        let reads = tun.reads.clone();
        let writes = tun.writes.clone();
        let (io, _worker) = ports(1);
        let (updates, receiver) = mpsc::channel(4);
        let mut acknowledgements = Vec::new();
        for change in [
            PacketPortOwnerChange::Attach {
                port: io,
                auth_deadline: Instant::now() + Duration::from_secs(60),
            },
            PacketPortOwnerChange::Revoke { owner_epoch: 1 },
        ] {
            let (acknowledgement, applied) = oneshot::channel();
            updates
                .try_send(PacketPortOwnerUpdate {
                    change,
                    acknowledgement,
                    receipt: None,
                })
                .unwrap();
            acknowledgements.push(applied);
        }
        let (acknowledgement, applied) = oneshot::channel();
        let (receipt, actual) = oneshot::channel();
        updates
            .try_send(PacketPortOwnerUpdate {
                change: PacketPortOwnerChange::Probe,
                acknowledgement,
                receipt: Some(receipt),
            })
            .unwrap();
        assert!(
            run_managed_packet_port_bridge(tun, binding(1), receiver, shutdown)
                .await
                .is_err()
        );
        for applied in acknowledgements {
            applied.await.unwrap().unwrap();
        }
        applied.await.unwrap().unwrap();
        let actual = actual.await.unwrap();
        assert_eq!(actual.binding, None);
        assert_eq!(actual.owner_epoch, 1);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(writes.load(Ordering::SeqCst), 0);

        let (tun, shutdown) = flood_tun(0);
        let reads = tun.reads.clone();
        tun.stop.send_replace(true);
        let (_updates, receiver) = mpsc::channel(1);
        run_managed_packet_port_bridge(tun, binding(1), receiver, shutdown)
            .await
            .unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    struct PollObservedPort(std::sync::atomic::AtomicUsize);

    impl PacketPort for PollObservedPort {
        fn try_send_packet(&self, _: &[u8]) -> io::Result<bool> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        }
        async fn recv_packet(&self) -> io::Result<Vec<u8>> {
            std::future::pending().await
        }
        async fn send_packet(&self, _: &[u8]) -> io::Result<()> {
            std::future::poll_fn(|_| {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::task::Poll::<io::Result<()>>::Pending
            })
            .await
        }
    }

    #[tokio::test]
    async fn authorization_is_checked_before_each_output_poll_and_failure_is_scoped() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let valid = Arc::new(AtomicBool::new(true));
        let check_valid = valid.clone();
        let authorization: AuthorizationCheck = Arc::new(move || {
            if check_valid.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "boot cap reached",
                ))
            }
        });
        let raw = Arc::new(PollObservedPort(AtomicUsize::new(0)));
        let (_deadline_tx, deadline) = watch::channel(Instant::now() + Duration::from_secs(60));
        let port = DeadlinePort {
            port: raw.clone(),
            deadline,
            authorization: Some(authorization),
            fence: Arc::new(OwnerFence::new()),
        };
        let send = port.send_packet(&[1]);
        tokio::pin!(send);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(send.as_mut().poll(&mut context).is_pending());
        assert_eq!(raw.0.load(Ordering::SeqCst), 1);
        valid.store(false, Ordering::SeqCst);
        let std::task::Poll::Ready(Err(error)) = send.as_mut().poll(&mut context) else {
            panic!("expired output must fail before polling the underlying port again");
        };
        assert!(is_authorization_failure(&error));
        assert_eq!(raw.0.load(Ordering::SeqCst), 1);
        assert!(is_authorization_failure(
            &port.try_send_packet(&[2]).unwrap_err()
        ));
        assert_eq!(raw.0.load(Ordering::SeqCst), 1);
        assert!(!is_authorization_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "real TUN permissions denied"
        )));
    }

    #[tokio::test]
    async fn authorized_owner_expiry_keeps_tun_and_allows_replacement() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (tun, kernel) = UnixDatagram::pair().unwrap();
        let tun = InheritedPacketFd::new(OwnedFd::from(tun.into_std().unwrap())).unwrap();
        let (stop, shutdown) = watch::channel(false);
        let (updates, receiver) = mpsc::channel(8);
        let task = tokio::spawn(run_managed_packet_port_bridge(
            tun,
            binding(1),
            receiver,
            shutdown,
        ));
        let valid = Arc::new(AtomicBool::new(true));
        let check_valid = valid.clone();
        let (io, worker) = ports(1);
        update(
            &updates,
            PacketPortOwnerChange::AttachAuthorized {
                port: io,
                auth_deadline: Instant::now() + Duration::from_secs(60),
                authorization: Arc::new(move || {
                    if check_valid.load(Ordering::SeqCst) {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "boot cap reached",
                        ))
                    }
                }),
            },
        )
        .await
        .unwrap();
        valid.store(false, Ordering::SeqCst);
        worker.send_packet(&[1; 64]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), kernel.recv(&mut [0; 256]))
                .await
                .is_err()
        );
        let actual = probe(&updates).await;
        assert!(actual.binding.is_none());
        assert!(!task.is_finished());
        let (replacement_io, replacement_worker) = ports(2);
        update(
            &updates,
            PacketPortOwnerChange::Attach {
                port: replacement_io,
                auth_deadline: Instant::now() + Duration::from_secs(60),
            },
        )
        .await
        .unwrap();
        replacement_worker.send_packet(&[2; 64]).await.unwrap();
        let mut packet = [0; 256];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), kernel.recv(&mut packet))
                .await
                .unwrap()
                .unwrap(),
            64
        );
        assert_eq!(&packet[..64], &[2; 64]);
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    fn binding(epoch: u64) -> PacketPortBinding {
        PacketPortBinding {
            infrastructure_id: [1; 16],
            routing_domain_id: [2; 16],
            infrastructure_generation: 1,
            io_epoch: 1,
            owner_epoch: epoch,
            policy_generation: epoch,
        }
    }
    fn ports(epoch: u64) -> (UnixPacketPort, UnixPacketPort) {
        let (io, worker) = UnixDatagram::pair().unwrap();
        (
            UnixPacketPort::new(io, binding(epoch), PacketPortRole::Infrastructure).unwrap(),
            UnixPacketPort::new(worker, binding(epoch), PacketPortRole::Worker).unwrap(),
        )
    }
    async fn update(
        tx: &mpsc::Sender<PacketPortOwnerUpdate>,
        change: PacketPortOwnerChange,
    ) -> Result<(), String> {
        let (acknowledgement, applied) = oneshot::channel();
        tx.send(PacketPortOwnerUpdate {
            change,
            acknowledgement,
            receipt: None,
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), applied)
            .await
            .unwrap()
            .unwrap()
    }

    async fn probe(tx: &mpsc::Sender<PacketPortOwnerUpdate>) -> PacketPortReceipt {
        let (acknowledgement, applied) = oneshot::channel();
        let (receipt, actual) = oneshot::channel();
        tx.send(PacketPortOwnerUpdate {
            change: PacketPortOwnerChange::Probe,
            acknowledgement,
            receipt: Some(receipt),
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), applied)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        actual.await.unwrap()
    }

    #[tokio::test]
    async fn actual_receipt_recovers_lost_ack_and_tracks_revoke_and_expiry() {
        let (tun, _kernel) = UnixDatagram::pair().unwrap();
        let tun = InheritedPacketFd::new(OwnedFd::from(tun.into_std().unwrap())).unwrap();
        let (updates, receiver) = mpsc::channel(4);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(run_managed_packet_port_bridge(
            tun,
            binding(1),
            receiver,
            shutdown,
        ));
        assert_eq!(probe(&updates).await.binding, None);
        let (io, _worker) = ports(1);
        let deadline = Instant::now() + Duration::from_secs(2);
        let (acknowledgement, applied) = oneshot::channel();
        let (receipt, actual) = oneshot::channel();
        updates
            .send(PacketPortOwnerUpdate {
                change: PacketPortOwnerChange::Attach {
                    port: io,
                    auth_deadline: deadline,
                },
                acknowledgement,
                receipt: Some(receipt),
            })
            .await
            .unwrap();
        let actual = actual.await.unwrap();
        // The side effect completed. Losing the ACK now must not make the
        // subsequent authenticated Probe describe the previous owner.
        drop(applied);
        assert_eq!(actual.binding, Some(binding(1)));
        assert_eq!(actual.auth_deadline, Some(deadline));
        assert_eq!(probe(&updates).await, actual);
        update(&updates, PacketPortOwnerChange::Revoke { owner_epoch: 1 })
            .await
            .unwrap();
        let revoked = probe(&updates).await;
        assert_eq!(revoked.binding, None);
        assert_eq!(revoked.auth_deadline, None);
        assert_eq!(revoked.owner_epoch, 1);
        let (io, _worker) = ports(2);
        update(
            &updates,
            PacketPortOwnerChange::Attach {
                port: io,
                auth_deadline: Instant::now() + Duration::from_millis(20),
            },
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let expired = probe(&updates).await;
        assert_eq!(expired.binding, None);
        assert_eq!(expired.owner_epoch, 2);
        assert_eq!(expired.policy_generation, 2);
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn abandoned_attach_does_not_consume_owner_epoch() {
        let (tun, kernel) = UnixDatagram::pair().unwrap();
        let tun = InheritedPacketFd::new(OwnedFd::from(tun.into_std().unwrap())).unwrap();
        let (updates, receiver) = mpsc::channel(4);
        let (acknowledgement, applied) = oneshot::channel();
        let (abandoned, _) = ports(1);
        drop(applied);
        updates
            .send(PacketPortOwnerUpdate {
                change: PacketPortOwnerChange::Attach {
                    port: abandoned,
                    auth_deadline: Instant::now() + Duration::from_secs(1),
                },
                acknowledgement,
                receipt: None,
            })
            .await
            .unwrap();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(run_managed_packet_port_bridge(
            tun,
            binding(1),
            receiver,
            shutdown,
        ));
        let (io, worker) = ports(1);
        update(
            &updates,
            PacketPortOwnerChange::Attach {
                port: io,
                auth_deadline: Instant::now() + Duration::from_secs(1),
            },
        )
        .await
        .unwrap();
        worker.send_packet(&[0x45; 64]).await.unwrap();
        let mut packet = [0; 128];
        let length = tokio::time::timeout(Duration::from_secs(1), kernel.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&packet[..length], &[0x45; 64]);
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn expired_owner_can_be_replaced_without_reopening_tun_and_old_epoch_is_rejected() {
        let (tun, kernel) = UnixDatagram::pair().unwrap();
        let tun = InheritedPacketFd::new(OwnedFd::from(tun.into_std().unwrap())).unwrap();
        let (updates, receiver) = mpsc::channel(4);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(run_managed_packet_port_bridge(
            tun,
            binding(1),
            receiver,
            shutdown,
        ));
        let (io, worker) = ports(1);
        update(
            &updates,
            PacketPortOwnerChange::Attach {
                port: io,
                auth_deadline: Instant::now() + Duration::from_millis(50),
            },
        )
        .await
        .unwrap();
        worker.send_packet(&[0x45; 64]).await.unwrap();
        kernel.recv(&mut [0; 128]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        kernel.send(&[0x45; 64]).await.unwrap();
        assert!(!matches!(
            tokio::time::timeout(Duration::from_millis(20), worker.recv_packet()).await,
            Ok(Ok(_))
        ));
        assert!(!task.is_finished());
        let (old, _) = ports(1);
        assert!(update(
            &updates,
            PacketPortOwnerChange::Attach {
                port: old,
                auth_deadline: Instant::now() + Duration::from_secs(1)
            }
        )
        .await
        .is_err());
        let (io, replacement) = ports(2);
        update(
            &updates,
            PacketPortOwnerChange::Attach {
                port: io,
                auth_deadline: Instant::now() + Duration::from_secs(1),
            },
        )
        .await
        .unwrap();
        assert!(
            update(&updates, PacketPortOwnerChange::Revoke { owner_epoch: 1 })
                .await
                .is_err()
        );
        kernel.send(&[0x46; 64]).await.unwrap();
        assert_eq!(replacement.recv_packet().await.unwrap(), vec![0x46; 64]);
        replacement.send_packet(&[0x47; 64]).await.unwrap();
        let mut packet = [0; 128];
        let size = kernel.recv(&mut packet).await.unwrap();
        assert_eq!(&packet[..size], &[0x47; 64]);
        stop.send(true).unwrap();
        let counters = task.await.unwrap().unwrap();
        assert_eq!(counters.no_worker_drops, 1);
        assert_eq!(
            (counters.to_tun_packets, counters.to_worker_packets),
            (2, 1)
        );
    }
    #[tokio::test]
    async fn control_loss_uses_existing_authorization_deadline_and_matching_renewal_only() {
        let (tun, kernel) = UnixDatagram::pair().unwrap();
        let tun = InheritedPacketFd::new(OwnedFd::from(tun.into_std().unwrap())).unwrap();
        let (updates, receiver) = mpsc::channel(4);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(run_managed_packet_port_bridge(
            tun,
            binding(1),
            receiver,
            shutdown,
        ));
        let (io, worker) = ports(1);
        update(
            &updates,
            PacketPortOwnerChange::Attach {
                port: io,
                auth_deadline: Instant::now() + Duration::from_millis(40),
            },
        )
        .await
        .unwrap();
        assert!(update(
            &updates,
            PacketPortOwnerChange::Renew {
                owner_epoch: 2,
                policy_generation: 1,
                auth_deadline: Instant::now() + Duration::from_secs(1)
            }
        )
        .await
        .is_err());
        update(
            &updates,
            PacketPortOwnerChange::Renew {
                owner_epoch: 1,
                policy_generation: 1,
                auth_deadline: Instant::now() + Duration::from_millis(120),
            },
        )
        .await
        .unwrap();
        drop(updates);
        tokio::time::sleep(Duration::from_millis(50)).await;
        kernel.send(&[0x45; 64]).await.unwrap();
        assert_eq!(worker.recv_packet().await.unwrap(), vec![0x45; 64]);
        tokio::time::sleep(Duration::from_millis(100)).await;
        kernel.send(&[0x45; 64]).await.unwrap();
        assert!(!matches!(
            tokio::time::timeout(Duration::from_millis(20), worker.recv_packet()).await,
            Ok(Ok(_))
        ));
        assert!(!task.is_finished());
        // A closed worker socket can return before the independent reader drains.
        tokio::time::sleep(Duration::from_millis(10)).await;
        stop.send(true).unwrap();
        let counters = task.await.unwrap().unwrap();
        assert_eq!(counters.no_worker_drops, 1);
    }
}
