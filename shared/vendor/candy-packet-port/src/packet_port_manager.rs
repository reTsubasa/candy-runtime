//! Single-domain infrastructure ownership control, independent of peer/worker lifecycle.

use crate::packet_port::{PacketOutput, PacketPort};
use crate::packet_port_ipc::{
    PacketBridgeCounters, PacketPortBinding, PacketPortRole, UnixPacketPort,
};
use std::future::Future;
use std::io;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketPortReceipt {
    pub binding: Option<PacketPortBinding>,
    pub auth_deadline: Option<Instant>,
    pub owner_epoch: u64,
    pub policy_generation: u64,
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
    to_worker: PacketOutput,
    to_tun: PacketOutput,
}

async fn owner_packet<P: PacketPort>(port: Option<&P>) -> io::Result<Vec<u8>> {
    match port {
        Some(port) => port.recv_packet().await,
        None => std::future::pending().await,
    }
}

enum DataPacket {
    FromTun(io::Result<Vec<u8>>),
    FromWorker(io::Result<Vec<u8>>),
}

async fn next_data_packet<T: PacketPort, W: PacketPort>(
    tun: &T,
    worker: Option<&W>,
    prefer_worker: bool,
) -> DataPacket {
    // Control stays in the outer select; only the two data directions rotate.
    if prefer_worker {
        tokio::select! {
            biased;
            packet = owner_packet(worker) => DataPacket::FromWorker(packet),
            packet = tun.recv_packet() => DataPacket::FromTun(packet),
        }
    } else {
        tokio::select! {
            biased;
            packet = tun.recv_packet() => DataPacket::FromTun(packet),
            packet = owner_packet(worker) => DataPacket::FromWorker(packet),
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

async fn owner_expiry(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn collect(owner: &Owner, counters: &mut PacketBridgeCounters) {
    let tx = owner.to_worker.take_delta();
    let rx = owner.to_tun.take_delta();
    counters.to_worker_packets += tx.sent_packets;
    counters.to_tun_packets += rx.sent_packets;
    counters.to_worker_bytes += tx.sent_bytes;
    counters.to_tun_bytes += rx.sent_bytes;
    counters.backpressure_drops += tx.backpressure_drops + rx.backpressure_drops;
    counters.deadline_drops += tx.deadline_drops + rx.deadline_drops;
    counters.stale_drops += tx.stale_drops + rx.stale_drops;
}

fn receipt(
    owner: Option<&Owner>,
    highest_owner_epoch: u64,
    highest_policy_generation: u64,
) -> PacketPortReceipt {
    PacketPortReceipt {
        binding: owner.map(|owner| owner.port.binding()),
        auth_deadline: owner.map(|owner| owner.auth_deadline),
        owner_epoch: highest_owner_epoch,
        policy_generation: highest_policy_generation,
    }
}

async fn revoke(owner: &mut Option<Owner>, counters: &mut PacketBridgeCounters) {
    if let Some(mut previous) = owner.take() {
        previous.to_worker.stop().await;
        previous.to_tun.stop().await;
        collect(&previous, counters);
    }
}

struct DeadlinePort<P> {
    port: Arc<P>,
    deadline: watch::Receiver<Instant>,
    authorization: Option<AuthorizationCheck>,
}

impl<P: PacketPort> PacketPort for DeadlinePort<P> {
    fn max_packet_size(&self) -> usize {
        self.port.max_packet_size()
    }
    fn try_send_packet(&self, packet: &[u8]) -> io::Result<bool> {
        if let Some(authorization) = &self.authorization {
            authorization().map_err(authorization_failure)?;
        }
        if Instant::now() >= *self.deadline.borrow() {
            return Ok(false);
        }
        self.port.try_send_packet(packet)
    }
    async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        self.port.recv_packet().await
    }
    async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        let mut deadline_rx = self.deadline.clone();
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
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(authorization_failure(io::Error::new(io::ErrorKind::PermissionDenied, "routing-domain authorization expired during output")));
                }
                changed = deadline_rx.changed() => {
                    if changed.is_err() { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "authorization publisher closed")); }
                }
                result = std::future::poll_fn(|cx| {
                    if let Some(authorization) = &self.authorization {
                        if let Err(error) = authorization() {
                            return std::task::Poll::Ready(Err(authorization_failure(error)));
                        }
                    }
                    send.as_mut().poll(cx)
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
    mut updates: mpsc::Receiver<PacketPortOwnerUpdate>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<PacketBridgeCounters> {
    let tun = Arc::new(tun);
    let mut owner: Option<Owner> = None;
    let mut highest_owner_epoch = 0;
    let mut highest_policy_generation = 0;
    let (deadline_tx, deadline_rx) = watch::channel(Instant::now());
    let mut control_available = true;
    let mut prefer_worker = false;
    let mut counters = PacketBridgeCounters::default();
    let result = loop {
        if *shutdown.borrow() {
            break Ok(());
        }
        let worker = owner.as_ref().map(|owner| owner.port.clone());
        let expiry = owner.as_ref().map(|owner| owner.auth_deadline);
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break Ok(()); }
            }
            _ = owner_expiry(expiry) => {
                tracing::warn!(code = "packet_port_owner_expired", module = "sdwan_tun_io",
                    owner_epoch = highest_owner_epoch, action = "revoke_domain_keep_infrastructure");
                revoke(&mut owner, &mut counters).await;
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
                    PacketPortOwnerChange::Attach { port, auth_deadline } => {
                        let binding = port.binding();
                        if port.role() != PacketPortRole::Infrastructure
                            || binding.infrastructure_id != infrastructure.infrastructure_id
                            || binding.infrastructure_generation != infrastructure.infrastructure_generation
                            || binding.io_epoch != infrastructure.io_epoch
                            || binding.routing_domain_id != infrastructure.routing_domain_id {
                            Err("packet port infrastructure or domain identity mismatch".into())
                        } else if authorization.as_ref().is_some_and(|check| check().is_err())
                            || auth_deadline <= Instant::now() || binding.owner_epoch <= highest_owner_epoch
                            || binding.policy_generation < highest_policy_generation {
                            Err("expired authorization or stale owner/policy epoch".into())
                        } else {
                            revoke(&mut owner, &mut counters).await;
                            if auth_deadline <= Instant::now()
                                || authorization.as_ref().is_some_and(|check| check().is_err()) {
                                Err("authorization expired while stopping prior owner".into())
                            } else {
                                highest_owner_epoch = binding.owner_epoch;
                                highest_policy_generation = binding.policy_generation;
                                deadline_tx.send_replace(auth_deadline);
                                let port = Arc::new(port);
                                owner = Some(Owner {
                                    to_worker: PacketOutput::new(Arc::new(DeadlinePort { port: port.clone(), deadline: deadline_rx.clone(), authorization: authorization.clone() })),
                                    to_tun: PacketOutput::new(Arc::new(DeadlinePort { port: tun.clone(), deadline: deadline_rx.clone(), authorization })),
                                    port, auth_deadline,
                                });
                                Ok(())
                            }
                        }
                    }
                    PacketPortOwnerChange::Renew { owner_epoch, policy_generation, auth_deadline } => {
                        match owner.as_mut() {
                            Some(owner) if owner_epoch == highest_owner_epoch
                                && policy_generation == highest_policy_generation
                                && auth_deadline > owner.auth_deadline => {
                                owner.auth_deadline = auth_deadline;
                                deadline_tx.send_replace(auth_deadline);
                                Ok(())
                            }
                            _ => Err("renewal requires matching live owner and advancing deadline".into()),
                        }
                    }
                    PacketPortOwnerChange::Revoke { owner_epoch } => {
                        if owner_epoch != highest_owner_epoch {
                            Err("revocation refers to stale owner epoch".into())
                        } else {
                            revoke(&mut owner, &mut counters).await;
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
                revoke(&mut owner, &mut counters).await;
            }
            packet = next_data_packet(tun.as_ref(), worker.as_deref(), prefer_worker) => {
                prefer_worker = matches!(&packet, DataPacket::FromTun(_));
                match packet {
                    DataPacket::FromTun(Ok(packet)) => match &owner {
                        Some(owner) => { counters.record_enqueue(owner.to_worker.enqueue(packet)); }
                        None => counters.no_worker_drops += 1,
                    },
                    DataPacket::FromTun(Err(error)) => break Err(error),
                    DataPacket::FromWorker(Ok(packet)) => {
                        if let Some(owner) = &owner {
                            counters.record_enqueue(owner.to_tun.enqueue(packet));
                        }
                    }
                    DataPacket::FromWorker(Err(error)) => {
                        tracing::warn!(code = "packet_port_owner_failed", module = "sdwan_tun_io",
                            owner_epoch = highest_owner_epoch, detail = %error,
                            action = "revoke_domain_keep_infrastructure");
                        counters.worker_failures += 1;
                        revoke(&mut owner, &mut counters).await;
                    }
                }
            },
        }
    };
    revoke(&mut owner, &mut counters).await;
    result.map(|_| counters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fd::InheritedPacketFd;
    use crate::packet_port_ipc::PacketPortRole;
    use std::os::fd::OwnedFd;
    use std::time::Duration;
    use tokio::net::UnixDatagram;

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
