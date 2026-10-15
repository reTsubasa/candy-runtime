use super::*;
use crate::fd::InheritedPacketFd;
use std::{os::fd::OwnedFd, time::Duration};
use tokio::net::UnixDatagram;

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
    let (a, b) = UnixDatagram::pair().unwrap();
    (
        UnixPacketPort::new(a, binding(epoch), PacketPortRole::Infrastructure).unwrap(),
        UnixPacketPort::new(b, binding(epoch), PacketPortRole::Worker).unwrap(),
    )
}
fn transaction(revision: u64, epoch: u64, expected: Option<u64>) -> OwnerTransaction {
    let now = Instant::now();
    OwnerTransaction {
        transaction_id: [revision as u8; 16],
        revision,
        expected_active_epoch: expected,
        binding: binding(epoch),
        auth_deadline: now + Duration::from_secs(10),
        prepare_deadline: now + Duration::from_secs(5),
    }
}
async fn change(
    tx: &mpsc::Sender<PacketPortOwnerUpdate>,
    change: PacketPortOwnerChange,
) -> (Result<(), String>, PacketPortReceipt) {
    let (acknowledgement, ack) = oneshot::channel();
    let (receipt, actual) = oneshot::channel();
    tx.send(PacketPortOwnerUpdate {
        change,
        acknowledgement,
        receipt: Some(receipt),
    })
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), ack)
        .await
        .unwrap()
        .unwrap();
    (result, actual.await.unwrap())
}
struct Fixture {
    tx: mpsc::Sender<PacketPortOwnerUpdate>,
    kernel: UnixDatagram,
    worker: UnixPacketPort,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<io::Result<PacketBridgeCounters>>,
}
impl Fixture {
    async fn new() -> Self {
        let (tun, kernel) = UnixDatagram::pair().unwrap();
        let tun = InheritedPacketFd::new(OwnedFd::from(tun.into_std().unwrap())).unwrap();
        let (tx, rx) = mpsc::channel(8);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(run_managed_packet_port_bridge(
            tun,
            binding(1),
            rx,
            shutdown,
        ));
        let (io, worker) = ports(1);
        change(
            &tx,
            PacketPortOwnerChange::Attach {
                port: io,
                auth_deadline: Instant::now() + Duration::from_secs(10),
            },
        )
        .await
        .0
        .unwrap();
        Self {
            tx,
            kernel,
            worker,
            stop,
            task,
        }
    }
    async fn old_still_works(&self) {
        self.kernel.send(&[0x45; 64]).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), self.worker.recv_packet())
                .await
                .unwrap()
                .unwrap(),
            vec![0x45; 64]
        );
        self.worker.send_packet(&[0x46; 64]).await.unwrap();
        let mut packet = [0; 128];
        let len = tokio::time::timeout(Duration::from_secs(1), self.kernel.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&packet[..len], &[0x46; 64]);
    }
    async fn stop(self) -> PacketBridgeCounters {
        self.stop.send_replace(true);
        self.task.await.unwrap().unwrap()
    }
}
fn prepare(transaction: OwnerTransaction, port: UnixPacketPort) -> PacketPortOwnerChange {
    PacketPortOwnerChange::PrepareOwner {
        transaction,
        port,
        authorization: Arc::new(|| Ok(())),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_pending_writer_cannot_send_after_readiness_or_deadline_changes() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct PendingPort {
        ready: AtomicBool,
        sends: AtomicUsize,
        entered: tokio::sync::Notify,
        wake: tokio::sync::Notify,
    }
    impl PacketPort for PendingPort {
        async fn recv_packet(&self) -> io::Result<Vec<u8>> {
            std::future::pending().await
        }
        async fn send_packet(&self, _: &[u8]) -> io::Result<()> {
            self.entered.notify_one();
            loop {
                let wake = self.wake.notified();
                if self.ready.load(Ordering::SeqCst) {
                    self.sends.fetch_add(1, Ordering::SeqCst);
                    return Ok(());
                }
                wake.await;
            }
        }
    }
    let raw = Arc::new(PendingPort {
        ready: AtomicBool::new(false),
        sends: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        wake: tokio::sync::Notify::new(),
    });
    let fence = Arc::new(OwnerFence::new());
    let (deadline, deadline_rx) = watch::channel(Instant::now() + Duration::from_secs(1));
    let port = Arc::new(DeadlinePort {
        port: raw.clone(),
        deadline: deadline_rx,
        authorization: None,
        fence: fence.clone(),
    });
    let writer = port.clone();
    let task = tokio::spawn(async move { writer.send_packet(&[1]).await });
    raw.entered.notified().await;
    fence.retire();
    deadline.send_replace(Instant::now() + Duration::from_secs(60));
    raw.ready.store(true, Ordering::SeqCst);
    raw.wake.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(is_authorization_failure(&error));
    assert!(is_authorization_failure(
        &port.try_send_packet(&[2]).unwrap_err()
    ));
    assert_eq!(raw.sends.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn prepare_keeps_real_fd_active_and_commit_is_exact_and_idempotent() {
    let f = Fixture::new().await;
    let (io, next) = ports(2);
    let tx = transaction(1, 2, Some(1));
    let before = change(&f.tx, PacketPortOwnerChange::Probe).await.1;
    let prepared = change(&f.tx, prepare(tx.clone(), io)).await;
    prepared.0.unwrap();
    assert_eq!(prepared.1.binding, before.binding);
    assert_eq!(prepared.1.auth_deadline, before.auth_deadline);
    assert_eq!(
        prepared.1.pending.as_ref().unwrap().phase,
        OwnerTransactionPhase::Prepared
    );
    next.send_packet(&[0x49; 64]).await.unwrap();
    f.old_still_works().await;
    let (duplicate, _unused) = ports(2);
    change(&f.tx, prepare(tx.clone(), duplicate))
        .await
        .0
        .unwrap();
    let (wrong_binding, _) = ports(3);
    assert!(change(&f.tx, prepare(tx.clone(), wrong_binding))
        .await
        .0
        .is_err());
    let (_, wrong_role) = ports(2);
    assert!(change(&f.tx, prepare(tx.clone(), wrong_role))
        .await
        .0
        .is_err());
    for field in 0..3 {
        let mut conflicting = tx.clone();
        match field {
            0 => conflicting.auth_deadline += Duration::from_secs(1),
            1 => conflicting.revision += 1,
            _ => conflicting.binding = binding(3),
        }
        let (io, _) = ports(conflicting.binding.owner_epoch);
        let (result, receipt) = change(&f.tx, prepare(conflicting, io)).await;
        assert!(result.is_err());
        assert_eq!(receipt.pending.as_ref().unwrap().transaction, tx);
        assert_eq!(receipt.binding, before.binding);
        assert_eq!(receipt.auth_deadline, before.auth_deadline);
    }
    let mut forged = tx.clone();
    forged.auth_deadline += Duration::from_secs(1);
    assert!(change(
        &f.tx,
        PacketPortOwnerChange::CommitOwner {
            transaction: forged
        }
    )
    .await
    .0
    .is_err());
    f.old_still_works().await;
    let (result, actual) = change(
        &f.tx,
        PacketPortOwnerChange::CommitOwner {
            transaction: tx.clone(),
        },
    )
    .await;
    result.unwrap();
    assert_eq!(actual.binding, Some(binding(2)));
    assert_eq!(
        actual.last_transaction.as_ref().unwrap().phase,
        OwnerTransactionPhase::Committed
    );
    assert!(actual.pending.is_none());
    assert_eq!(
        change(
            &f.tx,
            PacketPortOwnerChange::CommitOwner {
                transaction: tx.clone()
            }
        )
        .await
        .1,
        actual
    );
    f.kernel.send(&[0x47; 64]).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), next.recv_packet())
            .await
            .unwrap()
            .unwrap(),
        vec![0x47; 64]
    );
    let mut packet = [0; 128];
    let len = tokio::time::timeout(Duration::from_secs(1), f.kernel.recv(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&packet[..len], &[0x49; 64]);
    next.send_packet(&[0x48; 64]).await.unwrap();
    let len = tokio::time::timeout(Duration::from_secs(1), f.kernel.recv(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&packet[..len], &[0x48; 64]);
    let (aborted, terminal) = change(
        &f.tx,
        PacketPortOwnerChange::AbortOwner {
            transaction: tx.clone(),
        },
    )
    .await;
    assert!(aborted
        .unwrap_err()
        .contains("code=owner_transaction_committed"));
    assert_eq!(terminal, actual);
    assert!(change(
        &f.tx,
        PacketPortOwnerChange::Renew {
            owner_epoch: 2,
            policy_generation: 2,
            auth_deadline: tx.auth_deadline + Duration::from_secs(1)
        }
    )
    .await
    .0
    .is_err());
    let counters = f.stop().await;
    assert_eq!(counters.to_worker_packets, 3);
    assert_eq!(counters.to_tun_packets, 4);
}

#[tokio::test]
async fn candidate_capacity_abort_expiry_and_replays_preserve_old_owner() {
    let f = Fixture::new().await;
    let first = transaction(1, 2, Some(1));
    let (io, _next) = ports(2);
    change(&f.tx, prepare(first.clone(), io)).await.0.unwrap();
    let second = transaction(2, 3, Some(1));
    let (io, _other) = ports(3);
    assert!(change(&f.tx, prepare(second, io)).await.0.is_err());
    let mut wrong = first.clone();
    wrong.transaction_id = [9; 16];
    assert!(change(
        &f.tx,
        PacketPortOwnerChange::AbortOwner { transaction: wrong }
    )
    .await
    .0
    .is_err());
    let (_, aborted) = change(
        &f.tx,
        PacketPortOwnerChange::AbortOwner {
            transaction: first.clone(),
        },
    )
    .await;
    assert_eq!(
        aborted.last_transaction.as_ref().unwrap().phase,
        OwnerTransactionPhase::Aborted
    );
    let (result, repeated) = change(
        &f.tx,
        PacketPortOwnerChange::AbortOwner {
            transaction: first.clone(),
        },
    )
    .await;
    result.unwrap();
    assert_eq!(repeated, aborted);
    let (io, _) = ports(2);
    assert!(change(&f.tx, prepare(first.clone(), io)).await.0.is_err());
    f.old_still_works().await;
    let mut expiring = transaction(2, 2, Some(1));
    expiring.prepare_deadline = Instant::now() + Duration::from_millis(25);
    let (io, _next) = ports(2);
    change(&f.tx, prepare(expiring.clone(), io))
        .await
        .0
        .unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    let (result, actual) = change(
        &f.tx,
        PacketPortOwnerChange::ProbeTransaction {
            transaction_id: expiring.transaction_id,
            revision: expiring.revision,
        },
    )
    .await;
    result.unwrap();
    assert_eq!(
        actual.last_transaction.unwrap().phase,
        OwnerTransactionPhase::Expired
    );
    assert!(change(
        &f.tx,
        PacketPortOwnerChange::CommitOwner {
            transaction: expiring
        }
    )
    .await
    .0
    .is_err());
    f.old_still_works().await;
    f.stop().await;
}

#[tokio::test]
async fn revoked_candidate_and_intervening_active_epoch_cannot_commit() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let f = Fixture::new().await;
    let valid = Arc::new(AtomicBool::new(true));
    let check = valid.clone();
    let tx = transaction(1, 2, Some(1));
    let (io, _next) = ports(2);
    change(
        &f.tx,
        PacketPortOwnerChange::PrepareOwner {
            transaction: tx.clone(),
            port: io,
            authorization: Arc::new(move || {
                if check.load(Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "revoked candidate",
                    ))
                }
            }),
        },
    )
    .await
    .0
    .unwrap();
    valid.store(false, Ordering::SeqCst);
    assert!(change(
        &f.tx,
        PacketPortOwnerChange::CommitOwner {
            transaction: tx.clone()
        }
    )
    .await
    .0
    .is_err());
    f.old_still_works().await;
    valid.store(true, Ordering::SeqCst);
    let (io, _replacement) = ports(3);
    change(
        &f.tx,
        PacketPortOwnerChange::Attach {
            port: io,
            auth_deadline: Instant::now() + Duration::from_secs(10),
        },
    )
    .await
    .0
    .unwrap();
    let (result, actual) = change(
        &f.tx,
        PacketPortOwnerChange::CommitOwner { transaction: tx },
    )
    .await;
    assert!(result.is_err());
    assert_eq!(actual.binding, Some(binding(3)));
    f.stop().await;
}

#[tokio::test]
async fn lost_commit_ack_recovers_exact_receipt_and_never_reinstalls_owner() {
    let f = Fixture::new().await;
    let tx = transaction(1, 2, Some(1));
    let (io, _next) = ports(2);
    change(&f.tx, prepare(tx.clone(), io)).await.0.unwrap();
    let (acknowledgement, ack) = oneshot::channel();
    let (receipt, actual) = oneshot::channel();
    f.tx.send(PacketPortOwnerUpdate {
        change: PacketPortOwnerChange::CommitOwner {
            transaction: tx.clone(),
        },
        acknowledgement,
        receipt: Some(receipt),
    })
    .await
    .unwrap();
    let committed = actual.await.unwrap();
    drop(ack);
    assert_eq!(
        change(
            &f.tx,
            PacketPortOwnerChange::ProbeTransaction {
                transaction_id: tx.transaction_id,
                revision: tx.revision
            }
        )
        .await
        .1,
        committed
    );
    change(&f.tx, PacketPortOwnerChange::Revoke { owner_epoch: 2 })
        .await
        .0
        .unwrap();
    let (result, actual) = change(
        &f.tx,
        PacketPortOwnerChange::CommitOwner { transaction: tx },
    )
    .await;
    result.unwrap();
    assert!(actual.binding.is_none());
    assert_eq!(
        actual.last_transaction.unwrap().phase,
        OwnerTransactionPhase::Committed
    );
    f.stop().await;
}

#[tokio::test]
async fn prepare_does_not_extend_old_authorization_and_abandoned_requests_do_not_reserve() {
    let f = Fixture::new().await;
    let tx = transaction(1, 2, Some(1));
    let (io, _next) = ports(2);
    let (acknowledgement, abandoned) = oneshot::channel();
    drop(abandoned);
    f.tx.send(PacketPortOwnerUpdate {
        change: prepare(tx.clone(), io),
        acknowledgement,
        receipt: None,
    })
    .await
    .unwrap();
    let actual = change(&f.tx, PacketPortOwnerChange::Probe).await.1;
    assert_eq!(actual.highest_transaction_revision, 0);
    assert!(actual.pending.is_none());

    let short_cap = Instant::now() + Duration::from_millis(50);
    let (io, _short_owner) = ports(2);
    change(
        &f.tx,
        PacketPortOwnerChange::Attach {
            port: io,
            auth_deadline: short_cap,
        },
    )
    .await
    .0
    .unwrap();
    let candidate = transaction(1, 3, Some(2));
    let (io, _candidate_worker) = ports(3);
    let actual = change(&f.tx, prepare(candidate.clone(), io)).await;
    actual.0.unwrap();
    assert_eq!(actual.1.auth_deadline, Some(short_cap));
    tokio::time::sleep(Duration::from_millis(70)).await;
    let actual = change(&f.tx, PacketPortOwnerChange::Probe).await.1;
    assert!(actual.binding.is_none());
    assert!(actual.pending.is_some());
    let result = change(
        &f.tx,
        PacketPortOwnerChange::CommitOwner {
            transaction: candidate,
        },
    )
    .await;
    assert!(
        result.0.is_err(),
        "expired expected active owner must not pass CAS"
    );
    assert!(result.1.binding.is_none());
    assert!(!f.task.is_finished());
    f.stop().await;
}
