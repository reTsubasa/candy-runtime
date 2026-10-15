//! Packet boundary between routing workers and network I/O infrastructure.

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

/// Implementations must preserve packet boundaries. Cancelling a pending send
/// must never deliver a partial packet. Only the infrastructure adapter owns
/// kernel descriptors; routing workers can also use an IPC implementation.
pub trait PacketPort: Send + Sync + 'static {
    fn max_packet_size(&self) -> usize {
        65_535
    }
    /// Complete one nonblocking packet write, or return false without writing.
    /// Implementations that cannot do this safely keep the queued async path.
    fn try_send_packet(&self, _packet: &[u8]) -> io::Result<bool> {
        Ok(false)
    }
    fn recv_packet(&self) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
    fn send_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> impl Future<Output = io::Result<()>> + Send + 'a;
}

const OUTPUT_PACKET_LIMIT: usize = 256;
const OUTPUT_BYTE_LIMIT: usize = 512 * 1024;
const OUTPUT_WRITE_TIMEOUT: Duration = Duration::from_millis(100);
// Ready writes bypass reactor futures, so explicitly yield between bounded
// batches. Epoch and deadline checks still run before every packet.
const OUTPUT_DRAIN_BATCH: usize = 64;

#[derive(Default)]
struct OutputMetrics {
    sent_packets: AtomicU64,
    sent_bytes: AtomicU64,
    backpressure_drops: AtomicU64,
    deadline_drops: AtomicU64,
    stale_drops: AtomicU64,
    /// Queue admission failures split by the resource that was exhausted.
    queue_slot_exhausted: AtomicU64,
    queue_byte_exhausted: AtomicU64,
    queue_channel_full: AtomicU64,
    /// Maximum number of in-flight/queued packets.
    queue_high_watermark: AtomicU64,
    /// Number of nonblocking writes that observed a non-writable packet fd.
    write_blocked_events: AtomicU64,
    queued_write_attempts: AtomicU64,
    queue_wait_micros: AtomicU64,
    queue_wait_max_micros: AtomicU64,
    send_elapsed_micros: AtomicU64,
    send_elapsed_max_micros: AtomicU64,
}

#[derive(Default)]
pub struct OutputDelta {
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub backpressure_drops: u64,
    pub deadline_drops: u64,
    pub stale_drops: u64,
    pub queue_slot_exhausted: u64,
    pub queue_byte_exhausted: u64,
    pub queue_channel_full: u64,
    pub queue_depth: u64,
    pub queue_high_watermark: u64,
    pub write_blocked_events: u64,
    pub queued_write_attempts: u64,
    pub queue_wait_micros: u64,
    pub queue_wait_max_micros: u64,
    pub send_elapsed_micros: u64,
    pub send_elapsed_max_micros: u64,
}

struct QueuedPacket {
    epoch: u64,
    packet: Vec<u8>,
    _credit: OwnedSemaphorePermit,
    _slot_credit: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
    outstanding: Arc<AtomicUsize>,
    queue_depth: Arc<AtomicUsize>,
    failure: Option<io::Error>,
}

impl Drop for QueuedPacket {
    fn drop(&mut self) {
        self.outstanding.fetch_sub(1, Ordering::Release);
        self.queue_depth.fetch_sub(1, Ordering::Release);
    }
}

type NonblockingPacketWrite = dyn Fn(&[u8]) -> io::Result<bool> + Send + Sync;

fn record_elapsed(total: &AtomicU64, maximum: &AtomicU64, elapsed: Duration) {
    let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
    total.fetch_add(micros, Ordering::Relaxed);
    maximum.fetch_max(micros, Ordering::Relaxed);
}

/// A domain-local bounded queue. Credits cover both queued and in-flight bytes;
/// overload rejects the current packet without blocking the routing actor.
pub struct PacketOutput {
    queue: mpsc::Sender<QueuedPacket>,
    credit: Arc<Semaphore>,
    slot_credit: Arc<Semaphore>,
    epoch: watch::Sender<u64>,
    observed_epoch: watch::Receiver<u64>,
    metrics: Arc<OutputMetrics>,
    task: JoinHandle<io::Result<()>>,
    joined: bool,
    outstanding: Arc<AtomicUsize>,
    queue_depth: Arc<AtomicUsize>,
    try_send: Box<NonblockingPacketWrite>,
    max_packet_size: usize,
}

/// Direction-local ingress backpressure. The single producer waits before
/// reading another packet; owner updates and the opposite direction remain
/// independently pollable. Credits are still charged by enqueue.
#[derive(Clone)]
pub struct OutputAdmission {
    slots: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    packet_bytes: u32,
}

impl OutputAdmission {
    pub async fn ready(&self) {
        let slot = self.slots.acquire().await;
        let bytes = self.bytes.acquire_many(self.packet_bytes).await;
        drop(bytes);
        drop(slot);
    }
}

impl PacketOutput {
    pub fn admission(&self) -> OutputAdmission {
        OutputAdmission {
            slots: self.slot_credit.clone(),
            bytes: self.credit.clone(),
            packet_bytes: self.max_packet_size as u32,
        }
    }

    pub fn new<P: PacketPort>(port: Arc<P>) -> Self {
        let max_packet_size = port.max_packet_size().min(65_535);
        let try_port = port.clone();
        let (queue, mut receiver) = mpsc::channel::<QueuedPacket>(OUTPUT_PACKET_LIMIT);
        let (epoch, mut epoch_rx) = watch::channel(1_u64);
        let (observed_tx, observed_epoch) = watch::channel(1_u64);
        let credit = Arc::new(Semaphore::new(OUTPUT_BYTE_LIMIT));
        let metrics = Arc::new(OutputMetrics::default());
        let task_metrics = metrics.clone();
        let queue_depth = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(crate::executor_diagnostics::Observed::new(
            crate::executor_diagnostics::configured(),
            "packet_output_writer",
            async move {
                let mut batch = Vec::with_capacity(OUTPUT_DRAIN_BATCH);
                loop {
                    let received = tokio::select! {
                        biased;
                        changed = epoch_rx.changed() => {
                            if changed.is_err() { return Ok(()); }
                            observed_tx.send_replace(*epoch_rx.borrow_and_update());
                            continue;
                        }
                        received = receiver.recv_many(&mut batch, OUTPUT_DRAIN_BATCH) => received,
                    };
                    if received == 0 {
                        return Ok(());
                    }
                    for mut packet in batch.drain(..) {
                        if let Some(error) = packet.failure.take() {
                            return Err(error);
                        }
                        if packet.epoch != *epoch_rx.borrow() {
                            task_metrics.stale_drops.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let write_started = tokio::time::Instant::now();
                        task_metrics
                            .queued_write_attempts
                            .fetch_add(1, Ordering::Relaxed);
                        record_elapsed(
                            &task_metrics.queue_wait_micros,
                            &task_metrics.queue_wait_max_micros,
                            write_started
                                .saturating_duration_since(packet.deadline - OUTPUT_WRITE_TIMEOUT),
                        );
                        // timeout_at polls its inner future first. Reject expired
                        // packets before a ready fd can write them, including when
                        // readiness and the deadline become ready together.
                        let result = if write_started >= packet.deadline {
                            Err(())
                        } else {
                            match port.try_send_packet(&packet.packet) {
                                Ok(true) => Ok(Ok(())),
                                Err(error) => Ok(Err(error)),
                                Ok(false) => tokio::select! {
                                    biased;
                                    changed = epoch_rx.changed() => {
                                        if changed.is_err() { return Ok(()); }
                                        observed_tx.send_replace(*epoch_rx.borrow_and_update());
                                        task_metrics.stale_drops.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    }
                                    _ = tokio::time::sleep_until(packet.deadline) => Err(()),
                                    result = port.send_packet(&packet.packet) => Ok(result),
                                },
                            }
                        };
                        record_elapsed(
                            &task_metrics.send_elapsed_micros,
                            &task_metrics.send_elapsed_max_micros,
                            write_started.elapsed(),
                        );
                        match result {
                            Ok(Ok(())) => {
                                task_metrics.sent_packets.fetch_add(1, Ordering::Relaxed);
                                task_metrics
                                    .sent_bytes
                                    .fetch_add(packet.packet.len() as u64, Ordering::Relaxed);
                            }
                            Ok(Err(error)) if is_packet_scoped_write_error(&error) => {
                                let count = task_metrics
                                    .backpressure_drops
                                    .fetch_add(1, Ordering::Relaxed)
                                    + 1;
                                if count.is_power_of_two() {
                                    tracing::warn!(code = "tun_write_backpressure", module = "sdwan_packet_output",
                                    os_code = error.raw_os_error(), detail = %error,
                                    action = "drop_packet_keep_port", dropped_packets = count);
                                }
                            }
                            Ok(Err(error)) => return Err(error),
                            Err(_) => {
                                let count =
                                    task_metrics.deadline_drops.fetch_add(1, Ordering::Relaxed) + 1;
                                if count.is_power_of_two() {
                                    tracing::warn!(
                                        code = "tun_write_deadline",
                                        module = "sdwan_packet_output",
                                        port = std::any::type_name::<P>(),
                                        timeout_stage = if write_started >= packet.deadline {
                                            "expired_before_write"
                                        } else {
                                            "pending_send"
                                        },
                                        queue_wait_us = write_started
                                            .saturating_duration_since(
                                                packet.deadline - OUTPUT_WRITE_TIMEOUT
                                            )
                                            .as_micros()
                                            as u64,
                                        send_elapsed_us =
                                            write_started.elapsed().as_micros() as u64,
                                        deadline_overrun_us = tokio::time::Instant::now()
                                            .saturating_duration_since(packet.deadline)
                                            .as_micros()
                                            as u64,
                                        packet_bytes = packet.packet.len(),
                                        timeout_ms = OUTPUT_WRITE_TIMEOUT.as_millis() as u64,
                                        action = "drop_packet_keep_port",
                                        dropped_packets = count
                                    );
                                }
                            }
                        }
                    }
                    tokio::task::yield_now().await;
                }
            },
        ));
        Self {
            queue,
            credit,
            slot_credit: Arc::new(Semaphore::new(OUTPUT_PACKET_LIMIT)),
            epoch,
            observed_epoch,
            metrics,
            task,
            joined: false,
            outstanding: Arc::new(AtomicUsize::new(0)),
            queue_depth,
            try_send: Box::new(move |packet| try_port.try_send_packet(packet)),
            max_packet_size,
        }
    }

    pub fn enqueue(&self, packet: Vec<u8>) -> Result<(), &'static str> {
        if packet.is_empty() || packet.len() > self.max_packet_size {
            return Err("tun_output_invalid_packet");
        }
        // The routing actor is the only enqueuer. Never bypass queued/in-flight
        // packets; the nonblocking fast path performs no await or task handoff.
        let mut failure = None;
        if self.outstanding.load(Ordering::Acquire) == 0 {
            match (self.try_send)(&packet) {
                Ok(true) => {
                    self.metrics.sent_packets.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .sent_bytes
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    return Ok(());
                }
                Ok(false) => {
                    self.metrics
                        .write_blocked_events
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(error) if is_packet_scoped_write_error(&error) => {
                    self.metrics
                        .backpressure_drops
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                // Report without retrying a possibly short packet write.
                Err(error) => failure = Some(error),
            }
        }
        let slot_credit = self.slot_credit.clone().try_acquire_owned().map_err(|_| {
            self.metrics
                .queue_slot_exhausted
                .fetch_add(1, Ordering::Relaxed);
            "tun_output_queue_full"
        })?;
        let credit = self
            .credit
            .clone()
            .try_acquire_many_owned(u32::try_from(packet.capacity().max(packet.len())).map_err(
                |_| {
                    self.metrics
                        .queue_byte_exhausted
                        .fetch_add(1, Ordering::Relaxed);
                    "tun_output_queue_full"
                },
            )?)
            .map_err(|_| {
                self.metrics
                    .queue_byte_exhausted
                    .fetch_add(1, Ordering::Relaxed);
                "tun_output_queue_full"
            })?;
        self.outstanding.fetch_add(1, Ordering::Release);
        let depth = self.queue_depth.fetch_add(1, Ordering::AcqRel) + 1;
        let mut high = self.metrics.queue_high_watermark.load(Ordering::Relaxed);
        while depth as u64 > high {
            match self.metrics.queue_high_watermark.compare_exchange_weak(
                high,
                depth as u64,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => high = observed,
            }
        }
        self.queue
            .try_send(QueuedPacket {
                epoch: *self.epoch.borrow(),
                packet,
                _credit: credit,
                _slot_credit: slot_credit,
                deadline: tokio::time::Instant::now() + OUTPUT_WRITE_TIMEOUT,
                outstanding: self.outstanding.clone(),
                queue_depth: self.queue_depth.clone(),
                failure,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    self.metrics
                        .queue_channel_full
                        .fetch_add(1, Ordering::Relaxed);
                    "tun_output_queue_full"
                }
                mpsc::error::TrySendError::Closed(_) => "tun_output_closed",
            })
    }

    /// Fence pending output before acknowledging a successful policy change.
    pub async fn invalidate(&mut self) -> io::Result<()> {
        self.epoch
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        let epoch = *self.epoch.borrow();
        while *self.observed_epoch.borrow_and_update() != epoch {
            self.observed_epoch.changed().await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "packet output stopped before fencing acknowledgement",
                )
            })?;
        }
        Ok(())
    }

    pub fn take_delta(&self) -> OutputDelta {
        OutputDelta {
            sent_packets: self.metrics.sent_packets.swap(0, Ordering::Relaxed),
            sent_bytes: self.metrics.sent_bytes.swap(0, Ordering::Relaxed),
            backpressure_drops: self.metrics.backpressure_drops.swap(0, Ordering::Relaxed),
            deadline_drops: self.metrics.deadline_drops.swap(0, Ordering::Relaxed),
            stale_drops: self.metrics.stale_drops.swap(0, Ordering::Relaxed),
            queue_slot_exhausted: self.metrics.queue_slot_exhausted.swap(0, Ordering::Relaxed),
            queue_byte_exhausted: self.metrics.queue_byte_exhausted.swap(0, Ordering::Relaxed),
            queue_channel_full: self.metrics.queue_channel_full.swap(0, Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Acquire) as u64,
            queue_high_watermark: self.metrics.queue_high_watermark.swap(0, Ordering::Relaxed),
            write_blocked_events: self.metrics.write_blocked_events.swap(0, Ordering::Relaxed),
            queued_write_attempts: self
                .metrics
                .queued_write_attempts
                .swap(0, Ordering::Relaxed),
            queue_wait_micros: self.metrics.queue_wait_micros.swap(0, Ordering::Relaxed),
            queue_wait_max_micros: self
                .metrics
                .queue_wait_max_micros
                .swap(0, Ordering::Relaxed),
            send_elapsed_micros: self.metrics.send_elapsed_micros.swap(0, Ordering::Relaxed),
            send_elapsed_max_micros: self
                .metrics
                .send_elapsed_max_micros
                .swap(0, Ordering::Relaxed),
        }
    }

    pub async fn failed(&mut self) -> io::Error {
        let result = (&mut self.task).await;
        self.joined = true;
        match result {
            Ok(Err(error)) => error,
            Ok(Ok(())) => io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet output task exited unexpectedly",
            ),
            Err(error) => io::Error::other(format!("packet output task failed: {error}")),
        }
    }

    pub fn cancel(&self) {
        if !self.joined {
            self.task.abort();
        }
    }

    pub async fn stop(&mut self) {
        if !self.joined {
            self.cancel();
            let _ = (&mut self.task).await;
            self.joined = true;
        }
    }
}

impl Drop for PacketOutput {
    fn drop(&mut self) {
        if !self.joined {
            self.task.abort();
        }
    }
}

fn is_packet_scoped_write_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
    ) || matches!(error.raw_os_error(), Some(code) if code == libc::ENOBUFS
            || code == libc::ENOMEM || code == libc::EMSGSIZE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::Notify;

    struct TestPort {
        blocked: AtomicU64,
        attempts: AtomicU64,
        entered: Notify,
        unblock: Notify,
        packets: Mutex<Vec<Vec<u8>>>,
        fail_once: Option<i32>,
    }

    impl TestPort {
        fn new(blocked: bool, fail_once: Option<i32>) -> Arc<Self> {
            Arc::new(Self {
                blocked: AtomicU64::new(u64::from(blocked)),
                attempts: AtomicU64::new(0),
                entered: Notify::new(),
                unblock: Notify::new(),
                packets: Mutex::new(Vec::new()),
                fail_once,
            })
        }
    }

    impl PacketPort for TestPort {
        async fn recv_packet(&self) -> io::Result<Vec<u8>> {
            std::future::pending().await
        }
        async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
            let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
            self.entered.notify_one();
            if attempt == 0 {
                if let Some(code) = self.fail_once {
                    return Err(io::Error::from_raw_os_error(code));
                }
            }
            while self.blocked.load(Ordering::Relaxed) != 0 {
                self.unblock.notified().await;
            }
            self.packets.lock().unwrap().push(packet.to_vec());
            Ok(())
        }
    }

    async fn wait_packet(port: &TestPort, count: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while port.packets.lock().unwrap().len() < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn ingress_admission_waits_for_credit_and_resumes_without_rejection() {
        let port = TestPort::new(true, None);
        let mut output = PacketOutput::new(port.clone());
        for _ in 0..OUTPUT_PACKET_LIMIT {
            output.enqueue(vec![1; 100]).unwrap();
        }
        let admission = output.admission();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), admission.ready())
                .await
                .is_err()
        );
        port.blocked.store(0, Ordering::Relaxed);
        port.unblock.notify_one();
        tokio::time::timeout(Duration::from_secs(1), admission.ready())
            .await
            .unwrap();
        wait_packet(&port, OUTPUT_PACKET_LIMIT).await;
        let delta = output.take_delta();
        assert_eq!(delta.queue_slot_exhausted, 0);
        assert_eq!(delta.deadline_drops, 0);
        output.stop().await;
    }

    #[tokio::test]
    async fn cancelled_byte_wait_releases_slot_and_preserves_opposite_output() {
        let port = TestPort::new(true, None);
        let mut output = PacketOutput::new(port.clone());
        // Byte budget is exhausted before the 256-slot budget. Cancellation
        // must release the temporary slot held while waiting for bytes.
        for _ in 0..8 {
            output.enqueue(vec![1; 65_535]).unwrap();
        }
        let initial_slots = output.slot_credit.available_permits();
        for _ in 0..8 {
            let admission = output.admission();
            let mut ready = Box::pin(admission.ready());
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(ready.as_mut().poll(&mut context).is_pending());
            assert_eq!(output.slot_credit.available_permits(), initial_slots - 1);
            drop(ready);
            assert_eq!(output.slot_credit.available_permits(), initial_slots);
        }
        let reverse = TestPort::new(false, None);
        let mut reverse_output = PacketOutput::new(reverse.clone());
        reverse_output.admission().ready().await;
        reverse_output.enqueue(vec![2; 64]).unwrap();
        wait_packet(&reverse, 1).await;
        assert_eq!(*reverse.packets.lock().unwrap(), vec![vec![2; 64]]);
        output.stop().await;
        reverse_output.stop().await;
        assert_eq!(output.outstanding.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn enobufs_drops_only_current_packet_then_writes_next() {
        let port = TestPort::new(false, Some(libc::ENOBUFS));
        let mut output = PacketOutput::new(port.clone());
        output.enqueue(vec![1; 100]).unwrap();
        output.enqueue(vec![2; 200]).unwrap();
        wait_packet(&port, 1).await;
        assert_eq!(*port.packets.lock().unwrap(), vec![vec![2; 200]]);
        let delta = output.take_delta();
        assert_eq!(delta.backpressure_drops, 1);
        assert_eq!((delta.sent_packets, delta.sent_bytes), (1, 200));
        output.stop().await;
    }

    #[tokio::test]
    async fn blocked_output_is_byte_bounded_and_policy_fences_inflight_and_queued_packets() {
        let port = TestPort::new(true, None);
        let mut output = PacketOutput::new(port.clone());
        output.enqueue(vec![1; 65_535]).unwrap();
        port.entered.notified().await;
        for _ in 0..7 {
            output.enqueue(vec![2; 65_535]).unwrap();
        }
        assert_eq!(
            output.enqueue(vec![3; 65_535]),
            Err("tun_output_queue_full")
        );
        assert!(output.credit.available_permits() < 65_535);
        let diagnostic = output.take_delta();
        assert_eq!(diagnostic.queue_depth, 8);
        assert_eq!(diagnostic.queue_high_watermark, 8);
        assert!(diagnostic.write_blocked_events >= 1);
        assert!(diagnostic.queue_byte_exhausted >= 1);
        output.invalidate().await.unwrap();
        port.blocked.store(0, Ordering::Relaxed);
        port.unblock.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while output.credit.available_permits() != OUTPUT_BYTE_LIMIT {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(port.packets.lock().unwrap().is_empty());
        output.enqueue(vec![4; 100]).unwrap();
        wait_packet(&port, 1).await;
        assert_eq!(output.take_delta().stale_drops, 8);
        output.stop().await;
    }

    #[tokio::test]
    async fn short_packets_with_large_allocations_cannot_bypass_byte_credit() {
        let port = TestPort::new(true, None);
        let mut output = PacketOutput::new(port.clone());
        let mut packet = Vec::with_capacity(OUTPUT_BYTE_LIMIT);
        packet.push(1);
        output.enqueue(packet).unwrap();
        port.entered.notified().await;
        assert_eq!(output.credit.available_permits(), 0);
        assert_eq!(output.enqueue(vec![2]), Err("tun_output_queue_full"));
        assert_eq!(output.take_delta().queue_byte_exhausted, 1);
        output.invalidate().await.unwrap();
        output.stop().await;
        assert_eq!(output.credit.available_permits(), OUTPUT_BYTE_LIMIT);
        assert!(port.packets.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn packet_limit_includes_inflight_and_all_credits_return_after_cancellation() {
        let port = TestPort::new(true, None);
        let mut output = PacketOutput::new(port.clone());
        output.enqueue(vec![1]).unwrap();
        port.entered.notified().await;
        for _ in 1..OUTPUT_PACKET_LIMIT {
            output.enqueue(vec![2]).unwrap();
        }
        assert_eq!(
            output.outstanding.load(Ordering::Acquire),
            OUTPUT_PACKET_LIMIT
        );
        assert_eq!(output.slot_credit.available_permits(), 0);
        assert_eq!(output.queue.capacity(), 1);
        assert_eq!(output.enqueue(vec![3]), Err("tun_output_queue_full"));
        assert_eq!(
            output.outstanding.load(Ordering::Acquire),
            OUTPUT_PACKET_LIMIT
        );
        output.stop().await;
        assert_eq!(output.outstanding.load(Ordering::Acquire), 0);
        assert_eq!(output.slot_credit.available_permits(), OUTPUT_PACKET_LIMIT);
        assert_eq!(output.credit.available_permits(), OUTPUT_BYTE_LIMIT);
    }

    #[tokio::test(start_paused = true)]
    async fn write_deadline_drops_stalled_packet_and_keeps_writer() {
        let port = TestPort::new(true, None);
        let mut output = PacketOutput::new(port.clone());
        output.enqueue(vec![1; 100]).unwrap();
        port.entered.notified().await;
        tokio::time::advance(OUTPUT_WRITE_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(output.take_delta().deadline_drops, 1);
        port.blocked.store(0, Ordering::Relaxed);
        output.enqueue(vec![2; 100]).unwrap();
        wait_packet(&port, 1).await;
        output.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn queued_output_distinguishes_residence_from_send_elapsed() {
        let port = TestPort::new(true, None);
        let mut output = PacketOutput::new(port.clone());
        output.enqueue(vec![1; 100]).unwrap();
        port.entered.notified().await;
        output.enqueue(vec![2; 100]).unwrap();
        tokio::time::advance(Duration::from_millis(20)).await;
        port.blocked.store(0, Ordering::Relaxed);
        port.unblock.notify_one();
        wait_packet(&port, 2).await;
        let delta = output.take_delta();
        assert_eq!(delta.queued_write_attempts, 2);
        assert!(delta.queue_wait_max_micros >= 20_000);
        assert!(delta.send_elapsed_max_micros >= 20_000);
        assert_eq!(delta.sent_packets, 2);
        assert_eq!(delta.deadline_drops, 0);
        output.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn expired_queued_packets_never_poll_a_ready_port_and_release_all_credit() {
        let port = TestPort::new(false, None);
        let mut output = PacketOutput::new(port.clone());
        for value in 1..=4 {
            output.enqueue(vec![value; 100]).unwrap();
        }
        // Advance before the writer's first poll: a ready inner future must
        // not win over an already elapsed packet deadline.
        tokio::time::advance(OUTPUT_WRITE_TIMEOUT + Duration::from_millis(1)).await;
        while output.queue_depth.load(Ordering::Acquire) != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(port.attempts.load(Ordering::Relaxed), 0);
        assert!(port.packets.lock().unwrap().is_empty());
        assert_eq!(output.take_delta().deadline_drops, 4);
        assert_eq!(output.slot_credit.available_permits(), OUTPUT_PACKET_LIMIT);
        assert_eq!(output.credit.available_permits(), OUTPUT_BYTE_LIMIT);
        output.enqueue(vec![5; 100]).unwrap();
        wait_packet(&port, 1).await;
        output.stop().await;
    }

    struct ReadyDrainPort {
        ready: AtomicUsize,
        attempts: AtomicUsize,
        packets: Mutex<Vec<Vec<u8>>>,
    }

    impl PacketPort for ReadyDrainPort {
        fn try_send_packet(&self, packet: &[u8]) -> io::Result<bool> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            if self.ready.load(Ordering::Acquire) == 0 {
                return Ok(false);
            }
            self.packets.lock().unwrap().push(packet.to_vec());
            Ok(true)
        }
        async fn recv_packet(&self) -> io::Result<Vec<u8>> {
            std::future::pending().await
        }
        async fn send_packet(&self, _: &[u8]) -> io::Result<()> {
            panic!("queued ready writes must not poll the readiness future");
        }
    }

    fn ready_drain_port() -> Arc<ReadyDrainPort> {
        Arc::new(ReadyDrainPort {
            ready: AtomicUsize::new(0),
            attempts: AtomicUsize::new(0),
            packets: Mutex::new(Vec::new()),
        })
    }

    #[tokio::test]
    async fn queued_nonblocking_drain_preserves_order_across_batches_and_returns_credit() {
        let port = ready_drain_port();
        let mut output = PacketOutput::new(port.clone());
        let expected: Vec<_> = (0..OUTPUT_PACKET_LIMIT)
            .map(|value| vec![value as u8; 100])
            .collect();
        for packet in &expected {
            output.enqueue(packet.clone()).unwrap();
        }
        port.ready.store(1, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), async {
            while output.queue_depth.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(*port.packets.lock().unwrap(), expected);
        assert_eq!(output.take_delta().sent_packets, OUTPUT_PACKET_LIMIT as u64);
        assert_eq!(output.slot_credit.available_permits(), OUTPUT_PACKET_LIMIT);
        assert_eq!(output.credit.available_permits(), OUTPUT_BYTE_LIMIT);
        output.stop().await;
    }

    #[tokio::test]
    async fn fencing_a_ready_queued_drain_discards_old_epoch_before_any_fd_write() {
        let port = ready_drain_port();
        let mut output = PacketOutput::new(port.clone());
        for _ in 0..OUTPUT_PACKET_LIMIT {
            output.enqueue(vec![1; 100]).unwrap();
        }
        port.ready.store(1, Ordering::Release);
        output.invalidate().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while output.queue_depth.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(port.packets.lock().unwrap().is_empty());
        assert_eq!(port.attempts.load(Ordering::Relaxed), 1);
        assert_eq!(output.take_delta().stale_drops, OUTPUT_PACKET_LIMIT as u64);
        assert_eq!(output.slot_credit.available_permits(), OUTPUT_PACKET_LIMIT);
        assert_eq!(output.credit.available_permits(), OUTPUT_BYTE_LIMIT);
        output.enqueue(vec![2; 100]).unwrap();
        assert_eq!(*port.packets.lock().unwrap(), vec![vec![2; 100]]);
        output.stop().await;
    }

    #[tokio::test]
    async fn fatal_fd_error_is_reported_and_stop_cancels_blocked_writer() {
        let port = TestPort::new(false, Some(libc::EBADF));
        let mut output = PacketOutput::new(port);
        output.enqueue(vec![1; 100]).unwrap();
        assert_eq!(output.failed().await.raw_os_error(), Some(libc::EBADF));
        output.stop().await;
        let port = TestPort::new(true, None);
        let mut output = PacketOutput::new(port.clone());
        output.enqueue(vec![1; 100]).unwrap();
        port.entered.notified().await;
        tokio::time::timeout(Duration::from_millis(50), output.stop())
            .await
            .unwrap();
        assert!(port.packets.lock().unwrap().is_empty());
        assert_eq!(output.credit.available_permits(), OUTPUT_BYTE_LIMIT);
    }

    struct NonblockingTestPort {
        attempts: AtomicU64,
        error: Option<i32>,
    }

    impl PacketPort for NonblockingTestPort {
        fn max_packet_size(&self) -> usize {
            1400
        }
        fn try_send_packet(&self, _: &[u8]) -> io::Result<bool> {
            let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
            if attempt == 0 {
                if let Some(code) = self.error {
                    return Err(io::Error::from_raw_os_error(code));
                }
            }
            Ok(true)
        }
        async fn recv_packet(&self) -> io::Result<Vec<u8>> {
            std::future::pending().await
        }
        async fn send_packet(&self, _: &[u8]) -> io::Result<()> {
            panic!("a completed or failed nonblocking write must not be retried");
        }
    }

    #[tokio::test]
    async fn nonblocking_fast_path_preserves_packet_errors_and_never_retries_fatal_writes() {
        let port = Arc::new(NonblockingTestPort {
            attempts: AtomicU64::new(0),
            error: Some(libc::ENOBUFS),
        });
        let mut output = PacketOutput::new(port.clone());
        output.enqueue(vec![1; 100]).unwrap();
        output.enqueue(vec![2; 200]).unwrap();
        let delta = output.take_delta();
        assert_eq!(
            (
                delta.backpressure_drops,
                delta.sent_packets,
                delta.sent_bytes
            ),
            (1, 1, 200)
        );
        assert_eq!(port.attempts.load(Ordering::Relaxed), 2);
        output.stop().await;
        let port = Arc::new(NonblockingTestPort {
            attempts: AtomicU64::new(0),
            error: Some(libc::EBADF),
        });
        let mut output = PacketOutput::new(port.clone());
        output.enqueue(vec![1; 100]).unwrap();
        assert_eq!(output.failed().await.raw_os_error(), Some(libc::EBADF));
        assert_eq!(port.attempts.load(Ordering::Relaxed), 1);
        output.stop().await;
    }

    #[tokio::test]
    async fn oversized_packet_is_rejected_without_invoking_or_failing_port() {
        let port = Arc::new(NonblockingTestPort {
            attempts: AtomicU64::new(0),
            error: None,
        });
        let mut output = PacketOutput::new(port.clone());
        assert_eq!(
            output.enqueue(vec![1; 1401]),
            Err("tun_output_invalid_packet")
        );
        output.enqueue(vec![2; 1400]).unwrap();
        assert_eq!(port.attempts.load(Ordering::Relaxed), 1);
        assert_eq!(output.take_delta().sent_packets, 1);
        output.stop().await;
    }
}
