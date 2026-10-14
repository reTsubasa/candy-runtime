//! Connected Unix packet-port prototype. The Agent must authenticate the
//! process and transfer the connected socket; no public IPC listener is opened.

use crate::packet_port::{PacketOutput, PacketPort};
use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UnixDatagram;
use tokio::sync::watch;

const HEADER_BYTES: usize = 76;
// Matches netd v2's supported MTU and portable Unix datagram frame sizes.
const MAX_PACKET_BYTES: usize = 1400;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketPortBinding {
    pub infrastructure_id: [u8; 16],
    pub routing_domain_id: [u8; 16],
    pub infrastructure_generation: u64,
    pub io_epoch: u64,
    pub owner_epoch: u64,
    pub policy_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketPortRole {
    Infrastructure,
    Worker,
}

impl PacketPortRole {
    fn outgoing_direction(self) -> u8 {
        match self {
            Self::Infrastructure => 1,
            Self::Worker => 2,
        }
    }
}

/// One authenticated owner and routing domain per connected socket. An owner
/// change requires a new binding/socket; old sockets cannot mutate the binding.
pub struct UnixPacketPort {
    socket: UnixDatagram,
    binding: PacketPortBinding,
    role: PacketPortRole,
    rejected_packets: AtomicU64,
    #[cfg(test)]
    receive_buffer_allocations: AtomicU64,
    headers: Box<PacketPortHeaders>,
}

struct PacketPortHeaders {
    outgoing: [u8; HEADER_BYTES],
    incoming: [u8; HEADER_BYTES - 4],
}

impl UnixPacketPort {
    pub fn binding(&self) -> PacketPortBinding {
        self.binding
    }

    pub fn role(&self) -> PacketPortRole {
        self.role
    }

    pub fn new(
        socket: UnixDatagram,
        binding: PacketPortBinding,
        role: PacketPortRole,
    ) -> io::Result<Self> {
        socket.peer_addr()?;
        if binding.infrastructure_id == [0; 16]
            || binding.routing_domain_id == [0; 16]
            || binding.infrastructure_generation == 0
            || binding.io_epoch == 0
            || binding.owner_epoch == 0
            || binding.policy_generation == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet port binding requires nonzero generations",
            ));
        }
        let mut outgoing_header = [0_u8; HEADER_BYTES];
        outgoing_header[..4].copy_from_slice(b"CPIO");
        outgoing_header[4] = 1;
        outgoing_header[5] = role.outgoing_direction();
        outgoing_header[8..24].copy_from_slice(&binding.infrastructure_id);
        outgoing_header[24..40].copy_from_slice(&binding.routing_domain_id);
        outgoing_header[40..48].copy_from_slice(&binding.infrastructure_generation.to_be_bytes());
        outgoing_header[48..56].copy_from_slice(&binding.io_epoch.to_be_bytes());
        outgoing_header[56..64].copy_from_slice(&binding.owner_epoch.to_be_bytes());
        outgoing_header[64..72].copy_from_slice(&binding.policy_generation.to_be_bytes());
        let mut incoming_prefix = [0_u8; HEADER_BYTES - 4];
        incoming_prefix.copy_from_slice(&outgoing_header[..HEADER_BYTES - 4]);
        incoming_prefix[5] = 3 - role.outgoing_direction();
        Ok(Self {
            socket,
            binding,
            role,
            rejected_packets: AtomicU64::new(0),
            #[cfg(test)]
            receive_buffer_allocations: AtomicU64::new(0),
            headers: Box::new(PacketPortHeaders {
                outgoing: outgoing_header,
                incoming: incoming_prefix,
            }),
        })
    }

    pub fn rejected_packets(&self) -> u64 {
        self.rejected_packets.load(Ordering::Relaxed)
    }

    fn encode_header(&self, packet: &[u8]) -> io::Result<[u8; HEADER_BYTES]> {
        if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid IPC packet size",
            ));
        }
        let mut frame = self.headers.outgoing;
        frame[72..76].copy_from_slice(&(packet.len() as u32).to_be_bytes());
        Ok(frame)
    }

    fn send_frame(&self, packet: &[u8]) -> io::Result<()> {
        let header = self.encode_header(packet)?;
        let length = nix::sys::socket::sendmsg::<()>(
            self.socket.as_raw_fd(),
            &[IoSlice::new(&header), IoSlice::new(packet)],
            &[],
            nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            None,
        )
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        if length != HEADER_BYTES + packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC packet short write",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn encode(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        let mut frame = self.encode_header(packet)?.to_vec();
        frame.extend_from_slice(packet);
        Ok(frame)
    }

    fn matches_binding(&self, header: &[u8; HEADER_BYTES], frame_bytes: usize) -> bool {
        frame_bytes > HEADER_BYTES
            && frame_bytes <= HEADER_BYTES + MAX_PACKET_BYTES
            && header[..HEADER_BYTES - 4] == self.headers.incoming
            && header[72..76] == ((frame_bytes - HEADER_BYTES) as u32).to_be_bytes()
    }
}

impl PacketPort for UnixPacketPort {
    fn max_packet_size(&self) -> usize {
        MAX_PACKET_BYTES
    }
    fn try_send_packet(&self, packet: &[u8]) -> io::Result<bool> {
        // A nonblocking attempt must reflect the fd, even before the reactor
        // has populated its readiness cache. async_io clears stale readiness
        // when a queued writer observes actual EAGAIN.
        match self.send_frame(packet) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }
    async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        // Fair direction polling may cancel an empty receive on every packet.
        self.socket.readable().await?;
        // The extra byte detects oversized/truncated frames at the boundary.
        let mut header = [0_u8; HEADER_BYTES];
        #[cfg(test)]
        self.receive_buffer_allocations
            .fetch_add(1, Ordering::Relaxed);
        let mut packet = vec![0_u8; MAX_PACKET_BYTES + 1];
        loop {
            let received = self.socket.try_io(tokio::io::Interest::READABLE, || {
                let mut slices = [IoSliceMut::new(&mut header), IoSliceMut::new(&mut packet)];
                let message = nix::sys::socket::recvmsg::<()>(
                    self.socket.as_raw_fd(),
                    &mut slices,
                    None,
                    nix::sys::socket::MsgFlags::empty(),
                )
                .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
                Ok((message.bytes, message.flags))
            });
            let (length, flags) = match received {
                Ok(received) => received,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    self.socket.readable().await?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if !flags.intersects(
                nix::sys::socket::MsgFlags::MSG_TRUNC | nix::sys::socket::MsgFlags::MSG_CTRUNC,
            ) && self.matches_binding(&header, length)
            {
                packet.truncate(length - HEADER_BYTES);
                return Ok(packet);
            }
            let count = self.rejected_packets.fetch_add(1, Ordering::Relaxed) + 1;
            if count.is_power_of_two() {
                tracing::warn!(code = "packet_port_binding_rejected", module = "sdwan_tun_ipc",
                    infrastructure_generation = self.binding.infrastructure_generation,
                    io_epoch = self.binding.io_epoch,
                    owner_epoch = self.binding.owner_epoch, policy_generation = self.binding.policy_generation,
                    frame_bytes = length, rejected_packets = count,
                    detail = "invalid frame, direction, domain or stale infrastructure/owner/policy generation",
                    action = "drop_packet_keep_port");
            }
            // A corrupt sender must not monopolize the infrastructure executor.
            tokio::task::yield_now().await;
            self.socket.readable().await?;
        }
    }

    async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        self.socket
            .async_io(tokio::io::Interest::WRITABLE, || self.send_frame(packet))
            .await
    }
}

#[derive(Default, Debug)]
pub struct PacketBridgeCounters {
    pub to_worker_packets: u64,
    pub to_tun_packets: u64,
    pub to_worker_bytes: u64,
    pub to_tun_bytes: u64,
    pub queue_drops: u64,
    pub invalid_packet_drops: u64,
    pub backpressure_drops: u64,
    pub deadline_drops: u64,
    pub stale_drops: u64,
    pub worker_failures: u64,
    pub no_worker_drops: u64,
}

impl PacketBridgeCounters {
    pub(crate) fn record_enqueue(&mut self, result: Result<(), &'static str>) {
        if let Err(code) = result {
            if code == "tun_output_invalid_packet" {
                self.invalid_packet_drops += 1;
                if self.invalid_packet_drops.is_power_of_two() {
                    tracing::warn!(
                        code,
                        module = "sdwan_tun_io",
                        detail = "packet exceeds destination port capacity or is empty",
                        dropped_packets = self.invalid_packet_drops,
                        action = "drop_packet_keep_owner"
                    );
                }
            } else {
                self.queue_drops += 1;
            }
        }
    }
}

/// Infrastructure process loop for the single-domain prototype. Routing
/// workers receive only the IPC socket. This does not yet implement domain
/// demultiplexing, multi-reader ownership, netd acquisition or pool supervision.
pub async fn run_packet_port_bridge<P: PacketPort>(
    tun: P,
    worker: UnixPacketPort,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<PacketBridgeCounters> {
    if !matches!(worker.role, PacketPortRole::Infrastructure) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bridge requires infrastructure role",
        ));
    }
    let tun = Arc::new(tun);
    let worker = Arc::new(worker);
    let mut to_worker = PacketOutput::new(worker.clone());
    let mut to_tun = PacketOutput::new(tun.clone());
    let mut counters = PacketBridgeCounters::default();
    let mut worker_available = true;
    let result = loop {
        if *shutdown.borrow() {
            break Ok(());
        }
        let to_worker_admission = to_worker.admission();
        let to_tun_admission = to_tun.admission();
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break Ok(()); }
            }
            error = to_worker.failed(), if worker_available => {
                tracing::warn!(code = "packet_port_worker_unavailable", module = "sdwan_tun_io",
                    detail = %error, action = "retain_infrastructure_drop_domain_packets");
                worker_available = false;
                counters.worker_failures += 1;
                // Revoke output from this failed worker before servicing TUN.
                if let Err(error) = to_tun.invalidate().await { break Err(error); }
            }
            error = to_tun.failed() => { break Err(error); }
            packet = async {
                if worker_available { to_worker_admission.ready().await; }
                tun.recv_packet().await
            } => match packet {
                Ok(packet) => {
                    if !worker_available { counters.no_worker_drops += 1; }
                    else { counters.record_enqueue(to_worker.enqueue(packet)); }
                }
                Err(error) => break Err(error),
            },
            packet = async {
                to_tun_admission.ready().await;
                worker.recv_packet().await
            }, if worker_available => match packet {
                Ok(packet) => {
                    counters.record_enqueue(to_tun.enqueue(packet));
                }
                Err(error) => {
                    tracing::warn!(code = "packet_port_worker_unavailable", module = "sdwan_tun_io",
                        detail = %error, action = "retain_infrastructure_drop_domain_packets");
                    worker_available = false;
                    counters.worker_failures += 1;
                    to_worker.stop().await;
                    if let Err(error) = to_tun.invalidate().await { break Err(error); }
                }
            },
        }
    };
    to_worker.stop().await;
    to_tun.stop().await;
    let outgoing = to_worker.take_delta();
    let incoming = to_tun.take_delta();
    counters.to_worker_packets = outgoing.sent_packets;
    counters.to_tun_packets = incoming.sent_packets;
    counters.to_worker_bytes = outgoing.sent_bytes;
    counters.to_tun_bytes = incoming.sent_bytes;
    counters.backpressure_drops = outgoing.backpressure_drops + incoming.backpressure_drops;
    counters.deadline_drops = outgoing.deadline_drops + incoming.deadline_drops;
    counters.stale_drops = outgoing.stale_drops + incoming.stale_drops;
    result.map(|_| counters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::time::Duration;

    fn binding() -> PacketPortBinding {
        PacketPortBinding {
            infrastructure_id: [1; 16],
            routing_domain_id: [2; 16],
            infrastructure_generation: 1,
            io_epoch: 1,
            owner_epoch: 2,
            policy_generation: 3,
        }
    }

    #[tokio::test]
    async fn nonblocking_send_does_not_require_reactor_readiness_to_be_cached() {
        let (infrastructure, worker) = UnixDatagram::pair().unwrap();
        let infrastructure =
            UnixPacketPort::new(infrastructure, binding(), PacketPortRole::Infrastructure).unwrap();
        let worker = UnixPacketPort::new(worker, binding(), PacketPortRole::Worker).unwrap();
        assert!(infrastructure.try_send_packet(&[0x45; 64]).unwrap());
        assert_eq!(worker.recv_packet().await.unwrap(), vec![0x45; 64]);
    }

    // Linux reports a full connected datagram queue as EAGAIN; Darwin uses
    // ENOBUFS with different writable notifications, so test this contract there.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn saturated_socket_async_send_waits_and_recovers_without_spinning() {
        let (infrastructure, worker) = UnixDatagram::pair().unwrap();
        let infrastructure = Arc::new(
            UnixPacketPort::new(infrastructure, binding(), PacketPortRole::Infrastructure).unwrap(),
        );
        let worker = UnixPacketPort::new(worker, binding(), PacketPortRole::Worker).unwrap();
        let mut queued = 0;
        while infrastructure.try_send_packet(&[0x45; 1400]).unwrap() {
            queued += 1;
            assert!(queued < 10000, "socket backpressure was not exercised");
        }
        assert!(queued > 0);
        let sender = infrastructure.clone();
        let pending = tokio::spawn(async move { sender.send_packet(&[0x46; 1400]).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!pending.is_finished());
        for _ in 0..queued {
            assert_eq!(worker.recv_packet().await.unwrap(), vec![0x45; 1400]);
        }
        tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(worker.recv_packet().await.unwrap(), vec![0x46; 1400]);
    }

    #[tokio::test]
    async fn cancelling_empty_receive_before_readiness_allocates_no_payload_buffer() {
        let (infrastructure, worker) = UnixDatagram::pair().unwrap();
        let infrastructure =
            UnixPacketPort::new(infrastructure, binding(), PacketPortRole::Infrastructure).unwrap();
        let worker = UnixPacketPort::new(worker, binding(), PacketPortRole::Worker).unwrap();
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        for _ in 0..1024 {
            let mut receive = Box::pin(worker.recv_packet());
            assert!(receive.as_mut().poll(&mut context).is_pending());
            drop(receive);
        }
        assert_eq!(worker.receive_buffer_allocations.load(Ordering::Relaxed), 0);
        infrastructure.send_packet(&[0x45; 64]).await.unwrap();
        assert_eq!(worker.recv_packet().await.unwrap(), vec![0x45; 64]);
        assert_eq!(worker.receive_buffer_allocations.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn packet_frames_preserve_payload_in_both_directions() {
        let (infrastructure, worker) = UnixDatagram::pair().unwrap();
        let infrastructure =
            UnixPacketPort::new(infrastructure, binding(), PacketPortRole::Infrastructure).unwrap();
        let worker = UnixPacketPort::new(worker, binding(), PacketPortRole::Worker).unwrap();
        for size in [1, 1398, 1400] {
            let packet = vec![size as u8; size];
            infrastructure.send_packet(&packet).await.unwrap();
            assert_eq!(worker.recv_packet().await.unwrap(), packet);
            worker.send_packet(&packet).await.unwrap();
            assert_eq!(infrastructure.recv_packet().await.unwrap(), packet);
        }
    }

    #[tokio::test]
    async fn malformed_and_stale_frames_do_not_break_later_packets() {
        let (infrastructure, worker) = UnixDatagram::pair().unwrap();
        let infrastructure =
            UnixPacketPort::new(infrastructure, binding(), PacketPortRole::Infrastructure).unwrap();
        let worker = UnixPacketPort::new(worker, binding(), PacketPortRole::Worker).unwrap();
        for offset in [0, 4, 5, 6, 8, 24, 40, 48, 56, 64, 72] {
            let mut frame = infrastructure.encode(&[1; 64]).unwrap();
            frame[offset] ^= 0xff;
            infrastructure.socket.send(&frame).await.unwrap();
        }
        infrastructure.socket.send(&[0; 8]).await.unwrap();
        infrastructure.send_packet(&[2; 64]).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), worker.recv_packet())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, vec![2; 64]);
        assert_eq!(worker.rejected_packets(), 12);
        assert_eq!(worker.receive_buffer_allocations.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn vectored_receive_rejects_oversized_and_short_frames_before_valid_maximum_packet() {
        let (infrastructure, worker) = UnixDatagram::pair().unwrap();
        let infrastructure =
            UnixPacketPort::new(infrastructure, binding(), PacketPortRole::Infrastructure).unwrap();
        let worker = UnixPacketPort::new(worker, binding(), PacketPortRole::Worker).unwrap();
        let valid = infrastructure.encode(&[0x47; MAX_PACKET_BYTES]).unwrap();
        let mut oversized = valid.clone();
        oversized.extend_from_slice(&[0; 500]);
        infrastructure.socket.send(&oversized).await.unwrap();
        infrastructure
            .socket
            .send(&valid[..HEADER_BYTES - 1])
            .await
            .unwrap();
        infrastructure
            .socket
            .send(&valid[..HEADER_BYTES])
            .await
            .unwrap();
        infrastructure.socket.send(&valid).await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(1), worker.recv_packet())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet, vec![0x47; MAX_PACKET_BYTES]);
        assert_eq!(worker.rejected_packets(), 3);
    }

    #[tokio::test]
    async fn bridge_keeps_worker_off_the_packet_descriptor() {
        use crate::fd::InheritedPacketFd;
        use std::os::fd::OwnedFd;
        let (tun, host) = UnixDatagram::pair().unwrap();
        let tun = InheritedPacketFd::new(OwnedFd::from(tun.into_std().unwrap())).unwrap();
        let (infrastructure, worker) = UnixDatagram::pair().unwrap();
        let infrastructure =
            UnixPacketPort::new(infrastructure, binding(), PacketPortRole::Infrastructure).unwrap();
        let worker = UnixPacketPort::new(worker, binding(), PacketPortRole::Worker).unwrap();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(run_packet_port_bridge(tun, infrastructure, shutdown));
        host.send(&[0x45; 1500]).await.unwrap();
        host.send(&[0x45; 64]).await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(1), worker.recv_packet())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet, vec![0x45; 64]);
        worker.send_packet(&[0x46; 100]).await.unwrap();
        let mut packet = [0; 128];
        let length = tokio::time::timeout(Duration::from_secs(1), host.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&packet[..length], &[0x46; 100]);
        stop.send(true).unwrap();
        let counters = task.await.unwrap().unwrap();
        assert_eq!(
            (
                counters.to_worker_packets,
                counters.to_tun_packets,
                counters.queue_drops
            ),
            (1, 1, 0)
        );
        assert_eq!(counters.invalid_packet_drops, 1);
        assert_eq!(counters.worker_failures, 0);
    }

    #[tokio::test]
    async fn worker_disappearance_does_not_stop_infrastructure_reader() {
        use crate::fd::InheritedPacketFd;
        use std::os::fd::OwnedFd;
        let directory = tempfile::tempdir().unwrap();
        let io_path = directory.path().join("io");
        let worker_path = directory.path().join("worker");
        let (tun, host) = UnixDatagram::pair().unwrap();
        let tun = InheritedPacketFd::new(OwnedFd::from(tun.into_std().unwrap())).unwrap();
        let io = UnixDatagram::bind(&io_path).unwrap();
        let worker = UnixDatagram::bind(&worker_path).unwrap();
        io.connect(&worker_path).unwrap();
        worker.connect(&io_path).unwrap();
        let io = UnixPacketPort::new(io, binding(), PacketPortRole::Infrastructure).unwrap();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(run_packet_port_bridge(tun, io, shutdown));
        drop(worker);
        std::fs::remove_file(&worker_path).unwrap();
        host.send(&[0x45; 64]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "worker failure propagated into infrastructure lifetime"
        );
        host.send(&[0x45; 64]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        stop.send(true).unwrap();
        let counters = task.await.unwrap().unwrap();
        assert_eq!(counters.worker_failures, 1);
        assert_eq!(counters.no_worker_drops, 1);
    }
}
