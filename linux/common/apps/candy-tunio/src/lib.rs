use candy_packet_port::packet_port::PacketPort;
use candy_packet_port::packet_port_ipc::{
    run_packet_port_bridge, PacketBridgeCounters, UnixPacketPort,
};
use std::future::Future;
use std::io;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::Instant;

pub mod attach_control;
pub mod authority_control;
pub mod control;

pub struct ManagedInfrastructure {
    pub updates:
        tokio::sync::mpsc::Sender<candy_packet_port::packet_port_manager::PacketPortOwnerUpdate>,
    pub task: tokio::task::JoinHandle<io::Result<PacketBridgeCounters>>,
}

/// Opt-in rebind loop. The initial attachment must be active before publishing
/// readiness; later owner updates reuse the same physical packet descriptor.
pub async fn start_managed_infrastructure<P: PacketPort>(
    tun: P,
    worker: UnixPacketPort,
    shutdown: watch::Receiver<bool>,
    auth_deadline: Instant,
) -> io::Result<ManagedInfrastructure> {
    use candy_packet_port::packet_port_manager::{
        run_managed_packet_port_bridge, PacketPortOwnerChange, PacketPortOwnerUpdate,
    };
    let binding = worker.binding();
    let authorization = authority_control::bootstrap_check(auth_deadline)?;
    let (updates, receiver) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(run_managed_packet_port_bridge(
        tun, binding, receiver, shutdown,
    ));
    let (acknowledgement, applied) = tokio::sync::oneshot::channel();
    if updates
        .send(PacketPortOwnerUpdate {
            change: match authorization {
                Some(authorization) => PacketPortOwnerChange::AttachAuthorized {
                    port: worker,
                    auth_deadline,
                    authorization,
                },
                None => PacketPortOwnerChange::Attach {
                    port: worker,
                    auth_deadline,
                },
            },
            acknowledgement,
            receipt: None,
        })
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "initial PacketPort bridge exited",
        ));
    }
    let applied = tokio::time::timeout(std::time::Duration::from_secs(2), applied).await;
    match applied {
        Ok(Ok(Ok(()))) => Ok(ManagedInfrastructure { updates, task }),
        result => {
            task.abort();
            let _ = task.await;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("initial PacketPort attachment failed: {result:?}"),
            ))
        }
    }
}

struct SharedPort<P> {
    port: Arc<P>,
    auth_deadline: Instant,
    authorization: Option<candy_packet_port::packet_port_manager::AuthorizationCheck>,
}

impl<P: PacketPort> PacketPort for SharedPort<P> {
    fn max_packet_size(&self) -> usize {
        self.port.max_packet_size()
    }

    async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        self.port.recv_packet().await
    }

    async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        if Instant::now() >= self.auth_deadline {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owner authorization expired",
            ));
        }
        let send = self.port.send_packet(packet);
        tokio::pin!(send);
        let checked_send = std::future::poll_fn(|cx| {
            if let Some(authorization) = &self.authorization {
                if let Err(error) = authorization() {
                    return std::task::Poll::Ready(Err(error));
                }
            }
            send.as_mut().poll(cx)
        });
        tokio::time::timeout_at(self.auth_deadline, checked_send)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "owner authorization expired during output",
                )
            })?
    }
}

#[derive(Debug, Default)]
pub struct InfrastructureOutcome {
    pub bridge: PacketBridgeCounters,
    pub idle_dropped_packets: u64,
    pub degraded_reason: Option<String>,
}

/// The I/O owner survives the business worker and authorization expiry.
/// Rebinding a new owner is deliberately not permitted by this prototype.
pub async fn run_infrastructure<P: PacketPort>(
    tun: P,
    worker: UnixPacketPort,
    mut shutdown: watch::Receiver<bool>,
    auth_deadline: Instant,
) -> io::Result<InfrastructureOutcome> {
    let tun = Arc::new(tun);
    let authorization = authority_control::bootstrap_check(auth_deadline)?;
    let (bridge_stop, bridge_shutdown) = watch::channel(false);
    let bridge = run_packet_port_bridge(
        SharedPort {
            port: tun.clone(),
            auth_deadline,
            authorization,
        },
        worker,
        bridge_shutdown,
    );
    tokio::pin!(bridge);
    let mut outcome = InfrastructureOutcome::default();
    tokio::select! {
        result = &mut bridge => match result {
            Ok(counters) => outcome.bridge = counters,
            Err(error) => outcome.degraded_reason = Some(format!("worker_or_packet_port_failed: {error}")),
        },
        _ = tokio::time::sleep_until(auth_deadline) => {
            let _ = bridge_stop.send(true);
            if let Ok(counters) = (&mut bridge).await { outcome.bridge = counters; }
            outcome.degraded_reason = Some("owner_authorization_expired".into());
        },
        _ = async {
            if !*shutdown.borrow() { let _ = shutdown.changed().await; }
        } => {
            let _ = bridge_stop.send(true);
            if let Ok(counters) = (&mut bridge).await { outcome.bridge = counters; }
            return Ok(outcome);
        },
    }
    eprintln!("level=warn code=tunio_forwarding_unavailable module=tunio detail={:?} action=keep_infrastructure_drain_packets", outcome.degraded_reason);
    loop {
        if *shutdown.borrow() {
            return Ok(outcome);
        }
        tokio::select! {
            _ = shutdown.changed() => return Ok(outcome),
            packet = tun.recv_packet() => {
                packet?;
                outcome.idle_dropped_packets = outcome.idle_dropped_packets.saturating_add(1);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candy_packet_port::packet_port_ipc::{PacketPortBinding, PacketPortRole};
    use std::time::Duration;
    use tokio::net::UnixDatagram;

    struct FakeTun(UnixDatagram);
    impl PacketPort for FakeTun {
        async fn recv_packet(&self) -> io::Result<Vec<u8>> {
            let mut packet = vec![0; 1400];
            let size = self.0.recv(&mut packet).await?;
            packet.truncate(size);
            Ok(packet)
        }
        async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
            self.0.send(packet).await.map(|_| ())
        }
    }

    fn ports() -> (FakeTun, UnixDatagram, UnixPacketPort, UnixDatagram) {
        let (tun, kernel) = UnixDatagram::pair().unwrap();
        let (io, worker) = UnixDatagram::pair().unwrap();
        let binding = PacketPortBinding {
            infrastructure_id: [1; 16],
            routing_domain_id: [2; 16],
            infrastructure_generation: 1,
            io_epoch: 1,
            owner_epoch: 1,
            policy_generation: 1,
        };
        (
            FakeTun(tun),
            kernel,
            UnixPacketPort::new(io, binding, PacketPortRole::Infrastructure).unwrap(),
            worker,
        )
    }

    #[tokio::test]
    async fn expired_owner_stops_forwarding_but_keeps_tun_io_alive() {
        let (tun, kernel, io, worker) = ports();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(run_infrastructure(tun, io, shutdown, Instant::now()));
        tokio::time::sleep(Duration::from_millis(20)).await;
        kernel.send(&[0x45; 64]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), worker.recv(&mut [0; 256]))
                .await
                .is_err()
        );
        assert!(!task.is_finished());
        stop.send(true).unwrap();
        let result = task.await.unwrap().unwrap();
        assert_eq!(
            result.degraded_reason.as_deref(),
            Some("owner_authorization_expired")
        );
        assert_eq!(result.idle_dropped_packets, 1);
    }

    #[tokio::test]
    async fn exited_worker_does_not_stop_the_infrastructure_process_loop() {
        let (tun, kernel, io, worker) = ports();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(run_infrastructure(
            tun,
            io,
            shutdown,
            Instant::now() + Duration::from_secs(30),
        ));
        drop(worker);
        kernel.send(&[0x45; 64]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!task.is_finished());
        kernel.send(&[0x45; 64]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        stop.send(true).unwrap();
        let result = task.await.unwrap().unwrap();
        assert!(result.bridge.worker_failures >= 1);
        assert!(result.bridge.no_worker_drops >= 1);
    }

    struct BlockedTun(UnixDatagram);
    impl PacketPort for BlockedTun {
        async fn recv_packet(&self) -> io::Result<Vec<u8>> {
            std::future::pending().await
        }
        async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
            tokio::time::sleep(Duration::from_secs(60)).await;
            self.0.send(packet).await.map(|_| ())
        }
    }

    #[tokio::test]
    async fn authorization_expiry_cancels_inflight_output_before_it_can_reach_tun() {
        let (tun, kernel) = UnixDatagram::pair().unwrap();
        let port = SharedPort {
            port: Arc::new(BlockedTun(tun)),
            auth_deadline: Instant::now() + Duration::from_millis(10),
            authorization: None,
        };
        let error = port.send_packet(&[0x45; 64]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), kernel.recv(&mut [0; 64]))
                .await
                .is_err()
        );
    }
}
