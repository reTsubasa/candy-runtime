use crate::tun_fd::{TunPacketFd, TunPacketFdError};
use bytes::Bytes;
use candy_proto::control::ControlMessage;
use candy_proto::ip_tunnel::IpTunnelMtuUpdate;
use candy_tun::{MtuError, MtuUpdateOutcome, PacketContext, PumpAction, PumpDropReason};
use carrier_runtime::ip_tunnel::{
    IpTunnelConnection, IpTunnelConnectionError, IpTunnelConnectionRole, IpTunnelPhase,
};
use carrier_runtime::tun::{AttachedHubPacketAdapter, EdgePacketAdapter};
use carrier_transport::{send_datagram, DatagramSendError, DatagramSendOutcome};
use std::time::Instant;
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActivePacketLaneCounters {
    pub tun_packets_read: u64,
    pub transport_packets_sent: u64,
    pub transport_packets_received: u64,
    pub tun_packets_written: u64,
    pub backpressure_drops: u64,
    pub policy_drops: u64,
}

#[derive(Debug, Error)]
pub enum ActivePacketLaneError {
    #[error("packet lane requires an accepted active tunnel")]
    InactiveTunnel,
    #[error("packet lane role does not match the active tunnel role")]
    TunnelRoleMismatch,
    #[error("TUN packet I/O failed")]
    Tun(#[from] TunPacketFdError),
    #[error("packet tunnel state rejected a record")]
    Tunnel(#[from] IpTunnelConnectionError),
    #[error("QUIC DATAGRAM send failed")]
    DatagramSend(#[from] DatagramSendError),
    #[error("QUIC connection closed")]
    Connection(#[from] quinn::ConnectionError),
    #[error("peer does not support the required QUIC DATAGRAM lane")]
    DatagramUnsupported,
    #[error("packet lane peer-control channel closed")]
    ControlChannelClosed,
    #[error("packet lane MTU update channel is unavailable")]
    MtuUpdateChannelClosed,
}

enum PacketAdapter {
    Edge(EdgePacketAdapter),
    AttachedHub {
        adapter: AttachedHubPacketAdapter,
        remote_context: PacketContext,
    },
}

impl PacketAdapter {
    fn accept_tun_packet(&mut self, packet: Vec<u8>) -> Result<(), PumpDropReason> {
        match self {
            Self::Edge(adapter) => adapter.accept_tun_packet(packet),
            Self::AttachedHub { adapter, .. } => adapter.accept_tun_packet(packet),
        }
    }

    fn accept_transport_record(&mut self, record: Vec<u8>) -> Result<(), PumpDropReason> {
        match self {
            Self::Edge(adapter) => adapter.accept_transport_record(record),
            Self::AttachedHub {
                adapter,
                remote_context,
            } => adapter.accept_transport_record(*remote_context, record),
        }
    }

    fn drive_once(&mut self, now: std::time::Duration) -> PumpAction {
        match self {
            Self::Edge(adapter) => adapter.drive_once(now),
            Self::AttachedHub { adapter, .. } => adapter.drive_once(now),
        }
    }

    fn apply_mtu_update(
        &mut self,
        sequence: u64,
        effective_mtu: u16,
    ) -> Result<MtuUpdateOutcome, MtuError> {
        match self {
            Self::Edge(adapter) => adapter.apply_mtu_update(sequence, effective_mtu),
            Self::AttachedHub { adapter, .. } => adapter.apply_mtu_update(sequence, effective_mtu),
        }
    }

    fn take_transport_record(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Edge(adapter) => adapter.take_transport_record(),
            Self::AttachedHub { adapter, .. } => adapter.take_transport_record(),
        }
    }

    fn take_tun_packet(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Edge(adapter) => adapter.take_tun_packet(),
            Self::AttachedHub { adapter, .. } => adapter.take_tun_packet(),
        }
    }
}

pub struct ActivePacketLane {
    tun: TunPacketFd,
    transport: quinn::Connection,
    tunnel: IpTunnelConnection,
    adapter: PacketAdapter,
    peer_control: mpsc::Receiver<ControlMessage>,
    mtu_updates: Option<mpsc::Sender<IpTunnelMtuUpdate>>,
    started: Instant,
    counters: ActivePacketLaneCounters,
}

impl ActivePacketLane {
    pub fn edge(
        tun: TunPacketFd,
        transport: quinn::Connection,
        tunnel: IpTunnelConnection,
        adapter: EdgePacketAdapter,
        peer_control: mpsc::Receiver<ControlMessage>,
    ) -> Result<Self, ActivePacketLaneError> {
        Self::edge_with_mtu_updates(tun, transport, tunnel, adapter, peer_control, None)
    }

    pub fn edge_with_mtu_updates(
        tun: TunPacketFd,
        transport: quinn::Connection,
        tunnel: IpTunnelConnection,
        adapter: EdgePacketAdapter,
        peer_control: mpsc::Receiver<ControlMessage>,
        mtu_updates: Option<mpsc::Sender<IpTunnelMtuUpdate>>,
    ) -> Result<Self, ActivePacketLaneError> {
        Self::new(
            tun,
            transport,
            tunnel,
            IpTunnelConnectionRole::Client,
            PacketAdapter::Edge(adapter),
            peer_control,
            mtu_updates,
        )
    }

    pub fn attached_hub(
        tun: TunPacketFd,
        transport: quinn::Connection,
        tunnel: IpTunnelConnection,
        adapter: AttachedHubPacketAdapter,
        remote_context: PacketContext,
        peer_control: mpsc::Receiver<ControlMessage>,
    ) -> Result<Self, ActivePacketLaneError> {
        Self::attached_hub_with_mtu_updates(
            tun,
            transport,
            tunnel,
            adapter,
            remote_context,
            peer_control,
            None,
        )
    }

    pub fn attached_hub_with_mtu_updates(
        tun: TunPacketFd,
        transport: quinn::Connection,
        tunnel: IpTunnelConnection,
        adapter: AttachedHubPacketAdapter,
        remote_context: PacketContext,
        peer_control: mpsc::Receiver<ControlMessage>,
        mtu_updates: Option<mpsc::Sender<IpTunnelMtuUpdate>>,
    ) -> Result<Self, ActivePacketLaneError> {
        Self::new(
            tun,
            transport,
            tunnel,
            IpTunnelConnectionRole::Server,
            PacketAdapter::AttachedHub {
                adapter,
                remote_context,
            },
            peer_control,
            mtu_updates,
        )
    }

    fn new(
        tun: TunPacketFd,
        transport: quinn::Connection,
        tunnel: IpTunnelConnection,
        required_role: IpTunnelConnectionRole,
        adapter: PacketAdapter,
        peer_control: mpsc::Receiver<ControlMessage>,
        mtu_updates: Option<mpsc::Sender<IpTunnelMtuUpdate>>,
    ) -> Result<Self, ActivePacketLaneError> {
        if tunnel.phase() != IpTunnelPhase::Active {
            return Err(ActivePacketLaneError::InactiveTunnel);
        }
        if tunnel.role() != required_role {
            return Err(ActivePacketLaneError::TunnelRoleMismatch);
        }
        Ok(Self {
            tun,
            transport,
            tunnel,
            adapter,
            peer_control,
            mtu_updates,
            started: Instant::now(),
            counters: ActivePacketLaneCounters::default(),
        })
    }

    pub fn counters(&self) -> ActivePacketLaneCounters {
        self.counters
    }

    pub async fn run(mut self) -> Result<ActivePacketLaneCounters, ActivePacketLaneError> {
        loop {
            tokio::select! {
                packet = self.tun.read_packet() => {
                    self.handle_tun_packet(packet?).await?;
                }
                record = self.transport.read_datagram() => {
                    self.handle_transport_record(record?.to_vec()).await?;
                }
                message = self.peer_control.recv() => {
                    let message = message.ok_or(ActivePacketLaneError::ControlChannelClosed)?;
                    if self.handle_peer_control(message)? {
                        return Ok(self.counters);
                    }
                }
            }
        }
    }

    async fn handle_tun_packet(&mut self, packet: Vec<u8>) -> Result<(), ActivePacketLaneError> {
        self.counters.tun_packets_read = self.counters.tun_packets_read.saturating_add(1);
        if self.adapter.accept_tun_packet(packet).is_err() {
            self.record_policy_drop();
            return Ok(());
        }
        self.drive_adapter();
        self.flush_outputs().await
    }

    async fn handle_transport_record(
        &mut self,
        record: Vec<u8>,
    ) -> Result<(), ActivePacketLaneError> {
        self.counters.transport_packets_received =
            self.counters.transport_packets_received.saturating_add(1);
        self.tunnel.validate_packet(&record)?;
        if self.adapter.accept_transport_record(record).is_err() {
            self.record_policy_drop();
            return Ok(());
        }
        self.drive_adapter();
        self.flush_outputs().await
    }

    fn drive_adapter(&mut self) {
        if matches!(
            self.adapter.drive_once(self.started.elapsed()),
            PumpAction::Dropped(_)
        ) {
            self.record_policy_drop();
        }
    }

    fn handle_peer_control(
        &mut self,
        message: ControlMessage,
    ) -> Result<bool, ActivePacketLaneError> {
        self.tunnel.authorize_control(&message)?;
        match message {
            ControlMessage::IpTunnelMtuUpdate(update) => {
                self.tunnel.apply_mtu_update(&update)?;
                self.adapter
                    .apply_mtu_update(update.update_sequence, update.effective_inner_mtu)
                    .map_err(|_| IpTunnelConnectionError::InvalidMtuUpdate)?;
                if let Some(sender) = &self.mtu_updates {
                    sender
                        .try_send(update)
                        .map_err(|_| ActivePacketLaneError::MtuUpdateChannelClosed)?;
                }
                Ok(false)
            }
            ControlMessage::CloseIpTunnel(close) => {
                self.tunnel.apply_peer_close(&close)?;
                Ok(true)
            }
            _ => Err(IpTunnelConnectionError::UnauthorizedMessage.into()),
        }
    }

    async fn flush_outputs(&mut self) -> Result<(), ActivePacketLaneError> {
        while let Some(record) = self.adapter.take_transport_record() {
            self.tunnel.validate_packet(&record)?;
            match send_datagram(&self.transport, Bytes::from(record)).await? {
                DatagramSendOutcome::Sent => {
                    self.counters.transport_packets_sent =
                        self.counters.transport_packets_sent.saturating_add(1);
                }
                DatagramSendOutcome::DroppedBackpressure => {
                    self.counters.backpressure_drops =
                        self.counters.backpressure_drops.saturating_add(1);
                }
                DatagramSendOutcome::Unsupported => {
                    return Err(ActivePacketLaneError::DatagramUnsupported);
                }
            }
        }
        while let Some(packet) = self.adapter.take_tun_packet() {
            self.tun.write_packet(&packet).await?;
            self.counters.tun_packets_written = self.counters.tun_packets_written.saturating_add(1);
        }
        Ok(())
    }

    fn record_policy_drop(&mut self) {
        self.counters.policy_drops = self.counters.policy_drops.saturating_add(1);
    }
}
