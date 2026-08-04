use crate::tun_fd::{TunPacketFd, TunPacketFdError};
use crate::tun_lane::{ActivePacketLane, ActivePacketLaneCounters, ActivePacketLaneError};
use candy_netd_client::{IpcError, NetdClient};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, NetdProtocolError, PrepareDeclaration, RouteDeclaration, RouteKind,
    UnderlayExclusion, UnderlayKind,
};
use candy_proto::ip_tunnel::{AttachmentId, SegmentId};
use candy_proto::route_contract::{AttachmentPrincipalV1, AttachmentState, Ipv4PrefixV1};
use candy_tun::control::VerifiedDynamicRouteSnapshot;
use candy_tun::control::{HubNodeContext, VerifiedSegmentSnapshot, VerifiedSiteProjection};
use candy_tun::PacketContext;
use carrier_runtime::ip_tunnel::{IpTunnelConnection, IpTunnelPhase};
use carrier_runtime::tun::{AttachedHubPacketAdapter, EdgePacketAdapter};
use carrier_runtime::tun_control::{
    ClientTunnelControlError, OpenedClientTunnelControl, OpenedServerTunnelControl,
};
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum NetdPacketLaneError {
    #[error("signed route policy cannot be compiled for netd")]
    InvalidSignedPolicy(#[from] NetdProtocolError),
    #[error("all Cloud, Hub, and management underlay exclusions are required")]
    MissingUnderlayExclusion,
    #[error("accepted tunnel does not match the verified netd declaration")]
    TunnelBindingMismatch,
    #[error("netd transaction failed")]
    Netd(#[from] IpcError),
    #[error("netd transaction worker failed")]
    NetdWorker(#[from] tokio::task::JoinError),
    #[error("TUN packet descriptor is invalid")]
    Tun(#[from] TunPacketFdError),
    #[error("packet lane failed")]
    Lane(#[from] ActivePacketLaneError),
    #[error("dedicated tunnel control failed")]
    Control(#[from] ClientTunnelControlError),
}

#[derive(Debug)]
pub struct VerifiedNetdDeclaration {
    declaration: PrepareDeclaration,
    attachment_id: AttachmentId,
    segment_id: SegmentId,
    segment_generation: u64,
}

impl VerifiedNetdDeclaration {
    pub fn from_site_projection(
        projection: &VerifiedSiteProjection,
        table_id: u32,
        effective_mtu: u16,
        mut exclusions: Vec<UnderlayExclusion>,
        firewall: FirewallPolicy,
    ) -> Result<Self, NetdPacketLaneError> {
        let object = projection.object();
        if effective_mtu > object.max_inner_mtu {
            return Err(NetdPacketLaneError::TunnelBindingMismatch);
        }
        if ![
            UnderlayKind::CloudApi,
            UnderlayKind::HubEndpoint,
            UnderlayKind::Management,
        ]
        .into_iter()
        .all(|kind| exclusions.iter().any(|value| value.kind == kind))
        {
            return Err(NetdPacketLaneError::MissingUnderlayExclusion);
        }

        let mut routes = object
            .local_prefixes
            .iter()
            .copied()
            .map(|prefix| route(prefix, RouteKind::Local))
            .chain(
                object
                    .remote_routes
                    .iter()
                    .map(|value| route(value.destination_prefix, RouteKind::Remote)),
            )
            .collect::<Result<Vec<_>, _>>()?;
        routes.sort_unstable_by_key(|value| (value.prefix, value.kind as u64));
        exclusions.sort_unstable_by_key(|value| (value.prefix, value.kind as u64));
        let declaration = PrepareDeclaration {
            table_id,
            overlay_router_ipv4: object.overlay_router_ipv4,
            effective_mtu,
            routes,
            exclusions,
            firewall,
        };
        declaration.validate()?;
        Ok(Self {
            declaration,
            attachment_id: object.attachment_id,
            segment_id: object.segment_id,
            segment_generation: object.segment_generation,
        })
    }

    pub fn declaration(&self) -> &PrepareDeclaration {
        &self.declaration
    }

    fn matches(&self, tunnel: &IpTunnelConnection) -> bool {
        tunnel.phase() == IpTunnelPhase::Active
            && tunnel.attachment_id() == Some(self.attachment_id)
            && tunnel.segment_id() == Some(self.segment_id)
            && tunnel.segment_generation() == Some(self.segment_generation)
            && tunnel.effective_inner_mtu() == Some(self.declaration.effective_mtu)
    }
}

#[derive(Debug)]
pub struct VerifiedHubNetdDeclaration {
    declaration: PrepareDeclaration,
    node_attachment_id: AttachmentId,
    node_attachment_epoch: u64,
    segment_id: SegmentId,
    segment_generation: u64,
    segment_content_hash: [u8; 32],
    remote_attachment_id: AttachmentId,
}

impl VerifiedHubNetdDeclaration {
    #[allow(clippy::too_many_arguments)]
    pub fn from_segment_snapshot(
        snapshot: &VerifiedSegmentSnapshot,
        hub: HubNodeContext,
        node_attachment_id: AttachmentId,
        node_attachment_epoch: u64,
        table_id: u32,
        effective_mtu: u16,
        mut exclusions: Vec<UnderlayExclusion>,
        firewall: FirewallPolicy,
    ) -> Result<Self, NetdPacketLaneError> {
        let object = snapshot.object();
        let attachment = object
            .attachments
            .iter()
            .find(|value| value.attachment_id == node_attachment_id)
            .ok_or(NetdPacketLaneError::TunnelBindingMismatch)?;
        if object.tenant_id != hub.tenant_id
            || object.hub_node_pool_id != hub.node_pool_id
            || attachment.state != AttachmentState::Active
            || node_attachment_epoch < attachment.epoch_floor
            || !matches!(
                attachment.principal,
                AttachmentPrincipalV1::Node {
                    node_id,
                    node_key_id,
                } if node_id == hub.node_id && node_key_id == hub.node_key_id
            )
        {
            return Err(NetdPacketLaneError::TunnelBindingMismatch);
        }
        if ![
            UnderlayKind::CloudApi,
            UnderlayKind::HubEndpoint,
            UnderlayKind::Management,
        ]
        .into_iter()
        .all(|kind| exclusions.iter().any(|value| value.kind == kind))
        {
            return Err(NetdPacketLaneError::MissingUnderlayExclusion);
        }
        let mut routes = object
            .routes
            .iter()
            .map(|value| {
                route(
                    value.destination_prefix,
                    if value.owner_attachment_ids.contains(&node_attachment_id) {
                        RouteKind::Local
                    } else {
                        RouteKind::Remote
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut remote_attachment_ids = object
            .routes
            .iter()
            .filter(|route| !route.owner_attachment_ids.contains(&node_attachment_id))
            .flat_map(|route| route.owner_attachment_ids.iter().copied())
            .collect::<Vec<_>>();
        remote_attachment_ids.sort_unstable_by_key(|attachment| attachment.0);
        remote_attachment_ids.dedup();
        let [remote_attachment_id] = remote_attachment_ids.as_slice() else {
            return Err(NetdPacketLaneError::TunnelBindingMismatch);
        };
        routes.sort_unstable_by_key(|value| (value.prefix, value.kind as u64));
        exclusions.sort_unstable_by_key(|value| (value.prefix, value.kind as u64));
        let declaration = PrepareDeclaration {
            table_id,
            overlay_router_ipv4: attachment.overlay_router_ipv4,
            effective_mtu,
            routes,
            exclusions,
            firewall,
        };
        declaration.validate()?;
        Ok(Self {
            declaration,
            node_attachment_id,
            node_attachment_epoch,
            segment_id: object.segment_id,
            segment_generation: object.segment_generation,
            segment_content_hash: object.content_hash,
            remote_attachment_id: *remote_attachment_id,
        })
    }

    pub fn declaration(&self) -> &PrepareDeclaration {
        &self.declaration
    }

    pub fn with_dynamic_routes(
        mut self,
        dynamic: &VerifiedDynamicRouteSnapshot,
    ) -> Result<Self, NetdPacketLaneError> {
        if dynamic.object().segment_id != self.segment_id
            || dynamic.object().base_segment_generation != self.segment_generation
            || dynamic.object().base_segment_content_hash != self.segment_content_hash
        {
            return Err(NetdPacketLaneError::TunnelBindingMismatch);
        }
        for dynamic_route in &dynamic.object().routes {
            self.declaration.routes.push(route(
                dynamic_route.prefix,
                if dynamic_route.owner_attachment_id == self.node_attachment_id {
                    RouteKind::Local
                } else {
                    RouteKind::Remote
                },
            )?);
        }
        self.declaration
            .routes
            .sort_unstable_by_key(|value| (value.prefix, value.kind as u64));
        self.declaration.validate()?;
        Ok(self)
    }

    fn matches(&self, tunnel: &IpTunnelConnection) -> bool {
        tunnel.phase() == IpTunnelPhase::Active
            && tunnel.segment_id() == Some(self.segment_id)
            && tunnel.segment_generation() == Some(self.segment_generation)
            && tunnel.effective_inner_mtu() == Some(self.declaration.effective_mtu)
            && tunnel.attachment_id() == Some(self.remote_attachment_id)
    }

    fn local_context(&self, tunnel_id: u64) -> PacketContext {
        PacketContext {
            tunnel_id,
            attachment_id: self.node_attachment_id,
            attachment_epoch: self.node_attachment_epoch,
        }
    }
}

pub async fn run_committed_edge_packet_lane(
    netd: NetdClient,
    verified: VerifiedNetdDeclaration,
    transport: quinn::Connection,
    tunnel: IpTunnelConnection,
    adapter: EdgePacketAdapter,
    peer_control: mpsc::Receiver<candy_proto::control::ControlMessage>,
) -> Result<ActivePacketLaneCounters, NetdPacketLaneError> {
    if !verified.matches(&tunnel) {
        return Err(NetdPacketLaneError::TunnelBindingMismatch);
    }

    let declaration = verified.declaration;
    let (mut netd, prepared) = tokio::task::spawn_blocking(move || {
        let mut netd = netd;
        let result = netd.prepare(declaration);
        (netd, result)
    })
    .await?;
    let prepared = prepared?;
    let (mtu_sender, mut mtu_updates) = mpsc::channel(8);
    let lane = ActivePacketLane::edge_with_mtu_updates(
        TunPacketFd::new(prepared.tun)?,
        transport,
        tunnel,
        adapter,
        peer_control,
        Some(mtu_sender),
    )?;

    netd = tokio::task::spawn_blocking(move || {
        netd.commit()?;
        Ok::<_, IpcError>(netd)
    })
    .await??;
    let mut lane_task = Box::pin(lane.run());
    let lane_result = loop {
        tokio::select! {
            result = &mut lane_task => {
                let result = result.map_err(NetdPacketLaneError::Lane);
                while let Some(update) = mtu_updates.recv().await {
                    netd = tokio::task::spawn_blocking(move || {
                        netd.update_mtu(update.effective_inner_mtu)?;
                        Ok::<_, IpcError>(netd)
                    }).await??;
                }
                break result;
            },
            update = mtu_updates.recv() => {
                let Some(update) = update else {
                    break Err(NetdPacketLaneError::Lane(
                        ActivePacketLaneError::MtuUpdateChannelClosed,
                    ));
                };
                netd = tokio::task::spawn_blocking(move || {
                    netd.update_mtu(update.effective_inner_mtu)?;
                    Ok::<_, IpcError>(netd)
                }).await??;
            }
        }
    };
    tokio::task::spawn_blocking(move || netd.rollback()).await??;
    lane_result
}

pub async fn run_opened_committed_edge_packet_lane(
    netd: NetdClient,
    verified: VerifiedNetdDeclaration,
    opened: OpenedClientTunnelControl,
    adapter: EdgePacketAdapter,
) -> Result<ActivePacketLaneCounters, NetdPacketLaneError> {
    let (transport, tunnel, peer_control, owner) = opened.into_parts();
    let tunnel_id = tunnel
        .tunnel_id()
        .ok_or(NetdPacketLaneError::TunnelBindingMismatch)?;
    let result =
        run_committed_edge_packet_lane(netd, verified, transport, tunnel, adapter, peer_control)
            .await;
    if result.is_ok() {
        owner.shutdown().await;
    } else {
        let _ = owner
            .close(tunnel_id, candy_proto::ip_tunnel::codes::INTERNAL_ERROR)
            .await;
    }
    result
}

pub async fn run_committed_attached_hub_packet_lane(
    netd: NetdClient,
    verified: VerifiedHubNetdDeclaration,
    transport: quinn::Connection,
    tunnel: IpTunnelConnection,
    adapter: AttachedHubPacketAdapter,
    peer_control: mpsc::Receiver<candy_proto::control::ControlMessage>,
) -> Result<ActivePacketLaneCounters, NetdPacketLaneError> {
    if !verified.matches(&tunnel) {
        return Err(NetdPacketLaneError::TunnelBindingMismatch);
    }
    let tunnel_id = tunnel
        .tunnel_id()
        .ok_or(NetdPacketLaneError::TunnelBindingMismatch)?;
    let remote_context = PacketContext {
        tunnel_id,
        attachment_id: tunnel
            .attachment_id()
            .ok_or(NetdPacketLaneError::TunnelBindingMismatch)?,
        attachment_epoch: tunnel
            .attachment_epoch()
            .ok_or(NetdPacketLaneError::TunnelBindingMismatch)?,
    };
    let local_context = verified.local_context(tunnel_id);
    if adapter.local_context() != Some(local_context) {
        return Err(NetdPacketLaneError::TunnelBindingMismatch);
    }
    let declaration = verified.declaration;
    let (mut netd, prepared) = tokio::task::spawn_blocking(move || {
        let mut netd = netd;
        let result = netd.prepare(declaration);
        (netd, result)
    })
    .await?;
    let prepared = prepared?;
    let (mtu_sender, mut mtu_updates) = mpsc::channel(8);
    let lane = ActivePacketLane::attached_hub_with_mtu_updates(
        TunPacketFd::new(prepared.tun)?,
        transport,
        tunnel,
        adapter,
        remote_context,
        peer_control,
        Some(mtu_sender),
    )?;
    netd = tokio::task::spawn_blocking(move || {
        netd.commit()?;
        Ok::<_, IpcError>(netd)
    })
    .await??;
    let mut lane_task = Box::pin(lane.run());
    let lane_result = loop {
        tokio::select! {
            result = &mut lane_task => {
                let result = result.map_err(NetdPacketLaneError::Lane);
                while let Some(update) = mtu_updates.recv().await {
                    netd = tokio::task::spawn_blocking(move || {
                        netd.update_mtu(update.effective_inner_mtu)?;
                        Ok::<_, IpcError>(netd)
                    }).await??;
                }
                break result;
            },
            update = mtu_updates.recv() => {
                let Some(update) = update else {
                    break Err(NetdPacketLaneError::Lane(
                        ActivePacketLaneError::MtuUpdateChannelClosed,
                    ));
                };
                netd = tokio::task::spawn_blocking(move || {
                    netd.update_mtu(update.effective_inner_mtu)?;
                    Ok::<_, IpcError>(netd)
                }).await??;
            }
        }
    };
    tokio::task::spawn_blocking(move || netd.rollback()).await??;
    lane_result
}

pub async fn run_opened_committed_attached_hub_packet_lane(
    netd: NetdClient,
    verified: VerifiedHubNetdDeclaration,
    opened: OpenedServerTunnelControl,
    adapter: AttachedHubPacketAdapter,
) -> Result<ActivePacketLaneCounters, NetdPacketLaneError> {
    let (transport, tunnel, peer_control, owner) = opened.into_parts();
    let tunnel_id = tunnel
        .tunnel_id()
        .ok_or(NetdPacketLaneError::TunnelBindingMismatch)?;
    let result = run_committed_attached_hub_packet_lane(
        netd,
        verified,
        transport,
        tunnel,
        adapter,
        peer_control,
    )
    .await;
    if result.is_ok() {
        owner.shutdown().await;
    } else {
        let _ = owner
            .close(tunnel_id, candy_proto::ip_tunnel::codes::INTERNAL_ERROR)
            .await;
    }
    result
}

fn route(prefix: Ipv4PrefixV1, kind: RouteKind) -> Result<RouteDeclaration, NetdProtocolError> {
    Ok(RouteDeclaration {
        prefix: Ipv4Prefix::new(prefix.network, prefix.prefix_len)?,
        kind,
    })
}
