#![cfg(unix)]

use candy_netd_client::{recv_request, send_response, NetdClient};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix as NetdPrefix, LeaseOwner, NetdOperation, NetdResponse,
    ResponseBody, UnderlayExclusion, UnderlayKind, CANDY_TABLE_MIN,
};
use candy_proto::cloud_grant::{
    DeviceId, DeviceKeyId, NodePoolId, PolicyId, ServiceClass, TenantId,
};
use candy_proto::control::ControlMessage;
use candy_proto::dynamic_route_contract::{DynamicRouteSnapshotV1, DynamicRouteV1};
use candy_proto::features::FeatureSet;
use candy_proto::ip_tunnel::{
    codes, ipv4_header_checksum, AttachmentId, CloseIpTunnel, IpTunnelMtuUpdate, IpTunnelResult,
    OpenIpTunnel, SegmentId, SiteId, IP_PACKET_FORMAT_V1,
};
use candy_proto::route_contract::{
    AllowedHubNodeV1, AttachmentPrincipalV1, AttachmentState, FailoverPolicyV1, Ipv4PrefixV1,
    NodeId, NodeKeyId, PacketResourcePolicyV1, RemoteRouteV1, SegmentAttachmentV1,
    SegmentRouteSnapshotV1, SegmentRouteV1, SiteRouteProjectionV1,
};
use candy_runtime_linux::tun_netd::{
    run_opened_committed_edge_packet_lane, VerifiedHubNetdDeclaration, VerifiedNetdDeclaration,
};
use candy_tun::control::{
    HubNodeContext, RouteTrustStore, VerifiedDynamicRouteSnapshot, VerifiedSegmentSnapshot,
    VerifiedSiteProjection,
};
use candy_tun::{
    EdgeEngine, EdgeEngineConfig, EdgeTunPump, MtuState, PacketContext, PacketRecord,
    PumpQueueLimits, QueueLimits, ReplayLimits, RouteDomainId,
};
use carrier_crypto::route_contract::{
    seal_dynamic_route_snapshot, seal_segment_snapshot, seal_site_projection,
};
use carrier_runtime::ip_tunnel::{
    ClientTunnelPrerequisites, IpTunnelConnection, IpTunnelConnectionRole,
};
use carrier_runtime::tun::EdgePacketAdapter;
use carrier_runtime::tun_control::open_client_tunnel_control;
use carrier_transport::telemetry::TelemetryCounters;
use carrier_transport::{ControlReader, ControlWriter};
use ed25519_dalek::SigningKey;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixDatagram, UnixListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn prefix(network: [u8; 4], prefix_len: u8) -> Ipv4PrefixV1 {
    Ipv4PrefixV1::new(network, prefix_len).unwrap()
}

fn verified_projection() -> VerifiedSiteProjection {
    let key = SigningKey::from_bytes(&[42; 32]);
    let key_id = b"route-key-1".to_vec();
    let projection = SiteRouteProjectionV1 {
        tenant_id: TenantId([1; 16]),
        segment_id: SegmentId([2; 16]),
        segment_generation: 9,
        segment_content_hash: [3; 32],
        site_id: SiteId([4; 16]),
        attachment_id: AttachmentId([5; 16]),
        device_id: DeviceId([6; 16]),
        device_key_id: DeviceKeyId([7; 16]),
        overlay_router_ipv4: [100, 64, 0, 1],
        local_prefixes: vec![prefix([10, 1, 0, 0], 16)],
        remote_routes: vec![RemoteRouteV1 {
            destination_prefix: prefix([10, 2, 0, 0], 16),
            owner_site_id: SiteId([8; 16]),
            owner_attachment_ids: vec![AttachmentId([9; 16])],
        }],
        allowed_hub_nodes: vec![AllowedHubNodeV1 {
            node_id: NodeId([10; 16]),
            node_key_id: NodeKeyId([11; 16]),
            diagnostic_attachment_id: AttachmentId([12; 16]),
        }],
        max_inner_mtu: 1200,
        failover: FailoverPolicyV1 {
            max_preconnected_hubs: 1,
            critical_recovery_ms: 100,
            standard_recovery_ms: 500,
        },
        resources: PacketResourcePolicyV1 {
            max_route_prefixes: 64,
            max_queue_packets: 128,
            max_queue_bytes: 262_144,
            replay_window_packets: 1024,
            max_packets_per_second: 10_000,
            max_bytes_per_second: 1_000_000,
            allowed_traffic_classes: 1,
        },
        epoch_floor: 1,
        not_before: 100,
        expires_at: 200,
        stale_until: 250,
        projection_id: PolicyId([13; 16]),
        projection_generation: 1,
        previous_hash: [0; 32],
        content_hash: [1; 32],
    };
    let sealed = seal_site_projection(projection, key_id.clone(), &key).unwrap();
    let trust = RouteTrustStore::new([(key_id, key.verifying_key())]).unwrap();
    VerifiedSiteProjection::verify(&sealed.envelope, &trust).unwrap()
}

fn tunnel_open(projection: &VerifiedSiteProjection) -> OpenIpTunnel {
    let object = projection.object();
    OpenIpTunnel {
        tunnel_id: 7,
        attachment_id: object.attachment_id,
        attachment_epoch: 1,
        site_id: object.site_id,
        segment_id: object.segment_id,
        site_projection: projection.policy_ref(),
        segment_generation: object.segment_generation,
        segment_content_hash: object.segment_content_hash,
        requested_inner_mtu: 1180,
        packet_format_version: IP_PACKET_FORMAT_V1,
    }
}

fn ready_tunnel() -> IpTunnelConnection {
    let features = FeatureSet::from_bits(
        FeatureSet::CLOUD_GRANT_V1 | FeatureSet::DATAGRAM | FeatureSet::IP_PACKET_TUNNEL_V1,
    );
    IpTunnelConnection::new(IpTunnelConnectionRole::Client, features, features).unwrap()
}

fn edge_adapter(projection: &VerifiedSiteProjection) -> EdgePacketAdapter {
    let object = projection.object();
    let limits = QueueLimits {
        max_packets: object.resources.max_queue_packets as usize,
        max_bytes: object.resources.max_queue_bytes as usize,
    };
    let engine = EdgeEngine::new(EdgeEngineConfig {
        enabled: true,
        domain: RouteDomainId {
            tenant_id: object.tenant_id.0,
            segment_id: object.segment_id,
        },
        context: PacketContext {
            tunnel_id: 7,
            attachment_id: object.attachment_id,
            attachment_epoch: 1,
        },
        local_prefixes: projection.local_prefixes().clone(),
        remote_routes: projection.remote_routes().clone(),
        mtu: MtuState::new(1180, 1180, 1180, 0).unwrap(),
        replay_limits: ReplayLimits {
            max_attachments: 64,
            window: object.resources.replay_window_packets as usize,
        },
        upload_queue_limits: limits,
        download_queue_limits: limits,
        diagnostic_router_ipv4: Ipv4Addr::from(object.overlay_router_ipv4),
    })
    .unwrap();
    EdgePacketAdapter::new(EdgeTunPump::new(engine, PumpQueueLimits::default(), 1).unwrap())
}

fn packet() -> Vec<u8> {
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 1, 0, 10]);
    packet[16..20].copy_from_slice(&[10, 2, 0, 10]);
    let checksum = ipv4_header_checksum(&packet).unwrap();
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn socket_path() -> PathBuf {
    PathBuf::from(format!("/tmp/cnd-lane-{}.sock", std::process::id()))
}

fn verified_hub_snapshot() -> VerifiedSegmentSnapshot {
    let key = SigningKey::from_bytes(&[43; 32]);
    let key_id = b"route-key-1".to_vec();
    let snapshot = SegmentRouteSnapshotV1 {
        tenant_id: TenantId([1; 16]),
        segment_id: SegmentId([2; 16]),
        segment_generation: 1,
        hub_node_pool_id: NodePoolId([3; 16]),
        segment_overlay_prefix: prefix([100, 64, 0, 0], 24),
        attachments: vec![
            SegmentAttachmentV1 {
                attachment_id: AttachmentId([5; 16]),
                site_id: Some(SiteId([4; 16])),
                principal: AttachmentPrincipalV1::Device {
                    device_id: DeviceId([6; 16]),
                    device_key_id: DeviceKeyId([7; 16]),
                },
                overlay_router_ipv4: [100, 64, 0, 1],
                local_prefixes: vec![prefix([10, 1, 0, 0], 16)],
                state: AttachmentState::Active,
                epoch_floor: 1,
            },
            SegmentAttachmentV1 {
                attachment_id: AttachmentId([12; 16]),
                site_id: Some(SiteId([8; 16])),
                principal: AttachmentPrincipalV1::Node {
                    node_id: NodeId([10; 16]),
                    node_key_id: NodeKeyId([11; 16]),
                },
                overlay_router_ipv4: [100, 64, 0, 2],
                local_prefixes: vec![prefix([10, 2, 0, 0], 16)],
                state: AttachmentState::Active,
                epoch_floor: 3,
            },
        ],
        routes: vec![
            SegmentRouteV1 {
                destination_prefix: prefix([10, 1, 0, 0], 16),
                owner_site_id: Some(SiteId([4; 16])),
                owner_attachment_ids: vec![AttachmentId([5; 16])],
            },
            SegmentRouteV1 {
                destination_prefix: prefix([10, 2, 0, 0], 16),
                owner_site_id: Some(SiteId([8; 16])),
                owner_attachment_ids: vec![AttachmentId([12; 16])],
            },
        ],
        not_before: 100,
        expires_at: 200,
        stale_until: 250,
        previous_hash: [0; 32],
        content_hash: [1; 32],
    };
    let sealed = seal_segment_snapshot(snapshot, key_id.clone(), &key).unwrap();
    let trust = RouteTrustStore::new([(key_id, key.verifying_key())]).unwrap();
    VerifiedSegmentSnapshot::verify(&sealed.envelope, &trust).unwrap()
}

fn dynamic_route_envelope(
    snapshot: &VerifiedSegmentSnapshot,
    owner_site_id: SiteId,
    owner_attachment_id: AttachmentId,
    base_content_hash: [u8; 32],
) -> (
    candy_proto::route_contract::SignedRouteEnvelopeV1,
    RouteTrustStore,
) {
    let key = SigningKey::from_bytes(&[44; 32]);
    let key_id = b"dynamic-route-key-1".to_vec();
    let object = snapshot.object();
    let sealed = seal_dynamic_route_snapshot(
        DynamicRouteSnapshotV1 {
            tenant_id: object.tenant_id,
            segment_id: object.segment_id,
            base_segment_generation: object.segment_generation,
            base_segment_content_hash: base_content_hash,
            routes: vec![DynamicRouteV1 {
                prefix: prefix([10, 3, 0, 0], 16),
                owner_site_id,
                owner_attachment_id,
                metric: 100,
            }],
            policy_id: PolicyId([14; 16]),
            generation: 1,
            not_before: 100,
            expires_at: 200,
            stale_until: 250,
            previous_hash: [0; 32],
            content_hash: [0; 32],
        },
        key_id.clone(),
        &key,
    )
    .unwrap();
    let trust = RouteTrustStore::new([(key_id, key.verifying_key())]).unwrap();
    (sealed.envelope, trust)
}

fn hub_exclusions() -> Vec<UnderlayExclusion> {
    [
        (UnderlayKind::CloudApi, [192, 0, 2, 1]),
        (UnderlayKind::HubEndpoint, [192, 0, 2, 2]),
        (UnderlayKind::Management, [192, 0, 2, 3]),
    ]
    .into_iter()
    .map(|(kind, address)| UnderlayExclusion {
        prefix: NetdPrefix::new(address, 32).unwrap(),
        kind,
    })
    .collect()
}

#[test]
fn signed_node_attachment_drives_hub_netd_declaration() {
    let snapshot = verified_hub_snapshot();
    let hub = HubNodeContext {
        tenant_id: TenantId([1; 16]),
        node_id: NodeId([10; 16]),
        node_key_id: NodeKeyId([11; 16]),
        node_pool_id: NodePoolId([3; 16]),
        service_class: ServiceClass::CustomerPrivate,
    };
    let verified = VerifiedHubNetdDeclaration::from_segment_snapshot(
        &snapshot,
        hub,
        AttachmentId([12; 16]),
        3,
        CANDY_TABLE_MIN,
        1180,
        hub_exclusions(),
        FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    )
    .unwrap();
    assert_eq!(verified.declaration().overlay_router_ipv4, [100, 64, 0, 2]);
    assert_eq!(verified.declaration().routes.len(), 2);
    assert!(verified
        .declaration()
        .routes
        .iter()
        .any(|route| route.kind == candy_netd_proto::RouteKind::Local));
    assert!(verified
        .declaration()
        .routes
        .iter()
        .any(|route| route.kind == candy_netd_proto::RouteKind::Remote));

    let wrong_hub = HubNodeContext {
        node_key_id: NodeKeyId([99; 16]),
        ..hub
    };
    assert!(VerifiedHubNetdDeclaration::from_segment_snapshot(
        &snapshot,
        wrong_hub,
        AttachmentId([12; 16]),
        3,
        CANDY_TABLE_MIN,
        1180,
        hub_exclusions(),
        FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    )
    .is_err());
}

#[test]
fn signed_dynamic_route_drives_packet_lookup_and_hub_netd_declaration() {
    let snapshot = verified_hub_snapshot();
    let object = snapshot.object();
    let (envelope, trust) = dynamic_route_envelope(
        &snapshot,
        SiteId([4; 16]),
        AttachmentId([5; 16]),
        object.content_hash,
    );
    let dynamic = VerifiedDynamicRouteSnapshot::verify(&envelope, &trust, &snapshot).unwrap();

    let resolved = dynamic
        .routes()
        .lookup(
            candy_tun::RouteDomainId {
                tenant_id: object.tenant_id.0,
                segment_id: object.segment_id,
            },
            Ipv4Addr::new(10, 3, 1, 7),
        )
        .unwrap()
        .unwrap();
    assert_eq!(resolved.owners()[0].attachment_id, AttachmentId([5; 16]));

    let hub = HubNodeContext {
        tenant_id: TenantId([1; 16]),
        node_id: NodeId([10; 16]),
        node_key_id: NodeKeyId([11; 16]),
        node_pool_id: NodePoolId([3; 16]),
        service_class: ServiceClass::CustomerPrivate,
    };
    let declaration = VerifiedHubNetdDeclaration::from_segment_snapshot(
        &snapshot,
        hub,
        AttachmentId([12; 16]),
        3,
        CANDY_TABLE_MIN,
        1180,
        hub_exclusions(),
        FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    )
    .unwrap()
    .with_dynamic_routes(&dynamic)
    .unwrap();
    assert!(declaration.declaration().routes.iter().any(|route| {
        route.prefix == NetdPrefix::new([10, 3, 0, 0], 16).unwrap()
            && route.kind == candy_netd_proto::RouteKind::Remote
    }));

    let (wrong_base, trust) =
        dynamic_route_envelope(&snapshot, SiteId([4; 16]), AttachmentId([5; 16]), [99; 32]);
    assert!(VerifiedDynamicRouteSnapshot::verify(&wrong_base, &trust, &snapshot).is_err());

    let (wrong_owner, trust) = dynamic_route_envelope(
        &snapshot,
        SiteId([8; 16]),
        AttachmentId([5; 16]),
        object.content_hash,
    );
    assert!(VerifiedDynamicRouteSnapshot::verify(&wrong_owner, &trust, &snapshot).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_policy_drives_prepare_commit_packet_and_rollback() {
    let projection = verified_projection();
    let exclusions = [
        (UnderlayKind::CloudApi, [192, 0, 2, 1]),
        (UnderlayKind::HubEndpoint, [192, 0, 2, 2]),
        (UnderlayKind::Management, [192, 0, 2, 3]),
    ]
    .into_iter()
    .map(|(kind, address)| UnderlayExclusion {
        prefix: NetdPrefix::new(address, 32).unwrap(),
        kind,
    })
    .collect();
    let verified = VerifiedNetdDeclaration::from_site_projection(
        &projection,
        CANDY_TABLE_MIN,
        1180,
        exclusions,
        FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    )
    .unwrap();

    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let (lane_fd, peer_fd) = UnixDatagram::pair().unwrap();
    let netd = std::thread::spawn(move || {
        for expected in 1..=4 {
            let (stream, _) = listener.accept().unwrap();
            let request = recv_request(&stream).unwrap();
            assert_eq!(request.request_id, expected);
            let (body, descriptor) = match request.operation {
                NetdOperation::Prepare(declaration) => {
                    assert_eq!(declaration.routes.len(), 2);
                    (
                        ResponseBody::Prepared {
                            generation: 7,
                            tun_fd_attached: true,
                        },
                        Some(&lane_fd),
                    )
                }
                NetdOperation::Commit => (ResponseBody::Committed { generation: 7 }, None),
                NetdOperation::MtuUpdate { effective_mtu } => {
                    assert_eq!(effective_mtu, 1100);
                    (
                        ResponseBody::MtuUpdated {
                            generation: 7,
                            effective_mtu,
                        },
                        None,
                    )
                }
                NetdOperation::Rollback => (ResponseBody::RolledBack { generation: 7 }, None),
                _ => panic!("unexpected netd operation"),
            };
            send_response(
                &stream,
                &NetdResponse {
                    request_id: request.request_id,
                    body,
                },
                descriptor.map(AsRawFd::as_raw_fd),
            )
            .unwrap();
        }
    });

    peer_fd.set_nonblocking(true).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer_fd).unwrap();
    let quic = carrier_transport::local_quic_pair().await.unwrap();
    let (client_send, client_recv) = quic.client.open_bi().await.unwrap();
    let (release_control, wait_for_packet) = tokio::sync::oneshot::channel();
    let server_connection = quic.server.clone();
    let control_server = tokio::spawn(async move {
        let (mut send, mut recv) = server_connection.accept_bi().await.unwrap();
        let mut reader = ControlReader::new();
        let ControlMessage::OpenIpTunnel(request) = reader.next(&mut recv).await.unwrap() else {
            panic!("expected tunnel OPEN");
        };
        let mut writer = ControlWriter::new();
        writer
            .write(
                &mut send,
                &ControlMessage::IpTunnelResult(IpTunnelResult {
                    tunnel_id: request.tunnel_id,
                    accepted: true,
                    error_code: codes::OK,
                    effective_inner_mtu: 1180,
                    accepted_segment_generation: request.segment_generation,
                    attachment_epoch: request.attachment_epoch,
                }),
                false,
            )
            .await
            .unwrap();
        wait_for_packet.await.unwrap();
        writer
            .write(
                &mut send,
                &ControlMessage::IpTunnelMtuUpdate(IpTunnelMtuUpdate {
                    tunnel_id: request.tunnel_id,
                    update_sequence: 1,
                    effective_inner_mtu: 1100,
                    reason_code: codes::MTU_REDUCED,
                }),
                false,
            )
            .await
            .unwrap();
        writer
            .write(
                &mut send,
                &ControlMessage::CloseIpTunnel(CloseIpTunnel {
                    tunnel_id: request.tunnel_id,
                    reason_code: codes::OK,
                }),
                false,
            )
            .await
            .unwrap();
    });
    let features = FeatureSet::from_bits(
        FeatureSet::CLOUD_GRANT_V1 | FeatureSet::DATAGRAM | FeatureSet::IP_PACKET_TUNNEL_V1,
    );
    let opened = open_client_tunnel_control(
        quic.client.clone(),
        client_send,
        client_recv,
        ControlReader::new(),
        ready_tunnel(),
        ClientTunnelPrerequisites {
            grant_and_device_proof_authenticated: true,
            signed_policy_verified: true,
            underlay_exclusions_locked: true,
            local_preflight_passed: true,
        },
        tunnel_open(&projection),
        features,
        false,
        Arc::new(TelemetryCounters::default()),
    )
    .await
    .unwrap();
    let owner = LeaseOwner {
        instance_id: [14; 16],
        pid: std::process::id(),
        generation: 7,
        lease_deadline_mono_ms: 50_000,
    };
    let lane = tokio::spawn(run_opened_committed_edge_packet_lane(
        NetdClient::new(&path, owner),
        verified,
        opened,
        edge_adapter(&projection),
    ));

    peer.send(&packet()).await.unwrap();
    let encoded = tokio::time::timeout(Duration::from_secs(2), quic.server.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(PacketRecord::decode(&encoded).unwrap().tunnel_id(), 7);
    release_control.send(()).unwrap();
    let counters = tokio::time::timeout(Duration::from_secs(2), lane)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(counters.transport_packets_sent, 1);
    control_server.await.unwrap();
    netd.join().unwrap();
    std::fs::remove_file(path).unwrap();
}
