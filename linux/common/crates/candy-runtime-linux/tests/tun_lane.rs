#![cfg(unix)]

use bytes::Bytes;
use candy_proto::cloud_grant::{PolicyId, PolicyRefV1};
use candy_proto::control::ControlMessage;
use candy_proto::features::FeatureSet;
use candy_proto::ip_tunnel::{
    codes, ipv4_header_checksum, AttachmentId, CloseIpTunnel, IpTunnelMtuUpdate, IpTunnelResult,
    OpenIpTunnel, SegmentId, SiteId, IP_PACKET_FORMAT_V1,
};
use candy_runtime_linux::tun_fd::TunPacketFd;
use candy_runtime_linux::tun_lane::ActivePacketLane;
use candy_tun::{
    EdgeEngine, EdgeEngineConfig, EdgeTunPump, Ipv4Prefix, MtuState, PacketContext, PacketRecord,
    PrefixSet, PumpQueueLimits, QueueLimits, ReplayLimits, RouteDomainId, RouteEntry, RouteLimits,
    RouteOwner, RoutePolicy, RouteTable,
};
use carrier_runtime::ip_tunnel::{
    ClientTunnelPrerequisites, IpTunnelConnection, IpTunnelConnectionRole,
};
use carrier_runtime::tun::EdgePacketAdapter;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::str::FromStr;
use std::time::Duration;

fn attachment(value: u8) -> AttachmentId {
    AttachmentId([value; 16])
}

fn domain() -> RouteDomainId {
    RouteDomainId {
        tenant_id: [1; 16],
        segment_id: SegmentId([2; 16]),
    }
}

fn prefix(value: &str) -> Ipv4Prefix {
    Ipv4Prefix::from_str(value).unwrap()
}

fn routes() -> RouteTable {
    RouteTable::compile(
        domain(),
        [
            RouteEntry::new(
                prefix("10.1.0.0/16"),
                vec![RouteOwner {
                    attachment_id: attachment(1),
                }],
            )
            .unwrap(),
            RouteEntry::new(
                prefix("10.2.0.0/16"),
                vec![RouteOwner {
                    attachment_id: attachment(2),
                }],
            )
            .unwrap(),
        ],
        [Ipv4Addr::new(100, 64, 0, 1)],
        RouteLimits::default(),
        RoutePolicy::PrivateOnly,
    )
    .unwrap()
}

fn edge_adapter() -> EdgePacketAdapter {
    let engine = EdgeEngine::new(EdgeEngineConfig {
        enabled: true,
        domain: domain(),
        context: PacketContext {
            tunnel_id: 7,
            attachment_id: attachment(1),
            attachment_epoch: 1,
        },
        local_prefixes: PrefixSet::compile(
            [prefix("10.1.0.0/16")],
            RouteLimits::default(),
            RoutePolicy::PrivateOnly,
        )
        .unwrap(),
        remote_routes: routes(),
        mtu: MtuState::default(),
        replay_limits: ReplayLimits::default(),
        upload_queue_limits: QueueLimits::default(),
        download_queue_limits: QueueLimits::default(),
        diagnostic_router_ipv4: Ipv4Addr::new(100, 64, 0, 1),
    })
    .unwrap();
    EdgePacketAdapter::new(EdgeTunPump::new(engine, PumpQueueLimits::default(), 10).unwrap())
}

fn packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&packet).unwrap();
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn active_tunnel() -> IpTunnelConnection {
    let features = FeatureSet::from_bits(
        FeatureSet::CLOUD_GRANT_V1 | FeatureSet::DATAGRAM | FeatureSet::IP_PACKET_TUNNEL_V1,
    );
    let mut tunnel =
        IpTunnelConnection::new(IpTunnelConnectionRole::Client, features, features).unwrap();
    let open = OpenIpTunnel {
        tunnel_id: 7,
        attachment_id: attachment(1),
        attachment_epoch: 1,
        site_id: SiteId([3; 16]),
        segment_id: domain().segment_id,
        site_projection: PolicyRefV1 {
            policy_id: PolicyId([4; 16]),
            generation: 9,
            content_hash: [5; 32],
        },
        segment_generation: 9,
        segment_content_hash: [6; 32],
        requested_inner_mtu: 1180,
        packet_format_version: IP_PACKET_FORMAT_V1,
    };
    tunnel
        .begin_client_open(
            ClientTunnelPrerequisites {
                grant_and_device_proof_authenticated: true,
                signed_policy_verified: true,
                underlay_exclusions_locked: true,
                local_preflight_passed: true,
            },
            &open,
        )
        .unwrap();
    tunnel
        .apply_client_result(&IpTunnelResult {
            tunnel_id: 7,
            accepted: true,
            error_code: codes::OK,
            effective_inner_mtu: 1180,
            accepted_segment_generation: 9,
            attachment_epoch: 1,
        })
        .unwrap();
    tunnel
}

#[tokio::test(flavor = "multi_thread")]
async fn active_edge_lane_moves_packet_records_between_fd_and_quic() {
    let quic = carrier_transport::local_quic_pair().await.unwrap();
    let (lane_fd, peer_fd) = UnixDatagram::pair().unwrap();
    peer_fd.set_nonblocking(true).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer_fd).unwrap();
    let (control_send, control_receive) = tokio::sync::mpsc::channel(8);
    let lane = ActivePacketLane::edge(
        TunPacketFd::new(OwnedFd::from(lane_fd)).unwrap(),
        quic.client.clone(),
        active_tunnel(),
        edge_adapter(),
        control_receive,
    )
    .unwrap();
    let task = tokio::spawn(lane.run());

    let outbound = packet([10, 1, 0, 10], [10, 2, 0, 10]);
    peer.send(&outbound).await.unwrap();
    let encoded = tokio::time::timeout(Duration::from_secs(2), quic.server.read_datagram())
        .await
        .unwrap()
        .unwrap();
    let record = PacketRecord::decode(&encoded).unwrap();
    assert_eq!(record.tunnel_id(), 7);
    assert_eq!(record.source_attachment_id(), attachment(1));
    assert_eq!(record.packet_sequence(), 10);
    assert_eq!(record.packet(), outbound);

    let inbound = packet([10, 2, 0, 10], [10, 1, 0, 10]);
    let record = PacketRecord::new(7, attachment(2), 1, 0, inbound.clone()).unwrap();
    quic.server
        .send_datagram_wait(Bytes::from(record.encode().unwrap()))
        .await
        .unwrap();
    let mut received = [0_u8; 1401];
    let bytes = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..bytes], inbound);

    control_send
        .send(ControlMessage::IpTunnelMtuUpdate(IpTunnelMtuUpdate {
            tunnel_id: 7,
            update_sequence: 1,
            effective_inner_mtu: 1100,
            reason_code: codes::MTU_REDUCED,
        }))
        .await
        .unwrap();
    control_send
        .send(ControlMessage::CloseIpTunnel(CloseIpTunnel {
            tunnel_id: 7,
            reason_code: codes::OK,
        }))
        .await
        .unwrap();
    let counters = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(counters.tun_packets_read, 1);
    assert_eq!(counters.transport_packets_sent, 1);
    assert_eq!(counters.transport_packets_received, 1);
    assert_eq!(counters.tun_packets_written, 1);
    assert_eq!(counters.backpressure_drops, 0);
    assert_eq!(counters.policy_drops, 0);
}
