use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, LeaseOwner, NetdOperation, NetdRequest, NetdResponse,
    PrepareDeclaration, ResponseBody, RouteDeclaration, RouteKind, UnderlayExclusion, UnderlayKind,
    CANDY_TABLE_MIN,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorDocument {
    schema: String,
    prepare_request_hex: String,
    prepared_response_hex: String,
    notes: String,
}

fn prefix(network: [u8; 4], prefix_len: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(network, prefix_len).unwrap()
}

#[test]
fn frozen_netd_vectors_match_canonical_codec() {
    let vector: VectorDocument =
        serde_json::from_str(include_str!("../../../interop/vectors/candy-netd-v1.json")).unwrap();
    assert_eq!(vector.schema, "candy-netd-v1");
    assert!(!vector.notes.is_empty());
    let request = NetdRequest {
        request_id: 9,
        owner: LeaseOwner {
            instance_id: [1; 16],
            pid: 4242,
            generation: 7,
            lease_deadline_mono_ms: 50_000,
        },
        operation: NetdOperation::Prepare(PrepareDeclaration {
            table_id: CANDY_TABLE_MIN,
            overlay_router_ipv4: [100, 64, 0, 10],
            effective_mtu: 1180,
            routes: vec![
                RouteDeclaration {
                    prefix: prefix([10, 1, 0, 0], 16),
                    kind: RouteKind::Local,
                },
                RouteDeclaration {
                    prefix: prefix([10, 2, 0, 0], 16),
                    kind: RouteKind::Remote,
                },
            ],
            exclusions: vec![
                UnderlayExclusion {
                    prefix: prefix([192, 0, 2, 10], 32),
                    kind: UnderlayKind::CloudApi,
                },
                UnderlayExclusion {
                    prefix: prefix([198, 51, 100, 20], 32),
                    kind: UnderlayKind::HubEndpoint,
                },
            ],
            firewall: FirewallPolicy {
                allow_forward: true,
                clamp_tcp_mss: true,
                require_ipv4_forwarding: true,
                manage_rp_filter: true,
            },
        }),
    };
    let response = NetdResponse {
        request_id: 9,
        body: ResponseBody::Prepared {
            generation: 7,
            tun_fd_attached: true,
        },
    };
    assert_eq!(hex(&request.encode().unwrap()), vector.prepare_request_hex);
    assert_eq!(
        hex(&response.encode().unwrap()),
        vector.prepared_response_hex
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
