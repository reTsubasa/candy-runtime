use candy_netd::{LinuxNetworkPlan, CANDY_POLICY_PRIORITY_MIN};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, PrepareDeclaration, RouteDeclaration, RouteKind, UnderlayExclusion,
    UnderlayKind, CANDY_INTERFACE_NAME, CANDY_TABLE_MIN,
};

#[test]
fn linux_plan_installs_only_signed_remote_routes_with_fixed_owned_names() {
    let local = Ipv4Prefix::new([10, 1, 0, 0], 16).unwrap();
    let remote = Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap();
    let exclusion = UnderlayExclusion {
        prefix: Ipv4Prefix::new([192, 0, 2, 10], 32).unwrap(),
        kind: UnderlayKind::HubEndpoint,
    };
    let declaration = PrepareDeclaration {
        table_id: CANDY_TABLE_MIN,
        overlay_router_ipv4: [100, 64, 0, 10],
        effective_mtu: 1180,
        routes: vec![
            RouteDeclaration {
                prefix: local,
                kind: RouteKind::Local,
            },
            RouteDeclaration {
                prefix: remote,
                kind: RouteKind::Remote,
            },
        ],
        exclusions: vec![exclusion],
        firewall: FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    };
    let plan = LinuxNetworkPlan::compile(&declaration).unwrap();
    assert_eq!(plan.interface_name, CANDY_INTERFACE_NAME);
    assert_eq!(plan.route_table, CANDY_TABLE_MIN);
    assert_eq!(plan.policy_priority, CANDY_POLICY_PRIORITY_MIN);
    assert_eq!(plan.remote_routes, vec![remote]);
    assert_eq!(plan.exclusions, vec![exclusion]);
    assert_eq!(plan.nft_table_name, "candy_sdwan_20000");
    assert_eq!(plan.route_mtu, 1180);
    assert_eq!(plan.tcp_advmss, 1140);
}
