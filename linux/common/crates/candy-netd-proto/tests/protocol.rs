use candy_netd_proto::{
    ErrorCode, FirewallPolicy, Ipv4Prefix, LeaseOwner, NetdOperation, NetdRequest, NetdResponse,
    NetdSession, NetdSessionError, PrepareDeclaration, ResponseBody, RouteDeclaration, RouteKind,
    UnderlayExclusion, UnderlayKind, CANDY_INTERFACE_NAME, CANDY_TABLE_MAX, CANDY_TABLE_MIN,
    NETD_PROTOCOL_VERSION,
};

fn prefix(network: [u8; 4], prefix_len: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(network, prefix_len).unwrap()
}

fn owner() -> LeaseOwner {
    LeaseOwner {
        instance_id: [1; 16],
        pid: 4242,
        generation: 7,
        lease_deadline_mono_ms: 50_000,
    }
}

fn declaration() -> PrepareDeclaration {
    PrepareDeclaration {
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
    }
}

#[test]
fn request_and_response_round_trip_canonically() {
    assert_eq!(CANDY_INTERFACE_NAME, "candy0");
    assert_eq!(NETD_PROTOCOL_VERSION, 1);
    let request = NetdRequest {
        request_id: 9,
        owner: owner(),
        operation: NetdOperation::Prepare(declaration()),
    };
    let encoded = request.encode().unwrap();
    assert_eq!(NetdRequest::decode(&encoded).unwrap(), request);
    assert_eq!(
        NetdRequest::decode(&encoded).unwrap().encode().unwrap(),
        encoded
    );

    let response = NetdResponse {
        request_id: 9,
        body: ResponseBody::Prepared {
            generation: 7,
            tun_fd_attached: true,
        },
    };
    let encoded = response.encode().unwrap();
    assert_eq!(NetdResponse::decode(&encoded).unwrap(), response);
}

#[test]
fn declaration_rejects_arbitrary_interface_default_noncanonical_and_table_ids() {
    assert!(Ipv4Prefix::new([0, 0, 0, 0], 0).is_err());
    assert!(Ipv4Prefix::new([10, 1, 0, 1], 24).is_err());

    let mut value = declaration();
    value.table_id = CANDY_TABLE_MIN - 1;
    assert!(value.validate().is_err());
    value.table_id = CANDY_TABLE_MAX + 1;
    assert!(value.validate().is_err());

    let mut value = declaration();
    value.effective_mtu = 1401;
    assert!(value.validate().is_err());
}

#[test]
fn declaration_rejects_duplicates_overlap_and_unbounded_lists() {
    let mut value = declaration();
    value.routes.push(value.routes[0]);
    assert!(value.validate().is_err());

    let mut value = declaration();
    value.routes[1].prefix = prefix([10, 1, 128, 0], 17);
    assert!(value.validate().is_err());

    let mut value = declaration();
    value.exclusions.push(value.exclusions[0]);
    assert!(value.validate().is_err());
}

#[test]
fn decoder_rejects_noncanonical_unknown_trailing_and_oversized_frames() {
    let request = NetdRequest {
        request_id: 9,
        owner: owner(),
        operation: NetdOperation::Status,
    };
    let encoded = request.encode().unwrap();
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(NetdRequest::decode(&trailing).is_err());

    let mut unknown = encoded.clone();
    unknown[1] = 99;
    assert!(NetdRequest::decode(&unknown).is_err());

    let mut noncanonical = encoded;
    noncanonical.splice(2..3, [0x89, 0x00]);
    assert!(NetdRequest::decode(&noncanonical).is_err());
    assert!(NetdRequest::decode(&vec![0; 70 * 1024]).is_err());
}

#[test]
fn lifecycle_is_two_phase_idempotent_and_generation_bound() {
    let prepare = NetdRequest {
        request_id: 1,
        owner: owner(),
        operation: NetdOperation::Prepare(declaration()),
    };
    let commit = NetdRequest {
        request_id: 2,
        owner: owner(),
        operation: NetdOperation::Commit,
    };
    let rollback = NetdRequest {
        request_id: 3,
        owner: owner(),
        operation: NetdOperation::Rollback,
    };
    let mut session = NetdSession::new();
    assert!(session.apply(&prepare).is_ok());
    assert!(session.apply(&prepare).is_ok());
    assert!(session.apply(&commit).is_ok());
    assert!(session.apply(&commit).is_ok());
    assert!(session.apply(&rollback).is_ok());

    let mut replacement = prepare.clone();
    replacement.owner.pid += 1;
    assert!(session.apply(&replacement).is_ok());
    let replacement_rollback = NetdRequest {
        request_id: 4,
        owner: replacement.owner,
        operation: NetdOperation::Rollback,
    };
    assert!(session.apply(&replacement_rollback).is_ok());

    let mut divergent = prepare;
    let NetdOperation::Prepare(ref mut declaration) = divergent.operation else {
        unreachable!()
    };
    declaration.effective_mtu = 1200;
    assert_eq!(
        session.apply(&divergent).unwrap_err(),
        NetdSessionError::GenerationConflict
    );

    divergent.owner.generation = 8;
    assert!(session.apply(&divergent).is_ok());
    assert_eq!(session.phase(), candy_netd_proto::SessionPhase::Prepared);
}

#[test]
fn error_codes_are_stable() {
    assert_eq!(ErrorCode::InvalidRequest as u64, 1);
    assert_eq!(ErrorCode::UnauthorizedPeer as u64, 2);
    assert_eq!(ErrorCode::GenerationConflict as u64, 3);
    assert_eq!(ErrorCode::PreflightFailed as u64, 4);
    assert_eq!(ErrorCode::SystemFailure as u64, 5);
}
