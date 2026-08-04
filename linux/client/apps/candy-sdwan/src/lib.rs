#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use candy_core::{CompiledRules, LaneMode, PerformanceMode, UdpRedundancyPolicy};
use candy_netd_client::NetdClient;
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix as NetdIpv4Prefix, LeaseOwner, UnderlayExclusion, UnderlayKind,
};
use candy_proto::fabric_contract::FabricSegmentRefV1;
use candy_proto::ids::KeyId;
use candy_proto::ip_tunnel::{OpenIpTunnel, SegmentId, IP_PACKET_FORMAT_V1};
use candy_proto::route_contract::SignedRouteEnvelopeV1;
use candy_runtime_linux::epoch_store::FileEpochStore;
use candy_runtime_linux::tun_netd::{
    run_opened_committed_edge_packet_lane, VerifiedNetdDeclaration,
};
use candy_tun::control::{RouteTrustStore, VerifiedSiteProjection};
use candy_tun::{
    EdgeEngine, EdgeEngineConfig, EdgeTunPump, EpochStore, MtuState, PacketContext,
    PumpQueueLimits, QueueLimits, ReplayLimits, RouteDomainId,
};
use carrier_client::{
    connect_authenticated_tunnel_control, empty_dns_route_bindings, new_sdwan_tunnel_connection,
    CandyClientAuthProfile, ClientConfig,
};
use carrier_runtime::hub_identity::{
    identity_exporter, verify_hub_identity_proof, HubIdentityProofInput,
};
use carrier_runtime::ip_tunnel::ClientTunnelPrerequisites;
use carrier_runtime::tun::EdgePacketAdapter;
use carrier_runtime::tun_control::{
    open_client_tunnel_control, open_client_tunnel_control_with_hub_identity,
};
use carrier_runtime::{cloud_auth::normalize_cloud_device_id, ClientCredentials};
use carrier_transport::config::{CandyTransportProfile, ClientPlatform};
use carrier_transport::telemetry::TelemetryCounters;
use carrier_transport::{parse_sha256_hex, ServerIdentity, TransportSecurityProfile};
use ed25519_dalek::VerifyingKey;
use rand::RngCore;
use std::fs::OpenOptions;
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_SIGNED_OBJECT_BYTES: usize = 1024 * 1024;
const MAX_GRANT_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdwanConfig {
    pub server: String,
    pub server_name: String,
    pub server_pin_sha256: String,
    pub device_id: String,
    pub grant_envelope_path: PathBuf,
    pub device_signing_key_path: PathBuf,
    pub projection_path: PathBuf,
    pub route_signing_key_id: String,
    pub route_signing_public_key: String,
    pub netd_socket: PathBuf,
    pub epoch_file: PathBuf,
    pub table_id: u32,
    #[serde(default = "default_mtu")]
    pub requested_inner_mtu: u16,
    pub underlay_exclusions: Vec<FileUnderlayExclusion>,
    #[serde(default)]
    pub hub_identity: HubIdentityConfig,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileUnderlayExclusion {
    pub kind: String,
    pub prefix: String,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubIdentityConfig {
    #[serde(default)]
    pub enabled: bool,
    pub cloud_signing_public_key: Option<String>,
}

fn default_mtu() -> u16 {
    candy_proto::ip_tunnel::IPV4_DEFAULT_INNER_MTU
}

pub fn load_config(path: &Path) -> Result<SdwanConfig> {
    let raw = read_regular_file(path, MAX_CONFIG_BYTES, false)?;
    let config: SdwanConfig = toml::from_str(std::str::from_utf8(&raw)?)?;
    config.validate()?;
    Ok(config)
}

impl SdwanConfig {
    fn validate(&self) -> Result<()> {
        self.server.parse::<std::net::SocketAddr>()?;
        anyhow::ensure!(
            !self.server_name.trim().is_empty(),
            "server_name is required"
        );
        parse_sha256_hex(self.server_pin_sha256.trim())?;
        carrier_runtime::cloud_auth::normalize_cloud_device_id(&KeyId::new(&self.device_id))?;
        anyhow::ensure!(
            (candy_proto::ip_tunnel::IPV4_MIN_INNER_MTU
                ..=candy_proto::ip_tunnel::IPV4_MAX_INNER_MTU)
                .contains(&self.requested_inner_mtu),
            "requested_inner_mtu is outside the IPv4 packet lane range"
        );
        anyhow::ensure!(
            (candy_netd_proto::CANDY_TABLE_MIN..=candy_netd_proto::CANDY_TABLE_MAX)
                .contains(&self.table_id),
            "table_id is outside the Candy-owned range"
        );
        anyhow::ensure!(
            !self.route_signing_key_id.is_empty() && self.route_signing_key_id.len() <= 256,
            "route_signing_key_id is invalid"
        );
        decode_key(&self.route_signing_public_key)?;
        if self.hub_identity.enabled {
            decode_key(
                self.hub_identity
                    .cloud_signing_public_key
                    .as_deref()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "hub_identity.cloud_signing_public_key is required when enabled"
                        )
                    })?,
            )?;
        } else {
            anyhow::ensure!(
                self.hub_identity.cloud_signing_public_key.is_none(),
                "hub_identity.cloud_signing_public_key requires hub_identity.enabled = true"
            );
        }
        let exclusions = self.exclusions()?;
        for required in [
            UnderlayKind::CloudApi,
            UnderlayKind::HubEndpoint,
            UnderlayKind::Management,
        ] {
            anyhow::ensure!(
                exclusions.iter().any(|value| value.kind == required),
                "all Cloud API, Hub endpoint, and management exclusions are required"
            );
        }
        Ok(())
    }

    fn exclusions(&self) -> Result<Vec<UnderlayExclusion>> {
        self.underlay_exclusions
            .iter()
            .map(|value| {
                let kind = match value.kind.as_str() {
                    "cloud-api" => UnderlayKind::CloudApi,
                    "hub-endpoint" => UnderlayKind::HubEndpoint,
                    "management" => UnderlayKind::Management,
                    _ => anyhow::bail!("unknown underlay exclusion kind"),
                };
                let (network, prefix_len) = value
                    .prefix
                    .split_once('/')
                    .ok_or_else(|| anyhow::anyhow!("underlay exclusion must use IPv4 CIDR"))?;
                Ok(UnderlayExclusion {
                    kind,
                    prefix: NetdIpv4Prefix::new(
                        network.parse::<Ipv4Addr>()?.octets(),
                        prefix_len.parse()?,
                    )?,
                })
            })
            .collect()
    }
}

pub async fn run(config: SdwanConfig) -> Result<()> {
    run_inner(config, true).await
}

async fn run_inner(config: SdwanConfig, _enforce_unprivileged: bool) -> Result<()> {
    config.validate()?;
    #[cfg(target_os = "linux")]
    if _enforce_unprivileged {
        anyhow::ensure!(
            !nix::unistd::Uid::effective().is_root(),
            "candy-sdwan must run unprivileged"
        );
    }
    let projection = load_projection(&config)?;
    validate_projection_freshness(&projection)?;
    let object = projection.object();
    let domain = RouteDomainId {
        tenant_id: object.tenant_id.0,
        segment_id: object.segment_id,
    };
    let mut epoch_store = FileEpochStore::new(config.epoch_file.clone(), domain)
        .map_err(|error| anyhow::anyhow!("open epoch store: {error}"))?;
    let previous_epoch = epoch_store
        .load(domain)
        .map_err(|error| anyhow::anyhow!("load attachment epoch: {error}"))?;
    let attachment_epoch = previous_epoch
        .checked_add(1)
        .filter(|value| *value >= object.epoch_floor)
        .ok_or_else(|| anyhow::anyhow!("signed attachment epoch floor cannot be satisfied"))?;
    epoch_store
        .store(domain, attachment_epoch)
        .map_err(|error| anyhow::anyhow!("persist attachment epoch: {error}"))?;

    let grant_envelope = read_regular_file(&config.grant_envelope_path, MAX_GRANT_BYTES, true)?;
    let device_key = read_regular_file(&config.device_signing_key_path, 32, true)?;
    let device_signing_key: [u8; 32] = device_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("device signing key must be exactly 32 bytes"))?;
    let client = build_client_config(&config, grant_envelope, device_signing_key)?;
    let handoff = connect_authenticated_tunnel_control(&client).await?;
    let negotiated = handoff.negotiated_features();
    let authorized = handoff.authorized_features();
    let tunnel = new_sdwan_tunnel_connection(negotiated, authorized)?;
    let mut tunnel_id_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut tunnel_id_bytes);
    let tunnel_id = u64::from_be_bytes(tunnel_id_bytes).max(1);
    let open = OpenIpTunnel {
        tunnel_id,
        attachment_id: object.attachment_id,
        attachment_epoch,
        site_id: object.site_id,
        segment_id: object.segment_id,
        site_projection: projection.policy_ref(),
        segment_generation: object.segment_generation,
        segment_content_hash: object.segment_content_hash,
        requested_inner_mtu: config.requested_inner_mtu,
        packet_format_version: IP_PACKET_FORMAT_V1,
    };
    let prerequisites = ClientTunnelPrerequisites {
        grant_and_device_proof_authenticated: true,
        signed_policy_verified: true,
        underlay_exclusions_locked: true,
        local_preflight_passed: true,
    };
    let opened = if config.hub_identity.enabled {
        let protocol_version = handoff.protocol_version();
        let client_nonce = *handoff.client_nonce();
        let server_nonce = *handoff.server_nonce();
        let tls_exporter = identity_exporter(handoff.connection())?;
        let client_key_id = normalize_cloud_device_id(&KeyId::new(&config.device_id))?;
        let cloud_signing_public_key = decode_key(
            config
                .hub_identity
                .cloud_signing_public_key
                .as_deref()
                .expect("validated Hub identity key"),
        )?;
        let open_for_verification = open.clone();
        let (endpoint, connection, send, recv, reader, _, _, control_padding) =
            handoff.into_parts();
        let (opened, proof) = open_client_tunnel_control_with_hub_identity(
            connection,
            send,
            recv,
            reader,
            tunnel,
            prerequisites,
            open,
            authorized,
            control_padding,
            Arc::new(TelemetryCounters::default()),
        )
        .await?;
        let object = projection.object();
        let expected_segment = FabricSegmentRefV1 {
            segment_id: SegmentId(object.segment_id.0),
            generation: object.segment_generation,
            content_hash: object.segment_content_hash,
        };
        verify_hub_identity_proof(HubIdentityProofInput {
            proof: &proof,
            cloud_signing_public_key: &cloud_signing_public_key,
            protocol_version,
            client_nonce: &client_nonce,
            server_nonce: &server_nonce,
            accepted_features: negotiated,
            tls_exporter: &tls_exporter,
            client_key_id: &client_key_id,
            open: &open_for_verification,
            expected_tenant: object.tenant_id,
            expected_segment,
            allowed_hub_nodes: &object.allowed_hub_nodes,
            now_unix_seconds: carrier_runtime::cloud_auth::unix_time_seconds()?,
        })
        .map_err(|error| anyhow::anyhow!("Hub identity verification failed: {error}"))?;
        let _ = endpoint;
        opened
    } else {
        let (_endpoint, connection, send, recv, reader, _, _, control_padding) =
            handoff.into_parts();
        open_client_tunnel_control(
            connection,
            send,
            recv,
            reader,
            tunnel,
            prerequisites,
            open,
            authorized,
            control_padding,
            Arc::new(TelemetryCounters::default()),
        )
        .await?
    };
    let effective_mtu = opened
        .tunnel()
        .effective_inner_mtu()
        .ok_or_else(|| anyhow::anyhow!("accepted tunnel has no effective MTU"))?;
    let verified = VerifiedNetdDeclaration::from_site_projection(
        &projection,
        config.table_id,
        effective_mtu,
        config.exclusions()?,
        FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    )?;
    let adapter = edge_adapter(&projection, tunnel_id, attachment_epoch, effective_mtu)?;
    let mut instance_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut instance_id);
    anyhow::ensure!(
        instance_id != [0; 16],
        "failed to create netd owner identity"
    );
    run_opened_committed_edge_packet_lane(
        NetdClient::new(
            &config.netd_socket,
            LeaseOwner {
                instance_id,
                pid: std::process::id(),
                generation: attachment_epoch,
                lease_deadline_mono_ms: u64::MAX,
            },
        ),
        verified,
        opened,
        adapter,
    )
    .await?;
    Ok(())
}

fn build_client_config(
    config: &SdwanConfig,
    grant_envelope: Vec<u8>,
    device_signing_key: [u8; 32],
) -> Result<ClientConfig> {
    Ok(ClientConfig {
        server: config.server.parse()?,
        server_name: config.server_name.clone(),
        active_node_name: None,
        server_identity: ServerIdentity::PinnedSha256(parse_sha256_hex(
            config.server_pin_sha256.trim(),
        )?),
        ech: None,
        credentials: ClientCredentials {
            key_id: KeyId::new(&config.device_id),
            secret: Vec::new(),
        },
        authentication: CandyClientAuthProfile::CloudGrantV1 {
            grant_envelope,
            device_signing_key,
        },
        rules: CompiledRules::default(),
        dns_route_bindings: empty_dns_route_bindings(),
        performance_mode: PerformanceMode::Auto,
        lane_mode: LaneMode::Auto,
        udp_redundancy: UdpRedundancyPolicy::new(1, 1),
        security: TransportSecurityProfile::default(),
        transport: CandyTransportProfile::for_client(ClientPlatform::Linux),
        forwards: Vec::new(),
        transparent_tcp: Vec::new(),
        transparent_udp: Vec::new(),
    })
}

fn load_projection(config: &SdwanConfig) -> Result<VerifiedSiteProjection> {
    let raw = read_regular_file(&config.projection_path, MAX_SIGNED_OBJECT_BYTES, false)?;
    let envelope = SignedRouteEnvelopeV1::decode(&raw)?;
    let key = VerifyingKey::from_bytes(&decode_key(&config.route_signing_public_key)?)?;
    let trust = RouteTrustStore::new([(config.route_signing_key_id.as_bytes().to_vec(), key)])?;
    VerifiedSiteProjection::verify(&envelope, &trust).map_err(anyhow::Error::new)
}

fn validate_projection_freshness(projection: &VerifiedSiteProjection) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let object = projection.object();
    anyhow::ensure!(
        now >= object.not_before && now <= object.expires_at,
        "signed Site projection is outside its validity window"
    );
    Ok(())
}

fn edge_adapter(
    projection: &VerifiedSiteProjection,
    tunnel_id: u64,
    attachment_epoch: u64,
    effective_mtu: u16,
) -> Result<EdgePacketAdapter> {
    let object = projection.object();
    let limits = QueueLimits {
        max_packets: usize::try_from(object.resources.max_queue_packets)?,
        max_bytes: usize::try_from(object.resources.max_queue_bytes)?,
    };
    let replay_window = usize::try_from(object.resources.replay_window_packets)?;
    let engine = EdgeEngine::new(EdgeEngineConfig {
        enabled: true,
        domain: RouteDomainId {
            tenant_id: object.tenant_id.0,
            segment_id: object.segment_id,
        },
        context: PacketContext {
            tunnel_id,
            attachment_id: object.attachment_id,
            attachment_epoch,
        },
        local_prefixes: projection.local_prefixes().clone(),
        remote_routes: projection.remote_routes().clone(),
        mtu: MtuState::new(effective_mtu, effective_mtu, usize::from(effective_mtu), 0)?,
        replay_limits: ReplayLimits {
            max_attachments: 64,
            window: replay_window,
        },
        upload_queue_limits: limits,
        download_queue_limits: limits,
        diagnostic_router_ipv4: Ipv4Addr::from(object.overlay_router_ipv4),
    })?;
    Ok(EdgePacketAdapter::new(EdgeTunPump::new(
        engine,
        PumpQueueLimits::default(),
        0,
    )?))
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    let value = value.trim();
    anyhow::ensure!(
        value.len() == 64,
        "signing public key must be 64 hexadecimal characters"
    );
    let mut decoded = [0u8; 32];
    for (output, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *output = u8::from_str_radix(std::str::from_utf8(pair)?, 16)
            .context("signing public key contains invalid hexadecimal")?;
    }
    Ok(decoded)
}

fn read_regular_file(path: &Path, max_bytes: usize, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "input is not a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= max_bytes as u64,
        "input exceeds its size bound"
    );
    if private {
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "private input permissions are too broad"
        );
        anyhow::ensure!(
            metadata.uid() == nix::unistd::geteuid().as_raw(),
            "private input owner mismatch"
        );
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes as u64 + 1).read_to_end(&mut raw)?;
    anyhow::ensure!(raw.len() <= max_bytes, "input exceeds its size bound");
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use candy_netd_client::{recv_request, send_response};
    use candy_netd_proto::{NetdOperation, NetdResponse, ResponseBody};
    use candy_proto::cloud_grant::{
        AccessGrantPayloadV1, DeviceId, DeviceKeyId, EnvironmentId, GrantId, IssuerId, NodePoolId,
        OperatorScopeType, OrganizationId, PolicyId, ServiceClass, SubscriptionId, TenantId,
    };
    use candy_proto::features::FeatureSet;
    use candy_proto::ip_tunnel::{ipv4_header_checksum, AttachmentId, SegmentId, SiteId};
    use candy_proto::route_contract::{
        AllowedHubNodeV1, AttachmentPrincipalV1, AttachmentState, FailoverPolicyV1, Ipv4PrefixV1,
        NodeId, NodeKeyId, PacketResourcePolicyV1, RemoteRouteV1, SegmentAttachmentV1,
        SegmentRouteSnapshotV1, SegmentRouteV1, SiteRouteProjectionV1,
    };
    use candy_tun::control::{
        HubNodeContext, LastGoodControl, VerifiedControl, VerifiedSegmentSnapshot,
    };
    use candy_tun::PacketRecord;
    use carrier_crypto::cloud_grant::sign_access_grant;
    use carrier_crypto::route_contract::{seal_segment_snapshot, seal_site_projection};
    use carrier_runtime::dataplane::DataplaneQos;
    use carrier_runtime::limits::ResourceLimits;
    use carrier_server::{
        accept_signed_server_tunnel_control, ServerTunnelAuthenticationConfig,
        ServerTunnelAuthenticator,
    };
    use carrier_transport::{CertSource, TransportSecurityProfile};
    use ed25519_dalek::SigningKey;
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixDatagram, UnixListener};
    use std::time::Duration;

    fn valid_config() -> String {
        format!(
            r#"
server = "127.0.0.1:8443"
server_name = "localhost"
server_pin_sha256 = "{}"
device_id = "11111111-1111-1111-1111-111111111111"
grant_envelope_path = "/var/lib/candy/grant.bin"
device_signing_key_path = "/var/lib/candy/device.key"
projection_path = "/var/lib/candy/site.projection"
route_signing_key_id = "route-key-1"
route_signing_public_key = "{}"
netd_socket = "/run/candy/netd.sock"
epoch_file = "/var/lib/candy/epochs/site.epoch"
table_id = 20000
requested_inner_mtu = 1180

[[underlay_exclusions]]
kind = "cloud-api"
prefix = "192.0.2.10/32"

[[underlay_exclusions]]
kind = "hub-endpoint"
prefix = "198.51.100.20/32"

[[underlay_exclusions]]
kind = "management"
prefix = "203.0.113.0/24"
"#,
            "11".repeat(32),
            "22".repeat(32)
        )
    }

    #[test]
    fn config_accepts_only_operational_inputs_and_requires_all_exclusions() {
        let parsed: SdwanConfig = toml::from_str(&valid_config()).unwrap();
        parsed.validate().unwrap();

        let unsigned_route = valid_config() + "\nroute = \"10.0.0.0/8\"\n";
        assert!(toml::from_str::<SdwanConfig>(&unsigned_route).is_err());

        let missing_management = valid_config().replace(
            "\n[[underlay_exclusions]]\nkind = \"management\"\nprefix = \"203.0.113.0/24\"\n",
            "\n",
        );
        let parsed: SdwanConfig = toml::from_str(&missing_management).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn config_rejects_root_table_and_noncanonical_device_identity() {
        let table = valid_config().replace("table_id = 20000", "table_id = 254");
        assert!(toml::from_str::<SdwanConfig>(&table)
            .unwrap()
            .validate()
            .is_err());
        let identity = valid_config().replace("11111111-1111-1111-1111-111111111111", "DEVICE-ONE");
        assert!(toml::from_str::<SdwanConfig>(&identity)
            .unwrap()
            .validate()
            .is_err());
    }

    fn id(value: u8) -> [u8; 16] {
        [value; 16]
    }

    fn prefix(network: [u8; 4], prefix_len: u8) -> Ipv4PrefixV1 {
        Ipv4PrefixV1::new(network, prefix_len).unwrap()
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

    struct Fixture {
        snapshot: VerifiedSegmentSnapshot,
        projection: VerifiedSiteProjection,
        projection_raw: Vec<u8>,
        grant_raw: Vec<u8>,
        cloud_public_key: [u8; 32],
        device_key: [u8; 32],
        route_public_key: [u8; 32],
        hub: HubNodeContext,
    }

    fn fixture(now: u64) -> Fixture {
        let route_key = SigningKey::from_bytes(&[42; 32]);
        let cloud_key = SigningKey::from_bytes(&[43; 32]);
        let device_key = SigningKey::from_bytes(&[44; 32]);
        let route_key_id = b"route-key-1".to_vec();
        let snapshot = SegmentRouteSnapshotV1 {
            tenant_id: TenantId(id(1)),
            segment_id: SegmentId(id(2)),
            segment_generation: 1,
            hub_node_pool_id: NodePoolId(id(3)),
            segment_overlay_prefix: prefix([100, 64, 0, 0], 24),
            attachments: vec![
                SegmentAttachmentV1 {
                    attachment_id: AttachmentId(id(4)),
                    site_id: Some(SiteId(id(5))),
                    principal: AttachmentPrincipalV1::Device {
                        device_id: DeviceId(id(6)),
                        device_key_id: DeviceKeyId(id(7)),
                    },
                    overlay_router_ipv4: [100, 64, 0, 1],
                    local_prefixes: vec![prefix([10, 1, 0, 0], 16)],
                    state: AttachmentState::Active,
                    epoch_floor: 1,
                },
                SegmentAttachmentV1 {
                    attachment_id: AttachmentId(id(8)),
                    site_id: Some(SiteId(id(9))),
                    principal: AttachmentPrincipalV1::Device {
                        device_id: DeviceId(id(10)),
                        device_key_id: DeviceKeyId(id(11)),
                    },
                    overlay_router_ipv4: [100, 64, 0, 2],
                    local_prefixes: vec![prefix([10, 2, 0, 0], 16)],
                    state: AttachmentState::Active,
                    epoch_floor: 1,
                },
                SegmentAttachmentV1 {
                    attachment_id: AttachmentId(id(14)),
                    site_id: None,
                    principal: AttachmentPrincipalV1::Node {
                        node_id: NodeId(id(12)),
                        node_key_id: NodeKeyId(id(13)),
                    },
                    overlay_router_ipv4: [100, 64, 0, 3],
                    local_prefixes: Vec::new(),
                    state: AttachmentState::Active,
                    epoch_floor: 1,
                },
            ],
            routes: vec![
                SegmentRouteV1 {
                    destination_prefix: prefix([10, 1, 0, 0], 16),
                    owner_site_id: Some(SiteId(id(5))),
                    owner_attachment_ids: vec![AttachmentId(id(4))],
                },
                SegmentRouteV1 {
                    destination_prefix: prefix([10, 2, 0, 0], 16),
                    owner_site_id: Some(SiteId(id(9))),
                    owner_attachment_ids: vec![AttachmentId(id(8))],
                },
            ],
            not_before: now - 1,
            expires_at: now + 60,
            stale_until: now + 120,
            previous_hash: [0; 32],
            content_hash: [0; 32],
        };
        let sealed_snapshot =
            seal_segment_snapshot(snapshot, route_key_id.clone(), &route_key).unwrap();
        let projection = SiteRouteProjectionV1 {
            tenant_id: TenantId(id(1)),
            segment_id: SegmentId(id(2)),
            segment_generation: 1,
            segment_content_hash: sealed_snapshot.object.content_hash,
            site_id: SiteId(id(5)),
            attachment_id: AttachmentId(id(4)),
            device_id: DeviceId(id(6)),
            device_key_id: DeviceKeyId(id(7)),
            overlay_router_ipv4: [100, 64, 0, 1],
            local_prefixes: vec![prefix([10, 1, 0, 0], 16)],
            remote_routes: vec![RemoteRouteV1 {
                destination_prefix: prefix([10, 2, 0, 0], 16),
                owner_site_id: SiteId(id(9)),
                owner_attachment_ids: vec![AttachmentId(id(8))],
            }],
            allowed_hub_nodes: vec![AllowedHubNodeV1 {
                node_id: NodeId(id(12)),
                node_key_id: NodeKeyId(id(13)),
                diagnostic_attachment_id: AttachmentId(id(14)),
            }],
            max_inner_mtu: 1300,
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
            not_before: now - 1,
            expires_at: now + 60,
            stale_until: now + 120,
            projection_id: PolicyId(id(15)),
            projection_generation: 1,
            previous_hash: [0; 32],
            content_hash: [0; 32],
        };
        let sealed_projection =
            seal_site_projection(projection, route_key_id.clone(), &route_key).unwrap();
        let trust = RouteTrustStore::new([(route_key_id, route_key.verifying_key())]).unwrap();
        let verified_snapshot =
            VerifiedSegmentSnapshot::verify(&sealed_snapshot.envelope, &trust).unwrap();
        let verified_projection =
            VerifiedSiteProjection::verify(&sealed_projection.envelope, &trust).unwrap();
        let grant = AccessGrantPayloadV1 {
            grant_id: GrantId(id(20)),
            issuer_id: IssuerId(id(21)),
            environment_id: EnvironmentId(id(22)),
            organization_id: OrganizationId(id(23)),
            tenant_id: TenantId(id(1)),
            subscription_id: SubscriptionId(id(24)),
            device_id: DeviceId(id(6)),
            device_key_id: DeviceKeyId(id(7)),
            device_public_key: device_key.verifying_key().to_bytes(),
            assurance_level: 2,
            node_pool_id: NodePoolId(id(3)),
            service_class: ServiceClass::CandyDedicated,
            operator_scope_type: OperatorScopeType::Candy,
            operator_id: None,
            region_ids: Vec::new(),
            allowed_features: FeatureSet::from_bits(
                FeatureSet::DATAGRAM | FeatureSet::IP_PACKET_TUNNEL_V1,
            ),
            service_permissions: 1,
            route_policy: Some(verified_projection.policy_ref()),
            dns_policy: None,
            max_outer_connections_per_node: 2,
            max_outer_connections_per_pool: 4,
            max_active_sessions_per_connection: 128,
            max_udp_flows_per_connection: 256,
            max_pending_opens: 32,
            max_speculative_streams: 8,
            max_datagram_record: 1400,
            upload_rate_bps: 10_000_000,
            download_rate_bps: 10_000_000,
            issued_at: now - 1,
            not_before: now - 1,
            refresh_after: now + 30,
            expires_at: now + 60,
            policy_generation: 1,
            entitlement_generation: 1,
        };
        let envelope =
            sign_access_grant(grant.encode().unwrap(), b"cloud-key".to_vec(), &cloud_key).unwrap();
        Fixture {
            snapshot: verified_snapshot,
            projection: verified_projection,
            projection_raw: sealed_projection.envelope.encode().unwrap(),
            grant_raw: envelope.encode().unwrap(),
            cloud_public_key: cloud_key.verifying_key().to_bytes(),
            device_key: device_key.to_bytes(),
            route_public_key: route_key.verifying_key().to_bytes(),
            hub: HubNodeContext {
                tenant_id: TenantId(id(1)),
                node_id: NodeId(id(12)),
                node_key_id: NodeKeyId(id(13)),
                node_pool_id: NodePoolId(id(3)),
                service_class: ServiceClass::CandyDedicated,
            },
        }
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        std::io::Write::write_all(&mut file, bytes).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn linux_edge_app_runs_real_quic_netd_fd_and_bidirectional_packet_lane() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let fixture = fixture(now);
        let root =
            std::env::temp_dir().join(format!("candy-sdwan-e2e-{}-{}", std::process::id(), now));
        fs::create_dir(&root).unwrap();
        let grant_path = root.join("grant.bin");
        let device_key_path = root.join("device.key");
        let projection_path = root.join("site.projection");
        let epoch_file = root.join("site.epoch");
        let netd_socket = root.join("netd.sock");
        write_private(&grant_path, &fixture.grant_raw);
        write_private(&device_key_path, &fixture.device_key);
        fs::write(&projection_path, &fixture.projection_raw).unwrap();

        let endpoint = carrier_transport::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            CertSource::Generated,
        )
        .unwrap();
        let server_addr = endpoint.endpoint.local_addr().unwrap();
        let server_pin = endpoint.cert_sha256;
        let authenticator = ServerTunnelAuthenticator::new(ServerTunnelAuthenticationConfig {
            cloud_signing_public_key: fixture.cloud_public_key,
            limits: ResourceLimits::default(),
            qos: DataplaneQos::default(),
            security: TransportSecurityProfile::default(),
            auth_timeout: Duration::from_secs(2),
            stream_priority_enabled: false,
        })
        .unwrap();
        let control = LastGoodControl::new(
            VerifiedControl::new(fixture.snapshot, fixture.projection.clone()).unwrap(),
            now,
        )
        .unwrap();
        let hub = fixture.hub;
        let server_endpoint = endpoint.endpoint.clone();
        let server = tokio::spawn(async move {
            let handoff = authenticator
                .accept(server_endpoint.accept().await.unwrap())
                .await?;
            let opened = accept_signed_server_tunnel_control(
                handoff,
                &control,
                hub,
                now,
                Arc::new(TelemetryCounters::default()),
            )
            .await?;
            let (connection, _tunnel, _peer_control, owner) = opened.into_parts();
            let outbound = connection.read_datagram().await?;
            let record = PacketRecord::decode(&outbound)?;
            assert_eq!(record.packet()[8], 64);
            let inbound = PacketRecord::new(
                record.tunnel_id(),
                AttachmentId(id(8)),
                1,
                1,
                packet([10, 2, 0, 10], [10, 1, 0, 10]),
            )?;
            connection.send_datagram(inbound.encode()?.into())?;
            tokio::time::sleep(Duration::from_millis(50)).await;
            owner.shutdown().await;
            Ok::<_, anyhow::Error>(())
        });

        let listener = UnixListener::bind(&netd_socket).unwrap();
        let (lane_fd, peer_fd) = UnixDatagram::pair().unwrap();
        let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
        let netd = std::thread::spawn(move || {
            let mut committed_tx = Some(committed_tx);
            for expected in 1..=3 {
                let (stream, _) = listener.accept().unwrap();
                let request = recv_request(&stream).unwrap();
                assert_eq!(request.request_id, expected);
                let (body, descriptor): (ResponseBody, Option<&UnixDatagram>) = match request
                    .operation
                {
                    NetdOperation::Prepare(declaration) => {
                        assert_eq!(declaration.routes.len(), 2);
                        (
                            ResponseBody::Prepared {
                                generation: 1,
                                tun_fd_attached: true,
                            },
                            Some(&lane_fd),
                        )
                    }
                    NetdOperation::Commit => {
                        let _ = committed_tx.take().unwrap().send(());
                        (ResponseBody::Committed { generation: 1 }, None)
                    }
                    NetdOperation::Rollback => (ResponseBody::RolledBack { generation: 1 }, None),
                    other => panic!("unexpected netd operation: {other:?}"),
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

        let config = SdwanConfig {
            server: server_addr.to_string(),
            server_name: "localhost".into(),
            server_pin_sha256: carrier_transport::cert_sha256_hex(&server_pin),
            device_id: "06060606-0606-0606-0606-060606060606".into(),
            grant_envelope_path: grant_path,
            device_signing_key_path: device_key_path,
            projection_path,
            route_signing_key_id: "route-key-1".into(),
            route_signing_public_key: fixture
                .route_public_key
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            netd_socket,
            epoch_file,
            table_id: candy_netd_proto::CANDY_TABLE_MIN,
            requested_inner_mtu: 1180,
            underlay_exclusions: vec![
                FileUnderlayExclusion {
                    kind: "cloud-api".into(),
                    prefix: "192.0.2.10/32".into(),
                },
                FileUnderlayExclusion {
                    kind: "hub-endpoint".into(),
                    prefix: "198.51.100.20/32".into(),
                },
                FileUnderlayExclusion {
                    kind: "management".into(),
                    prefix: "203.0.113.0/24".into(),
                },
            ],
            hub_identity: HubIdentityConfig::default(),
        };
        let app = tokio::spawn(run_inner(config, false));
        committed_rx.await.unwrap();
        peer_fd
            .send(&packet([10, 1, 0, 10], [10, 2, 0, 10]))
            .unwrap();
        peer_fd.set_nonblocking(true).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer_fd).unwrap();
        let mut received = [0u8; 128];
        let bytes = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[..bytes], packet([10, 2, 0, 10], [10, 1, 0, 10]));
        server.await.unwrap().unwrap();
        let app_result = app.await.unwrap();
        assert!(
            app_result.is_err(),
            "peer shutdown must surface from the lane"
        );
        netd.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
