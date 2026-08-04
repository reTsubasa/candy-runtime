use anyhow::Result;
use candy_netd_client::NetdClient;
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix as NetdIpv4Prefix, LeaseOwner, UnderlayExclusion, UnderlayKind,
    CANDY_TABLE_MAX, CANDY_TABLE_MIN,
};
use candy_proto::cloud_grant::{NodePoolId, ServiceClass, TenantId};
use candy_proto::features::FeatureSet;
use candy_proto::ids::KeyId;
use candy_proto::ip_tunnel::AttachmentId;
use candy_proto::route_contract::{NodeId, NodeKeyId};
use candy_proto::route_contract::{
    SignedRouteEnvelopeV1, MAX_ROUTE_OBJECT_ENVELOPE_LEN, MAX_ROUTE_SIGNING_KEY_ID_LEN,
};
use candy_runtime_linux::tun_netd::{
    run_opened_committed_attached_hub_packet_lane, VerifiedHubNetdDeclaration,
};
use candy_tun::control::{
    LastGoodControl, LastGoodControlCatalog, RouteTrustStore, VerifiedControl,
    VerifiedDynamicRouteSnapshot, VerifiedFabricAssignment, VerifiedMeshMembership,
    VerifiedSegmentSnapshot, VerifiedSharedHubAdmission, VerifiedSiteProjection,
};
use candy_tun::{
    GeneratedPacketIdentity, HubEngine, HubEngineConfig, HubTunPump, MtuState, PacketContext,
    PumpQueueLimits, QueueLimits, ReplayLimits,
};
use carrier_runtime::dataplane::DataplaneQos;
use carrier_runtime::hub_identity::{validate_hub_identity_signer, HubIdentitySigner};
use carrier_runtime::limits::ResourceLimits;
use carrier_runtime::session_state::HARD_MAX_TOTAL_OPENS;
use carrier_runtime::tun::AttachedHubPacketAdapter;
use carrier_runtime::tun_fabric::{
    TransitAttachmentLane, TransitFabricLane, TransitHubDriverLimits, TransitHubPacketDriver,
};
use carrier_runtime::tun_shared::{
    admit_shared_hub_policy, SharedHubAdmission, SharedTransitCatalogLane,
    SharedTransitDriverLimits, SharedTransitHubDriver, VerifiedSharedTransitDomain,
    VerifiedSharedTransitNodeContext,
};
use carrier_runtime::ServerUser;
use carrier_server::{
    accept_signed_server_tunnel_control, accept_signed_server_tunnel_control_with_hub_identity,
    run_hub_fabric_server, run_sdwan_tunnel_server, CandyServerAuthProfile, ServerAdmissionLimits,
    ServerConfig,
};
use carrier_transport::telemetry::TelemetryCounters;
use carrier_transport::{
    cert_sha256_hex,
    config::{
        CalibrationEvidence, CandyTransportProfile, CongestionChoice, MemoryCalibration, MIB,
    },
    server_endpoints_with_profiles_and_ech, CertSource, ServerEchConfig, TransportSecurityProfile,
};
use rand::RngCore;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

const DEFAULT_TRANSPORT_MEMORY_BUDGET_MIB: u64 = 2048;
const MAX_CALIBRATION_REPORT_BYTES: usize = 1024 * 1024;
const MAX_ECH_CONFIG_BYTES: usize = 65_535;
const ECH_PRIVATE_KEY_BYTES: usize = 32;
const MAX_ECH_KEYS: usize = 8;

pub struct HubSignedPolicyCache {
    last_good: LastGoodControl,
}

impl fmt::Debug for HubSignedPolicyCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HubSignedPolicyCache")
            .field(
                "segment_generation",
                &self.last_good.current().snapshot().generation(),
            )
            .field(
                "projection_generation",
                &self.last_good.current().projection().generation(),
            )
            .finish()
    }
}

impl HubSignedPolicyCache {
    pub fn load_files(
        snapshot_path: &Path,
        projection_path: &Path,
        trust: &RouteTrustStore,
        now: u64,
    ) -> Result<Self> {
        let candidate = load_verified_control(snapshot_path, projection_path, trust)?;
        Ok(Self {
            last_good: LastGoodControl::new(candidate, now)?,
        })
    }

    pub fn reload_files(
        &mut self,
        snapshot_path: &Path,
        projection_path: &Path,
        trust: &RouteTrustStore,
        now: u64,
    ) -> Result<()> {
        self.replace(
            load_verified_control(snapshot_path, projection_path, trust)?,
            now,
        )
    }

    pub fn replace(&mut self, candidate: VerifiedControl, now: u64) -> Result<()> {
        self.last_good.replace(candidate, now)?;
        Ok(())
    }

    pub fn current(&self) -> &LastGoodControl {
        &self.last_good
    }

    pub fn snapshot(&self) -> LastGoodControl {
        self.last_good.clone()
    }
}

pub fn load_signed_policy_candidate(
    snapshot_path: &Path,
    projection_path: &Path,
    trust: &RouteTrustStore,
) -> Result<VerifiedControl> {
    load_verified_control(snapshot_path, projection_path, trust)
}

fn load_verified_control(
    snapshot_path: &Path,
    projection_path: &Path,
    trust: &RouteTrustStore,
) -> Result<VerifiedControl> {
    let snapshot_raw = read_regular_file(snapshot_path, MAX_ROUTE_OBJECT_ENVELOPE_LEN, false)
        .map_err(|error| anyhow::anyhow!("invalid signed segment snapshot file: {error}"))?;
    let projection_raw =
        read_regular_file(projection_path, MAX_ROUTE_OBJECT_ENVELOPE_LEN, false)
            .map_err(|error| anyhow::anyhow!("invalid signed site projection file: {error}"))?;
    let snapshot_envelope = SignedRouteEnvelopeV1::decode(&snapshot_raw)
        .map_err(|error| anyhow::anyhow!("invalid signed segment snapshot envelope: {error}"))?;
    let projection_envelope = SignedRouteEnvelopeV1::decode(&projection_raw)
        .map_err(|error| anyhow::anyhow!("invalid signed site projection envelope: {error}"))?;
    let snapshot = VerifiedSegmentSnapshot::verify(&snapshot_envelope, trust)?;
    let projection = VerifiedSiteProjection::verify(&projection_envelope, trust)?;
    Ok(VerifiedControl::new(snapshot, projection)?)
}

#[derive(Clone, Default)]
struct VerifiedExpansionPolicies {
    shared_hub: Option<VerifiedSharedHubAdmission>,
    mesh: Option<VerifiedMeshMembership>,
    dynamic_routes: Option<VerifiedDynamicRouteSnapshot>,
}

struct LoadedSharedTransitDomain {
    snapshot: VerifiedSegmentSnapshot,
    admission: VerifiedSharedHubAdmission,
    dynamic_routes: Option<VerifiedDynamicRouteSnapshot>,
    node_attachment_id: AttachmentId,
    node_attachment_epoch: u64,
    effective_mtu: u16,
}

struct LoadedSharedTransitCatalog {
    controls: LastGoodControlCatalog,
    domains: Vec<LoadedSharedTransitDomain>,
}

impl LoadedSharedTransitCatalog {
    fn load(config: &SdwanSharedTransitConfig, now: u64) -> Result<Self> {
        let mut controls = Vec::new();
        let mut domains = Vec::with_capacity(config.domains.len());
        for domain in &config.domains {
            let snapshot = VerifiedSegmentSnapshot::verify(
                &load_signed_envelope(&domain.snapshot_path, "shared Transit Segment snapshot")?,
                &config.trust,
            )?;
            snapshot.require_fresh(now)?;
            let admission = VerifiedSharedHubAdmission::verify(
                &load_signed_envelope(&domain.admission_path, "shared Transit admission")?,
                &config.trust,
            )?;
            admission.require_fresh(now)?;
            let dynamic_routes = domain
                .dynamic_route_path
                .as_deref()
                .map(|path| load_signed_envelope(path, "shared Transit dynamic routes"))
                .transpose()?
                .map(|envelope| {
                    VerifiedDynamicRouteSnapshot::verify(&envelope, &config.trust, &snapshot)
                })
                .transpose()?;
            if let Some(dynamic) = &dynamic_routes {
                dynamic.require_fresh(now)?;
            }
            for projection_path in &domain.projection_paths {
                let projection = VerifiedSiteProjection::verify(
                    &load_signed_envelope(projection_path, "shared Transit Site projection")?,
                    &config.trust,
                )?;
                controls.push(VerifiedControl::new(snapshot.clone(), projection)?);
            }
            domains.push(LoadedSharedTransitDomain {
                snapshot,
                admission,
                dynamic_routes,
                node_attachment_id: domain.node_attachment_id,
                node_attachment_epoch: domain.node_attachment_epoch,
                effective_mtu: domain.effective_mtu,
            });
        }
        Ok(Self {
            controls: LastGoodControlCatalog::new(controls, now)?,
            domains,
        })
    }

    fn runtime_domains(&self) -> Vec<VerifiedSharedTransitDomain<'_>> {
        self.domains
            .iter()
            .map(|domain| VerifiedSharedTransitDomain {
                snapshot: &domain.snapshot,
                dynamic_routes: domain.dynamic_routes.as_ref(),
                admission: &domain.admission,
                node_attachment_id: domain.node_attachment_id,
                node_attachment_epoch: domain.node_attachment_epoch,
                effective_mtu: domain.effective_mtu,
            })
            .collect()
    }
}

impl VerifiedExpansionPolicies {
    fn load(config: &SdwanTunConfig, control: &LastGoodControl) -> Result<Self> {
        let shared_hub = config
            .shared_hub_admission_path
            .as_deref()
            .map(|path| load_signed_envelope(path, "shared Hub admission"))
            .transpose()?
            .map(|envelope| VerifiedSharedHubAdmission::verify(&envelope, &config.trust))
            .transpose()?;
        let mesh = config
            .mesh_membership_path
            .as_deref()
            .map(|path| load_signed_envelope(path, "Mesh membership"))
            .transpose()?
            .map(|envelope| VerifiedMeshMembership::verify(&envelope, &config.trust))
            .transpose()?;
        let dynamic_routes = config
            .dynamic_route_snapshot_path
            .as_deref()
            .map(|path| load_signed_envelope(path, "dynamic route snapshot"))
            .transpose()?
            .map(|envelope| {
                VerifiedDynamicRouteSnapshot::verify(
                    &envelope,
                    &config.trust,
                    control.current().snapshot(),
                )
            })
            .transpose()?;
        Ok(Self {
            shared_hub,
            mesh,
            dynamic_routes,
        })
    }

    fn validate(
        &self,
        config: &SdwanTunConfig,
        control: &LastGoodControl,
        now: u64,
    ) -> Result<Option<SharedHubAdmission>> {
        let snapshot = control.current().snapshot().object();
        let projection = control.current().projection().object();
        let shared_hub = self
            .shared_hub
            .as_ref()
            .map(|verified| {
                verified.require_fresh(now)?;
                Ok::<SharedHubAdmission, anyhow::Error>(admit_shared_hub_policy(
                    verified,
                    config.hub.node_id,
                    config.hub.node_key_id,
                    config.hub.node_pool_id,
                    snapshot.tenant_id.0,
                    snapshot.segment_id,
                    snapshot.segment_generation,
                    snapshot.content_hash,
                    now,
                )?)
            })
            .transpose()?;
        if let Some(mesh) = &self.mesh {
            mesh.require_fresh(now)?;
            let mesh = mesh.object();
            anyhow::ensure!(
                mesh.tenant_id == snapshot.tenant_id
                    && mesh.segment_id == snapshot.segment_id
                    && mesh.segment_generation == snapshot.segment_generation
                    && mesh.segment_content_hash == snapshot.content_hash
                    && mesh.local_site_id == projection.site_id
                    && mesh.local_attachment_id == projection.attachment_id,
                "Mesh membership does not match the applied signed route policy"
            );
        }
        if let Some(dynamic) = &self.dynamic_routes {
            dynamic.require_fresh(now)?;
            anyhow::ensure!(
                dynamic.object().base_segment_generation == snapshot.segment_generation
                    && dynamic.object().base_segment_content_hash == snapshot.content_hash,
                "dynamic route snapshot does not match the applied signed route policy"
            );
        }
        Ok(shared_hub)
    }
}

fn load_signed_envelope(path: &Path, name: &str) -> Result<SignedRouteEnvelopeV1> {
    let raw = read_regular_file(path, MAX_ROUTE_OBJECT_ENVELOPE_LEN, false)
        .map_err(|error| anyhow::anyhow!("invalid signed {name} file: {error}"))?;
    SignedRouteEnvelopeV1::decode(&raw)
        .map_err(|error| anyhow::anyhow!("invalid signed {name} envelope: {error}"))
}

pub struct LoadedServerConfig {
    pub config: ServerConfig,
    pub summary: ServerConfigSummary,
    pub sdwan_tun: Option<SdwanTunConfig>,
    pub sdwan_private_transit: Option<SdwanPrivateTransitConfig>,
    pub sdwan_shared_transit: Option<SdwanSharedTransitConfig>,
}

#[derive(Clone)]
pub struct SdwanTunConfig {
    snapshot_path: PathBuf,
    projection_path: PathBuf,
    shared_hub_admission_path: Option<PathBuf>,
    mesh_membership_path: Option<PathBuf>,
    dynamic_route_snapshot_path: Option<PathBuf>,
    trust: RouteTrustStore,
    hub: candy_tun::control::HubNodeContext,
    node_attachment_id: AttachmentId,
    node_attachment_epoch: u64,
    netd_socket: PathBuf,
    table_id: u32,
    exclusions: Vec<UnderlayExclusion>,
}

#[derive(Clone)]
pub struct SdwanSharedTransitConfig {
    trust: RouteTrustStore,
    node_id: NodeId,
    node_key_id: NodeKeyId,
    node_pool_id: NodePoolId,
    domains: Vec<SdwanSharedTransitDomainConfig>,
}

#[derive(Clone)]
pub struct SdwanPrivateTransitConfig {
    trust: RouteTrustStore,
    snapshot_path: PathBuf,
    projection_paths: Vec<PathBuf>,
    fabric_assignment_path: PathBuf,
    dynamic_route_path: Option<PathBuf>,
    node_id: NodeId,
    node_key_id: NodeKeyId,
    node_pool_id: NodePoolId,
    node_attachment_id: AttachmentId,
    node_attachment_epoch: u64,
    effective_mtu: u16,
    fabric_listen: SocketAddr,
    node_grant_path: PathBuf,
    node_signing_key_path: PathBuf,
}

#[derive(Clone)]
struct SdwanSharedTransitDomainConfig {
    snapshot_path: PathBuf,
    projection_paths: Vec<PathBuf>,
    admission_path: PathBuf,
    dynamic_route_path: Option<PathBuf>,
    node_attachment_id: AttachmentId,
    node_attachment_epoch: u64,
    effective_mtu: u16,
}

impl fmt::Debug for LoadedServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedServerConfig")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, serde::Serialize)]
pub struct ServerConfigSummary {
    pub listen: String,
    pub port_hopping_listens: Vec<String>,
    pub user_count: usize,
    pub auth_profile: String,
    pub cert_source: String,
    pub ech_enabled: bool,
    pub max_sessions_per_connection: usize,
    pub max_udp_flows: usize,
    pub max_datagram_size: usize,
    pub server_udp_multiplier: u8,
    pub accept_client_udp_multiplier_proposal: bool,
    pub client_udp_multiplier: u8,
    pub propose_client_udp_multiplier: bool,
    pub requested_max_connections: usize,
    pub max_connections: usize,
    pub auth_timeout_seconds: u64,
    pub max_connections_per_user: usize,
    pub transport_memory_budget_mib: u64,
    pub transport_requested_connections: usize,
    pub transport_effective_connections: usize,
    pub transport_worst_case_bytes: u64,
    pub transport_profile: CandyTransportProfile,
    pub transport_requested_profile_sha256: String,
    pub transport_profile_sha256: String,
    pub transport_fallback_reason: Option<String>,
    pub sdwan_tun_enabled: bool,
    pub sdwan_private_transit_enabled: bool,
    pub sdwan_shared_transit_enabled: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct PreflightReport {
    pub ok: bool,
    pub listen: String,
    pub cert_sha256: String,
    pub socket_buffers: carrier_transport::UdpSocketBufferInfo,
    pub summary: ServerConfigSummary,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: String,
    cert_pem: Option<String>,
    key_pem: Option<String>,
    #[serde(default)]
    development_ephemeral_certificate: bool,
    #[serde(default)]
    users: Vec<FileUser>,
    #[serde(default)]
    limits: Option<FileLimits>,
    #[serde(default)]
    qos: FileQos,
    #[serde(default)]
    security: FileSecurity,
    #[serde(default)]
    admission: FileAdmission,
    #[serde(default = "default_transport_memory_budget_mib")]
    transport_memory_budget_mib: u64,
    transport_memory_calibration_report: Option<PathBuf>,
    #[serde(default)]
    transport: FileTransport,
    #[serde(default)]
    port_hopping: FilePortHopping,
    ech: Option<FileEch>,
    #[serde(default)]
    cloud_auth: FileCloudAuth,
    sdwan_tun: Option<FileSdwanTun>,
    sdwan_private_transit: Option<FileSdwanPrivateTransit>,
    sdwan_shared_transit: Option<FileSdwanSharedTransit>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSdwanPrivateTransit {
    #[serde(default)]
    enabled: bool,
    route_signing_key_id: Option<String>,
    route_signing_public_key: Option<String>,
    snapshot_file: Option<PathBuf>,
    projection_files: Option<Vec<PathBuf>>,
    fabric_assignment_file: Option<PathBuf>,
    dynamic_route_snapshot_file: Option<PathBuf>,
    node_id: Option<String>,
    node_key_id: Option<String>,
    node_pool_id: Option<String>,
    node_attachment_id: Option<String>,
    node_attachment_epoch: Option<u64>,
    effective_mtu: Option<u16>,
    fabric_listen: Option<String>,
    node_grant_file: Option<PathBuf>,
    node_signing_key_file: Option<PathBuf>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSdwanSharedTransit {
    #[serde(default)]
    enabled: bool,
    route_signing_key_id: Option<String>,
    route_signing_public_key: Option<String>,
    node_id: Option<String>,
    node_key_id: Option<String>,
    node_pool_id: Option<String>,
    #[serde(default)]
    domains: Vec<FileSdwanSharedTransitDomain>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSdwanSharedTransitDomain {
    snapshot_file: PathBuf,
    projection_files: Vec<PathBuf>,
    shared_hub_admission_file: PathBuf,
    dynamic_route_snapshot_file: Option<PathBuf>,
    node_attachment_id: String,
    node_attachment_epoch: u64,
    effective_mtu: u16,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCloudAuth {
    #[serde(default)]
    enabled: bool,
    cloud_signing_public_key: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSdwanTun {
    #[serde(default)]
    enabled: bool,
    snapshot_file: Option<PathBuf>,
    projection_file: Option<PathBuf>,
    shared_hub_admission_file: Option<PathBuf>,
    mesh_membership_file: Option<PathBuf>,
    dynamic_route_snapshot_file: Option<PathBuf>,
    route_signing_key_id: Option<String>,
    route_signing_public_key: Option<String>,
    tenant_id: Option<String>,
    node_id: Option<String>,
    node_key_id: Option<String>,
    node_pool_id: Option<String>,
    node_attachment_id: Option<String>,
    node_attachment_epoch: Option<u64>,
    netd_socket: Option<PathBuf>,
    table_id: Option<u32>,
    #[serde(default)]
    underlay_exclusions: Vec<FileUnderlayExclusion>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUnderlayExclusion {
    kind: FileUnderlayKind,
    prefix: String,
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FileUnderlayKind {
    CloudApi,
    HubEndpoint,
    Management,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEch {
    directory: Option<PathBuf>,
    config_file: Option<PathBuf>,
    private_key_file: Option<PathBuf>,
    #[serde(default = "default_true")]
    retry_config: bool,
}

fn default_true() -> bool {
    true
}

fn default_transport_memory_budget_mib() -> u64 {
    DEFAULT_TRANSPORT_MEMORY_BUDGET_MIB
}

#[derive(Default, serde::Deserialize)]
struct FileQos {
    server_udp_multiplier: Option<u8>,
    accept_client_udp_multiplier_proposal: Option<bool>,
    client_udp_multiplier: Option<u8>,
    propose_client_udp_multiplier: Option<bool>,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePortHopping {
    #[serde(default)]
    ports: Vec<u16>,
}

#[derive(Default, serde::Deserialize)]
struct FileSecurity {
    alpn: Option<String>,
    alpn_compatibility: Option<bool>,
    auth_failure_delay_ms: Option<u64>,
    control_padding: Option<bool>,
}

#[derive(Default, serde::Deserialize)]
struct FileAdmission {
    max_connections: Option<usize>,
    auth_timeout_seconds: Option<u64>,
    max_connections_per_user: Option<usize>,
}

#[derive(Clone, Copy, Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ServerTransportProfile {
    ServerStandard,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTransport {
    profile: Option<ServerTransportProfile>,
    keep_alive_seconds: Option<u64>,
    idle_timeout_seconds: Option<u64>,
    stream_receive_window_mib: Option<u64>,
    connection_receive_window_mib: Option<u64>,
    send_window_mib: Option<u64>,
    initial_incoming_bidi: Option<u32>,
    incoming_uni: Option<u32>,
    datagram_receive_buffer_mib: Option<u64>,
    datagram_send_buffer_mib: Option<u64>,
    congestion: Option<CongestionChoice>,
    stream_priority_enabled: Option<bool>,
}

#[derive(serde::Deserialize)]
struct CalibrationReport {
    schema_version: u8,
    benchmark_schema_version: u8,
    server_sha256: String,
    transport_profile_sha256: String,
    matrix_sha256: String,
    server_fixed_bytes_per_connection: u64,
    sample_seconds: u64,
}

#[derive(serde::Deserialize)]
struct BenchmarkCalibrationEnvelope {
    schema_version: u8,
    memory_calibration: CalibrationReport,
}

#[derive(serde::Deserialize)]
struct FileUser {
    key_id: String,
    secret: String,
    #[serde(default = "default_user_features")]
    features: Vec<String>,
}

fn default_user_features() -> Vec<String> {
    vec!["recommended".to_string()]
}

#[derive(serde::Deserialize)]
struct FileLimits {
    max_sessions_per_connection: Option<usize>,
    max_udp_flows: Option<usize>,
    max_datagram_size: Option<usize>,
}

pub fn load_server_config_from_str(text: &str) -> Result<LoadedServerConfig> {
    let current_server_sha256 = current_server_sha256()?;
    load_server_config_from_str_with_server_sha256(text, &current_server_sha256)
}

pub fn load_server_config_from_str_with_server_sha256(
    text: &str,
    current_server_sha256: &str,
) -> Result<LoadedServerConfig> {
    let fc: FileConfig = toml::from_str(text)?;
    build_server_config(fc, current_server_sha256)
}

pub async fn preflight_server_config_from_str(text: &str) -> Result<PreflightReport> {
    let current_server_sha256 = current_server_sha256()?;
    preflight_server_config_from_str_with_server_sha256(text, &current_server_sha256).await
}

pub async fn preflight_server_config_from_str_with_server_sha256(
    text: &str,
    current_server_sha256: &str,
) -> Result<PreflightReport> {
    let loaded = load_server_config_from_str_with_server_sha256(text, current_server_sha256)?;
    if let Some(sdwan) = loaded.sdwan_tun.as_ref() {
        let cache = HubSignedPolicyCache::load_files(
            &sdwan.snapshot_path,
            &sdwan.projection_path,
            &sdwan.trust,
            carrier_runtime::cloud_auth::unix_time_seconds()?,
        )?;
        validate_sdwan_static_binding(sdwan, cache.current())?;
        VerifiedExpansionPolicies::load(sdwan, cache.current())?.validate(
            sdwan,
            cache.current(),
            carrier_runtime::cloud_auth::unix_time_seconds()?,
        )?;
    }
    if let Some(shared) = loaded.sdwan_shared_transit.as_ref() {
        let now = carrier_runtime::cloud_auth::unix_time_seconds()?;
        let catalog = LoadedSharedTransitCatalog::load(shared, now)?;
        let _ = SharedTransitHubDriver::new_dynamic_from_verified_catalog(
            VerifiedSharedTransitNodeContext {
                node_id: shared.node_id,
                node_key_id: shared.node_key_id,
                node_pool_id: shared.node_pool_id,
                now_unix: now,
                runtime_now: Duration::ZERO,
            },
            catalog.runtime_domains(),
            SharedTransitDriverLimits::default(),
        )?;
    }
    if let Some(private) = loaded.sdwan_private_transit.as_ref() {
        let now = carrier_runtime::cloud_auth::unix_time_seconds()?;
        let runtime = load_private_transit(private, now)?;
        let cloud_signing_public_key = match &loaded.config.auth_profile {
            CandyServerAuthProfile::CloudGrantV1 {
                cloud_signing_public_key,
            } => *cloud_signing_public_key,
            CandyServerAuthProfile::Standard => {
                anyhow::bail!("private Transit requires cloud-grant-v1 authentication")
            }
        };
        let _ = load_private_transit_hub_identity(
            private,
            cloud_signing_public_key,
            runtime.snapshot.object().tenant_id,
            now,
        )?;
        let routes = runtime
            .dynamic_routes
            .as_ref()
            .map(|dynamic| dynamic.routes().clone())
            .unwrap_or_else(|| runtime.snapshot.routes().clone());
        let attachment = runtime
            .snapshot
            .object()
            .attachments
            .iter()
            .find(|value| value.attachment_id == private.node_attachment_id)
            .ok_or_else(|| anyhow::anyhow!("private Transit NodeAttachment is missing"))?;
        let engine = HubEngine::new_with_fabric(
            HubEngineConfig {
                enabled: true,
                domain: routes.domain(),
                routes,
                mtu: MtuState::new(
                    private.effective_mtu,
                    private.effective_mtu,
                    usize::from(private.effective_mtu),
                    0,
                )?,
                replay_limits: ReplayLimits::default(),
                egress_queue_limits: QueueLimits::default(),
                diagnostic_identity: GeneratedPacketIdentity {
                    attachment_id: private.node_attachment_id,
                    attachment_epoch: private.node_attachment_epoch,
                    router_ipv4: Ipv4Addr::from(attachment.overlay_router_ipv4),
                },
            },
            runtime.assignment.compile_directory(private.node_id)?,
        )?;
        let adapter =
            carrier_runtime::tun::TransitHubPacketAdapter::new(engine, PumpQueueLimits::default())?;
        let _ = TransitHubPacketDriver::new_dynamic(adapter, TransitHubDriverLimits::default())?;
    }
    let mut listens = Vec::with_capacity(loaded.config.additional_listens.len().saturating_add(1));
    listens.push(loaded.config.listen);
    listens.extend(loaded.config.additional_listens.iter().copied());
    let mut endpoints = server_endpoints_with_profiles_and_ech(
        &listens,
        loaded.config.cert,
        &loaded.config.security,
        &loaded.config.transport,
        loaded.config.ech.as_ref(),
    )?;
    let endpoint = endpoints.remove(0);
    let listen = endpoint.endpoint.local_addr()?.to_string();
    let cert_sha256 = cert_sha256_hex(&endpoint.cert_sha256);
    let socket_buffers = endpoint.socket_buffers;
    drop(endpoint);
    drop(endpoints);
    Ok(PreflightReport {
        ok: true,
        listen,
        cert_sha256,
        socket_buffers,
        summary: loaded.summary,
    })
}

pub async fn run_loaded_server(loaded: LoadedServerConfig) -> Result<()> {
    if loaded.sdwan_shared_transit.is_some() {
        return run_loaded_shared_transit_server(loaded).await;
    }
    if loaded.sdwan_private_transit.is_some() {
        return run_loaded_private_transit_server(loaded).await;
    }
    let Some(sdwan) = loaded.sdwan_tun else {
        return carrier_server::run_server(loaded.config).await;
    };
    let now = carrier_runtime::cloud_auth::unix_time_seconds()?;
    let initial_cache = HubSignedPolicyCache::load_files(
        &sdwan.snapshot_path,
        &sdwan.projection_path,
        &sdwan.trust,
        now,
    )?;
    validate_sdwan_static_binding(&sdwan, initial_cache.current())?;
    let expansion = Arc::new(VerifiedExpansionPolicies::load(
        &sdwan,
        initial_cache.current(),
    )?);
    expansion.validate(&sdwan, initial_cache.current(), now)?;
    let cache = Arc::new(RwLock::new(initial_cache));
    let mut instance_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut instance_id);
    anyhow::ensure!(
        instance_id != [0; 16],
        "failed to create netd owner identity"
    );
    let generations = Arc::new(AtomicU64::new(1));
    let sdwan = Arc::new(sdwan);
    spawn_signed_policy_reloader(Arc::clone(&cache), Arc::clone(&sdwan));
    run_sdwan_tunnel_server(loaded.config, move |handoff| {
        let cache = Arc::clone(&cache);
        let sdwan = Arc::clone(&sdwan);
        let generations = Arc::clone(&generations);
        let expansion = Arc::clone(&expansion);
        async move {
            let control = cache
                .read()
                .map_err(|_| anyhow::anyhow!("signed policy cache lock is poisoned"))?
                .snapshot();
            let now = carrier_runtime::cloud_auth::unix_time_seconds()?;
            expansion.validate(&sdwan, &control, now)?;
            let opened = accept_signed_server_tunnel_control(
                handoff,
                &control,
                sdwan.hub,
                now,
                Arc::new(TelemetryCounters::default()),
            )
            .await?;
            let effective_mtu = opened
                .tunnel()
                .effective_inner_mtu()
                .ok_or_else(|| anyhow::anyhow!("accepted tunnel has no effective MTU"))?;
            let tunnel_id = opened
                .tunnel()
                .tunnel_id()
                .ok_or_else(|| anyhow::anyhow!("accepted tunnel has no tunnel ID"))?;
            let mut verified = VerifiedHubNetdDeclaration::from_segment_snapshot(
                control.current().snapshot(),
                sdwan.hub,
                sdwan.node_attachment_id,
                sdwan.node_attachment_epoch,
                sdwan.table_id,
                effective_mtu,
                sdwan.exclusions.clone(),
                hub_firewall_policy(),
            )?;
            if let Some(dynamic) = &expansion.dynamic_routes {
                verified = verified.with_dynamic_routes(dynamic)?;
            }
            let adapter = attached_hub_adapter(
                control.current().snapshot(),
                expansion.dynamic_routes.as_ref(),
                sdwan.node_attachment_id,
                sdwan.node_attachment_epoch,
                tunnel_id,
                effective_mtu,
            )?;
            let generation = generations
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| anyhow::anyhow!("netd owner generation is exhausted"))?;
            let owner = LeaseOwner {
                instance_id,
                pid: std::process::id(),
                generation,
                lease_deadline_mono_ms: u64::MAX,
            };
            run_opened_committed_attached_hub_packet_lane(
                NetdClient::new(&sdwan.netd_socket, owner),
                verified,
                opened,
                adapter,
            )
            .await?;
            Ok(())
        }
    })
    .await
}

struct LoadedPrivateTransit {
    controls: LastGoodControlCatalog,
    snapshot: VerifiedSegmentSnapshot,
    assignment: VerifiedFabricAssignment,
    dynamic_routes: Option<VerifiedDynamicRouteSnapshot>,
}

fn load_private_transit_hub_identity(
    config: &SdwanPrivateTransitConfig,
    cloud_signing_public_key: [u8; 32],
    tenant_id: TenantId,
    now: u64,
) -> Result<HubIdentitySigner> {
    let node_grant_envelope = read_regular_file(
        &config.node_grant_path,
        candy_proto::fabric_contract::MAX_NODE_GRANT_ENVELOPE_LEN,
        true,
    )?;
    let node_key = read_regular_file(&config.node_signing_key_path, 32, true)?;
    let node_key: [u8; 32] = node_key.try_into().map_err(|_| {
        anyhow::anyhow!("private Transit Node signing key must be exactly 32 bytes")
    })?;
    let signer = HubIdentitySigner {
        node_grant_envelope,
        node_signing_key: ed25519_dalek::SigningKey::from_bytes(&node_key),
        cloud_signing_public_key,
    };
    validate_hub_identity_signer(
        &signer,
        tenant_id,
        config.node_id,
        config.node_key_id,
        config.node_pool_id,
        now,
    )?;
    Ok(signer)
}

fn load_private_transit(
    config: &SdwanPrivateTransitConfig,
    now: u64,
) -> Result<LoadedPrivateTransit> {
    let snapshot = VerifiedSegmentSnapshot::verify(
        &load_signed_envelope(&config.snapshot_path, "private Transit Segment snapshot")?,
        &config.trust,
    )?;
    snapshot.require_fresh(now)?;
    let assignment = VerifiedFabricAssignment::verify(
        &load_signed_envelope(
            &config.fabric_assignment_path,
            "private Transit Fabric assignment",
        )?,
        &config.trust,
        &snapshot,
    )?;
    assignment.require_fresh(now)?;
    let dynamic_routes = config
        .dynamic_route_path
        .as_deref()
        .map(|path| load_signed_envelope(path, "private Transit dynamic routes"))
        .transpose()?
        .map(|envelope| VerifiedDynamicRouteSnapshot::verify(&envelope, &config.trust, &snapshot))
        .transpose()?;
    if let Some(dynamic) = &dynamic_routes {
        dynamic.require_fresh(now)?;
    }
    let controls = config
        .projection_paths
        .iter()
        .map(|path| {
            let projection = VerifiedSiteProjection::verify(
                &load_signed_envelope(path, "private Transit Site projection")?,
                &config.trust,
            )?;
            let assigned = assignment
                .assignment_for(projection.object().attachment_id)
                .ok_or_else(|| {
                    anyhow::anyhow!("Site projection has no signed Fabric assignment")
                })?;
            anyhow::ensure!(
                assigned.site_id == projection.object().site_id,
                "Site projection and Fabric assignment Site differ"
            );
            VerifiedControl::new(snapshot.clone(), projection).map_err(Into::into)
        })
        .collect::<Result<Vec<_>>>()?;
    let controls = LastGoodControlCatalog::new(controls, now)?;
    Ok(LoadedPrivateTransit {
        controls,
        snapshot,
        assignment,
        dynamic_routes,
    })
}

async fn run_loaded_private_transit_server(loaded: LoadedServerConfig) -> Result<()> {
    let config = Arc::new(
        loaded
            .sdwan_private_transit
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("private Transit configuration is missing"))?
            .clone(),
    );
    let now = carrier_runtime::cloud_auth::unix_time_seconds()?;
    let runtime = Arc::new(load_private_transit(&config, now)?);
    let cloud_signing_public_key = match &loaded.config.auth_profile {
        CandyServerAuthProfile::CloudGrantV1 {
            cloud_signing_public_key,
        } => *cloud_signing_public_key,
        CandyServerAuthProfile::Standard => {
            anyhow::bail!("private Transit requires cloud-grant-v1 authentication")
        }
    };
    let identity_signer = Arc::new(load_private_transit_hub_identity(
        &config,
        cloud_signing_public_key,
        runtime.snapshot.object().tenant_id,
        now,
    )?);
    let attachment = runtime
        .snapshot
        .object()
        .attachments
        .iter()
        .find(|value| value.attachment_id == config.node_attachment_id)
        .ok_or_else(|| anyhow::anyhow!("private Transit NodeAttachment is missing"))?;
    anyhow::ensure!(
        matches!(
            attachment.principal,
            candy_proto::route_contract::AttachmentPrincipalV1::Node { node_id, node_key_id }
                if node_id == config.node_id && node_key_id == config.node_key_id
        ) && attachment.epoch_floor <= config.node_attachment_epoch,
        "private Transit NodeAttachment does not match configured Node identity and epoch"
    );
    let routes = runtime
        .dynamic_routes
        .as_ref()
        .map(|dynamic| dynamic.routes().clone())
        .unwrap_or_else(|| runtime.snapshot.routes().clone());
    let fabric = runtime.assignment.compile_directory(config.node_id)?;
    let engine = HubEngine::new_with_fabric(
        HubEngineConfig {
            enabled: true,
            domain: routes.domain(),
            routes,
            mtu: MtuState::new(
                config.effective_mtu,
                config.effective_mtu,
                usize::from(config.effective_mtu),
                0,
            )?,
            replay_limits: ReplayLimits::default(),
            egress_queue_limits: QueueLimits::default(),
            diagnostic_identity: GeneratedPacketIdentity {
                attachment_id: config.node_attachment_id,
                attachment_epoch: config.node_attachment_epoch,
                router_ipv4: Ipv4Addr::from(attachment.overlay_router_ipv4),
            },
        },
        fabric,
    )?;
    let adapter =
        carrier_runtime::tun::TransitHubPacketAdapter::new(engine, PumpQueueLimits::default())?;
    let (driver, attachment_handle, fabric_handle) =
        TransitHubPacketDriver::new_dynamic(adapter, TransitHubDriverLimits::default())?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut driver_task = tokio::spawn(driver.run(shutdown_rx));

    let site_runtime = Arc::clone(&runtime);
    let site_config = Arc::clone(&config);
    let site_identity_signer = Arc::clone(&identity_signer);
    let site_server = run_sdwan_tunnel_server(loaded.config.clone(), move |handoff| {
        let runtime = Arc::clone(&site_runtime);
        let config = Arc::clone(&site_config);
        let identity_signer = Arc::clone(&site_identity_signer);
        let attachment_handle = attachment_handle.clone();
        async move {
            anyhow::ensure!(
                handoff.grant().service_class == ServiceClass::CustomerPrivate,
                "private Transit requires CustomerPrivate service class"
            );
            let policy = handoff
                .grant()
                .route_policy
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("private Transit Grant has no route policy"))?;
            let control = runtime.controls.select(policy)?.clone();
            let opened = accept_signed_server_tunnel_control_with_hub_identity(
                handoff,
                &control,
                candy_tun::control::HubNodeContext {
                    tenant_id: runtime.snapshot.object().tenant_id,
                    node_id: config.node_id,
                    node_key_id: config.node_key_id,
                    node_pool_id: config.node_pool_id,
                    service_class: ServiceClass::CustomerPrivate,
                },
                carrier_runtime::cloud_auth::unix_time_seconds()?,
                Arc::new(TelemetryCounters::default()),
                (*identity_signer).clone(),
            )
            .await?;
            let (connection, tunnel, mut peer_control, owner) = opened.into_parts();
            let context = PacketContext {
                tunnel_id: tunnel
                    .tunnel_id()
                    .ok_or_else(|| anyhow::anyhow!("private Transit tunnel ID is missing"))?,
                attachment_id: tunnel
                    .attachment_id()
                    .ok_or_else(|| anyhow::anyhow!("private Transit attachment ID is missing"))?,
                attachment_epoch: tunnel.attachment_epoch().ok_or_else(|| {
                    anyhow::anyhow!("private Transit attachment epoch is missing")
                })?,
            };
            let assigned = runtime
                .assignment
                .assignment_for(context.attachment_id)
                .ok_or_else(|| anyhow::anyhow!("accepted Site has no signed Fabric assignment"))?;
            anyhow::ensure!(
                assigned.hub_node_id == config.node_id
                    && assigned.hub_node_key_id == config.node_key_id
                    && assigned.hub_attachment_id == config.node_attachment_id
                    && assigned.attachment_epoch == context.attachment_epoch,
                "accepted Site lane does not match signed Fabric assignment"
            );
            let mut lease = attachment_handle
                .register(TransitAttachmentLane {
                    context,
                    connection,
                })
                .await?;
            let lane_closed = tokio::select! {
                result = lease.closed() => { result?; true }
                _ = peer_control.recv() => false,
            };
            if !lane_closed {
                lease.release_and_wait().await?;
            }
            owner.shutdown().await;
            Ok(())
        }
    });

    let expected_segment = candy_proto::fabric_contract::FabricSegmentRefV1 {
        segment_id: runtime.snapshot.object().segment_id,
        generation: runtime.snapshot.object().segment_generation,
        content_hash: runtime.snapshot.object().content_hash,
    };
    let mut fabric_server_config = loaded.config;
    fabric_server_config.listen = config.fabric_listen;
    fabric_server_config.additional_listens.clear();
    let fabric_runtime = Arc::clone(&runtime);
    let fabric_config = Arc::clone(&config);
    let fabric_server =
        run_hub_fabric_server(fabric_server_config, expected_segment, move |pending| {
            let runtime = Arc::clone(&fabric_runtime);
            let config = Arc::clone(&fabric_config);
            let fabric_handle = fabric_handle.clone();
            async move {
                let principal = pending.principal();
                anyhow::ensure!(
                    principal.tenant_id == runtime.snapshot.object().tenant_id
                        && principal.node_pool_id == config.node_pool_id
                        && principal.hub_id.0 == principal.node_id.0,
                    "Fabric principal does not match signed private Transit domain"
                );
                anyhow::ensure!(
                    runtime
                        .assignment
                        .object()
                        .assignments
                        .iter()
                        .any(|assignment| {
                            assignment.hub_node_id == principal.node_id
                                && assignment.hub_node_key_id == principal.node_key_id
                        }),
                    "Fabric peer is absent from signed assignment"
                );
                let admitted = pending.admit().await?;
                let connection = admitted.connection().clone();
                let mut lease = fabric_handle
                    .register(TransitFabricLane {
                        hub_id: candy_tun::HubId(principal.hub_id.0),
                        connection,
                    })
                    .await?;
                tokio::select! {
                    result = lease.closed() => { result?; }
                    _ = admitted.wait_closed() => { lease.release_and_wait().await?; }
                }
                Ok(())
            }
        });
    tokio::pin!(site_server);
    tokio::pin!(fabric_server);
    tokio::select! {
        result = &mut site_server => {
            let _ = shutdown_tx.send(true);
            let _ = driver_task.await;
            result
        }
        result = &mut fabric_server => {
            let _ = shutdown_tx.send(true);
            let _ = driver_task.await;
            result
        }
        result = &mut driver_task => match result {
            Ok(Ok(outcome)) => anyhow::bail!(
                "private Transit driver stopped unexpectedly after {} records",
                outcome.attachment_records_received + outcome.fabric_records_received
            ),
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        }
    }
}

async fn run_loaded_shared_transit_server(loaded: LoadedServerConfig) -> Result<()> {
    let shared = loaded
        .sdwan_shared_transit
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("shared Transit configuration is missing"))?;
    let now = carrier_runtime::cloud_auth::unix_time_seconds()?;
    let catalog = Arc::new(LoadedSharedTransitCatalog::load(shared, now)?);
    let (driver, handle) = SharedTransitHubDriver::new_dynamic_from_verified_catalog(
        VerifiedSharedTransitNodeContext {
            node_id: shared.node_id,
            node_key_id: shared.node_key_id,
            node_pool_id: shared.node_pool_id,
            now_unix: now,
            runtime_now: Duration::ZERO,
        },
        catalog.runtime_domains(),
        SharedTransitDriverLimits::default(),
    )?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut driver_task = tokio::spawn(driver.run(shutdown_rx));
    let node_id = shared.node_id;
    let node_key_id = shared.node_key_id;
    let node_pool_id = shared.node_pool_id;
    let server = run_sdwan_tunnel_server(loaded.config, move |handoff| {
        let catalog = Arc::clone(&catalog);
        let handle = handle.clone();
        async move {
            anyhow::ensure!(
                handoff.grant().service_class == ServiceClass::CandySharedAcceleration,
                "shared Transit requires CandySharedAcceleration service class"
            );
            let policy = handoff
                .grant()
                .route_policy
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("shared Transit Grant has no route policy"))?;
            let control = catalog.controls.select(policy)?.clone();
            let projection = control.current().projection().object();
            let route_domain = candy_tun::RouteDomainId {
                tenant_id: projection.tenant_id.0,
                segment_id: projection.segment_id,
            };
            let site_id = projection.site_id;
            let opened = accept_signed_server_tunnel_control(
                handoff,
                &control,
                candy_tun::control::HubNodeContext {
                    tenant_id: projection.tenant_id,
                    node_id,
                    node_key_id,
                    node_pool_id,
                    service_class: ServiceClass::CandySharedAcceleration,
                },
                carrier_runtime::cloud_auth::unix_time_seconds()?,
                Arc::new(TelemetryCounters::default()),
            )
            .await?;
            let (connection, tunnel, mut peer_control, owner) = opened.into_parts();
            let context = PacketContext {
                tunnel_id: tunnel
                    .tunnel_id()
                    .ok_or_else(|| anyhow::anyhow!("shared Transit tunnel ID is missing"))?,
                attachment_id: tunnel
                    .attachment_id()
                    .ok_or_else(|| anyhow::anyhow!("shared Transit attachment ID is missing"))?,
                attachment_epoch: tunnel
                    .attachment_epoch()
                    .ok_or_else(|| anyhow::anyhow!("shared Transit attachment epoch is missing"))?,
            };
            let mut lease = handle
                .register(SharedTransitCatalogLane {
                    key: candy_tun::SharedTunnelKey {
                        domain: route_domain,
                        site_id,
                        tunnel_id: context.tunnel_id,
                    },
                    context,
                    connection,
                })
                .await?;
            let lane_closed = tokio::select! {
                result = lease.closed() => {
                    result?;
                    true
                }
                _ = peer_control.recv() => false,
            };
            if !lane_closed {
                lease.release_and_wait().await?;
            }
            owner.shutdown().await;
            Ok(())
        }
    });
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => {
            let _ = shutdown_tx.send(true);
            let _ = driver_task.await;
            result
        }
        result = &mut driver_task => {
            match result {
                Ok(Ok(outcome)) => anyhow::bail!(
                    "shared Transit driver stopped unexpectedly after {} records",
                    outcome.counters.records_received
                ),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            }
        }
    }
}

fn validate_sdwan_static_binding(config: &SdwanTunConfig, control: &LastGoodControl) -> Result<()> {
    VerifiedHubNetdDeclaration::from_segment_snapshot(
        control.current().snapshot(),
        config.hub,
        config.node_attachment_id,
        config.node_attachment_epoch,
        config.table_id,
        candy_proto::ip_tunnel::IPV4_MIN_INNER_MTU,
        config.exclusions.clone(),
        hub_firewall_policy(),
    )?;
    Ok(())
}

fn hub_firewall_policy() -> FirewallPolicy {
    FirewallPolicy {
        allow_forward: true,
        clamp_tcp_mss: true,
        require_ipv4_forwarding: true,
        manage_rp_filter: true,
    }
}

fn spawn_signed_policy_reloader(
    cache: Arc<RwLock<HubSignedPolicyCache>>,
    config: Arc<SdwanTunConfig>,
) {
    tokio::spawn(async move {
        let mut signal = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(error) => {
                tracing::warn!(%error, "SD-WAN signed policy reload signal unavailable");
                return;
            }
        };
        while signal.recv().await.is_some() {
            let snapshot_path = config.snapshot_path.clone();
            let projection_path = config.projection_path.clone();
            let trust = config.trust.clone();
            let candidate = tokio::task::spawn_blocking(move || {
                load_signed_policy_candidate(&snapshot_path, &projection_path, &trust)
            })
            .await;
            let candidate = match candidate {
                Ok(Ok(candidate)) => candidate,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "SD-WAN signed policy reload rejected");
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "SD-WAN signed policy reload worker failed");
                    continue;
                }
            };
            let now = match carrier_runtime::cloud_auth::unix_time_seconds() {
                Ok(now) => now,
                Err(error) => {
                    tracing::warn!(%error, "SD-WAN signed policy reload clock failed");
                    continue;
                }
            };
            let mut cache = match cache.write() {
                Ok(cache) => cache,
                Err(_) => {
                    tracing::warn!("SD-WAN signed policy cache lock is poisoned");
                    return;
                }
            };
            if let Err(error) = cache.replace(candidate, now) {
                tracing::warn!(%error, "SD-WAN signed policy reload rejected");
                continue;
            }
            tracing::info!(
                segment_generation = cache.current().current().snapshot().generation(),
                projection_generation = cache.current().current().projection().generation(),
                "SD-WAN signed policy reloaded"
            );
        }
    });
}

fn attached_hub_adapter(
    snapshot: &VerifiedSegmentSnapshot,
    dynamic_routes: Option<&VerifiedDynamicRouteSnapshot>,
    node_attachment_id: AttachmentId,
    node_attachment_epoch: u64,
    tunnel_id: u64,
    effective_mtu: u16,
) -> Result<AttachedHubPacketAdapter> {
    let attachment = snapshot
        .object()
        .attachments
        .iter()
        .find(|value| value.attachment_id == node_attachment_id)
        .ok_or_else(|| anyhow::anyhow!("signed NodeAttachment is missing"))?;
    let routes = dynamic_routes
        .map(|dynamic| dynamic.routes().clone())
        .unwrap_or_else(|| snapshot.routes().clone());
    let engine = HubEngine::new(HubEngineConfig {
        enabled: true,
        domain: routes.domain(),
        routes,
        mtu: MtuState::new(effective_mtu, effective_mtu, usize::from(effective_mtu), 0)?,
        replay_limits: ReplayLimits::default(),
        egress_queue_limits: QueueLimits::default(),
        diagnostic_identity: GeneratedPacketIdentity {
            attachment_id: node_attachment_id,
            attachment_epoch: node_attachment_epoch,
            router_ipv4: Ipv4Addr::from(attachment.overlay_router_ipv4),
        },
    })?;
    Ok(AttachedHubPacketAdapter::new(HubTunPump::new(
        engine,
        PacketContext {
            tunnel_id,
            attachment_id: node_attachment_id,
            attachment_epoch: node_attachment_epoch,
        },
        PumpQueueLimits::default(),
        0,
    )?))
}

fn current_server_sha256() -> Result<String> {
    let current_exe = std::env::current_exe()?;
    carrier_transport::file_sha256_hex(&current_exe)
}

fn build_server_config(fc: FileConfig, current_server_sha256: &str) -> Result<LoadedServerConfig> {
    let auth_profile = if fc.cloud_auth.enabled {
        let encoded = fc.cloud_auth.cloud_signing_public_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!("cloud_auth.cloud_signing_public_key is required when cloud_auth.enabled is true")
        })?;
        CandyServerAuthProfile::CloudGrantV1 {
            cloud_signing_public_key: decode_public_key(encoded)?,
        }
    } else {
        if fc.cloud_auth.cloud_signing_public_key.is_some() {
            anyhow::bail!("cloud_auth.cloud_signing_public_key requires cloud_auth.enabled = true");
        }
        CandyServerAuthProfile::Standard
    };
    let is_cloud = matches!(auth_profile, CandyServerAuthProfile::CloudGrantV1 { .. });
    let cloud_signing_public_key = match &auth_profile {
        CandyServerAuthProfile::CloudGrantV1 {
            cloud_signing_public_key,
        } => Some(*cloud_signing_public_key),
        CandyServerAuthProfile::Standard => None,
    };
    let sdwan_tun = build_sdwan_tun_config(fc.sdwan_tun, is_cloud)?;
    let sdwan_private_transit = build_sdwan_private_transit_config(
        fc.sdwan_private_transit,
        is_cloud,
        cloud_signing_public_key,
    )?;
    let sdwan_shared_transit =
        build_sdwan_shared_transit_config(fc.sdwan_shared_transit, is_cloud)?;
    anyhow::ensure!(
        [
            sdwan_tun.is_some(),
            sdwan_private_transit.is_some(),
            sdwan_shared_transit.is_some()
        ]
        .into_iter()
        .filter(|enabled| *enabled)
        .count()
            <= 1,
        "sdwan_tun, sdwan_private_transit, and sdwan_shared_transit are mutually exclusive"
    );
    let ech = fc.ech.map(load_server_ech).transpose()?;
    let ech_enabled = ech.is_some();
    let cert_source = match (
        &fc.cert_pem,
        &fc.key_pem,
        fc.development_ephemeral_certificate,
    ) {
        (Some(_), Some(_), false) => "files",
        (None, None, true) => "generated-development",
        (Some(_), Some(_), true) => anyhow::bail!(
            "development_ephemeral_certificate cannot be enabled with cert_pem and key_pem"
        ),
        (None, None, false) => anyhow::bail!(
            "cert_pem and key_pem are required unless development_ephemeral_certificate is true"
        ),
        _ => anyhow::bail!("cert_pem and key_pem must be configured together"),
    };
    let cert = match (
        fc.cert_pem,
        fc.key_pem,
        fc.development_ephemeral_certificate,
    ) {
        (Some(c), Some(k), false) => CertSource::Files {
            cert_pem: c.into(),
            key_pem: k.into(),
        },
        (None, None, true) => CertSource::Generated,
        _ => unreachable!("certificate pair already validated"),
    };

    if is_cloud {
        if !fc.users.is_empty() {
            anyhow::bail!("[[users]] cannot be configured when cloud_auth.enabled is true");
        }
    } else if fc.users.is_empty() {
        anyhow::bail!("at least one [[users]] entry is required");
    }
    let user_count = fc.users.len();
    let mut seen_key_ids = std::collections::HashSet::new();
    let users = fc
        .users
        .into_iter()
        .map(|u| {
            if u.key_id.trim().is_empty() {
                anyhow::bail!("user key_id must not be empty");
            }
            if u.secret.len() < 16 || u.secret == "change-me-long-random-secret" {
                anyhow::bail!(
                    "user secret for key_id '{}' must be a non-placeholder value with at least 16 bytes",
                    u.key_id
                );
            }
            if !seen_key_ids.insert(u.key_id.clone()) {
                anyhow::bail!("duplicate user key_id '{}'", u.key_id);
            }
            Ok(ServerUser {
                key_id: KeyId::new(u.key_id),
                secret: u.secret.into_bytes(),
                allowed_features: feature_bits(&u.features),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let defaults = ServerAdmissionLimits::default();
    let max_connections = fc
        .admission
        .max_connections
        .unwrap_or(defaults.max_connections);
    if !(1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&max_connections) {
        anyhow::bail!(
            "max_connections must be between 1 and {}",
            tokio::sync::Semaphore::MAX_PERMITS
        );
    }
    let auth_timeout_seconds = fc.admission.auth_timeout_seconds.unwrap_or(if is_cloud {
        5
    } else {
        defaults.auth_timeout.as_secs()
    });
    if !(1..=300).contains(&auth_timeout_seconds) {
        anyhow::bail!("auth_timeout_seconds must be between 1 and 300");
    }
    let max_connections_per_user = fc
        .admission
        .max_connections_per_user
        .unwrap_or(defaults.max_connections_per_user);
    if !(1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&max_connections_per_user) {
        anyhow::bail!(
            "max_connections_per_user must be between 1 and {}",
            tokio::sync::Semaphore::MAX_PERMITS
        );
    }
    let requested_admission = ServerAdmissionLimits {
        max_connections,
        auth_timeout: Duration::from_secs(auth_timeout_seconds),
        max_connections_per_user,
    };
    if sdwan_tun.is_some() {
        anyhow::ensure!(
            max_connections == 1,
            "Attached Private Hub mode requires admission.max_connections = 1"
        );
    }

    let mut limits = ResourceLimits::default();
    if let Some(l) = fc.limits {
        if let Some(v) = l.max_sessions_per_connection {
            if v == 0 || v > HARD_MAX_TOTAL_OPENS {
                anyhow::bail!(
                    "max_sessions_per_connection must be between 1 and {HARD_MAX_TOTAL_OPENS}"
                );
            }
            limits.max_sessions_per_connection = v;
        }
        if let Some(v) = l.max_udp_flows {
            if v == 0 || v > HARD_MAX_TOTAL_OPENS {
                anyhow::bail!("max_udp_flows must be between 1 and {HARD_MAX_TOTAL_OPENS}");
            }
            limits.max_udp_flows = v;
        }
        if let Some(v) = l.max_datagram_size {
            if v == 0 || v > candy_proto::frame::MAX_FRAME_LEN {
                anyhow::bail!(
                    "max_datagram_size must be between 1 and {}",
                    candy_proto::frame::MAX_FRAME_LEN
                );
            }
            limits.max_datagram_size = v;
        }
    }

    let listen: SocketAddr = fc.listen.parse()?;
    anyhow::ensure!(
        fc.port_hopping.ports.len() <= 16,
        "port_hopping.ports supports at most 16 entries"
    );
    let mut seen_ports = std::collections::HashSet::new();
    seen_ports.insert(listen.port());
    let additional_listens = fc
        .port_hopping
        .ports
        .into_iter()
        .map(|port| {
            anyhow::ensure!(port != 0, "port_hopping.ports must not contain zero");
            anyhow::ensure!(
                seen_ports.insert(port),
                "port_hopping.ports contains duplicate or primary port {port}"
            );
            Ok(SocketAddr::new(listen.ip(), port))
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(private) = &sdwan_private_transit {
        anyhow::ensure!(
            private.fabric_listen != listen && !additional_listens.contains(&private.fabric_listen),
            "sdwan_private_transit.fabric_listen must differ from every Site listener"
        );
    }
    let security_defaults = TransportSecurityProfile::default();
    let security = TransportSecurityProfile {
        alpn: fc
            .security
            .alpn
            .unwrap_or_else(|| "candy/0.3".to_string())
            .into_bytes(),
        auth_failure_delay_ms: fc
            .security
            .auth_failure_delay_ms
            .unwrap_or(security_defaults.auth_failure_delay_ms),
        control_padding: fc
            .security
            .control_padding
            .unwrap_or(security_defaults.control_padding),
        legacy_alpn_compatibility: fc.security.alpn_compatibility.unwrap_or(true),
    };
    let server_udp_multiplier = match fc.qos.server_udp_multiplier.unwrap_or(1) {
        value @ 1..=3 => value,
        _ => anyhow::bail!("server_udp_multiplier must be between 1 and 3"),
    };
    let client_udp_multiplier = match fc.qos.client_udp_multiplier.unwrap_or(1) {
        value @ 1..=3 => value,
        _ => anyhow::bail!("client_udp_multiplier must be between 1 and 3"),
    };
    let qos = DataplaneQos {
        server_udp_multiplier,
        max_client_udp_multiplier: 3,
        max_server_udp_multiplier: 3,
        accept_client_udp_multiplier_proposal: fc
            .qos
            .accept_client_udp_multiplier_proposal
            .unwrap_or(false),
        proposed_client_udp_multiplier: client_udp_multiplier,
        propose_client_udp_multiplier: fc.qos.propose_client_udp_multiplier.unwrap_or(false),
        traffic_budget: DataplaneQos::default().traffic_budget,
    };
    let requested_transport = build_transport_profile(fc.transport)?;
    let transport_requested_profile_sha256 =
        carrier_transport::transport_profile_sha256(&requested_transport)?;
    let transport_memory_budget = fc
        .transport_memory_budget_mib
        .checked_mul(MIB)
        .ok_or_else(|| anyhow::anyhow!("transport memory budget MiB overflow"))?;
    let calibration = load_calibration(
        fc.transport_memory_calibration_report.as_deref(),
        current_server_sha256,
        &transport_requested_profile_sha256,
    );
    let effective = requested_transport.admission_for_budget(
        requested_admission.max_connections,
        transport_memory_budget,
        calibration,
    )?;
    let admission = requested_admission.with_effective_connections(&effective)?;
    let transport = effective.effective_profile.clone();
    let transport_profile_sha256 = carrier_transport::transport_profile_sha256(&transport)?;
    let summary = ServerConfigSummary {
        listen: listen.to_string(),
        port_hopping_listens: additional_listens.iter().map(ToString::to_string).collect(),
        user_count,
        auth_profile: if is_cloud {
            "cloud-grant-v1".to_string()
        } else {
            "standard".to_string()
        },
        cert_source: cert_source.to_string(),
        ech_enabled,
        max_sessions_per_connection: limits.max_sessions_per_connection,
        max_udp_flows: limits.max_udp_flows,
        max_datagram_size: limits.max_datagram_size,
        server_udp_multiplier,
        accept_client_udp_multiplier_proposal: qos.accept_client_udp_multiplier_proposal,
        client_udp_multiplier,
        propose_client_udp_multiplier: qos.propose_client_udp_multiplier,
        requested_max_connections: max_connections,
        max_connections: effective.effective_connections,
        auth_timeout_seconds,
        max_connections_per_user,
        transport_memory_budget_mib: fc.transport_memory_budget_mib,
        transport_requested_connections: effective.requested_connections,
        transport_effective_connections: effective.effective_connections,
        transport_worst_case_bytes: effective.worst_case_bytes,
        transport_profile: transport.clone(),
        transport_requested_profile_sha256,
        transport_profile_sha256,
        transport_fallback_reason: effective.fallback_reason.clone(),
        sdwan_tun_enabled: sdwan_tun.is_some(),
        sdwan_private_transit_enabled: sdwan_private_transit.is_some(),
        sdwan_shared_transit_enabled: sdwan_shared_transit.is_some(),
    };
    Ok(LoadedServerConfig {
        config: ServerConfig {
            listen,
            additional_listens,
            cert,
            users,
            limits,
            qos,
            security,
            transport,
            admission,
            ech,
            auth_profile,
        },
        summary,
        sdwan_tun,
        sdwan_private_transit,
        sdwan_shared_transit,
    })
}

fn build_sdwan_tun_config(
    file: Option<FileSdwanTun>,
    cloud_auth_enabled: bool,
) -> Result<Option<SdwanTunConfig>> {
    let Some(file) = file else {
        return Ok(None);
    };
    if !file.enabled {
        anyhow::ensure!(
            file.snapshot_file.is_none()
                && file.projection_file.is_none()
                && file.shared_hub_admission_file.is_none()
                && file.mesh_membership_file.is_none()
                && file.dynamic_route_snapshot_file.is_none()
                && file.route_signing_key_id.is_none()
                && file.route_signing_public_key.is_none()
                && file.tenant_id.is_none()
                && file.node_id.is_none()
                && file.node_key_id.is_none()
                && file.node_pool_id.is_none()
                && file.node_attachment_id.is_none()
                && file.node_attachment_epoch.is_none()
                && file.netd_socket.is_none()
                && file.table_id.is_none()
                && file.underlay_exclusions.is_empty(),
            "sdwan_tun fields require sdwan_tun.enabled = true"
        );
        return Ok(None);
    }
    anyhow::ensure!(
        cloud_auth_enabled,
        "sdwan_tun.enabled requires cloud_auth.enabled = true"
    );
    let required = |value: Option<String>, name: &str| {
        value.ok_or_else(|| anyhow::anyhow!("sdwan_tun.{name} is required when enabled"))
    };
    let required_path = |value: Option<PathBuf>, name: &str| {
        value.ok_or_else(|| anyhow::anyhow!("sdwan_tun.{name} is required when enabled"))
    };
    let key_id = required(file.route_signing_key_id, "route_signing_key_id")?;
    anyhow::ensure!(
        !key_id.is_empty() && key_id.len() <= MAX_ROUTE_SIGNING_KEY_ID_LEN,
        "sdwan_tun.route_signing_key_id length is invalid"
    );
    let public_key = decode_32_byte_key(
        &required(file.route_signing_public_key, "route_signing_public_key")?,
        "sdwan_tun.route_signing_public_key",
    )?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|_| anyhow::anyhow!("sdwan_tun.route_signing_public_key is invalid"))?;
    let trust = RouteTrustStore::new([(key_id.into_bytes(), verifying_key)])?;
    let table_id = file.table_id.unwrap_or(CANDY_TABLE_MIN);
    anyhow::ensure!(
        (CANDY_TABLE_MIN..=CANDY_TABLE_MAX).contains(&table_id),
        "sdwan_tun.table_id must be between {CANDY_TABLE_MIN} and {CANDY_TABLE_MAX}"
    );
    let node_attachment_epoch = file.node_attachment_epoch.ok_or_else(|| {
        anyhow::anyhow!("sdwan_tun.node_attachment_epoch is required when enabled")
    })?;
    anyhow::ensure!(
        node_attachment_epoch > 0,
        "sdwan_tun.node_attachment_epoch must be nonzero"
    );
    let mut exclusions = file
        .underlay_exclusions
        .into_iter()
        .map(|value| {
            Ok(UnderlayExclusion {
                prefix: parse_netd_prefix(&value.prefix)?,
                kind: match value.kind {
                    FileUnderlayKind::CloudApi => UnderlayKind::CloudApi,
                    FileUnderlayKind::HubEndpoint => UnderlayKind::HubEndpoint,
                    FileUnderlayKind::Management => UnderlayKind::Management,
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    exclusions.sort_unstable_by_key(|value| (value.prefix, value.kind as u64));
    anyhow::ensure!(
        [
            UnderlayKind::CloudApi,
            UnderlayKind::HubEndpoint,
            UnderlayKind::Management,
        ]
        .into_iter()
        .all(|kind| exclusions.iter().any(|value| value.kind == kind)),
        "sdwan_tun requires cloud-api, hub-endpoint, and management exclusions"
    );
    Ok(Some(SdwanTunConfig {
        snapshot_path: required_path(file.snapshot_file, "snapshot_file")?,
        projection_path: required_path(file.projection_file, "projection_file")?,
        shared_hub_admission_path: file.shared_hub_admission_file,
        mesh_membership_path: file.mesh_membership_file,
        dynamic_route_snapshot_path: file.dynamic_route_snapshot_file,
        trust,
        hub: candy_tun::control::HubNodeContext {
            tenant_id: TenantId(decode_fixed_id(
                &required(file.tenant_id, "tenant_id")?,
                "sdwan_tun.tenant_id",
            )?),
            node_id: NodeId(decode_fixed_id(
                &required(file.node_id, "node_id")?,
                "sdwan_tun.node_id",
            )?),
            node_key_id: NodeKeyId(decode_fixed_id(
                &required(file.node_key_id, "node_key_id")?,
                "sdwan_tun.node_key_id",
            )?),
            node_pool_id: NodePoolId(decode_fixed_id(
                &required(file.node_pool_id, "node_pool_id")?,
                "sdwan_tun.node_pool_id",
            )?),
            service_class: ServiceClass::CustomerPrivate,
        },
        node_attachment_id: AttachmentId(decode_fixed_id(
            &required(file.node_attachment_id, "node_attachment_id")?,
            "sdwan_tun.node_attachment_id",
        )?),
        node_attachment_epoch,
        netd_socket: required_path(file.netd_socket, "netd_socket")?,
        table_id,
        exclusions,
    }))
}

fn build_sdwan_private_transit_config(
    file: Option<FileSdwanPrivateTransit>,
    cloud_auth_enabled: bool,
    cloud_signing_public_key: Option<[u8; 32]>,
) -> Result<Option<SdwanPrivateTransitConfig>> {
    let Some(file) = file else {
        return Ok(None);
    };
    if !file.enabled {
        anyhow::ensure!(
            file.route_signing_key_id.is_none()
                && file.route_signing_public_key.is_none()
                && file.snapshot_file.is_none()
                && file.projection_files.is_none()
                && file.fabric_assignment_file.is_none()
                && file.dynamic_route_snapshot_file.is_none()
                && file.node_id.is_none()
                && file.node_key_id.is_none()
                && file.node_pool_id.is_none()
                && file.node_attachment_id.is_none()
                && file.node_attachment_epoch.is_none()
                && file.effective_mtu.is_none()
                && file.fabric_listen.is_none()
                && file.node_grant_file.is_none()
                && file.node_signing_key_file.is_none(),
            "sdwan_private_transit fields require sdwan_private_transit.enabled = true"
        );
        return Ok(None);
    }
    anyhow::ensure!(
        cloud_auth_enabled,
        "sdwan_private_transit.enabled requires cloud_auth.enabled = true"
    );
    anyhow::ensure!(
        cloud_signing_public_key.is_some(),
        "sdwan_private_transit.enabled requires cloud_auth.cloud_signing_public_key"
    );
    let required = |value: Option<String>, name: &str| {
        value
            .ok_or_else(|| anyhow::anyhow!("sdwan_private_transit.{name} is required when enabled"))
    };
    let required_path = |value: Option<PathBuf>, name: &str| {
        value
            .ok_or_else(|| anyhow::anyhow!("sdwan_private_transit.{name} is required when enabled"))
    };
    let key_id = required(file.route_signing_key_id, "route_signing_key_id")?;
    anyhow::ensure!(
        !key_id.is_empty() && key_id.len() <= MAX_ROUTE_SIGNING_KEY_ID_LEN,
        "sdwan_private_transit.route_signing_key_id length is invalid"
    );
    let public_key = decode_32_byte_key(
        &required(file.route_signing_public_key, "route_signing_public_key")?,
        "sdwan_private_transit.route_signing_public_key",
    )?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).map_err(|_| {
        anyhow::anyhow!("sdwan_private_transit.route_signing_public_key is invalid")
    })?;
    let projection_paths = file.projection_files.ok_or_else(|| {
        anyhow::anyhow!("sdwan_private_transit.projection_files is required when enabled")
    })?;
    anyhow::ensure!(
        !projection_paths.is_empty() && projection_paths.len() <= 1024,
        "sdwan_private_transit.projection_files must contain between 1 and 1024 entries"
    );
    let unique: std::collections::HashSet<_> = projection_paths.iter().collect();
    anyhow::ensure!(
        unique.len() == projection_paths.len(),
        "sdwan_private_transit projection_file is duplicated"
    );
    let node_attachment_epoch = file.node_attachment_epoch.ok_or_else(|| {
        anyhow::anyhow!("sdwan_private_transit.node_attachment_epoch is required when enabled")
    })?;
    anyhow::ensure!(
        node_attachment_epoch > 0,
        "sdwan_private_transit.node_attachment_epoch must be nonzero"
    );
    let effective_mtu = file.effective_mtu.ok_or_else(|| {
        anyhow::anyhow!("sdwan_private_transit.effective_mtu is required when enabled")
    })?;
    anyhow::ensure!(
        (candy_proto::ip_tunnel::IPV4_MIN_INNER_MTU..=1500).contains(&effective_mtu),
        "sdwan_private_transit.effective_mtu is invalid"
    );
    let fabric_listen: SocketAddr = required(file.fabric_listen, "fabric_listen")?
        .parse()
        .map_err(|_| anyhow::anyhow!("sdwan_private_transit.fabric_listen is invalid"))?;
    let node_grant_path = required_path(file.node_grant_file, "node_grant_file")?;
    let node_signing_key_path = required_path(file.node_signing_key_file, "node_signing_key_file")?;
    Ok(Some(SdwanPrivateTransitConfig {
        trust: RouteTrustStore::new([(key_id.into_bytes(), verifying_key)])?,
        snapshot_path: required_path(file.snapshot_file, "snapshot_file")?,
        projection_paths,
        fabric_assignment_path: required_path(
            file.fabric_assignment_file,
            "fabric_assignment_file",
        )?,
        dynamic_route_path: file.dynamic_route_snapshot_file,
        node_id: NodeId(decode_fixed_id(
            &required(file.node_id, "node_id")?,
            "sdwan_private_transit.node_id",
        )?),
        node_key_id: NodeKeyId(decode_fixed_id(
            &required(file.node_key_id, "node_key_id")?,
            "sdwan_private_transit.node_key_id",
        )?),
        node_pool_id: NodePoolId(decode_fixed_id(
            &required(file.node_pool_id, "node_pool_id")?,
            "sdwan_private_transit.node_pool_id",
        )?),
        node_attachment_id: AttachmentId(decode_fixed_id(
            &required(file.node_attachment_id, "node_attachment_id")?,
            "sdwan_private_transit.node_attachment_id",
        )?),
        node_attachment_epoch,
        effective_mtu,
        fabric_listen,
        node_grant_path,
        node_signing_key_path,
    }))
}

fn build_sdwan_shared_transit_config(
    file: Option<FileSdwanSharedTransit>,
    cloud_auth_enabled: bool,
) -> Result<Option<SdwanSharedTransitConfig>> {
    let Some(file) = file else {
        return Ok(None);
    };
    if !file.enabled {
        anyhow::ensure!(
            file.route_signing_key_id.is_none()
                && file.route_signing_public_key.is_none()
                && file.node_id.is_none()
                && file.node_key_id.is_none()
                && file.node_pool_id.is_none()
                && file.domains.is_empty(),
            "sdwan_shared_transit fields require sdwan_shared_transit.enabled = true"
        );
        return Ok(None);
    }
    anyhow::ensure!(
        cloud_auth_enabled,
        "sdwan_shared_transit.enabled requires cloud_auth.enabled = true"
    );
    anyhow::ensure!(
        !file.domains.is_empty() && file.domains.len() <= 256,
        "sdwan_shared_transit.domains must contain between 1 and 256 entries"
    );
    let required = |value: Option<String>, name: &str| {
        value.ok_or_else(|| anyhow::anyhow!("sdwan_shared_transit.{name} is required when enabled"))
    };
    let key_id = required(file.route_signing_key_id, "route_signing_key_id")?;
    anyhow::ensure!(
        !key_id.is_empty() && key_id.len() <= MAX_ROUTE_SIGNING_KEY_ID_LEN,
        "sdwan_shared_transit.route_signing_key_id length is invalid"
    );
    let public_key = decode_32_byte_key(
        &required(file.route_signing_public_key, "route_signing_public_key")?,
        "sdwan_shared_transit.route_signing_public_key",
    )?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|_| anyhow::anyhow!("sdwan_shared_transit.route_signing_public_key is invalid"))?;
    let trust = RouteTrustStore::new([(key_id.into_bytes(), verifying_key)])?;
    let mut projection_paths = std::collections::HashSet::new();
    let domains = file
        .domains
        .into_iter()
        .map(|domain| {
            anyhow::ensure!(
                !domain.projection_files.is_empty() && domain.projection_files.len() <= 1024,
                "each shared Transit domain requires between 1 and 1024 projections"
            );
            anyhow::ensure!(
                domain.node_attachment_epoch > 0,
                "shared Transit node_attachment_epoch must be nonzero"
            );
            anyhow::ensure!(
                (candy_proto::ip_tunnel::IPV4_MIN_INNER_MTU..=1500).contains(&domain.effective_mtu),
                "shared Transit effective_mtu is invalid"
            );
            for path in &domain.projection_files {
                anyhow::ensure!(
                    projection_paths.insert(path.clone()),
                    "shared Transit projection_file is duplicated"
                );
            }
            Ok(SdwanSharedTransitDomainConfig {
                snapshot_path: domain.snapshot_file,
                projection_paths: domain.projection_files,
                admission_path: domain.shared_hub_admission_file,
                dynamic_route_path: domain.dynamic_route_snapshot_file,
                node_attachment_id: AttachmentId(decode_fixed_id(
                    &domain.node_attachment_id,
                    "sdwan_shared_transit.node_attachment_id",
                )?),
                node_attachment_epoch: domain.node_attachment_epoch,
                effective_mtu: domain.effective_mtu,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(SdwanSharedTransitConfig {
        trust,
        node_id: NodeId(decode_fixed_id(
            &required(file.node_id, "node_id")?,
            "sdwan_shared_transit.node_id",
        )?),
        node_key_id: NodeKeyId(decode_fixed_id(
            &required(file.node_key_id, "node_key_id")?,
            "sdwan_shared_transit.node_key_id",
        )?),
        node_pool_id: NodePoolId(decode_fixed_id(
            &required(file.node_pool_id, "node_pool_id")?,
            "sdwan_shared_transit.node_pool_id",
        )?),
        domains,
    }))
}

fn parse_netd_prefix(value: &str) -> Result<NetdIpv4Prefix> {
    let (network, prefix_len) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("sdwan_tun exclusion must use IPv4 CIDR syntax"))?;
    anyhow::ensure!(
        !prefix_len.contains('/'),
        "sdwan_tun exclusion must use IPv4 CIDR syntax"
    );
    NetdIpv4Prefix::new(
        network.parse::<Ipv4Addr>()?.octets(),
        prefix_len.parse::<u8>()?,
    )
    .map_err(anyhow::Error::new)
}

fn decode_fixed_id(value: &str, name: &str) -> Result<[u8; 16]> {
    let value = value.trim();
    let valid = match value.len() {
        32 => value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        36 => value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        }),
        _ => false,
    };
    anyhow::ensure!(
        valid,
        "{name} must be a canonical UUID or 32-character hex ID"
    );
    let compact = value.replace('-', "");
    let mut decoded = [0u8; 16];
    for (output, pair) in decoded.iter_mut().zip(compact.as_bytes().chunks_exact(2)) {
        let high = (pair[0] as char).to_digit(16).expect("validated hex");
        let low = (pair[1] as char).to_digit(16).expect("validated hex");
        *output = ((high << 4) | low) as u8;
    }
    anyhow::ensure!(decoded != [0; 16], "{name} must not be zero");
    Ok(decoded)
}

fn load_server_ech(file: FileEch) -> Result<ServerEchConfig> {
    match (file.directory, file.config_file, file.private_key_file) {
        (Some(directory), None, None) => {
            ServerEchConfig::from_keys(load_ech_directory(&directory)?, file.retry_config)
        }
        (None, Some(config_file), Some(private_key_file)) => {
            let config =
                read_regular_file(&config_file, MAX_ECH_CONFIG_BYTES, false).map_err(|error| {
                    anyhow::anyhow!("invalid ECH config file {config_file:?}: {error}")
                })?;
            let private_key = read_regular_file(&private_key_file, ECH_PRIVATE_KEY_BYTES, true)
                .map_err(|error| {
                    anyhow::anyhow!("invalid ECH private key file {private_key_file:?}: {error}")
                })?;
            ServerEchConfig::new(config, private_key, file.retry_config)
        }
        _ => {
            anyhow::bail!("ECH requires either directory, or both config_file and private_key_file")
        }
    }
}

fn load_ech_directory(directory: &Path) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let metadata = std::fs::symlink_metadata(directory)?;
    anyhow::ensure!(metadata.is_dir(), "ECH directory is not a directory");
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "ECH directory must not be a symlink"
    );
    let mut configs = std::fs::read_dir(directory)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "config")
        })
        .collect::<Vec<_>>();
    configs.sort();
    anyhow::ensure!(
        !configs.is_empty(),
        "ECH directory contains no key-*.config files"
    );
    anyhow::ensure!(
        configs.len() <= MAX_ECH_KEYS,
        "ECH directory contains more than 8 keys"
    );
    configs
        .into_iter()
        .map(|config_path| {
            let key_path = config_path.with_extension("key");
            let config =
                read_regular_file(&config_path, MAX_ECH_CONFIG_BYTES, false).map_err(|error| {
                    anyhow::anyhow!("invalid ECH config file {config_path:?}: {error}")
                })?;
            let private_key =
                read_regular_file(&key_path, ECH_PRIVATE_KEY_BYTES, true).map_err(|error| {
                    anyhow::anyhow!("invalid ECH private key file {key_path:?}: {error}")
                })?;
            Ok((config, private_key))
        })
        .collect()
}

pub struct EchInitReport {
    pub config_id: u8,
    pub config_list_file: PathBuf,
    pub dns_ech_value: String,
    pub key_count: usize,
}

pub fn initialize_or_rotate_ech(directory: &Path, public_name: &str) -> Result<EchInitReport> {
    use base64::Engine;
    use rand::RngCore;
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use x25519_dalek::{PublicKey, StaticSecret};

    validate_ech_public_name(public_name)?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(directory)?;
    let directory_metadata = std::fs::symlink_metadata(directory)?;
    anyhow::ensure!(directory_metadata.is_dir(), "ECH path is not a directory");
    anyhow::ensure!(
        !directory_metadata.file_type().is_symlink(),
        "ECH directory must not be a symlink"
    );

    let public_name_file = directory.join("public-name.txt");
    if public_name_file.exists() {
        let existing = std::fs::read_to_string(&public_name_file)?;
        anyhow::ensure!(
            existing.trim() == public_name,
            "ECH directory belongs to public name {:?}",
            existing.trim()
        );
    } else {
        write_new_file(&public_name_file, 0o644, public_name.as_bytes())?;
    }

    let existing = load_ech_public_configs(directory)?;
    anyhow::ensure!(
        existing.len() < MAX_ECH_KEYS,
        "ECH directory already has 8 keys; retire an old key before rotating"
    );
    let mut rng = rand::rngs::OsRng;
    let (config_id, config_path, key_path) = loop {
        let id = (rng.next_u32() & 0xff) as u8;
        let stem = format!("key-{id:02x}");
        let config_path = directory.join(format!("{stem}.config"));
        let key_path = directory.join(format!("{stem}.key"));
        if !config_path.exists() && !key_path.exists() {
            break (id, config_path, key_path);
        }
    };
    let secret = StaticSecret::random_from_rng(rng);
    let public = PublicKey::from(&secret);
    let config = marshal_ech_config(config_id, public.as_bytes(), public_name)?;
    write_new_file(&key_path, 0o600, secret.as_bytes())?;
    if let Err(error) = write_new_file(&config_path, 0o644, &config) {
        let _ = std::fs::remove_file(&key_path);
        return Err(error);
    }

    let mut all_configs = existing
        .into_iter()
        .map(|(_, config)| config)
        .collect::<Vec<_>>();
    all_configs.push(config);
    let config_list = marshal_ech_config_list(&all_configs)?;
    let list_path = directory.join("ech-config-list.bin");
    let temporary_path = directory.join(".ech-config-list.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o644);
    let mut file = options.open(&temporary_path)?;
    file.write_all(&config_list)?;
    file.sync_all()?;
    std::fs::rename(&temporary_path, &list_path)?;

    Ok(EchInitReport {
        config_id,
        config_list_file: list_path,
        dns_ech_value: base64::engine::general_purpose::STANDARD.encode(config_list),
        key_count: all_configs.len(),
    })
}

fn load_ech_public_configs(directory: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut paths = std::fs::read_dir(directory)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "config")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let config = read_regular_file(&path, MAX_ECH_CONFIG_BYTES, false)?;
            Ok((path, config))
        })
        .collect()
}

pub fn retire_ech_key(directory: &Path, config_id: u8) -> Result<EchInitReport> {
    use base64::Engine;
    use std::io::Write;

    let config_path = directory.join(format!("key-{config_id:02x}.config"));
    let key_path = directory.join(format!("key-{config_id:02x}.key"));
    anyhow::ensure!(
        config_path.is_file() && key_path.is_file(),
        "ECH key {config_id:02x} does not exist"
    );
    let configs = load_ech_public_configs(directory)?;
    anyhow::ensure!(configs.len() > 1, "cannot retire the only ECH key");
    let remaining = configs
        .into_iter()
        .filter(|(path, _)| path != &config_path)
        .map(|(_, config)| config)
        .collect::<Vec<_>>();
    anyhow::ensure!(!remaining.is_empty(), "cannot retire the only ECH key");
    let config_list = marshal_ech_config_list(&remaining)?;
    let list_path = directory.join("ech-config-list.bin");
    let temporary_path = directory.join(".ech-config-list.tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary_path)?;
    file.write_all(&config_list)?;
    file.sync_all()?;
    std::fs::rename(&temporary_path, &list_path)?;
    std::fs::remove_file(config_path)?;
    std::fs::remove_file(key_path)?;
    Ok(EchInitReport {
        config_id,
        config_list_file: list_path,
        dns_ech_value: base64::engine::general_purpose::STANDARD.encode(config_list),
        key_count: remaining.len(),
    })
}

fn write_new_file(path: &Path, mode: u32, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn validate_ech_public_name(public_name: &str) -> Result<()> {
    anyhow::ensure!(
        !public_name.is_empty() && public_name.len() <= 253,
        "ECH public name must be 1..=253 bytes"
    );
    anyhow::ensure!(
        public_name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }),
        "ECH public name must be a valid ASCII DNS name"
    );
    Ok(())
}

fn marshal_ech_config(config_id: u8, public_key: &[u8; 32], public_name: &str) -> Result<Vec<u8>> {
    let mut contents = Vec::with_capacity(58 + public_name.len());
    contents.push(config_id);
    contents.extend_from_slice(&0x0020u16.to_be_bytes());
    contents.extend_from_slice(&32u16.to_be_bytes());
    contents.extend_from_slice(public_key);
    contents.extend_from_slice(&8u16.to_be_bytes());
    contents.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03]);
    contents.push(0);
    contents.push(public_name.len() as u8);
    contents.extend_from_slice(public_name.as_bytes());
    contents.extend_from_slice(&0u16.to_be_bytes());
    anyhow::ensure!(
        contents.len() <= u16::MAX as usize,
        "ECH config is too large"
    );
    let mut config = Vec::with_capacity(contents.len() + 4);
    config.extend_from_slice(&0xfe0du16.to_be_bytes());
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);
    Ok(config)
}

fn marshal_ech_config_list(configs: &[Vec<u8>]) -> Result<Vec<u8>> {
    let content_len = configs
        .iter()
        .try_fold(0usize, |total, config| total.checked_add(config.len()))
        .ok_or_else(|| anyhow::anyhow!("ECH config list length overflow"))?;
    anyhow::ensure!(
        content_len <= u16::MAX as usize,
        "ECH config list is too large"
    );
    let mut list = Vec::with_capacity(content_len + 2);
    list.extend_from_slice(&(content_len as u16).to_be_bytes());
    for config in configs {
        list.extend_from_slice(config);
    }
    Ok(list)
}

fn read_regular_file(path: &Path, max_bytes: usize, private: bool) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "path is not a regular file");
    anyhow::ensure!(
        metadata.len() <= max_bytes as u64,
        "file exceeds {max_bytes} bytes"
    );
    if private {
        anyhow::ensure!(
            metadata.mode() & 0o077 == 0,
            "file permissions must not grant group or other access"
        );
    }

    let capacity = usize::try_from(metadata.len())
        .unwrap_or(max_bytes)
        .min(max_bytes);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= max_bytes, "file exceeds {max_bytes} bytes");
    Ok(bytes)
}

fn build_transport_profile(file: FileTransport) -> Result<CandyTransportProfile> {
    let mut profile = match file
        .profile
        .unwrap_or(ServerTransportProfile::ServerStandard)
    {
        ServerTransportProfile::ServerStandard => CandyTransportProfile::for_server(),
    };
    if let Some(value) = file.keep_alive_seconds {
        profile.keep_alive = Some(Duration::from_secs(value));
    }
    if let Some(value) = file.idle_timeout_seconds {
        profile.idle_timeout = Duration::from_secs(value);
    }
    if let Some(value) = file.stream_receive_window_mib {
        profile.stream_receive_window = transport_mib(value, "stream_receive_window_mib")?;
    }
    if let Some(value) = file.connection_receive_window_mib {
        profile.connection_receive_window = transport_mib(value, "connection_receive_window_mib")?;
    }
    if let Some(value) = file.send_window_mib {
        profile.send_window = transport_mib(value, "send_window_mib")?;
    }
    if let Some(value) = file.initial_incoming_bidi {
        anyhow::ensure!(
            value == 1,
            "initial_incoming_bidi must be 1 for the control stream"
        );
    }
    if let Some(value) = file.incoming_uni {
        profile.incoming_uni = value;
    }
    if let Some(value) = file.datagram_receive_buffer_mib {
        profile.datagram_receive_buffer =
            usize::try_from(transport_mib(value, "datagram_receive_buffer_mib")?)
                .map_err(|_| anyhow::anyhow!("datagram_receive_buffer_mib exceeds usize"))?;
    }
    if let Some(value) = file.datagram_send_buffer_mib {
        profile.datagram_send_buffer =
            usize::try_from(transport_mib(value, "datagram_send_buffer_mib")?)
                .map_err(|_| anyhow::anyhow!("datagram_send_buffer_mib exceeds usize"))?;
    }
    if let Some(value) = file.congestion {
        profile.congestion = value;
    }
    if let Some(value) = file.stream_priority_enabled {
        profile.stream_priority_enabled = value;
    }
    Ok(profile)
}

fn transport_mib(value: u64, field: &str) -> Result<u64> {
    value
        .checked_mul(MIB)
        .ok_or_else(|| anyhow::anyhow!("{field} MiB overflow"))
}

fn load_calibration(
    path: Option<&Path>,
    current_server_sha256: &str,
    current_transport_profile_sha256: &str,
) -> CalibrationEvidence {
    let Some(path) = path else {
        return CalibrationEvidence::Unavailable("memory-calibration-missing".into());
    };
    let bytes = match read_calibration_file_with_hook(path, || {}) {
        Ok(bytes) => bytes,
        Err(CalibrationFileReadError::Missing) => {
            return CalibrationEvidence::Unavailable("memory-calibration-missing".into())
        }
        Err(CalibrationFileReadError::Invalid) => {
            return CalibrationEvidence::Unavailable("memory-calibration-invalid".into())
        }
    };
    let envelope = match serde_json::from_slice::<BenchmarkCalibrationEnvelope>(&bytes) {
        Ok(envelope) => envelope,
        Err(_) => return CalibrationEvidence::Unavailable("memory-calibration-invalid".into()),
    };
    let report = envelope.memory_calibration;
    if envelope.schema_version != 3
        || report.schema_version != 1
        || report.benchmark_schema_version != 3
        || report.sample_seconds < 900
        || report.server_fixed_bytes_per_connection == 0
    {
        return CalibrationEvidence::Unavailable("memory-calibration-stale-schema".into());
    }
    if report.server_sha256 != current_server_sha256
        || report.transport_profile_sha256 != current_transport_profile_sha256
        || !is_sha256_hex(&report.matrix_sha256)
    {
        return CalibrationEvidence::Unavailable("memory-calibration-stale-hash".into());
    }
    CalibrationEvidence::Verified(MemoryCalibration {
        benchmark_schema_version: report.benchmark_schema_version,
        measured_fixed_bytes_per_connection: report.server_fixed_bytes_per_connection,
    })
}

#[derive(Debug)]
enum CalibrationFileReadError {
    Missing,
    Invalid,
}

fn read_calibration_file_with_hook(
    path: &Path,
    after_open: impl FnOnce(),
) -> Result<Vec<u8>, CalibrationFileReadError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CalibrationFileReadError::Missing
        } else {
            CalibrationFileReadError::Invalid
        }
    })?;
    after_open();

    let metadata = file
        .metadata()
        .map_err(|_| CalibrationFileReadError::Invalid)?;
    if !metadata.is_file() || metadata.len() > MAX_CALIBRATION_REPORT_BYTES as u64 {
        return Err(CalibrationFileReadError::Invalid);
    }

    let capacity = usize::try_from(metadata.len())
        .unwrap_or(MAX_CALIBRATION_REPORT_BYTES)
        .min(MAX_CALIBRATION_REPORT_BYTES);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take((MAX_CALIBRATION_REPORT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CalibrationFileReadError::Invalid)?;
    if bytes.len() > MAX_CALIBRATION_REPORT_BYTES {
        return Err(CalibrationFileReadError::Invalid);
    }
    Ok(bytes)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn feature_bits(names: &[String]) -> FeatureSet {
    let mut bits = 0u64;
    for n in names {
        match n.as_str() {
            "recommended" => {
                bits |= FeatureSet::DATAGRAM
                    | FeatureSet::STREAM_UDP_FALLBACK
                    | FeatureSet::METRICS_V1
                    | FeatureSet::POST_AUTH_CAPS_V1
                    | FeatureSet::EARLY_DATA_STREAM_V1
                    | FeatureSet::FRAGMENTED_DATAGRAM_V1
                    | FeatureSet::UDP_FEC_V1;
            }
            "datagram" => bits |= FeatureSet::DATAGRAM,
            "stream_udp_fallback" => bits |= FeatureSet::STREAM_UDP_FALLBACK,
            "metrics_v1" => bits |= FeatureSet::METRICS_V1,
            "post_auth_caps_v1" => bits |= FeatureSet::POST_AUTH_CAPS_V1,
            "early_data_stream_v1" => bits |= FeatureSet::EARLY_DATA_STREAM_V1,
            "adaptive_policy_v1" => bits |= FeatureSet::ADAPTIVE_POLICY_V1,
            "fragmented_datagram_v1" => bits |= FeatureSet::FRAGMENTED_DATAGRAM_V1,
            "udp_fec_v1" => bits |= FeatureSet::UDP_FEC_V1,
            other => tracing::warn!(feature = other, "unknown feature in config, ignoring"),
        }
    }
    FeatureSet::from_bits(bits)
}

fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    decode_32_byte_key(value, "cloud_auth.cloud_signing_public_key")
}

fn decode_32_byte_key(value: &str, name: &str) -> Result<[u8; 32]> {
    let value = value.trim();
    let decoded = if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut bytes = Vec::with_capacity(32);
        for pair in value.as_bytes().chunks_exact(2) {
            let high = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| anyhow::anyhow!("invalid {name} hex"))?;
            let low = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| anyhow::anyhow!("invalid {name} hex"))?;
            bytes.push(((high << 4) | low) as u8);
        }
        bytes
    } else {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| anyhow::anyhow!("{name} must be base64 or 64-character hex"))?
    };
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must decode to exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrier_transport::config::{CandyTransportProfile, CongestionChoice, MIB};
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn feature_bits_maps_control_feature_names() {
        let names = [
            "metrics_v1".to_string(),
            "post_auth_caps_v1".to_string(),
            "early_data_stream_v1".to_string(),
            "adaptive_policy_v1".to_string(),
            "fragmented_datagram_v1".to_string(),
            "udp_fec_v1".to_string(),
        ];

        assert_eq!(
            feature_bits(&names).bits(),
            FeatureSet::METRICS_V1
                | FeatureSet::POST_AUTH_CAPS_V1
                | FeatureSet::EARLY_DATA_STREAM_V1
                | FeatureSet::ADAPTIVE_POLICY_V1
                | FeatureSet::FRAGMENTED_DATAGRAM_V1
                | FeatureSet::UDP_FEC_V1
        );
    }

    #[test]
    fn recommended_feature_preset_enables_automatic_fragmentation_and_fec() {
        let recommended = feature_bits(&["recommended".to_string()]);

        assert!(recommended.contains(FeatureSet::FRAGMENTED_DATAGRAM_V1));
        assert!(recommended.contains(FeatureSet::UDP_FEC_V1));
        assert!(recommended.contains(FeatureSet::DATAGRAM));
        assert!(recommended.contains(FeatureSet::STREAM_UDP_FALLBACK));
    }

    #[test]
    fn feature_bits_combines_legacy_names_and_ignores_unknown_names() {
        let names = [
            "datagram".to_string(),
            "unknown".to_string(),
            "stream_udp_fallback".to_string(),
            "post_auth_caps_v1".to_string(),
        ];

        assert_eq!(
            feature_bits(&names).bits(),
            FeatureSet::DATAGRAM | FeatureSet::STREAM_UDP_FALLBACK | FeatureSet::POST_AUTH_CAPS_V1
        );
    }

    fn config_without_certificate_opt_in() -> String {
        r#"
listen = "127.0.0.1:0"

[[users]]
key_id = "alice"
secret = "alice-secret-value"
features = ["datagram", "metrics_v1"]

[limits]
max_sessions_per_connection = 64
max_udp_flows = 32
max_datagram_size = 1200
"#
        .to_string()
    }

    fn valid_config() -> String {
        config_without_certificate_opt_in().replace(
            "listen = \"127.0.0.1:0\"",
            "listen = \"127.0.0.1:0\"\ndevelopment_ephemeral_certificate = true",
        )
    }

    fn valid_sdwan_config() -> String {
        let route_key = SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!(
            r#"
listen = "127.0.0.1:0"
development_ephemeral_certificate = true

[admission]
max_connections = 1

[cloud_auth]
enabled = true
cloud_signing_public_key = "{cloud_key}"

[sdwan_tun]
enabled = true
snapshot_file = "/var/lib/candy/segment.snapshot"
projection_file = "/var/lib/candy/site.projection"
route_signing_key_id = "route-key-1"
route_signing_public_key = "{route_key}"
tenant_id = "01010101-0101-0101-0101-010101010101"
node_id = "02020202-0202-0202-0202-020202020202"
node_key_id = "03030303-0303-0303-0303-030303030303"
node_pool_id = "04040404-0404-0404-0404-040404040404"
node_attachment_id = "05050505-0505-0505-0505-050505050505"
node_attachment_epoch = 3
netd_socket = "/run/candy/netd.sock"
table_id = 20001

[[sdwan_tun.underlay_exclusions]]
kind = "cloud-api"
prefix = "192.0.2.1/32"

[[sdwan_tun.underlay_exclusions]]
kind = "hub-endpoint"
prefix = "192.0.2.2/32"

[[sdwan_tun.underlay_exclusions]]
kind = "management"
prefix = "192.0.2.3/32"
"#,
            cloud_key = "11".repeat(32),
        )
    }

    fn valid_shared_transit_config() -> String {
        let route_key = SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!(
            r#"
listen = "127.0.0.1:0"
development_ephemeral_certificate = true

[admission]
max_connections = 64

[cloud_auth]
enabled = true
cloud_signing_public_key = "{cloud_key}"

[sdwan_shared_transit]
enabled = true
route_signing_key_id = "route-key-1"
route_signing_public_key = "{route_key}"
node_id = "02020202-0202-0202-0202-020202020202"
node_key_id = "03030303-0303-0303-0303-030303030303"
node_pool_id = "04040404-0404-0404-0404-040404040404"

[[sdwan_shared_transit.domains]]
snapshot_file = "/var/lib/candy/shared/segment.snapshot"
projection_files = ["/var/lib/candy/shared/site-a.projection", "/var/lib/candy/shared/site-b.projection"]
shared_hub_admission_file = "/var/lib/candy/shared/hub.admission"
node_attachment_id = "05050505-0505-0505-0505-050505050505"
node_attachment_epoch = 3
effective_mtu = 1180
"#,
            cloud_key = "11".repeat(32),
        )
    }

    fn valid_private_transit_config() -> String {
        let route_key = SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!(
            r#"
listen = "127.0.0.1:0"
development_ephemeral_certificate = true

[admission]
max_connections = 64

[cloud_auth]
enabled = true
cloud_signing_public_key = "{cloud_key}"

[sdwan_private_transit]
enabled = true
route_signing_key_id = "route-key-1"
route_signing_public_key = "{route_key}"
snapshot_file = "/var/lib/candy/private/segment.snapshot"
projection_files = ["/var/lib/candy/private/site-a.projection", "/var/lib/candy/private/site-b.projection"]
fabric_assignment_file = "/var/lib/candy/private/fabric.assignment"
node_id = "02020202-0202-0202-0202-020202020202"
node_key_id = "03030303-0303-0303-0303-030303030303"
node_pool_id = "04040404-0404-0404-0404-040404040404"
node_attachment_id = "05050505-0505-0505-0505-050505050505"
node_attachment_epoch = 3
effective_mtu = 1180
fabric_listen = "127.0.0.1:7444"
node_grant_file = "/var/lib/candy/private/node.grant"
node_signing_key_file = "/var/lib/candy/private/node.key"
"#,
            cloud_key = "11".repeat(32),
        )
    }

    fn with_root_config(config: &str, root: &str) -> String {
        config.replace(
            "development_ephemeral_certificate = true",
            &format!("development_ephemeral_certificate = true\n{root}"),
        )
    }

    fn with_max_connections(config: &str, max_connections: usize) -> String {
        config.replace(
            "[limits]",
            &format!("[admission]\nmax_connections = {max_connections}\n\n[limits]"),
        )
    }

    fn temp_report_path(label: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "candy-serverd-{label}-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn decode_hex_fixture(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                ((high << 4) | low) as u8
            })
            .collect()
    }

    #[test]
    fn signed_policy_cache_reloads_atomically_and_redacts_debug() {
        #[derive(serde::Deserialize)]
        struct RouteVector {
            verifying_key_hex: String,
            segment_envelope_hex: String,
            projection_envelope_hex: String,
        }

        let vector: RouteVector = serde_json::from_str(include_str!(
            "../../../interop/vectors/candy-sdwan-route-contract-v1.json"
        ))
        .unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            &decode_hex_fixture(&vector.verifying_key_hex)
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let trust = RouteTrustStore::new([(b"route-key-1".to_vec(), verifying_key)]).unwrap();
        let snapshot_path = temp_report_path("segment-snapshot");
        let projection_path = temp_report_path("site-projection");
        std::fs::write(
            &snapshot_path,
            decode_hex_fixture(&vector.segment_envelope_hex),
        )
        .unwrap();
        std::fs::write(
            &projection_path,
            decode_hex_fixture(&vector.projection_envelope_hex),
        )
        .unwrap();

        let mut cache = HubSignedPolicyCache::load_files(
            &snapshot_path,
            &projection_path,
            &trust,
            1_800_000_100,
        )
        .unwrap();
        assert_eq!(cache.current().current().snapshot().generation(), 1);
        assert_eq!(cache.current().current().projection().generation(), 1);
        let snapshot = cache.current().current().snapshot();
        let node_attachment = snapshot
            .object()
            .attachments
            .iter()
            .find(|attachment| {
                matches!(
                    attachment.principal,
                    candy_proto::route_contract::AttachmentPrincipalV1::Node { .. }
                )
            })
            .unwrap();
        let adapter = attached_hub_adapter(
            snapshot,
            None,
            node_attachment.attachment_id,
            node_attachment.epoch_floor,
            7,
            1180,
        )
        .unwrap();
        assert_eq!(
            adapter.local_context(),
            Some(PacketContext {
                tunnel_id: 7,
                attachment_id: node_attachment.attachment_id,
                attachment_epoch: node_attachment.epoch_floor,
            })
        );
        let debug = format!("{cache:?}");
        assert!(!debug.contains("route-key-1"));
        assert!(!debug.contains(&vector.segment_envelope_hex));

        std::fs::write(&projection_path, b"not-a-signed-envelope").unwrap();
        assert!(cache
            .reload_files(&snapshot_path, &projection_path, &trust, 1_800_000_101,)
            .is_err());
        assert_eq!(cache.current().current().snapshot().generation(), 1);
        assert_eq!(cache.current().current().projection().generation(), 1);

        std::fs::remove_file(snapshot_path).unwrap();
        std::fs::remove_file(projection_path).unwrap();
    }

    #[test]
    fn expansion_policy_files_bind_the_current_hub_snapshot_and_site() {
        use candy_proto::dynamic_route_contract::{DynamicRouteSnapshotV1, DynamicRouteV1};
        use candy_proto::mesh_contract::{MeshMembershipProjectionV1, MeshPeerRefV1};
        use candy_proto::shared_hub_contract::{SharedHubAdmissionPolicyV1, SharedHubQuotaV1};
        use carrier_crypto::route_contract::{
            seal_dynamic_route_snapshot, seal_mesh_membership, seal_shared_hub_admission,
        };

        #[derive(serde::Deserialize)]
        struct RouteVector {
            segment_envelope_hex: String,
            projection_envelope_hex: String,
        }
        let vector: RouteVector = serde_json::from_str(include_str!(
            "../../../interop/vectors/candy-sdwan-route-contract-v1.json"
        ))
        .unwrap();
        let key = SigningKey::from_bytes(&[0x77; 32]);
        let trust = RouteTrustStore::new([(b"route-key-1".to_vec(), key.verifying_key())]).unwrap();
        let snapshot_path = temp_report_path("expansion-segment");
        let projection_path = temp_report_path("expansion-site");
        let shared_path = temp_report_path("shared-hub-admission");
        let mesh_path = temp_report_path("mesh-membership");
        let dynamic_path = temp_report_path("dynamic-routes");
        std::fs::write(
            &snapshot_path,
            decode_hex_fixture(&vector.segment_envelope_hex),
        )
        .unwrap();
        std::fs::write(
            &projection_path,
            decode_hex_fixture(&vector.projection_envelope_hex),
        )
        .unwrap();
        let control = HubSignedPolicyCache::load_files(
            &snapshot_path,
            &projection_path,
            &trust,
            1_800_000_100,
        )
        .unwrap();
        let snapshot = control.current().current().snapshot().object();
        let projection = control.current().current().projection().object();
        let quota = |entities| SharedHubQuotaV1 {
            max_entities: entities,
            max_queue_packets: 1024,
            max_queue_bytes: 1024 * 1024,
            packets_per_second: 10_000,
            bytes_per_second: 10_000_000,
            burst_packets: 1_000,
            burst_bytes: 1_000_000,
        };
        let shared = seal_shared_hub_admission(
            SharedHubAdmissionPolicyV1 {
                node_id: NodeId([0x50; 16]),
                node_key_id: NodeKeyId([0x51; 16]),
                node_pool_id: NodePoolId([3; 16]),
                tenant_id: snapshot.tenant_id,
                segment_id: snapshot.segment_id,
                segment_generation: snapshot.segment_generation,
                segment_content_hash: snapshot.content_hash,
                policy_id: candy_proto::cloud_grant::PolicyId([70; 16]),
                policy_generation: 1,
                not_before: 1_800_000_000,
                expires_at: 1_800_003_600,
                stale_until: 1_800_007_200,
                previous_hash: [0; 32],
                node: quota(64),
                tenant: quota(32),
                site: quota(16),
                tunnel: quota(1),
                content_hash: [0; 32],
            },
            b"route-key-1".to_vec(),
            &key,
        )
        .unwrap();
        std::fs::write(&shared_path, shared.envelope.encode().unwrap()).unwrap();
        let mesh = seal_mesh_membership(
            MeshMembershipProjectionV1 {
                tenant_id: snapshot.tenant_id,
                segment_id: snapshot.segment_id,
                segment_generation: snapshot.segment_generation,
                segment_content_hash: snapshot.content_hash,
                local_site_id: projection.site_id,
                local_attachment_id: projection.attachment_id,
                peers: vec![MeshPeerRefV1 {
                    site_id: candy_proto::ip_tunnel::SiteId([21; 16]),
                    attachment_id: AttachmentId([11; 16]),
                    epoch_floor: 1,
                }],
                projection_id: candy_proto::cloud_grant::PolicyId([71; 16]),
                projection_generation: 1,
                not_before: 1_800_000_000,
                expires_at: 1_800_003_600,
                stale_until: 1_800_007_200,
                previous_hash: [0; 32],
                content_hash: [0; 32],
            },
            b"route-key-1".to_vec(),
            &key,
        )
        .unwrap();
        std::fs::write(&mesh_path, mesh.envelope.encode().unwrap()).unwrap();
        let dynamic = seal_dynamic_route_snapshot(
            DynamicRouteSnapshotV1 {
                tenant_id: snapshot.tenant_id,
                segment_id: snapshot.segment_id,
                base_segment_generation: snapshot.segment_generation,
                base_segment_content_hash: snapshot.content_hash,
                routes: vec![DynamicRouteV1 {
                    prefix: candy_proto::route_contract::Ipv4PrefixV1::new([10, 2, 0, 0], 24)
                        .unwrap(),
                    owner_site_id: candy_proto::ip_tunnel::SiteId([0x21; 16]),
                    owner_attachment_id: AttachmentId([0x11; 16]),
                    metric: 100,
                }],
                policy_id: candy_proto::cloud_grant::PolicyId([72; 16]),
                generation: 1,
                not_before: 1_800_000_000,
                expires_at: 1_800_003_600,
                stale_until: 1_800_007_200,
                previous_hash: [0; 32],
                content_hash: [0; 32],
            },
            b"route-key-1".to_vec(),
            &key,
        )
        .unwrap();
        std::fs::write(&dynamic_path, dynamic.envelope.encode().unwrap()).unwrap();
        let config = SdwanTunConfig {
            snapshot_path: snapshot_path.clone(),
            projection_path: projection_path.clone(),
            shared_hub_admission_path: Some(shared_path.clone()),
            mesh_membership_path: Some(mesh_path.clone()),
            dynamic_route_snapshot_path: Some(dynamic_path.clone()),
            trust: trust.clone(),
            hub: candy_tun::control::HubNodeContext {
                tenant_id: snapshot.tenant_id,
                node_id: NodeId([0x50; 16]),
                node_key_id: NodeKeyId([0x51; 16]),
                node_pool_id: NodePoolId([3; 16]),
                service_class: ServiceClass::CandyDedicated,
            },
            node_attachment_id: AttachmentId([0x12; 16]),
            node_attachment_epoch: 3,
            netd_socket: PathBuf::from("/run/candy/netd.sock"),
            table_id: CANDY_TABLE_MIN,
            exclusions: Vec::new(),
        };
        let expansion = VerifiedExpansionPolicies::load(&config, control.current()).unwrap();
        assert!(expansion
            .validate(&config, control.current(), 1_800_000_100)
            .unwrap()
            .is_some());
        assert_eq!(expansion.dynamic_routes.as_ref().unwrap().routes().len(), 3);

        let shared_config = SdwanSharedTransitConfig {
            trust,
            node_id: NodeId([0x50; 16]),
            node_key_id: NodeKeyId([0x51; 16]),
            node_pool_id: NodePoolId([3; 16]),
            domains: vec![SdwanSharedTransitDomainConfig {
                snapshot_path: snapshot_path.clone(),
                projection_paths: vec![projection_path.clone()],
                admission_path: shared_path.clone(),
                dynamic_route_path: Some(dynamic_path.clone()),
                node_attachment_id: AttachmentId([0x12; 16]),
                node_attachment_epoch: 3,
                effective_mtu: 1180,
            }],
        };
        let shared_catalog =
            LoadedSharedTransitCatalog::load(&shared_config, 1_800_000_100).unwrap();
        assert_eq!(shared_catalog.controls.len(), 1);
        let (_driver, _handle) = SharedTransitHubDriver::new_dynamic_from_verified_catalog(
            VerifiedSharedTransitNodeContext {
                node_id: shared_config.node_id,
                node_key_id: shared_config.node_key_id,
                node_pool_id: shared_config.node_pool_id,
                now_unix: 1_800_000_100,
                runtime_now: Duration::ZERO,
            },
            shared_catalog.runtime_domains(),
            SharedTransitDriverLimits::default(),
        )
        .unwrap();

        for path in [
            snapshot_path,
            projection_path,
            shared_path,
            mesh_path,
            dynamic_path,
        ] {
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn private_transit_runtime_requires_signed_complete_fabric_assignment() {
        use candy_proto::fabric_assignment_contract::{
            FabricAttachmentAssignmentV1, HubFabricAssignmentV1,
        };
        use candy_proto::route_contract::AttachmentPrincipalV1;
        use carrier_crypto::route_contract::seal_fabric_assignment;

        #[derive(serde::Deserialize)]
        struct RouteVector {
            segment_envelope_hex: String,
            projection_envelope_hex: String,
        }
        let vector: RouteVector = serde_json::from_str(include_str!(
            "../../../interop/vectors/candy-sdwan-route-contract-v1.json"
        ))
        .unwrap();
        let key = SigningKey::from_bytes(&[0x77; 32]);
        let trust = RouteTrustStore::new([(b"route-key-1".to_vec(), key.verifying_key())]).unwrap();
        let snapshot_path = temp_report_path("private-transit-segment");
        let projection_path = temp_report_path("private-transit-site");
        let assignment_path = temp_report_path("private-transit-assignment");
        std::fs::write(
            &snapshot_path,
            decode_hex_fixture(&vector.segment_envelope_hex),
        )
        .unwrap();
        std::fs::write(
            &projection_path,
            decode_hex_fixture(&vector.projection_envelope_hex),
        )
        .unwrap();
        let snapshot = VerifiedSegmentSnapshot::verify(
            &load_signed_envelope(&snapshot_path, "test Segment").unwrap(),
            &trust,
        )
        .unwrap();
        let hub = snapshot
            .object()
            .attachments
            .iter()
            .find(|attachment| matches!(attachment.principal, AttachmentPrincipalV1::Node { .. }))
            .unwrap();
        let (hub_node_id, hub_node_key_id) = match hub.principal {
            AttachmentPrincipalV1::Node {
                node_id,
                node_key_id,
            } => (node_id, node_key_id),
            _ => unreachable!(),
        };
        let assignments = snapshot
            .object()
            .attachments
            .iter()
            .filter(|attachment| {
                matches!(attachment.principal, AttachmentPrincipalV1::Device { .. })
            })
            .map(|attachment| FabricAttachmentAssignmentV1 {
                site_id: attachment.site_id.unwrap(),
                attachment_id: attachment.attachment_id,
                hub_node_id,
                hub_node_key_id,
                hub_attachment_id: hub.attachment_id,
                attachment_epoch: attachment.epoch_floor,
            })
            .collect();
        let assignment = HubFabricAssignmentV1 {
            tenant_id: snapshot.object().tenant_id,
            segment_id: snapshot.object().segment_id,
            segment_generation: snapshot.object().segment_generation,
            segment_content_hash: snapshot.object().content_hash,
            assignments,
            policy_id: candy_proto::cloud_grant::PolicyId([99; 16]),
            generation: 1,
            not_before: 1_800_000_000,
            expires_at: 1_800_003_600,
            stale_until: 1_800_007_200,
            previous_hash: [0; 32],
            content_hash: [0; 32],
        };
        let sealed =
            seal_fabric_assignment(assignment.clone(), b"route-key-1".to_vec(), &key).unwrap();
        std::fs::write(&assignment_path, sealed.envelope.encode().unwrap()).unwrap();
        let config = SdwanPrivateTransitConfig {
            trust: trust.clone(),
            snapshot_path: snapshot_path.clone(),
            projection_paths: vec![projection_path.clone()],
            fabric_assignment_path: assignment_path.clone(),
            dynamic_route_path: None,
            node_id: hub_node_id,
            node_key_id: hub_node_key_id,
            node_pool_id: snapshot.object().hub_node_pool_id,
            node_attachment_id: hub.attachment_id,
            node_attachment_epoch: hub.epoch_floor,
            effective_mtu: 1180,
            fabric_listen: "127.0.0.1:7444".parse().unwrap(),
            node_grant_path: std::path::PathBuf::from("/tmp/test-node.grant"),
            node_signing_key_path: std::path::PathBuf::from("/tmp/test-node.key"),
        };
        let loaded = load_private_transit(&config, 1_800_000_100).unwrap();
        assert_eq!(loaded.assignment.object().assignments.len(), 2);

        let mut wrong = assignment;
        wrong.segment_content_hash = [0xff; 32];
        let wrong = seal_fabric_assignment(wrong, b"route-key-1".to_vec(), &key).unwrap();
        std::fs::write(&assignment_path, wrong.envelope.encode().unwrap()).unwrap();
        assert!(load_private_transit(&config, 1_800_000_100).is_err());

        std::fs::remove_file(snapshot_path).unwrap();
        std::fs::remove_file(projection_path).unwrap();
        std::fs::remove_file(assignment_path).unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn write_calibration_report(
        path: &std::path::Path,
        outer_schema: u8,
        memory_schema: u8,
        benchmark_schema: u8,
        server_sha256: &str,
        profile_sha256: &str,
        matrix_sha256: &str,
        fixed_bytes: u64,
        sample_seconds: u64,
    ) {
        let report = serde_json::json!({
            "schema_version": outer_schema,
            "memory_calibration": {
                "schema_version": memory_schema,
                "benchmark_schema_version": benchmark_schema,
                "server_sha256": server_sha256,
                "transport_profile_sha256": profile_sha256,
                "matrix_sha256": matrix_sha256,
                "server_fixed_bytes_per_connection": fixed_bytes,
                "sample_seconds": sample_seconds
            }
        });
        std::fs::write(path, serde_json::to_vec(&report).unwrap()).unwrap();
    }

    fn config_with_report(config: &str, path: &std::path::Path) -> String {
        with_root_config(
            config,
            &format!(
                "transport_memory_calibration_report = {:?}",
                path.to_string_lossy()
            ),
        )
    }

    #[test]
    fn transport_config_rejects_unknown_top_level_and_table_fields() {
        let top_level = with_root_config(&valid_config(), "transport_memory_budget_mb = 2048");
        let err = load_server_config_from_str_with_server_sha256(&top_level, &"1".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(err.contains("transport_memory_budget_mb"), "{err}");

        let table = format!(
            "{}\n[transport]\nstream_receive_window_mb = 4\n",
            valid_config()
        );
        let err = load_server_config_from_str_with_server_sha256(&table, &"1".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(err.contains("stream_receive_window_mb"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn transport_calibration_reader_rejects_oversize_links_fifo_and_devices_without_blocking() {
        use nix::sys::stat::Mode;
        use std::sync::mpsc;

        let server_sha256 = "1".repeat(64);
        let oversized_path = temp_report_path("oversized");
        std::fs::write(&oversized_path, vec![b' '; 1024 * 1024 + 1]).unwrap();
        let oversized = config_with_report(&valid_config(), &oversized_path);
        let loaded =
            load_server_config_from_str_with_server_sha256(&oversized, &server_sha256).unwrap();
        std::fs::remove_file(oversized_path).unwrap();
        assert_eq!(
            loaded.summary.transport_fallback_reason.as_deref(),
            Some("memory-calibration-invalid")
        );

        let target_path = temp_report_path("target");
        let symlink_path = temp_report_path("symlink");
        write_calibration_report(
            &target_path,
            3,
            1,
            3,
            &server_sha256,
            &carrier_transport::transport_profile_sha256(&CandyTransportProfile::for_server())
                .unwrap(),
            &"a".repeat(64),
            4 * MIB,
            900,
        );
        std::os::unix::fs::symlink(&target_path, &symlink_path).unwrap();
        let symlink = config_with_report(&valid_config(), &symlink_path);
        let loaded =
            load_server_config_from_str_with_server_sha256(&symlink, &server_sha256).unwrap();
        std::fs::remove_file(symlink_path).unwrap();
        std::fs::remove_file(target_path).unwrap();
        assert_eq!(
            loaded.summary.transport_fallback_reason.as_deref(),
            Some("memory-calibration-invalid")
        );

        let fifo_path = temp_report_path("fifo");
        nix::unistd::mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        let fifo = config_with_report(&valid_config(), &fifo_path);
        let server_sha256_for_thread = server_sha256.clone();
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let result =
                load_server_config_from_str_with_server_sha256(&fifo, &server_sha256_for_thread);
            let _ = tx.send(result);
        });
        let loaded = match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(result) => result.unwrap(),
            Err(error) => {
                let _writer = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&fifo_path)
                    .unwrap();
                reader.join().unwrap();
                std::fs::remove_file(fifo_path).unwrap();
                panic!("FIFO calibration read blocked: {error}");
            }
        };
        reader.join().unwrap();
        std::fs::remove_file(fifo_path).unwrap();
        assert_eq!(
            loaded.summary.transport_fallback_reason.as_deref(),
            Some("memory-calibration-invalid")
        );

        let device = config_with_report(&valid_config(), Path::new("/dev/null"));
        let loaded =
            load_server_config_from_str_with_server_sha256(&device, &server_sha256).unwrap();
        assert_eq!(
            loaded.summary.transport_fallback_reason.as_deref(),
            Some("memory-calibration-invalid")
        );
    }

    #[test]
    fn transport_calibration_reader_uses_opened_file_after_path_replacement() {
        let path = temp_report_path("replace-after-open");
        let replacement = temp_report_path("replacement");
        std::fs::write(&path, b"opened-file").unwrap();

        let bytes = read_calibration_file_with_hook(&path, || {
            std::fs::rename(&path, &replacement).unwrap();
            std::fs::write(&path, b"replacement-path").unwrap();
        })
        .unwrap();

        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(replacement).unwrap();
        assert_eq!(bytes, b"opened-file");
    }

    #[test]
    fn transport_profile_hash_is_canonical_and_binds_structured_input() {
        let profile = CandyTransportProfile::for_server();
        let same = CandyTransportProfile::for_server();
        let mut changed = profile.clone();
        changed.send_window -= 1;

        assert_eq!(
            carrier_transport::transport_profile_sha256(&profile).unwrap(),
            carrier_transport::transport_profile_sha256(&same).unwrap()
        );
        assert_ne!(
            carrier_transport::transport_profile_sha256(&profile).unwrap(),
            carrier_transport::transport_profile_sha256(&changed).unwrap()
        );
    }

    #[test]
    fn transport_verified_calibration_uses_measured_fixed_memory() {
        let server_sha256 = "1".repeat(64);
        let profile_hash =
            carrier_transport::transport_profile_sha256(&CandyTransportProfile::for_server())
                .unwrap();
        let path = temp_report_path("verified");
        write_calibration_report(
            &path,
            3,
            1,
            3,
            &server_sha256,
            &profile_hash,
            &"A".repeat(64),
            4 * MIB,
            900,
        );
        let config = config_with_report(&with_max_connections(&valid_config(), 10), &path);

        let loaded =
            load_server_config_from_str_with_server_sha256(&config, &server_sha256).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(loaded.summary.transport_requested_connections, 10);
        assert_eq!(loaded.summary.transport_effective_connections, 10);
        assert_eq!(loaded.summary.transport_worst_case_bytes, 10 * 76 * MIB);
        assert_eq!(loaded.config.admission.max_connections, 10);
        assert_eq!(loaded.config.transport, CandyTransportProfile::for_server());
        assert_eq!(loaded.summary.transport_fallback_reason, None);
    }

    #[test]
    fn transport_missing_and_malformed_calibration_have_precise_fallbacks() {
        let server_sha256 = "1".repeat(64);
        let missing =
            load_server_config_from_str_with_server_sha256(&valid_config(), &server_sha256)
                .unwrap();
        assert_eq!(
            missing.summary.transport_fallback_reason.as_deref(),
            Some("memory-calibration-missing")
        );
        assert_eq!(missing.summary.transport_effective_connections, 32);
        assert_eq!(
            missing.config.transport,
            CandyTransportProfile::for_server().with_low_memory_windows()
        );

        let unreadable_path = temp_report_path("absent");
        let unreadable_config = config_with_report(&valid_config(), &unreadable_path);
        let unreadable =
            load_server_config_from_str_with_server_sha256(&unreadable_config, &server_sha256)
                .unwrap();
        assert_eq!(
            unreadable.summary.transport_fallback_reason.as_deref(),
            Some("memory-calibration-missing")
        );

        let unreadable_path = temp_report_path("unreadable");
        std::fs::create_dir(&unreadable_path).unwrap();
        let unreadable_config = config_with_report(&valid_config(), &unreadable_path);
        let unreadable =
            load_server_config_from_str_with_server_sha256(&unreadable_config, &server_sha256)
                .unwrap();
        std::fs::remove_dir(unreadable_path).unwrap();
        assert_eq!(
            unreadable.summary.transport_fallback_reason.as_deref(),
            Some("memory-calibration-invalid")
        );

        let malformed_path = temp_report_path("malformed");
        std::fs::write(&malformed_path, b"{").unwrap();
        let malformed_config = config_with_report(&valid_config(), &malformed_path);
        let malformed =
            load_server_config_from_str_with_server_sha256(&malformed_config, &server_sha256)
                .unwrap();
        std::fs::remove_file(malformed_path).unwrap();
        assert_eq!(
            malformed.summary.transport_fallback_reason.as_deref(),
            Some("memory-calibration-invalid")
        );
    }

    #[test]
    fn transport_stale_schema_and_hash_have_precise_fallbacks() {
        let server_sha256 = "1".repeat(64);
        let profile_hash =
            carrier_transport::transport_profile_sha256(&CandyTransportProfile::for_server())
                .unwrap();
        for (label, outer_schema, report_server, report_profile, matrix, expected) in [
            (
                "schema2",
                2,
                server_sha256.clone(),
                profile_hash.clone(),
                "a".repeat(64),
                "memory-calibration-stale-schema",
            ),
            (
                "server-hash",
                3,
                "2".repeat(64),
                profile_hash.clone(),
                "a".repeat(64),
                "memory-calibration-stale-hash",
            ),
            (
                "profile-hash",
                3,
                server_sha256.clone(),
                "2".repeat(64),
                "a".repeat(64),
                "memory-calibration-stale-hash",
            ),
            (
                "matrix-nonhex",
                3,
                server_sha256.clone(),
                profile_hash.clone(),
                "z".repeat(64),
                "memory-calibration-stale-hash",
            ),
        ] {
            let path = temp_report_path(label);
            write_calibration_report(
                &path,
                outer_schema,
                1,
                3,
                &report_server,
                &report_profile,
                &matrix,
                4 * MIB,
                900,
            );
            let config = config_with_report(&valid_config(), &path);
            let loaded =
                load_server_config_from_str_with_server_sha256(&config, &server_sha256).unwrap();
            std::fs::remove_file(path).unwrap();
            assert_eq!(
                loaded.summary.transport_fallback_reason.as_deref(),
                Some(expected),
                "{label}"
            );
        }
    }

    #[test]
    fn transport_budget_clamps_effective_connections() {
        let server_sha256 = "1".repeat(64);
        let profile_hash =
            carrier_transport::transport_profile_sha256(&CandyTransportProfile::for_server())
                .unwrap();
        let path = temp_report_path("clamp");
        write_calibration_report(
            &path,
            3,
            1,
            3,
            &server_sha256,
            &profile_hash,
            &"a".repeat(64),
            4 * MIB,
            900,
        );
        let config = config_with_report(&with_max_connections(&valid_config(), 10), &path);
        let config = with_root_config(&config, "transport_memory_budget_mib = 152");

        let loaded =
            load_server_config_from_str_with_server_sha256(&config, &server_sha256).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(loaded.summary.transport_requested_connections, 10);
        assert_eq!(loaded.summary.transport_effective_connections, 2);
        assert_eq!(loaded.config.admission.max_connections, 2);
        assert_eq!(
            loaded.summary.transport_fallback_reason.as_deref(),
            Some("transport-memory-budget")
        );
    }

    #[test]
    fn transport_typed_server_profile_overrides_are_effective() {
        let server_sha256 = "1".repeat(64);
        let mut expected = CandyTransportProfile::for_server();
        expected.keep_alive = Some(Duration::from_secs(30));
        expected.idle_timeout = Duration::from_secs(180);
        expected.stream_receive_window = 3 * MIB;
        expected.connection_receive_window = 24 * MIB;
        expected.send_window = 20 * MIB;
        expected.initial_incoming_bidi = 1;
        expected.datagram_receive_buffer = (2 * MIB) as usize;
        expected.datagram_send_buffer = (2 * MIB) as usize;
        expected.congestion = CongestionChoice::CandyBbr;
        let profile_hash = carrier_transport::transport_profile_sha256(&expected).unwrap();
        let path = temp_report_path("overrides");
        write_calibration_report(
            &path,
            3,
            1,
            3,
            &server_sha256,
            &profile_hash,
            &"a".repeat(64),
            4 * MIB,
            900,
        );
        let config = config_with_report(&with_max_connections(&valid_config(), 1), &path);
        let config = format!(
            "{config}\n[transport]\nprofile = \"server-standard\"\nkeep_alive_seconds = 30\nidle_timeout_seconds = 180\nstream_receive_window_mib = 3\nconnection_receive_window_mib = 24\nsend_window_mib = 20\ninitial_incoming_bidi = 1\ndatagram_receive_buffer_mib = 2\ndatagram_send_buffer_mib = 2\ncongestion = \"candy-bbr\"\nstream_priority_enabled = true\n"
        );

        let loaded =
            load_server_config_from_str_with_server_sha256(&config, &server_sha256).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(loaded.config.transport, expected);
        assert_eq!(loaded.summary.transport_profile, expected);
        assert_eq!(loaded.summary.transport_effective_connections, 1);
    }

    #[test]
    fn transport_hard_budget_and_profile_errors_are_rejected() {
        for (label, root, transport, expected) in [
            (
                "zero",
                "transport_memory_budget_mib = 0",
                "",
                "transport memory budget must be nonzero",
            ),
            (
                "overflow",
                "transport_memory_budget_mib = 17592186044416",
                "",
                "transport memory budget MiB overflow",
            ),
            (
                "insufficient",
                "transport_memory_budget_mib = 1",
                "",
                "transport memory budget cannot admit one connection",
            ),
            (
                "unsafe",
                "",
                "[transport]\nconnection_receive_window_mib = 65\n",
                "transport window exceeds 64 MiB safety ceiling",
            ),
        ] {
            let config = with_root_config(&valid_config(), root);
            let config = format!("{config}\n{transport}");
            let err = load_server_config_from_str_with_server_sha256(&config, &"1".repeat(64))
                .unwrap_err()
                .to_string();
            assert_eq!(err, expected, "{label}");
        }
    }

    #[test]
    fn initial_incoming_bidi_is_fixed_to_the_control_stream_credit() {
        for value in [0, 2] {
            let config = format!(
                "{}\n[transport]\ninitial_incoming_bidi = {value}\n",
                valid_config()
            );
            let error = load_server_config_from_str_with_server_sha256(&config, &"1".repeat(64))
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                "initial_incoming_bidi must be 1 for the control stream"
            );
        }

        let fallback =
            load_server_config_from_str_with_server_sha256(&valid_config(), &"1".repeat(64))
                .unwrap();
        assert_eq!(fallback.config.transport.initial_incoming_bidi, 1);
        assert_eq!(fallback.summary.transport_profile.initial_incoming_bidi, 1);

        let explicit = format!(
            "{}\n[transport]\ninitial_incoming_bidi = 1\n",
            valid_config()
        );
        let explicit =
            load_server_config_from_str_with_server_sha256(&explicit, &"1".repeat(64)).unwrap();
        assert_eq!(explicit.config.transport.initial_incoming_bidi, 1);
        assert_eq!(explicit.summary.transport_profile.initial_incoming_bidi, 1);
    }

    #[tokio::test]
    async fn transport_hard_failure_precedes_endpoint_bind() {
        let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let config = valid_config().replace(
            "listen = \"127.0.0.1:0\"",
            &format!(
                "listen = {:?}\ntransport_memory_budget_mib = 0",
                occupied.local_addr().unwrap().to_string()
            ),
        );

        let err = preflight_server_config_from_str_with_server_sha256(&config, &"1".repeat(64))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "transport memory budget must be nonzero");
    }

    #[test]
    fn parses_valid_config_into_runtime_config_and_summary() {
        let loaded = load_server_config_from_str(&valid_config()).unwrap();

        assert_eq!(loaded.summary.listen, "127.0.0.1:0");
        assert_eq!(loaded.summary.user_count, 1);
        assert_eq!(loaded.config.limits.max_sessions_per_connection, 64);
        assert_eq!(loaded.config.limits.max_udp_flows, 32);
        assert_eq!(loaded.config.limits.max_datagram_size, 1200);
        assert_eq!(loaded.config.admission.max_connections, 32);
        assert_eq!(loaded.config.admission.auth_timeout.as_secs(), 10);
        assert_eq!(loaded.config.admission.max_connections_per_user, 8);
        assert_eq!(loaded.summary.requested_max_connections, 1024);
        assert_eq!(loaded.summary.max_connections, 32);
        assert_eq!(loaded.summary.auth_timeout_seconds, 10);
        assert_eq!(loaded.summary.max_connections_per_user, 8);
        assert!(!loaded.summary.ech_enabled);
        assert_eq!(loaded.summary.auth_profile, "standard");
        assert!(!loaded.summary.sdwan_tun_enabled);
        assert!(loaded.sdwan_tun.is_none());
    }

    #[test]
    fn sdwan_tun_is_explicit_and_requires_cloud_auth_and_exclusions() {
        let loaded =
            load_server_config_from_str_with_server_sha256(&valid_sdwan_config(), &"1".repeat(64))
                .unwrap();
        assert!(loaded.summary.sdwan_tun_enabled);
        assert!(loaded.sdwan_tun.is_some());

        let concurrent = valid_sdwan_config().replace("max_connections = 1", "max_connections = 2");
        let error = load_server_config_from_str_with_server_sha256(&concurrent, &"1".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires admission.max_connections = 1"));

        let without_cloud = valid_sdwan_config().replace("enabled = true\ncloud_signing_public_key = \"1111111111111111111111111111111111111111111111111111111111111111\"", "enabled = false");
        let error = load_server_config_from_str_with_server_sha256(&without_cloud, &"1".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires cloud_auth.enabled"), "{error}");

        let without_management = valid_sdwan_config().replace(
            "\n[[sdwan_tun.underlay_exclusions]]\nkind = \"management\"\nprefix = \"192.0.2.3/32\"",
            "",
        );
        let error =
            load_server_config_from_str_with_server_sha256(&without_management, &"1".repeat(64))
                .unwrap_err()
                .to_string();
        assert!(error.contains("requires cloud-api, hub-endpoint, and management"));
    }

    #[test]
    fn sdwan_tun_accepts_only_explicit_signed_expansion_policy_files() {
        let config = valid_sdwan_config().replace(
            "projection_file = \"/var/lib/candy/site.projection\"",
            "projection_file = \"/var/lib/candy/site.projection\"\nshared_hub_admission_file = \"/var/lib/candy/shared-hub.admission\"\nmesh_membership_file = \"/var/lib/candy/mesh.membership\"\ndynamic_route_snapshot_file = \"/var/lib/candy/dynamic-routes.snapshot\"",
        );
        let loaded =
            load_server_config_from_str_with_server_sha256(&config, &"1".repeat(64)).unwrap();
        let sdwan = loaded.sdwan_tun.unwrap();
        assert_eq!(
            sdwan.shared_hub_admission_path.as_deref(),
            Some(Path::new("/var/lib/candy/shared-hub.admission"))
        );
        assert_eq!(
            sdwan.mesh_membership_path.as_deref(),
            Some(Path::new("/var/lib/candy/mesh.membership"))
        );
        assert_eq!(
            sdwan.dynamic_route_snapshot_path.as_deref(),
            Some(Path::new("/var/lib/candy/dynamic-routes.snapshot"))
        );
    }

    #[test]
    fn shared_transit_config_is_explicit_bounded_and_mutually_exclusive() {
        let loaded = load_server_config_from_str_with_server_sha256(
            &valid_shared_transit_config(),
            &"1".repeat(64),
        )
        .unwrap();
        assert!(loaded.summary.sdwan_shared_transit_enabled);
        assert!(!loaded.summary.sdwan_tun_enabled);
        let shared = loaded.sdwan_shared_transit.unwrap();
        assert_eq!(shared.domains.len(), 1);
        assert_eq!(shared.domains[0].projection_paths.len(), 2);
        assert_eq!(shared.domains[0].effective_mtu, 1180);

        let empty = valid_shared_transit_config().replace(
            "[[sdwan_shared_transit.domains]]",
            "[[sdwan_shared_transit_disabled.domains]]",
        );
        assert!(load_server_config_from_str_with_server_sha256(&empty, &"1".repeat(64)).is_err());

        let both = format!(
            "{}\n{}",
            valid_sdwan_config(),
            valid_shared_transit_config()
        );
        assert!(load_server_config_from_str_with_server_sha256(&both, &"1".repeat(64)).is_err());
    }

    #[test]
    fn private_transit_config_separates_site_and_fabric_listeners_and_is_exclusive() {
        let loaded = load_server_config_from_str_with_server_sha256(
            &valid_private_transit_config(),
            &"1".repeat(64),
        )
        .unwrap();
        assert!(loaded.summary.sdwan_private_transit_enabled);
        assert!(!loaded.summary.sdwan_tun_enabled);
        assert!(!loaded.summary.sdwan_shared_transit_enabled);
        let private = loaded.sdwan_private_transit.unwrap();
        assert_eq!(private.projection_paths.len(), 2);
        assert_eq!(private.effective_mtu, 1180);
        assert_eq!(private.fabric_listen, "127.0.0.1:7444".parse().unwrap());

        let same_listener = valid_private_transit_config().replace(
            "fabric_listen = \"127.0.0.1:7444\"",
            "fabric_listen = \"127.0.0.1:0\"",
        );
        assert!(
            load_server_config_from_str_with_server_sha256(&same_listener, &"1".repeat(64),)
                .is_err()
        );

        let both = format!(
            "{}\n{}",
            valid_sdwan_config(),
            valid_private_transit_config()
        );
        assert!(load_server_config_from_str_with_server_sha256(&both, &"1".repeat(64)).is_err());
    }

    #[test]
    fn parses_cloud_auth_profile_without_local_users() {
        let text = r#"
listen = "127.0.0.1:0"
development_ephemeral_certificate = true

[cloud_auth]
enabled = true
cloud_signing_public_key = "0000000000000000000000000000000000000000000000000000000000000000"
"#;
        let loaded = load_server_config_from_str_with_server_sha256(text, &"1".repeat(64)).unwrap();
        assert_eq!(loaded.summary.user_count, 0);
        assert_eq!(loaded.summary.auth_profile, "cloud-grant-v1");
        assert_eq!(loaded.config.admission.auth_timeout.as_secs(), 5);
        assert!(matches!(
            loaded.config.auth_profile,
            CandyServerAuthProfile::CloudGrantV1 { cloud_signing_public_key } if cloud_signing_public_key == [0; 32]
        ));
    }

    #[test]
    fn cloud_auth_rejects_local_users_and_missing_or_disabled_key() {
        let with_user = format!(
            "{}\n[cloud_auth]\nenabled = true\ncloud_signing_public_key = \"{}\"\n",
            valid_config(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let err = load_server_config_from_str_with_server_sha256(&with_user, &"1".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(err.contains("[[users]]"));

        let missing = "listen = \"127.0.0.1:0\"\ndevelopment_ephemeral_certificate = true\n[cloud_auth]\nenabled = true\n";
        let err = load_server_config_from_str_with_server_sha256(missing, &"1".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cloud_signing_public_key is required"));

        let disabled = format!(
            "{}\n[cloud_auth]\ncloud_signing_public_key = \"{}\"\n",
            valid_config(),
            "AA=="
        );
        let err = load_server_config_from_str_with_server_sha256(&disabled, &"1".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires cloud_auth.enabled"));
    }

    #[test]
    fn omitted_user_features_use_the_recommended_preset() {
        let text = valid_config().replace("features = [\"datagram\", \"metrics_v1\"]", "");
        let loaded = load_server_config_from_str(&text).unwrap();

        assert!(loaded.config.users[0]
            .allowed_features
            .contains(FeatureSet::UDP_FEC_V1));
        assert!(loaded.config.users[0]
            .allowed_features
            .contains(FeatureSet::FRAGMENTED_DATAGRAM_V1));
    }

    #[test]
    fn explicit_empty_user_features_still_means_no_capabilities() {
        let text =
            valid_config().replace("features = [\"datagram\", \"metrics_v1\"]", "features = []");
        let loaded = load_server_config_from_str(&text).unwrap();

        assert_eq!(loaded.config.users[0].allowed_features.bits(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ech_setup_creates_a_loadable_key_ring_and_dns_value() {
        use base64::Engine;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = temp_report_path("ech-key-ring");
        let first = initialize_or_rotate_ech(&directory, "public.example.com").unwrap();
        let second = initialize_or_rotate_ech(&directory, "public.example.com").unwrap();

        assert_ne!(first.config_id, second.config_id);
        assert_eq!(second.key_count, 2);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&second.dns_ech_value)
            .unwrap();
        assert_eq!(decoded, std::fs::read(&second.config_list_file).unwrap());
        assert_eq!(
            u16::from_be_bytes([decoded[0], decoded[1]]) as usize,
            decoded.len() - 2
        );
        let key_path = directory.join(format!("key-{:02x}.key", second.config_id));
        assert_eq!(std::fs::metadata(&key_path).unwrap().mode() & 0o077, 0);

        let text = valid_config().replace(
            "[limits]",
            &format!(
                "[ech]\ndirectory = {:?}\n\n[limits]",
                directory.to_string_lossy()
            ),
        );
        let loaded = load_server_config_from_str(&text).unwrap();
        assert!(loaded.summary.ech_enabled);
        let preflight = preflight_server_config_from_str_with_server_sha256(&text, &"1".repeat(64))
            .await
            .unwrap();
        assert!(preflight.ok);
        assert!(preflight.summary.ech_enabled);

        let retired = retire_ech_key(&directory, first.config_id).unwrap();
        assert_eq!(retired.key_count, 1);
        assert!(!directory
            .join(format!("key-{:02x}.key", first.config_id))
            .exists());
        assert!(retire_ech_key(&directory, second.config_id).is_err());

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn loads_ech_files_without_exposing_private_key_in_diagnostics() {
        use std::os::unix::fs::PermissionsExt;

        let config_path = temp_report_path("ech-config");
        let key_path = temp_report_path("ech-key");
        std::fs::write(&config_path, [0xfe, 0x0d, 0x00, 0x00]).unwrap();
        std::fs::write(&key_path, [0x5a; ECH_PRIVATE_KEY_BYTES]).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let text = valid_config().replace(
            "[limits]",
            &format!(
                "[ech]\nconfig_file = {:?}\nprivate_key_file = {:?}\nretry_config = true\n\n[limits]",
                config_path.to_string_lossy(),
                key_path.to_string_lossy()
            ),
        );

        let loaded = load_server_config_from_str(&text).unwrap();
        std::fs::remove_file(config_path).unwrap();
        std::fs::remove_file(key_path).unwrap();

        assert!(loaded.summary.ech_enabled);
        assert!(!format!("{loaded:?}").contains("5a5a5a5a"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_ech_private_keys_with_unsafe_permissions_or_symlinks() {
        use std::os::unix::fs::PermissionsExt;

        let config_path = temp_report_path("ech-config-security");
        let key_path = temp_report_path("ech-key-security");
        let link_path = temp_report_path("ech-key-link");
        std::fs::write(&config_path, [0xfe, 0x0d, 0x00, 0x00]).unwrap();
        std::fs::write(&key_path, [0x5a; ECH_PRIVATE_KEY_BYTES]).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let with_key = |path: &Path| {
            valid_config().replace(
                "[limits]",
                &format!(
                    "[ech]\nconfig_file = {:?}\nprivate_key_file = {:?}\n\n[limits]",
                    config_path.to_string_lossy(),
                    path.to_string_lossy()
                ),
            )
        };
        let permissions_error = load_server_config_from_str(&with_key(&key_path))
            .unwrap_err()
            .to_string();
        assert!(
            permissions_error.contains("permissions"),
            "{permissions_error}"
        );

        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&key_path, &link_path).unwrap();
        let symlink_error = load_server_config_from_str(&with_key(&link_path))
            .unwrap_err()
            .to_string();
        assert!(
            symlink_error.contains("private key file"),
            "{symlink_error}"
        );

        std::fs::remove_file(link_path).unwrap();
        std::fs::remove_file(key_path).unwrap();
        std::fs::remove_file(config_path).unwrap();
    }

    #[test]
    fn parses_and_validates_port_hopping_listeners() {
        let config = with_root_config(&valid_config(), "[port_hopping]\nports = [10443, 20443]");
        let loaded = load_server_config_from_str(&config).unwrap();
        assert_eq!(
            loaded.config.additional_listens,
            [
                "127.0.0.1:10443".parse().unwrap(),
                "127.0.0.1:20443".parse().unwrap(),
            ]
        );
        assert_eq!(
            loaded.summary.port_hopping_listens,
            ["127.0.0.1:10443", "127.0.0.1:20443"]
        );

        let duplicate = with_root_config(&valid_config(), "[port_hopping]\nports = [10443, 10443]");
        assert!(load_server_config_from_str(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
    }

    #[test]
    fn rejects_omitted_certificate_pair_without_development_opt_in() {
        let err = load_server_config_from_str(&config_without_certificate_opt_in())
            .unwrap_err()
            .to_string();

        assert!(err.contains("development_ephemeral_certificate"), "{err}");
    }

    #[test]
    fn accepts_omitted_certificate_pair_with_development_opt_in() {
        let text = config_without_certificate_opt_in().replace(
            "listen = \"127.0.0.1:0\"",
            "listen = \"127.0.0.1:0\"\ndevelopment_ephemeral_certificate = true",
        );

        let loaded = load_server_config_from_str(&text).unwrap();

        assert_eq!(loaded.summary.cert_source, "generated-development");
    }

    #[test]
    fn rejects_certificate_files_with_development_ephemeral_opt_in() {
        let text = config_without_certificate_opt_in().replace(
            "listen = \"127.0.0.1:0\"",
            r#"listen = "127.0.0.1:0"
cert_pem = "/tmp/server.crt"
key_pem = "/tmp/server.key"
development_ephemeral_certificate = true"#,
        );

        let err = load_server_config_from_str(&text).unwrap_err().to_string();

        assert!(err.contains("development_ephemeral_certificate"), "{err}");
    }

    #[test]
    fn rejects_duplicate_user_ids() {
        let text = format!(
            "{}\n[[users]]\nkey_id = \"alice\"\nsecret = \"another-alice-secret\"\n",
            valid_config()
        );

        let err = load_server_config_from_str(&text).unwrap_err().to_string();

        assert!(err.contains("duplicate user key_id 'alice'"));
    }

    #[test]
    fn parses_admission_limits() {
        let text = valid_config().replace(
            "[limits]",
            r#"[admission]
max_connections = 24
auth_timeout_seconds = 7
max_connections_per_user = 3

[limits]"#,
        );

        let loaded = load_server_config_from_str(&text).unwrap();

        assert_eq!(loaded.config.admission.max_connections, 24);
        assert_eq!(loaded.config.admission.auth_timeout.as_secs(), 7);
        assert_eq!(loaded.config.admission.max_connections_per_user, 3);
        assert_eq!(loaded.summary.max_connections, 24);
        assert_eq!(loaded.summary.auth_timeout_seconds, 7);
        assert_eq!(loaded.summary.max_connections_per_user, 3);
    }

    #[test]
    fn rejects_invalid_admission_limits() {
        for (field, value) in [
            ("max_connections", 0),
            ("max_connections", tokio::sync::Semaphore::MAX_PERMITS + 1),
            ("auth_timeout_seconds", 0),
            ("auth_timeout_seconds", 301),
            ("max_connections_per_user", 0),
            (
                "max_connections_per_user",
                tokio::sync::Semaphore::MAX_PERMITS + 1,
            ),
        ] {
            let text = valid_config().replace(
                "[limits]",
                &format!("[admission]\n{field} = {value}\n\n[limits]"),
            );

            let err = load_server_config_from_str(&text).unwrap_err().to_string();
            assert!(err.contains(field), "unexpected error for {field}: {err}");
        }
    }

    #[test]
    fn rejects_mismatched_certificate_pair() {
        let text = valid_config().replace(
            "listen = \"127.0.0.1:0\"",
            "listen = \"127.0.0.1:0\"\ncert_pem = \"/tmp/server.crt\"",
        );

        let err = load_server_config_from_str(&text).unwrap_err().to_string();

        assert!(err.contains("cert_pem and key_pem"));
    }

    #[test]
    fn rejects_config_without_users() {
        let text = r#"
listen = "127.0.0.1:0"
development_ephemeral_certificate = true
"#;

        let err = load_server_config_from_str(text).unwrap_err().to_string();

        assert!(err.contains("at least one"));
    }

    #[test]
    fn rejects_placeholder_secret() {
        let text = valid_config().replace("alice-secret-value", "change-me-long-random-secret");

        let err = load_server_config_from_str(&text).unwrap_err().to_string();

        assert!(err.contains("non-placeholder"));
    }

    #[test]
    fn rejects_zero_limit() {
        let text = valid_config().replace("max_udp_flows = 32", "max_udp_flows = 0");

        let err = load_server_config_from_str(&text).unwrap_err().to_string();

        assert!(err.contains("max_udp_flows"));
    }

    #[test]
    fn rejects_session_and_udp_limits_above_hard_open_bound() {
        for field in ["max_sessions_per_connection = 64", "max_udp_flows = 32"] {
            let text = valid_config().replace(
                field,
                &format!("{} = 1048577", field.split_once(" = ").unwrap().0),
            );
            let err = load_server_config_from_str(&text).unwrap_err().to_string();
            assert!(err.contains("1048576"), "{field}: {err}");
        }
    }

    #[test]
    fn parses_security_profile() {
        let text = valid_config().replace(
            "[limits]",
            r#"[security]
alpn = "candy-private/1"
alpn_compatibility = false
auth_failure_delay_ms = 25
control_padding = true

[limits]"#,
        );

        let loaded = load_server_config_from_str(&text).unwrap();

        assert_eq!(loaded.config.security.alpn, b"candy-private/1");
        assert!(!loaded.config.security.legacy_alpn_compatibility);
        assert_eq!(loaded.config.security.auth_failure_delay_ms, 25);
        assert!(loaded.config.security.control_padding);
    }

    #[test]
    fn server_security_defaults_are_hardened() {
        let loaded = load_server_config_from_str(&valid_config()).unwrap();

        assert_eq!(loaded.config.security.auth_failure_delay_ms, 50);
        assert!(loaded.config.security.control_padding);
    }

    #[test]
    fn explicit_compatibility_security_values_remain_configurable() {
        let text = valid_config().replace(
            "[limits]",
            r#"[security]
auth_failure_delay_ms = 0
control_padding = false

[limits]"#,
        );

        let loaded = load_server_config_from_str(&text).unwrap();

        assert_eq!(loaded.config.security.auth_failure_delay_ms, 0);
        assert!(!loaded.config.security.control_padding);
    }

    #[test]
    fn parses_server_udp_multiplier_qos() {
        let text = valid_config().replace(
            "[limits]",
            r#"[qos]
server_udp_multiplier = 3

[limits]"#,
        );

        let loaded = load_server_config_from_str(&text).unwrap();

        assert_eq!(loaded.config.qos.server_udp_multiplier, 3);
        assert_eq!(loaded.summary.server_udp_multiplier, 3);
        assert!(!loaded.config.qos.accept_client_udp_multiplier_proposal);
        assert!(!loaded.config.qos.propose_client_udp_multiplier);
        assert_eq!(loaded.config.qos.proposed_client_udp_multiplier, 1);
    }

    #[test]
    fn parses_udp_multiplier_proposal_qos() {
        let text = valid_config().replace(
            "[limits]",
            r#"[qos]
server_udp_multiplier = 1
accept_client_udp_multiplier_proposal = true
client_udp_multiplier = 2
propose_client_udp_multiplier = true

[limits]"#,
        );

        let loaded = load_server_config_from_str(&text).unwrap();

        assert!(loaded.config.qos.accept_client_udp_multiplier_proposal);
        assert!(loaded.config.qos.propose_client_udp_multiplier);
        assert_eq!(loaded.config.qos.proposed_client_udp_multiplier, 2);
        assert!(loaded.summary.accept_client_udp_multiplier_proposal);
        assert!(loaded.summary.propose_client_udp_multiplier);
        assert_eq!(loaded.summary.client_udp_multiplier, 2);
    }

    #[test]
    fn rejects_out_of_range_server_udp_multiplier() {
        let text = valid_config().replace(
            "[limits]",
            r#"[qos]
server_udp_multiplier = 4

[limits]"#,
        );

        let err = load_server_config_from_str(&text).unwrap_err().to_string();

        assert!(err.contains("server_udp_multiplier"));
    }

    #[tokio::test]
    async fn preflight_binds_endpoint_and_reports_certificate_pin() {
        let report = preflight_server_config_from_str(&valid_config())
            .await
            .unwrap();

        assert_eq!(report.summary.user_count, 1);
        assert!(report.listen.starts_with("127.0.0.1:"));
        assert_eq!(report.cert_sha256.len(), 64);
        assert_eq!(
            report.socket_buffers.target_bytes,
            carrier_transport::UDP_SOCKET_BUFFER_TARGET_BYTES
        );
        assert!(report.socket_buffers.receive_bytes > 0);
        assert!(report.socket_buffers.send_bytes > 0);
    }
}
