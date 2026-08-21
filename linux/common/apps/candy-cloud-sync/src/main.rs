use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey};
use reqwest::{
    blocking::{Client, Response},
    header::{CONTENT_TYPE, ETAG, IF_MATCH, IF_NONE_MATCH},
    StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

mod grant;
mod transport_identity;

const MAX_PROFILE_BYTES: u64 = 64 * 1024;
const MAX_CONFIGURATION_BYTES: u64 = 3 * 1024 * 1024;
const MAX_ROUTE_ENVELOPE_BYTES: usize = 1024 * 1024;
const MAX_LOCAL_ROUTE_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_LOCAL_NETWORKS: usize = 64;
const LOCAL_ROUTE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
const ACTIVATION_REVALIDATION_SECONDS: u64 = 300;
const CONFIGURATION_MEDIA_TYPE: &str = "application/vnd.candy.runtime-configuration.v1+json";
const PUBLIC_ENDPOINT_ENV: &str = "CANDY_PUBLIC_ENDPOINT";

#[derive(Debug, Parser)]
#[command(
    name = "candy-cloud-sync",
    version,
    about = "Candy Cloud Runtime synchronizer"
)]
struct Args {
    #[arg(long, default_value = "/var/lib/candy/sdwan")]
    state_dir: PathBuf,
    #[arg(long, default_value = "/run/candy")]
    run_dir: PathBuf,
    #[arg(long)]
    identity_dir: Option<PathBuf>,
    #[arg(long)]
    ca_certificate: Option<PathBuf>,
    #[arg(long)]
    core: Option<PathBuf>,
    #[arg(long)]
    server_config: Option<PathBuf>,
    #[arg(long = "public-endpoint")]
    public_endpoints: Vec<SocketAddr>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    SyncOnce,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceIdentity {
    schema_version: u8,
    cloud_address: String,
    organization_id: Uuid,
    tenant_id: Option<Uuid>,
    site_id: Option<Uuid>,
    #[serde(default)]
    display_name: Option<String>,
    device_id: Uuid,
    device_key_id: Uuid,
    not_after: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfiguration {
    schema_version: u8,
    projection_publication_id: Uuid,
    projection_id: Uuid,
    segment_id: Uuid,
    attachment_id: Uuid,
    segment_generation: u64,
    projection_generation: u64,
    projection_content_hash: String,
    route_signing_key_id: String,
    route_signing_public_key: String,
    segment_snapshot: String,
    site_projection: String,
    peer_projection_catalog: Vec<RuntimePeerProjection>,
    grant_verification_keys: Vec<RuntimeGrantVerificationKey>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimePeerProjection {
    projection_id: Uuid,
    projection_generation: u64,
    projection_content_hash: String,
    site_projection: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeGrantVerificationKey {
    key_id: String,
    ed25519_public_key: String,
    issuer_id: Uuid,
    environment_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedControlReport {
    schema_version: u16,
    ok: bool,
    tenant_id: String,
    segment_id: String,
    site_id: String,
    attachment_id: String,
    projection_id: String,
    device_id: String,
    device_key_id: String,
    segment_generation: u64,
    projection_generation: u64,
    projection_content_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiscoveredControlReport {
    schema_version: u16,
    ok: bool,
    tenant_id: String,
    segment_id: String,
    site_id: String,
    attachment_id: String,
    device_id: String,
    device_key_id: String,
    segment_generation: u64,
    projection_generation: u64,
    route_policy: CorePolicyRef,
    netd: DiscoveredNetd,
    outbound_candidates: Vec<DiscoveredCandidate>,
    inbound_expected: Vec<DiscoveredInbound>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CorePolicyRef {
    policy_id: String,
    generation: u64,
    content_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiscoveredNetd {
    table_id: u32,
    overlay_router_ipv4: String,
    max_inner_mtu: u16,
    local_prefixes: Vec<String>,
    remote_routes: Vec<DiscoveredRoute>,
    underlay_ipv4_exclusions: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiscoveredRoute {
    destination: String,
    owner_attachment_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiscoveredCandidate {
    candidate_id: String,
    peer_site_id: String,
    peer_attachment_id: String,
    kind: String,
    priority: u16,
    endpoint: String,
    node_pool_id: String,
    transport_node_id: String,
    transport_node_key_id: String,
    server_name: String,
    server_cert_sha256: String,
    transport_preset: String,
    authorization: CorePolicyRef,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiscoveredInbound {
    candidate_id: String,
    peer_attachment_id: String,
    endpoint: String,
    node_pool_id: String,
    transport_node_id: String,
    transport_node_key_id: String,
    server_name: String,
    server_cert_sha256: String,
    transport_preset: String,
    authorization_generation: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyncState {
    schema_version: u8,
    etag: Option<String>,
    configuration_sha256: Option<String>,
    #[serde(default)]
    activation_required: bool,
    #[serde(default)]
    activation_rejected_etag: Option<String>,
    #[serde(default)]
    activation_rejected_at_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SyncResult<'a> {
    schema_version: u8,
    state: &'a str,
    network_ready: bool,
    configuration_changed: bool,
    etag: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct LocalSyncStatus<'a> {
    schema_version: u8,
    state: &'a str,
    updated_at: u64,
    error_code: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct ConfigurationStatus<'a> {
    projection_publication_id: Uuid,
    projection_content_hash: &'a str,
    state: &'a str,
    error_code: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct RuntimeTelemetry<'a> {
    schema_version: u8,
    boot_id: Uuid,
    sequence: u64,
    lifecycle: &'a str,
    configured_peers: u32,
    active_peers: u32,
    required_route_owners: u32,
    ready_route_owners: u32,
    fail_open_required: bool,
    last_error_code: Option<&'a str>,
    rtt_ms: Option<u32>,
    jitter_ms: Option<u32>,
    packet_loss_ppm: Option<u32>,
    rx_bps: Option<u64>,
    tx_bps: Option<u64>,
    reconnects: Option<u64>,
    path_changes: Option<u64>,
    paths: &'a [RuntimePathTelemetry],
    #[serde(skip_serializing_if = "Option::is_none")]
    local_networks: Option<&'a [LocalNetworkTelemetry]>,
}

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
struct LocalNetworkTelemetry {
    network_id: String,
    interface_name: String,
    cidr: String,
    address: String,
    kind: &'static str,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
struct RuntimePathTelemetry {
    peer_attachment_id: String,
    candidate_id: Option<String>,
    path_kind: String,
    transport: String,
    connection_epoch: u64,
    rtt_ms: Option<u32>,
    jitter_ms: Option<u32>,
    packet_loss_ppm: Option<u32>,
    rx_bps: Option<u64>,
    tx_bps: Option<u64>,
    reconnects: u64,
    path_changes: u64,
}

#[derive(Debug, Deserialize)]
struct CoreRuntimeStatus {
    schema_version: u16,
    generation: u64,
    pid: u32,
    lifecycle: String,
    configured_peers: u32,
    active_peers: u32,
    required_route_owners: u32,
    ready_route_owners: u32,
    fail_open_required: bool,
    last_error_code: Option<String>,
    #[serde(default)]
    counters: CorePacketCounters,
    #[serde(default)]
    paths: Vec<CorePathStatus>,
    #[serde(default)]
    reconnects: u64,
    #[serde(default)]
    path_changes: u64,
}

#[derive(Debug, Default, Deserialize)]
struct CorePacketCounters {
    #[serde(default)]
    tun_bytes_received: u64,
    #[serde(default)]
    tun_bytes_sent: u64,
}

#[derive(Debug, Deserialize)]
struct CorePathStatus {
    peer_attachment_id: String,
    candidate_id: Option<String>,
    path_kind: String,
    transport: String,
    connection_epoch: u64,
    rtt_micros: u64,
    rtt_variance_micros: u64,
    rtt_sample_count: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    sent_packets: u64,
    lost_packets: u64,
    congestion_window_bytes: u64,
    path_mtu: u16,
    reconnects: u64,
    path_changes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeTelemetrySample {
    schema_version: u8,
    boot_id: Uuid,
    sequence: u64,
    core_pid: u32,
    generation: u64,
    observed_monotonic_ms: u64,
    tun_bytes_received: u64,
    tun_bytes_sent: u64,
    paths: BTreeMap<String, RuntimePathSample>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimePathSample {
    connection_epoch: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    sent_packets: u64,
    lost_packets: u64,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct DerivedRuntimePerformance {
    rtt_ms: Option<u32>,
    jitter_ms: Option<u32>,
    packet_loss_ppm: Option<u32>,
    rx_bps: Option<u64>,
    tx_bps: Option<u64>,
    reconnects: Option<u64>,
    path_changes: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct LocalRuntimeStatus {
    schema_version: u8,
    runtime: LocalRuntimeState,
}

#[derive(Debug, Deserialize)]
struct LocalRuntimeState {
    state: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationReadyReceipt {
    schema_version: u8,
    activation_id: String,
    candidate_target: String,
    generation: u64,
    agent_pid: u32,
    state: String,
    error_code: Option<String>,
}

#[derive(Debug)]
struct ActivationOutcome {
    receipt: ActivationReadyReceipt,
    descriptor: ActivationDescriptor,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivationDescriptor {
    schema_version: u8,
    activation_id: String,
    delivery_etag: String,
    delivery_sha256: String,
    projection_publication_id: Uuid,
    projection_content_hash: String,
    segment_generation: u64,
    projection_generation: u64,
    core_role: String,
    core_config: String,
    netd_declaration: String,
    grant_refresh_after_unix: u64,
    grant_expires_at_unix: u64,
}

#[derive(Debug, Serialize)]
struct ActivationGrantManifest {
    node_pool_id: Uuid,
    grant_id: Uuid,
    grant_sha256: String,
    refresh_after_unix: u64,
    expires_at_unix: u64,
}

#[derive(Debug)]
struct ServerOutboundPeerActivation {
    candidate_id: String,
    tunnel_id: u64,
    transport_config: PathBuf,
}

#[derive(Debug, Serialize)]
struct NetdDeclaration {
    table_id: u32,
    overlay_router_ipv4: String,
    effective_mtu: u16,
    routes: Vec<NetdRoute>,
    exclusions: Vec<NetdExclusion>,
    firewall: NetdFirewall,
}

#[derive(Debug, Serialize)]
struct NetdRoute {
    prefix: String,
    kind: &'static str,
}

#[derive(Debug, Serialize)]
struct NetdExclusion {
    prefix: String,
    kind: &'static str,
}

#[derive(Debug, Serialize)]
struct NetdFirewall {
    allow_forward: bool,
    clamp_tcp_mss: bool,
    require_ipv4_forwarding: bool,
    manage_rp_filter: bool,
}

fn main() {
    let args = Args::parse();
    let state_dir = args.state_dir.clone();
    if let Err(error) = run(args) {
        let error_text = format!("{error:#}");
        let error_code = if error_text.contains("Core") {
            "core_verification_failed"
        } else if error_text.contains("publish") || error_text.contains("atomic") {
            "local_publish_failed"
        } else {
            "cloud_sync_failed"
        };
        let _ = write_local_sync_status(&state_dir, "error", Some(error_code));
        eprintln!("candy-cloud-sync: {error:#}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    match args.command {
        Command::SyncOnce => sync_once(&args),
    }
}

fn sync_once(args: &Args) -> Result<()> {
    let public_endpoint = std::env::var_os(PUBLIC_ENDPOINT_ENV);
    sync_once_with_public_endpoint_env(args, public_endpoint.as_deref())
}

fn sync_once_with_public_endpoint_env(args: &Args, public_endpoint: Option<&OsStr>) -> Result<()> {
    ensure_private_state_root(&args.state_dir)?;
    let public_endpoints = effective_public_endpoints(args, public_endpoint)?;
    if args.server_config.is_some() && public_endpoints.is_empty() {
        write_local_sync_status(
            &args.state_dir,
            "waiting_for_public_endpoint",
            Some("public_endpoint_required"),
        )?;
        eprintln!(
            "level=warn event=cloud_sync_waiting state=waiting_for_public_endpoint error_code=public_endpoint_required reason=server_public_endpoint_missing"
        );
        println!(
            "{}",
            serde_json::to_string(&SyncResult {
                schema_version: 1,
                state: "waiting_for_public_endpoint",
                network_ready: false,
                configuration_changed: false,
                etag: None,
            })?
        );
        return Ok(());
    }
    sync_once_with_retry(args, &public_endpoints, true)
}

fn effective_public_endpoints(
    args: &Args,
    public_endpoint: Option<&OsStr>,
) -> Result<Vec<SocketAddr>> {
    if !args.public_endpoints.is_empty() {
        validate_public_endpoints(&args.public_endpoints, "explicit --public-endpoint")?;
        return Ok(args.public_endpoints.clone());
    }
    if args.server_config.is_none() {
        return Ok(Vec::new());
    }
    let Some(public_endpoint) = public_endpoint else {
        return Ok(Vec::new());
    };
    let public_endpoint = public_endpoint
        .to_str()
        .context("CANDY_PUBLIC_ENDPOINT must be valid UTF-8")?;
    let endpoint = public_endpoint.parse::<SocketAddr>().context(
        "CANDY_PUBLIC_ENDPOINT must contain exactly one IP:PORT endpoint (IPv6 addresses require brackets)",
    )?;
    validate_public_endpoints(&[endpoint], "CANDY_PUBLIC_ENDPOINT")?;
    Ok(vec![endpoint])
}

fn validate_public_endpoints(endpoints: &[SocketAddr], source: &str) -> Result<()> {
    for endpoint in endpoints {
        if endpoint.port() == 0 || endpoint.ip().is_unspecified() {
            bail!("{source} must contain a concrete IP address and a non-zero port")
        }
    }
    Ok(())
}

fn activation_required(
    server_mode: bool,
    configuration: &RuntimeConfiguration,
    discovery: &DiscoveredControlReport,
) -> bool {
    if server_mode {
        !configuration.peer_projection_catalog.is_empty()
            || !discovery.inbound_expected.is_empty()
            || !discovery.outbound_candidates.is_empty()
    } else {
        !discovery.outbound_candidates.is_empty()
    }
}

fn sync_once_with_retry(
    args: &Args,
    public_endpoints: &[SocketAddr],
    allow_unconditional_retry: bool,
) -> Result<()> {
    ensure_private_state_root(&args.state_dir)?;
    let identity_dir = args
        .identity_dir
        .clone()
        .unwrap_or_else(|| args.state_dir.join("identity"));
    let identity: DeviceIdentity = read_bounded_json(
        &identity_dir.join("device-identity-v1.json"),
        MAX_PROFILE_BYTES,
    )?;
    validate_identity(&identity)?;
    let cloud = validate_cloud(&identity.cloud_address)?;
    let client = build_client(&identity_dir, args.ca_certificate.as_deref())?;
    reconcile_transport_identity(args, public_endpoints, &client, &cloud)?;

    let state_path = args.state_dir.join("sync-state-v1.json");
    let mut state: SyncState = if state_path.exists() {
        read_bounded_json(&state_path, MAX_PROFILE_BYTES)?
    } else {
        SyncState {
            schema_version: 1,
            ..SyncState::default()
        }
    };
    if state.schema_version != 1 {
        bail!("unsupported Cloud synchronization state schema")
    }

    // The agent is the only component allowed to publish a committed receipt.
    // Promote that exact immutable candidate before making any Cloud status
    // assertion. If the receipt is absent, the normal configuration request
    // below remains responsible for obtaining or renewing a candidate.
    if state.activation_required {
        if let Some(activation) = read_activation_ready_receipt(&args.state_dir)? {
            if state.etag.as_deref() == Some(activation.descriptor.delivery_etag.as_str()) {
                match activation.receipt.state.as_str() {
                    "committed" => {
                        promote_committed_activation(&args.state_dir, &activation)?;
                        report_activation_status(&client, &cloud, &activation, "active", None)?;
                        state.activation_rejected_etag = None;
                        state.activation_rejected_at_unix = None;
                    }
                    "rejected" => {
                        report_activation_status(
                            &client,
                            &cloud,
                            &activation,
                            "rejected",
                            activation.receipt.error_code.as_deref(),
                        )?;
                        remove_candidate_if_matches(&args.state_dir, &activation)?;
                        state.activation_rejected_etag =
                            Some(activation.descriptor.delivery_etag.clone());
                        state.activation_rejected_at_unix = Some(unix_now()?);
                    }
                    _ => unreachable!("validated activation receipt state"),
                }
                clear_activation_ready_receipt(&args.state_dir)?;
                atomic_json(&state_path, &state, 0o600)?;
            }
        }
    }

    let mut request = client.get(endpoint(&cloud, "auth/v1/runtime/configuration")?);
    if let Some(etag) = state.etag.as_deref() {
        validate_etag(etag)?;
        request = request.header(IF_NONE_MATCH, etag);
    }
    let response = request.send().context("request Runtime configuration")?;
    match response.status() {
        StatusCode::NO_CONTENT => {
            withdraw_local_activation(&args.state_dir)?;
            state.etag = None;
            state.configuration_sha256 = None;
            state.activation_required = false;
            state.activation_rejected_etag = None;
            state.activation_rejected_at_unix = None;
            atomic_json(&state_path, &state, 0o600)?;
            write_local_sync_status(&args.state_dir, "waiting_for_network_configuration", None)?;
            println!(
                "{}",
                serde_json::to_string(&SyncResult {
                    schema_version: 1,
                    state: "waiting_for_network_configuration",
                    network_ready: false,
                    configuration_changed: false,
                    etag: state.etag.as_deref(),
                })?
            );
        }
        StatusCode::NOT_MODIFIED => {
            let etag = required_etag(&response)?;
            if state.etag.as_deref() != Some(etag.as_str()) {
                bail!("Cloud returned 304 with an unexpected ETag")
            }
            if state.activation_required
                && state.activation_rejected_etag.as_deref() != Some(etag.as_str())
                && (!candidate_matches_delivery(&args.state_dir, &etag)?
                    || candidate_grant_refresh_due(&args.state_dir)?)
            {
                if !allow_unconditional_retry {
                    bail!("Cloud returned 304 but the local activation needs revalidation")
                }
                state.etag = None;
                state.configuration_sha256 = None;
                atomic_json(&state_path, &state, 0o600)?;
                write_local_sync_status(
                    &args.state_dir,
                    "configuration_revalidation_required",
                    None,
                )?;
                return sync_once_with_retry(args, public_endpoints, false);
            }
            let activation_rejected =
                state.activation_rejected_etag.as_deref() == Some(etag.as_str());
            if activation_rejected {
                let now = unix_now()?;
                let rejected_at = state.activation_rejected_at_unix.get_or_insert(now);
                if now.saturating_sub(*rejected_at) >= ACTIVATION_REVALIDATION_SECONDS
                    && allow_unconditional_retry
                {
                    state.etag = None;
                    state.configuration_sha256 = None;
                    state.activation_rejected_etag = None;
                    state.activation_rejected_at_unix = None;
                    atomic_json(&state_path, &state, 0o600)?;
                    write_local_sync_status(
                        &args.state_dir,
                        "configuration_revalidation_required",
                        None,
                    )?;
                    return sync_once_with_retry(args, public_endpoints, false);
                }
                atomic_json(&state_path, &state, 0o600)?;
            }
            let result_state = if activation_rejected {
                "activation_rejected"
            } else {
                "configuration_unchanged"
            };
            write_local_sync_status(
                &args.state_dir,
                result_state,
                activation_rejected.then_some("local_activation_failed"),
            )?;
            println!(
                "{}",
                serde_json::to_string(&SyncResult {
                    schema_version: 1,
                    state: result_state,
                    network_ready: !activation_rejected,
                    configuration_changed: false,
                    etag: state.etag.as_deref(),
                })?
            );
        }
        StatusCode::OK => {
            require_content_type(&response, CONFIGURATION_MEDIA_TYPE)?;
            let etag = required_etag(&response)?;
            let bytes = bounded_response(response, MAX_CONFIGURATION_BYTES)?;
            let configuration: RuntimeConfiguration =
                serde_json::from_slice(&bytes).context("parse Runtime configuration")?;
            validate_configuration(&configuration, &identity)?;
            let segment = decode_envelope(&configuration.segment_snapshot, "segment snapshot")?;
            let projection = decode_envelope(&configuration.site_projection, "site projection")?;
            let peer_projections = decode_peer_projections(&configuration.peer_projection_catalog)?;
            let signed_objects_hash = configuration_objects_digest(
                &segment,
                &projection,
                &configuration.peer_projection_catalog,
                &peer_projections,
            );
            let digest = configuration_delivery_digest(&configuration, &signed_objects_hash)?;
            let expected = etag
                .strip_prefix("\"sha256-")
                .and_then(|value| value.strip_suffix('"'))
                .context("invalid Runtime configuration ETag")?;
            if digest != expected {
                bail!("Runtime configuration body does not match its ETag")
            }
            if let Err(error) = verify_control_with_core(
                &args.state_dir,
                args.core.as_deref(),
                &configuration,
                &identity,
                &segment,
                &projection,
            ) {
                report_configuration_status(
                    &client,
                    &cloud,
                    &configuration,
                    &etag,
                    "rejected",
                    Some("core_verification_failed"),
                )
                .context("report rejected Core verification to Cloud")?;
                return Err(error);
            }
            let discovery = match discover_control_with_core(
                &args.state_dir,
                args.core.as_deref(),
                &configuration,
                &identity,
                &segment,
                &projection,
            ) {
                Ok(report) => report,
                Err(error) => {
                    report_configuration_status(
                        &client,
                        &cloud,
                        &configuration,
                        &etag,
                        "rejected",
                        Some("core_discovery_failed"),
                    )?;
                    return Err(error);
                }
            };
            let core = resolve_core(args.core.as_deref())?;
            let resolved_grants = match resolve_grants(
                &args.state_dir,
                &core,
                &client,
                &cloud,
                &identity,
                &configuration,
                &discovery,
            ) {
                Ok(grants) => grants,
                Err(error) => {
                    report_configuration_status(
                        &client,
                        &cloud,
                        &configuration,
                        &etag,
                        "rejected",
                        Some("grant_resolution_failed"),
                    )?;
                    return Err(error);
                }
            };
            let discovery_bytes = serde_json::to_vec(&discovery)?;
            if let Err(error) = publish_configuration_generation(
                &args.state_dir,
                &digest,
                &segment,
                &projection,
                &configuration.peer_projection_catalog,
                &peer_projections,
                configuration.route_signing_public_key.as_bytes(),
                &bytes,
                &discovery_bytes,
            ) {
                report_configuration_status(
                    &client,
                    &cloud,
                    &configuration,
                    &etag,
                    "rejected",
                    Some("local_publish_failed"),
                )
                .context("report rejected local publication to Cloud")?;
                return Err(error);
            }
            let activation_result = if let Some(server_config) = args.server_config.as_deref() {
                activation_required(true, &configuration, &discovery).then(|| {
                    publish_server_activation(
                        &args.state_dir,
                        &identity_dir,
                        &core,
                        server_config,
                        &cloud,
                        &etag,
                        &digest,
                        &configuration,
                        &identity,
                        &segment,
                        &projection,
                        &peer_projections,
                        &discovery,
                        &resolved_grants,
                    )
                })
            } else {
                activation_required(false, &configuration, &discovery).then(|| {
                    publish_client_activation(
                        &args.state_dir,
                        &identity_dir,
                        &core,
                        &cloud,
                        &etag,
                        &digest,
                        &configuration,
                        &identity,
                        &segment,
                        &projection,
                        &discovery,
                        &resolved_grants,
                    )
                })
            };
            if let Some(result) = activation_result {
                if let Err(error) = result {
                    report_configuration_status(
                        &client,
                        &cloud,
                        &configuration,
                        &etag,
                        "rejected",
                        Some("local_activation_failed"),
                    )?;
                    return Err(error);
                }
                state.activation_required = true;
                state.activation_rejected_etag = None;
                state.activation_rejected_at_unix = None;
            } else {
                withdraw_local_activation(&args.state_dir)?;
                state.activation_required = false;
                state.activation_rejected_etag = None;
                state.activation_rejected_at_unix = None;
            }
            state.etag = Some(etag);
            state.configuration_sha256 = Some(digest);
            atomic_json(&state_path, &state, 0o600)?;
            let result_state = if state.activation_required {
                "activation_pending"
            } else {
                "configuration_updated"
            };
            write_local_sync_status(&args.state_dir, result_state, None)?;
            println!(
                "{}",
                serde_json::to_string(&SyncResult {
                    schema_version: 1,
                    state: result_state,
                    network_ready: !state.activation_required,
                    configuration_changed: true,
                    etag: state.etag.as_deref(),
                })?
            );
        }
        status => bail!("Cloud Runtime configuration request failed with HTTP {status}"),
    }
    if let Err(error) = report_runtime_telemetry(&client, &cloud, &args.state_dir, &args.run_dir) {
        eprintln!(
            "level=warn event=runtime_telemetry_report_failed error={}",
            sanitize_log_value(&format!("{error:#}"))
        );
    }
    Ok(())
}

fn report_runtime_telemetry(
    client: &Client,
    cloud: &Url,
    state_dir: &Path,
    run_dir: &Path,
) -> Result<()> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("read kernel boot id")?
        .trim()
        .parse::<Uuid>()
        .context("parse kernel boot id")?;
    let observed_monotonic_ms = monotonic_millis()?.max(1);
    let sample_path = state_dir.join("runtime-telemetry-sample-v1.json");
    let previous_sample =
        read_bounded_json::<RuntimeTelemetrySample>(&sample_path, MAX_PROFILE_BYTES)
            .ok()
            .filter(|sample| sample.schema_version == 1 && sample.boot_id == boot_id);
    let sequence = previous_sample
        .as_ref()
        .map_or(observed_monotonic_ms, |sample| {
            observed_monotonic_ms.max(sample.sequence.saturating_add(1))
        });
    let core_status = read_active_core_status(state_dir, run_dir)?;
    let current_sample = core_status
        .as_ref()
        .filter(|status| status.schema_version >= 2)
        .map(|status| runtime_telemetry_sample(boot_id, sequence, observed_monotonic_ms, status));
    let performance = derive_runtime_performance(
        core_status.as_ref(),
        previous_sample.as_ref(),
        current_sample.as_ref(),
    );
    let path_performance = match derive_runtime_paths(
        core_status.as_ref(),
        previous_sample.as_ref(),
        current_sample.as_ref(),
    ) {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!(
                "level=warn event=runtime_path_telemetry_omitted reason={}",
                sanitize_log_value(&format!("{error:#}"))
            );
            Vec::new()
        }
    };
    let local_networks = match discover_local_networks() {
        Ok(networks) => Some(networks),
        Err(error) => {
            eprintln!(
                "level=warn event=local_network_telemetry_omitted reason={}",
                sanitize_log_value(&format!("{error:#}"))
            );
            None
        }
    };
    let local_status = read_local_runtime_status(state_dir).ok();
    let lifecycle = if core_status
        .as_ref()
        .is_some_and(|status| status.fail_open_required)
    {
        "fail_open"
    } else if let Some(status) = core_status.as_ref() {
        match status.lifecycle.as_str() {
            "active" => "active",
            "starting" => "starting",
            "degraded" => "degraded",
            "failed" => "fail_open",
            _ => "unknown",
        }
    } else {
        match local_status
            .as_ref()
            .map(|status| status.runtime.state.as_str())
        {
            Some("fail-open") => "fail_open",
            Some("stopped") => "stopped",
            Some("reconnecting" | "running") => "starting",
            _ => "unknown",
        }
    };
    let empty = CoreRuntimeStatus {
        schema_version: 1,
        generation: 0,
        pid: 0,
        lifecycle: "unknown".into(),
        configured_peers: 0,
        active_peers: 0,
        required_route_owners: 0,
        ready_route_owners: 0,
        fail_open_required: lifecycle == "fail_open",
        last_error_code: None,
        counters: CorePacketCounters::default(),
        paths: Vec::new(),
        reconnects: 0,
        path_changes: 0,
    };
    let status = core_status.as_ref().unwrap_or(&empty);
    let response = client
        .put(endpoint(cloud, "auth/v1/runtime/telemetry")?)
        .json(&RuntimeTelemetry {
            schema_version: 1,
            boot_id,
            sequence,
            lifecycle,
            configured_peers: status.configured_peers,
            active_peers: status.active_peers,
            required_route_owners: status.required_route_owners,
            ready_route_owners: status.ready_route_owners,
            fail_open_required: lifecycle == "fail_open",
            last_error_code: status.last_error_code.as_deref(),
            rtt_ms: performance.rtt_ms,
            jitter_ms: performance.jitter_ms,
            packet_loss_ppm: performance.packet_loss_ppm,
            rx_bps: performance.rx_bps,
            tx_bps: performance.tx_bps,
            reconnects: performance.reconnects,
            path_changes: performance.path_changes,
            paths: &path_performance,
            local_networks: local_networks.as_deref(),
        })
        .send()
        .context("report Runtime telemetry")?;
    if response.status() != StatusCode::NO_CONTENT {
        bail!(
            "Cloud rejected Runtime telemetry with HTTP {}",
            response.status()
        )
    }
    if let Some(sample) = current_sample {
        atomic_json(&sample_path, &sample, 0o600)?;
    }
    Ok(())
}

fn discover_local_networks() -> Result<Vec<LocalNetworkTelemetry>> {
    let mut child = ProcessCommand::new("ip")
        .args([
            "-o", "-4", "route", "show", "table", "main", "proto", "kernel", "scope", "link",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("run IPv4 connected-route discovery")?;
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if started.elapsed() >= LOCAL_ROUTE_DISCOVERY_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!("IPv4 connected-route discovery timed out")
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let status = child.wait()?;
    let stdout = child
        .stdout
        .take()
        .context("read IPv4 route discovery output")?;
    let mut bytes = Vec::new();
    stdout
        .take((MAX_LOCAL_ROUTE_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read IPv4 connected-route discovery output")?;
    if !status.success() {
        bail!(
            "IPv4 connected-route discovery exited with status {}",
            status
        )
    }
    if bytes.len() > MAX_LOCAL_ROUTE_OUTPUT_BYTES {
        bail!("IPv4 connected-route discovery output exceeds the reporting bound")
    }
    let routes = std::str::from_utf8(&bytes)
        .context("IPv4 connected-route discovery output is not UTF-8")?;
    Ok(parse_local_networks(routes))
}

fn parse_local_networks(routes: &str) -> Vec<LocalNetworkTelemetry> {
    let mut networks = routes
        .lines()
        .filter_map(parse_local_network_route)
        .collect::<Vec<_>>();
    networks.sort_by(|left, right| {
        (&left.interface_name, &left.cidr, &left.address).cmp(&(
            &right.interface_name,
            &right.cidr,
            &right.address,
        ))
    });
    networks.dedup_by(|current, previous| {
        current.interface_name == previous.interface_name && current.cidr == previous.cidr
    });
    networks.truncate(MAX_LOCAL_NETWORKS);
    networks
}

fn parse_local_network_route(route: &str) -> Option<LocalNetworkTelemetry> {
    let fields = route.split_ascii_whitespace().collect::<Vec<_>>();
    let destination = *fields.first()?;
    if destination == "default" {
        return None;
    }
    let interface_name = route_field(&fields, "dev")?;
    let source = route_field(&fields, "src")?;
    if !valid_interface_name(interface_name) || virtual_interface(interface_name) {
        return None;
    }
    let (network, prefix, cidr) = canonical_ipv4_cidr(destination)?;
    let address = source.parse::<Ipv4Addr>().ok()?;
    if excluded_ipv4(network) || excluded_ipv4(address) || ipv4_network(address, prefix) != network
    {
        return None;
    }
    let address_text = address.to_string();
    if cidr.len() > 64 || address_text.len() > 64 {
        return None;
    }
    let network_id = local_network_id(interface_name, &cidr);
    debug_assert_eq!(network_id.len(), 64);
    Some(LocalNetworkTelemetry {
        network_id,
        interface_name: interface_name.to_owned(),
        cidr,
        address: address_text,
        kind: "direct_ipv4",
    })
}

fn route_field<'a>(fields: &'a [&str], name: &str) -> Option<&'a str> {
    fields
        .windows(2)
        .find_map(|pair| (pair[0] == name).then_some(pair[1]))
}

fn valid_interface_name(interface_name: &str) -> bool {
    !interface_name.is_empty()
        && interface_name.len() <= 15
        && interface_name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@')
        })
}

fn virtual_interface(interface_name: &str) -> bool {
    let interface_name = interface_name.to_ascii_lowercase();
    interface_name.contains("candy")
        || interface_name.starts_with("tun")
        || interface_name.starts_with("utun")
        || ["docker", "virbr", "veth", "wg", "tailscale", "zt"]
            .iter()
            .any(|prefix| interface_name.starts_with(prefix))
}

fn canonical_ipv4_cidr(value: &str) -> Option<(Ipv4Addr, u8, String)> {
    let (address, prefix) = value.split_once('/')?;
    let address = address.parse::<Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }
    let network = ipv4_network(address, prefix);
    Some((network, prefix, format!("{network}/{prefix}")))
}

fn ipv4_network(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ipv4Addr::from(u32::from(address) & mask)
}

fn excluded_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_link_local()
        || !(octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
            || (octets[0] == 100 && (64..=127).contains(&octets[1])))
}

fn local_network_id(interface_name: &str, cidr: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"local-network-v1\0");
    digest.update(interface_name.as_bytes());
    digest.update(b"\0");
    digest.update(cidr.as_bytes());
    format!("{:x}", digest.finalize())
}

fn runtime_telemetry_sample(
    boot_id: Uuid,
    sequence: u64,
    observed_monotonic_ms: u64,
    status: &CoreRuntimeStatus,
) -> RuntimeTelemetrySample {
    RuntimeTelemetrySample {
        schema_version: 1,
        boot_id,
        sequence,
        core_pid: status.pid,
        generation: status.generation,
        observed_monotonic_ms,
        tun_bytes_received: status.counters.tun_bytes_received,
        tun_bytes_sent: status.counters.tun_bytes_sent,
        paths: status
            .paths
            .iter()
            .map(|path| {
                (
                    path.peer_attachment_id.clone(),
                    RuntimePathSample {
                        connection_epoch: path.connection_epoch,
                        tx_bytes: path.tx_bytes,
                        rx_bytes: path.rx_bytes,
                        sent_packets: path.sent_packets,
                        lost_packets: path.lost_packets,
                    },
                )
            })
            .collect(),
    }
}

fn derive_runtime_performance(
    status: Option<&CoreRuntimeStatus>,
    previous: Option<&RuntimeTelemetrySample>,
    current: Option<&RuntimeTelemetrySample>,
) -> DerivedRuntimePerformance {
    let Some(status) = status.filter(|status| status.schema_version >= 2) else {
        return DerivedRuntimePerformance::default();
    };
    let rtt_ms = status
        .paths
        .iter()
        .filter(|path| path.rtt_micros > 0)
        .map(|path| micros_to_millis(path.rtt_micros))
        .max();
    let jitter_ms = status
        .paths
        .iter()
        .filter(|path| path.rtt_sample_count >= 2)
        .map(|path| micros_to_millis(path.rtt_variance_micros))
        .max();
    let mut performance = DerivedRuntimePerformance {
        rtt_ms,
        jitter_ms,
        reconnects: Some(status.reconnects),
        path_changes: Some(status.path_changes),
        ..DerivedRuntimePerformance::default()
    };
    let (Some(previous), Some(current)) = (previous, current) else {
        return performance;
    };
    if previous.boot_id != current.boot_id
        || previous.core_pid != current.core_pid
        || previous.generation != current.generation
        || current.observed_monotonic_ms <= previous.observed_monotonic_ms
    {
        return performance;
    }
    let elapsed_ms = current
        .observed_monotonic_ms
        .saturating_sub(previous.observed_monotonic_ms);
    if (1_000..=300_000).contains(&elapsed_ms)
        && current.tun_bytes_received >= previous.tun_bytes_received
        && current.tun_bytes_sent >= previous.tun_bytes_sent
    {
        performance.tx_bps = Some(rate_bps(
            current
                .tun_bytes_received
                .saturating_sub(previous.tun_bytes_received),
            elapsed_ms,
        ));
        performance.rx_bps = Some(rate_bps(
            current
                .tun_bytes_sent
                .saturating_sub(previous.tun_bytes_sent),
            elapsed_ms,
        ));
    }
    let mut sent_packets = 0_u64;
    let mut lost_packets = 0_u64;
    for (attachment_id, current_path) in &current.paths {
        let Some(previous_path) = previous.paths.get(attachment_id) else {
            continue;
        };
        if current_path.connection_epoch != previous_path.connection_epoch
            || current_path.sent_packets < previous_path.sent_packets
            || current_path.lost_packets < previous_path.lost_packets
        {
            continue;
        }
        sent_packets = sent_packets.saturating_add(
            current_path
                .sent_packets
                .saturating_sub(previous_path.sent_packets),
        );
        lost_packets = lost_packets.saturating_add(
            current_path
                .lost_packets
                .saturating_sub(previous_path.lost_packets),
        );
    }
    if sent_packets > 0 {
        performance.packet_loss_ppm = Some(
            ((u128::from(lost_packets.min(sent_packets)) * 1_000_000) / u128::from(sent_packets))
                as u32,
        );
    }
    performance
}

fn derive_runtime_paths(
    status: Option<&CoreRuntimeStatus>,
    previous: Option<&RuntimeTelemetrySample>,
    current: Option<&RuntimeTelemetrySample>,
) -> Result<Vec<RuntimePathTelemetry>> {
    let Some(status) = status.filter(|status| status.schema_version >= 2) else {
        return Ok(Vec::new());
    };
    if status.paths.len() > 256 {
        bail!("Core Runtime path telemetry exceeds the Cloud reporting bound")
    }
    let interval = previous.zip(current).filter(|(previous, current)| {
        previous.boot_id == current.boot_id
            && previous.core_pid == current.core_pid
            && previous.generation == current.generation
            && current.observed_monotonic_ms > previous.observed_monotonic_ms
            && (1_000..=300_000).contains(
                &current
                    .observed_monotonic_ms
                    .saturating_sub(previous.observed_monotonic_ms),
            )
    });
    status
        .paths
        .iter()
        .map(|path| {
            let mut result = RuntimePathTelemetry {
                peer_attachment_id: canonical_uuid_hex(&path.peer_attachment_id)?,
                candidate_id: path
                    .candidate_id
                    .as_deref()
                    .map(canonical_uuid_hex)
                    .transpose()?,
                path_kind: path.path_kind.clone(),
                transport: path.transport.clone(),
                connection_epoch: path.connection_epoch,
                rtt_ms: (path.rtt_micros > 0).then(|| micros_to_millis(path.rtt_micros)),
                jitter_ms: (path.rtt_sample_count >= 2)
                    .then(|| micros_to_millis(path.rtt_variance_micros)),
                packet_loss_ppm: None,
                rx_bps: None,
                tx_bps: None,
                reconnects: path.reconnects,
                path_changes: path.path_changes,
            };
            let Some((previous, current)) = interval else {
                return Ok(result);
            };
            let Some(previous_path) = previous.paths.get(&path.peer_attachment_id) else {
                return Ok(result);
            };
            let Some(current_path) = current.paths.get(&path.peer_attachment_id) else {
                return Ok(result);
            };
            if previous_path.connection_epoch != current_path.connection_epoch
                || current_path.tx_bytes < previous_path.tx_bytes
                || current_path.rx_bytes < previous_path.rx_bytes
                || current_path.sent_packets < previous_path.sent_packets
                || current_path.lost_packets < previous_path.lost_packets
            {
                return Ok(result);
            }
            let elapsed_ms = current
                .observed_monotonic_ms
                .saturating_sub(previous.observed_monotonic_ms);
            result.tx_bps = Some(rate_bps(
                current_path.tx_bytes.saturating_sub(previous_path.tx_bytes),
                elapsed_ms,
            ));
            result.rx_bps = Some(rate_bps(
                current_path.rx_bytes.saturating_sub(previous_path.rx_bytes),
                elapsed_ms,
            ));
            let sent = current_path
                .sent_packets
                .saturating_sub(previous_path.sent_packets);
            let lost = current_path
                .lost_packets
                .saturating_sub(previous_path.lost_packets);
            if sent > 0 {
                result.packet_loss_ppm =
                    Some(((u128::from(lost.min(sent)) * 1_000_000) / u128::from(sent)) as u32);
            }
            Ok(result)
        })
        .collect()
}

fn canonical_uuid_hex(value: &str) -> Result<String> {
    validate_hex(value, 16, "Runtime path identifier")?;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &value[..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..]
    ))
}

fn micros_to_millis(value: u64) -> u32 {
    value
        .saturating_add(999)
        .saturating_div(1_000)
        .min(u64::from(u32::MAX)) as u32
}

fn rate_bps(bytes: u64, elapsed_ms: u64) -> u64 {
    ((u128::from(bytes) * 8_000) / u128::from(elapsed_ms.max(1))).min(u128::from(u64::MAX)) as u64
}

fn read_active_core_status(state_dir: &Path, run_dir: &Path) -> Result<Option<CoreRuntimeStatus>> {
    let active = state_dir.join("active");
    let target = match fs::read_link(&active) {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read active Runtime pointer"),
    };
    let components = target.components().collect::<Vec<_>>();
    if components.len() != 2
        || components[0] != std::path::Component::Normal("activations".as_ref())
    {
        bail!("active Runtime pointer has an invalid target")
    }
    let activation_id = components[1]
        .as_os_str()
        .to_str()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .context("active Runtime pointer has an invalid activation id")?;
    let activation_directory = state_dir.join(&target);
    let metadata =
        fs::symlink_metadata(&activation_directory).context("inspect active Runtime activation")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("active Runtime activation must be a real directory")
    }
    let descriptor: ActivationDescriptor = read_bounded_json(
        &activation_directory.join("activation-v1.json"),
        MAX_PROFILE_BYTES,
    )?;
    if descriptor.schema_version != 1
        || descriptor.activation_id != activation_id
        || descriptor.projection_generation == 0
    {
        bail!("active Runtime activation descriptor is invalid")
    }
    let paths = [
        run_dir.join("sdwan-status.json"),
        run_dir.join(format!("sdwan-{activation_id}.status.json")),
    ];
    let mut status = None;
    for path in paths {
        if !path.exists() {
            continue;
        }
        let candidate: CoreRuntimeStatus = read_bounded_json(&path, MAX_PROFILE_BYTES)
            .context("read active Core Runtime status")?;
        if candidate.generation == descriptor.projection_generation {
            status = Some(candidate);
            break;
        }
    }
    let Some(status) = status else {
        return Ok(None);
    };
    if !matches!(status.schema_version, 1 | 2)
        || status.pid == 0
        || !process_is_alive(status.pid)
        || !matches!(
            status.lifecycle.as_str(),
            "starting" | "active" | "stopping" | "stopped" | "failed" | "degraded"
        )
        || status.active_peers > status.configured_peers
        || status.ready_route_owners > status.required_route_owners
        || status.ready_route_owners > status.active_peers
        || status.last_error_code.as_deref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 80
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    {
        bail!("active Core Runtime status is invalid")
    }
    if status.schema_version >= 2 {
        validate_core_path_status(&status)?;
    }
    Ok(Some(status))
}

fn validate_core_path_status(status: &CoreRuntimeStatus) -> Result<()> {
    if status.paths.len() > status.active_peers as usize {
        bail!("active Core Runtime path count exceeds active peers")
    }
    let mut paths = BTreeMap::new();
    for path in &status.paths {
        validate_hex(&path.peer_attachment_id, 16, "Core path peer attachment id")?;
        if let Some(candidate_id) = &path.candidate_id {
            validate_hex(candidate_id, 16, "Core path candidate id")?;
        }
        if !matches!(path.path_kind.as_str(), "direct" | "relay")
            || path.transport != "quic_udp"
            || path.connection_epoch == 0
            || path.lost_packets > path.sent_packets
            || path.rtt_micros > 60_000_000
            || path.rtt_variance_micros > 60_000_000
            || path.rtt_sample_count == 0
            || path.path_mtu < 1_200
            || path.congestion_window_bytes == 0
            || path.reconnects > status.reconnects
            || path.path_changes > status.path_changes
            || paths.insert(&path.peer_attachment_id, ()).is_some()
        {
            bail!("active Core Runtime path telemetry is invalid")
        }
        let _ = (path.tx_bytes, path.rx_bytes);
    }
    Ok(())
}

fn process_is_alive(pid: u32) -> bool {
    if pid > i32::MAX as u32 {
        return false;
    }
    #[cfg(unix)]
    {
        let result = unsafe { nix::libc::kill(pid as nix::libc::pid_t, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn read_local_runtime_status(state_dir: &Path) -> Result<LocalRuntimeStatus> {
    let status: LocalRuntimeStatus =
        read_bounded_json(&state_dir.join("status-v1.json"), MAX_PROFILE_BYTES)?;
    if status.schema_version != 1 {
        bail!("local Runtime status has an unsupported schema")
    }
    Ok(status)
}

fn monotonic_millis() -> Result<u64> {
    let uptime = fs::read_to_string("/proc/uptime").context("read monotonic clock")?;
    let seconds = uptime
        .split_whitespace()
        .next()
        .context("kernel uptime is empty")?
        .parse::<f64>()
        .context("parse kernel uptime")?;
    if !seconds.is_finite() || seconds < 0.0 {
        bail!("kernel uptime is invalid")
    }
    Ok((seconds * 1000.0) as u64)
}

fn sanitize_log_value(value: &str) -> String {
    value
        .chars()
        .take(512)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn reconcile_transport_identity(
    args: &Args,
    public_endpoints: &[SocketAddr],
    client: &Client,
    cloud: &Url,
) -> Result<()> {
    if public_endpoints.is_empty() {
        return Ok(());
    }
    let server_config = args
        .server_config
        .as_deref()
        .context("explicit public-endpoint requires --server-config")?;
    let core = resolve_core(args.core.as_deref())?;
    let inspected = transport_identity::inspect_core(&core, server_config)?;
    let desired = transport_identity::build_registration(&inspected, public_endpoints)?;
    let outcome = transport_identity::reconcile(
        &args.state_dir.join("transport-identity-state-v1.json"),
        desired,
        |request| {
            transport_identity::put_to_cloud(
                client,
                endpoint(cloud, "auth/v1/runtime/transport-identity")?,
                request,
            )
        },
    )?;
    eprintln!(
        "level=info event=transport_identity_reconciled outcome={outcome:?} endpoint_count={}",
        public_endpoints.len()
    );
    Ok(())
}

fn write_local_sync_status(state_dir: &Path, state: &str, error_code: Option<&str>) -> Result<()> {
    let updated_at = unix_now()?;
    atomic_json(
        &state_dir.join("cloud-sync-status-v1.json"),
        &LocalSyncStatus {
            schema_version: 1,
            state,
            updated_at,
            error_code,
        },
        0o600,
    )
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system clock")?
        .as_secs())
}

fn candidate_activation_directory(state_dir: &Path) -> Result<Option<PathBuf>> {
    let candidate = state_dir.join("candidate");
    let metadata = match fs::symlink_metadata(&candidate) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect Runtime candidate pointer"),
    };
    if !metadata.file_type().is_symlink() {
        bail!("Runtime candidate pointer must be a symbolic link")
    }
    let target = fs::read_link(&candidate).context("read Runtime candidate pointer")?;
    let components = target.components().collect::<Vec<_>>();
    if components.len() != 2
        || components[0] != std::path::Component::Normal("activations".as_ref())
        || !matches!(components[1], std::path::Component::Normal(_))
    {
        bail!("Runtime candidate pointer has an invalid target")
    }
    let id = components[1]
        .as_os_str()
        .to_str()
        .context("Runtime candidate id is not UTF-8")?;
    validate_hex(id, 32, "Runtime candidate id")?;
    let directory = state_dir.join(target);
    let directory_metadata =
        fs::symlink_metadata(&directory).context("inspect Runtime candidate activation")?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        bail!("Runtime candidate activation must be a real directory")
    }
    Ok(Some(directory))
}

fn candidate_descriptor(state_dir: &Path) -> Result<Option<ActivationDescriptor>> {
    let Some(directory) = candidate_activation_directory(state_dir)? else {
        return Ok(None);
    };
    let descriptor: ActivationDescriptor =
        read_bounded_json(&directory.join("activation-v1.json"), MAX_PROFILE_BYTES)?;
    validate_hex(&descriptor.activation_id, 32, "activation id")?;
    validate_hex(
        &descriptor.delivery_sha256,
        32,
        "activation delivery digest",
    )?;
    if descriptor.schema_version != 1
        || directory.file_name().and_then(|name| name.to_str())
            != Some(descriptor.activation_id.as_str())
        || descriptor.delivery_etag != format!("\"sha256-{}\"", descriptor.delivery_sha256)
        || descriptor.segment_generation == 0
        || descriptor.projection_generation == 0
        || descriptor.grant_refresh_after_unix > descriptor.grant_expires_at_unix
    {
        bail!("Runtime candidate activation descriptor is invalid")
    }
    Ok(Some(descriptor))
}

fn candidate_matches_delivery(state_dir: &Path, etag: &str) -> Result<bool> {
    Ok(candidate_descriptor(state_dir)?.is_some_and(|descriptor| descriptor.delivery_etag == etag))
}

fn candidate_grant_refresh_due(state_dir: &Path) -> Result<bool> {
    let Some(descriptor) = candidate_descriptor(state_dir)? else {
        return Ok(true);
    };
    if descriptor.grant_refresh_after_unix == 0 && descriptor.grant_expires_at_unix == 0 {
        return Ok(false);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system time for candidate Grant refresh")?
        .as_secs();
    Ok(now >= descriptor.grant_refresh_after_unix || now >= descriptor.grant_expires_at_unix)
}

fn read_activation_ready_receipt(state_dir: &Path) -> Result<Option<ActivationOutcome>> {
    let path = state_dir.join("activation-ready-v1.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect SD-WAN activation receipt"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("SD-WAN activation receipt must be a regular file")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!("SD-WAN activation receipt must have mode 0600")
        }
        let owner = fs::symlink_metadata(state_dir).context("inspect SD-WAN state owner")?;
        if metadata.uid() != owner.uid() || metadata.gid() != owner.gid() {
            bail!("SD-WAN activation receipt owner does not match the state owner")
        }
    }
    let receipt: ActivationReadyReceipt = read_bounded_json(&path, MAX_PROFILE_BYTES)?;
    validate_hex(&receipt.activation_id, 32, "activation receipt id")?;
    let expected_target = format!("activations/{}", receipt.activation_id);
    if receipt.schema_version != 1
        || !matches!(receipt.state.as_str(), "committed" | "rejected")
        || receipt.candidate_target != expected_target
        || receipt.generation == 0
        || receipt.agent_pid == 0
    {
        bail!("SD-WAN activation receipt metadata is invalid")
    }
    let candidate = state_dir.join("candidate");
    match fs::read_link(&candidate) {
        Ok(target) if target == Path::new(&receipt.candidate_target) => {}
        Ok(_) => {
            clear_activation_ready_receipt(state_dir)?;
            return Ok(None);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            clear_activation_ready_receipt(state_dir)?;
            return Ok(None);
        }
        Err(error) => return Err(error).context("inspect candidate for activation receipt"),
    }
    #[cfg(target_os = "linux")]
    if receipt.state == "committed" {
        use std::os::unix::fs::MetadataExt;
        let process = PathBuf::from(format!("/proc/{}", receipt.agent_pid));
        let process_metadata = fs::metadata(&process)
            .with_context(|| format!("inspect SD-WAN agent process {}", receipt.agent_pid))?;
        let owner = fs::symlink_metadata(state_dir).context("inspect SD-WAN state owner")?;
        if process_metadata.uid() != owner.uid() {
            bail!("SD-WAN activation receipt process owner does not match the state owner")
        }
    }
    #[cfg(unix)]
    if receipt.state == "committed"
        && unsafe { nix::libc::kill(receipt.agent_pid as nix::libc::pid_t, 0) } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(nix::libc::EPERM) {
            return Err(error).context("verify SD-WAN agent process is alive");
        }
    }
    let descriptor = candidate_descriptor(state_dir)?
        .context("SD-WAN activation receipt has no matching candidate")?;
    if descriptor.activation_id != receipt.activation_id
        || descriptor.projection_generation != receipt.generation
    {
        bail!("SD-WAN activation receipt does not match the candidate")
    }
    if (receipt.state == "committed" && receipt.error_code.is_some())
        || (receipt.state == "rejected"
            && receipt
                .error_code
                .as_deref()
                .is_none_or(|value| value.is_empty() || value.len() > 80 || !value.is_ascii()))
    {
        bail!("SD-WAN activation receipt result is invalid")
    }
    Ok(Some(ActivationOutcome {
        receipt,
        descriptor,
    }))
}

fn promote_committed_activation(state_dir: &Path, activation: &ActivationOutcome) -> Result<()> {
    let candidate_target = fs::read_link(state_dir.join("candidate"))
        .context("read SD-WAN candidate pointer before promotion")?;
    if candidate_target != Path::new(&activation.receipt.candidate_target) {
        bail!("SD-WAN candidate changed before activation promotion")
    }
    publish_pointer(state_dir, "active", candidate_target)
}

fn remove_candidate_if_matches(state_dir: &Path, activation: &ActivationOutcome) -> Result<()> {
    let candidate = state_dir.join("candidate");
    match fs::read_link(&candidate) {
        Ok(target) if target == Path::new(&activation.receipt.candidate_target) => {
            fs::remove_file(&candidate).context("remove rejected SD-WAN candidate")?;
            File::open(state_dir)
                .and_then(|directory| directory.sync_all())
                .context("sync rejected SD-WAN candidate removal")?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect rejected SD-WAN candidate"),
    }
    Ok(())
}

fn report_activation_status(
    client: &Client,
    cloud: &Url,
    activation: &ActivationOutcome,
    state: &str,
    error_code: Option<&str>,
) -> Result<()> {
    let response = client
        .put(endpoint(cloud, "auth/v1/runtime/configuration/status")?)
        .header(IF_MATCH, &activation.descriptor.delivery_etag)
        .json(&ConfigurationStatus {
            projection_publication_id: activation.descriptor.projection_publication_id,
            projection_content_hash: &activation.descriptor.projection_content_hash,
            state,
            error_code,
        })
        .send()
        .context("report SD-WAN activation status")?;
    if response.status() != StatusCode::NO_CONTENT {
        bail!(
            "Cloud rejected SD-WAN activation status with HTTP {}",
            response.status()
        )
    }
    Ok(())
}

fn clear_activation_ready_receipt(state_dir: &Path) -> Result<()> {
    let path = state_dir.join("activation-ready-v1.json");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("SD-WAN activation receipt must be a regular file")
            }
            fs::remove_file(&path).context("remove committed SD-WAN activation receipt")?;
            File::open(state_dir)
                .and_then(|directory| directory.sync_all())
                .context("sync removed SD-WAN activation receipt")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect SD-WAN activation receipt"),
    }
    Ok(())
}

fn withdraw_local_activation(state_dir: &Path) -> Result<()> {
    for name in ["candidate", "active"] {
        let path = state_dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_symlink() {
                    bail!("Runtime {name} pointer must be a symbolic link")
                }
                fs::remove_file(&path)
                    .with_context(|| format!("withdraw Runtime {name} pointer"))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspect Runtime {name} pointer"))
            }
        }
    }
    File::open(state_dir)
        .and_then(|directory| directory.sync_all())
        .context("sync withdrawn Runtime activation pointers")
}

fn report_configuration_status(
    client: &Client,
    cloud: &Url,
    configuration: &RuntimeConfiguration,
    etag: &str,
    state: &str,
    error_code: Option<&str>,
) -> Result<()> {
    let response = client
        .put(endpoint(cloud, "auth/v1/runtime/configuration/status")?)
        .header(IF_MATCH, etag)
        .json(&ConfigurationStatus {
            projection_publication_id: configuration.projection_publication_id,
            projection_content_hash: &configuration.projection_content_hash,
            state,
            error_code,
        })
        .send()
        .context("report Runtime configuration status")?;
    if response.status() != StatusCode::NO_CONTENT {
        bail!(
            "Cloud rejected Runtime configuration status with HTTP {}",
            response.status()
        )
    }
    Ok(())
}

fn verify_control_with_core(
    state_dir: &Path,
    requested_core: Option<&Path>,
    configuration: &RuntimeConfiguration,
    identity: &DeviceIdentity,
    segment: &[u8],
    projection: &[u8],
) -> Result<()> {
    let core = resolve_core(requested_core)?;
    let verification = state_dir.join(format!(".verify.{}", Uuid::new_v4()));
    ensure_private_directory(&verification)?;
    let result = (|| {
        let segment_path = verification.join("segment.snapshot");
        let projection_path = verification.join("site.projection");
        atomic_bytes(&segment_path, segment, 0o600)?;
        atomic_bytes(&projection_path, projection, 0o600)?;
        let output = ProcessCommand::new(&core)
            .args(["client", "sdwan", "verify-control", "--segment-snapshot"])
            .arg(&segment_path)
            .arg("--site-projection")
            .arg(&projection_path)
            .arg("--route-signing-public-key")
            .arg(&configuration.route_signing_public_key)
            .arg("--route-signing-key-id")
            .arg(&configuration.route_signing_key_id)
            .output()
            .context("run Candy Core signed-control verification")?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            bail!(
                "Candy Core rejected signed SD-WAN control: {}",
                detail.chars().take(1024).collect::<String>()
            )
        }
        if output.stdout.is_empty() || output.stdout.len() > 64 * 1024 {
            bail!("Candy Core returned an invalid signed-control report")
        }
        let report: VerifiedControlReport = serde_json::from_slice(&output.stdout)
            .context("parse Candy Core verification report")?;
        validate_verified_report(&report, configuration, identity)
    })();
    let cleanup = fs::remove_dir_all(&verification).context("remove Core verification staging");
    result.and(cleanup)
}

fn render_core_control_config(
    directory: &Path,
    configuration: &RuntimeConfiguration,
    peers: &[(&DiscoveredCandidate, u64, &Path)],
) -> Result<String> {
    let path = |name: &str| -> Result<String> {
        Ok(serde_json::to_string(
            directory
                .join(name)
                .to_str()
                .context("Runtime generation path is not UTF-8")?,
        )?)
    };
    let mut output = String::new();
    use std::fmt::Write as _;
    writeln!(&mut output, "schema_version = 1")?;
    writeln!(
        &mut output,
        "segment_snapshot = {}",
        path("segment.snapshot")?
    )?;
    writeln!(
        &mut output,
        "site_projection = {}",
        path("site.projection")?
    )?;
    writeln!(
        &mut output,
        "route_signing_public_key = {}",
        serde_json::to_string(&configuration.route_signing_public_key)?
    )?;
    writeln!(
        &mut output,
        "route_signing_key_id = {}",
        serde_json::to_string(&configuration.route_signing_key_id)?
    )?;
    writeln!(&mut output, "underlay_exclusions_locked = true")?;
    writeln!(&mut output, "local_preflight_passed = true")?;
    for key in &configuration.grant_verification_keys {
        writeln!(&mut output, "\n[[grant_verification_keys]]")?;
        writeln!(
            &mut output,
            "key_id = {}",
            serde_json::to_string(&key.key_id)?
        )?;
        writeln!(
            &mut output,
            "public_key = {}",
            serde_json::to_string(&key.ed25519_public_key)?
        )?;
        writeln!(
            &mut output,
            "issuer_id = {}",
            serde_json::to_string(&key.issuer_id.simple().to_string())?
        )?;
        writeln!(
            &mut output,
            "environment_id = {}",
            serde_json::to_string(&key.environment_id.simple().to_string())?
        )?;
    }
    for (candidate, tunnel_id, transport) in peers {
        writeln!(&mut output, "\n[[peers]]")?;
        writeln!(
            &mut output,
            "candidate_id = {}",
            serde_json::to_string(&candidate.candidate_id)?
        )?;
        writeln!(&mut output, "tunnel_id = {tunnel_id}")?;
        writeln!(
            &mut output,
            "transport_config = {}",
            serde_json::to_string(
                transport
                    .to_str()
                    .context("transport config path is not UTF-8")?
            )?
        )?;
    }
    Ok(output)
}

fn discover_control_with_core(
    state_dir: &Path,
    requested_core: Option<&Path>,
    configuration: &RuntimeConfiguration,
    identity: &DeviceIdentity,
    segment: &[u8],
    projection: &[u8],
) -> Result<DiscoveredControlReport> {
    let core = resolve_core(requested_core)?;
    let staging = state_dir.join(format!(".discover.{}", Uuid::new_v4()));
    ensure_private_directory(&staging)?;
    let result = (|| {
        atomic_bytes(&staging.join("segment.snapshot"), segment, 0o600)?;
        atomic_bytes(&staging.join("site.projection"), projection, 0o600)?;
        let config = render_core_control_config(&staging, configuration, &[])?;
        let config_path = staging.join("core.toml");
        atomic_bytes(&config_path, config.as_bytes(), 0o600)?;
        let output = ProcessCommand::new(&core)
            .args(["client", "sdwan", "discover-control", "--config"])
            .arg(&config_path)
            .output()
            .context("run Candy Core signed-control discovery")?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            bail!(
                "Candy Core rejected SD-WAN control discovery: {}",
                detail.chars().take(1024).collect::<String>()
            )
        }
        if output.stdout.is_empty() || output.stdout.len() > 1024 * 1024 {
            bail!("Candy Core returned an invalid control discovery report")
        }
        let report: DiscoveredControlReport = serde_json::from_slice(&output.stdout)
            .context("parse Candy Core control discovery report")?;
        validate_discovered_control(&report, configuration, identity)?;
        Ok(report)
    })();
    let cleanup = fs::remove_dir_all(&staging).context("remove Core discovery staging");
    match (result, cleanup) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn validate_discovered_control(
    report: &DiscoveredControlReport,
    configuration: &RuntimeConfiguration,
    identity: &DeviceIdentity,
) -> Result<()> {
    let uuid_hex = |value: Uuid| value.simple().to_string();
    if report.schema_version != 1
        || !report.ok
        || identity.tenant_id.map(uuid_hex).as_deref() != Some(report.tenant_id.as_str())
        || report.segment_id != uuid_hex(configuration.segment_id)
        || identity.site_id.map(uuid_hex).as_deref() != Some(report.site_id.as_str())
        || report.attachment_id != uuid_hex(configuration.attachment_id)
        || report.device_id != uuid_hex(identity.device_id)
        || report.device_key_id != uuid_hex(identity.device_key_id)
        || report.segment_generation != configuration.segment_generation
        || report.projection_generation != configuration.projection_generation
        || report.route_policy.policy_id != uuid_hex(configuration.projection_id)
        || report.route_policy.generation != configuration.projection_generation
        || report.route_policy.content_hash != configuration.projection_content_hash
        || !(20_000..=20_999).contains(&report.netd.table_id)
        || report.netd.max_inner_mtu < 576
        || report.netd.local_prefixes.len() > 4096
        || report.netd.remote_routes.len() > 4096
        || report.netd.underlay_ipv4_exclusions.len() > 512
        || report.outbound_candidates.len() > 256
        || report.inbound_expected.len() > 256
    {
        bail!("Candy Core discovery report is not bound to the Cloud delivery")
    }
    report
        .netd
        .overlay_router_ipv4
        .parse::<std::net::Ipv4Addr>()
        .context("Core discovery returned an invalid overlay router address")?;
    for candidate in &report.outbound_candidates {
        validate_discovered_candidate(candidate, configuration)?;
    }
    for inbound in &report.inbound_expected {
        validate_hex(&inbound.candidate_id, 16, "inbound candidate id")?;
        validate_hex(&inbound.peer_attachment_id, 16, "inbound attachment id")?;
        validate_hex(&inbound.node_pool_id, 16, "inbound node pool id")?;
        validate_hex(&inbound.transport_node_id, 16, "inbound transport node id")?;
        validate_hex(
            &inbound.transport_node_key_id,
            16,
            "inbound transport node key id",
        )?;
        validate_hex(&inbound.server_cert_sha256, 32, "inbound certificate pin")?;
        inbound.endpoint.parse::<SocketAddr>()?;
        if inbound.server_name.is_empty()
            || inbound.server_name.len() > 253
            || !matches!(
                inbound.transport_preset.as_str(),
                "current" | "bbr_v1" | "aggressive"
            )
            || inbound.authorization_generation == 0
        {
            bail!("Core discovery returned an invalid inbound expectation")
        }
    }
    Ok(())
}

fn validate_discovered_candidate(
    candidate: &DiscoveredCandidate,
    _configuration: &RuntimeConfiguration,
) -> Result<()> {
    validate_hex(&candidate.candidate_id, 16, "candidate id")?;
    validate_hex(&candidate.peer_site_id, 16, "peer Site id")?;
    validate_hex(&candidate.peer_attachment_id, 16, "peer attachment id")?;
    validate_hex(&candidate.node_pool_id, 16, "node pool id")?;
    validate_hex(&candidate.transport_node_id, 16, "transport node id")?;
    validate_hex(
        &candidate.transport_node_key_id,
        16,
        "transport node key id",
    )?;
    validate_hex(&candidate.server_cert_sha256, 32, "server certificate pin")?;
    candidate.endpoint.parse::<SocketAddr>()?;
    if !matches!(candidate.kind.as_str(), "direct" | "relay") {
        bail!(
            "Core discovery returned invalid outbound candidate kind: {}",
            candidate.kind
        )
    }
    if candidate.server_name.is_empty() || candidate.server_name.len() > 253 {
        bail!("Core discovery returned invalid outbound candidate server_name")
    }
    if !matches!(
        candidate.transport_preset.as_str(),
        "current" | "bbr_v1" | "aggressive"
    ) {
        bail!(
            "Core discovery returned unsupported outbound transport preset: {}",
            candidate.transport_preset
        )
    }
    // The candidate authorization is the signed path-resource policy carried
    // inside the Site projection. It is intentionally not compared with the
    // current or peer projection IDs: those are different namespaces. Core
    // has already verified the signed projection and its candidate policy.
    validate_hex(&candidate.authorization.policy_id, 16, "outbound policy id")?;
    if candidate.authorization.generation == 0 {
        bail!("Core discovery returned an outbound candidate with zero policy generation")
    }
    validate_hex(
        &candidate.authorization.content_hash,
        32,
        "outbound policy content hash",
    )?;
    Ok(())
}

fn parse_hex_uuid(value: &str, label: &str) -> Result<Uuid> {
    validate_hex(value, 16, label)?;
    Uuid::parse_str(value).with_context(|| format!("parse {label}"))
}

fn verify_grant_with_core(
    core: &Path,
    grant_path: &Path,
    subject: &grant::GrantSubject,
    keys: &[RuntimeGrantVerificationKey],
) -> Result<grant::VerifiedGrantReport> {
    let mut attempted = 0_usize;
    let mut rejection_details = Vec::new();
    for key in keys {
        attempted += 1;
        let output = ProcessCommand::new(core)
            .args(["client", "sdwan", "verify-grant", "--grant"])
            .arg(grant_path)
            .args(["--public-key", &key.ed25519_public_key])
            .args(["--key-id", &key.key_id])
            .args(["--issuer-id", &key.issuer_id.simple().to_string()])
            .args(["--environment-id", &key.environment_id.simple().to_string()])
            .args(["--tenant-id", &subject.tenant_id.to_string()])
            .args(["--device-id", &subject.device_id.to_string()])
            .args(["--device-key-id", &subject.device_key_id.to_string()])
            .args(["--node-pool-id", &subject.node_pool_id.to_string()])
            .args(["--projection-id", &subject.projection_id.to_string()])
            .args([
                "--projection-generation",
                &subject.projection_generation.to_string(),
            ])
            .args([
                "--projection-content-hash",
                &subject.projection_content_hash,
            ])
            .output()
            .context("run Candy Core Grant verification")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.trim();
            rejection_details.push(format!(
                "key_id={} status={} error={}",
                key.key_id,
                output.status,
                if detail.is_empty() {
                    "no Core diagnostic"
                } else {
                    detail
                }
            ));
            continue;
        }
        if output.stdout.is_empty() || output.stdout.len() > 64 * 1024 {
            bail!("Candy Core returned an invalid Grant verification report")
        }
        return serde_json::from_slice(&output.stdout)
            .context("parse Candy Core Grant verification report");
    }
    bail!(
        "Candy Core rejected the Grant against all {attempted} trusted signing keys: {}",
        rejection_details.join("; ")
    )
}

fn resolve_grants(
    state_dir: &Path,
    core: &Path,
    client: &Client,
    cloud: &Url,
    identity: &DeviceIdentity,
    configuration: &RuntimeConfiguration,
    discovery: &DiscoveredControlReport,
) -> Result<Vec<(grant::GrantSubject, grant::CachedGrant)>> {
    let tenant_id = identity.tenant_id.context("Cloud identity has no tenant")?;
    let mut pools = discovery
        .outbound_candidates
        .iter()
        .map(|candidate| parse_hex_uuid(&candidate.node_pool_id, "node pool id"))
        .collect::<Result<Vec<_>>>()?;
    pools.sort_unstable();
    pools.dedup();
    if !pools.is_empty() && configuration.grant_verification_keys.is_empty() {
        bail!("outbound SD-WAN candidates require Grant verification keys")
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system time for Grant renewal")?
        .as_secs();
    let store = grant::GrantStore::new(state_dir);
    let grant_endpoint = endpoint(cloud, "auth/v1/access-grants")?;
    let mut resolved = Vec::with_capacity(pools.len());
    for node_pool_id in pools {
        let subject = grant::GrantSubject {
            node_pool_id,
            tenant_id,
            device_id: identity.device_id,
            device_key_id: identity.device_key_id,
            projection_id: configuration.projection_id,
            projection_generation: configuration.projection_generation,
            projection_content_hash: configuration.projection_content_hash.clone(),
        };
        let outcome = store.refresh(
            &subject,
            now,
            |request| grant::fetch_from_cloud(client, grant_endpoint.clone(), request),
            |path| {
                verify_grant_with_core(core, path, &subject, &configuration.grant_verification_keys)
            },
        )?;
        if let grant::RefreshOutcome::RetainedAfterTransientFailure { error, .. } = &outcome {
            eprintln!(
                "level=warn event=sdwan_grant_refresh_retained node_pool_id={} error={error:#}",
                node_pool_id
            );
        }
        resolved.push((subject, outcome.grant().clone()));
    }
    Ok(resolved)
}

fn resolve_core(requested_core: Option<&Path>) -> Result<PathBuf> {
    let core = requested_core
        .map(Path::to_path_buf)
        .or_else(|| {
            [
                PathBuf::from("/usr/lib/candy/cores/current/candy-core"),
                PathBuf::from("/opt/candy/cores/current/candy-core"),
            ]
            .into_iter()
            .find(|candidate| candidate.exists())
        })
        .context("Candy Core is not installed; signed SD-WAN state was not activated")?;
    let metadata = fs::metadata(&core).context("inspect active Candy Core")?;
    if !metadata.is_file() {
        bail!("active Candy Core is not a regular file")
    }
    Ok(core)
}

fn validate_verified_report(
    report: &VerifiedControlReport,
    configuration: &RuntimeConfiguration,
    identity: &DeviceIdentity,
) -> Result<()> {
    let uuid_hex = |value: Uuid| value.simple().to_string();
    if report.schema_version != 1
        || !report.ok
        || identity.tenant_id.map(uuid_hex).as_deref() != Some(report.tenant_id.as_str())
        || report.segment_id != uuid_hex(configuration.segment_id)
        || identity.site_id.map(uuid_hex).as_deref() != Some(report.site_id.as_str())
        || report.attachment_id != uuid_hex(configuration.attachment_id)
        || report.projection_id != uuid_hex(configuration.projection_id)
        || report.device_id != uuid_hex(identity.device_id)
        || report.device_key_id != uuid_hex(identity.device_key_id)
        || report.segment_generation != configuration.segment_generation
        || report.projection_generation != configuration.projection_generation
        || report.projection_content_hash != configuration.projection_content_hash
    {
        bail!("Candy Core verification report does not match the authenticated Cloud profile")
    }
    Ok(())
}

fn validate_identity(identity: &DeviceIdentity) -> Result<()> {
    if identity.schema_version != 1
        || identity.organization_id.is_nil()
        || identity.tenant_id.is_some_and(|value| value.is_nil())
        || identity.site_id.is_some_and(|value| value.is_nil())
        || identity
            .display_name
            .as_deref()
            .is_some_and(|value| value.trim().is_empty() || value.len() > 200)
        || identity.device_id.is_nil()
        || identity.device_key_id.is_nil()
        || identity.not_after.trim().is_empty()
        || identity.not_after.len() > 64
    {
        bail!("invalid local Cloud device identity")
    }
    Ok(())
}

fn validate_configuration(value: &RuntimeConfiguration, identity: &DeviceIdentity) -> Result<()> {
    if value.schema_version != 1
        || value.projection_publication_id.is_nil()
        || value.projection_id.is_nil()
        || value.segment_id.is_nil()
        || value.attachment_id.is_nil()
        || value.segment_generation == 0
        || value.projection_generation == 0
        || value.route_signing_key_id.is_empty()
        || value.route_signing_key_id.len() > 64
        || !value.route_signing_key_id.is_ascii()
        || value.peer_projection_catalog.len() > 4096
        || value.grant_verification_keys.len() > 8
    {
        bail!("Cloud Runtime configuration metadata is invalid")
    }
    validate_hex(
        &value.projection_content_hash,
        32,
        "projection content hash",
    )?;
    validate_hex(
        &value.route_signing_public_key,
        32,
        "route signing public key",
    )?;
    validate_catalog(&value.peer_projection_catalog)?;
    validate_grant_verification_keys(&value.grant_verification_keys)?;
    if identity.tenant_id.is_none() || identity.site_id.is_none() {
        bail!("local Cloud identity has no assigned tenant or Site")
    }
    Ok(())
}

fn validate_cloud(value: &str) -> Result<Url> {
    let cloud = Url::parse(value).context("parse Cloud address")?;
    if cloud.scheme() != "https"
        || cloud.host_str().is_none()
        || !cloud.username().is_empty()
        || cloud.password().is_some()
        || cloud.query().is_some()
        || cloud.fragment().is_some()
    {
        bail!("Cloud address must be an absolute https:// URL without credentials")
    }
    Ok(cloud)
}

fn endpoint(cloud: &Url, path: &str) -> Result<Url> {
    Url::parse(&format!(
        "{}/{}",
        cloud.as_str().trim_end_matches('/'),
        path
    ))
    .context("construct Cloud Runtime endpoint")
}

fn build_client(identity_dir: &Path, ca_certificate: Option<&Path>) -> Result<Client> {
    let identity_pem = read_bounded(&identity_dir.join("device-mtls.pem"), 512 * 1024)?;
    let identity =
        reqwest::Identity::from_pem(&identity_pem).context("parse device mTLS identity")?;
    let mut builder = Client::builder()
        .identity(identity)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .https_only(true)
        .user_agent(concat!("candy-cloud-sync/", env!("CARGO_PKG_VERSION")));
    if let Some(path) = ca_certificate {
        let certificate = reqwest::Certificate::from_pem(&read_bounded(path, 512 * 1024)?)
            .context("parse Cloud CA certificate")?;
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().context("build Cloud Runtime client")
}

fn bounded_response(response: Response, maximum: u64) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|size| size > maximum) {
        bail!("Cloud Runtime response exceeds {maximum} bytes")
    }
    let bytes = response.bytes().context("read Cloud Runtime response")?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        bail!("Cloud Runtime response size is invalid")
    }
    Ok(bytes.to_vec())
}

fn require_content_type(response: &Response, expected: &str) -> Result<()> {
    let value = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if value.split(';').next().map(str::trim) != Some(expected) {
        bail!("Cloud Runtime response has an unexpected media type")
    }
    Ok(())
}

fn required_etag(response: &Response) -> Result<String> {
    let value = response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .context("Cloud Runtime response is missing an ETag")?
        .to_owned();
    validate_etag(&value)?;
    Ok(value)
}

fn validate_etag(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("\"sha256-")
        .and_then(|value| value.strip_suffix('"'))
        .context("invalid Runtime configuration ETag")?;
    validate_hex(digest, 32, "Runtime configuration ETag")
}

fn validate_hex(value: &str, bytes: usize, label: &str) -> Result<()> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be canonical lowercase hexadecimal")
    }
    Ok(())
}

fn decode_envelope(value: &str, label: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("decode {label}"))?;
    if bytes.is_empty() || bytes.len() > MAX_ROUTE_ENVELOPE_BYTES {
        bail!("{label} size is invalid")
    }
    Ok(bytes)
}

fn decode_peer_projections(catalog: &[RuntimePeerProjection]) -> Result<Vec<Vec<u8>>> {
    catalog
        .iter()
        .map(|projection| decode_envelope(&projection.site_projection, "peer Site projection"))
        .collect()
}

fn validate_catalog(catalog: &[RuntimePeerProjection]) -> Result<()> {
    let mut previous: Option<(Uuid, u64)> = None;
    for projection in catalog {
        if projection.projection_id.is_nil() || projection.projection_generation == 0 {
            bail!("Peer projection catalog contains an invalid identity")
        }
        validate_hex(
            &projection.projection_content_hash,
            32,
            "Peer projection content hash",
        )?;
        let current = (projection.projection_id, projection.projection_generation);
        if previous.is_some_and(|value| value >= current) {
            bail!("Peer projection catalog is not strictly ordered")
        }
        previous = Some(current);
    }
    Ok(())
}

fn validate_grant_verification_keys(keys: &[RuntimeGrantVerificationKey]) -> Result<()> {
    let mut previous: Option<&str> = None;
    for key in keys {
        if key.key_id.is_empty()
            || key.key_id.len() > 64
            || !key.key_id.is_ascii()
            || previous.is_some_and(|value| value >= key.key_id.as_str())
            || key.issuer_id.is_nil()
            || key.environment_id.is_nil()
        {
            bail!("Grant verification key set is invalid or not strictly ordered")
        }
        validate_hex(&key.ed25519_public_key, 32, "Grant verification public key")?;
        previous = Some(&key.key_id);
    }
    Ok(())
}

fn configuration_objects_digest(
    segment: &[u8],
    projection: &[u8],
    catalog: &[RuntimePeerProjection],
    peer_projections: &[Vec<u8>],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"candy/runtime-configuration-v1\0");
    digest.update((segment.len() as u64).to_be_bytes());
    digest.update(segment);
    digest.update((projection.len() as u64).to_be_bytes());
    digest.update(projection);
    digest.update((catalog.len() as u64).to_be_bytes());
    for (entry, envelope) in catalog.iter().zip(peer_projections) {
        digest.update(entry.projection_id.as_bytes());
        digest.update(entry.projection_generation.to_be_bytes());
        digest.update(decode_hex_32(&entry.projection_content_hash).expect("validated catalog"));
        digest.update((envelope.len() as u64).to_be_bytes());
        digest.update(envelope);
    }
    digest.finalize().into()
}

fn configuration_delivery_digest(
    configuration: &RuntimeConfiguration,
    signed_objects_hash: &[u8; 32],
) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"candy/runtime-delivery-v1\0");
    digest.update(signed_objects_hash);
    digest.update((configuration.route_signing_key_id.len() as u64).to_be_bytes());
    digest.update(configuration.route_signing_key_id.as_bytes());
    digest.update(decode_hex_32(&configuration.route_signing_public_key)?);
    digest.update((configuration.grant_verification_keys.len() as u64).to_be_bytes());
    for key in &configuration.grant_verification_keys {
        digest.update((key.key_id.len() as u64).to_be_bytes());
        digest.update(key.key_id.as_bytes());
        digest.update(decode_hex_32(&key.ed25519_public_key)?);
        digest.update(key.issuer_id.as_bytes());
        digest.update(key.environment_id.as_bytes());
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    validate_hex(value, 32, "32-byte value")?;
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(output)
}

fn stable_tunnel_id(candidate_id: &str) -> Result<u64> {
    let candidate = decode_hex(candidate_id, 16, "candidate id")?;
    let mut digest = Sha256::new();
    digest.update(b"candy/runtime-tunnel-id-v1\0");
    digest.update(candidate);
    let bytes: [u8; 8] = digest.finalize()[..8].try_into().unwrap();
    // TOML integers are signed 64-bit values even though the wire tunnel id is
    // unsigned. Keep generated ids in the shared positive domain so every
    // candidate can be represented by both client and server configurations.
    let value = u64::from_be_bytes(bytes) & (i64::MAX as u64);
    Ok(if value == 0 { 1 } else { value })
}

fn decode_hex(value: &str, bytes: usize, label: &str) -> Result<Vec<u8>> {
    validate_hex(value, bytes, label)?;
    (0..bytes)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .with_context(|| format!("decode {label}"))
        })
        .collect()
}

fn cloud_ipv4_exclusions(cloud: &Url) -> Result<Vec<String>> {
    let host = cloud.host_str().context("Cloud URL has no host")?;
    let port = cloud
        .port_or_known_default()
        .context("Cloud URL has no known port")?;
    let mut addresses = (host, port)
        .to_socket_addrs()
        .context("resolve authenticated Cloud API host before SD-WAN activation")?
        .filter_map(|address| match address {
            SocketAddr::V4(value) if !value.ip().is_unspecified() && !value.ip().is_multicast() => {
                Some(format!("{}/32", value.ip()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        bail!("authenticated Cloud API host has no usable IPv4 address for netd exclusion")
    }
    Ok(addresses)
}

fn activation_grants(
    grants: &[(grant::GrantSubject, grant::CachedGrant)],
) -> Result<Vec<(ActivationGrantManifest, Vec<u8>)>> {
    let mut output = Vec::with_capacity(grants.len());
    for (subject, cached) in grants {
        let raw = URL_SAFE_NO_PAD
            .decode(cached.access_grant())
            .context("decode verified Cloud Grant for activation")?;
        if raw.is_empty() || raw.len() > 8 * 1024 {
            bail!("verified Cloud Grant has an invalid activation size")
        }
        let grant_sha256 = format!("{:x}", Sha256::digest(&raw));
        output.push((
            ActivationGrantManifest {
                node_pool_id: subject.node_pool_id,
                grant_id: cached.grant_id(),
                grant_sha256,
                refresh_after_unix: cached.refresh_after_unix(),
                expires_at_unix: cached.expires_at_unix(),
            },
            raw,
        ));
    }
    output.sort_by_key(|(manifest, _)| manifest.node_pool_id);
    Ok(output)
}

fn activation_digest(
    delivery_digest: &str,
    grants: &[(ActivationGrantManifest, Vec<u8>)],
) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"candy/runtime-activation-v1\0");
    digest.update(decode_hex_32(delivery_digest)?);
    digest.update((grants.len() as u64).to_be_bytes());
    for (manifest, raw) in grants {
        digest.update(manifest.node_pool_id.as_bytes());
        digest.update(manifest.grant_id.as_bytes());
        digest.update(Sha256::digest(raw));
        digest.update(manifest.refresh_after_unix.to_be_bytes());
        digest.update(manifest.expires_at_unix.to_be_bytes());
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn render_transport_config(
    candidate: &DiscoveredCandidate,
    identity: &DeviceIdentity,
    grant_path: &Path,
    signing_key_path: &Path,
) -> Result<String> {
    let quote = |value: &str| serde_json::to_string(value).map_err(Into::into);
    let path = |value: &Path| -> Result<String> {
        quote(
            value
                .to_str()
                .context("activation transport path is not UTF-8")?,
        )
    };
    Ok(format!(
        "server = {}\nserver_name = {}\nserver_pin = {}\nkey_id = {}\nsecret = \"\"\nauth_profile = \"cloud_grant_v1\"\n\n[cloud_auth]\ngrant_envelope_path = {}\ndevice_signing_key_path = {}\n\n[transport]\nprofile = \"linux\"\ncongestion = \"candy-bbr\"\ncandy_bbr_preset = {}\nautomatic_bbr_fallback = false\n",
        quote(&candidate.endpoint)?,
        quote(&candidate.server_name)?,
        quote(&format!("sha256:{}", candidate.server_cert_sha256))?,
        quote(&identity.device_key_id.to_string())?,
        path(grant_path)?,
        path(signing_key_path)?,
        quote(&candidate.transport_preset)?,
    ))
}

fn render_server_activation_config(
    ordinary_config: &Path,
    configuration: &RuntimeConfiguration,
    segment_path: &Path,
    local_projection_path: &Path,
    peer_projection_paths: &[PathBuf],
    outbound_peers: &[ServerOutboundPeerActivation],
) -> Result<String> {
    use std::str::FromStr;
    use toml_edit::{value, Array, ArrayOfTables, DocumentMut, Item, Table};

    if configuration.grant_verification_keys.is_empty() {
        bail!("server activation requires at least one scoped Grant verification key")
    }
    let text = String::from_utf8(read_bounded(ordinary_config, MAX_CONFIGURATION_BYTES)?)
        .context("ordinary Candy Server config is not UTF-8")?;
    let mut document = DocumentMut::from_str(&text).context("parse ordinary Candy Server TOML")?;
    if document.as_table().contains_key("cloud_auth") {
        bail!("ordinary Candy Server config already defines cloud_auth")
    }
    if document.as_table().contains_key("sdwan") {
        bail!("ordinary Candy Server config already defines sdwan")
    }

    let path = |value: &Path| -> Result<String> {
        Ok(value
            .to_str()
            .context("server activation path is not UTF-8")?
            .to_owned())
    };

    let mut cloud_auth = Table::new();
    cloud_auth.insert("enabled", value(true));
    let mut verification_keys = ArrayOfTables::new();
    for key in &configuration.grant_verification_keys {
        let mut entry = Table::new();
        entry.insert("key_id", value(&key.key_id));
        entry.insert("public_key", value(&key.ed25519_public_key));
        entry.insert("issuer_id", value(key.issuer_id.simple().to_string()));
        entry.insert(
            "environment_id",
            value(key.environment_id.simple().to_string()),
        );
        verification_keys.push(entry);
    }
    cloud_auth.insert("verification_keys", Item::ArrayOfTables(verification_keys));
    document["cloud_auth"] = Item::Table(cloud_auth);

    let mut peers = Array::new();
    for peer in peer_projection_paths {
        peers.push(path(peer)?);
    }
    let mut sdwan = Table::new();
    sdwan.insert("enabled", value(true));
    sdwan.insert("segment_snapshot", value(path(segment_path)?));
    sdwan.insert("peer_projections", value(peers));
    sdwan.insert("local_projection", value(path(local_projection_path)?));
    sdwan.insert(
        "route_signing_public_key",
        value(&configuration.route_signing_public_key),
    );
    let mut outbound = ArrayOfTables::new();
    for peer in outbound_peers {
        let mut entry = Table::new();
        entry.insert("candidate_id", value(&peer.candidate_id));
        entry.insert("tunnel_id", value(i64::try_from(peer.tunnel_id)?));
        entry.insert("transport_config", value(path(&peer.transport_config)?));
        outbound.push(entry);
    }
    sdwan.insert("outbound_peers", Item::ArrayOfTables(outbound));
    document["sdwan"] = Item::Table(sdwan);
    Ok(document.to_string())
}

fn build_netd_declaration(
    discovery: &DiscoveredControlReport,
    cloud: &Url,
) -> Result<NetdDeclaration> {
    let mut routes = discovery
        .netd
        .local_prefixes
        .iter()
        .map(|prefix| NetdRoute {
            prefix: prefix.clone(),
            kind: "local",
        })
        .chain(discovery.netd.remote_routes.iter().map(|route| NetdRoute {
            prefix: route.destination.clone(),
            kind: "remote",
        }))
        .collect::<Vec<_>>();
    routes.sort_by(|left, right| {
        netd_prefix_sort_key(&left.prefix)
            .cmp(&netd_prefix_sort_key(&right.prefix))
            .then(left.kind.cmp(right.kind))
    });
    let mut exclusions = BTreeMap::<String, &'static str>::new();
    for prefix in &discovery.netd.underlay_ipv4_exclusions {
        exclusions.insert(prefix.clone(), "hub-endpoint");
    }
    for prefix in cloud_ipv4_exclusions(cloud)? {
        exclusions.insert(prefix, "cloud-api");
    }
    let mut exclusions = exclusions
        .into_iter()
        .map(|(prefix, kind)| NetdExclusion { prefix, kind })
        .collect::<Vec<_>>();
    // candy-netd-proto validates declarations in canonical numeric IPv4 order.
    // A lexical String/BTreeMap order puts `104.x` before `47.x`, which is
    // rejected even though both prefixes are otherwise valid. Keep the wire
    // declaration deterministic and aligned with the shared protocol order.
    exclusions.sort_by(|left, right| {
        netd_prefix_sort_key(&left.prefix)
            .cmp(&netd_prefix_sort_key(&right.prefix))
            .then(left.kind.cmp(right.kind))
    });
    Ok(NetdDeclaration {
        table_id: discovery.netd.table_id,
        overlay_router_ipv4: discovery.netd.overlay_router_ipv4.clone(),
        effective_mtu: discovery.netd.max_inner_mtu,
        routes,
        exclusions,
        firewall: NetdFirewall {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    })
}

fn netd_prefix_sort_key(prefix: &str) -> (u32, u8) {
    let Some((address, length)) = prefix.split_once('/') else {
        return (u32::MAX, u8::MAX);
    };
    let Ok(address) = address.parse::<Ipv4Addr>() else {
        return (u32::MAX, u8::MAX);
    };
    let Ok(length) = length.parse::<u8>() else {
        return (u32::MAX, u8::MAX);
    };
    (u32::from(address), length)
}

#[allow(clippy::too_many_arguments)]
fn publish_client_activation(
    state_dir: &Path,
    identity_dir: &Path,
    core: &Path,
    cloud: &Url,
    etag: &str,
    delivery_digest: &str,
    configuration: &RuntimeConfiguration,
    identity: &DeviceIdentity,
    segment: &[u8],
    projection: &[u8],
    discovery: &DiscoveredControlReport,
    grants: &[(grant::GrantSubject, grant::CachedGrant)],
) -> Result<String> {
    let grants = activation_grants(grants)?;
    let declaration = build_netd_declaration(discovery, cloud)?;
    let declaration_bytes = serde_json::to_vec(&declaration)?;
    let mut activation_hash = Sha256::new();
    activation_hash.update(b"candy/runtime-client-activation-v2\0");
    activation_hash.update(decode_hex_32(&activation_digest(
        delivery_digest,
        &grants,
    )?)?);
    activation_hash.update(Sha256::digest(&declaration_bytes));
    let activation_id = format!("{:x}", activation_hash.finalize());
    let activations = state_dir.join("activations");
    ensure_private_directory(&activations)?;
    let generation = activations.join(&activation_id);
    if !generation.exists() {
        let staging = activations.join(format!(".{activation_id}.{}.tmp", Uuid::new_v4()));
        ensure_private_directory(&staging)?;
        let result = (|| {
            atomic_bytes(&staging.join("segment.snapshot"), segment, 0o600)?;
            atomic_bytes(&staging.join("site.projection"), projection, 0o600)?;
            let key_pem = String::from_utf8(read_bounded(
                &identity_dir.join("operational-key.pem"),
                MAX_PROFILE_BYTES,
            )?)
            .context("operational private key PEM is not UTF-8")?;
            let signing_key = SigningKey::from_pkcs8_pem(&key_pem)
                .context("decode operational private key for SD-WAN activation")?;
            let signing_key_path = staging.join("device-signing-key.raw");
            atomic_bytes(&signing_key_path, &signing_key.to_bytes(), 0o600)?;

            let grant_directory = staging.join("grants");
            let transport_directory = staging.join("transports");
            ensure_private_directory(&grant_directory)?;
            ensure_private_directory(&transport_directory)?;
            let mut grant_paths = BTreeMap::new();
            for (manifest, raw) in &grants {
                let path =
                    grant_directory.join(format!("{}.grant", manifest.node_pool_id.simple()));
                atomic_bytes(&path, raw, 0o600)?;
                grant_paths.insert(manifest.node_pool_id, path);
            }
            let mut peer_configs = Vec::with_capacity(discovery.outbound_candidates.len());
            for candidate in &discovery.outbound_candidates {
                let pool = parse_hex_uuid(&candidate.node_pool_id, "node pool id")?;
                let grant_path = grant_paths
                    .get(&pool)
                    .context("outbound candidate has no verified Grant")?;
                let transport_path =
                    transport_directory.join(format!("{}.toml", candidate.candidate_id));
                let transport =
                    render_transport_config(candidate, identity, grant_path, &signing_key_path)?;
                atomic_bytes(&transport_path, transport.as_bytes(), 0o600)?;
                peer_configs.push((
                    candidate,
                    stable_tunnel_id(&candidate.candidate_id)?,
                    transport_path,
                ));
            }
            let peers = peer_configs
                .iter()
                .map(|(candidate, tunnel_id, path)| (*candidate, *tunnel_id, path.as_path()))
                .collect::<Vec<_>>();
            let core_config = render_core_control_config(&staging, configuration, &peers)?;
            let core_config_path = staging.join("core.toml");
            atomic_bytes(&core_config_path, core_config.as_bytes(), 0o600)?;
            let output = ProcessCommand::new(core)
                .args(["client", "sdwan", "compile-control", "--config"])
                .arg(&core_config_path)
                .output()
                .context("compile final Candy Core SD-WAN activation")?;
            if !output.status.success() {
                bail!(
                    "Candy Core rejected final SD-WAN activation: {}",
                    String::from_utf8_lossy(&output.stderr)
                        .chars()
                        .take(1024)
                        .collect::<String>()
                )
            }
            let final_signing_key_path = generation.join("device-signing-key.raw");
            let final_grant_directory = generation.join("grants");
            let final_transport_directory = generation.join("transports");
            let mut final_peers = Vec::with_capacity(discovery.outbound_candidates.len());
            for candidate in &discovery.outbound_candidates {
                let pool = parse_hex_uuid(&candidate.node_pool_id, "node pool id")?;
                let final_grant_path =
                    final_grant_directory.join(format!("{}.grant", pool.simple()));
                let staged_transport_path =
                    transport_directory.join(format!("{}.toml", candidate.candidate_id));
                let final_transport_path =
                    final_transport_directory.join(format!("{}.toml", candidate.candidate_id));
                let transport = render_transport_config(
                    candidate,
                    identity,
                    &final_grant_path,
                    &final_signing_key_path,
                )?;
                atomic_bytes(&staged_transport_path, transport.as_bytes(), 0o600)?;
                final_peers.push((
                    candidate,
                    stable_tunnel_id(&candidate.candidate_id)?,
                    final_transport_path,
                ));
            }
            let final_peer_refs = final_peers
                .iter()
                .map(|(candidate, tunnel_id, path)| (*candidate, *tunnel_id, path.as_path()))
                .collect::<Vec<_>>();
            let final_core_config =
                render_core_control_config(&generation, configuration, &final_peer_refs)?;
            atomic_bytes(&core_config_path, final_core_config.as_bytes(), 0o600)?;
            atomic_bytes(&staging.join("declaration.json"), &declaration_bytes, 0o600)?;
            atomic_json(
                &staging.join("grants-v1.json"),
                &grants.iter().map(|v| &v.0).collect::<Vec<_>>(),
                0o600,
            )?;
            let refresh_after = grants
                .iter()
                .map(|value| value.0.refresh_after_unix)
                .min()
                .unwrap_or(0);
            let expires_at = grants
                .iter()
                .map(|value| value.0.expires_at_unix)
                .min()
                .unwrap_or(0);
            atomic_json(
                &staging.join("activation-v1.json"),
                &ActivationDescriptor {
                    schema_version: 1,
                    activation_id: activation_id.clone(),
                    delivery_etag: etag.to_owned(),
                    delivery_sha256: delivery_digest.to_owned(),
                    projection_publication_id: configuration.projection_publication_id,
                    projection_content_hash: configuration.projection_content_hash.clone(),
                    segment_generation: configuration.segment_generation,
                    projection_generation: configuration.projection_generation,
                    core_role: "client_sdwan".to_owned(),
                    core_config: "core.toml".to_owned(),
                    netd_declaration: "declaration.json".to_owned(),
                    grant_refresh_after_unix: refresh_after,
                    grant_expires_at_unix: expires_at,
                },
                0o600,
            )?;
            File::open(&staging).and_then(|directory| directory.sync_all())?;
            fs::rename(&staging, &generation).context("publish immutable SD-WAN activation")?;
            File::open(&activations).and_then(|directory| directory.sync_all())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
    }
    publish_pointer(
        state_dir,
        "candidate",
        Path::new("activations").join(&activation_id),
    )?;
    Ok(activation_id)
}

#[allow(clippy::too_many_arguments)]
fn publish_server_activation(
    state_dir: &Path,
    identity_dir: &Path,
    core: &Path,
    ordinary_config: &Path,
    cloud: &Url,
    etag: &str,
    delivery_digest: &str,
    configuration: &RuntimeConfiguration,
    identity: &DeviceIdentity,
    segment: &[u8],
    projection: &[u8],
    peer_projections: &[Vec<u8>],
    discovery: &DiscoveredControlReport,
    resolved_grants: &[(grant::GrantSubject, grant::CachedGrant)],
) -> Result<String> {
    if peer_projections.len() > 256 {
        bail!("server activation allows at most 256 authenticated peer projections")
    }
    if peer_projections.is_empty()
        && discovery.inbound_expected.is_empty()
        && discovery.outbound_candidates.is_empty()
    {
        bail!("server activation requires an inbound or outbound signed peer")
    }
    let grants = activation_grants(resolved_grants)?;
    let declaration = build_netd_declaration(discovery, cloud)?;
    let declaration_bytes = serde_json::to_vec(&declaration)?;
    let ordinary = read_bounded(ordinary_config, MAX_CONFIGURATION_BYTES)?;
    let mut activation_hash = Sha256::new();
    activation_hash.update(b"candy/runtime-server-activation-v2\0");
    activation_hash.update(decode_hex_32(&activation_digest(
        delivery_digest,
        &grants,
    )?)?);
    activation_hash.update(Sha256::digest(&declaration_bytes));
    activation_hash.update(Sha256::digest(&ordinary));
    let activation_id = format!("{:x}", activation_hash.finalize());
    let activations = state_dir.join("activations");
    ensure_private_directory(&activations)?;
    let generation = activations.join(&activation_id);
    if !generation.exists() {
        let staging = activations.join(format!(".{activation_id}.{}.tmp", Uuid::new_v4()));
        ensure_private_directory(&staging)?;
        let result = (|| {
            let staged_segment = staging.join("segment.snapshot");
            let staged_local = staging.join("site.projection");
            atomic_bytes(&staged_segment, segment, 0o600)?;
            atomic_bytes(&staged_local, projection, 0o600)?;

            let key_pem = String::from_utf8(read_bounded(
                &identity_dir.join("operational-key.pem"),
                MAX_PROFILE_BYTES,
            )?)
            .context("operational private key PEM is not UTF-8")?;
            let signing_key = SigningKey::from_pkcs8_pem(&key_pem)
                .context("decode operational private key for Server SD-WAN activation")?;
            let staged_signing_key = staging.join("device-signing-key.raw");
            atomic_bytes(&staged_signing_key, &signing_key.to_bytes(), 0o600)?;

            let staged_grants = staging.join("grants");
            let staged_transports = staging.join("transports");
            ensure_private_directory(&staged_grants)?;
            ensure_private_directory(&staged_transports)?;
            let mut staged_grant_paths = BTreeMap::new();
            for (manifest, raw) in &grants {
                let path = staged_grants.join(format!("{}.grant", manifest.node_pool_id.simple()));
                atomic_bytes(&path, raw, 0o600)?;
                staged_grant_paths.insert(manifest.node_pool_id, path);
            }
            let mut staged_outbound = Vec::with_capacity(discovery.outbound_candidates.len());
            for candidate in &discovery.outbound_candidates {
                let pool = parse_hex_uuid(&candidate.node_pool_id, "node pool id")?;
                let grant_path = staged_grant_paths
                    .get(&pool)
                    .context("Server outbound candidate has no verified Grant")?;
                let transport_path =
                    staged_transports.join(format!("{}.toml", candidate.candidate_id));
                let transport =
                    render_transport_config(candidate, identity, grant_path, &staged_signing_key)?;
                atomic_bytes(&transport_path, transport.as_bytes(), 0o600)?;
                staged_outbound.push(ServerOutboundPeerActivation {
                    candidate_id: candidate.candidate_id.clone(),
                    tunnel_id: stable_tunnel_id(&candidate.candidate_id)?,
                    transport_config: transport_path,
                });
            }
            let staged_peers = staging.join("peer-projections");
            ensure_private_directory(&staged_peers)?;
            let mut staged_peer_paths = Vec::with_capacity(peer_projections.len());
            let mut final_peer_paths = Vec::with_capacity(peer_projections.len());
            for (entry, envelope) in configuration
                .peer_projection_catalog
                .iter()
                .zip(peer_projections)
            {
                let name = format!(
                    "{}-{}.projection",
                    entry.projection_id.simple(),
                    entry.projection_generation
                );
                atomic_bytes(&staged_peers.join(&name), envelope, 0o600)?;
                staged_peer_paths.push(staged_peers.join(&name));
                final_peer_paths.push(generation.join("peer-projections").join(name));
            }
            let core_config_path = staging.join("core.toml");
            let staged_config = render_server_activation_config(
                ordinary_config,
                configuration,
                &staged_segment,
                &staged_local,
                &staged_peer_paths,
                &staged_outbound,
            )?;
            atomic_bytes(&core_config_path, staged_config.as_bytes(), 0o600)?;
            let output = ProcessCommand::new(core)
                .args(["server", "--config"])
                .arg(&core_config_path)
                .arg("--check-config")
                .output()
                .context("validate unified Candy Server SD-WAN activation")?;
            if !output.status.success() {
                bail!(
                    "Candy Core rejected unified Server SD-WAN activation: {}",
                    String::from_utf8_lossy(&output.stderr)
                        .chars()
                        .take(1024)
                        .collect::<String>()
                )
            }
            let final_signing_key = generation.join("device-signing-key.raw");
            let final_grants = generation.join("grants");
            let final_transports = generation.join("transports");
            let mut final_outbound = Vec::with_capacity(discovery.outbound_candidates.len());
            for candidate in &discovery.outbound_candidates {
                let pool = parse_hex_uuid(&candidate.node_pool_id, "node pool id")?;
                let final_grant_path = final_grants.join(format!("{}.grant", pool.simple()));
                let staged_transport_path =
                    staged_transports.join(format!("{}.toml", candidate.candidate_id));
                let final_transport_path =
                    final_transports.join(format!("{}.toml", candidate.candidate_id));
                let transport = render_transport_config(
                    candidate,
                    identity,
                    &final_grant_path,
                    &final_signing_key,
                )?;
                atomic_bytes(&staged_transport_path, transport.as_bytes(), 0o600)?;
                final_outbound.push(ServerOutboundPeerActivation {
                    candidate_id: candidate.candidate_id.clone(),
                    tunnel_id: stable_tunnel_id(&candidate.candidate_id)?,
                    transport_config: final_transport_path,
                });
            }
            let final_config = render_server_activation_config(
                ordinary_config,
                configuration,
                &generation.join("segment.snapshot"),
                &generation.join("site.projection"),
                &final_peer_paths,
                &final_outbound,
            )?;
            atomic_bytes(&core_config_path, final_config.as_bytes(), 0o600)?;
            atomic_bytes(&staging.join("declaration.json"), &declaration_bytes, 0o600)?;
            atomic_json(
                &staging.join("grants-v1.json"),
                &grants.iter().map(|value| &value.0).collect::<Vec<_>>(),
                0o600,
            )?;
            let refresh_after = grants
                .iter()
                .map(|value| value.0.refresh_after_unix)
                .min()
                .unwrap_or(0);
            let expires_at = grants
                .iter()
                .map(|value| value.0.expires_at_unix)
                .min()
                .unwrap_or(0);
            atomic_json(
                &staging.join("activation-v1.json"),
                &ActivationDescriptor {
                    schema_version: 1,
                    activation_id: activation_id.clone(),
                    delivery_etag: etag.to_owned(),
                    delivery_sha256: delivery_digest.to_owned(),
                    projection_publication_id: configuration.projection_publication_id,
                    projection_content_hash: configuration.projection_content_hash.clone(),
                    segment_generation: configuration.segment_generation,
                    projection_generation: configuration.projection_generation,
                    core_role: "server".to_owned(),
                    core_config: "core.toml".to_owned(),
                    netd_declaration: "declaration.json".to_owned(),
                    grant_refresh_after_unix: refresh_after,
                    grant_expires_at_unix: expires_at,
                },
                0o600,
            )?;
            File::open(&staging).and_then(|directory| directory.sync_all())?;
            fs::rename(&staging, &generation)
                .context("publish immutable Server SD-WAN activation")?;
            File::open(&activations).and_then(|directory| directory.sync_all())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
    }
    publish_pointer(
        state_dir,
        "candidate",
        Path::new("activations").join(&activation_id),
    )?;
    Ok(activation_id)
}

fn publish_pointer(state_dir: &Path, name: &str, target: PathBuf) -> Result<()> {
    if !matches!(name, "candidate" | "active") {
        bail!("invalid Runtime activation pointer name")
    }
    let destination = state_dir.join(name);
    let temporary = state_dir.join(format!(".{name}.{}.tmp", Uuid::new_v4()));
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &temporary).context("stage Runtime activation pointer")?;
    #[cfg(not(unix))]
    bail!("Runtime activation pointers require a Unix platform");
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("publish Runtime activation pointer");
    }
    File::open(state_dir).and_then(|directory| directory.sync_all())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn publish_configuration_generation(
    state_dir: &Path,
    digest: &str,
    segment: &[u8],
    projection: &[u8],
    peer_catalog: &[RuntimePeerProjection],
    peer_projections: &[Vec<u8>],
    route_key: &[u8],
    manifest: &[u8],
    discovery: &[u8],
) -> Result<()> {
    validate_hex(digest, 32, "Runtime configuration digest")?;
    let generations = state_dir.join("generations");
    ensure_private_directory(&generations)?;
    let generation = generations.join(digest);
    if !generation.exists() {
        let staging = generations.join(format!(".{digest}.{}.tmp", Uuid::new_v4()));
        ensure_private_directory(&staging)?;
        let write_result = (|| {
            atomic_bytes(&staging.join("segment.snapshot"), segment, 0o600)?;
            atomic_bytes(&staging.join("site.projection"), projection, 0o600)?;
            let peers = staging.join("peer-projections");
            ensure_private_directory(&peers)?;
            for (entry, envelope) in peer_catalog.iter().zip(peer_projections) {
                atomic_bytes(
                    &peers.join(format!(
                        "{}-{}.projection",
                        entry.projection_id.simple(),
                        entry.projection_generation
                    )),
                    envelope,
                    0o600,
                )?;
            }
            atomic_bytes(&staging.join("route-signing-public-key"), route_key, 0o600)?;
            atomic_bytes(&staging.join("configuration-v1.json"), manifest, 0o600)?;
            atomic_bytes(&staging.join("discovery-v1.json"), discovery, 0o600)?;
            File::open(&staging)
                .and_then(|directory| directory.sync_all())
                .context("sync staged Runtime configuration")?;
            fs::rename(&staging, &generation)
                .context("publish Runtime configuration generation")?;
            File::open(&generations)
                .and_then(|directory| directory.sync_all())
                .context("sync Runtime generation directory")
        })();
        if write_result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        write_result?;
    } else {
        let metadata = fs::symlink_metadata(&generation)
            .context("inspect existing Runtime configuration generation")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("Runtime configuration generation is not a real directory")
        }
        if read_bounded(
            &generation.join("segment.snapshot"),
            MAX_ROUTE_ENVELOPE_BYTES as u64,
        )? != segment
            || read_bounded(
                &generation.join("site.projection"),
                MAX_ROUTE_ENVELOPE_BYTES as u64,
            )? != projection
            || read_bounded(&generation.join("route-signing-public-key"), 128)? != route_key
            || read_bounded(
                &generation.join("configuration-v1.json"),
                MAX_CONFIGURATION_BYTES,
            )? != manifest
            || read_bounded(&generation.join("discovery-v1.json"), 1024 * 1024)? != discovery
        {
            bail!("immutable Runtime configuration generation has conflicting content")
        }
        for (entry, envelope) in peer_catalog.iter().zip(peer_projections) {
            if read_bounded(
                &generation.join("peer-projections").join(format!(
                    "{}-{}.projection",
                    entry.projection_id.simple(),
                    entry.projection_generation
                )),
                MAX_ROUTE_ENVELOPE_BYTES as u64,
            )? != *envelope
            {
                bail!("immutable Peer projection has conflicting content")
            }
        }
    }

    let current = state_dir.join("configuration");
    if current.exists() && !fs::symlink_metadata(&current)?.file_type().is_symlink() {
        let legacy = generations.join(format!("legacy-{}", Uuid::new_v4()));
        fs::rename(&current, legacy).context("preserve legacy Runtime configuration")?;
    }
    let next = state_dir.join(format!(".configuration.{}.tmp", Uuid::new_v4()));
    #[cfg(unix)]
    std::os::unix::fs::symlink(Path::new("generations").join(digest), &next)
        .context("stage Runtime configuration pointer")?;
    #[cfg(not(unix))]
    bail!("atomic Runtime generation pointers require a Unix platform");
    if let Err(error) = fs::rename(&next, &current) {
        let _ = fs::remove_file(&next);
        return Err(error).context("activate Runtime configuration generation");
    }
    File::open(state_dir)
        .and_then(|directory| directory.sync_all())
        .context("sync active Runtime configuration pointer")?;
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).context("inspect Runtime state directory")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("Runtime state directory must be a real directory")
        }
    } else {
        let parent = path
            .parent()
            .context("Runtime state directory has no parent")?;
        if !parent.exists() {
            fs::create_dir_all(parent).context("create Runtime state parent directory")?;
        }
        let parent_metadata =
            fs::symlink_metadata(parent).context("inspect Runtime state parent directory")?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            bail!("Runtime state parent must be a real directory")
        }
        fs::create_dir(path).context("create Runtime state directory")?;
        set_owner(path, &parent_metadata)?;
        set_mode(path, 0o700)?;
    }
    set_mode(path, 0o700)?;
    Ok(())
}

fn ensure_private_state_root(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).context("inspect Runtime state root")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("Runtime state root must be a real directory")
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o777 != 0o700 {
                bail!("Runtime state root must have mode 0700")
            }
        }
    }
    ensure_private_directory(path)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        bail!("{} is not a bounded regular file", path.display())
    }
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

fn read_bounded_json<T: DeserializeOwned>(path: &Path, maximum: u64) -> Result<T> {
    serde_json::from_slice(&read_bounded(path, maximum)?)
        .with_context(|| format!("parse {}", path.display()))
}

fn atomic_json(path: &Path, value: &impl Serialize, mode: u32) -> Result<()> {
    atomic_bytes(path, &serde_json::to_vec(value)?, mode)
}

fn atomic_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    ensure_private_directory(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options
        .open(&temporary)
        .context("create atomic state file")?;
    let parent_metadata = fs::symlink_metadata(parent).context("inspect state file parent")?;
    set_file_owner(&file, &parent_metadata)?;
    file.write_all(bytes).context("write atomic state file")?;
    file.sync_all().context("sync atomic state file")?;
    set_file_mode(&file, mode)?;
    drop(file);
    fs::rename(&temporary, path).context("replace atomic state file")?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("sync Runtime state directory")?;
    Ok(())
}

#[cfg(unix)]
fn set_file_owner(file: &File, owner: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let result = unsafe {
        nix::libc::fchown(
            file.as_raw_fd(),
            owner.uid() as nix::libc::uid_t,
            owner.gid() as nix::libc::gid_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("set state file owner");
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_file_owner(_file: &File, _owner: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_owner(path: &Path, owner: &fs::Metadata) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let result = unsafe {
        nix::libc::chown(
            path.as_ptr(),
            owner.uid() as nix::libc::uid_t,
            owner.gid() as nix::libc::gid_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("set state directory owner");
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_owner(_path: &Path, _owner: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_file: &File, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_network_routes_are_canonical_sorted_and_deduplicated() {
        let routes = r#"
10.20.30.77/24 dev eth1 proto kernel scope link src 10.20.30.9 metric 10
192.168.50.0/24 dev br-lan proto kernel scope link src 192.168.50.1
10.20.30.0/24 dev eth1 proto kernel scope link src 10.20.30.8
"#;
        let networks = parse_local_networks(routes);

        assert_eq!(networks.len(), 2);
        assert!(networks.windows(2).all(|pair| {
            (&pair[0].interface_name, &pair[0].cidr, &pair[0].address)
                < (&pair[1].interface_name, &pair[1].cidr, &pair[1].address)
        }));
        let eth1 = networks
            .iter()
            .find(|network| network.interface_name == "eth1")
            .unwrap();
        assert_eq!(eth1.cidr, "10.20.30.0/24");
        assert_eq!(eth1.address, "10.20.30.8");
        assert_eq!(eth1.kind, "direct_ipv4");
        assert_eq!(eth1.network_id.len(), 64);
        assert!(eth1.network_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn netd_declaration_sorts_prefixes_numerically_not_lexically() {
        let mut report = discovery();
        report.netd.underlay_ipv4_exclusions = vec!["104.243.28.153/32".into()];
        let declaration = build_netd_declaration(
            &report,
            &Url::parse("https://47-83-1-189.sslip.io").unwrap(),
        )
        .unwrap();
        assert_eq!(
            declaration
                .exclusions
                .iter()
                .map(|item| (item.prefix.as_str(), item.kind))
                .collect::<Vec<_>>(),
            vec![
                ("47.83.1.189/32", "cloud-api"),
                ("104.243.28.153/32", "hub-endpoint"),
            ]
        );
    }

    #[test]
    fn local_network_routes_exclude_unsafe_or_virtual_entries() {
        let routes = r#"
default via 192.0.2.1 dev eth0 proto static
127.0.0.0/8 dev lo proto kernel scope link src 127.0.0.1
169.254.0.0/16 dev eth0 proto kernel scope link src 169.254.4.5
0.0.0.0/8 dev eth0 proto kernel scope link src 0.0.0.1
192.168.1.0/24 dev candy0 proto kernel scope link src 192.168.1.1
192.168.2.0/24 dev tun0 proto kernel scope link src 192.168.2.1
192.168.3.0/24 dev utun4 proto kernel scope link src 192.168.3.1
192.168.4.0/24 dev interface-name-too-long proto kernel scope link src 192.168.4.1
192.168.5.0/24 dev eth0 proto kernel scope link
192.168.6.0/33 dev eth0 proto kernel scope link src 192.168.6.1
192.168.7.0/24 dev eth0 proto kernel scope link src invalid
192.168.8.0/24 dev eth0 proto kernel scope link src 192.168.9.1
10.0.0.0/8 dev br-home proto kernel scope link src 10.0.0.1
"#;

        assert_eq!(
            parse_local_networks(routes),
            vec![LocalNetworkTelemetry {
                network_id: local_network_id("br-home", "10.0.0.0/8"),
                interface_name: "br-home".into(),
                cidr: "10.0.0.0/8".into(),
                address: "10.0.0.1".into(),
                kind: "direct_ipv4",
            }]
        );
    }

    #[test]
    fn local_network_id_is_stable_and_bound_to_interface_and_canonical_cidr() {
        let first = parse_local_network_route(
            "192.168.7.19/24 dev br-lan proto kernel scope link src 192.168.7.1",
        )
        .unwrap();
        let same = parse_local_network_route(
            "192.168.7.0/24 dev br-lan proto kernel scope link src 192.168.7.2",
        )
        .unwrap();
        let other_interface = parse_local_network_route(
            "192.168.7.0/24 dev eth0 proto kernel scope link src 192.168.7.1",
        )
        .unwrap();
        let other_network = parse_local_network_route(
            "192.168.8.0/24 dev br-lan proto kernel scope link src 192.168.8.1",
        )
        .unwrap();

        assert_eq!(first.cidr, "192.168.7.0/24");
        assert_eq!(
            first.network_id,
            "0c733427cadad740e05695151d376806bf3a6700ddbfd77cee83c5613eaeca8f"
        );
        assert_eq!(first.network_id, same.network_id);
        assert_ne!(first.network_id, other_interface.network_id);
        assert_ne!(first.network_id, other_network.network_id);
    }

    #[test]
    fn local_network_reporting_has_a_deterministic_bound() {
        let routes = (0..80)
            .map(|index| {
                format!("10.{index}.0.0/16 dev eth0 proto kernel scope link src 10.{index}.0.1")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let networks = parse_local_networks(&routes);

        assert_eq!(networks.len(), MAX_LOCAL_NETWORKS);
        assert!(networks.windows(2).all(|pair| pair[0].cidr < pair[1].cidr));
    }

    fn core_status_v2() -> CoreRuntimeStatus {
        CoreRuntimeStatus {
            schema_version: 2,
            generation: 7,
            pid: std::process::id(),
            lifecycle: "active".into(),
            configured_peers: 1,
            active_peers: 1,
            required_route_owners: 1,
            ready_route_owners: 1,
            fail_open_required: false,
            last_error_code: None,
            counters: CorePacketCounters {
                tun_bytes_received: 3_000,
                tun_bytes_sent: 5_000,
            },
            paths: vec![CorePathStatus {
                peer_attachment_id: "11".repeat(16),
                candidate_id: Some("22".repeat(16)),
                path_kind: "direct".into(),
                transport: "quic_udp".into(),
                connection_epoch: 1,
                rtt_micros: 12_500,
                rtt_variance_micros: 1_500,
                rtt_sample_count: 3,
                tx_bytes: 9_000,
                rx_bytes: 8_000,
                sent_packets: 140,
                lost_packets: 4,
                congestion_window_bytes: 64_000,
                path_mtu: 1_400,
                reconnects: 2,
                path_changes: 1,
            }],
            reconnects: 2,
            path_changes: 1,
        }
    }

    #[test]
    fn runtime_performance_uses_same_generation_monotonic_deltas() {
        let boot_id = Uuid::new_v4();
        let status = core_status_v2();
        let mut previous = runtime_telemetry_sample(boot_id, 1, 1_000, &status);
        previous.tun_bytes_received = 1_000;
        previous.tun_bytes_sent = 2_000;
        previous
            .paths
            .get_mut(&"11".repeat(16))
            .unwrap()
            .sent_packets = 100;
        previous
            .paths
            .get_mut(&"11".repeat(16))
            .unwrap()
            .lost_packets = 2;
        let current = runtime_telemetry_sample(boot_id, 2, 3_000, &status);

        assert_eq!(
            derive_runtime_performance(Some(&status), Some(&previous), Some(&current)),
            DerivedRuntimePerformance {
                rtt_ms: Some(13),
                jitter_ms: Some(2),
                packet_loss_ppm: Some(50_000),
                rx_bps: Some(12_000),
                tx_bps: Some(8_000),
                reconnects: Some(2),
                path_changes: Some(1),
            }
        );
    }

    #[test]
    fn runtime_performance_never_diffs_across_connection_epoch_or_old_core() {
        let boot_id = Uuid::new_v4();
        let status = core_status_v2();
        let mut previous = runtime_telemetry_sample(boot_id, 1, 1_000, &status);
        previous
            .paths
            .get_mut(&"11".repeat(16))
            .unwrap()
            .connection_epoch = 9;
        let current = runtime_telemetry_sample(boot_id, 2, 3_000, &status);
        assert_eq!(
            derive_runtime_performance(Some(&status), Some(&previous), Some(&current))
                .packet_loss_ppm,
            None
        );

        let mut old = core_status_v2();
        old.schema_version = 1;
        assert_eq!(
            derive_runtime_performance(Some(&old), None, None),
            DerivedRuntimePerformance::default()
        );
    }

    #[test]
    fn runtime_path_telemetry_uses_canonical_ids_and_real_transport_counters() {
        let boot_id = Uuid::new_v4();
        let status = core_status_v2();
        let mut previous = runtime_telemetry_sample(boot_id, 1, 1_000, &status);
        let path = previous.paths.get_mut(&"11".repeat(16)).unwrap();
        path.tx_bytes = 1_000;
        path.rx_bytes = 2_000;
        path.sent_packets = 100;
        path.lost_packets = 2;
        let current = runtime_telemetry_sample(boot_id, 2, 3_000, &status);
        let paths = derive_runtime_paths(Some(&status), Some(&previous), Some(&current)).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths[0].peer_attachment_id,
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(
            paths[0].candidate_id.as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );
        assert_eq!(paths[0].tx_bps, Some(32_000));
        assert_eq!(paths[0].rx_bps, Some(24_000));
        assert_eq!(paths[0].packet_loss_ppm, Some(50_000));
    }

    fn args(state_dir: PathBuf, server_mode: bool, public_endpoints: Vec<SocketAddr>) -> Args {
        Args {
            state_dir,
            run_dir: PathBuf::from("/run/candy"),
            identity_dir: None,
            ca_certificate: None,
            core: None,
            server_config: server_mode.then(|| PathBuf::from("/etc/candy/server.toml")),
            public_endpoints,
            command: Command::SyncOnce,
        }
    }

    #[test]
    #[cfg(unix)]
    fn active_core_status_is_bound_to_activation_generation_and_live_process() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let run = root.path().join("run");
        let activation_id = "11".repeat(32);
        let activation = state.join("activations").join(&activation_id);
        fs::create_dir_all(&activation).unwrap();
        fs::create_dir_all(&run).unwrap();
        fs::write(
            activation.join("activation-v1.json"),
            serde_json::json!({
                "schema_version": 1,
                "activation_id": activation_id,
                "delivery_etag": format!("\"sha256-{}\"", "22".repeat(32)),
                "delivery_sha256": "22".repeat(32),
                "projection_publication_id": Uuid::new_v4(),
                "projection_content_hash": "33".repeat(32),
                "segment_generation": 4,
                "projection_generation": 7,
                "core_role": "client_sdwan",
                "core_config": "core.toml",
                "netd_declaration": "netd.json",
                "grant_refresh_after_unix": 0,
                "grant_expires_at_unix": 0
            })
            .to_string(),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            Path::new("activations").join(&activation_id),
            state.join("active"),
        )
        .unwrap();
        fs::write(
            run.join("sdwan-status.json"),
            serde_json::json!({
                "schema_version": 1,
                "generation": 7,
                "pid": std::process::id(),
                "lifecycle": "active",
                "configured_peers": 1,
                "active_peers": 1,
                "required_route_owners": 1,
                "ready_route_owners": 1,
                "fail_open_required": false,
                "last_error_code": null
            })
            .to_string(),
        )
        .unwrap();
        let status = read_active_core_status(&state, &run).unwrap().unwrap();
        assert_eq!(status.lifecycle, "active");
        assert_eq!(status.active_peers, 1);

        fs::write(
            run.join("sdwan-status.json"),
            serde_json::json!({
                "schema_version": 1,
                "generation": 7,
                "pid": u32::MAX,
                "lifecycle": "active",
                "configured_peers": 1,
                "active_peers": 1,
                "required_route_owners": 1,
                "ready_route_owners": 1,
                "fail_open_required": false,
                "last_error_code": null
            })
            .to_string(),
        )
        .unwrap();
        assert!(read_active_core_status(&state, &run).is_err());
    }

    #[test]
    fn explicit_public_endpoint_has_priority_over_environment() {
        let explicit = "203.0.113.7:18443".parse().unwrap();
        let args = args(PathBuf::from("state"), true, vec![explicit]);
        assert_eq!(
            effective_public_endpoints(&args, Some(OsStr::new("not-an-endpoint"))).unwrap(),
            vec![explicit]
        );
    }

    #[test]
    fn server_public_endpoint_uses_one_valid_environment_value() {
        let args = args(PathBuf::from("state"), true, Vec::new());
        assert_eq!(
            effective_public_endpoints(&args, Some(OsStr::new("[2001:db8::7]:18443"))).unwrap(),
            vec!["[2001:db8::7]:18443".parse().unwrap()]
        );
        let error = effective_public_endpoints(
            &args,
            Some(OsStr::new("203.0.113.7:18443,203.0.113.8:18443")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("exactly one IP:PORT endpoint"));
    }

    #[test]
    fn invalid_or_non_concrete_server_public_endpoint_is_rejected() {
        let args = args(PathBuf::from("state"), true, Vec::new());
        assert!(
            effective_public_endpoints(&args, Some(OsStr::new("0.0.0.0:18443")))
                .unwrap_err()
                .to_string()
                .contains("concrete IP address")
        );
        assert!(
            effective_public_endpoints(&args, Some(OsStr::new("203.0.113.7:0")))
                .unwrap_err()
                .to_string()
                .contains("non-zero port")
        );
    }

    #[test]
    fn client_mode_ignores_server_public_endpoint_environment() {
        let args = args(PathBuf::from("state"), false, Vec::new());
        assert!(
            effective_public_endpoints(&args, Some(OsStr::new("not-an-endpoint")))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn server_without_public_endpoint_publishes_waiting_status_before_identity_access() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let args = args(state_dir.clone(), true, Vec::new());

        sync_once_with_public_endpoint_env(&args, None).unwrap();

        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(state_dir.join("cloud-sync-status-v1.json")).unwrap())
                .unwrap();
        assert_eq!(status["state"], "waiting_for_public_endpoint");
        assert_eq!(status["error_code"], "public_endpoint_required");
        assert!(!state_dir.join("sync-state-v1.json").exists());
        assert!(!state_dir.join("transport-identity-state-v1.json").exists());
        assert!(!state_dir.join("candidate").exists());
    }

    fn identity() -> DeviceIdentity {
        DeviceIdentity {
            schema_version: 1,
            cloud_address: "https://cloud.example.test".into(),
            organization_id: Uuid::from_bytes([1; 16]),
            tenant_id: Some(Uuid::from_bytes([2; 16])),
            site_id: Some(Uuid::from_bytes([5; 16])),
            display_name: Some("Router".into()),
            device_id: Uuid::from_bytes([3; 16]),
            device_key_id: Uuid::from_bytes([4; 16]),
            not_after: "2030-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn accepts_legacy_identity_without_display_name() {
        let legacy = serde_json::json!({
            "schema_version": 1,
            "cloud_address": "https://cloud.example.test",
            "organization_id": "01010101-0101-0101-0101-010101010101",
            "tenant_id": "02020202-0202-0202-0202-020202020202",
            "site_id": "05050505-0505-0505-0505-050505050505",
            "device_id": "03030303-0303-0303-0303-030303030303",
            "device_key_id": "04040404-0404-0404-0404-040404040404",
            "not_after": "2030-01-01T00:00:00Z"
        });
        let identity: DeviceIdentity = serde_json::from_value(legacy).unwrap();
        assert_eq!(identity.display_name, None);
        validate_identity(&identity).unwrap();
    }

    fn configuration() -> RuntimeConfiguration {
        RuntimeConfiguration {
            schema_version: 1,
            projection_publication_id: Uuid::from_bytes([8; 16]),
            projection_id: Uuid::from_bytes([9; 16]),
            segment_id: Uuid::from_bytes([6; 16]),
            attachment_id: Uuid::from_bytes([7; 16]),
            segment_generation: 4,
            projection_generation: 5,
            projection_content_hash: "11".repeat(32),
            route_signing_key_id: "route-1".into(),
            route_signing_public_key: "22".repeat(32),
            segment_snapshot: "AA".into(),
            site_projection: "AA".into(),
            peer_projection_catalog: Vec::new(),
            grant_verification_keys: Vec::new(),
        }
    }

    fn discovery() -> DiscoveredControlReport {
        DiscoveredControlReport {
            schema_version: 1,
            ok: true,
            tenant_id: "02".repeat(16),
            segment_id: "06".repeat(16),
            site_id: "05".repeat(16),
            attachment_id: "07".repeat(16),
            device_id: "03".repeat(16),
            device_key_id: "04".repeat(16),
            segment_generation: 4,
            projection_generation: 5,
            route_policy: CorePolicyRef {
                policy_id: "09".repeat(16),
                generation: 5,
                content_hash: "11".repeat(32),
            },
            netd: DiscoveredNetd {
                table_id: 100,
                overlay_router_ipv4: "10.250.0.1".into(),
                max_inner_mtu: 1180,
                local_prefixes: vec!["10.0.0.0/24".into()],
                remote_routes: vec![DiscoveredRoute {
                    destination: "10.1.0.0/24".into(),
                    owner_attachment_ids: vec!["12".repeat(16)],
                }],
                underlay_ipv4_exclusions: vec!["198.51.100.1/32".into()],
            },
            outbound_candidates: Vec::new(),
            inbound_expected: Vec::new(),
        }
    }

    #[test]
    fn delivery_digest_matches_cloud_domain_separation() {
        let mut configuration = configuration();
        configuration.peer_projection_catalog = vec![RuntimePeerProjection {
            projection_id: Uuid::from_bytes([10; 16]),
            projection_generation: 7,
            projection_content_hash: "33".repeat(32),
            site_projection: URL_SAFE_NO_PAD.encode([4, 5]),
        }];
        configuration.grant_verification_keys = vec![RuntimeGrantVerificationKey {
            key_id: "grant-1".into(),
            ed25519_public_key: "44".repeat(32),
            issuer_id: Uuid::from_bytes([11; 16]),
            environment_id: Uuid::from_bytes([12; 16]),
        }];
        validate_configuration(&configuration, &identity()).unwrap();
        let peers = decode_peer_projections(&configuration.peer_projection_catalog).unwrap();
        let objects = configuration_objects_digest(
            &[1, 2, 3],
            &[4, 5],
            &configuration.peer_projection_catalog,
            &peers,
        );
        let first = configuration_delivery_digest(&configuration, &objects).unwrap();
        configuration.route_signing_key_id = "route-2".into();
        let second = configuration_delivery_digest(&configuration, &objects).unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn core_report_must_bind_every_runtime_identity_dimension() {
        let identity = identity();
        let configuration = configuration();
        let mut report = VerifiedControlReport {
            schema_version: 1,
            ok: true,
            tenant_id: identity.tenant_id.unwrap().simple().to_string(),
            segment_id: configuration.segment_id.simple().to_string(),
            site_id: identity.site_id.unwrap().simple().to_string(),
            attachment_id: configuration.attachment_id.simple().to_string(),
            projection_id: configuration.projection_id.simple().to_string(),
            device_id: identity.device_id.simple().to_string(),
            device_key_id: identity.device_key_id.simple().to_string(),
            segment_generation: configuration.segment_generation,
            projection_generation: configuration.projection_generation,
            projection_content_hash: configuration.projection_content_hash.clone(),
        };
        validate_verified_report(&report, &configuration, &identity).unwrap();
        report.device_id = Uuid::new_v4().simple().to_string();
        assert!(validate_verified_report(&report, &configuration, &identity).is_err());
    }

    #[test]
    fn atomic_state_rejects_symlink_parent_and_replaces_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        atomic_bytes(&path, b"first", 0o600).unwrap();
        atomic_bytes(&path, b"second", 0o600).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"second");
    }

    #[test]
    fn configuration_generation_switch_is_atomic_and_immutable() {
        let directory = tempfile::tempdir().unwrap();
        publish_configuration_generation(
            directory.path(),
            &format!("{:x}", Sha256::digest(b"generation-1")),
            b"segment-1",
            b"projection-1",
            &[],
            &[],
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            br#"{"generation":1}"#,
            br#"{"schema_version":1}"#,
        )
        .unwrap();
        let current = directory.path().join("configuration");
        assert!(fs::symlink_metadata(&current)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read(current.join("segment.snapshot")).unwrap(),
            b"segment-1"
        );

        publish_configuration_generation(
            directory.path(),
            &format!("{:x}", Sha256::digest(b"generation-2")),
            b"segment-2",
            b"projection-2",
            &[],
            &[],
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            br#"{"generation":2}"#,
            br#"{"schema_version":1}"#,
        )
        .unwrap();
        assert_eq!(
            fs::read(current.join("segment.snapshot")).unwrap(),
            b"segment-2"
        );
        assert_eq!(
            fs::read_dir(directory.path().join("generations"))
                .unwrap()
                .count(),
            2
        );
    }

    #[test]
    fn cloud_underlay_requires_at_least_one_ipv4_address() {
        assert_eq!(
            cloud_ipv4_exclusions(&Url::parse("https://127.0.0.1").unwrap()).unwrap(),
            vec!["127.0.0.1/32"]
        );
        assert!(cloud_ipv4_exclusions(&Url::parse("https://[::1]").unwrap()).is_err());
    }

    #[test]
    fn activation_digest_changes_when_grant_material_changes() {
        let manifest = |grant_id: u8, digest: &str| ActivationGrantManifest {
            node_pool_id: Uuid::from_bytes([1; 16]),
            grant_id: Uuid::from_bytes([grant_id; 16]),
            grant_sha256: digest.to_owned(),
            refresh_after_unix: 100,
            expires_at_unix: 200,
        };
        let delivery = "11".repeat(32);
        let first = activation_digest(&delivery, &[(manifest(2, "aa"), vec![1, 2, 3])]).unwrap();
        let second = activation_digest(&delivery, &[(manifest(3, "bb"), vec![1, 2, 4])]).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn withdrawal_removes_both_activation_pointers() {
        let directory = tempfile::tempdir().unwrap();
        let activations = directory.path().join("activations");
        fs::create_dir(&activations).unwrap();
        let id = "a".repeat(64);
        fs::create_dir(activations.join(&id)).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                Path::new("activations").join(&id),
                directory.path().join("candidate"),
            )
            .unwrap();
            std::os::unix::fs::symlink(
                Path::new("activations").join(&id),
                directory.path().join("active"),
            )
            .unwrap();
        }
        withdraw_local_activation(directory.path()).unwrap();
        assert!(!directory.path().join("candidate").exists());
        assert!(!directory.path().join("active").exists());
    }

    #[test]
    fn broad_runtime_state_root_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ensure_private_state_root(directory.path()).is_err());
    }

    fn activation_outcome_fixture(
        state: &str,
        error_code: Option<&str>,
        generation: u64,
    ) -> (tempfile::TempDir, String) {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let activation_id = "a".repeat(64);
        let delivery = "b".repeat(64);
        let activations = directory.path().join("activations");
        fs::create_dir(&activations).unwrap();
        fs::set_permissions(&activations, fs::Permissions::from_mode(0o700)).unwrap();
        let activation = activations.join(&activation_id);
        fs::create_dir(&activation).unwrap();
        fs::set_permissions(&activation, fs::Permissions::from_mode(0o700)).unwrap();
        atomic_json(
            &activation.join("activation-v1.json"),
            &ActivationDescriptor {
                schema_version: 1,
                activation_id: activation_id.clone(),
                delivery_etag: format!("\"sha256-{delivery}\""),
                delivery_sha256: delivery,
                projection_publication_id: Uuid::from_bytes([8; 16]),
                projection_content_hash: "c".repeat(64),
                segment_generation: 3,
                projection_generation: 7,
                core_role: "client_sdwan".into(),
                core_config: "core.toml".into(),
                netd_declaration: "declaration.json".into(),
                grant_refresh_after_unix: 100,
                grant_expires_at_unix: 200,
            },
            0o600,
        )
        .unwrap();
        symlink(
            Path::new("activations").join(&activation_id),
            directory.path().join("candidate"),
        )
        .unwrap();
        atomic_json(
            &directory.path().join("activation-ready-v1.json"),
            &serde_json::json!({
                "schema_version": 1,
                "activation_id": activation_id,
                "candidate_target": format!("activations/{activation_id}"),
                "generation": generation,
                "agent_pid": if state == "committed" { std::process::id() } else { u32::MAX },
                "state": state,
                "error_code": error_code,
            }),
            0o600,
        )
        .unwrap();
        (directory, activation_id)
    }

    #[test]
    fn committed_receipt_is_bound_to_candidate_before_atomic_promotion() {
        let (directory, activation_id) = activation_outcome_fixture("committed", None, 7);
        let outcome = read_activation_ready_receipt(directory.path())
            .unwrap()
            .unwrap();
        promote_committed_activation(directory.path(), &outcome).unwrap();
        assert_eq!(
            fs::read_link(directory.path().join("active")).unwrap(),
            Path::new("activations").join(activation_id)
        );
    }

    #[test]
    fn rejected_receipt_removes_only_candidate_and_preserves_last_good_active() {
        use std::os::unix::fs::symlink;
        let (directory, _) =
            activation_outcome_fixture("rejected", Some("core_readiness_failed"), 7);
        let last_good = Path::new("activations").join("d".repeat(64));
        symlink(&last_good, directory.path().join("active")).unwrap();
        let outcome = read_activation_ready_receipt(directory.path())
            .unwrap()
            .unwrap();
        remove_candidate_if_matches(directory.path(), &outcome).unwrap();
        assert!(!directory.path().join("candidate").exists());
        assert_eq!(
            fs::read_link(directory.path().join("active")).unwrap(),
            last_good
        );
    }

    #[test]
    fn receipt_generation_must_match_immutable_candidate() {
        let (directory, _) = activation_outcome_fixture("committed", None, 8);
        assert!(read_activation_ready_receipt(directory.path()).is_err());
    }

    #[test]
    fn stale_receipt_is_discarded_after_candidate_withdrawal_or_replacement() {
        use std::os::unix::fs::symlink;
        let (directory, _) = activation_outcome_fixture("committed", None, 7);
        fs::remove_file(directory.path().join("candidate")).unwrap();
        assert!(read_activation_ready_receipt(directory.path())
            .unwrap()
            .is_none());
        assert!(!directory.path().join("activation-ready-v1.json").exists());

        let (directory, _) = activation_outcome_fixture("rejected", Some("core_exit"), 7);
        fs::remove_file(directory.path().join("candidate")).unwrap();
        symlink(
            Path::new("activations").join("d".repeat(64)),
            directory.path().join("candidate"),
        )
        .unwrap();
        assert!(read_activation_ready_receipt(directory.path())
            .unwrap()
            .is_none());
        assert!(!directory.path().join("activation-ready-v1.json").exists());
    }

    #[test]
    fn legacy_sync_state_defaults_to_no_activation_requirement() {
        let state: SyncState =
            serde_json::from_str(r#"{"schema_version":1,"etag":null,"configuration_sha256":null}"#)
                .unwrap();
        assert!(!state.activation_required);
        assert!(state.activation_rejected_etag.is_none());
    }

    #[test]
    fn core_control_uses_fixed_width_hex_scopes() {
        let directory = tempfile::tempdir().unwrap();
        let mut configuration = configuration();
        configuration.grant_verification_keys = vec![RuntimeGrantVerificationKey {
            key_id: "grant-key".into(),
            ed25519_public_key: "11".repeat(32),
            issuer_id: Uuid::parse_str("31b6bd7f-4fd7-42f9-842c-9e0d635c9ea9").unwrap(),
            environment_id: Uuid::parse_str("d12c8a2f-18d2-44ba-810c-7d5b5097058f").unwrap(),
        }];
        let rendered = render_core_control_config(directory.path(), &configuration, &[]).unwrap();
        assert!(rendered.contains("issuer_id = \"31b6bd7f4fd742f9842c9e0d635c9ea9\""));
        assert!(rendered.contains("environment_id = \"d12c8a2f18d244ba810c7d5b5097058f\""));
        assert!(!rendered.contains("31b6bd7f-4fd7-42f9-842c-9e0d635c9ea9"));
    }

    #[test]
    fn server_activation_is_driven_by_either_inbound_or_outbound_candidates() {
        let mut configuration = configuration();
        let mut discovery = discovery();
        assert!(!activation_required(true, &configuration, &discovery));
        discovery.outbound_candidates.push(DiscoveredCandidate {
            candidate_id: "13".repeat(16),
            peer_site_id: "14".repeat(16),
            peer_attachment_id: "12".repeat(16),
            kind: "direct".into(),
            priority: 1,
            endpoint: "198.51.100.2:443".into(),
            node_pool_id: "15".repeat(16),
            transport_node_id: "16".repeat(16),
            transport_node_key_id: "17".repeat(16),
            server_name: "peer.example".into(),
            server_cert_sha256: "18".repeat(32),
            transport_preset: "current".into(),
            authorization: CorePolicyRef {
                policy_id: "09".repeat(16),
                generation: 5,
                content_hash: "11".repeat(32),
            },
        });
        assert!(activation_required(true, &configuration, &discovery));
        assert!(activation_required(false, &configuration, &discovery));
        discovery.outbound_candidates.clear();
        configuration.peer_projection_catalog = vec![RuntimePeerProjection {
            projection_id: Uuid::from_bytes([10; 16]),
            projection_generation: 5,
            projection_content_hash: "33".repeat(32),
            site_projection: URL_SAFE_NO_PAD.encode(b"peer"),
        }];
        assert!(activation_required(true, &configuration, &discovery));
        assert!(!activation_required(false, &configuration, &discovery));
    }

    #[test]
    fn server_config_merge_preserves_ordinary_service_and_adds_scoped_cloud_auth() {
        let directory = tempfile::tempdir().unwrap();
        let ordinary = directory.path().join("server.toml");
        fs::write(
            &ordinary,
            "listen = \"0.0.0.0:8443\"\ndevelopment_ephemeral_certificate = true\n\n[[users]]\nkey_id = \"ordinary-user\"\nsecret = \"ordinary-secret\"\n",
        )
        .unwrap();
        let mut configuration = configuration();
        configuration.grant_verification_keys = vec![RuntimeGrantVerificationKey {
            key_id: "cloud-key-1".into(),
            ed25519_public_key: "44".repeat(32),
            issuer_id: Uuid::from_bytes([11; 16]),
            environment_id: Uuid::from_bytes([12; 16]),
        }];
        let rendered = render_server_activation_config(
            &ordinary,
            &configuration,
            Path::new("/secure/segment.snapshot"),
            Path::new("/secure/local.projection"),
            &[PathBuf::from("/secure/peer.projection")],
            &[ServerOutboundPeerActivation {
                candidate_id: "13".repeat(16),
                tunnel_id: 42,
                transport_config: PathBuf::from("/secure/transport.toml"),
            }],
        )
        .unwrap();
        let document = rendered.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(document["listen"].as_str(), Some("0.0.0.0:8443"));
        assert_eq!(
            document["users"][0]["key_id"].as_str(),
            Some("ordinary-user")
        );
        assert_eq!(document["cloud_auth"]["enabled"].as_bool(), Some(true));
        assert_eq!(
            document["cloud_auth"]["verification_keys"][0]["key_id"].as_str(),
            Some("cloud-key-1")
        );
        assert_eq!(document["sdwan"]["enabled"].as_bool(), Some(true));
        assert_eq!(
            document["sdwan"]["peer_projections"][0].as_str(),
            Some("/secure/peer.projection")
        );
        assert_eq!(
            document["sdwan"]["outbound_peers"][0]["candidate_id"].as_str(),
            Some("13131313131313131313131313131313")
        );
        assert_eq!(
            document["sdwan"]["outbound_peers"][0]["tunnel_id"].as_integer(),
            Some(42)
        );
    }

    #[test]
    fn server_config_merge_rejects_preexisting_managed_sections() {
        let directory = tempfile::tempdir().unwrap();
        let ordinary = directory.path().join("server.toml");
        fs::write(
            &ordinary,
            "listen = \"127.0.0.1:8443\"\n[cloud_auth]\nenabled = false\n",
        )
        .unwrap();
        assert!(render_server_activation_config(
            &ordinary,
            &configuration(),
            Path::new("segment"),
            Path::new("local"),
            &[PathBuf::from("peer")],
            &[],
        )
        .is_err());
    }
}
