//! Versioned local authorization capabilities. The trusted Agent verifies the
//! business signatures; IO binds its exact result without interpreting routes.
use crate::{attach_control::PacketPortBinding, control::Controller};
use anyhow::{bail, Context, Result};
use candy_packet_port::{
    packet_port_ipc::{PacketPortRole, UnixPacketPort},
    packet_port_manager::{
        AuthorizationCheck, PacketPortOwnerChange, PacketPortOwnerUpdate, PacketPortReceipt,
    },
};
use candy_process_control::{peer_identity, process_is_current, ProcessIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{fs::PermissionsExt, net::UnixListener},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot, watch};

const CONTROL_BYTES: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEnvelope {
    pub transaction_id: String,
    pub authority_revision: u64,
    pub binding: PacketPortBinding,
    pub candidate: ProcessIdentity,
    pub controller: ProcessIdentity,
    pub controller_epoch: u64,
    pub signed_control_hash: String,
    pub declaration_hash: String,
    pub verification_report_hash: String,
    pub snapshot_closure_hash: String,
    pub signed_min_expiry_unix: u64,
    pub effective_expiry_unix: u64,
    pub verified_at_unix: u64,
    pub verified_at_mono_ms: u64,
    pub effective_deadline_mono_ms: u64,
    pub boot_id: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub(crate) struct AuthorityState {
    pub(crate) highest_revision: u64,
    pub(crate) highest_policy_generation: u64,
    pub(crate) highest_owner_epoch: u64,
    pub(crate) pending: Option<AuthorityEnvelope>,
    pub(crate) active: Option<AuthorityEnvelope>,
    pub(crate) actual_deadline_mono_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityOperation {
    StageAuthority,
    ProbeTransaction,
    AttachAuthorized,
    RevokeExact,
    DiscardAuthority,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityControlRequest {
    pub schema_version: u8,
    pub process: ProcessIdentity,
    pub controller: ProcessIdentity,
    pub controller_epoch: u64,
    pub token_sha256: String,
    pub nonce: String,
    pub operation: AuthorityOperation,
    pub envelope: Option<AuthorityEnvelope>,
    pub transaction_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityControlResponse {
    pub schema_version: u8,
    pub process: ProcessIdentity,
    pub controller: ProcessIdentity,
    pub controller_epoch: u64,
    pub nonce: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub active: Option<AuthorityEnvelope>,
    pub pending: Option<AuthorityEnvelope>,
    pub highest_revision: u64,
    pub highest_owner_epoch: u64,
    pub highest_policy_generation: u64,
    pub applied_transaction_id: Option<String>,
    pub authority_revision: Option<u64>,
    pub current_binding: PacketPortBinding,
    pub auth_deadline_unix: u64,
    pub owner_active: bool,
    pub actual_deadline_mono_ms: Option<u64>,
}

pub fn authority_control_path(supervision: &Path) -> PathBuf {
    let mut path = supervision.as_os_str().to_os_string();
    path.push(".authority");
    PathBuf::from(path)
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

/// Same machine monotonic clock used by the Agent (/proc/uptime includes suspend).
pub fn monotonic_ms() -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut value = nix::libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_BOOTTIME, &mut value) } != 0 {
            return Err(std::io::Error::last_os_error()).context("authorization clock");
        }
        let seconds = u64::try_from(value.tv_sec)?;
        seconds
            .checked_mul(1000)
            .and_then(|v| v.checked_add(u64::try_from(value.tv_nsec).ok()? / 1_000_000))
            .context("authorization clock overflow")
    }
    #[cfg(not(target_os = "linux"))]
    bail!("signed authority capabilities require Linux boot clock")
}

pub fn boot_id() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let value = value.trim();
        if value.len() != 36 || !value.bytes().all(|v| v.is_ascii_hexdigit() || v == b'-') {
            bail!("invalid boot identity");
        }
        Ok(value.to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    bail!("signed authority capabilities require Linux boot identity")
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn infrastructure_matches(a: PacketPortBinding, b: PacketPortBinding) -> bool {
    a.infrastructure_id == b.infrastructure_id
        && a.routing_domain_id == b.routing_domain_id
        && a.infrastructure_generation == b.infrastructure_generation
        && a.io_epoch == b.io_epoch
}

fn validate_envelope(state: &Controller, authority: &AuthorityEnvelope) -> Result<()> {
    let now_unix = unix_time()?;
    let now_mono = monotonic_ms()?;
    let verified_duration = authority
        .effective_expiry_unix
        .checked_sub(authority.verified_at_unix)
        .and_then(|v| v.checked_mul(1000))
        .context("invalid verified authorization duration")?;
    let candidate_current = process_is_current(authority.candidate);
    let boot_matches = authority.boot_id == boot_id()?;
    let checks = [
        (hex(&authority.transaction_id, 32), "transaction_id_invalid"),
        (authority.authority_revision != 0, "authority_revision_zero"),
        (
            infrastructure_matches(authority.binding, state.binding),
            "infrastructure_binding_mismatch",
        ),
        (
            authority.binding.policy_generation != 0,
            "policy_generation_zero",
        ),
        (authority.binding.owner_epoch != 0, "owner_epoch_zero"),
        (
            authority.controller == state.controller,
            "controller_identity_mismatch",
        ),
        (
            authority.controller_epoch == state.epoch,
            "controller_epoch_mismatch",
        ),
        (candidate_current, "candidate_process_not_current"),
        (
            authority.candidate != state.process && authority.candidate != state.controller,
            "candidate_identity_not_independent",
        ),
        (
            hex(&authority.signed_control_hash, 64),
            "signed_control_hash_invalid",
        ),
        (
            hex(&authority.declaration_hash, 64),
            "declaration_hash_invalid",
        ),
        (
            hex(&authority.verification_report_hash, 64),
            "verification_report_hash_invalid",
        ),
        (
            hex(&authority.snapshot_closure_hash, 64),
            "snapshot_closure_hash_invalid",
        ),
        (
            authority.effective_expiry_unix <= authority.signed_min_expiry_unix,
            "wall_cap_exceeds_signed_expiry",
        ),
        (
            authority.effective_expiry_unix > now_unix,
            "wall_cap_expired",
        ),
        (
            authority.verified_at_unix <= now_unix,
            "verified_wall_time_in_future",
        ),
        (
            authority.verified_at_mono_ms <= now_mono,
            "verified_monotonic_time_in_future",
        ),
        (
            authority.effective_deadline_mono_ms > now_mono,
            "monotonic_cap_expired",
        ),
        (
            authority.effective_deadline_mono_ms > authority.verified_at_mono_ms,
            "monotonic_cap_precedes_verification",
        ),
        (
            authority
                .effective_deadline_mono_ms
                .checked_sub(authority.verified_at_mono_ms)
                .is_some_and(|duration| duration <= verified_duration),
            "monotonic_cap_exceeds_verified_wall_duration",
        ),
        (boot_matches, "boot_identity_mismatch"),
    ];
    if let Some((_, reason)) = checks.iter().find(|(valid, _)| !valid) {
        bail!("code=authority_envelope_rejected module=tunio_authority reason={} detail=scope/identity/hash/verified_deadline_mismatch transaction_id={} authority_revision={} infrastructure_matches={} controller_matches={} controller_epoch_matches={} candidate_current={} now_unix={} verified_at_unix={} effective_expiry_unix={} signed_min_expiry_unix={} now_mono_ms={} verified_at_mono_ms={} effective_deadline_mono_ms={} deadline_span_ms={} verified_duration_ms={} boot_matches={}",
            reason,
            authority.transaction_id, authority.authority_revision,
            infrastructure_matches(authority.binding, state.binding),
            authority.controller == state.controller, authority.controller_epoch == state.epoch,
            candidate_current, now_unix, authority.verified_at_unix,
            authority.effective_expiry_unix, authority.signed_min_expiry_unix, now_mono,
            authority.verified_at_mono_ms, authority.effective_deadline_mono_ms,
            authority.effective_deadline_mono_ms.saturating_sub(authority.verified_at_mono_ms),
            verified_duration, boot_matches);
    }
    Ok(())
}

fn owner_deadline(authority: &AuthorityEnvelope) -> Result<tokio::time::Instant> {
    owner_deadline_with_clocks(
        authority.effective_deadline_mono_ms,
        authority.effective_expiry_unix,
        monotonic_ms,
        || Ok(SystemTime::now().duration_since(UNIX_EPOCH)?),
    )
}

fn owner_deadline_with_clocks(
    deadline_mono_ms: u64,
    expiry_unix: u64,
    read_mono: impl FnOnce() -> Result<u64>,
    read_wall: impl FnOnce() -> Result<Duration>,
) -> Result<tokio::time::Instant> {
    // Anchor before sampling remaining time; descheduling may shorten the cap,
    // but must never extend it past the authority's original clock deadline.
    let anchor = tokio::time::Instant::now();
    let remaining_mono = deadline_mono_ms
        .checked_sub(read_mono()?)
        .filter(|v| *v > 0)
        .context("authority monotonic deadline expired")?;
    let remaining_wall = Duration::from_secs(expiry_unix)
        .checked_sub(read_wall()?)
        .filter(|v| !v.is_zero())
        .context("authority wall deadline expired")?;
    Ok(anchor + Duration::from_millis(remaining_mono).min(remaining_wall))
}

fn authorization_check(authority: &AuthorityEnvelope) -> AuthorizationCheck {
    let cap = authority.effective_deadline_mono_ms;
    deadline_check(cap, Duration::from_secs(authority.effective_expiry_unix))
}

static BOOTSTRAP_CAP: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Startup receives a trusted local Runtime cap; later signed grants carry their own cap.
pub fn install_bootstrap_cap(cap: u64) -> Result<()> {
    if cap <= monotonic_ms()? {
        bail!(
            "code=authority_expired module=tunio_authority detail=bootstrap monotonic cap expired"
        );
    }
    BOOTSTRAP_CAP
        .set(cap)
        .map_err(|_| anyhow::anyhow!("bootstrap cap already installed"))
}

#[cfg(target_os = "linux")]
fn capped_bootstrap_deadline(calculated: u64, inherited: Option<u64>) -> u64 {
    inherited.map_or(calculated, |cap| cap.min(calculated))
}

pub(crate) fn bootstrap_check(
    deadline: tokio::time::Instant,
) -> std::io::Result<Option<AuthorizationCheck>> {
    #[cfg(target_os = "linux")]
    {
        let boot_anchor = monotonic_ms().map_err(std::io::Error::other)?;
        let wall_anchor = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let milliseconds = u64::try_from(remaining.as_millis()).map_err(std::io::Error::other)?;
        let cap = boot_anchor
            .checked_add(milliseconds)
            .ok_or_else(|| std::io::Error::other("bootstrap authorization clock overflow"))?;
        let cap = capped_bootstrap_deadline(cap, BOOTSTRAP_CAP.get().copied());
        Ok(Some(deadline_check(cap, wall_anchor + remaining)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = deadline;
        Ok(None)
    }
}

fn deadline_check(cap: u64, wall_cap: Duration) -> AuthorizationCheck {
    Arc::new(move || {
        let now = monotonic_ms().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("code=authority_clock_unavailable module=tunio_authority detail={error:#}"),
            )
        })?;
        let wall =
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| {
                    std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("code=authority_clock_unavailable module=tunio_authority detail={error}"),
            )
                })?;
        if now >= cap || wall >= wall_cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "code=authority_expired module=tunio_authority detail=boot or wall deadline reached",
            ));
        }
        Ok(())
    })
}

fn wait_receiver<T>(mut receiver: oneshot::Receiver<T>, deadline: Instant) -> Result<T> {
    loop {
        crate::attach_control::remaining(deadline)?;
        match receiver.try_recv() {
            Ok(value) => return Ok(value),
            Err(oneshot::error::TryRecvError::Closed) => {
                bail!("actual PacketPort receipt publisher closed")
            }
            Err(oneshot::error::TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
        }
    }
}

fn manager_change(
    updates: &mpsc::Sender<PacketPortOwnerUpdate>,
    change: PacketPortOwnerChange,
    deadline: Instant,
) -> Result<PacketPortReceipt> {
    let (acknowledgement, ack) = oneshot::channel();
    let (receipt, actual) = oneshot::channel();
    updates
        .try_send(PacketPortOwnerUpdate {
            change,
            acknowledgement,
            receipt: Some(receipt),
        })
        .map_err(|error| anyhow::anyhow!("PacketPort owner queue unavailable: {error}"))?;
    // Keep the ACK receiver alive while waiting for actual applied state.
    let result = wait_receiver(ack, deadline)?;
    let actual = wait_receiver(actual, deadline)?;
    result.map_err(|error| anyhow::anyhow!("actual PacketPort change rejected: {error}"))?;
    Ok(actual)
}

fn reconcile(state: &mut Controller, actual: PacketPortReceipt) -> Result<()> {
    if let Some(pending) = &state.authority.pending {
        if pending.binding.owner_epoch == actual.owner_epoch
            && pending.binding.policy_generation == actual.policy_generation
        {
            // High-water is manager-authoritative even after expiry or output failure.
            state.authority.active = state.authority.pending.take();
        }
    }
    state.authority.highest_owner_epoch =
        state.authority.highest_owner_epoch.max(actual.owner_epoch);
    state.authority.highest_policy_generation = state
        .authority
        .highest_policy_generation
        .max(actual.policy_generation);
    if let Some(binding) = actual.binding {
        state.binding = binding;
    } else if let Some(active) = &state.authority.active {
        if active.binding.owner_epoch == actual.owner_epoch {
            state.binding = active.binding;
        }
    }
    state.owner_active = actual.binding.is_some()
        && actual
            .auth_deadline
            .is_some_and(|v| v > tokio::time::Instant::now());
    // Read the boot clock before the Instant sample so the returned cap is
    // conservative even if this control thread is descheduled between reads.
    let now_mono = monotonic_ms()?;
    state.authority.actual_deadline_mono_ms = actual
        .auth_deadline
        .and_then(|deadline| deadline.checked_duration_since(tokio::time::Instant::now()))
        .and_then(|remaining| u64::try_from(remaining.as_millis()).ok())
        .and_then(|remaining| now_mono.checked_add(remaining));
    if let Some(active) = &state.authority.active {
        if active.binding.owner_epoch == actual.owner_epoch {
            state.auth_deadline_unix = active.effective_expiry_unix;
            state.authority.actual_deadline_mono_ms = state
                .authority
                .actual_deadline_mono_ms
                .map(|deadline| deadline.min(active.effective_deadline_mono_ms));
        }
    }
    Ok(())
}

fn packet_port(
    fd: OwnedFd,
    peer: ProcessIdentity,
    binding: PacketPortBinding,
    runtime: &tokio::runtime::Handle,
) -> Result<UnixPacketPort> {
    if nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::SockType)?
        != nix::sys::socket::SockType::Datagram
    {
        bail!("authorized PacketPort descriptor must be datagram");
    }
    nix::sys::socket::getsockname::<nix::sys::socket::UnixAddr>(fd.as_raw_fd())
        .context("authorized PacketPort descriptor must be AF_UNIX")?;
    let socket = std::os::unix::net::UnixDatagram::from(fd);
    socket
        .peer_addr()
        .context("authorized PacketPort must be connected")?;
    #[cfg(target_os = "linux")]
    {
        let credentials =
            nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::PeerCredentials)?;
        if credentials.uid() != nix::unistd::geteuid().as_raw()
            || credentials.pid() != peer.pid as i32
        {
            bail!("authorized PacketPort was not created by current controller");
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = peer;
    socket.set_nonblocking(true)?;
    let _runtime = runtime.enter();
    Ok(UnixPacketPort::new(
        tokio::net::UnixDatagram::from_std(socket)?,
        binding,
        PacketPortRole::Infrastructure,
    )?)
}

fn apply_request(
    state: &mut Controller,
    peer: ProcessIdentity,
    request: &AuthorityControlRequest,
    mut descriptors: Vec<OwnedFd>,
    updates: &mpsc::Sender<PacketPortOwnerUpdate>,
    runtime: &tokio::runtime::Handle,
    deadline: Instant,
) -> Result<()> {
    if request.schema_version != 2
        || request.process != state.process
        || request.controller != peer
        || peer != state.controller
        || request.controller_epoch != state.epoch
        || !process_is_current(peer)
        || request.token_sha256 != format!("{:x}", Sha256::digest(state.token.as_bytes()))
        || !hex(&request.nonce, 32)
        || !hex(&request.transaction_id, 32)
        || !state.registered
    {
        bail!("code=authority_controller_rejected module=tunio_authority detail=controller/epoch/capability/registration mismatch");
    }
    if descriptors.len()
        != usize::from(matches!(
            request.operation,
            AuthorityOperation::AttachAuthorized
        ))
    {
        bail!("authorized Attach requires one descriptor; other operations require none");
    }
    reconcile(
        state,
        manager_change(updates, PacketPortOwnerChange::Probe, deadline)?,
    )?;
    match request.operation {
        AuthorityOperation::ProbeTransaction => {
            if request.envelope.is_some() {
                bail!("Probe cannot supply an authorization envelope");
            }
        }
        AuthorityOperation::StageAuthority => {
            let envelope = request
                .envelope
                .as_ref()
                .context("Stage requires verified local authority")?;
            if envelope.transaction_id != request.transaction_id {
                bail!("Stage transaction differs");
            }
            validate_envelope(state, envelope)?;
            if state.authority.pending.as_ref() == Some(envelope)
                || state.authority.active.as_ref() == Some(envelope)
            {
                return Ok(());
            }
            if state.authority.pending.is_some()
                || envelope.authority_revision <= state.authority.highest_revision
                || envelope.binding.policy_generation
                    < state
                        .binding
                        .policy_generation
                        .max(state.authority.highest_policy_generation)
                || envelope.binding.owner_epoch
                    <= state
                        .binding
                        .owner_epoch
                        .max(state.authority.highest_owner_epoch)
            {
                bail!("code=authority_revision_rejected module=tunio_authority detail=unresolved candidate or stale authority/policy/owner epoch");
            }
            state.authority.highest_revision = envelope.authority_revision;
            state.authority.highest_policy_generation = state
                .authority
                .highest_policy_generation
                .max(envelope.binding.policy_generation);
            state.authority.highest_owner_epoch = state
                .authority
                .highest_owner_epoch
                .max(envelope.binding.owner_epoch);
            state.authority.pending = Some(envelope.clone());
        }
        AuthorityOperation::AttachAuthorized => {
            let envelope = request
                .envelope
                .as_ref()
                .context("Attach requires exact staged authority")?;
            if envelope.transaction_id != request.transaction_id
                || state.authority.pending.as_ref() != Some(envelope)
            {
                bail!("code=authority_stage_mismatch module=tunio_authority detail=exact staged authority required");
            }
            validate_envelope(state, envelope)?;
            let auth_deadline = owner_deadline(envelope)?;
            let port = packet_port(
                descriptors.pop().expect("checked one fd"),
                peer,
                envelope.binding,
                runtime,
            )?;
            reconcile(
                state,
                manager_change(
                    updates,
                    PacketPortOwnerChange::AttachAuthorized {
                        port,
                        auth_deadline,
                        authorization: authorization_check(envelope),
                    },
                    deadline,
                )?,
            )?;
            if state.authority.active.as_ref() != Some(envelope)
                || state.binding != envelope.binding
            {
                bail!("actual PacketPort attachment does not match authority transaction");
            }
        }
        AuthorityOperation::RevokeExact => {
            if request.envelope.is_some() {
                bail!("Revoke cannot supply an envelope");
            }
            let active = state
                .authority
                .active
                .as_ref()
                .context("no applied authority transaction")?;
            if active.transaction_id != request.transaction_id || state.binding != active.binding {
                bail!("Revoke refers to another applied authority transaction");
            }
            let epoch = active.binding.owner_epoch;
            reconcile(
                state,
                manager_change(
                    updates,
                    PacketPortOwnerChange::Revoke { owner_epoch: epoch },
                    deadline,
                )?,
            )?;
        }
        AuthorityOperation::DiscardAuthority => {
            if request.envelope.is_some() {
                bail!("Discard cannot supply an envelope");
            }
            if state
                .authority
                .pending
                .as_ref()
                .is_none_or(|v| v.transaction_id != request.transaction_id)
            {
                bail!("Discard refers to another pending authority transaction");
            }
            state.authority.pending = None;
        }
    }
    state.publish()?;
    Ok(())
}

pub fn exchange_authority(
    path: &Path,
    expected_io: ProcessIdentity,
    request: &AuthorityControlRequest,
    fd: Option<&OwnedFd>,
    deadline: Instant,
) -> Result<AuthorityControlResponse> {
    crate::attach_control::validate_endpoint(path)?;
    crate::attach_control::remaining(deadline)?;
    if request.process != expected_io || !process_is_current(expected_io) {
        bail!("authority IO identity differs");
    }
    if fd.is_some() != matches!(request.operation, AuthorityOperation::AttachAuthorized) {
        bail!("authority descriptor shape differs");
    }
    let stream = crate::attach_control::connect_until(path, deadline)?;
    if peer_identity(&stream)? != expected_io {
        bail!("authority IO peer identity differs");
    }
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > CONTROL_BYTES {
        bail!("authority request too large");
    }
    candy_netd_client::send_descriptor_frame_until(
        &stream,
        &bytes,
        fd.map(AsRawFd::as_raw_fd),
        deadline,
    )?;
    let (bytes, descriptors) =
        candy_netd_client::receive_descriptor_frame_until(&stream, deadline)?;
    if bytes.len() > CONTROL_BYTES || !descriptors.is_empty() {
        bail!("authority response shape differs");
    }
    let reply: AuthorityControlResponse = serde_json::from_slice(&bytes)?;
    if reply.schema_version != 2
        || reply.process != expected_io
        || reply.controller != request.controller
        || reply.controller_epoch != request.controller_epoch
        || reply.nonce != request.nonce
        || peer_identity(&stream)? != expected_io
    {
        bail!("authority response fencing differs");
    }
    if !reply.accepted {
        bail!(
            "code={} module=tunio_authority detail={}",
            reply.code,
            reply.detail
        );
    }
    Ok(reply)
}

pub(crate) fn start(
    supervision: PathBuf,
    state: Arc<Mutex<Controller>>,
    updates: mpsc::Sender<PacketPortOwnerUpdate>,
    stop: watch::Sender<bool>,
    bootstrap_deadline: tokio::time::Instant,
) -> Result<()> {
    let socket = authority_control_path(&supervision);
    crate::control::private_parent(&socket)?;
    let listener = UnixListener::bind(&socket).with_context(|| {
        format!("code=control_bind_failed module=tunio_authority path={} detail=bind authority endpoint", socket.display())
    })?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let runtime = tokio::runtime::Handle::current();
    let guard_state = Arc::clone(&state);
    let guard_updates = updates.clone();
    let guard_stop = stop.subscribe();
    let bootstrap_authorization = bootstrap_check(bootstrap_deadline)?;
    runtime.spawn(boot_deadline_guard(
        guard_state,
        guard_updates,
        guard_stop,
        bootstrap_authorization,
    ));
    thread::spawn(move || {
        let shutdown = stop.subscribe();
        while !*shutdown.borrow() {
            match listener.accept() {
                Ok((stream, _)) => {
                    let deadline = Instant::now() + REQUEST_TIMEOUT;
                    let result = (|| -> Result<()> {
                        let peer = peer_identity(&stream)?;
                        let (bytes, descriptors) =
                            candy_netd_client::receive_descriptor_frame_until(&stream, deadline)?;
                        if bytes.len() > CONTROL_BYTES {
                            bail!("authority request too large");
                        }
                        let request: AuthorityControlRequest = serde_json::from_slice(&bytes)?;
                        let mut state = state
                            .lock()
                            .map_err(|_| anyhow::anyhow!("authority controller state poisoned"))?;
                        let result = apply_request(
                            &mut state,
                            peer,
                            &request,
                            descriptors,
                            &updates,
                            &runtime,
                            deadline,
                        );
                        let reply = AuthorityControlResponse {
                            schema_version: 2,
                            process: state.process,
                            controller: state.controller,
                            controller_epoch: state.epoch,
                            nonce: request.nonce,
                            accepted: result.is_ok(),
                            code: if result.is_ok() {
                                "authority_transaction_confirmed"
                            } else {
                                "authority_transaction_rejected"
                            }
                            .into(),
                            detail: result
                                .as_ref()
                                .err()
                                .map(|v| format!("{v:#}"))
                                .unwrap_or_default(),
                            active: state.authority.active.clone(),
                            pending: state.authority.pending.clone(),
                            highest_revision: state.authority.highest_revision,
                            highest_owner_epoch: state.authority.highest_owner_epoch,
                            highest_policy_generation: state.authority.highest_policy_generation,
                            applied_transaction_id: state
                                .authority
                                .active
                                .as_ref()
                                .map(|v| v.transaction_id.clone()),
                            authority_revision: state
                                .authority
                                .active
                                .as_ref()
                                .map(|v| v.authority_revision),
                            current_binding: state.binding,
                            auth_deadline_unix: state.auth_deadline_unix,
                            owner_active: state.owner_active,
                            actual_deadline_mono_ms: state.authority.actual_deadline_mono_ms,
                        };
                        drop(state);
                        let bytes = serde_json::to_vec(&reply)?;
                        if bytes.len() > CONTROL_BYTES {
                            bail!("authority response too large");
                        }
                        if reply.accepted {
                            eprintln!("level=info code=authority_transaction_confirmed module=tunio_authority io_pid={} controller_pid={} controller_epoch={} transaction_id={} authority_revision={} owner_epoch={} policy_generation={} owner_active={} actual_deadline_mono_ms={} operation={:?}", reply.process.pid, reply.controller.pid, reply.controller_epoch, request.transaction_id, reply.authority_revision.unwrap_or(0), reply.current_binding.owner_epoch, reply.current_binding.policy_generation, reply.owner_active, reply.actual_deadline_mono_ms.unwrap_or(0), request.operation);
                        }
                        candy_netd_client::send_descriptor_frame_until(
                            &stream, &bytes, None, deadline,
                        )?;
                        result
                    })();
                    if let Err(error) = result {
                        eprintln!("level=warn code=authority_control_failed module=tunio_authority detail={error:#}");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) => {
                    eprintln!("level=error code=authority_accept_failed module=tunio_authority detail={error}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        let _ = fs::remove_file(socket);
    });
    Ok(())
}

/// Tokio's `Instant` normally uses CLOCK_MONOTONIC, which does not advance
/// while Linux is suspended. Authority envelopes use CLOCK_BOOTTIME so a
/// suspended device must not keep an expired owner alive. Keep this guard
/// independent from the packet bridge's fast path and revoke through the same
/// manager transaction channel when the boot clock reaches the signed cap.
async fn boot_deadline_guard(
    state: Arc<Mutex<Controller>>,
    updates: mpsc::Sender<PacketPortOwnerUpdate>,
    mut stop: watch::Receiver<bool>,
    bootstrap_authorization: Option<AuthorizationCheck>,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { return; }
            }
            _ = tick.tick() => {}
        }
        let (active, binding, owner_active, wall_cap) = match state.try_lock() {
            Ok(state) => (
                state.authority.active.clone(),
                state.binding,
                state.owner_active,
                state.auth_deadline_unix,
            ),
            Err(std::sync::TryLockError::WouldBlock) => continue,
            Err(std::sync::TryLockError::Poisoned(_)) => return,
        };
        if !owner_active {
            continue;
        }
        let expired = match &active {
            Some(active) => authorization_check(active)().is_err(),
            None => {
                bootstrap_authorization
                    .as_ref()
                    .is_some_and(|check| check().is_err())
                    || unix_time().map_or(true, |now| now >= wall_cap)
            }
        };
        if !expired {
            continue;
        }
        let (acknowledgement, applied) = oneshot::channel();
        if updates
            .send(PacketPortOwnerUpdate {
                change: PacketPortOwnerChange::Revoke {
                    owner_epoch: binding.owner_epoch,
                },
                acknowledgement,
                receipt: None,
            })
            .await
            .is_err()
        {
            return;
        }
        let result = tokio::time::timeout(Duration::from_secs(2), applied).await;
        let revoked = matches!(result, Ok(Ok(Ok(()))));
        if !revoked {
            eprintln!("level=warn code=authority_expiry_revoke_failed module=tunio_authority owner_epoch={} transaction_id={} detail={result:?} action=retry", binding.owner_epoch, active.as_ref().map(|v| v.transaction_id.as_str()).unwrap_or("bootstrap"));
            continue;
        }
        if let Ok(mut current) = state.try_lock() {
            // A fresh attach may have raced the revoke. Only clear the exact
            // expired transaction; the replacement remains authoritative.
            if current.binding == binding && current.authority.active.as_ref() == active.as_ref() {
                current.authority.active = None;
                current.authority.actual_deadline_mono_ms = None;
                current.owner_active = false;
                if let Err(error) = current.publish() {
                    eprintln!("level=warn code=authority_expiry_status_failed module=tunio_authority detail={error:#}");
                }
            }
        }
        eprintln!("level=warn code=authority_expired module=tunio_authority owner_epoch={} transaction_id={} action=keep_infrastructure", binding.owner_epoch, active.as_ref().map(|v| v.transaction_id.as_str()).unwrap_or("bootstrap"));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn inherited_bootstrap_cap_cannot_be_extended_by_recomputed_wall_time() {
        assert_eq!(capped_bootstrap_deadline(90_000, Some(50_000)), 50_000);
        assert_eq!(capped_bootstrap_deadline(40_000, Some(50_000)), 40_000);
        assert_eq!(capped_bootstrap_deadline(90_000, None), 90_000);
    }
    use candy_packet_port::{fd::InheritedPacketFd, packet_port::PacketPort};
    use std::process::{Child, Command};
    use tokio::net::UnixDatagram;

    #[test]
    fn delayed_clock_sampling_cannot_extend_authority_deadline() {
        let deadline = owner_deadline_with_clocks(
            1_005,
            100,
            || {
                thread::sleep(Duration::from_millis(20));
                Ok(1_000)
            },
            || Ok(Duration::from_secs(99)),
        )
        .unwrap();
        assert!(deadline <= tokio::time::Instant::now());
        assert!(owner_deadline_with_clocks(
            1_000,
            100,
            || Ok(1_000),
            || Ok(Duration::from_secs(99)),
        )
        .is_err());
        assert!(owner_deadline_with_clocks(
            1_005,
            100,
            || Ok(1_000),
            || Ok(Duration::from_secs(100)),
        )
        .is_err());
    }

    fn binding(epoch: u64, policy: u64) -> PacketPortBinding {
        PacketPortBinding {
            infrastructure_id: [1; 16],
            routing_domain_id: [2; 16],
            infrastructure_generation: 1,
            io_epoch: 1,
            owner_epoch: epoch,
            policy_generation: policy,
        }
    }

    fn ports(epoch: u64, policy: u64) -> (OwnedFd, UnixPacketPort) {
        let (io, worker) = UnixDatagram::pair().unwrap();
        (
            OwnedFd::from(io.into_std().unwrap()),
            UnixPacketPort::new(worker, binding(epoch, policy), PacketPortRole::Worker).unwrap(),
        )
    }

    struct Harness {
        _dir: tempfile::TempDir,
        candidate: Candidate,
        _old_worker: UnixPacketPort,
        socket: PathBuf,
        state: Arc<Mutex<Controller>>,
        kernel: UnixDatagram,
        stop: watch::Sender<bool>,
        task: tokio::task::JoinHandle<
            std::io::Result<candy_packet_port::packet_port_ipc::PacketBridgeCounters>,
        >,
    }

    struct Candidate(Child);
    impl Drop for Candidate {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    impl Harness {
        async fn start(initial_duration: Duration) -> Self {
            let dir = tempfile::tempdir_in("/tmp").unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let candidate = Candidate(Command::new("sleep").arg("60").spawn().unwrap());
            let (tun, kernel) = UnixDatagram::pair().unwrap();
            let tun = InheritedPacketFd::new(OwnedFd::from(tun.into_std().unwrap())).unwrap();
            let (io, old_worker) = ports(1, 1);
            let io = std::os::unix::net::UnixDatagram::from(io);
            io.set_nonblocking(true).unwrap();
            let io = UnixPacketPort::new(
                UnixDatagram::from_std(io).unwrap(),
                binding(1, 1),
                PacketPortRole::Infrastructure,
            )
            .unwrap();
            let (stop, shutdown) = watch::channel(false);
            let managed = crate::start_managed_infrastructure(
                tun,
                io,
                shutdown,
                tokio::time::Instant::now() + initial_duration,
            )
            .await
            .unwrap();
            let process = candy_process_control::process_identity(std::process::id()).unwrap();
            let state = Arc::new(Mutex::new(Controller {
                process,
                controller: process,
                epoch: 1,
                token: "fixture-capability-0123456789abcdef".into(),
                status: dir.path().join("status.json"),
                generation: 1,
                auth_deadline_unix: unix_time().unwrap() + initial_duration.as_secs(),
                binding: binding(1, 1),
                owner_active: true,
                registered: true,
                registration: None,
                authority: AuthorityState::default(),
            }));
            state.lock().unwrap().publish().unwrap();
            let supervision = dir.path().join("control.sock");
            start(
                supervision.clone(),
                state.clone(),
                managed.updates,
                stop.clone(),
                tokio::time::Instant::now() + initial_duration,
            )
            .unwrap();
            Self {
                _dir: dir,
                candidate,
                _old_worker: old_worker,
                socket: authority_control_path(&supervision),
                state,
                kernel,
                stop,
                task: managed.task,
            }
        }

        fn envelope(&self, epoch: u64, policy: u64, revision: u64) -> AuthorityEnvelope {
            let state = self.state.lock().unwrap();
            let now_unix = unix_time().unwrap();
            let now_mono = monotonic_ms().unwrap();
            AuthorityEnvelope {
                transaction_id: format!("{revision:032x}"),
                authority_revision: revision,
                binding: binding(epoch, policy),
                candidate: candy_process_control::process_identity(self.candidate.0.id()).unwrap(),
                controller: state.controller,
                controller_epoch: state.epoch,
                signed_control_hash: format!("{revision:064x}"),
                declaration_hash: "b".repeat(64),
                verification_report_hash: "c".repeat(64),
                snapshot_closure_hash: "d".repeat(64),
                signed_min_expiry_unix: now_unix + 60,
                effective_expiry_unix: now_unix + 30,
                verified_at_unix: now_unix,
                verified_at_mono_ms: now_mono,
                effective_deadline_mono_ms: now_mono + 29_000,
                boot_id: boot_id().unwrap(),
            }
        }

        fn request(
            &self,
            operation: AuthorityOperation,
            envelope: Option<AuthorityEnvelope>,
            transaction: &str,
        ) -> AuthorityControlRequest {
            let state = self.state.lock().unwrap();
            AuthorityControlRequest {
                schema_version: 2,
                process: state.process,
                controller: state.controller,
                controller_epoch: state.epoch,
                token_sha256: format!("{:x}", Sha256::digest(state.token.as_bytes())),
                nonce: "e".repeat(32),
                operation,
                envelope,
                transaction_id: transaction.into(),
            }
        }

        async fn exchange(
            &self,
            request: AuthorityControlRequest,
            fd: Option<OwnedFd>,
        ) -> Result<AuthorityControlResponse> {
            let path = self.socket.clone();
            let process = self.state.lock().unwrap().process;
            tokio::task::spawn_blocking(move || {
                exchange_authority(
                    &path,
                    process,
                    &request,
                    fd.as_ref(),
                    Instant::now() + REQUEST_TIMEOUT,
                )
            })
            .await
            .unwrap()
        }

        async fn finish(self) {
            self.stop.send(true).unwrap();
            self.task.await.unwrap().unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fresh_authority_advances_policy_after_expiry_on_same_io() {
        let harness = Harness::start(Duration::from_millis(20)).await;
        tokio::time::sleep(Duration::from_millis(35)).await;
        let envelope = harness.envelope(2, 2, 1);
        let transaction = envelope.transaction_id.clone();
        let stage = harness
            .exchange(
                harness.request(
                    AuthorityOperation::StageAuthority,
                    Some(envelope.clone()),
                    &transaction,
                ),
                None,
            )
            .await
            .unwrap();
        assert!(!stage.owner_active);
        assert_eq!(stage.current_binding, binding(1, 1));
        assert_eq!(stage.pending, Some(envelope.clone()));
        let (fd, worker) = ports(2, 2);
        let attached = harness
            .exchange(
                harness.request(
                    AuthorityOperation::AttachAuthorized,
                    Some(envelope.clone()),
                    &transaction,
                ),
                Some(fd),
            )
            .await
            .unwrap();
        assert!(attached.owner_active);
        assert_eq!(attached.active, Some(envelope.clone()));
        assert_eq!(attached.pending, None);
        assert_eq!(attached.current_binding, binding(2, 2));
        harness.kernel.send(&[0x45; 64]).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), worker.recv_packet())
                .await
                .unwrap()
                .unwrap(),
            vec![0x45; 64]
        );
        worker.send_packet(&[0x46; 64]).await.unwrap();
        let mut bytes = [0; 100];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), harness.kernel.recv(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            64
        );
        assert_eq!(&bytes[..64], &[0x46; 64]);
        let probe = harness
            .exchange(
                harness.request(AuthorityOperation::ProbeTransaction, None, &transaction),
                None,
            )
            .await
            .unwrap();
        assert_eq!(probe.active, Some(envelope));
        assert_eq!(probe.applied_transaction_id, Some(transaction.clone()));
        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(&harness.state.lock().unwrap().status).unwrap())
                .unwrap();
        assert_eq!(status["generation"], 1);
        assert_eq!(status["infrastructure_generation"], 1);
        assert_eq!(status["policy_generation"], 2);
        let revoked = harness
            .exchange(
                harness.request(AuthorityOperation::RevokeExact, None, &transaction),
                None,
            )
            .await
            .unwrap();
        assert!(!revoked.owner_active);
        harness.kernel.send(&[0x45; 64]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), worker.recv_packet())
                .await
                .is_err()
        );
        assert!(!harness.task.is_finished());
        harness.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn boot_clock_expiry_revokes_owner_with_unexpired_instant_and_keeps_io() {
        let harness = Harness::start(Duration::from_secs(30)).await;
        let envelope = harness.envelope(2, 2, 1);
        let transaction = envelope.transaction_id.clone();
        harness
            .exchange(
                harness.request(
                    AuthorityOperation::StageAuthority,
                    Some(envelope.clone()),
                    &transaction,
                ),
                None,
            )
            .await
            .unwrap();
        let (io, _worker) = ports(2, 2);
        harness
            .exchange(
                harness.request(
                    AuthorityOperation::AttachAuthorized,
                    Some(envelope),
                    &transaction,
                ),
                Some(io),
            )
            .await
            .unwrap();
        // Emulate BOOTTIME advancing across suspend while the manager's
        // CLOCK_MONOTONIC Instant remains far in the future.
        harness
            .state
            .lock()
            .unwrap()
            .authority
            .active
            .as_mut()
            .unwrap()
            .effective_deadline_mono_ms = monotonic_ms().unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !harness.state.lock().unwrap().owner_active {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let probe = harness
            .exchange(
                harness.request(AuthorityOperation::ProbeTransaction, None, &transaction),
                None,
            )
            .await
            .unwrap();
        assert!(!probe.owner_active);
        assert!(probe.actual_deadline_mono_ms.is_none());
        assert_eq!(probe.highest_owner_epoch, 2);
        assert!(!harness.task.is_finished());
        harness.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bad_authority_and_wrong_fd_preserve_io_and_valid_later_attach() {
        let harness = Harness::start(Duration::from_secs(30)).await;
        let envelope = harness.envelope(2, 2, 1);
        let transaction = envelope.transaction_id.clone();
        for mutation in 0..6 {
            let mut invalid = envelope.clone();
            match mutation {
                0 => invalid.effective_expiry_unix = invalid.signed_min_expiry_unix + 1,
                1 => invalid.binding.routing_domain_id = [9; 16],
                2 => invalid.effective_deadline_mono_ms += 120_000,
                3 => invalid.controller_epoch += 1,
                4 => invalid.boot_id = "a".repeat(36),
                _ => invalid.snapshot_closure_hash = "bad".into(),
            }
            assert!(harness
                .exchange(
                    harness.request(
                        AuthorityOperation::StageAuthority,
                        Some(invalid),
                        &transaction
                    ),
                    None
                )
                .await
                .is_err());
        }
        harness
            .exchange(
                harness.request(
                    AuthorityOperation::StageAuthority,
                    Some(envelope.clone()),
                    &transaction,
                ),
                None,
            )
            .await
            .unwrap();
        let replay = harness
            .exchange(
                harness.request(
                    AuthorityOperation::StageAuthority,
                    Some(envelope.clone()),
                    &transaction,
                ),
                None,
            )
            .await
            .unwrap();
        assert_eq!(replay.pending, Some(envelope.clone()));
        let mut changed = envelope.clone();
        changed.effective_deadline_mono_ms += 1;
        assert!(harness
            .exchange(
                harness.request(
                    AuthorityOperation::StageAuthority,
                    Some(changed),
                    &transaction
                ),
                None
            )
            .await
            .is_err());
        let (wrong, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(harness
            .exchange(
                harness.request(
                    AuthorityOperation::AttachAuthorized,
                    Some(envelope.clone()),
                    &transaction
                ),
                Some(OwnedFd::from(wrong))
            )
            .await
            .is_err());
        let (fd, _worker) = ports(2, 2);
        harness
            .exchange(
                harness.request(
                    AuthorityOperation::AttachAuthorized,
                    Some(envelope),
                    &transaction,
                ),
                Some(fd),
            )
            .await
            .unwrap();
        let next = harness.envelope(3, 3, 2);
        let staged = harness
            .exchange(
                harness.request(
                    AuthorityOperation::StageAuthority,
                    Some(next.clone()),
                    &next.transaction_id,
                ),
                None,
            )
            .await
            .unwrap();
        assert!(serde_json::to_vec(&staged).unwrap().len() <= CONTROL_BYTES);
        let discarded = harness
            .exchange(
                harness.request(
                    AuthorityOperation::DiscardAuthority,
                    None,
                    &next.transaction_id,
                ),
                None,
            )
            .await
            .unwrap();
        assert!(discarded.pending.is_none());
        assert_eq!(discarded.highest_revision, 2);
        assert!(harness
            .exchange(
                harness.request(
                    AuthorityOperation::StageAuthority,
                    Some(next.clone()),
                    &next.transaction_id
                ),
                None
            )
            .await
            .is_err());
        harness.finish().await;
    }
}
