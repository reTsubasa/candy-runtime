use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

const GRANT_STATE_SCHEMA_VERSION: u8 = 2;
const MAX_GRANT_ENVELOPE_BYTES: usize = 8 * 1024;
const MAX_GRANT_STATE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantFailure {
    pub stage: &'static str,
    pub code: &'static str,
}

impl std::fmt::Display for GrantFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.stage, self.code)
    }
}
impl std::error::Error for GrantFailure {}

fn failure(stage: &'static str, code: &'static str) -> GrantFailure {
    GrantFailure { stage, code }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSubject {
    pub node_pool_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub projection_id: Uuid,
    pub projection_generation: u64,
    pub projection_content_hash: String,
}

impl GrantSubject {
    pub fn validate(&self) -> Result<()> {
        if self.node_pool_id.is_nil()
            || self.tenant_id.is_nil()
            || self.device_id.is_nil()
            || self.device_key_id.is_nil()
            || self.projection_id.is_nil()
            || self.projection_generation == 0
            || !canonical_hex(&self.projection_content_hash, 32)
        {
            bail!("Grant subject contains an invalid signed authorization binding")
        }
        Ok(())
    }

    fn storage_id(&self) -> Result<String> {
        self.validate()?;
        Ok(domain_hash(b"candy/sdwan-grant-state-v2\0", self, None))
    }

    fn request_id(&self, sequence: u64) -> Result<String> {
        self.validate()?;
        if sequence == 0 {
            bail!("Grant renewal sequence must be non-zero")
        }
        Ok(format!(
            "sdwan-v2-{}",
            domain_hash(b"candy/sdwan-grant-request-v2\0", self, Some(sequence))
        ))
    }
}

fn domain_hash(domain: &[u8], subject: &GrantSubject, sequence: Option<u64>) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(subject.node_pool_id.as_bytes());
    digest.update(subject.tenant_id.as_bytes());
    digest.update(subject.device_id.as_bytes());
    digest.update(subject.device_key_id.as_bytes());
    digest.update(subject.projection_id.as_bytes());
    digest.update(subject.projection_generation.to_be_bytes());
    digest.update(subject.projection_content_hash.as_bytes());
    if let Some(sequence) = sequence {
        digest.update(sequence.to_be_bytes());
    }
    format!("{:x}", digest.finalize())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantIssueRequest<'a> {
    pub request_id: &'a str,
    pub node_pool_id: Uuid,
    pub service_class: &'static str,
    pub service_permission: &'static str,
}

impl<'a> GrantIssueRequest<'a> {
    fn new(subject: &'a GrantSubject, request_id: &'a str) -> Self {
        Self {
            request_id,
            node_pool_id: subject.node_pool_id,
            service_class: "private",
            service_permission: "private.tun.connect",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantIssueResponse {
    pub grant_id: Uuid,
    pub expires_at_unix: u64,
    pub refresh_after_unix: u64,
    pub replayed: bool,
    pub access_grant: String,
}

/// Core-authenticated facts for one opaque `cloud_grant_v1` envelope. Runtime
/// never derives these fields from the Cloud JSON response.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedGrantReport {
    pub schema_version: u16,
    pub ok: bool,
    pub grant_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub node_pool_id: Uuid,
    pub service_permission: String,
    pub route_policy_id: Uuid,
    pub route_policy_generation: u64,
    pub route_policy_content_hash: String,
    pub not_before_unix: u64,
    pub refresh_after_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachedGrant {
    sequence: u64,
    request_id: String,
    grant_id: Uuid,
    fetched_at_unix: u64,
    expires_at_unix: u64,
    access_grant: String,
    verification: VerifiedGrantReport,
}

impl CachedGrant {
    fn from_response(
        subject: &GrantSubject,
        sequence: u64,
        request_id: String,
        response: GrantIssueResponse,
        verification: VerifiedGrantReport,
        now: u64,
    ) -> Result<Self> {
        validate_request_id(&request_id)?;
        if request_id != subject.request_id(sequence)? {
            bail!("Grant response request id is not bound to its renewal transaction")
        }
        validate_cloud_grant_response(&response)?;
        validate_verified_grant(subject, &response, &verification, now)?;
        Ok(Self {
            sequence,
            request_id,
            grant_id: response.grant_id,
            fetched_at_unix: now,
            expires_at_unix: verification.expires_at_unix,
            access_grant: response.access_grant,
            verification,
        })
    }

    fn validate_for(&self, subject: &GrantSubject) -> Result<()> {
        if self.sequence == 0
            || self.request_id != subject.request_id(self.sequence)?
            || self.grant_id.is_nil()
            || self.fetched_at_unix == 0
            || self.expires_at_unix <= self.fetched_at_unix
            || !valid_access_grant(&self.access_grant)
        {
            bail!("cached Grant does not match its renewal transaction")
        }
        validate_verified_grant_binding(subject, &self.verification)?;
        if self.verification.grant_id != self.grant_id
            || self.verification.expires_at_unix != self.expires_at_unix
        {
            bail!("cached Grant metadata does not match its Core verification")
        }
        Ok(())
    }

    pub fn access_grant(&self) -> &str {
        &self.access_grant
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub fn grant_id(&self) -> Uuid {
        self.grant_id
    }

    pub fn refresh_after_unix(&self) -> u64 {
        self.verification.refresh_after_unix
    }

    pub fn is_usable_at(&self, now: u64) -> bool {
        now >= self.verification.not_before_unix
            && now < self.expires_at_unix
            && valid_access_grant(&self.access_grant)
    }

    fn should_refresh_at(&self, now: u64) -> bool {
        self.is_usable_at(now) && now >= self.verification.refresh_after_unix
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingIssuance {
    sequence: u64,
    request_id: String,
    created_at_unix: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantState {
    schema_version: u8,
    node_pool_id: Uuid,
    tenant_id: Uuid,
    device_id: Uuid,
    device_key_id: Uuid,
    projection_id: Uuid,
    projection_generation: u64,
    projection_content_hash: String,
    completed_sequence: u64,
    pending: Option<PendingIssuance>,
    active: Option<CachedGrant>,
    revoked_at_unix: Option<u64>,
}

impl GrantState {
    fn new(subject: &GrantSubject) -> Self {
        Self {
            schema_version: GRANT_STATE_SCHEMA_VERSION,
            node_pool_id: subject.node_pool_id,
            tenant_id: subject.tenant_id,
            device_id: subject.device_id,
            device_key_id: subject.device_key_id,
            projection_id: subject.projection_id,
            projection_generation: subject.projection_generation,
            projection_content_hash: subject.projection_content_hash.clone(),
            completed_sequence: 0,
            pending: None,
            active: None,
            revoked_at_unix: None,
        }
    }

    fn validate_for(&self, subject: &GrantSubject) -> Result<()> {
        subject.validate()?;
        if self.schema_version != GRANT_STATE_SCHEMA_VERSION
            || self.node_pool_id != subject.node_pool_id
            || self.tenant_id != subject.tenant_id
            || self.device_id != subject.device_id
            || self.device_key_id != subject.device_key_id
            || self.projection_id != subject.projection_id
            || self.projection_generation != subject.projection_generation
            || self.projection_content_hash != subject.projection_content_hash
        {
            bail!("Grant state does not match its signed candidate")
        }
        if let Some(active) = &self.active {
            active.validate_for(subject)?;
            if active.sequence != self.completed_sequence {
                bail!("active Grant sequence does not match committed renewal state")
            }
        } else if self.completed_sequence != 0 {
            bail!("Grant state has a completed sequence without an active Grant")
        }
        if let Some(pending) = &self.pending {
            validate_request_id(&pending.request_id)?;
            if pending.sequence
                != self
                    .completed_sequence
                    .checked_add(1)
                    .context("Grant sequence overflow")?
                || pending.request_id != subject.request_id(pending.sequence)?
                || pending.created_at_unix == 0
            {
                bail!("pending Grant transaction is inconsistent")
            }
        }
        if self.revoked_at_unix.is_some() && self.active.is_some() {
            bail!("revoked Grant state still contains an active credential")
        }
        Ok(())
    }

    fn usable(&self, now: u64) -> Option<&CachedGrant> {
        if self.revoked_at_unix.is_some() {
            return None;
        }
        self.active.as_ref().filter(|grant| grant.is_usable_at(now))
    }
}

#[derive(Debug)]
pub enum RefreshOutcome {
    Current(CachedGrant),
    Refreshed(CachedGrant),
    RetainedAfterTransientFailure {
        grant: CachedGrant,
        error: anyhow::Error,
    },
}

impl RefreshOutcome {
    pub fn grant(&self) -> &CachedGrant {
        match self {
            Self::Current(grant) | Self::Refreshed(grant) => grant,
            Self::RetainedAfterTransientFailure { grant, .. } => grant,
        }
    }
}

#[derive(Debug)]
pub enum FetchFailure {
    Transient(anyhow::Error),
    Denied(anyhow::Error),
}

pub fn fetch_from_cloud(
    client: &reqwest::blocking::Client,
    endpoint: Url,
    request: &GrantIssueRequest<'_>,
) -> std::result::Result<GrantIssueResponse, FetchFailure> {
    let response = client
        .post(endpoint)
        .json(request)
        .send()
        .map_err(|error| {
            FetchFailure::Transient(
                anyhow::Error::from(error)
                    .context(failure("grant_http_request", "grant_transport_failed")),
            )
        })?;
    let status = response.status();
    match classify_grant_http_status(status) {
        "success" => {}
        "transient" => {
            return Err(FetchFailure::Transient(
                anyhow::anyhow!("Grant issuance returned HTTP {status}").context(failure(
                    "grant_http_response",
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        "grant_rate_limited"
                    } else {
                        "grant_service_unavailable"
                    },
                )),
            ));
        }
        _ => {
            return Err(FetchFailure::Denied(
                anyhow::anyhow!("Grant issuance returned HTTP {status}").context(failure(
                    "grant_http_response",
                    "grant_http_request_rejected",
                )),
            ));
        }
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type.split(';').next().map(str::trim) != Some("application/json") {
        return Err(FetchFailure::Transient(
            anyhow::anyhow!("Cloud Grant response has an unexpected media type").context(failure(
                "grant_http_response",
                "grant_response_media_type_invalid",
            )),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_GRANT_STATE_BYTES)
    {
        return Err(FetchFailure::Transient(
            anyhow::anyhow!("Cloud Grant response exceeds the bounded size")
                .context(failure("grant_http_response", "grant_response_too_large")),
        ));
    }
    let bytes = response.bytes().map_err(|error| {
        FetchFailure::Transient(
            anyhow::Error::from(error)
                .context(failure("grant_http_body", "grant_response_read_failed")),
        )
    })?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_GRANT_STATE_BYTES {
        return Err(FetchFailure::Transient(
            anyhow::anyhow!("Cloud Grant response has an invalid size")
                .context(failure("grant_http_body", "grant_response_size_invalid")),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        FetchFailure::Transient(anyhow::Error::from(error).context(failure(
            "grant_response_decode",
            "grant_response_json_invalid",
        )))
    })
}

fn classify_grant_http_status(status: reqwest::StatusCode) -> &'static str {
    if status == reqwest::StatusCode::OK {
        "success"
    } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        "transient"
    } else {
        "denied"
    }
}

#[derive(Debug, Clone)]
pub struct GrantStore {
    directory: PathBuf,
}

impl GrantStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            directory: state_dir.join("grants"),
        }
    }

    #[cfg(test)]
    pub fn refresh<F, V>(
        &self,
        subject: &GrantSubject,
        now: u64,
        fetch: F,
        verify: V,
    ) -> Result<RefreshOutcome>
    where
        F: FnOnce(&GrantIssueRequest<'_>) -> std::result::Result<GrantIssueResponse, FetchFailure>,
        V: FnOnce(&Path) -> Result<VerifiedGrantReport>,
    {
        self.refresh_with_clock(subject, now, fetch, verify, || Ok(now))
    }

    pub fn refresh_current<F, V>(
        &self,
        subject: &GrantSubject,
        fetch: F,
        verify: V,
    ) -> Result<RefreshOutcome>
    where
        F: FnOnce(&GrantIssueRequest<'_>) -> std::result::Result<GrantIssueResponse, FetchFailure>,
        V: FnOnce(&Path) -> Result<VerifiedGrantReport>,
    {
        self.refresh_with_clock(subject, unix_now()?, fetch, verify, unix_now)
    }

    fn refresh_with_clock<F, V, N>(
        &self,
        subject: &GrantSubject,
        now: u64,
        fetch: F,
        verify: V,
        validation_now: N,
    ) -> Result<RefreshOutcome>
    where
        F: FnOnce(&GrantIssueRequest<'_>) -> std::result::Result<GrantIssueResponse, FetchFailure>,
        V: FnOnce(&Path) -> Result<VerifiedGrantReport>,
        N: FnOnce() -> Result<u64>,
    {
        subject
            .validate()
            .context(failure("grant_subject_validation", "grant_subject_invalid"))?;
        let mut state = self
            .load_state(subject)
            .context(failure("grant_state_load", "grant_state_load_failed"))?
            .unwrap_or_else(|| GrantState::new(subject));
        if state.revoked_at_unix.is_some() {
            return Err(anyhow::anyhow!(
                "Grant was definitively revoked for this signed authorization generation"
            )
            .context(failure(
                "grant_cached_authorization",
                "grant_authorization_revoked",
            )));
        }
        if let Some(grant) = state
            .usable(now)
            .filter(|grant| !grant.should_refresh_at(now))
            .cloned()
        {
            return Ok(RefreshOutcome::Current(grant));
        }

        if state.pending.is_none() {
            let sequence = state
                .completed_sequence
                .checked_add(1)
                .context("Grant renewal sequence overflow")?;
            state.pending = Some(PendingIssuance {
                sequence,
                request_id: subject.request_id(sequence)?,
                created_at_unix: now.max(1),
            });
            self.store_state(subject, &state).context(failure(
                "grant_pending_persist",
                "grant_pending_persist_failed",
            ))?;
        }
        let pending = state
            .pending
            .clone()
            .context("missing pending Grant transaction")?;
        match fetch(&GrantIssueRequest::new(subject, &pending.request_id)) {
            Ok(response) => {
                validate_cloud_grant_response(&response).context(failure(
                    "grant_response_validation",
                    "grant_response_invalid",
                ))?;
                let staging = self
                    .stage_unverified(&response.access_grant)
                    .context(failure("grant_stage", "grant_staging_failed"))?;
                let verified = verify(&staging).context(failure(
                    "grant_core_verification",
                    "grant_core_verification_failed",
                ));
                let cleanup = fs::remove_file(&staging).context(failure(
                    "grant_stage_cleanup",
                    "grant_staging_cleanup_failed",
                ));
                let verification = match (verified, cleanup) {
                    (Ok(report), Ok(())) => report,
                    (Err(error), _) => return Err(error),
                    (Ok(_), Err(error)) => return Err(error),
                };
                let grant = CachedGrant::from_response(
                    subject,
                    pending.sequence,
                    pending.request_id,
                    response,
                    verification,
                    validation_now().context("read time after Grant verification")?,
                )?;
                state.completed_sequence = pending.sequence;
                state.pending = None;
                state.revoked_at_unix = None;
                state.active = Some(grant.clone());
                self.store_state(subject, &state).context(failure(
                    "grant_active_persist",
                    "grant_active_persist_failed",
                ))?;
                Ok(RefreshOutcome::Refreshed(grant))
            }
            Err(FetchFailure::Transient(error)) => {
                let Some(grant) = state.usable(now).cloned() else {
                    let error = if error.downcast_ref::<GrantFailure>().is_some() {
                        error
                    } else {
                        error.context(failure("grant_fetch", "grant_fetch_transient_failed"))
                    };
                    return Err(error)
                        .context("Grant fetch failed and no unexpired cached Grant exists");
                };
                Ok(RefreshOutcome::RetainedAfterTransientFailure { grant, error })
            }
            Err(FetchFailure::Denied(error)) => {
                state.active = None;
                state.completed_sequence = 0;
                state.pending = None;
                state.revoked_at_unix = Some(now.max(1));
                self.store_state(subject, &state).context(failure(
                    "grant_revocation_persist",
                    "grant_revocation_persist_failed",
                ))?;
                let error = if error.downcast_ref::<GrantFailure>().is_some() {
                    error
                } else {
                    error.context(failure("grant_http_response", "grant_authorization_denied"))
                };
                Err(error).context("Grant request rejected; cached credential invalidated")
            }
        }
    }

    #[cfg(test)]
    pub fn load_usable(&self, subject: &GrantSubject, now: u64) -> Result<Option<CachedGrant>> {
        Ok(self
            .load_state(subject)?
            .and_then(|state| state.usable(now).cloned()))
    }

    fn load_state(&self, subject: &GrantSubject) -> Result<Option<GrantState>> {
        let path = self.path(subject)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("inspect Grant state"),
        };
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_GRANT_STATE_BYTES
        {
            bail!("Grant state must be a bounded regular file")
        }
        let state: GrantState =
            serde_json::from_slice(&fs::read(&path).context("read Grant state")?)
                .context("parse Grant state")?;
        state.validate_for(subject)?;
        Ok(Some(state))
    }

    fn store_state(&self, subject: &GrantSubject, state: &GrantState) -> Result<()> {
        state.validate_for(subject)?;
        ensure_private_directory(&self.directory)?;
        atomic_private_json(&self.path(subject)?, state)
    }

    fn stage_unverified(&self, access_grant: &str) -> Result<PathBuf> {
        if !valid_access_grant(access_grant) {
            bail!("Cloud returned a malformed Grant response")
        }
        let raw = URL_SAFE_NO_PAD
            .decode(access_grant)
            .context("decode staged Grant envelope")?;
        ensure_private_directory(&self.directory)?;
        let path = self
            .directory
            .join(format!(".candidate-grant.{}.tmp", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .context("create staged candidate Grant")?;
        if let Err(error) = file.write_all(&raw).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&path);
            return Err(error).context("write staged candidate Grant");
        }
        Ok(path)
    }

    fn path(&self, subject: &GrantSubject) -> Result<PathBuf> {
        Ok(self
            .directory
            .join(format!("{}.json", subject.storage_id()?)))
    }
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read Grant validation clock")
        .map(|duration| duration.as_secs())
}

fn validate_request_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 120
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("Grant request id is invalid")
    }
    Ok(())
}

fn validate_cloud_grant_response(response: &GrantIssueResponse) -> Result<()> {
    if response.grant_id.is_nil() || !valid_access_grant(&response.access_grant) {
        bail!("Cloud returned a malformed Grant response")
    }
    Ok(())
}

fn validate_verified_grant(
    subject: &GrantSubject,
    response: &GrantIssueResponse,
    report: &VerifiedGrantReport,
    now: u64,
) -> Result<()> {
    validate_verified_grant_binding(subject, report)?;
    for (matches, code) in [
        (
            report.grant_id == response.grant_id,
            "grant_response_id_mismatch",
        ),
        (
            report.expires_at_unix == response.expires_at_unix,
            "grant_response_expiry_mismatch",
        ),
        (
            report.refresh_after_unix == response.refresh_after_unix,
            "grant_response_refresh_mismatch",
        ),
    ] {
        if !matches {
            return Err(failure("grant_response_binding", code).into());
        }
    }
    if report.not_before_unix > now {
        return Err(failure("grant_validity", "grant_not_yet_valid").into());
    }
    if now >= report.expires_at_unix {
        return Err(failure("grant_validity", "grant_expired").into());
    }
    if report.refresh_after_unix < report.not_before_unix
        || report.refresh_after_unix >= report.expires_at_unix
    {
        return Err(failure("grant_validity", "grant_validity_window_invalid").into());
    }
    Ok(())
}

pub fn resolution_error_code(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<GrantFailure>()
        .map_or("grant_resolution_unclassified", |cause| cause.code)
}

pub fn resolution_error_stage(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<GrantFailure>()
        .map_or("grant_resolution", |cause| cause.stage)
}

pub fn resolution_is_retryable(error: &anyhow::Error) -> bool {
    matches!(
        resolution_error_code(error),
        "grant_transport_failed"
            | "grant_rate_limited"
            | "grant_service_unavailable"
            | "grant_response_media_type_invalid"
            | "grant_response_too_large"
            | "grant_response_read_failed"
            | "grant_response_size_invalid"
            | "grant_response_json_invalid"
            | "grant_fetch_transient_failed"
            | "grant_expired"
            | "grant_not_yet_valid"
    )
}

fn validate_verified_grant_binding(
    subject: &GrantSubject,
    report: &VerifiedGrantReport,
) -> Result<()> {
    for (valid, stage, code) in [
        (
            report.schema_version == 1,
            "grant_core_report",
            "grant_report_schema_unsupported",
        ),
        (report.ok, "grant_core_report", "grant_report_rejected"),
        (
            !report.grant_id.is_nil(),
            "grant_core_report",
            "grant_report_id_invalid",
        ),
        (
            report.tenant_id == subject.tenant_id,
            "grant_candidate_binding",
            "grant_tenant_mismatch",
        ),
        (
            report.device_id == subject.device_id,
            "grant_candidate_binding",
            "grant_device_mismatch",
        ),
        (
            report.device_key_id == subject.device_key_id,
            "grant_candidate_binding",
            "grant_device_key_mismatch",
        ),
        (
            report.node_pool_id == subject.node_pool_id,
            "grant_candidate_binding",
            "grant_node_pool_mismatch",
        ),
        (
            report.service_permission == "private.tun.connect",
            "grant_candidate_binding",
            "grant_service_permission_mismatch",
        ),
        (
            report.route_policy_id == subject.projection_id,
            "grant_candidate_binding",
            "grant_route_policy_id_mismatch",
        ),
        (
            report.route_policy_generation == subject.projection_generation,
            "grant_candidate_binding",
            "grant_route_policy_generation_mismatch",
        ),
        (
            report.route_policy_content_hash == subject.projection_content_hash,
            "grant_candidate_binding",
            "grant_route_policy_hash_mismatch",
        ),
        (
            report.not_before_unix != 0,
            "grant_validity",
            "grant_not_before_invalid",
        ),
        (
            report.not_before_unix <= report.refresh_after_unix,
            "grant_validity",
            "grant_refresh_before_validity",
        ),
        (
            report.refresh_after_unix < report.expires_at_unix,
            "grant_validity",
            "grant_refresh_after_expiry",
        ),
    ] {
        if !valid {
            return Err(failure(stage, code).into());
        }
    }
    Ok(())
}

fn valid_access_grant(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 10_924
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= MAX_GRANT_ENVELOPE_BYTES)
}

fn canonical_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("private Grant path is not a real directory")
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).context("create private Grant directory")?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(error).context("inspect private Grant directory"),
    }
    Ok(())
}

fn atomic_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().context("private Grant path has no parent")?;
    ensure_private_directory(parent)?;
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_GRANT_STATE_BYTES {
        bail!("serialized Grant state size is invalid")
    }
    let temporary = parent.join(format!(".grant.{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .context("create staged Grant state")?;
        file.write_all(&bytes).context("write staged Grant state")?;
        file.sync_all().context("sync staged Grant state")?;
        fs::rename(&temporary, path).context("publish Grant state")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("sync Grant state directory")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    fn subject() -> GrantSubject {
        GrantSubject {
            node_pool_id: Uuid::from_bytes([9; 16]),
            tenant_id: Uuid::from_bytes([1; 16]),
            device_id: Uuid::from_bytes([2; 16]),
            device_key_id: Uuid::from_bytes([3; 16]),
            projection_id: Uuid::from_bytes([5; 16]),
            projection_generation: 11,
            projection_content_hash: "66".repeat(32),
        }
    }

    fn response(expires_at_unix: u64) -> GrantIssueResponse {
        GrantIssueResponse {
            grant_id: Uuid::from_bytes([4; 16]),
            expires_at_unix,
            refresh_after_unix: 1_500.min(expires_at_unix - 1),
            replayed: false,
            access_grant: URL_SAFE_NO_PAD.encode(b"opaque grant v1"),
        }
    }

    fn verification(expires_at_unix: u64) -> VerifiedGrantReport {
        let subject = subject();
        VerifiedGrantReport {
            schema_version: 1,
            ok: true,
            grant_id: Uuid::from_bytes([4; 16]),
            tenant_id: subject.tenant_id,
            device_id: subject.device_id,
            device_key_id: subject.device_key_id,
            node_pool_id: subject.node_pool_id,
            service_permission: "private.tun.connect".into(),
            route_policy_id: subject.projection_id,
            route_policy_generation: subject.projection_generation,
            route_policy_content_hash: subject.projection_content_hash,
            not_before_unix: 900,
            refresh_after_unix: 1_500.min(expires_at_unix - 1),
            expires_at_unix,
        }
    }

    #[test]
    fn grant_binding_errors_identify_each_invalid_field() {
        let cases: &[(fn(&mut VerifiedGrantReport), &str, &str)] = &[
            (
                |r| r.schema_version = 2,
                "grant_core_report",
                "grant_report_schema_unsupported",
            ),
            (
                |r| r.ok = false,
                "grant_core_report",
                "grant_report_rejected",
            ),
            (
                |r| r.grant_id = Uuid::nil(),
                "grant_core_report",
                "grant_report_id_invalid",
            ),
            (
                |r| r.tenant_id = Uuid::nil(),
                "grant_candidate_binding",
                "grant_tenant_mismatch",
            ),
            (
                |r| r.device_id = Uuid::nil(),
                "grant_candidate_binding",
                "grant_device_mismatch",
            ),
            (
                |r| r.device_key_id = Uuid::nil(),
                "grant_candidate_binding",
                "grant_device_key_mismatch",
            ),
            (
                |r| r.node_pool_id = Uuid::nil(),
                "grant_candidate_binding",
                "grant_node_pool_mismatch",
            ),
            (
                |r| r.service_permission.clear(),
                "grant_candidate_binding",
                "grant_service_permission_mismatch",
            ),
            (
                |r| r.route_policy_id = Uuid::nil(),
                "grant_candidate_binding",
                "grant_route_policy_id_mismatch",
            ),
            (
                |r| r.route_policy_generation += 1,
                "grant_candidate_binding",
                "grant_route_policy_generation_mismatch",
            ),
            (
                |r| r.route_policy_content_hash.clear(),
                "grant_candidate_binding",
                "grant_route_policy_hash_mismatch",
            ),
            (
                |r| r.not_before_unix = 0,
                "grant_validity",
                "grant_not_before_invalid",
            ),
            (
                |r| r.refresh_after_unix = 899,
                "grant_validity",
                "grant_refresh_before_validity",
            ),
            (
                |r| r.refresh_after_unix = r.expires_at_unix,
                "grant_validity",
                "grant_refresh_after_expiry",
            ),
        ];
        for (mutate, stage, code) in cases {
            let mut report = verification(10_000);
            mutate(&mut report);
            let error = validate_verified_grant_binding(&subject(), &report).unwrap_err();
            assert_eq!(resolution_error_stage(&error), *stage);
            assert_eq!(resolution_error_code(&error), *code);
        }
    }

    #[test]
    fn renewal_request_is_stable_per_sequence_and_changes_after_success() {
        let subject = subject();
        assert!(subject.request_id(1).unwrap().starts_with("sdwan-v2-"));
        assert_eq!(
            subject.request_id(1).unwrap(),
            subject.request_id(1).unwrap()
        );
        assert_ne!(
            subject.request_id(1).unwrap(),
            subject.request_id(2).unwrap()
        );
        assert!(subject.request_id(1).unwrap().len() <= 120);
    }

    #[test]
    fn legacy_grant_cache_is_not_reused_after_wire_contract_upgrade() {
        let root = tempdir().unwrap();
        let grants = root.path().join("grants");
        fs::create_dir(&grants).unwrap();
        let subject = subject();
        let legacy_id = domain_hash(b"candy/sdwan-grant-state-v1\0", &subject, None);
        fs::write(
            grants.join(format!("{legacy_id}.json")),
            b"legacy grant state",
        )
        .unwrap();

        let fetched = Arc::new(Mutex::new(false));
        let fetch_called = Arc::clone(&fetched);
        let outcome = GrantStore::new(root.path())
            .refresh(
                &subject,
                1_000,
                |_| {
                    *fetch_called.lock().unwrap() = true;
                    Ok(response(10_000))
                },
                |_| Ok(verification(10_000)),
            )
            .unwrap();

        assert!(matches!(outcome, RefreshOutcome::Refreshed(_)));
        assert!(*fetched.lock().unwrap());
        assert!(GrantStore::new(root.path())
            .path(&subject)
            .unwrap()
            .exists());
    }

    #[test]
    fn grant_scope_reuses_one_request_across_candidates_in_the_same_pool() {
        let ipv4_candidate = subject();
        let ipv6_candidate = subject();
        assert_eq!(
            ipv4_candidate.storage_id().unwrap(),
            ipv6_candidate.storage_id().unwrap()
        );
        assert_eq!(
            ipv4_candidate.request_id(1).unwrap(),
            ipv6_candidate.request_id(1).unwrap()
        );

        let mut other_pool = subject();
        other_pool.node_pool_id = Uuid::from_bytes([8; 16]);
        assert_ne!(
            ipv4_candidate.storage_id().unwrap(),
            other_pool.storage_id().unwrap()
        );
        assert_ne!(
            ipv4_candidate.request_id(1).unwrap(),
            other_pool.request_id(1).unwrap()
        );
    }

    #[test]
    fn pending_request_survives_lost_response_and_restart() {
        let root = tempdir().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let first_seen = Arc::clone(&seen);
        assert!(GrantStore::new(root.path())
            .refresh(
                &subject(),
                1_000,
                |request| {
                    first_seen
                        .lock()
                        .unwrap()
                        .push(request.request_id.to_owned());
                    Err(FetchFailure::Transient(anyhow::anyhow!("response lost")))
                },
                |_| unreachable!(),
            )
            .is_err());
        let second_seen = Arc::clone(&seen);
        let outcome = GrantStore::new(root.path())
            .refresh(
                &subject(),
                1_001,
                |request| {
                    second_seen
                        .lock()
                        .unwrap()
                        .push(request.request_id.to_owned());
                    Ok(response(10_000))
                },
                |_| Ok(verification(10_000)),
            )
            .unwrap();
        assert!(matches!(outcome, RefreshOutcome::Refreshed(_)));
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0], seen[1]);
    }

    #[test]
    fn cache_is_private_and_transient_failure_keeps_unexpired_grant() {
        let root = tempdir().unwrap();
        let store = GrantStore::new(root.path());
        store
            .refresh(
                &subject(),
                1_000,
                |_| Ok(response(2_000)),
                |_| Ok(verification(2_000)),
            )
            .unwrap();
        let retained = store
            .refresh(
                &subject(),
                1_800,
                |_| Err(FetchFailure::Transient(anyhow::anyhow!("offline"))),
                |_| unreachable!(),
            )
            .unwrap();
        assert!(matches!(
            retained,
            RefreshOutcome::RetainedAfterTransientFailure { .. }
        ));
        assert_eq!(
            fs::metadata(store.path(&subject()).unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn expired_grant_never_masks_cloud_failure() {
        let root = tempdir().unwrap();
        let store = GrantStore::new(root.path());
        store
            .refresh(
                &subject(),
                1_000,
                |_| Ok(response(2_000)),
                |_| Ok(verification(2_000)),
            )
            .unwrap();
        assert!(store
            .refresh(
                &subject(),
                2_000,
                |_| Err(FetchFailure::Transient(anyhow::anyhow!("offline"))),
                |_| unreachable!(),
            )
            .is_err());
        assert!(store.load_usable(&subject(), 2_000).unwrap().is_none());
    }

    #[test]
    fn definitive_denial_removes_active_credential() {
        let root = tempdir().unwrap();
        let store = GrantStore::new(root.path());
        store
            .refresh(
                &subject(),
                1_000,
                |_| Ok(response(10_000)),
                |_| Ok(verification(10_000)),
            )
            .unwrap();
        assert!(store
            .refresh(
                &subject(),
                8_000,
                |_| Err(FetchFailure::Denied(anyhow::anyhow!("forbidden"))),
                |_| unreachable!(),
            )
            .is_err());
        assert!(store.load_usable(&subject(), 8_001).unwrap().is_none());
        let encoded_secret = response(10_000).access_grant;
        assert!(!fs::read_to_string(store.path(&subject()).unwrap())
            .unwrap()
            .contains(&encoded_secret));
    }

    #[test]
    fn successful_renewal_advances_sequence_only_after_new_grant_is_persisted() {
        let root = tempdir().unwrap();
        let store = GrantStore::new(root.path());
        let first = store
            .refresh(
                &subject(),
                1_000,
                |_| Ok(response(2_000)),
                |_| Ok(verification(2_000)),
            )
            .unwrap()
            .grant()
            .request_id
            .clone();
        let second = store
            .refresh(
                &subject(),
                1_800,
                |_| Ok(response(20_000)),
                |_| Ok(verification(20_000)),
            )
            .unwrap()
            .grant()
            .request_id
            .clone();
        assert_ne!(first, second);
        assert_eq!(
            store
                .load_usable(&subject(), 1_801)
                .unwrap()
                .unwrap()
                .request_id,
            second
        );
    }

    #[test]
    fn core_verifier_reads_private_staging_and_failure_preserves_last_good() {
        let root = tempdir().unwrap();
        let store = GrantStore::new(root.path());
        store
            .refresh(
                &subject(),
                1_000,
                |_| Ok(response(10_000)),
                |path| {
                    assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
                    assert_eq!(fs::read(path)?, b"opaque grant v1");
                    Ok(verification(10_000))
                },
            )
            .unwrap();
        let original = store
            .load_usable(&subject(), 8_000)
            .unwrap()
            .unwrap()
            .request_id;
        assert!(store
            .refresh(
                &subject(),
                8_000,
                |_| Ok(response(20_000)),
                |_| bail!("signature mismatch"),
            )
            .is_err());
        assert_eq!(
            store
                .load_usable(&subject(), 8_001)
                .unwrap()
                .unwrap()
                .request_id,
            original
        );
        assert!(fs::read_dir(root.path().join("grants"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("candidate-grant")));
    }

    #[test]
    fn grant_http_failures_distinguish_authorization_from_outage() {
        assert_eq!(
            classify_grant_http_status(reqwest::StatusCode::FORBIDDEN),
            "denied"
        );
        assert_eq!(
            classify_grant_http_status(reqwest::StatusCode::CONFLICT),
            "denied"
        );
        assert_eq!(
            classify_grant_http_status(reqwest::StatusCode::TOO_MANY_REQUESTS),
            "transient"
        );
        assert_eq!(
            classify_grant_http_status(reqwest::StatusCode::SERVICE_UNAVAILABLE),
            "transient"
        );
    }

    #[test]
    fn grant_resolution_errors_have_actionable_codes() {
        for (stage, code, retryable) in [
            ("grant_http_request", "grant_transport_failed", true),
            ("grant_http_response", "grant_rate_limited", true),
            ("grant_http_response", "grant_service_unavailable", true),
            ("grant_http_response", "grant_http_request_rejected", false),
            ("grant_response_decode", "grant_response_json_invalid", true),
            (
                "grant_core_verification",
                "grant_core_verification_failed",
                false,
            ),
            ("grant_candidate_binding", "grant_binding_mismatch", false),
            ("grant_validity", "grant_not_yet_valid", true),
            ("grant_validity", "grant_expired", true),
            ("grant_response_binding", "grant_response_mismatch", false),
        ] {
            let error = anyhow::anyhow!("arbitrary source wording")
                .context(failure(stage, code))
                .context("outer caller context");
            assert_eq!(resolution_error_code(&error), code);
            assert_eq!(resolution_error_stage(&error), stage);
            assert_eq!(resolution_is_retryable(&error), retryable);
        }
        // Text alone is never evidence for a specific failure category.
        assert_eq!(
            resolution_error_code(&anyhow::anyhow!("Cloud rejected Grant issuance")),
            "grant_resolution_unclassified"
        );
    }

    #[test]
    fn validation_uses_the_clock_after_cloud_issuance() {
        let root = tempdir().unwrap();
        let mut verified = verification(10_000);
        verified.not_before_unix = 1_001;
        GrantStore::new(root.path())
            .refresh_with_clock(
                &subject(),
                1_000,
                |_| Ok(response(10_000)),
                |_| Ok(verified),
                || Ok(1_001),
            )
            .expect("post-response time must avoid a false not-yet-valid rejection");
    }
}
