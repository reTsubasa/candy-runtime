use super::*;
use candy_runtime_log::structured_eprintln as eprintln;
use nix::fcntl::{Flock, FlockArg};
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const CATALOG_KEY: &str =
    include_str!("../../../../../openwrt/client/packages/candy-client/catalog-release.pub");
const CATALOG_REF_URL: &str =
    "https://api.github.com/repos/reTsubasa/candy-release/git/ref/heads/main";
const CATALOG_RAW_ROOT: &str = "https://raw.githubusercontent.com/reTsubasa/candy-release";
const RELEASE_ROOT: &str = "https://github.com/reTsubasa/candy-release/releases/download/";
const MAX_BUNDLE: u64 = 256 * 1024 * 1024;
const CATALOG_FETCH_ATTEMPTS: usize = 3;
const CATALOG_CACHE_SECONDS: u64 = 120;
const OPENWRT_UPDATE_MANAGER: &str = "/usr/libexec/candy-update-manager";
const OPENWRT_CLOUD_SYNC_INIT: &str = "/etc/init.d/candy-cloud-sync";
const OPENWRT_CLOUD_SYNC_BIN: &str = "/usr/libexec/candy-cloud-sync";
const OPENWRT_CLOUD_SYNC_LOOP: &str = "/usr/libexec/candy-cloud-sync-loop";
const OPENWRT_UPDATE_CATALOG: &str = "/var/lib/candy/update/stable.json";
const OPENWRT_UPDATE_OPERATION: &str = "/tmp/candy-update-operation.json";
const OPENWRT_CORE_OPERATION: &str = "/tmp/candy-core-operation.json";
const OPENWRT_RUNTIME_HANDOFF_MARKER: &str = "runtime-restart-required.json";
const OPENWRT_RUNTIME_HANDOFF_COMPLETED: &str = "runtime-restart-completed.json";
const OPENWRT_RUNTIME_HANDOFF_FAILURE: &str = "runtime-restart-failed.json";
const OPENWRT_RUNTIME_HANDOFF_TIMEOUT_SECONDS: u64 = 5 * 60;
const MAX_OPERATION_BYTES: u64 = 64 * 1024;
const MAX_FAILURE_DETAIL_CHARS: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UpgradeOutcome {
    Continue,
    RestartRequired,
}

fn completed_upgrade_outcome(component: &str, phase: &str) -> UpgradeOutcome {
    if component == "runtime" && phase == "succeeded" {
        UpgradeOutcome::RestartRequired
    } else {
        UpgradeOutcome::Continue
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Target {
    component: String,
    current_version: String,
    version: String,
    version_key: String,
    digest: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct Job {
    id: Uuid,
    node_id: Uuid,
    device_id: Uuid,
    device_key_id: Uuid,
    target: Target,
    state: String,
    error_code: Option<String>,
    phase: Option<String>,
    // Cloud emits RFC3339 timestamps; the executor only persists/echoes them.
    // Keep them as strings so the wire contract does not depend on chrono's
    // optional serde feature in minimal runtime builds.
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    job: Job,
    phase: String,
    error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure_phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_detail: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RuntimeHandoffMarker {
    schema_version: u8,
    job_id: Uuid,
    version: String,
    sync_binary_sha256: String,
    sync_loop_sha256: String,
    requested_at: u64,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RuntimeHandoffFailure {
    schema_version: u8,
    state: String,
    phase: String,
    error_code: String,
    version: String,
    updated_at: u64,
}

#[derive(Debug, Deserialize)]
struct ManagerOperation {
    state: String,
    action: String,
    phase: String,
    error_code: String,
    detail: String,
    #[serde(default)]
    updated_at: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct UpgradeFailure {
    phase: String,
    error_code: String,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct CoreManagerStatus {
    #[serde(default)]
    current_version: Option<String>,
    #[serde(default)]
    previous_version: Option<String>,
    #[serde(default)]
    installed: Vec<InstalledCore>,
}

#[derive(Debug, Deserialize)]
struct InstalledCore {
    version: String,
    #[serde(default)]
    active: bool,
    #[serde(default)]
    rollback: bool,
    #[serde(default)]
    managed: bool,
}

#[derive(Serialize)]
struct Inventory {
    schema_version: u8,
    platform: &'static str,
    architecture: String,
    targets: Vec<Target>,
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"._+-".contains(&v))
}

fn private_root(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("stage=upgrade_journal error_code=unsafe_state_directory")
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn fetch(client: &Client, url: &str, destination: &Path, limit: u64) -> Result<()> {
    let response = client.get(url).send()?.error_for_status()?;
    if response.content_length().is_some_and(|n| n > limit) {
        bail!("artifact_size_limit");
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(destination)?;
    let length = std::io::copy(&mut response.take(limit + 1), &mut output)?;
    output.sync_all()?;
    if length == 0 || length > limit {
        bail!("artifact_size_limit");
    }
    Ok(())
}

fn command(program: &str, arguments: &[&str], root: &Path) -> Result<()> {
    command_with_env(program, arguments, root, &[])
}

fn command_with_env(
    program: &str,
    arguments: &[&str],
    root: &Path,
    environment: &[(&str, &str)],
) -> Result<()> {
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(root.join("execution.log"))?;
    let mut child = ProcessCommand::new(program)
        .args(arguments)
        .envs(environment.iter().copied())
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("command_exit_{}", status.code().unwrap_or(-1));
            }
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(15 * 60) {
            // SIGTERM lets existing transactional managers run their rollback trap.
            unsafe {
                nix::libc::kill(child.id() as i32, nix::libc::SIGTERM);
            }
            child.wait()?;
            bail!("installer_timeout");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn artifact_sha256(path: &Path, reject_symlink: bool) -> Result<String> {
    let metadata = if reject_symlink {
        fs::symlink_metadata(path)?
    } else {
        fs::metadata(path)?
    };
    if !metadata.is_file()
        || (reject_symlink && metadata.file_type().is_symlink())
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_BUNDLE
    {
        bail!("runtime_handoff_artifact_unsafe");
    }
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn installed_artifact_sha256(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != 0 {
        bail!("runtime_handoff_artifact_unsafe");
    }
    artifact_sha256(path, true)
}

fn running_executable_sha256() -> Result<String> {
    // /proc/self/exe follows the inode mapped by this process. After an APK
    // replacement it still exposes the old deleted binary, so matching this
    // digest proves the final receipt is sent by the newly loaded worker.
    artifact_sha256(Path::new("/proc/self/exe"), false)
}

fn runtime_handoff_marker(root: &Path, journal: &Journal) -> Result<RuntimeHandoffMarker> {
    let path = root.join(OPENWRT_RUNTIME_HANDOFF_MARKER);
    let marker = RuntimeHandoffMarker {
        schema_version: 1,
        job_id: journal.job.id,
        version: journal.job.target.version.clone(),
        sync_binary_sha256: installed_artifact_sha256(Path::new(OPENWRT_CLOUD_SYNC_BIN))?,
        sync_loop_sha256: installed_artifact_sha256(Path::new(OPENWRT_CLOUD_SYNC_LOOP))?,
        requested_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    if !path.exists() {
        return Ok(marker);
    }
    let committed: RuntimeHandoffMarker = read_bounded_json(&path, MAX_PROFILE_BYTES)?;
    if committed.schema_version != marker.schema_version
        || committed.job_id != marker.job_id
        || committed.version != marker.version
        || committed.sync_binary_sha256 != marker.sync_binary_sha256
        || committed.sync_loop_sha256 != marker.sync_loop_sha256
        || committed.requested_at == 0
    {
        bail!("runtime_handoff_marker_conflict");
    }
    Ok(committed)
}

fn validate_runtime_handoff_marker(marker: &RuntimeHandoffMarker) -> Result<()> {
    let valid_digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if marker.schema_version != 1
        || !token(&marker.version)
        || !valid_digest(&marker.sync_binary_sha256)
        || !valid_digest(&marker.sync_loop_sha256)
        || marker.requested_at == 0
    {
        bail!("runtime_handoff_marker_invalid");
    }
    Ok(())
}

fn schedule_openwrt_runtime_handoff(root: &Path) -> Result<()> {
    command(OPENWRT_CLOUD_SYNC_INIT, &["handoff_runtime_upgrade"], root)
        .context("runtime_handoff_schedule_failed")
}

fn catalog_ref_attempt_url(nonce: u128, attempt: usize) -> String {
    let query = format!(
        "?candy_catalog_attempt={nonce}-{}-{attempt}",
        std::process::id()
    );
    format!("{CATALOG_REF_URL}{query}")
}

fn git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn catalog_attempt_urls(commit: &str, nonce: u128, attempt: usize) -> (String, String) {
    let query = format!(
        "?candy_catalog_attempt={nonce}-{}-{attempt}",
        std::process::id()
    );
    (
        format!("{CATALOG_RAW_ROOT}/{commit}/channels/stable.json{query}"),
        format!("{CATALOG_RAW_ROOT}/{commit}/channels/stable.json.sig{query}"),
    )
}

fn catalog_cache_fresh(checked_at: u64, now: u64) -> bool {
    checked_at > 0 && checked_at <= now && now.saturating_sub(checked_at) < CATALOG_CACHE_SECONDS
}

fn verify_catalog_signature(root: &Path, catalog: &Path, signature: &Path) -> bool {
    ProcessCommand::new("usign")
        .args([
            "-V",
            "-p",
            root.join("catalog.pub").to_str().unwrap_or_default(),
            "-m",
            catalog.to_str().unwrap_or_default(),
            "-x",
            signature.to_str().unwrap_or_default(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn validate_catalog_sequence(root: &Path, value: &serde_json::Value) -> Result<u64> {
    let sequence = value["sequence"]
        .as_u64()
        .context("catalog_sequence_missing")?;
    let previous = fs::read_to_string(root.join("catalog-sequence"))
        .unwrap_or_default()
        .parse::<u64>()
        .unwrap_or(0);
    if sequence < previous || value["schema_version"] != 1 || value["channel"] != "stable" {
        bail!("catalog_rollback_or_invalid_schema");
    }
    Ok(sequence)
}

fn cached_catalog(root: &Path, now: u64) -> Option<serde_json::Value> {
    let checked_at = fs::read_to_string(root.join("catalog-checked-at"))
        .ok()?
        .parse::<u64>()
        .ok()?;
    if !catalog_cache_fresh(checked_at, now) {
        return None;
    }
    let catalog_path = root.join("catalog.json");
    let signature_path = root.join("catalog.sig");
    if !verify_catalog_signature(root, &catalog_path, &signature_path) {
        return None;
    }
    let value: serde_json::Value = read_bounded_json(&catalog_path, 4 * 1024 * 1024).ok()?;
    let sequence = validate_catalog_sequence(root, &value).ok()?;
    let recorded = fs::read_to_string(root.join("catalog-sequence"))
        .ok()?
        .parse::<u64>()
        .ok()?;
    (sequence == recorded).then_some(value)
}

fn catalog(root: &Path) -> Result<serde_json::Value> {
    let client = Client::builder()
        .https_only(true)
        .user_agent(concat!("candy-runtime/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(180))
        .connect_timeout(Duration::from_secs(10))
        .build()?;
    atomic_bytes(&root.join("catalog.pub"), CATALOG_KEY.as_bytes(), 0o600)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if let Some(value) = cached_catalog(root, now) {
        return Ok(value);
    }
    let reference_path = root.join("catalog.download.ref.json");
    let catalog_path = root.join("catalog.download.json");
    let signature_path = root.join("catalog.download.sig");
    let mut verified = false;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    for attempt in 1..=CATALOG_FETCH_ATTEMPTS {
        fetch(
            &client,
            &catalog_ref_attempt_url(nonce, attempt),
            &reference_path,
            64 * 1024,
        )?;
        let reference: serde_json::Value = read_bounded_json(&reference_path, 64 * 1024)?;
        let commit = reference["object"]["sha"]
            .as_str()
            .filter(|value| git_object_id(value))
            .context("catalog_ref_invalid_commit")?;
        let (catalog_url, signature_url) = catalog_attempt_urls(commit, nonce, attempt);
        fetch(&client, &catalog_url, &catalog_path, 4 * 1024 * 1024)?;
        fetch(&client, &signature_url, &signature_path, 4096)?;
        if verify_catalog_signature(root, &catalog_path, &signature_path) {
            verified = true;
            break;
        }
        if attempt < CATALOG_FETCH_ATTEMPTS {
            // Re-resolve the branch before retrying. Catalog and signature are
            // always fetched through one immutable repository generation.
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    if !verified {
        bail!("stage=catalog_signature error_code=signature_verification_failed");
    }
    let value: serde_json::Value = read_bounded_json(&catalog_path, 4 * 1024 * 1024)?;
    let sequence = validate_catalog_sequence(root, &value)?;
    atomic_bytes(
        &root.join("catalog.json"),
        &read_bounded(&catalog_path, 4 * 1024 * 1024)?,
        0o600,
    )?;
    atomic_bytes(
        &root.join("catalog.sig"),
        &read_bounded(&signature_path, 4096)?,
        0o600,
    )?;
    atomic_bytes(
        &root.join("catalog-sequence"),
        sequence.to_string().as_bytes(),
        0o600,
    )?;
    atomic_bytes(
        &root.join("catalog-checked-at"),
        now.to_string().as_bytes(),
        0o600,
    )?;
    Ok(value)
}

fn manager(openwrt: bool) -> &'static str {
    if openwrt {
        "/usr/libexec/candy-core-manager"
    } else {
        "/usr/local/bin/candy-core-manager"
    }
}

fn openwrt_runtime_version(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.split_ascii_whitespace().next())
        .and_then(|package| package.strip_prefix("candy-client-"))
        .filter(|version| token(version))
        .map(ToOwned::to_owned)
}

fn current(component: &str, openwrt: bool) -> Result<String> {
    if component == "core" {
        let output = ProcessCommand::new(manager(openwrt))
            .arg("status")
            .output()?;
        if !output.status.success() {
            bail!("core_status_failed");
        }
        let status: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        return Ok(status["current_version"]
            .as_str()
            .unwrap_or("uninstalled")
            .into());
    }
    if openwrt {
        let output = ProcessCommand::new("apk")
            .args(["list", "--installed", "candy-client"])
            .output()?;
        if !output.status.success() {
            bail!("runtime_status_failed");
        }
        return openwrt_runtime_version(&String::from_utf8(output.stdout)?)
            .context("runtime_version_missing");
    }
    Ok(fs::read_to_string("/opt/candy/current/RUNTIME-RELEASE")?
        .trim()
        .into())
}

fn target_key(component: &str, openwrt: bool, arch: &str) -> Result<String> {
    match (component, openwrt, arch) {
        ("core", _, "x86_64" | "aarch64") => Ok(format!("linux_musl_{arch}")),
        ("core", true, "arm") => Ok("linux_musl_armv7".into()),
        ("runtime", false, "x86_64" | "aarch64") => Ok(format!("linux_{arch}")),
        ("runtime", true, "x86_64") => Ok("openwrt_25_12_4_x86_64".into()),
        ("runtime", true, "arm") => Ok("openwrt_25_12_4_arm_cortex_a7_neon_vfpv4".into()),
        _ => bail!("unsupported_upgrade_platform"),
    }
}

fn candidate(
    catalog: &serde_json::Value,
    component: &str,
    openwrt: bool,
    arch: &str,
    key: &str,
) -> Result<(Target, serde_json::Value)> {
    if !token(key) || !matches!(component, "core" | "runtime") {
        bail!("invalid_upgrade_target");
    }
    let release = &catalog[component]["releases"][key];
    let artifact = release["targets"][target_key(component, openwrt, arch)?].clone();
    if artifact.is_null() {
        bail!("target_not_in_signed_catalog");
    }
    let version = release[if component == "runtime" {
        "display_version"
    } else {
        "version"
    }]
    .as_str()
    .context("catalog_version_missing")?;
    if !token(version) {
        bail!("invalid_catalog_version");
    }
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&artifact)?));
    Ok((
        Target {
            component: component.into(),
            current_version: current(component, openwrt)?,
            version: version.into(),
            version_key: key.into(),
            digest,
        },
        artifact,
    ))
}

fn download_artifact(root: &Path, artifact: &serde_json::Value, name: &str) -> Result<PathBuf> {
    let url = artifact["url"].as_str().context("artifact_url_missing")?;
    if !url.starts_with(RELEASE_ROOT) {
        bail!("untrusted_artifact_origin");
    }
    let size = artifact["size"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= MAX_BUNDLE)
        .context("artifact_size_invalid")?;
    let path = root.join(name);
    let client = Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(300))
        .build()?;
    fetch(&client, url, &path, size)?;
    let bytes = read_bounded(&path, MAX_BUNDLE)?;
    if bytes.len() as u64 != size
        || format!("{:x}", Sha256::digest(&bytes)) != artifact["sha256"].as_str().unwrap_or("")
    {
        bail!("artifact_integrity_mismatch");
    }
    Ok(path)
}

fn openwrt_manager_action(component: &str) -> Result<&'static str> {
    match component {
        "core" => Ok("install-core"),
        "runtime" => Ok("install-runtime"),
        _ => bail!("invalid_upgrade_target"),
    }
}

fn verify_openwrt_manager_target(root: &Path, target: &Target) -> Result<()> {
    command(OPENWRT_UPDATE_MANAGER, &["check"], root)?;
    let cache: serde_json::Value =
        read_bounded_json(Path::new(OPENWRT_UPDATE_CATALOG), 4 * 1024 * 1024)?;
    let (checked, _) = candidate(
        &cache,
        &target.component,
        true,
        std::env::consts::ARCH,
        &target.version_key,
    )?;
    if checked.digest != target.digest || checked.version != target.version {
        bail!("catalog_target_changed");
    }
    Ok(())
}

fn linux_runtime_installer_arguments<'a>(
    script: &'a str,
    bundle: &'a str,
    digest: &'a str,
    version: &'a str,
) -> [&'a str; 7] {
    [
        script,
        "--bundle-file",
        bundle,
        "--sha256",
        digest,
        "--version",
        version,
    ]
}

fn install(
    root: &Path,
    target: &Target,
    artifact: &serde_json::Value,
    openwrt: bool,
) -> Result<()> {
    if openwrt {
        // The OpenWrt update manager owns its verified catalog cache, package
        // rollback and local-file handoff to the Core manager. Re-check its
        // signed view and bind it to the Cloud-selected target before install.
        verify_openwrt_manager_target(root, target)?;
        command_with_env(
            OPENWRT_UPDATE_MANAGER,
            &[
                openwrt_manager_action(&target.component)?,
                &target.version_key,
            ],
            root,
            &[("CANDY_UPDATE_PRESERVE_CLOUD_UPGRADE_WORKER", "1")],
        )?;
        if target.component == "core" {
            command(manager(true), &["activate", &target.version], root)?;
            cleanup_managed_cores(root, true);
        }
    } else if target.component == "core" {
        let bundle = download_artifact(root, artifact, "core.tar.gz")?;
        command(
            manager(false),
            &[
                "install",
                &target.version,
                bundle.to_str().context("path")?,
                artifact["sha256"].as_str().context("digest")?,
            ],
            root,
        )?;
        command(manager(false), &["activate", &target.version], root)?;
        cleanup_managed_cores(root, false);
    } else {
        let bundle = download_artifact(root, &artifact["runtime"], "runtime.tar.gz")?;
        // Only extract the one installer from an authenticated artifact. Its
        // own archive validation and transaction remain authoritative.
        let output = ProcessCommand::new("tar")
            .args([
                "-xOf",
                bundle.to_str().context("path")?,
                "./install/upgrade-candy-server.sh",
            ])
            .output()?;
        if !output.status.success() || output.stdout.is_empty() || output.stdout.len() > 128 * 1024
        {
            bail!("runtime_installer_invalid");
        }
        let script = root.join("upgrade.sh");
        atomic_bytes(&script, &output.stdout, 0o700)?;
        let script = script.to_str().context("path")?;
        let bundle = bundle.to_str().context("path")?;
        let digest = artifact["runtime"]["sha256"].as_str().context("digest")?;
        command(
            "sh",
            &linux_runtime_installer_arguments(script, bundle, digest, &target.version),
            root,
        )?;
    }
    if current(&target.component, openwrt)? != target.version {
        bail!("installed_version_mismatch");
    }
    Ok(())
}

fn upgrade_error_code(error: &anyhow::Error) -> &'static str {
    let text = format!("{error:#}");
    if text.contains("artifact_size_invalid") || text.contains("artifact_size_limit") {
        return "upgrade_artifact_invalid_size";
    }
    if text.contains("artifact_integrity_mismatch") {
        return "upgrade_checksum_mismatch";
    }
    if text.contains("untrusted_artifact_origin") {
        return "upgrade_artifact_untrusted_origin";
    }
    if text.contains("runtime_installer_invalid") {
        return "upgrade_installer_invalid";
    }
    if text.contains("unsupported_upgrade_platform")
        || text.contains("target_not_in_signed_catalog")
    {
        return "upgrade_platform_mismatch";
    }
    if text.contains("catalog_target_changed")
        || text.contains("catalog_or_installed_version_changed")
    {
        return "upgrade_catalog_changed";
    }
    if text.contains("installed_version_mismatch") {
        return "upgrade_post_install_version_mismatch";
    }
    if text.contains("installer_timeout") {
        return "upgrade_install_timeout";
    }
    if text.contains("core_status_failed") || text.contains("runtime_status_failed") {
        return "upgrade_pre_install_status_failed";
    }
    if text.contains("signature") || text.contains("signature_verification_failed") {
        return "upgrade_signature_invalid";
    }
    if text.contains("rollback") || text.contains("rollback_failed") {
        return "upgrade_rollback_failed";
    }
    if text.contains("health") {
        return "upgrade_health_check_failed";
    }
    if text.contains("command_exit_") {
        return "upgrade_install_failed";
    }
    "upgrade_execution_failed"
}

fn safe_failure_detail(value: &str) -> String {
    value
        .chars()
        .take(MAX_FAILURE_DETAIL_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn cloud_failure_phase(manager_phase: &str) -> &'static str {
    if manager_phase.contains("rollback") {
        return "rolled_back";
    }
    if manager_phase.contains("health") {
        return "health_check";
    }
    match manager_phase {
        "preflight" | "request" => "prepared",
        "download" | "archive" | "signature" | "manifest" | "validation" | "process_probe"
        | "executable" | "upload" => "verifying",
        "install" => "installing",
        _ => "executing",
    }
}

fn operation_failure_from_bytes(bytes: &[u8]) -> Option<(ManagerOperation, UpgradeFailure)> {
    let operation: ManagerOperation = serde_json::from_slice(bytes).ok()?;
    if operation.state != "error"
        || !token(&operation.action)
        || !token(&operation.phase)
        || !token(&operation.error_code)
    {
        return None;
    }
    let detail = safe_failure_detail(&operation.detail);
    let failure = UpgradeFailure {
        phase: cloud_failure_phase(&operation.phase).into(),
        error_code: operation.error_code.clone(),
        detail,
    };
    Some((operation, failure))
}

fn operation_failure(path: &Path) -> Option<(ManagerOperation, UpgradeFailure)> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_OPERATION_BYTES
    {
        return None;
    }
    let bytes = read_bounded(path, MAX_OPERATION_BYTES).ok()?;
    operation_failure_from_bytes(&bytes)
}

fn structured_failure_from_log(value: &str) -> Option<UpgradeFailure> {
    let mut phase = None;
    let mut error_code = None;
    for field in value.split_ascii_whitespace() {
        if let Some(value) = field.strip_prefix("stage=").filter(|value| token(value)) {
            phase = Some(value);
        }
        if let Some(value) = field
            .strip_prefix("error_code=")
            .filter(|value| token(value))
        {
            error_code = Some(value);
        }
    }
    Some(UpgradeFailure {
        phase: cloud_failure_phase(phase?).into(),
        error_code: error_code?.into(),
        detail: safe_failure_detail(value),
    })
}

fn execution_log_failure(root: &Path) -> Option<UpgradeFailure> {
    let path = root.join("execution.log");
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.mode() & 0o022 != 0 {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let length = metadata.len();
    let keep = length.min(4096);
    file.seek(SeekFrom::Start(length.saturating_sub(keep)))
        .ok()?;
    let mut bytes = Vec::with_capacity(keep as usize);
    file.take(keep).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    text.lines().rev().find_map(structured_failure_from_log)
}

fn reset_execution_log(root: &Path) -> Result<()> {
    let path = root.join("execution.log");
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.sync_all()?;
    Ok(())
}

fn upgrade_failure(
    root: &Path,
    openwrt: bool,
    component: &str,
    error: &anyhow::Error,
) -> UpgradeFailure {
    if openwrt {
        let operation_paths: &[&str] = if component == "runtime" {
            &[OPENWRT_UPDATE_OPERATION]
        } else {
            &[OPENWRT_UPDATE_OPERATION, OPENWRT_CORE_OPERATION]
        };
        let mut operations = operation_paths
            .iter()
            .copied()
            .filter_map(|path| {
                let (operation, failure) = operation_failure(Path::new(path))?;
                let action_matches = match component {
                    "runtime" => operation.action == "install-runtime",
                    "core" => matches!(operation.action.as_str(), "install-core" | "activate"),
                    _ => false,
                };
                action_matches.then_some((operation.updated_at, failure))
            })
            .collect::<Vec<_>>();
        operations.sort_by_key(|(updated_at, _)| *updated_at);
        if let Some((_, failure)) = operations.pop() {
            return failure;
        }
    }
    if let Some(failure) = execution_log_failure(root) {
        return failure;
    }
    UpgradeFailure {
        phase: "executing".into(),
        error_code: upgrade_error_code(error).into(),
        detail: safe_failure_detail(&format!("{error:#}")),
    }
}

fn managed_core_cleanup_versions(status: &CoreManagerStatus) -> Vec<String> {
    status
        .installed
        .iter()
        .filter(|installed| {
            installed.managed
                && !installed.active
                && !installed.rollback
                && status.current_version.as_deref() != Some(&installed.version)
                && status.previous_version.as_deref() != Some(&installed.version)
                && token(&installed.version)
        })
        .map(|installed| installed.version.clone())
        .collect()
}

fn cleanup_managed_cores(root: &Path, openwrt: bool) {
    let manager = manager(openwrt);
    let output = match ProcessCommand::new(manager).arg("status").output() {
        Ok(output)
            if output.status.success() && output.stdout.len() <= MAX_OPERATION_BYTES as usize =>
        {
            output
        }
        Ok(output) => {
            eprintln!(
                "event=core_history_cleanup_failed phase=status error_code=core_status_failed exit={}",
                output.status.code().unwrap_or(-1)
            );
            return;
        }
        Err(error) => {
            eprintln!(
                "event=core_history_cleanup_failed phase=status error_code=core_status_execute_failed detail={}",
                safe_failure_detail(&error.to_string())
            );
            return;
        }
    };
    let status: CoreManagerStatus = match serde_json::from_slice(&output.stdout) {
        Ok(status) => status,
        Err(error) => {
            eprintln!(
                "event=core_history_cleanup_failed phase=status error_code=core_status_invalid detail={}",
                safe_failure_detail(&error.to_string())
            );
            return;
        }
    };
    for version in managed_core_cleanup_versions(&status) {
        if let Err(error) = command(manager, &["remove", &version], root) {
            eprintln!(
                "event=core_history_cleanup_failed phase=remove error_code=core_remove_failed version={} detail={}",
                version,
                safe_failure_detail(&format!("{error:#}"))
            );
        }
    }
}

fn receipt_body(journal: &Journal, state: &str) -> serde_json::Value {
    serde_json::json!({
        "id": journal.job.id,
        "state": state,
        "phase": journal.failure_phase.as_deref().unwrap_or(&journal.phase),
        "error_code": journal.error_code,
        "error_detail": journal.error_detail,
    })
}

fn receipt(client: &Client, cloud: &Url, journal: &Journal, state: &str) -> Result<()> {
    client
        .put(endpoint(cloud, "auth/v1/runtime/upgrades")?)
        .json(&receipt_body(journal, state))
        .send()?
        .error_for_status()?;
    Ok(())
}

fn finalize_terminal_journal<Submit>(
    root: &Path,
    journal_path: &Path,
    journal: &Journal,
    mut submit_receipt: Submit,
) -> Result<UpgradeOutcome>
where
    Submit: FnMut() -> Result<()>,
{
    submit_receipt()?;
    fs::remove_file(journal_path)?;
    File::open(root)?.sync_all()?;
    Ok(completed_upgrade_outcome(
        &journal.job.target.component,
        &journal.phase,
    ))
}

fn ensure_runtime_handoff_marker(root: &Path, marker: &RuntimeHandoffMarker) -> Result<()> {
    validate_runtime_handoff_marker(marker)?;
    let path = root.join(OPENWRT_RUNTIME_HANDOFF_MARKER);
    if path.exists() {
        let committed: RuntimeHandoffMarker = read_bounded_json(&path, MAX_PROFILE_BYTES)?;
        if committed != *marker {
            bail!("runtime_handoff_marker_conflict");
        }
        return Ok(());
    }
    atomic_bytes(&path, &serde_json::to_vec(marker)?, 0o600)?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn read_runtime_handoff_completion(root: &Path, marker: &RuntimeHandoffMarker) -> Result<bool> {
    let path = root.join(OPENWRT_RUNTIME_HANDOFF_COMPLETED);
    if !path.exists() {
        return Ok(false);
    }
    let completed: RuntimeHandoffMarker = read_bounded_json(&path, MAX_PROFILE_BYTES)?;
    if completed != *marker {
        // A previous Runtime transaction may have left completion evidence
        // behind after the worker receipt was interrupted. Only discard
        // structurally valid evidence for another version.
        if completed.schema_version == marker.schema_version
            && token(&completed.version)
            && completed.version != marker.version
        {
            fs::remove_file(&path)?;
            File::open(root)?.sync_all()?;
            return Ok(false);
        }
        bail!("runtime_handoff_completion_conflict");
    }
    Ok(true)
}

fn read_runtime_handoff_failure(
    root: &Path,
    marker: &RuntimeHandoffMarker,
) -> Result<Option<RuntimeHandoffFailure>> {
    let path = root.join(OPENWRT_RUNTIME_HANDOFF_FAILURE);
    if !path.exists() {
        return Ok(None);
    }
    let failure: RuntimeHandoffFailure = read_bounded_json(&path, MAX_PROFILE_BYTES)?;
    if failure.schema_version != 1
        || failure.state != "failed"
        || failure.phase != "runtime_handoff"
        || !token(&failure.error_code)
        || !token(&failure.version)
        || failure.updated_at == 0
    {
        bail!("runtime_handoff_failure_invalid");
    }
    if failure.version != marker.version {
        // A prior Runtime version must not block a newer transaction. Keep
        // malformed and current-version evidence fail-closed.
        fs::remove_file(&path)?;
        File::open(root)?.sync_all()?;
        return Ok(None);
    }
    Ok(Some(failure))
}

fn record_runtime_handoff_failure(
    root: &Path,
    marker: &RuntimeHandoffMarker,
    error_code: &str,
) -> Result<()> {
    let failure = RuntimeHandoffFailure {
        schema_version: 1,
        state: "failed".into(),
        phase: "runtime_handoff".into(),
        error_code: error_code.into(),
        version: marker.version.clone(),
        updated_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    atomic_bytes(
        &root.join(OPENWRT_RUNTIME_HANDOFF_FAILURE),
        &serde_json::to_vec(&failure)?,
        0o600,
    )?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn runtime_handoff_timed_out(marker: &RuntimeHandoffMarker, now: u64) -> bool {
    now.saturating_sub(marker.requested_at) >= OPENWRT_RUNTIME_HANDOFF_TIMEOUT_SECONDS
}

fn schedule_committed_runtime_handoff(root: &Path, marker: &RuntimeHandoffMarker) -> Result<()> {
    if let Err(error) = schedule_openwrt_runtime_handoff(root) {
        record_runtime_handoff_failure(root, marker, "handoff_schedule_failed")?;
        return Err(error);
    }
    Ok(())
}

fn begin_runtime_handoff<Schedule>(
    root: &Path,
    journal_path: &Path,
    marker: &RuntimeHandoffMarker,
    mut schedule_handoff: Schedule,
) -> Result<UpgradeOutcome>
where
    Schedule: FnMut() -> Result<()>,
{
    ensure_runtime_handoff_marker(root, marker)?;
    // The succeeded journal deliberately remains durable. Only the newly
    // loaded worker may submit the final success receipt and remove it.
    if !journal_path.exists() {
        bail!("runtime_handoff_journal_missing");
    }
    schedule_handoff()?;
    Ok(UpgradeOutcome::Continue)
}

fn finalize_completed_runtime_handoff<Submit>(
    root: &Path,
    journal_path: &Path,
    mut submit_receipt: Submit,
) -> Result<UpgradeOutcome>
where
    Submit: FnMut() -> Result<()>,
{
    submit_receipt()?;
    fs::remove_file(journal_path)?;
    for name in [
        OPENWRT_RUNTIME_HANDOFF_MARKER,
        OPENWRT_RUNTIME_HANDOFF_COMPLETED,
        OPENWRT_RUNTIME_HANDOFF_FAILURE,
    ] {
        match fs::remove_file(root.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    File::open(root)?.sync_all()?;
    Ok(UpgradeOutcome::Continue)
}

fn finalize_failed_runtime_handoff<Submit>(
    root: &Path,
    journal_path: &Path,
    journal: &mut Journal,
    marker: &RuntimeHandoffMarker,
    failure: &RuntimeHandoffFailure,
    mut submit_receipt: Submit,
) -> Result<UpgradeOutcome>
where
    Submit: FnMut(&Journal) -> Result<()>,
{
    journal.phase = "failed".into();
    journal.failure_phase = Some("runtime_handoff".into());
    journal.error_code = Some(failure.error_code.clone());
    journal.error_detail = Some(format!(
        "Runtime {} installed but the full Cloud sync service handoff failed",
        marker.version
    ));
    atomic_bytes(journal_path, &serde_json::to_vec(journal)?, 0o600)?;
    File::open(root)?.sync_all()?;
    submit_receipt(journal)?;
    fs::remove_file(journal_path)?;
    File::open(root)?.sync_all()?;
    Ok(UpgradeOutcome::Continue)
}

fn finish_terminal_upgrade(
    client: &Client,
    cloud: &Url,
    root: &Path,
    journal_path: &Path,
    journal: &mut Journal,
    openwrt: bool,
) -> Result<UpgradeOutcome> {
    if openwrt && journal.phase == "succeeded" && journal.job.target.component == "runtime" {
        let marker = runtime_handoff_marker(root, journal)?;
        ensure_runtime_handoff_marker(root, &marker)?;
        if read_runtime_handoff_completion(root, &marker)? {
            if running_executable_sha256()? != marker.sync_binary_sha256 {
                schedule_committed_runtime_handoff(root, &marker)?;
                return Ok(UpgradeOutcome::Continue);
            }
            let receipt_journal = journal.clone();
            return finalize_completed_runtime_handoff(root, journal_path, || {
                receipt(client, cloud, &receipt_journal, "succeeded")
            });
        }
        if read_runtime_handoff_failure(root, &marker)?.is_none()
            && runtime_handoff_timed_out(
                &marker,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            )
        {
            record_runtime_handoff_failure(root, &marker, "handoff_timeout")?;
        }
        if let Some(failure) = read_runtime_handoff_failure(root, &marker)? {
            finalize_failed_runtime_handoff(
                root,
                journal_path,
                journal,
                &marker,
                &failure,
                |failed_journal| receipt(client, cloud, failed_journal, "failed"),
            )?;
            // The Cloud job is now terminal failed, but the installed Runtime
            // still needs local recovery. Keep the marker and retry detached.
            schedule_committed_runtime_handoff(root, &marker)?;
            return Ok(UpgradeOutcome::Continue);
        }
        return begin_runtime_handoff(root, journal_path, &marker, || {
            schedule_committed_runtime_handoff(root, &marker)
        });
    }

    let state = journal.phase.clone();
    let receipt_journal = journal.clone();
    finalize_terminal_journal(root, journal_path, journal, || {
        receipt(client, cloud, &receipt_journal, &state)
    })
}

pub(super) fn run(args: &Args) -> Result<UpgradeOutcome> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("upgrade_requires_root");
    }
    let openwrt = Path::new("/etc/openwrt_release").exists();
    let root = Path::new(if openwrt {
        "/etc/candy/node-upgrades"
    } else {
        "/var/lib/candy/node-upgrades"
    });
    private_root(root)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(root.join("lock"))?;
    let _lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| e)?;
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
    let client = build_client(
        &identity_dir,
        args.ca_certificate.as_deref(),
        &cloud,
        &resolve_cloud_endpoints(&args.state_dir, &cloud)?,
    )?;
    let journal_path = root.join("receipt.json");
    if journal_path.exists() {
        let mut journal: Journal = read_bounded_json(&journal_path, MAX_PROFILE_BYTES)?;
        if journal.job.device_id != identity.device_id
            || journal.job.device_key_id != identity.device_key_id
        {
            bail!("upgrade_journal_identity_changed");
        }
        if journal.phase == "executing" {
            journal.phase = "failed".into();
            journal.error_code = Some("upgrade_interrupted_verify_required".into());
            atomic_bytes(&journal_path, &serde_json::to_vec(&journal)?, 0o600)?;
        }
        if matches!(journal.phase.as_str(), "succeeded" | "failed") {
            return finish_terminal_upgrade(
                &client,
                &cloud,
                root,
                &journal_path,
                &mut journal,
                openwrt,
            );
        }
    }
    if openwrt && root.join(OPENWRT_RUNTIME_HANDOFF_MARKER).exists() {
        let marker: RuntimeHandoffMarker = read_bounded_json(
            &root.join(OPENWRT_RUNTIME_HANDOFF_MARKER),
            MAX_PROFILE_BYTES,
        )?;
        validate_runtime_handoff_marker(&marker)?;
        if read_runtime_handoff_completion(root, &marker)?
            && running_executable_sha256()? == marker.sync_binary_sha256
        {
            for name in [
                OPENWRT_RUNTIME_HANDOFF_MARKER,
                OPENWRT_RUNTIME_HANDOFF_COMPLETED,
                OPENWRT_RUNTIME_HANDOFF_FAILURE,
            ] {
                match fs::remove_file(root.join(name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            File::open(root)?.sync_all()?;
            return Ok(UpgradeOutcome::Continue);
        }
        schedule_committed_runtime_handoff(root, &marker)?;
        return Ok(UpgradeOutcome::Continue);
    }
    let catalog = catalog(root)?;
    let arch = std::env::consts::ARCH;
    let targets = ["runtime", "core"]
        .iter()
        .filter_map(|component| {
            let key = catalog[*component]["latest"].as_str()?;
            candidate(&catalog, component, openwrt, arch, key)
                .ok()
                .map(|(t, _)| t)
        })
        .collect();
    client
        .put(endpoint(&cloud, "auth/v1/runtime/upgrade-inventory")?)
        .json(&Inventory {
            schema_version: 1,
            platform: if openwrt { "openwrt" } else { "linux" },
            architecture: arch.into(),
            targets,
        })
        .send()?
        .error_for_status()?;
    let response = client
        .get(endpoint(&cloud, "auth/v1/runtime/upgrades")?)
        .send()?
        .error_for_status()?;
    let Some(job) =
        serde_json::from_slice::<Option<Job>>(&bounded_response(response, MAX_PROFILE_BYTES)?)?
    else {
        return Ok(UpgradeOutcome::Continue);
    };
    if job.device_id != identity.device_id || job.device_key_id != identity.device_key_id {
        bail!("upgrade_identity_mismatch");
    }
    let (target, artifact) = candidate(
        &catalog,
        &job.target.component,
        openwrt,
        arch,
        &job.target.version_key,
    )?;
    let mut journal = Journal {
        job,
        phase: "prepared".into(),
        error_code: None,
        failure_phase: None,
        error_detail: None,
    };
    reset_execution_log(root)?;
    atomic_bytes(&journal_path, &serde_json::to_vec(&journal)?, 0o600)?;
    receipt(&client, &cloud, &journal, "running")?;
    journal.phase = "executing".into();
    atomic_bytes(&journal_path, &serde_json::to_vec(&journal)?, 0o600)?;
    let result = if target != journal.job.target {
        Err(anyhow::anyhow!("catalog_or_installed_version_changed"))
    } else {
        install(root, &target, &artifact, openwrt)
    };
    journal.phase = if result.is_ok() {
        "succeeded"
    } else {
        "failed"
    }
    .into();
    if let Err(error) = result {
        let failure = upgrade_failure(root, openwrt, &target.component, &error);
        eprintln!(
            "event=node_upgrade_failed id={} phase={} error_code={} detail={}",
            journal.job.id, failure.phase, failure.error_code, failure.detail
        );
        journal.failure_phase = Some(failure.phase);
        journal.error_code = Some(failure.error_code);
        journal.error_detail = Some(failure.detail);
    }
    atomic_bytes(&journal_path, &serde_json::to_vec(&journal)?, 0o600)?;
    finish_terminal_upgrade(&client, &cloud, root, &journal_path, &mut journal, openwrt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn succeeded_runtime_journal() -> Journal {
        Journal {
            job: Job {
                id: Uuid::nil(),
                node_id: Uuid::nil(),
                device_id: Uuid::nil(),
                device_key_id: Uuid::nil(),
                target: Target {
                    component: "runtime".into(),
                    current_version: "0.4.0-r132".into(),
                    version: "0.4.0-r133".into(),
                    version_key: "v0_4_0_r133".into(),
                    digest: "digest".into(),
                },
                state: "running".into(),
                error_code: None,
                phase: Some("executing".into()),
                created_at: "2026-09-17T00:00:00Z".into(),
                updated_at: "2026-09-17T00:00:01Z".into(),
            },
            phase: "succeeded".into(),
            error_code: None,
            failure_phase: None,
            error_detail: None,
        }
    }

    fn runtime_handoff_fixture(journal: &Journal) -> RuntimeHandoffMarker {
        RuntimeHandoffMarker {
            schema_version: 1,
            job_id: journal.job.id,
            version: journal.job.target.version.clone(),
            sync_binary_sha256: "a".repeat(64),
            sync_loop_sha256: "b".repeat(64),
            requested_at: 1,
        }
    }

    #[test]
    fn identifiers_and_architectures_are_restricted() {
        assert!(token("v0_4_0_r112"));
        for value in ["", "$(id)", "../core", "v1;reboot", "--version x"] {
            assert!(!token(value));
        }
        assert!(target_key("runtime", false, "mips").is_err());
        assert_eq!(
            target_key("core", false, "aarch64").unwrap(),
            "linux_musl_aarch64"
        );
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert!(git_object_id(commit));
        assert!(git_object_id(&"a".repeat(64)));
        assert!(!git_object_id("ABCDEF0123456789abcdef0123456789abcdef01"));
        assert!(!git_object_id("../main"));
        assert!(catalog_cache_fresh(100, 100));
        assert!(catalog_cache_fresh(100, 219));
        assert!(!catalog_cache_fresh(100, 220));
        assert!(!catalog_cache_fresh(100, 99));
        assert!(!catalog_cache_fresh(0, 1));
        let ref_url = catalog_ref_attempt_url(123, 2);
        assert_eq!(
            ref_url,
            format!(
                "{CATALOG_REF_URL}?candy_catalog_attempt=123-{}-2",
                std::process::id()
            )
        );
        let (catalog_url, signature_url) = catalog_attempt_urls(commit, 123, 2);
        assert_eq!(
            catalog_url,
            format!(
                "{CATALOG_RAW_ROOT}/{commit}/channels/stable.json?candy_catalog_attempt=123-{}-2",
                std::process::id()
            )
        );
        assert_eq!(
            signature_url,
            format!(
                "{CATALOG_RAW_ROOT}/{commit}/channels/stable.json.sig?candy_catalog_attempt=123-{}-2",
                std::process::id()
            )
        );
    }

    #[test]
    fn parses_apk_tools_v3_installed_runtime_version() {
        assert_eq!(
            openwrt_runtime_version(
                "candy-client-0.4.0-r113 x86_64 {feeds/base/candy-client} () [installed]\n"
            )
            .as_deref(),
            Some("0.4.0-r113")
        );
        assert!(openwrt_runtime_version("candy-client-$(id) x86_64 [installed]\n").is_none());
    }

    #[test]
    fn upgrade_failures_keep_their_stage() {
        assert_eq!(
            upgrade_error_code(&anyhow::anyhow!("artifact_integrity_mismatch")),
            "upgrade_checksum_mismatch"
        );
        assert_eq!(
            upgrade_error_code(&anyhow::anyhow!("installer_timeout")),
            "upgrade_install_timeout"
        );
        assert_eq!(
            upgrade_error_code(&anyhow::anyhow!("installed_version_mismatch")),
            "upgrade_post_install_version_mismatch"
        );
        assert_eq!(
            upgrade_error_code(&anyhow::anyhow!("rollback failed")),
            "upgrade_rollback_failed"
        );
        assert_eq!(
            upgrade_error_code(&anyhow::anyhow!("unexpected process failure")),
            "upgrade_execution_failed"
        );
        let (_, failure) = operation_failure_from_bytes(
            br#"{"state":"error","action":"install-runtime","phase":"preflight","error_code":"insufficient_space","detail":"required_bytes=900 available_bytes=100\nunsafe","updated_at":7}"#,
        )
        .unwrap();
        assert_eq!(failure.phase, "prepared");
        assert_eq!(failure.error_code, "insufficient_space");
        assert_eq!(
            failure.detail,
            "required_bytes=900 available_bytes=100 unsafe"
        );
        assert_eq!(
            structured_failure_from_log(
                "candy-core-manager: stage=core_rollback error_code=service_recovery_failed detail"
            ),
            Some(UpgradeFailure {
                phase: "rolled_back".into(),
                error_code: "service_recovery_failed".into(),
                detail: "candy-core-manager: stage=core_rollback error_code=service_recovery_failed detail".into(),
            })
        );
        assert!(operation_failure_from_bytes(
            br#"{"state":"error","action":"install-runtime","phase":"install","error_code":"bad code","detail":"x"}"#,
        )
        .is_none());
    }

    #[test]
    fn managed_core_cleanup_preserves_active_rollback_and_unmanaged_versions() {
        let status: CoreManagerStatus = serde_json::from_value(serde_json::json!({
            "current_version": "0.3.53",
            "previous_version": "0.3.52",
            "installed": [
                {"version":"0.3.53","active":false,"rollback":false,"managed":true},
                {"version":"0.3.52","active":false,"rollback":false,"managed":true},
                {"version":"0.3.51","active":false,"rollback":false,"managed":true},
                {"version":"0.3.50","active":false,"rollback":false,"managed":false},
                {"version":"0.3.49","active":true,"rollback":false,"managed":true},
                {"version":"0.3.48","active":false,"rollback":true,"managed":true},
                {"version":"../escape","active":false,"rollback":false,"managed":true}
            ]
        }))
        .unwrap();
        assert_eq!(managed_core_cleanup_versions(&status), ["0.3.51"]);
    }

    #[test]
    fn platform_install_contracts_use_the_owning_manager_and_exact_arguments() {
        assert_eq!(OPENWRT_UPDATE_CATALOG, "/var/lib/candy/update/stable.json");
        assert_eq!(
            openwrt_manager_action("runtime").unwrap(),
            "install-runtime"
        );
        assert_eq!(openwrt_manager_action("core").unwrap(), "install-core");
        assert!(openwrt_manager_action("other").is_err());
        assert_eq!(
            linux_runtime_installer_arguments(
                "/var/lib/candy/node-upgrades/upgrade.sh",
                "/var/lib/candy/node-upgrades/runtime.tar.gz",
                "digest",
                "0.4.0-r129",
            ),
            [
                "/var/lib/candy/node-upgrades/upgrade.sh",
                "--bundle-file",
                "/var/lib/candy/node-upgrades/runtime.tar.gz",
                "--sha256",
                "digest",
                "--version",
                "0.4.0-r129",
            ]
        );
        assert_eq!(
            completed_upgrade_outcome("runtime", "succeeded"),
            UpgradeOutcome::RestartRequired
        );
        assert_eq!(
            completed_upgrade_outcome("runtime", "failed"),
            UpgradeOutcome::Continue
        );
        assert_eq!(
            completed_upgrade_outcome("core", "succeeded"),
            UpgradeOutcome::Continue
        );
    }

    #[test]
    fn runtime_handoff_keeps_terminal_receipt_pending_until_new_worker() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let journal_path = root.join("receipt.json");
        fs::write(&journal_path, b"journal").unwrap();
        let journal = succeeded_runtime_journal();
        let marker = runtime_handoff_fixture(&journal);
        let events = RefCell::new(Vec::new());

        let outcome = begin_runtime_handoff(root, &journal_path, &marker, || {
            assert!(journal_path.exists());
            let committed: RuntimeHandoffMarker = read_bounded_json(
                &root.join(OPENWRT_RUNTIME_HANDOFF_MARKER),
                MAX_PROFILE_BYTES,
            )?;
            assert_eq!(committed, marker);
            events.borrow_mut().push("handoff");
            Ok(())
        })
        .unwrap();

        assert_eq!(outcome, UpgradeOutcome::Continue);
        assert_eq!(*events.borrow(), ["handoff"]);
        assert!(journal_path.exists());
    }

    #[test]
    fn new_worker_commits_success_before_removing_handoff_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let journal_path = root.join("receipt.json");
        fs::write(&journal_path, b"journal").unwrap();
        let journal = succeeded_runtime_journal();
        let marker = runtime_handoff_fixture(&journal);
        ensure_runtime_handoff_marker(root, &marker).unwrap();
        fs::write(
            root.join(OPENWRT_RUNTIME_HANDOFF_COMPLETED),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();

        let outcome = finalize_completed_runtime_handoff(root, &journal_path, || {
            assert!(journal_path.exists());
            assert!(root.join(OPENWRT_RUNTIME_HANDOFF_MARKER).exists());
            assert!(root.join(OPENWRT_RUNTIME_HANDOFF_COMPLETED).exists());
            Ok(())
        })
        .unwrap();

        assert_eq!(outcome, UpgradeOutcome::Continue);
        assert!(!journal_path.exists());
        assert!(!root.join(OPENWRT_RUNTIME_HANDOFF_MARKER).exists());
        assert!(!root.join(OPENWRT_RUNTIME_HANDOFF_COMPLETED).exists());
    }

    #[test]
    fn bounded_handoff_failure_submits_precise_terminal_failure() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let journal_path = root.join("receipt.json");
        fs::write(&journal_path, b"journal").unwrap();
        let mut journal = succeeded_runtime_journal();
        let marker = runtime_handoff_fixture(&journal);
        ensure_runtime_handoff_marker(root, &marker).unwrap();
        let failure = RuntimeHandoffFailure {
            schema_version: 1,
            state: "failed".into(),
            phase: "runtime_handoff".into(),
            error_code: "handoff_service_restart_failed".into(),
            version: marker.version.clone(),
            updated_at: 1,
        };

        let outcome = finalize_failed_runtime_handoff(
            root,
            &journal_path,
            &mut journal,
            &marker,
            &failure,
            |failed_journal| {
                assert_eq!(failed_journal.phase, "failed");
                assert_eq!(
                    failed_journal.failure_phase.as_deref(),
                    Some("runtime_handoff")
                );
                assert_eq!(
                    failed_journal.error_code.as_deref(),
                    Some("handoff_service_restart_failed")
                );
                assert!(journal_path.exists());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(outcome, UpgradeOutcome::Continue);
        assert!(!journal_path.exists());
        assert!(root.join(OPENWRT_RUNTIME_HANDOFF_MARKER).exists());
    }

    #[test]
    fn power_loss_retry_is_idempotent_and_failed_schedule_keeps_journal() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let journal_path = root.join("receipt.json");
        fs::write(&journal_path, b"journal").unwrap();
        let journal = succeeded_runtime_journal();
        let marker = runtime_handoff_fixture(&journal);

        let error = begin_runtime_handoff(root, &journal_path, &marker, || {
            bail!("detached_restart_unavailable")
        })
        .unwrap_err();

        assert!(error.to_string().contains("detached_restart_unavailable"));
        assert!(journal_path.exists());
        assert!(root.join(OPENWRT_RUNTIME_HANDOFF_MARKER).exists());

        let outcome = begin_runtime_handoff(root, &journal_path, &marker, || Ok(())).unwrap();
        assert_eq!(outcome, UpgradeOutcome::Continue);
        let committed: RuntimeHandoffMarker = read_bounded_json(
            &root.join(OPENWRT_RUNTIME_HANDOFF_MARKER),
            MAX_PROFILE_BYTES,
        )
        .unwrap();
        assert_eq!(committed, marker);
    }

    #[test]
    fn missing_handoff_evidence_has_a_bounded_cloud_deadline() {
        let journal = succeeded_runtime_journal();
        let mut marker = runtime_handoff_fixture(&journal);
        marker.requested_at = 1_000;
        assert!(!runtime_handoff_timed_out(&marker, 1_299));
        assert!(runtime_handoff_timed_out(&marker, 1_300));
    }

    #[test]
    fn stale_handoff_failure_is_removed_for_a_new_runtime_version() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let journal = succeeded_runtime_journal();
        let marker = runtime_handoff_fixture(&journal);
        let stale = RuntimeHandoffFailure {
            schema_version: 1,
            state: "failed".into(),
            phase: "runtime_handoff".into(),
            error_code: "handoff_completion_write_failed".into(),
            version: "0.4.0-r136".into(),
            updated_at: 1,
        };
        fs::write(
            root.join(OPENWRT_RUNTIME_HANDOFF_FAILURE),
            serde_json::to_vec(&stale).unwrap(),
        )
        .unwrap();

        assert_eq!(read_runtime_handoff_failure(root, &marker).unwrap(), None);
        assert!(!root.join(OPENWRT_RUNTIME_HANDOFF_FAILURE).exists());
    }

    #[test]
    fn stale_handoff_completion_is_removed_for_a_new_runtime_version() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let journal = succeeded_runtime_journal();
        let marker = runtime_handoff_fixture(&journal);
        let mut stale = marker.clone();
        stale.version = "0.4.0-r136".into();
        fs::write(
            root.join(OPENWRT_RUNTIME_HANDOFF_COMPLETED),
            serde_json::to_vec(&stale).unwrap(),
        )
        .unwrap();

        assert!(!read_runtime_handoff_completion(root, &marker).unwrap());
        assert!(!root.join(OPENWRT_RUNTIME_HANDOFF_COMPLETED).exists());
    }

    #[test]
    fn failed_receipt_preserves_handoff_phase_and_detail() {
        let mut journal = succeeded_runtime_journal();
        journal.phase = "failed".into();
        journal.failure_phase = Some("runtime_handoff".into());
        journal.error_code = Some("handoff_service_restart_failed".into());
        journal.error_detail = Some(
            "Runtime 0.4.0-r134 installed but the full Cloud sync service handoff failed".into(),
        );

        let body = receipt_body(&journal, "failed");
        assert_eq!(body["state"], "failed");
        assert_eq!(body["phase"], "runtime_handoff");
        assert_eq!(body["error_code"], "handoff_service_restart_failed");
        assert_eq!(
            body["error_detail"],
            "Runtime 0.4.0-r134 installed but the full Cloud sync service handoff failed"
        );
    }
}
