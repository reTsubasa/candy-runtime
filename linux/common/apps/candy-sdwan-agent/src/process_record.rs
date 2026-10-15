#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Read;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_RECORD_BYTES: u64 = 16 * 1024;
const MAX_STATUS_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedProcessRecord {
    pub schema_version: u8,
    pub pid: u32,
    pub process_start_ticks: u64,
    pub uid: u32,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub executable: PathBuf,
    pub status_path: PathBuf,
    pub readiness_token_sha256: String,
    pub infrastructure_generation: u64,
    pub policy_generation: u64,
    #[serde(default)]
    pub status_generation: Option<u64>,
    #[serde(default)]
    pub worker_epoch: Option<u64>,
    #[serde(default)]
    pub io_epoch: Option<u64>,
    #[serde(default)]
    pub packet_binding_file: Option<PathBuf>,
    #[serde(default)]
    pub effective_plan_file: Option<PathBuf>,
    #[serde(default)]
    pub authorization_snapshot_sha256: Option<String>,
    pub auth_deadline_unix: u64,
    #[serde(default)]
    pub shared_worker: Option<crate::shared_worker::SharedWorker>,
    #[serde(default)]
    pub shared_domain_instance: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> Result<(u64, u32, u64, u64)> {
    if pid == 0 || pid > i32::MAX as u32 {
        bail!("invalid managed PID");
    }
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = fs::read_to_string(root.join("stat"))?;
    let fields = stat
        .rsplit_once(')')
        .context("invalid process stat")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields
        .first()
        .is_none_or(|state| matches!(*state, "Z" | "X" | "x"))
    {
        bail!("managed process exited");
    }
    let start = fields.get(19).context("missing process epoch")?.parse()?;
    let owner = fs::metadata(&root)?.uid();
    let executable = fs::metadata(root.join("exe"))?;
    Ok((start, owner, executable.dev(), executable.ino()))
}

#[cfg(not(target_os = "linux"))]
fn process_identity(_: u32) -> Result<(u64, u32, u64, u64)> {
    bail!("managed process identity requires Linux procfs")
}

impl ManagedProcessRecord {
    pub fn business_is_current(&self) -> Result<bool> {
        if !candy_process_control::process_is_current_confirmed(
            candy_process_control::ProcessIdentity {
                pid: self.pid,
                start_ticks: self.process_start_ticks,
            },
        )? {
            return Ok(false);
        }
        match (&self.shared_worker, &self.shared_domain_instance) {
            (Some(host), Some(instance)) => {
                anyhow::ensure!(
                    host.identity.pid == self.pid
                        && host.identity.start_ticks == self.process_start_ticks,
                    "shared business record host differs"
                );
                crate::shared_worker::domain_running(host, instance)
            }
            (None, None) => Ok(true),
            _ => anyhow::bail!("shared business record incomplete"),
        }
    }
    pub fn private_status(&self) -> Result<serde_json::Value> {
        read_private_json(&self.status_path, MAX_STATUS_BYTES)
    }
    #[cfg(target_os = "linux")]
    pub fn capture(
        pid: u32,
        executable: &Path,
        status_path: &Path,
        token: &str,
        infrastructure_generation: u64,
        policy_generation: u64,
        auth_deadline_unix: u64,
    ) -> Result<Self> {
        let (process_start_ticks, uid, executable_device, executable_inode) =
            process_identity(pid)?;
        let expected = fs::metadata(executable)?;
        if (expected.dev(), expected.ino()) != (executable_device, executable_inode) {
            bail!("managed executable identity differs from configured Core");
        }
        if uid != nix::unistd::geteuid().as_raw() {
            bail!("managed process UID differs from Runtime");
        }
        Ok(Self {
            schema_version: 1,
            shared_worker: None,
            shared_domain_instance: None,
            pid,
            process_start_ticks,
            uid,
            executable_device,
            executable_inode,
            executable: fs::canonicalize(executable)?,
            status_path: status_path.to_owned(),
            readiness_token_sha256: format!("{:x}", Sha256::digest(token.as_bytes())),
            infrastructure_generation,
            policy_generation,
            status_generation: Some(policy_generation),
            worker_epoch: None,
            io_epoch: None,
            packet_binding_file: None,
            effective_plan_file: None,
            authorization_snapshot_sha256: None,
            auth_deadline_unix,
        })
    }

    pub fn validate_current(&self, expected_executable: &Path, now_unix: u64) -> Result<()> {
        let status = self.validate_bound_status(expected_executable, now_unix)?;
        if !matches!(status["lifecycle"].as_str(), Some("active" | "starting")) {
            bail!("managed Core lifecycle is not active or starting");
        }
        Ok(())
    }

    pub fn validate_bound_status(
        &self,
        expected_executable: &Path,
        now_unix: u64,
    ) -> Result<serde_json::Value> {
        self.validate_identity(expected_executable, now_unix)?;
        let status = self.private_status()?;
        let policy_generation = status["policy_generation"]
            .as_u64()
            .filter(|v| *v != 0)
            .or_else(|| status["generation"].as_u64());
        let token_matches = status["readiness_token"].as_str().is_some_and(|token| {
            format!("{:x}", Sha256::digest(token.as_bytes())) == self.readiness_token_sha256
        });
        if status["schema_version"] != 3
            || status["pid"] != self.pid
            || status["generation"]
                != self
                    .status_generation
                    .unwrap_or(self.infrastructure_generation)
            || policy_generation != Some(self.policy_generation)
            || !token_matches
            || status["auth_deadline_unix"]
                .as_u64()
                .is_some_and(|deadline| deadline != self.auth_deadline_unix)
        {
            bail!("managed Core status is not bound to process, epoch, token and generations");
        }
        Ok(status)
    }

    pub fn validate_identity(&self, expected_executable: &Path, now_unix: u64) -> Result<()> {
        self.validate_infrastructure_identity(expected_executable)?;
        if self.auth_deadline_unix == 0 || now_unix >= self.auth_deadline_unix {
            bail!("managed record authorization invalid or expired");
        }
        Ok(())
    }

    pub fn validate_infrastructure_identity(&self, expected_executable: &Path) -> Result<()> {
        if self.schema_version != 1
            || self.infrastructure_generation == 0
            || !self.status_path.is_absolute()
        {
            bail!("managed infrastructure metadata invalid");
        }
        let actual = process_identity(self.pid)?;
        if actual
            != (
                self.process_start_ticks,
                self.uid,
                self.executable_device,
                self.executable_inode,
            )
            || self.uid != nix::unistd::geteuid().as_raw()
        {
            bail!("managed process identity or epoch changed");
        }
        let expected = fs::metadata(expected_executable)?;
        if (expected.dev(), expected.ino()) != (self.executable_device, self.executable_inode) {
            bail!("configured executable differs from managed record");
        }
        Ok(())
    }

    pub fn validate_infrastructure_current(&self, expected_executable: &Path) -> Result<()> {
        self.validate_infrastructure_identity(expected_executable)?;
        let status = self.private_status()?;
        let token_matches = status["readiness_token"].as_str().is_some_and(|token| {
            format!("{:x}", Sha256::digest(token.as_bytes())) == self.readiness_token_sha256
        });
        if status["schema_version"] != 3
            || status["pid"] != self.pid
            || status["process_start_ticks"] != self.process_start_ticks
            || status["packet_binding"]["infrastructure_generation"]
                != self.infrastructure_generation
            || self
                .io_epoch
                .is_some_and(|epoch| status["packet_binding"]["io_epoch"] != epoch)
            || !token_matches
            || status["lifecycle"] != "active"
        {
            bail!("live infrastructure status is not bound to actual IO process/epoch/capability");
        }
        Ok(())
    }
}

pub fn read(path: &Path) -> Result<ManagedProcessRecord> {
    read_private_json(path, MAX_RECORD_BYTES)
}

/// Missing proof and unreadable proof are different recovery states.
pub fn read_optional(path: &Path) -> Result<Option<ManagedProcessRecord>> {
    match read(path) {
        Ok(record) => Ok(Some(record)),
        Err(error) if error.downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound) => Ok(None),
        Err(error) => Err(error.context(format!(
            "code=managed_record_unconfirmed module=process_record path={} action=preserve_owner_and_reconcile_original_record", path.display()
        ))),
    }
}

fn read_private_json<T: serde::de::DeserializeOwned>(path: &Path, bound: u64) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.len() == 0
        || metadata.len() > bound
    {
        bail!("managed proof must be a bounded current-user 0600 regular file");
    }
    let mut bytes = Vec::new();
    file.take(bound + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > bound {
        bail!("managed proof exceeds size bound");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(target_os = "linux")]
pub fn publish(path: &Path, record: &ManagedProcessRecord) -> Result<()> {
    let parent = path.parent().context("managed record has no parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        bail!("managed record parent invalid");
    }
    let temporary = parent.join(format!(
        ".managed-process-{}-{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(record)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn managed_record_rejects_epoch_token_generation_and_executable_mismatch() {
        let directory = tempfile::tempdir().unwrap();
        let status = directory.path().join("status.json");
        let executable = fs::read_link(format!("/proc/{}/exe", std::process::id())).unwrap();
        let record = ManagedProcessRecord::capture(
            std::process::id(),
            &executable,
            &status,
            "secret-token",
            7,
            8,
            100,
        )
        .unwrap();
        let json = serde_json::json!({"schema_version":3,"pid":record.pid,"generation":8,"policy_generation":8,"readiness_token":"secret-token","lifecycle":"active"});
        fs::write(&status, serde_json::to_vec(&json).unwrap()).unwrap();
        fs::set_permissions(&status, fs::Permissions::from_mode(0o600)).unwrap();
        record.validate_current(&executable, 99).unwrap();
        let mut terminal = json.clone();
        terminal["lifecycle"] = "failed".into();
        fs::write(&status, serde_json::to_vec(&terminal).unwrap()).unwrap();
        assert_eq!(
            record.validate_bound_status(&executable, 99).unwrap()["lifecycle"],
            "failed"
        );
        assert!(record.validate_current(&executable, 99).is_err());
        terminal["pid"] = (record.pid + 1).into();
        fs::write(&status, serde_json::to_vec(&terminal).unwrap()).unwrap();
        assert!(record.validate_bound_status(&executable, 99).is_err());
        fs::write(&status, serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(record.infrastructure_generation, 7);
        assert_eq!(record.status_generation, Some(8));
        assert!(record.validate_current(&executable, 100).is_err());
        let mut changed = record.clone();
        changed.process_start_ticks += 1;
        assert!(changed.validate_current(&executable, 99).is_err());
        let mut changed = record.clone();
        changed.policy_generation += 1;
        assert!(changed.validate_current(&executable, 99).is_err());
        let mut changed = record.clone();
        changed.readiness_token_sha256 = "0".repeat(64);
        assert!(changed.validate_current(&executable, 99).is_err());
        assert!(record.validate_current(Path::new("/bin/sh"), 99).is_err());
        let path = directory.path().join("record.json");
        publish(&path, &record).unwrap();
        assert!(!fs::read_to_string(&path).unwrap().contains("secret-token"));
        read(&path)
            .unwrap()
            .validate_current(&executable, 99)
            .unwrap();
    }

    #[test]
    fn expired_business_authority_does_not_invalidate_live_infrastructure_identity() {
        let directory = tempfile::tempdir().unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let status = directory.path().join("status");
        let mut record = ManagedProcessRecord::capture(
            std::process::id(),
            &executable,
            &status,
            "io-token",
            7,
            1,
            100,
        )
        .unwrap();
        record.io_epoch = Some(3);
        let proof = serde_json::json!({
            "schema_version":3,"pid":record.pid,"process_start_ticks":record.process_start_ticks,
            "readiness_token":"io-token","lifecycle":"active",
            "packet_binding":{"infrastructure_generation":7,"io_epoch":3},
            "auth_deadline_unix":100,
        });
        fs::write(&status, serde_json::to_vec(&proof).unwrap()).unwrap();
        fs::set_permissions(&status, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(record.validate_identity(&executable, 101).is_err());
        record.validate_infrastructure_current(&executable).unwrap();
        record.io_epoch = Some(4);
        assert!(record.validate_infrastructure_current(&executable).is_err());
    }

    #[test]
    fn exited_managed_process_is_never_rebound_by_pid_alone() {
        let directory = tempfile::tempdir().unwrap();
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let executable = fs::read_link(format!("/proc/{}/exe", child.id())).unwrap();
        let record = ManagedProcessRecord::capture(
            child.id(),
            &executable,
            &directory.path().join("status"),
            "token",
            7,
            7,
            100,
        )
        .unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(record.validate_current(&executable, 99).is_err());
    }
}

#[cfg(test)]
mod optional_record_tests {
    use super::*;

    #[test]
    fn only_absence_is_optional_corrupt_unsafe_and_symlink_records_remain_unknown() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record.json");
        assert!(read_optional(&path).unwrap().is_none());
        fs::write(&path, b"{invalid").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = read_optional(&path).unwrap_err();
        assert!(error.to_string().contains("managed_record_unconfirmed"));
        assert!(error.chain().any(|cause| cause.is::<serde_json::Error>()));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_optional(&path).is_err());
        fs::remove_file(&path).unwrap();
        symlink(directory.path().join("missing-target"), &path).unwrap();
        assert!(
            read_optional(&path).is_err(),
            "dangling symlink is not an absent record"
        );
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(read_optional(&path).is_err());
    }
}
