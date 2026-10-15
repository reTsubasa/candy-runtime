//! Existing Runtime loop owns shared domain hosts; no second supervisor.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub desired_file: PathBuf,
    pub directory: PathBuf,
    pub core: PathBuf,
    pub max_workers: usize,
    pub max_domains_per_worker: usize,
    pub max_domain_threads: usize,
    pub max_domain_stack_bytes: usize,
    pub max_reserved_fds: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn aggregate_handoff_credits_reject_before_any_host_is_started() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let desired = directory.path().join("desired.json");
        publish(
            &desired,
            &serde_json::json!({"schema_version":1,"revision":1,"workers":1}),
        )
        .unwrap();
        for (threads, stack, fds, per_host) in [
            (23, 25_165_824, 256, 8),
            (24, 25_165_823, 256, 8),
            (24, 25_165_824, 135, 8),
            (24, 25_165_824, 256, 7),
        ] {
            let mut manager = Manager::new(Config {
                desired_file: desired.clone(),
                directory: directory.path().to_owned(),
                core: PathBuf::from("/bin/false"),
                max_workers: 4,
                max_domains_per_worker: per_host,
                max_domain_threads: threads,
                max_domain_stack_bytes: stack,
                max_reserved_fds: fds,
            })
            .unwrap();
            let plans = (0..4)
                .map(|index| directory.path().join(format!("plan-{index}.json")))
                .collect::<Vec<_>>();
            assert!(manager
                .reconcile(&plans)
                .unwrap_err()
                .to_string()
                .contains("shared_pool_budget_rejected"));
            assert!(manager.hosts.is_empty());
            assert!(!directory.path().join("worker-1.lock").exists());
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Desired {
    schema_version: u8,
    revision: u64,
    workers: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    host: crate::shared_worker::SharedWorker,
    executable_device: u64,
    executable_inode: u64,
}
struct Host {
    receipt: Receipt,
    child: Option<Child>,
}
pub(super) struct Manager {
    config: Config,
    hosts: BTreeMap<u64, Host>,
    retry: BTreeMap<u64, (Instant, u64)>,
}

fn private<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o600
            && metadata.len() <= 16 * 1024 * 1024,
        "shared pool state must be private bounded regular file"
    );
    Ok(serde_json::from_reader(file.take(16 * 1024 * 1024 + 1))?)
}
fn publish(path: &Path, value: &impl Serialize) -> Result<()> {
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    File::open(path.parent().context("pool state parent absent")?)?.sync_all()?;
    Ok(())
}
impl Manager {
    pub fn new(config: Config) -> Result<Self> {
        anyhow::ensure!(
            (1..=64).contains(&config.max_workers)
                && (1..=256).contains(&config.max_domains_per_worker),
            "shared pool budget invalid"
        );
        let metadata = fs::symlink_metadata(&config.directory)?;
        anyhow::ensure!(
            metadata.is_dir()
                && metadata.uid() == nix::unistd::geteuid().as_raw()
                && metadata.mode() & 0o777 == 0o700
                && config.core.is_absolute()
                && config.desired_file.is_absolute(),
            "shared pool directory/config invalid"
        );
        Ok(Self {
            config,
            hosts: BTreeMap::new(),
            retry: BTreeMap::new(),
        })
    }
    fn start(&mut self, id: u64) -> Result<()> {
        if self
            .hosts
            .get(&id)
            .is_some_and(|host| crate::shared_worker::probe_host(&host.receipt.host).is_ok())
        {
            return Ok(());
        }
        if let Some(host) = self.hosts.get_mut(&id) {
            let exited = match &mut host.child {
                Some(child) => child.try_wait()?.is_some(),
                None => !candy_process_control::process_is_current(host.receipt.host.identity),
            };
            anyhow::ensure!(exited, "code=shared_host_probe_pending module=runtime_agent action=preserve_live_host_retry");
        }
        self.hosts.remove(&id);
        if self
            .retry
            .get(&id)
            .is_some_and(|(until, _)| Instant::now() < *until)
        {
            anyhow::bail!("shared host restart backoff");
        }
        let path = self.config.directory.join(format!("host-{id}.json"));
        let expected = fs::metadata(&self.config.core)?;
        if let Ok(receipt) = private::<Receipt>(&path) {
            if candy_process_control::process_is_current(receipt.host.identity) {
                let actual = fs::metadata(format!("/proc/{}/exe", receipt.host.identity.pid))?;
                anyhow::ensure!(
                    (receipt.executable_device, receipt.executable_inode)
                        == (expected.dev(), expected.ino())
                        && (actual.dev(), actual.ino()) == (expected.dev(), expected.ino()),
                    "shared host executable identity differs"
                );
                crate::shared_worker::probe_host(&receipt.host)?;
                self.hosts.insert(
                    id,
                    Host {
                        receipt,
                        child: None,
                    },
                );
                return Ok(());
            }
        }
        let slot_path = self.config.directory.join(format!("worker-{id}.lock"));
        let slot = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&slot_path)?;
        anyhow::ensure!(
            unsafe { nix::libc::flock(slot.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) }
                == 0,
            "shared host slot still owned"
        );
        let socket = self.config.directory.join(format!("host-{id}.sock"));
        if socket.try_exists()? {
            fs::remove_file(&socket)?;
        }
        let fd = slot.as_raw_fd();
        let mut command = Command::new(&self.config.core);
        command
            .args(["client", "sdwan", "host", "--socket"])
            .arg(&socket)
            .arg("--worker-id")
            .arg(id.to_string())
            .arg("--worker-slot-fd")
            .arg(fd.to_string())
            .arg("--worker-slot-file")
            .arg(&slot_path)
            .arg("--max-domains")
            .arg(self.config.max_domains_per_worker.to_string());
        unsafe {
            command.pre_exec(move || {
                nix::fcntl::fcntl(
                    fd,
                    nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
                )
                .map(|_| ())
                .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
            });
        }
        let mut child = command.spawn()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let identity = candy_process_control::process_identity(child.id())?;
        let host = crate::shared_worker::SharedWorker { socket, identity };
        while crate::shared_worker::probe_host(&host).is_err() {
            if child.try_wait()?.is_some() || Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let delay = self
                    .retry
                    .get(&id)
                    .map_or(100, |(_, delay)| (*delay * 2).min(5000));
                self.retry
                    .insert(id, (Instant::now() + Duration::from_millis(delay), delay));
                anyhow::bail!("shared host bounded readiness failed");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let receipt = Receipt {
            host,
            executable_device: expected.dev(),
            executable_inode: expected.ino(),
        };
        publish(&path, &receipt)?;
        self.hosts.insert(
            id,
            Host {
                receipt,
                child: Some(child),
            },
        );
        Ok(())
    }
    pub fn reconcile(&mut self, plans: &[PathBuf]) -> Result<()> {
        let desired: Desired = private(&self.config.desired_file)?;
        anyhow::ensure!(
            desired.schema_version == 1
                && desired.revision > 0
                && (1..=self.config.max_workers).contains(&desired.workers),
            "shared pool desired budget invalid"
        );
        // Every live domain owns execution, control, and at most one blocking
        // status writer thread. Handoff reserves one old and one candidate.
        let instances = plans
            .len()
            .checked_mul(2)
            .context("shared domain thread budget overflow")?;
        let threads = instances
            .checked_mul(3)
            .context("shared domain thread budget overflow")?;
        anyhow::ensure!(threads <= self.config.max_domain_threads
            && threads.checked_mul(1_048_576).is_some_and(|bytes| bytes <= self.config.max_domain_stack_bytes)
            && instances.checked_mul(16).and_then(|fds| fds.checked_add(desired.workers * 8)).is_some_and(|fds| fds <= self.config.max_reserved_fds)
            && plans.len().div_ceil(desired.workers) * 2 <= self.config.max_domains_per_worker,
            "code=shared_pool_budget_rejected module=runtime_agent detail=declared thread stack descriptor or per-host handoff credits exceeded");
        let mut failures = Vec::new();
        for id in 1..=desired.workers as u64 {
            if let Err(error) = self.start(id) {
                failures.push(format!("worker={id} detail={error:#}"));
            }
        }
        let mut used = BTreeSet::new();
        for (index, path) in plans.iter().enumerate() {
            let mut plan: serde_json::Value = private(path)?;
            let id = (index % desired.workers + 1) as u64;
            used.insert(id);
            let Some(host) = self.hosts.get(&id).map(|host| &host.receipt.host) else {
                continue;
            };
            let mut placement = serde_json::json!({"revision":desired.revision,"target_worker_id":id,"pool_directory":self.config.directory,"shared":host});
            if plan["placement"]["target_worker_id"] != id
                || plan["placement"]["shared"] != serde_json::to_value(host)?
                || plan["placement"]["revision"].as_u64().unwrap_or(0) < desired.revision
            {
                // The pool revision remains local; signed policy and expiration are untouched.
                let previous = plan["placement"]["revision"].as_u64().unwrap_or(0);
                placement["revision"] = serde_json::json!(desired.revision.max(
                    previous
                        .checked_add(1)
                        .context("shared pool placement revision exhausted")?
                ));
                plan["placement"] = placement;
                publish(path, &plan)?;
            }
        }
        let retired = self
            .hosts
            .keys()
            .copied()
            .filter(|id| !used.contains(id) && *id > desired.workers as u64)
            .collect::<Vec<_>>();
        for id in retired {
            if crate::shared_worker::retire_host(&self.hosts[&id].receipt.host).is_ok() {
                if let Some(mut host) = self.hosts.remove(&id) {
                    if let Some(mut child) = host.child.take() {
                        let _ = child.wait();
                    }
                }
                let _ = fs::remove_file(self.config.directory.join(format!("host-{id}.json")));
            }
        }
        anyhow::ensure!(failures.is_empty(), "code=shared_pool_host_pending module=runtime_agent action=retry_preserve_healthy_domains {}", failures.join("; "));
        Ok(())
    }
    pub fn retire_empty(&mut self) -> Result<()> {
        let mut pending = 0;
        for host in self.hosts.values_mut() {
            if candy_process_control::process_is_current(host.receipt.host.identity)
                && crate::shared_worker::retire_host(&host.receipt.host).is_err()
            {
                pending += 1;
                continue;
            }
            if let Some(child) = &mut host.child {
                let _ = child.wait();
            }
        }
        anyhow::ensure!(
            pending == 0,
            "shared pool retirement pending: live domains preserved"
        );
        Ok(())
    }
}
