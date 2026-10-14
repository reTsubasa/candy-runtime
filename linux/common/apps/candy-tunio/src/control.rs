use anyhow::{bail, Context, Result};
use candy_process_control::{
    peer_identity, process_identity, process_is_current, read_message, write_message,
    ControlOperation, ControlRequest, ControlResponse, ProcessIdentity,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::sync::watch;

pub(crate) struct Controller {
    pub(crate) process: ProcessIdentity,
    pub(crate) controller: ProcessIdentity,
    pub(crate) epoch: u64,
    pub(crate) token: String,
    pub(crate) status: PathBuf,
    pub(crate) generation: u64,
    pub(crate) auth_deadline_unix: u64,
    pub(crate) binding: candy_packet_port::packet_port_ipc::PacketPortBinding,
    pub(crate) owner_active: bool,
    pub(crate) registered: bool,
    pub(crate) registration: Option<watch::Sender<bool>>,
    pub(crate) authority: crate::authority_control::AuthorityState,
}

impl Controller {
    pub(crate) fn publish(&self) -> Result<()> {
        let bytes = serde_json::to_vec(
            &json!({"schema_version":3,"pid":self.process.pid,"generation":self.generation,"infrastructure_generation":self.binding.infrastructure_generation,"policy_generation":self.binding.policy_generation,"readiness_token":self.token,"lifecycle":if self.registered {"active"} else {"starting"},"process_start_ticks":self.process.start_ticks,"controller":self.controller,"controller_epoch":self.epoch,"auth_deadline_unix":self.auth_deadline_unix,"packet_binding":self.binding,"owner_active":self.owner_active,"authority":self.authority}),
        )?;
        let temporary = self
            .status
            .with_extension(format!("{}.tmp", self.process.pid));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.status)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    fn request(
        &mut self,
        peer: ProcessIdentity,
        request: &ControlRequest,
    ) -> (ControlResponse, bool) {
        let authorized = request.schema_version == 1
            && request.token_sha256 == format!("{:x}", Sha256::digest(self.token.as_bytes()))
            && request.nonce.len() == 32
            && request.nonce.bytes().all(|byte| byte.is_ascii_hexdigit());
        let mut accepted = false;
        let mut stop = false;
        let mut code = "control_capability_invalid";
        if authorized {
            match request.operation {
                ControlOperation::Probe => {
                    accepted = true;
                    code = "process_probed";
                    if peer == self.controller && process_is_current(peer) {
                        if let Some(registration) = &self.registration {
                            registration.send_replace(true);
                        }
                    }
                }
                ControlOperation::Takeover if !self.registered => {
                    code = "registration_incomplete";
                }
                ControlOperation::Takeover if peer == self.controller => {
                    accepted = true;
                    code = "controller_current";
                }
                ControlOperation::Takeover if process_is_current(self.controller) => {
                    code = "previous_controller_alive";
                }
                ControlOperation::Takeover => {
                    let old = self.controller;
                    let old_epoch = self.epoch;
                    if let Some(epoch) = self.epoch.checked_add(1) {
                        self.controller = peer;
                        self.epoch = epoch;
                        if self.publish().is_ok() {
                            accepted = true;
                            code = "controller_adopted";
                        } else {
                            self.controller = old;
                            self.epoch = old_epoch;
                            code = "controller_record_unavailable";
                        }
                    } else {
                        code = "controller_epoch_exhausted";
                    }
                }
                ControlOperation::Stop if peer == self.controller => {
                    accepted = true;
                    stop = true;
                    code = "controller_stop";
                }
                ControlOperation::Stop => {
                    code = "controller_identity_mismatch";
                }
            }
        }
        (
            ControlResponse {
                schema_version: 1,
                process: self.process,
                controller: self.controller,
                controller_epoch: self.epoch,
                nonce: request.nonce.clone(),
                accepted,
                code: code.into(),
            },
            stop,
        )
    }
}

fn publish_bridge_snapshot(
    status: &Path,
    process: ProcessIdentity,
    outputs: &candy_packet_port::packet_port_manager::PacketBridgeOutputStatus,
) -> Result<()> {
    let mut monotonic = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &mut monotonic) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read snapshot monotonic clock");
    }
    let report_monotonic_millis = (monotonic.tv_sec.max(0) as u64)
        .saturating_mul(1_000)
        .saturating_add(monotonic.tv_nsec.max(0) as u64 / 1_000_000);
    let bytes = serde_json::to_vec(&json!({
        "schema_version": 1,
        "pid": process.pid,
        "process_start_ticks": process.start_ticks,
        "report_monotonic_millis": report_monotonic_millis,
        "bridge_outputs": outputs,
    }))?;
    if bytes.len() > 16 * 1024 {
        bail!("bridge snapshot exceeds bounded status size");
    }
    let temporary = status.with_extension(format!("{}.tmp", process.pid));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(&bytes)?;
        // Diagnostic snapshots are volatile, independent of durable authority records.
        fs::rename(&temporary, status)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub struct ControlRegistration {
    state: Arc<Mutex<Controller>>,
    registered: watch::Receiver<bool>,
}

/// Run on the original startup thread: Linux parent-death signals are thread
/// local, so a detached control thread cannot clear this registration guard.
pub fn install_startup_guard() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let parent = unsafe { nix::libc::getppid() };
        if parent <= 1
            || unsafe { nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL) } != 0
        {
            bail!("could not install TUNIO parent registration guard");
        }
        if unsafe { nix::libc::getppid() } != parent {
            bail!("parent changed while installing registration guard");
        }
    }
    Ok(())
}

impl ControlRegistration {
    /// Publish low-frequency queue diagnostics outside the packet executor.
    pub fn observe_bridge(
        &self,
        outputs: watch::Receiver<candy_packet_port::packet_port_manager::PacketBridgeOutputStatus>,
        shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let (status, process) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("controller state poisoned"))?;
            (state.status.with_extension("outputs.json"), state.process)
        };
        thread::spawn(move || {
            while !*shutdown.borrow() {
                thread::sleep(Duration::from_secs(1));
                if *shutdown.borrow() {
                    break;
                }
                let snapshot = outputs.borrow().clone();
                let result = publish_bridge_snapshot(&status, process, &snapshot);
                if let Err(error) = result {
                    eprintln!("level=warn code=bridge_status_publish_failed module=tunio_control detail={error:#} action=keep_packet_service");
                }
            }
        });
        Ok(())
    }

    pub async fn wait(mut self) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if *self.registered.borrow() {
                    break;
                }
                self.registered
                    .changed()
                    .await
                    .context("registration publisher closed")?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("TUNIO durable registration not confirmed within startup deadline")??;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("controller state poisoned"))?;
        if !process_is_current(state.controller) {
            bail!("controller exited before registration completed");
        }
        #[cfg(target_os = "linux")]
        {
            if unsafe { nix::libc::getppid() } != state.controller.pid as i32
                || unsafe { nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, 0) } != 0
            {
                bail!("registration requires same living startup parent");
            }
            if !process_is_current(state.controller) {
                bail!("controller exited while registration guard cleared");
            }
        }
        state.registered = true;
        state.registration = None;
        state.publish()
    }
}

pub(crate) fn private_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("control/status paths must be absolute");
    }
    let metadata = fs::symlink_metadata(path.parent().context("missing control directory")?)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        bail!("control/status parent must be current-user 0700 real directory");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn start(
    socket: PathBuf,
    status: PathBuf,
    token: String,
    generation: u64,
    auth_deadline_unix: u64,
    stop: watch::Sender<bool>,
    binding: candy_packet_port::packet_port_ipc::PacketPortBinding,
    updates: tokio::sync::mpsc::Sender<
        candy_packet_port::packet_port_manager::PacketPortOwnerUpdate,
    >,
    auth_deadline: tokio::time::Instant,
) -> Result<ControlRegistration> {
    private_parent(&socket)?;
    private_parent(&status)?;
    if token.len() < 32 {
        bail!("supervision capability must have at least 128 bits of entropy");
    }
    let process = process_identity(std::process::id())?;
    let controller = process_identity(unsafe { nix::libc::getppid() } as u32)?;
    let (registration, registered) = watch::channel(false);
    let state = Controller {
        process,
        controller,
        epoch: 1,
        token,
        status,
        generation,
        auth_deadline_unix,
        binding,
        owner_active: true,
        registered: false,
        registration: Some(registration),
        authority: crate::authority_control::AuthorityState::default(),
    };
    let listener = UnixListener::bind(&socket).with_context(|| {
        format!("code=control_bind_failed module=tunio_control path={} detail=bind supervision endpoint", socket.display())
    })?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    state.publish()?;
    let state = Arc::new(Mutex::new(state));
    crate::attach_control::start(
        socket.clone(),
        Arc::clone(&state),
        updates.clone(),
        stop.clone(),
        auth_deadline,
    )?;
    crate::authority_control::start(
        socket.clone(),
        Arc::clone(&state),
        updates,
        stop.clone(),
        auth_deadline,
    )?;
    let serving_state = Arc::clone(&state);
    thread::spawn(move || {
        let shutdown = stop.subscribe();
        while !*shutdown.borrow() {
            match listener.accept() {
                Ok((stream, _)) => {
                    let result = (|| -> Result<bool> {
                        let peer = peer_identity(&stream)?;
                        let request: ControlRequest = read_message(&stream)?;
                        let (reply, stopping) = serving_state
                            .lock()
                            .map_err(|_| anyhow::anyhow!("controller state poisoned"))?
                            .request(peer, &request);
                        write_message(&stream, &reply)?;
                        Ok(stopping)
                    })();
                    match result {Ok(true)=>{let _=stop.send(true);break;},Ok(false)=>(),Err(error)=>eprintln!("level=warn code=supervision_request_rejected module=tunio_control detail={error:#}"),}
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(error) => {
                    eprintln!("level=error code=supervision_accept_failed module=tunio_control detail={error}");
                    thread::sleep(Duration::from_millis(250));
                }
            }
        }
        let _ = fs::remove_file(socket);
    });
    Ok(ControlRegistration { state, registered })
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn bridge_sidecar_is_private_atomic_bounded_and_has_process_identity() {
        let directory = tempfile::tempdir().unwrap();
        let status = directory.path().join("tunio-status.outputs.json");
        let process = ProcessIdentity {
            pid: std::process::id(),
            start_ticks: 123,
        };
        let mut snapshot =
            candy_packet_port::packet_port_manager::PacketBridgeOutputStatus::default();
        snapshot.to_tun.sent_packets = 42;
        publish_bridge_snapshot(&status, process, &snapshot).unwrap();
        snapshot.to_tun.sent_packets = 43;
        publish_bridge_snapshot(&status, process, &snapshot).unwrap();
        let bytes = fs::read(&status).unwrap();
        assert!(bytes.len() < 16 * 1024);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["pid"], process.pid);
        assert_eq!(value["process_start_ticks"], process.start_ticks);
        assert!(value["report_monotonic_millis"].as_u64().unwrap() > 0);
        assert_eq!(value["bridge_outputs"]["to_tun"]["sent_packets"], 43);
        assert!(value.get("readiness_token").is_none());
        assert_eq!(
            fs::metadata(&status).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
