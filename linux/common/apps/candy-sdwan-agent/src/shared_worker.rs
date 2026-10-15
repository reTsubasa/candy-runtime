//! Domain handles separate business retirement from shared host PID lifetime.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{IoSlice, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SharedWorker {
    pub socket: PathBuf,
    pub identity: candy_process_control::ProcessIdentity,
}

pub(super) struct SharedDomain {
    pub host: SharedWorker,
    pub instance: String,
    pub control: PathBuf,
    pub token_sha256: String,
}

pub(super) enum BusinessWorker {
    Dedicated(Child),
    Shared(SharedDomain),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u8,
    pid: u32,
    instance: String,
    accepted: bool,
    running: bool,
    code: String,
    live_domains: usize,
    completed_domains: usize,
    max_domains: usize,
}

fn exchange(
    host: &SharedWorker,
    instance: &str,
    operation: &str,
    arguments: &[String],
    fds: &[i32],
) -> Result<Response> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    anyhow::ensure!(
        candy_process_control::process_is_current(host.identity),
        "code=shared_worker_identity_changed module=sdwan_host"
    );
    let mut stream = UnixStream::connect(&host.socket)?;
    anyhow::ensure!(
        candy_process_control::peer_identity(&stream)? == host.identity,
        "shared worker endpoint identity differs"
    );
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    let marker = [0_u8];
    let slices = [IoSlice::new(&marker)];
    let controls = if fds.is_empty() {
        Vec::new()
    } else {
        vec![ControlMessage::ScmRights(fds)]
    };
    anyhow::ensure!(
        sendmsg::<()>(
            stream.as_raw_fd(),
            &slices,
            &controls,
            MsgFlags::empty(),
            None
        )? == 1,
        "shared worker descriptor send incomplete"
    );
    let bytes = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"operation":operation,"instance":instance,"arguments":arguments,"namespace":fds.len()==2}),
    )?;
    anyhow::ensure!(bytes.len() <= 65536, "shared worker request exceeds budget");
    stream.write_all(&bytes)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reply = Vec::new();
    stream.take(65537).read_to_end(&mut reply)?;
    anyhow::ensure!(reply.len() <= 65536, "shared worker reply exceeds budget");
    let response: Response = serde_json::from_slice(&reply)?;
    anyhow::ensure!(
        response.live_domains + response.completed_domains <= response.max_domains,
        "shared worker accounting exceeds domain budget"
    );
    anyhow::ensure!(
        response.schema_version == 1
            && response.pid == host.identity.pid
            && response.accepted
            && response.instance == instance,
        "code=shared_domain_rejected module=sdwan_host detail={}",
        response.code
    );
    Ok(response)
}

impl SharedDomain {
    pub fn start(
        host: SharedWorker,
        control: &Path,
        token: &str,
        arguments: &[String],
        packet_fd: i32,
        namespace: Option<&OwnedFd>,
    ) -> Result<Self> {
        use sha2::{Digest, Sha256};
        let instance = control
            .to_str()
            .context("domain instance path is not UTF-8")?
            .to_owned();
        let mut fds = vec![packet_fd];
        if let Some(namespace) = namespace {
            fds.push(namespace.as_raw_fd());
        }
        let response = exchange(&host, &instance, "start", arguments, &fds)?;
        anyhow::ensure!(response.running, "shared domain did not start");
        Ok(Self {
            host,
            instance,
            control: control.to_owned(),
            token_sha256: format!("{:x}", Sha256::digest(token.as_bytes())),
        })
    }
    pub fn running(&self) -> Result<bool> {
        if !candy_process_control::process_is_current(self.host.identity) {
            return Ok(false);
        }
        Ok(exchange(&self.host, &self.instance, "probe", &[], &[])?.running)
    }
    pub fn stop(&self) -> Result<()> {
        if !self.running()? {
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let request = candy_process_control::ControlRequest {
            schema_version: 1,
            operation: candy_process_control::ControlOperation::Stop,
            token_sha256: self.token_sha256.clone(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
        };
        if let Err(error) =
            candy_process_control::exchange(&self.control, self.host.identity, &request)
        {
            // A failed per-domain endpoint must not force a host signal. The
            // authenticated owning Runtime cancels only this domain runtime.
            exchange(&self.host, &self.instance, "cancel", &[], &[])
                .with_context(|| format!("domain authenticated stop failed: {error:#}"))?;
        }
        while self.running()? && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        anyhow::ensure!(
            !self.running()?,
            "code=shared_domain_stop_pending module=sdwan_host action=preserve_other_domains_retry"
        );
        exchange(&self.host, &self.instance, "forget", &[], &[])?;
        Ok(())
    }
}

impl BusinessWorker {
    pub fn id(&self) -> u32 {
        match self {
            Self::Dedicated(child) => child.id(),
            Self::Shared(domain) => domain.host.identity.pid,
        }
    }
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        match self {
            Self::Dedicated(child) => child.try_wait(),
            Self::Shared(domain) => domain
                .running()
                .map(|running| (!running).then(|| ExitStatus::from_raw(0)))
                .map_err(std::io::Error::other),
        }
    }
    pub fn kill(&mut self) -> std::io::Result<()> {
        match self {
            Self::Dedicated(child) => child.kill(),
            Self::Shared(domain) => domain.stop().map_err(std::io::Error::other),
        }
    }
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match self {
            Self::Dedicated(child) => child.wait(),
            Self::Shared(domain) => {
                if domain.running().map_err(std::io::Error::other)? {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "shared domain is still running",
                    ));
                }
                Ok(ExitStatus::from_raw(0))
            }
        }
    }
}

pub(super) fn domain_running(host: &SharedWorker, instance: &Path) -> Result<bool> {
    if !candy_process_control::process_is_current(host.identity) {
        return Ok(false);
    }
    Ok(exchange(
        host,
        instance
            .to_str()
            .context("domain instance path is not UTF-8")?,
        "probe",
        &[],
        &[],
    )?
    .running)
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
pub(super) fn forget_domain(host: &SharedWorker, instance: &Path) -> Result<()> {
    exchange(
        host,
        instance
            .to_str()
            .context("domain instance path is not UTF-8")?,
        "forget",
        &[],
        &[],
    )?;
    Ok(())
}

pub(super) fn retire_host(host: &SharedWorker) -> Result<()> {
    exchange(host, "", "retire", &[], &[])?;
    Ok(())
}

pub(super) fn probe_host(host: &SharedWorker) -> Result<()> {
    exchange(host, "", "probe", &[], &[])?;
    Ok(())
}
