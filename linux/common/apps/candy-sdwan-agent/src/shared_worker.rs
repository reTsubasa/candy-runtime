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
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    detail: Option<String>,
}

fn terminal_status(response: Response) -> Option<ExitStatus> {
    if response.running {
        return None;
    }
    // Old hosts omit exit status. An unknown completion is never success.
    let code = response.exit_code.unwrap_or(1);
    if code != 0 {
        eprintln!("level=error code={} module=sdwan_host instance={} exit_code={} detail={} action=preserve_other_domains_recover_failed_domain",
            response.code, response.instance, code, response.detail.as_deref().unwrap_or("domain completion status unavailable"));
    }
    Some(ExitStatus::from_raw(code << 8))
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
        candy_process_control::process_is_current_confirmed(host.identity)?,
        "code=shared_worker_identity_changed module=sdwan_host"
    );
    let mut stream =
        UnixStream::connect(&host.socket).context("connect shared worker control endpoint")?;
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
    stream
        .write_all(&bytes)
        .context("write bounded shared worker request")?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .context("finish shared worker request")?;
    let mut reply = Vec::new();
    stream
        .take(65537)
        .read_to_end(&mut reply)
        .context("read bounded shared worker response")?;
    anyhow::ensure!(reply.len() <= 65536, "shared worker reply exceeds budget");
    let response: Response = serde_json::from_slice(&reply)?;
    anyhow::ensure!(
        response.live_domains + response.completed_domains <= response.max_domains,
        "shared worker accounting exceeds domain budget"
    );
    anyhow::ensure!(
        response
            .exit_code
            .is_none_or(|code| (0..=255).contains(&code)),
        "shared worker exit status is invalid"
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
        if !candy_process_control::process_is_current_confirmed(self.host.identity)? {
            return Ok(false);
        }
        Ok(exchange(&self.host, &self.instance, "probe", &[], &[])?.running)
    }
    pub fn stop(&self) -> Result<()> {
        if !self.running()? {
            if candy_process_control::process_is_current_confirmed(self.host.identity)? {
                exchange(&self.host, &self.instance, "forget", &[], &[])?;
            }
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
    // Keep control errors typed so transient IPC failures remain retryable.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        match self {
            Self::Dedicated(child) => Ok(child.try_wait()?),
            Self::Shared(domain) => domain.completion(),
        }
    }
    pub fn kill(&mut self) -> Result<()> {
        match self {
            Self::Dedicated(child) => Ok(child.kill()?),
            Self::Shared(domain) => domain.stop(),
        }
    }
    pub fn wait(&mut self) -> Result<ExitStatus> {
        match self {
            Self::Dedicated(child) => Ok(child.wait()?),
            Self::Shared(domain) => domain.completion()?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "shared domain is still running",
                )
                .into()
            }),
        }
    }
}

impl SharedDomain {
    fn completion(&self) -> Result<Option<ExitStatus>> {
        if !candy_process_control::process_is_current_confirmed(self.host.identity)? {
            eprintln!("level=error code=shared_host_exited module=sdwan_host instance={} pid={} action=recover_affected_domains_preserve_infrastructure", self.instance, self.host.identity.pid);
            return Ok(Some(ExitStatus::from_raw(1 << 8)));
        }
        Ok(terminal_status(exchange(
            &self.host,
            &self.instance,
            "probe",
            &[],
            &[],
        )?))
    }
}

pub(super) fn domain_running(host: &SharedWorker, instance: &Path) -> Result<bool> {
    if !candy_process_control::process_is_current_confirmed(host.identity)? {
        return Ok(false);
    }
    match exchange(
        host,
        instance
            .to_str()
            .context("domain instance path is not UTF-8")?,
        "probe",
        &[],
        &[],
    ) {
        Ok(response) => Ok(response.running),
        Err(_) if !candy_process_control::process_is_current_confirmed(host.identity)? => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
pub(super) fn forget_domain(host: &SharedWorker, instance: &Path) -> Result<()> {
    match exchange(
        host,
        instance
            .to_str()
            .context("domain instance path is not UTF-8")?,
        "forget",
        &[],
        &[],
    ) {
        Ok(_) => Ok(()),
        // A confirmed exited host cannot retain a business domain or its
        // completion receipt. Recheck after exchange to cover a concurrent exit.
        Err(_) if !candy_process_control::process_is_current_confirmed(host.identity)? => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn retire_host(host: &SharedWorker) -> Result<()> {
    exchange(host, "", "retire", &[], &[])?;
    Ok(())
}

pub(super) fn probe_host(host: &SharedWorker) -> Result<()> {
    exchange(host, "", "probe", &[], &[])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(running: bool, exit_code: Option<i32>) -> Response {
        Response {
            schema_version: 1,
            pid: 1,
            instance: "domain".into(),
            accepted: true,
            running,
            code: "domain_stopped".into(),
            live_domains: usize::from(running),
            completed_domains: usize::from(!running),
            max_domains: 1,
            exit_code,
            detail: None,
        }
    }

    #[test]
    fn failed_or_unknown_domain_completion_cannot_be_reported_as_success() {
        assert!(terminal_status(response(true, None)).is_none());
        assert!(terminal_status(response(false, Some(0))).unwrap().success());
        assert_eq!(
            terminal_status(response(false, Some(1))).unwrap().code(),
            Some(1)
        );
        assert!(!terminal_status(response(false, None)).unwrap().success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_completion_timeout_preserves_retryable_io_cause() {
        use std::os::unix::net::UnixListener;

        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("host.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            connection.read_to_end(&mut request).unwrap();
            std::thread::sleep(Duration::from_millis(1200));
        });
        let mut worker = BusinessWorker::Shared(SharedDomain {
            host: SharedWorker {
                socket,
                identity: candy_process_control::process_identity(std::process::id()).unwrap(),
            },
            instance: "domain".into(),
            control: root.path().join("domain.sock"),
            token_sha256: "unused".into(),
        });
        let error = worker.try_wait().unwrap_err();
        assert!(matches!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        assert!(crate::runtime_agent::transient_error(&error));
        server.join().unwrap();
    }

    #[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
    #[test]
    fn domain_cleanup_requires_confirmed_host_exit_or_successful_exchange() {
        let root = tempfile::tempdir().unwrap();
        let mut host = SharedWorker {
            socket: root.path().join("missing-host.sock"),
            identity: candy_process_control::process_identity(std::process::id()).unwrap(),
        };
        let instance = root.path().join("domain.sock");
        assert!(domain_running(&host, &instance).is_err());
        assert!(forget_domain(&host, &instance).is_err());

        host.identity.start_ticks += 1;
        assert!(!domain_running(&host, &instance).unwrap());
        forget_domain(&host, &instance).unwrap();
    }
}
