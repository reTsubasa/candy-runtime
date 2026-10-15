use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub const MAX_CONTROL_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
}

pub fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    #[cfg(target_os = "linux")]
    {
        if pid == 0 || pid > i32::MAX as u32 {
            bail!("invalid process PID");
        }
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        parse_optional_process_identity(pid, Ok(stat))?.context("process exited")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        bail!("process ownership requires Linux procfs");
    }
}

pub fn process_is_current(identity: ProcessIdentity) -> bool {
    process_identity(identity.pid).is_ok_and(|actual| actual == identity)
}

#[derive(Debug)]
pub struct ProcessLivenessUnconfirmed {
    pub identity: ProcessIdentity,
}

impl std::fmt::Display for ProcessLivenessUnconfirmed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter,
            "code=process_liveness_unconfirmed module=process_control pid={} start_ticks={} action=preserve_owner_and_retry",
            self.identity.pid, self.identity.start_ticks)
    }
}

impl std::error::Error for ProcessLivenessUnconfirmed {}

/// Recovery may retire ownership only with proof of exit or a changed epoch.
/// Permission, IO and malformed procfs errors leave ownership unknown.
pub fn process_is_current_confirmed(identity: ProcessIdentity) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let result = parse_optional_process_identity(
            identity.pid,
            fs::read_to_string(format!("/proc/{}/stat", identity.pid)),
        );
        result
            .map(|actual| actual == Some(identity))
            .context(ProcessLivenessUnconfirmed { identity })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = identity;
        bail!("process ownership requires Linux procfs");
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_optional_process_identity(
    pid: u32,
    stat: std::io::Result<String>,
) -> Result<Option<ProcessIdentity>> {
    anyhow::ensure!(pid > 0 && pid <= i32::MAX as u32, "invalid process PID");
    let stat = match stat {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let fields = stat
        .rsplit_once(')')
        .context("invalid process stat")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let state = *fields.first().context("missing process state")?;
    let start_ticks = fields.get(19).context("missing process epoch")?.parse()?;
    if matches!(state, "Z" | "X" | "x") {
        return Ok(None);
    }
    Ok(Some(ProcessIdentity { pid, start_ticks }))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlOperation {
    Probe,
    Takeover,
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub schema_version: u8,
    pub operation: ControlOperation,
    pub token_sha256: String,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResponse {
    pub schema_version: u8,
    pub process: ProcessIdentity,
    pub controller: ProcessIdentity,
    pub controller_epoch: u64,
    pub nonce: String,
    pub accepted: bool,
    pub code: String,
}

pub fn peer_identity(stream: &UnixStream) -> Result<ProcessIdentity> {
    #[cfg(target_os = "linux")]
    {
        let peer =
            nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)?;
        if peer.uid() != nix::unistd::geteuid().as_raw() {
            bail!("control peer UID differs from Runtime");
        }
        process_identity(peer.pid() as u32)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        bail!("authenticated control requires Linux socket credentials");
    }
}

pub fn read_message<T: serde::de::DeserializeOwned>(stream: &UnixStream) -> Result<T> {
    let deadline = Instant::now() + Duration::from_millis(500);
    stream.set_nonblocking(false)?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut input = stream;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .context("process-control read deadline exceeded")?;
        stream.set_read_timeout(Some(remaining))?;
        match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if count > (MAX_CONTROL_BYTES as usize).saturating_sub(bytes.len()) {
                    bail!("invalid bounded process-control message");
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("read bounded process-control message"),
        }
    }
    if bytes.is_empty() || bytes.len() as u64 > MAX_CONTROL_BYTES {
        bail!("invalid bounded process-control message");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn write_message<T: Serialize>(mut stream: &UnixStream, message: &T) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(500);
    stream.set_nonblocking(false)?;
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() as u64 > MAX_CONTROL_BYTES {
        bail!("process-control response too large");
    }
    let mut remaining_bytes = bytes.as_slice();
    while !remaining_bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .context("process-control write deadline exceeded")?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(remaining_bytes) {
            Ok(0) => bail!("process-control output closed"),
            Ok(count) => remaining_bytes = &remaining_bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("write bounded process-control message"),
        }
    }
    stream.shutdown(Shutdown::Write)?;
    Ok(())
}

pub fn exchange(
    path: &Path,
    expected_process: ProcessIdentity,
    request: &ControlRequest,
) -> Result<ControlResponse> {
    validate_endpoint(path)?;
    let stream = connect_bounded(path)?;
    if peer_identity(&stream)? != expected_process {
        bail!("control peer PID or epoch differs from managed process");
    }
    write_message(&stream, request)?;
    let reply: ControlResponse = read_message(&stream)?;
    if reply.schema_version != 1
        || reply.process != expected_process
        || reply.nonce != request.nonce
    {
        bail!("control challenge response identity mismatch");
    }
    if !reply.accepted {
        bail!(
            "code={} module=process_control detail=controller request rejected",
            reply.code
        );
    }
    Ok(reply)
}

/// Inspect the kernel-authenticated endpoint owner when a durable record is
/// unavailable. This identifies a live process; it does not grant adoption.
pub fn inspect_endpoint_process(path: &Path) -> Result<ProcessIdentity> {
    validate_endpoint(path)?;
    let stream = connect_bounded(path)?;
    peer_identity(&stream)
}

fn validate_endpoint(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type())
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        bail!("control endpoint must be a current-user 0600 Unix socket");
    }
    Ok(())
}

fn connect_bounded(path: &Path) -> Result<UnixStream> {
    use nix::sys::socket::{
        connect, getsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
    };
    use std::os::fd::AsRawFd;
    let descriptor = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
    fcntl(
        descriptor.as_raw_fd(),
        FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC),
    )?;
    fcntl(descriptor.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    match connect(descriptor.as_raw_fd(), &UnixAddr::new(path)?) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINPROGRESS) => {
            let deadline = Instant::now() + Duration::from_millis(500);
            loop {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .context("process-control connect deadline exceeded")?;
                let mut poll = nix::libc::pollfd {
                    fd: descriptor.as_raw_fd(),
                    events: nix::libc::POLLOUT,
                    revents: 0,
                };
                let result =
                    unsafe { nix::libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) };
                if result == 0 {
                    bail!("process-control connect deadline exceeded");
                }
                if result < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error).context("poll process-control connect");
                }
                let error = getsockopt(&descriptor, sockopt::SocketError)?;
                if error != 0 {
                    return Err(std::io::Error::from_raw_os_error(error))
                        .context("connect process-control endpoint");
                }
                break;
            }
        }
        Err(error) => return Err(error).context("connect process-control endpoint"),
    }
    Ok(UnixStream::from(descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liveness_unknown_is_distinct_from_exit_and_epoch_change() {
        use std::io::{Error, ErrorKind};
        let stat = |state| {
            let mut fields = vec!["0"; 20];
            fields[0] = state;
            fields[19] = "1234";
            Ok(format!("42 (worker (name)) {}", fields.join(" ")))
        };
        assert_eq!(
            parse_optional_process_identity(42, stat("S")).unwrap(),
            Some(ProcessIdentity {
                pid: 42,
                start_ticks: 1234
            })
        );
        for state in ["Z", "X", "x"] {
            assert_eq!(
                parse_optional_process_identity(42, stat(state)).unwrap(),
                None
            );
        }
        assert_eq!(
            parse_optional_process_identity(42, Err(Error::from(ErrorKind::NotFound))).unwrap(),
            None
        );
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::Interrupted,
            ErrorKind::InvalidData,
        ] {
            let error = parse_optional_process_identity(42, Err(Error::from(kind))).unwrap_err();
            assert_eq!(error.downcast_ref::<Error>().unwrap().kind(), kind);
        }
        for malformed in ["", "42 (worker)", "42 (worker) S", "42 worker S 0"] {
            assert!(parse_optional_process_identity(42, Ok(malformed.into())).is_err());
        }
        assert!(parse_optional_process_identity(0, stat("S")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn confirmed_liveness_checks_real_process_epoch_and_reaped_child() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = process_identity(child.id()).unwrap();
        assert!(process_is_current_confirmed(identity).unwrap());
        assert!(!process_is_current_confirmed(ProcessIdentity {
            start_ticks: identity.start_ticks + 1,
            ..identity
        })
        .unwrap());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!process_is_current_confirmed(identity).unwrap());
    }

    #[test]
    fn trickled_control_request_cannot_extend_total_read_deadline() {
        let (receiver, mut sender) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            for _ in 0..10 {
                if sender.write_all(b" ").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        assert!(read_message::<ControlRequest>(&receiver).is_err());
        assert!(started.elapsed() < Duration::from_millis(900));
        drop(receiver);
        writer.join().unwrap();
    }

    #[test]
    fn malformed_request_does_not_poison_the_next_control_stream() {
        let (receiver, mut sender) = UnixStream::pair().unwrap();
        sender
            .write_all(&vec![b'x'; MAX_CONTROL_BYTES as usize + 1])
            .unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        assert!(read_message::<ControlRequest>(&receiver).is_err());
        let (receiver, sender) = UnixStream::pair().unwrap();
        let request = ControlRequest {
            schema_version: 1,
            operation: ControlOperation::Probe,
            token_sha256: "token".into(),
            nonce: "11".repeat(16),
        };
        write_message(&sender, &request).unwrap();
        assert_eq!(
            read_message::<ControlRequest>(&receiver).unwrap().nonce,
            request.nonce
        );
    }
}
