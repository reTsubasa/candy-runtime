use anyhow::{bail, Context, Result};
use std::io::{ErrorKind, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct ProbeUnavailable {
    code: &'static str,
    detail: String,
}
impl std::fmt::Display for ProbeUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "code={} module=cloud_sync detail={}",
            self.code, self.detail
        )
    }
}
impl std::error::Error for ProbeUnavailable {}

struct OwnedProbe {
    child: Child,
    completed: bool,
}

impl Drop for OwnedProbe {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        // The leader remains unreaped until both output pipes close. On a
        // failed probe this also terminates descendants holding a pipe open.
        unsafe {
            nix::libc::kill(-(self.child.id() as i32), nix::libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let flags = fcntl(pipe.as_raw_fd(), FcntlArg::F_GETFL)?;
    fcntl(
        pipe.as_raw_fd(),
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
    )?;
    Ok(())
}

fn drain(pipe: &mut impl Read, bytes: &mut Vec<u8>, limit: usize) -> Result<bool> {
    let mut buffer = [0_u8; 8192];
    for _ in 0..32 {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if count > limit.saturating_sub(bytes.len()) {
                    return Err(ProbeUnavailable {
                        code: "core_probe_output_exceeded",
                        detail: format!("probe output exceeds {limit} bytes"),
                    }
                    .into());
                }
                if bytes.capacity() < bytes.len() + count {
                    let capacity = bytes
                        .capacity()
                        .saturating_mul(2)
                        .max(bytes.len() + count)
                        .min(limit);
                    bytes.try_reserve_exact(capacity - bytes.len())?;
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("read probe output"),
        }
    }
    Ok(false)
}

#[cfg(test)]
pub(super) fn output(
    command: &mut Command,
    stdout_limit: usize,
    timeout: Duration,
) -> Result<Output> {
    output_controlled(command, stdout_limit, timeout, None)
}

pub(super) fn output_controlled(
    command: &mut Command,
    stdout_limit: usize,
    timeout: Duration,
    control: Option<&super::SyncControl>,
) -> Result<Output> {
    super::checkpoint(control)?;
    if stdout_limit == 0 || timeout.is_zero() {
        bail!(
            "code=core_probe_limits_invalid module=cloud_sync detail=probe budget must be nonzero"
        );
    }
    let timeout = if let Some(control) = control {
        timeout.min(control.remaining()?)
    } else {
        timeout
    };
    let deadline = Instant::now() + timeout;
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .context("start bounded Core probe")?;
    let mut probe = OwnedProbe {
        child,
        completed: false,
    };
    let child = &mut probe.child;
    let mut stdout = child.stdout.take().context("missing probe stdout")?;
    let mut stderr = child.stderr.take().context("missing probe stderr")?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut stdout_closed = false;
    let mut stderr_closed = false;
    loop {
        super::checkpoint(control)?;
        if Instant::now() >= deadline {
            return Err(ProbeUnavailable {
                code: "core_probe_timeout",
                detail: format!("probe exceeded {} ms", timeout.as_millis()),
            }
            .into());
        }
        if !stdout_closed {
            stdout_closed = drain(&mut stdout, &mut out, stdout_limit)?;
        }
        if !stderr_closed {
            stderr_closed = drain(&mut stderr, &mut err, 64 * 1024)?;
        }
        // Reap only after all pipe writers have finished, keeping process group
        // identity stable for timeout cleanup if a descendant stalls.
        if stdout_closed && stderr_closed {
            if let Some(status) = child.try_wait()? {
                probe.completed = true;
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_drains_both_pipes_before_waiting_for_exit() {
        let result = output(
            Command::new("sh").args(["-c", "head -c 65536 /dev/zero; head -c 32768 /dev/zero >&2"]),
            65536,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout.len(), 65536);
        assert_eq!(result.stderr.len(), 32768);
    }

    #[test]
    fn probe_output_overflow_is_bounded_and_the_next_probe_works() {
        let error = output(
            Command::new("sh").args(["-c", "head -c 1048576 /dev/zero"]),
            1024,
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("core_probe_output_exceeded"));
        let next = output(
            Command::new("sh").args(["-c", "printf ok"]),
            1024,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(next.stdout, b"ok");
    }

    #[test]
    fn probe_deadline_cleans_up_descendant_held_pipes() {
        let directory = tempfile::tempdir().unwrap();
        let late = directory.path().join("late");
        let started = Instant::now();
        let error = output(
            Command::new("sh")
                .args(["-c", "(sleep 0.3; touch \"$1\") & exit 0", "probe"])
                .arg(&late),
            1024,
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("core_probe_timeout"));
        assert!(started.elapsed() < Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(400));
        assert!(!late.exists());
    }

    #[test]
    fn supervisor_cancel_stops_a_running_probe_and_preserves_retry_classification() {
        let control = super::super::SyncControl::new(Duration::from_secs(2)).unwrap();
        let cancel = control.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            cancel.cancel();
        });
        let error = output_controlled(
            Command::new("sh").args(["-c", "sleep 2"]),
            1024,
            Duration::from_secs(2),
            Some(&control),
        )
        .unwrap_err();
        canceller.join().unwrap();
        assert!(super::super::local_operation_unavailable(&error));
        assert!(format!("{error:#}").contains("cloud_sync_cancelled"));
    }
}
