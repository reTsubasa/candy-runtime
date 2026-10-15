//! Opt-in executor timing. The packet path never waits for diagnostic output.
use std::{
    fs::OpenOptions,
    future::Future,
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, OnceLock,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

const ENVIRONMENT: &str = "CANDY_PACKET_EXECUTOR_DIAGNOSTICS";
const QUEUE_SIZE: usize = 1024;
const SLOW_POLL: Duration = Duration::from_millis(5);
const HEARTBEAT_PERIOD: Duration = Duration::from_millis(10);

#[derive(Clone)]
pub struct Diagnostics(Arc<Recorder>);

struct Recorder {
    sender: mpsc::SyncSender<Event>,
    lost: Arc<AtomicU64>,
}

#[derive(Debug)]
struct Event {
    kind: &'static str,
    label: &'static str,
    monotonic_ns: u64,
    thread_id: u64,
    wall_ns: u64,
    thread_cpu_ns: Option<u64>,
    ready: bool,
}

#[derive(serde::Serialize)]
struct ExportEvent<'a> {
    kind: &'static str,
    label: &'a str,
    pid: u32,
    tid: u64,
    monotonic_ns: u64,
    wall_ns: u64,
    thread_cpu_ns: Option<u64>,
    cpu_scope: &'static str,
    ready: bool,
    lost_events: u64,
}

impl Event {
    fn for_export(&self, lost_events: u64) -> ExportEvent<'_> {
        ExportEvent {
            kind: self.kind,
            label: self.label,
            pid: std::process::id(),
            tid: self.thread_id,
            monotonic_ns: self.monotonic_ns,
            wall_ns: self.wall_ns,
            thread_cpu_ns: self.thread_cpu_ns,
            cpu_scope: match self.kind {
                "heartbeat" => "thread_interval",
                "sync" => "operation",
                _ => "poll",
            },
            ready: self.ready,
            lost_events,
        }
    }
}

static CONFIGURATION: OnceLock<Result<Option<Diagnostics>, String>> = OnceLock::new();

impl Diagnostics {
    /// Read once at process initialization. Existing evidence is never replaced.
    pub fn from_environment() -> io::Result<Option<Self>> {
        match CONFIGURATION.get_or_init(|| {
            let Some(path) = std::env::var_os(ENVIRONMENT) else {
                return Ok(None);
            };
            Self::open_directory(Path::new(&path))
                .map(Some)
                .map_err(|error| error.to_string())
        }) {
            Ok(value) => Ok(value.clone()),
            Err(error) => Err(io::Error::new(io::ErrorKind::InvalidInput, error.clone())),
        }
    }

    fn open_directory(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "executor diagnostic directory must be absolute",
            ));
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let executable = std::env::current_exe()
            .ok()
            .and_then(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "process".into());
        let executable: String = executable
            .chars()
            .filter(|value| value.is_ascii_alphanumeric() || *value == '-')
            .take(48)
            .collect();
        let name = std::ffi::CString::new(format!(
            "{executable}-{}-{}.jsonl",
            std::process::id(),
            monotonic_ns()
        ))
        .unwrap();
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::export(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    #[cfg(test)]
    fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "executor diagnostic path must be absolute",
            ));
        }
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        Self::export(output)
    }

    fn export(mut output: std::fs::File) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Event>(QUEUE_SIZE);
        let lost = Arc::new(AtomicU64::new(0));
        let export_lost = lost.clone();
        std::thread::Builder::new()
            .name("packet-diagnostics".into())
            .spawn(move || {
                // Formatting and filesystem operations run outside packet executors.
                while let Ok(event) = receiver.recv() {
                    let record = event.for_export(export_lost.load(Ordering::Relaxed));
                    if serde_json::to_writer(&mut output, &record).is_err()
                        || output.write_all(b"\n").is_err()
                        || output.flush().is_err()
                    {
                        break;
                    }
                }
            })?;
        Ok(Self(Arc::new(Recorder { sender, lost })))
    }

    fn record(&self, event: Event) {
        if self.0.sender.try_send(event).is_err() {
            self.0.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Labels are escaped only by the exporter, never by the measured task.
    pub fn observe<F: Future>(&self, label: &'static str, future: F) -> Observed<F> {
        Observed::new(Some(self.clone()), label, future)
    }

    /// Must be started from the same runtime that executes the measured actor.
    pub fn heartbeat(&self, label: &'static str) -> HeartbeatGuard {
        let recorder = self.clone();
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(HEARTBEAT_PERIOD);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut previous_cpu = thread_cpu_ns();
            let mut previous_tid = thread_id();
            loop {
                let scheduled = tick.tick().await;
                let now = Instant::now();
                let tid = thread_id();
                let cpu = thread_cpu_ns();
                recorder.record(Event {
                    kind: "heartbeat",
                    label,
                    monotonic_ns: monotonic_ns(),
                    thread_id: tid,
                    wall_ns: nanos(now.saturating_duration_since(scheduled.into_std())),
                    thread_cpu_ns: (tid == previous_tid)
                        .then(|| {
                            cpu.zip(previous_cpu)
                                .map(|(now, previous)| now.saturating_sub(previous))
                        })
                        .flatten(),
                    ready: true,
                });
                previous_cpu = cpu;
                previous_tid = tid;
            }
        });
        HeartbeatGuard(task)
    }
}

/// Configuration errors must not stop packet service. Report once off executor.
pub fn configured() -> Option<Diagnostics> {
    static REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    match Diagnostics::from_environment() {
        Ok(value) => value,
        Err(error) => {
            if !REPORTED.swap(true, Ordering::Relaxed) {
                let _ = std::thread::Builder::new().name("diagnostic-config".into()).spawn(move || {
                    eprintln!("code=executor_diagnostics_unavailable module=executor_diagnostics detail={error} action=preserve_packet_service");
                });
            }
            None
        }
    }
}

/// Time one synchronous operation without allocating or reading clocks when
/// disabled. Nested operations overlap and their durations must not be summed.
pub fn observe_sync<T>(
    diagnostics: Option<&Diagnostics>,
    label: &'static str,
    operation: impl FnOnce() -> T,
) -> T {
    let Some(diagnostics) = diagnostics else {
        return operation();
    };
    let started = Instant::now();
    let cpu_started = thread_cpu_ns();
    let result = operation();
    let elapsed = started.elapsed();
    let cpu_finished = thread_cpu_ns();
    if elapsed >= SLOW_POLL {
        diagnostics.record(Event {
            kind: "sync",
            label,
            monotonic_ns: monotonic_ns(),
            thread_id: thread_id(),
            wall_ns: nanos(elapsed),
            thread_cpu_ns: cpu_finished
                .zip(cpu_started)
                .map(|(end, start)| end.saturating_sub(start)),
            ready: true,
        });
    }
    result
}

pub struct HeartbeatGuard(tokio::task::JoinHandle<()>);
impl Drop for HeartbeatGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct Observed<F> {
    future: Pin<Box<F>>,
    diagnostics: Option<Diagnostics>,
    label: &'static str,
}

impl<F> Observed<F> {
    pub fn new(diagnostics: Option<Diagnostics>, label: &'static str, future: F) -> Self {
        Self {
            future: Box::pin(future),
            diagnostics,
            label,
        }
    }
}

impl<F: Future> Future for Observed<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(diagnostics) = &this.diagnostics else {
            return this.future.as_mut().poll(cx);
        };
        let started = Instant::now();
        let cpu_started = thread_cpu_ns();
        let result = this.future.as_mut().poll(cx);
        let elapsed = started.elapsed();
        let cpu_finished = thread_cpu_ns();
        if elapsed >= SLOW_POLL {
            diagnostics.record(Event {
                kind: "poll",
                label: this.label,
                monotonic_ns: monotonic_ns(),
                thread_id: thread_id(),
                wall_ns: nanos(elapsed),
                thread_cpu_ns: cpu_finished
                    .zip(cpu_started)
                    .map(|(end, start)| end.saturating_sub(start)),
                ready: result.is_ready(),
            });
        }
        result
    }
}

fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn clock_ns(clock: libc::clockid_t) -> Option<u64> {
    #[cfg(test)]
    CLOCK_READS.with(|count| count.set(count.get() + 1));
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock, &mut value) } != 0 {
        return None;
    }
    u64::try_from(value.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(value.tv_nsec).ok()?)
}
fn monotonic_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC).unwrap_or(0)
}
fn thread_cpu_ns() -> Option<u64> {
    clock_ns(libc::CLOCK_THREAD_CPUTIME_ID)
}
fn thread_id() -> u64 {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::syscall(libc::SYS_gettid) as u64 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(test)]
thread_local! { static CLOCK_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn synchronous_operation_preserves_result_and_disabled_path_reads_no_clocks() {
        let before = CLOCK_READS.with(|count| count.get());
        let mut calls = 0;
        let result: io::Result<usize> = observe_sync(None, "disabled_sync", || {
            calls += 1;
            Err(io::Error::from_raw_os_error(libc::EAGAIN))
        });
        assert_eq!(calls, 1);
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EAGAIN));
        assert_eq!(CLOCK_READS.with(|count| count.get()), before);
    }

    #[test]
    fn synchronous_operation_reports_its_own_wall_and_cpu_scope() {
        let (sender, receiver) = mpsc::sync_channel(2);
        let diagnostics = Diagnostics(Arc::new(Recorder {
            sender,
            lost: Arc::new(AtomicU64::new(0)),
        }));
        let result = observe_sync(Some(&diagnostics), "test_operation", || {
            std::thread::sleep(Duration::from_millis(15));
            42
        });
        assert_eq!(result, 42);
        let event = receiver.try_recv().unwrap();
        assert_eq!(event.kind, "sync");
        assert_eq!(event.label, "test_operation");
        assert!(event.wall_ns >= 5_000_000);
        assert!(event.ready);
        let exported = event.for_export(0);
        assert_eq!(exported.cpu_scope, "operation");
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn disabled_preserves_pending_ready_and_cancellation_without_clock_reads() {
        struct Probe {
            polls: usize,
            dropped: Arc<AtomicBool>,
        }
        impl Future for Probe {
            type Output = usize;
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
                self.polls += 1;
                if self.polls == 1 {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(self.polls)
                }
            }
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let before = CLOCK_READS.with(|count| count.get());
        assert_eq!(
            Observed::new(
                None,
                "disabled",
                Probe {
                    polls: 0,
                    dropped: dropped.clone()
                }
            )
            .await,
            2
        );
        assert!(dropped.load(Ordering::SeqCst));
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut pending = Box::pin(Observed::new(
            None,
            "cancelled",
            Probe {
                polls: 0,
                dropped: cancelled.clone(),
            },
        ));
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(pending.as_mut().poll(&mut context).is_pending());
        drop(pending);
        assert!(cancelled.load(Ordering::SeqCst));
        assert_eq!(CLOCK_READS.with(|count| count.get()), before);
    }

    #[test]
    fn directory_outputs_are_unique_private_and_reject_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let first = Diagnostics::open_directory(directory.path()).unwrap();
        let second = Diagnostics::open_directory(directory.path()).unwrap();
        let files = std::fs::read_dir(directory.path())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(files.len(), 2);
        for file in files {
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
        let link = directory.path().join("link");
        symlink(directory.path(), &link).unwrap();
        assert!(Diagnostics::open_directory(&link).is_err());
        assert!(Diagnostics::open_directory(Path::new("relative")).is_err());
        drop((first, second));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn long_poll_and_same_executor_delay_are_observable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("diagnostics.jsonl");
        let diagnostics = Diagnostics::open(&path).unwrap();
        let heartbeat = diagnostics.heartbeat("test_executor");
        tokio::time::sleep(Duration::from_millis(15)).await;
        diagnostics
            .observe("slow_task", async {
                std::thread::sleep(Duration::from_millis(30));
                42
            })
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(heartbeat);
        drop(diagnostics);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let content = std::fs::read_to_string(&path).unwrap();
                let events: Vec<serde_json::Value> = content
                    .lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
                let poll = events
                    .iter()
                    .any(|event| event["kind"] == "poll" && event["label"] == "slow_task");
                let late = events
                    .iter()
                    .filter(|event| event["kind"] == "heartbeat")
                    .filter_map(|event| event["wall_ns"].as_u64())
                    .any(|lateness| lateness >= 15_000_000);
                if poll && late {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(Diagnostics::open(&path).is_err());
        assert!(Diagnostics::open(Path::new("relative.jsonl")).is_err());
    }

    #[tokio::test]
    async fn enabled_preserves_pending_ready_and_drops_cancelled_inner_future() {
        let directory = tempfile::tempdir().unwrap();
        let diagnostics = Diagnostics::open(&directory.path().join("events.jsonl")).unwrap();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let mut observed = Box::pin(diagnostics.observe("waiting", receiver));
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(observed.as_mut().poll(&mut context).is_pending());
        sender.send(42).unwrap();
        assert_eq!(observed.await.unwrap(), 42);
        let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
        let mut cancelled = Box::pin(diagnostics.observe("cancelled", receiver));
        assert!(cancelled.as_mut().poll(&mut context).is_pending());
        drop(cancelled);
        assert!(sender.is_closed());
    }

    #[test]
    fn full_queue_drops_evidence_without_waiting() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let diagnostics = Diagnostics(Arc::new(Recorder {
            sender,
            lost: Arc::new(AtomicU64::new(0)),
        }));
        for _ in 0..100 {
            diagnostics.record(Event {
                kind: "test",
                label: "queue",
                monotonic_ns: 0,
                thread_id: 0,
                wall_ns: 0,
                thread_cpu_ns: None,
                ready: true,
            });
        }
        assert_eq!(diagnostics.0.lost.load(Ordering::Relaxed), 99);
        let event = Event {
            kind: "poll",
            label: "quoted\"\\\n",
            monotonic_ns: 1,
            thread_id: 2,
            wall_ns: 3,
            thread_cpu_ns: None,
            ready: false,
        };
        let record = serde_json::to_value(event.for_export(99)).unwrap();
        assert_eq!(record["label"], event.label);
        assert_eq!(record["thread_cpu_ns"], serde_json::Value::Null);
        assert_eq!(record["cpu_scope"], "poll");
        assert_eq!(record["lost_events"], 99);
    }
}
