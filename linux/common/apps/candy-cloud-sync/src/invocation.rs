use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder, Response};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) enum SyncInterrupted {
    Cancelled,
    Deadline,
}

impl std::fmt::Display for SyncInterrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cancelled => "code=cloud_sync_cancelled module=cloud_sync detail=iteration cancelled by supervisor",
            Self::Deadline => "code=cloud_sync_deadline module=cloud_sync detail=iteration deadline reached",
        })
    }
}
impl std::error::Error for SyncInterrupted {}

#[derive(Clone, Debug)]
pub struct SyncControl {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl SyncControl {
    pub fn new(timeout: Duration) -> Result<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(600) {
            bail!("code=cloud_sync_budget_invalid module=cloud_sync detail=iteration timeout must be within 0..600 seconds");
        }
        Ok(Self {
            deadline: Instant::now()
                .checked_add(timeout)
                .context("sync deadline overflow")?,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn remaining(&self) -> Result<Duration> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(SyncInterrupted::Cancelled.into());
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| SyncInterrupted::Deadline.into())
    }
}

pub(crate) fn checkpoint(control: Option<&SyncControl>) -> Result<()> {
    if let Some(control) = control {
        control.remaining()?;
    }
    Ok(())
}

pub(crate) struct SyncClient {
    pub inner: Client,
    pub control: Option<SyncControl>,
}

impl std::ops::Deref for SyncClient {
    type Target = Client;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl SyncClient {
    pub(crate) fn send(&self, mut request: RequestBuilder) -> Result<Response> {
        if let Some(control) = &self.control {
            request = request.timeout(control.remaining()?.min(Duration::from_secs(35)));
        }
        let response = request.send();
        checkpoint(self.control.as_ref())?;
        response.context("send bounded Cloud request")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn cancelled_request_does_not_reach_the_network() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let control = SyncControl::new(Duration::from_secs(1)).unwrap();
        control.cancel();
        let client = SyncClient {
            inner: Client::builder().no_proxy().build().unwrap(),
            control: Some(control),
        };
        let error = client
            .send(client.get(format!("http://{address}/")))
            .unwrap_err();
        assert!(format!("{error:#}").contains("cloud_sync_cancelled"));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn iteration_deadline_bounds_a_stalled_http_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0_u8; 1024];
            assert!(socket.read(&mut request).unwrap() > 0);
            std::thread::sleep(Duration::from_millis(200));
            let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });
        let client = SyncClient {
            inner: Client::builder().no_proxy().build().unwrap(),
            control: Some(SyncControl::new(Duration::from_millis(50)).unwrap()),
        };
        let started = Instant::now();
        let error = client
            .send(client.get(format!("http://{address}/")))
            .unwrap_err();
        assert!(format!("{error:#}").contains("cloud_sync_deadline"));
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }
}
