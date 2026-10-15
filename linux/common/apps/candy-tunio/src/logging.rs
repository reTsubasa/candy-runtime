use tracing_subscriber::{fmt::MakeWriter, EnvFilter};

fn subscriber<W>(writer: W, filter: EnvFilter) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(writer)
        .finish()
}

pub fn init() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing::subscriber::set_global_default(subscriber(std::io::stderr, filter))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn packet_failure_diagnostics_are_visible_without_verbose_packet_logging() {
        let capture = Capture::default();
        let writer = capture.clone();
        tracing::subscriber::with_default(
            subscriber(move || writer.clone(), EnvFilter::new("warn")),
            || {
                tracing::info!(code = "packet_received", "not enabled by default");
                tracing::warn!(
                    code = "tun_write_deadline",
                    module = "sdwan_packet_output",
                    timeout_stage = "expired_before_write",
                    queue_wait_us = 120_000_u64,
                    action = "drop_packet_keep_port"
                );
            },
        );
        let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        for expected in [
            "tun_write_deadline",
            "sdwan_packet_output",
            "expired_before_write",
            "queue_wait_us=120000",
            "drop_packet_keep_port",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
        assert!(!output.contains("packet_received"));
        assert!(!output.contains('\u{1b}'));
    }
}
