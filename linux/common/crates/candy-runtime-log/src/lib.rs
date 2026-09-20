use std::ffi::CString;
use std::fmt;
use std::io::Write as _;
use std::sync::Once;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Severity {
    Debug,
    Info,
    Warn,
    Error,
}

fn severity(message: &str) -> Severity {
    let level = message
        .strip_prefix("level=")
        .and_then(|value| value.split_ascii_whitespace().next());
    match level {
        Some("debug") => Severity::Debug,
        Some("info") => Severity::Info,
        Some("warn") | Some("warning") => Severity::Warn,
        Some("error") => Severity::Error,
        // Unclassified stderr was historically used only for fatal failures.
        // Treating it as an error keeps such failures visible while structured
        // producers are migrated to an explicit level.
        _ => Severity::Error,
    }
}

fn use_syslog() -> bool {
    std::env::var_os("CANDY_LOG_TARGET").is_some_and(|value| value == "syslog")
}

#[cfg(unix)]
fn emit_syslog(level: Severity, message: &str) {
    static OPEN_SYSLOG: Once = Once::new();
    OPEN_SYSLOG.call_once(|| unsafe {
        nix::libc::openlog(
            std::ptr::null(),
            nix::libc::LOG_NDELAY | nix::libc::LOG_PID,
            nix::libc::LOG_DAEMON,
        );
    });
    let priority = match level {
        Severity::Debug => nix::libc::LOG_DEBUG,
        Severity::Info => nix::libc::LOG_INFO,
        Severity::Warn => nix::libc::LOG_WARNING,
        Severity::Error => nix::libc::LOG_ERR,
    };
    let message = CString::new(message.replace('\0', "?")).expect("NUL bytes were replaced");
    unsafe {
        nix::libc::syslog(priority, c"%s".as_ptr(), message.as_ptr());
    }
}

pub fn emit(arguments: fmt::Arguments<'_>) {
    let message = arguments.to_string();
    let level = severity(&message);
    if use_syslog() {
        #[cfg(unix)]
        emit_syslog(level, &message);
        #[cfg(not(unix))]
        emit_stream(level, &message);
    } else {
        emit_stream(level, &message);
    }
}

fn emit_stream(level: Severity, message: &str) {
    match level {
        Severity::Debug | Severity::Info => {
            let _ = writeln!(std::io::stdout().lock(), "{message}");
        }
        Severity::Warn | Severity::Error => {
            let _ = writeln!(std::io::stderr().lock(), "{message}");
        }
    }
}

#[macro_export]
macro_rules! structured_eprintln {
    ($($argument:tt)*) => {{
        $crate::emit(format_args!($($argument)*));
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_level_maps_to_the_same_transport_severity() {
        assert_eq!(severity("level=debug event=tick"), Severity::Debug);
        assert_eq!(severity("level=info event=ready"), Severity::Info);
        assert_eq!(severity("level=warn event=retry"), Severity::Warn);
        assert_eq!(severity("level=warning event=retry"), Severity::Warn);
        assert_eq!(severity("level=error event=failed"), Severity::Error);
    }

    #[test]
    fn malformed_or_unclassified_records_fail_toward_visibility() {
        assert_eq!(severity("candy-netd: fatal"), Severity::Error);
        assert_eq!(severity("event=missing_level"), Severity::Error);
        assert_eq!(severity("level=invalid event=bad"), Severity::Error);
    }
}
