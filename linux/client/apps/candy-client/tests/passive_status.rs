use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn temporary_directory() -> std::path::PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "candy-cli-status-side-effect-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn status_command_does_not_touch_readiness_but_daemon_path_still_withdraws_it() {
    let directory = temporary_directory();
    let readiness = directory.join("client.ready");
    let status = directory.join("passive.json");
    fs::write(&readiness, b"sentinel\n").unwrap();
    fs::set_permissions(&readiness, fs::Permissions::from_mode(0o640)).unwrap();
    fs::write(
        &status,
        b"{\"schema_version\":1,\"configured_intent\":null,\"applied_transport\":null,\"local\":null,\"peer\":null,\"fallback_reason\":null,\"updated_unix_ms\":17}\n",
    )
    .unwrap();
    let before = fs::metadata(&readiness).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_client-cli"))
        .env("CANDY_READY_FILE", &readiness)
        .args(["status", "--path"])
        .arg(&status)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&readiness).unwrap(), b"sentinel\n");
    let after = fs::metadata(&readiness).unwrap();
    assert_eq!(after.ino(), before.ino());
    assert_eq!(after.permissions().mode() & 0o777, 0o640);
    assert!(!directory.join("client.ready.lock").exists());

    let daemon = Command::new(env!("CARGO_BIN_EXE_client-cli"))
        .env("CANDY_READY_FILE", &readiness)
        .args([
            "--config",
            "/definitely/missing/candy.json",
            "--check-config",
        ])
        .output()
        .unwrap();
    assert!(!daemon.status.success());
    assert!(!readiness.exists());
    fs::remove_dir_all(directory).unwrap();
}
