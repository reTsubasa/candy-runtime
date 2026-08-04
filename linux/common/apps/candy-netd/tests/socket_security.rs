use candy_netd::{bind_private_socket, bind_private_socket_for, SocketSecurityError};
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn test_directory() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("candy-netd-test-{}", std::process::id()))
}

#[test]
fn socket_can_be_owned_by_the_configured_caller() {
    let directory = test_directory().with_extension("owner");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.join("netd.sock");
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let listener = bind_private_socket_for(&socket, uid, gid).unwrap();
    let metadata = fs::metadata(&socket).unwrap();
    assert_eq!((metadata.uid(), metadata.gid()), (uid, gid));
    drop(listener);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn socket_rejects_symlinks_and_preserves_existing_targets() {
    let directory = test_directory().with_extension("targets");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let target = directory.join("existing");
    fs::write(&target, b"preserve").unwrap();
    assert!(matches!(
        bind_private_socket(&target),
        Err(SocketSecurityError::ExistingPath)
    ));
    assert_eq!(fs::read(&target).unwrap(), b"preserve");

    let socket = directory.join("netd.sock");
    symlink(&target, &socket).unwrap();
    assert!(matches!(
        bind_private_socket(&socket),
        Err(SocketSecurityError::ExistingPath)
    ));
    assert!(fs::symlink_metadata(&socket)
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn socket_is_owner_only_and_rejects_unsafe_parent() {
    let directory = test_directory();
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.join("netd.sock");
    let listener = bind_private_socket(&socket).unwrap();
    assert_eq!(
        fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(listener);
    fs::remove_file(&socket).unwrap();

    fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        bind_private_socket(&socket),
        Err(SocketSecurityError::UnsafeParent)
    ));
    fs::remove_dir(&directory).unwrap();
}
