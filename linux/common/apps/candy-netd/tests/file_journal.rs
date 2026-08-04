use candy_netd::{FileNetworkJournal, NetworkJournal, TransactionPhase, TransactionRecord};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, LeaseOwner, PrepareDeclaration, RouteDeclaration, RouteKind,
    UnderlayExclusion, UnderlayKind, CANDY_TABLE_MIN,
};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

fn test_directory() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("candy-netd-journal-test-{}", std::process::id()))
}

fn record() -> TransactionRecord {
    TransactionRecord {
        owner: LeaseOwner {
            instance_id: [1; 16],
            pid: 4242,
            generation: 7,
            lease_deadline_mono_ms: 50_000,
        },
        declaration: PrepareDeclaration {
            table_id: CANDY_TABLE_MIN,
            overlay_router_ipv4: [100, 64, 0, 10],
            effective_mtu: 1180,
            routes: vec![RouteDeclaration {
                prefix: Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap(),
                kind: RouteKind::Remote,
            }],
            exclusions: vec![UnderlayExclusion {
                prefix: Ipv4Prefix::new([192, 0, 2, 10], 32).unwrap(),
                kind: UnderlayKind::CloudApi,
            }],
            firewall: FirewallPolicy {
                allow_forward: true,
                clamp_tcp_mss: true,
                require_ipv4_forwarding: true,
                manage_rp_filter: true,
            },
        },
        phase: TransactionPhase::Prepared,
        completed_steps: 15,
        sysctls: Vec::new(),
    }
}

#[test]
fn journal_round_trips_privately_and_clear_is_durable() {
    let directory = test_directory().with_extension("roundtrip");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.join("state.journal");
    let mut journal = FileNetworkJournal::new(path.clone()).unwrap();
    journal.store(&record()).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(journal.load().unwrap(), Some(record()));
    journal.clear().unwrap();
    assert!(journal.load().unwrap().is_none());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn journal_rejects_corruption_symlinks_and_unsafe_parents() {
    let directory = test_directory().with_extension("reject");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.join("state.journal");
    let mut journal = FileNetworkJournal::new(path.clone()).unwrap();
    journal.store(&record()).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    bytes[10] ^= 0x80;
    fs::write(&path, bytes).unwrap();
    assert!(journal.load().is_err());

    fs::remove_file(&path).unwrap();
    let target = directory.join("target");
    fs::write(&target, b"preserve").unwrap();
    symlink(&target, &path).unwrap();
    assert!(journal.load().is_err());
    assert_eq!(fs::read(&target).unwrap(), b"preserve");
    fs::remove_file(&path).unwrap();

    fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(FileNetworkJournal::new(path).is_err());
    fs::remove_dir_all(directory).unwrap();
}
