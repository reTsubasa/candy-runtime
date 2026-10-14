#![cfg(target_os = "linux")]

use candy_netd::v2::domains::{
    monotonic_millis, DomainBudgets, DomainConfig, DomainsConfig, FrontDispatcher,
    MultiDomainService,
};
use candy_netd::PeerCredentials;
use candy_netd_client::v2::InfrastructureClient;
use candy_netd_proto::v2::{Body, ForwardOwner, InfraSpec, Operation, Phase, Request};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, PrepareDeclaration, RouteDeclaration, RouteKind, UnderlayExclusion,
    UnderlayKind,
};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Fixture {
    path: PathBuf,
    names: Vec<String>,
    config: DomainsConfig,
}

fn command(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

impl Fixture {
    fn new(count: u8) -> Self {
        assert_eq!(
            std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
            Ok("1")
        );
        assert_eq!(unsafe { nix::libc::geteuid() }, 0);
        let path =
            std::env::temp_dir().join(format!("candy-multidomain-{}-{count}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let mut fixture = Self {
            path,
            names: Vec::new(),
            config: DomainsConfig {
                budgets: DomainBudgets {
                    max_domains: 4,
                    front_control_threads: 2,
                    max_control_threads: 6,
                    thread_stack_bytes: 256 * 1024,
                    max_total_stack_bytes: 6 * 256 * 1024,
                    max_pending_control_requests: 8,
                    max_pending_control_bytes: 2 * 4 * candy_netd_proto::MAX_NETD_FRAME_LEN,
                    max_reserved_fds: 1024,
                },
                domains: Vec::new(),
            },
        };
        for index in 1..=count {
            let name = format!("candytest-{}-{count}-{index}", std::process::id());
            command(&["netns", "add", &name]);
            command(&["-n", &name, "link", "set", "lo", "up"]);
            fixture.config.domains.push(DomainConfig {
                domain_id: [index; 16],
                infra_id: [index + 10; 16],
                namespace_path: PathBuf::from("/var/run/netns").join(&name),
                journal_path: fixture.path.join(format!("domain-{index}.journal")),
                table_id: 20_000,
            });
            fixture.names.push(name);
        }
        fixture
    }

    fn spec(&self, index: usize) -> InfraSpec {
        let domain = &self.config.domains[index];
        let namespace = fs::metadata(&domain.namespace_path).unwrap();
        InfraSpec {
            infra_id: domain.infra_id,
            generation: 1,
            netns_device: namespace.dev(),
            netns_inode: namespace.ino(),
            overlay_router_ipv4: [100, 64, 0, 10],
            mtu: 1398,
        }
    }

    fn operation(&self, index: usize, operation: Operation) -> Operation {
        let domain = &self.config.domains[index];
        Operation::InDomain {
            domain_id: domain.domain_id,
            infra_id: domain.infra_id,
            operation: Box::new(operation),
        }
    }

    fn call(&self, service: &MultiDomainService, index: usize, operation: Operation) -> Body {
        self.raw_call(service, self.operation(index, operation))
            .unwrap()
            .0
    }

    fn raw_call(
        &self,
        service: &MultiDomainService,
        operation: Operation,
    ) -> Result<(Body, Option<std::os::fd::OwnedFd>), candy_netd::v2::InfrastructureError> {
        service.process(
            Request {
                request_id: 1,
                caller_instance_id: [1; 16],
                caller_pid: std::process::id(),
                operation,
            },
            PeerCredentials {
                pid: std::process::id(),
                uid: 0,
                gid: 0,
            },
            monotonic_millis().unwrap(),
        )
    }

    fn snapshot(&self, index: usize) -> serde_json::Value {
        let name = &self.names[index];
        let output = Command::new("ip").args(["netns", "exec", name, "sh", "-ec",
            "cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/all/rp_filter /proc/sys/net/ipv4/conf/candy0/rp_filter /proc/sys/net/ipv6/conf/candy0/disable_ipv6; nft -j list ruleset"])
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::json!({
            "routes": serde_json::from_str::<serde_json::Value>(&command(&["-n", name, "-j", "route", "show", "table", "20000"])).unwrap(),
            "rules": serde_json::from_str::<serde_json::Value>(&command(&["-n", name, "-j", "rule", "show"])).unwrap(),
            "interface": serde_json::from_str::<serde_json::Value>(&command(&["-n", name, "-j", "addr", "show", "dev", "candy0"])).unwrap(),
            "sysctl_and_firewall": String::from_utf8(output.stdout).unwrap(),
        })
    }

    fn activate(&self, service: &MultiDomainService, index: usize, owner: &ForwardOwner) {
        assert!(matches!(
            self.call(service, index, Operation::InfraEnsure(self.spec(index))),
            Body::InfraStatus { spec: Some(spec), ifindex: Some(_), .. } if spec == self.spec(index)
        ));
        assert_eq!(
            self.call(
                service,
                index,
                Operation::ForwardPrepare {
                    infra_id: self.config.domains[index].infra_id,
                    infra_generation: 1,
                    owner: owner.clone(),
                    declaration: declaration(),
                }
            ),
            Body::Ack
        );
        assert_eq!(
            self.call(
                service,
                index,
                Operation::ForwardCommit {
                    owner: owner.clone()
                }
            ),
            Body::Ack
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = Command::new("ip").args(["netns", "del", name]).status();
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn owner(domain: u8) -> ForwardOwner {
    let now = monotonic_millis().unwrap();
    ForwardOwner {
        domain_id: [domain; 16],
        signed_generation: 1,
        worker_epoch: 1,
        fencing_token: 1,
        auth_deadline_mono_ms: now + 120_000,
        lease_deadline_mono_ms: now + 60_000,
    }
}

fn declaration() -> PrepareDeclaration {
    PrepareDeclaration {
        table_id: 20_000,
        overlay_router_ipv4: [100, 64, 0, 10],
        effective_mtu: 1398,
        routes: vec![
            RouteDeclaration {
                prefix: Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap(),
                kind: RouteKind::Remote,
            },
            RouteDeclaration {
                prefix: Ipv4Prefix::new([10, 4, 0, 0], 16).unwrap(),
                kind: RouteKind::Remote,
            },
        ],
        exclusions: vec![UnderlayExclusion {
            prefix: Ipv4Prefix::new([192, 0, 2, 1], 32).unwrap(),
            kind: UnderlayKind::CloudApi,
        }],
        firewall: FirewallPolicy {
            allow_forward: true,
            clamp_tcp_mss: true,
            require_ipv4_forwarding: true,
            manage_rp_filter: true,
        },
    }
}

fn wait_for(path: &Path) {
    for _ in 0..1000 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("helper did not become ready: {}", path.display());
}

fn start_server(
    service: Arc<MultiDomainService>,
    socket: &Path,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let listener = candy_netd::bind_private_socket_for(socket, 0, 0).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_server = stop.clone();
    let server = std::thread::spawn(move || {
        let front = FrontDispatcher::new(service).unwrap();
        while !stop_server.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    front.dispatch(stream).unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("{error}"),
            }
        }
    });
    (stop, server)
}

fn spawn_io(
    fixture: &Fixture,
    index: usize,
    epoch: u64,
    socket: &Path,
    conflicting_instance: Option<u8>,
) -> Child {
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "real_multidomain_fd_child",
            "--ignored",
            "--nocapture",
        ])
        .env("CANDY_DOMAIN_CHILD", (index + 1).to_string())
        .env("CANDY_DOMAIN_EPOCH", epoch.to_string())
        .env("CANDY_DOMAIN_SOCKET", socket)
        .env(
            "CANDY_DOMAIN_READY",
            fixture.path.join(format!("io-{index}-{epoch}.ready")),
        )
        .env(
            "CANDY_DOMAIN_STOP",
            fixture.path.join(format!("io-{index}-{epoch}.stop")),
        );
    if let Some(instance) = conflicting_instance {
        child.env("CANDY_DOMAIN_CONFLICT_INSTANCE", instance.to_string());
    }
    let namespace = fs::File::open(&fixture.config.domains[index].namespace_path).unwrap();
    unsafe {
        child.pre_exec(move || {
            if nix::libc::setns(namespace.as_raw_fd(), nix::libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    child.spawn().unwrap()
}

#[test]
#[ignore = "subprocess helper for isolated multi-domain kernel tests"]
fn real_multidomain_fd_child() {
    let Ok(domain) = std::env::var("CANDY_DOMAIN_CHILD") else {
        return;
    };
    let domain: u8 = domain.parse().unwrap();
    let epoch: u64 = std::env::var("CANDY_DOMAIN_EPOCH")
        .unwrap()
        .parse()
        .unwrap();
    let socket = PathBuf::from(std::env::var("CANDY_DOMAIN_SOCKET").unwrap());
    let conflicting_instance = std::env::var("CANDY_DOMAIN_CONFLICT_INSTANCE")
        .ok()
        .map(|value| value.parse::<u8>().unwrap());
    let mut client =
        InfrastructureClient::new(&socket, [conflicting_instance.unwrap_or(domain + 20); 16]);
    let (body, descriptor) = client
        .exchange_in_domain(
            [domain; 16],
            [domain + 10; 16],
            Operation::InfraAcquireIoFd {
                infra_id: [domain + 10; 16],
                generation: 1,
                io_epoch: epoch,
            },
        )
        .unwrap();
    if conflicting_instance.is_some() {
        assert!(matches!(&body, Body::Error { code, .. } if code == "domain_io_owner_conflict"));
        fs::write(
            std::env::var("CANDY_DOMAIN_READY").unwrap(),
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        return;
    }
    assert!(matches!(body, Body::IoFd { .. }));
    let descriptor = descriptor.unwrap();
    let (duplicate, _) = client
        .exchange_in_domain(
            [domain; 16],
            [domain + 10; 16],
            Operation::InfraAcquireIoFd {
                infra_id: [domain + 10; 16],
                generation: 1,
                io_epoch: epoch + 1,
            },
        )
        .unwrap();
    assert!(matches!(duplicate, Body::Error { code, .. } if code == "io_owner_alive"));
    let other = if domain == 1 { 2 } else { 1 };
    let mut different_instance = InfrastructureClient::new(&socket, [domain + 40; 16]);
    let (rejected, _) = different_instance
        .exchange_in_domain(
            [other; 16],
            [other + 10; 16],
            Operation::InfraAcquireIoFd {
                infra_id: [other + 10; 16],
                generation: 1,
                io_epoch: epoch + 10,
            },
        )
        .unwrap();
    assert!(matches!(rejected, Body::Error { code, .. } if code == "domain_io_owner_conflict"));
    fs::write(
        std::env::var("CANDY_DOMAIN_READY").unwrap(),
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let stop = PathBuf::from(std::env::var("CANDY_DOMAIN_STOP").unwrap());
    wait_for(&stop);
    drop(descriptor);
}

#[test]
#[ignore = "requires isolated root Linux namespaces, TUN and nftables"]
fn real_two_domains_same_prefix_failures_leases_journals_and_fd_owners_are_isolated() {
    let fixture = Fixture::new(2);
    let host_namespace = fs::metadata("/proc/thread-self/ns/net").unwrap();
    let host_forward = fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap();
    let mut service = Arc::new(MultiDomainService::new(0, 0, fixture.config.clone()).unwrap());
    let first = owner(1);
    let second = owner(2);
    fixture.activate(&service, 0, &first);
    fixture.activate(&service, 1, &second);
    assert_ne!(fixture.spec(0).netns_inode, fixture.spec(1).netns_inode);
    let healthy_before = fixture.snapshot(1);
    let first_before = fixture.snapshot(0);
    let mut inadmissible = fixture.config.clone();
    inadmissible.budgets.max_domains = 1;
    assert!(matches!(
        MultiDomainService::new(0, 0, inadmissible),
        Err(candy_netd::v2::InfrastructureError::ResourceBudget {
            resource: "domains",
            required: 2,
            allowed: 1,
        })
    ));
    assert_eq!(fixture.snapshot(0), first_before);
    assert_eq!(fixture.snapshot(1), healthy_before);
    let config_path = fixture.path.join("domains.json");
    let candidate_socket = fixture.path.join("inadmissible.sock");
    let mut inadmissible = fixture.config.clone();
    inadmissible.budgets.max_control_threads = 1;
    fs::write(&config_path, serde_json::to_vec(&inadmissible).unwrap()).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    let failed = Command::new(env!("CARGO_BIN_EXE_candy-netd"))
        .args([
            "--protocol-v2",
            "--allowed-uid",
            "0",
            "--allowed-gid",
            "0",
            "--domain-config",
        ])
        .arg(&config_path)
        .arg("--socket")
        .arg(&candidate_socket)
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr)
        .contains("resource=control_threads required=4 allowed=1"));
    assert!(
        !candidate_socket.exists(),
        "rejected admission must not create the front socket"
    );
    let precheck = Command::new(env!("CARGO_BIN_EXE_candy-netd"))
        .arg("--check-domain-resources")
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(!precheck.status.success());
    assert!(String::from_utf8_lossy(&precheck.stderr).contains("resource=control_threads"));
    fs::write(&config_path, serde_json::to_vec(&fixture.config).unwrap()).unwrap();
    let mut limited = Command::new(env!("CARGO_BIN_EXE_candy-netd"));
    limited.arg("--check-domain-resources").arg(&config_path);
    unsafe {
        limited.pre_exec(|| {
            let limit = nix::libc::rlimit {
                rlim_cur: 32,
                rlim_max: 32,
            };
            if nix::libc::setrlimit(nix::libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let insufficient_fds = limited.output().unwrap();
    assert!(!insufficient_fds.status.success());
    assert!(
        String::from_utf8_lossy(&insufficient_fds.stderr).contains("resource=rlimit_nofile_soft")
    );
    assert!(Command::new(env!("CARGO_BIN_EXE_candy-netd"))
        .arg("--check-domain-resources")
        .arg(&config_path)
        .status()
        .unwrap()
        .success());
    assert_eq!(fixture.snapshot(0), first_before);
    assert_eq!(fixture.snapshot(1), healthy_before);
    assert!(fixture.raw_call(&service, Operation::InfraStatus).is_err());
    assert!(fixture
        .raw_call(
            &service,
            Operation::InDomain {
                domain_id: [1; 16],
                infra_id: [12; 16],
                operation: Box::new(Operation::InfraStatus)
            }
        )
        .is_err());
    assert!(fixture
        .raw_call(
            &service,
            fixture.operation(
                0,
                Operation::ForwardRevoke {
                    owner: second.clone()
                }
            )
        )
        .is_err());
    assert!(fixture
        .raw_call(
            &service,
            fixture.operation(
                0,
                Operation::InfraAcquireIoFd {
                    infra_id: [12; 16],
                    generation: 1,
                    io_epoch: 1
                }
            )
        )
        .is_err());
    let mut wrong_epoch = first.clone();
    wrong_epoch.worker_epoch += 1;
    assert!(fixture
        .raw_call(
            &service,
            fixture.operation(0, Operation::ForwardRevoke { owner: wrong_epoch })
        )
        .is_err());

    let socket = fixture.path.join("netd.sock");
    let (stop, server) = start_server(service.clone(), &socket);
    use std::io::Write;
    let mut partial = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    partial.write_all(&[0]).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let healthy_started = std::time::Instant::now();
    let mut healthy_client = InfrastructureClient::new(&socket, [99; 16]);
    let healthy = healthy_client
        .exchange_in_domain([2; 16], [12; 16], Operation::InfraStatus)
        .unwrap()
        .0;
    assert!(matches!(healthy, Body::InfraStatus { .. }));
    assert!(
        healthy_started.elapsed() < Duration::from_millis(500),
        "partial request blocked healthy domain"
    );
    drop(partial);
    let mut first_io = spawn_io(&fixture, 0, 1, &socket, None);
    let mut second_io = spawn_io(&fixture, 1, 1, &socket, None);
    wait_for(&fixture.path.join("io-0-1.ready"));
    wait_for(&fixture.path.join("io-1-1.ready"));

    let failed = Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap();
    fixture.call(
        &service,
        0,
        Operation::ForwardFailedPrefixes {
            owner: first.clone(),
            failure_revision: 1,
            failed_prefixes: vec![failed],
        },
    );
    assert!(
        command(&["-n", &fixture.names[0], "route", "show", "table", "20000"])
            .contains("unreachable 10.2.0.0/16")
    );
    assert_eq!(healthy_before, fixture.snapshot(1));
    let first_failed = fixture.snapshot(0);
    assert_eq!(first_before["rules"], first_failed["rules"]);
    assert_eq!(first_before["interface"], first_failed["interface"]);
    assert_eq!(
        first_before["sysctl_and_firewall"],
        first_failed["sysctl_and_firewall"]
    );
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    drop(service);
    service = Arc::new(MultiDomainService::new(0, 0, fixture.config.clone()).unwrap());
    assert_eq!(healthy_before, fixture.snapshot(1));
    assert_eq!(first_failed, fixture.snapshot(0));
    fixture.call(
        &service,
        0,
        Operation::ForwardFailedPrefixes {
            owner: first.clone(),
            failure_revision: 2,
            failed_prefixes: vec![],
        },
    );
    assert_eq!(first_before, fixture.snapshot(0));
    assert_eq!(healthy_before, fixture.snapshot(1));

    assert!(MultiDomainService::new(0, 0, fixture.config.clone())
        .err()
        .unwrap()
        .to_string()
        .contains("domain_journal_busy"));
    drop(service);

    let mut duplicate_namespace = fixture.config.clone();
    duplicate_namespace.domains[1].namespace_path =
        duplicate_namespace.domains[0].namespace_path.clone();
    assert!(MultiDomainService::new(0, 0, duplicate_namespace).is_err());
    let mut duplicate_journal = fixture.config.clone();
    duplicate_journal.domains[1].journal_path = duplicate_journal.domains[0].journal_path.clone();
    assert!(MultiDomainService::new(0, 0, duplicate_journal).is_err());
    let mut swapped_journal = fixture.config.clone();
    swapped_journal.domains[0].journal_path = fixture.config.domains[1].journal_path.clone();
    swapped_journal.domains[1].journal_path = fixture.config.domains[0].journal_path.clone();
    assert!(MultiDomainService::new(0, 0, swapped_journal).is_err());
    assert_eq!(healthy_before, fixture.snapshot(1));

    service = Arc::new(MultiDomainService::new(0, 0, fixture.config.clone()).unwrap());
    let (stop, server) = start_server(service.clone(), &socket);
    let mut conflicting_io = spawn_io(&fixture, 1, 9, &socket, Some(21));
    wait_for(&fixture.path.join("io-1-9.ready"));
    assert!(conflicting_io.wait().unwrap().success());
    fs::write(fixture.path.join("io-0-1.stop"), b"stop").unwrap();
    assert!(first_io.wait().unwrap().success());
    fixture.call(
        &service,
        0,
        Operation::InfraReleaseIo {
            infra_id: [11; 16],
            generation: 1,
            io_epoch: 1,
        },
    );
    let mut replacement_io = spawn_io(&fixture, 0, 2, &socket, None);
    wait_for(&fixture.path.join("io-0-2.ready"));
    fs::write(fixture.path.join("io-0-2.stop"), b"stop").unwrap();
    assert!(replacement_io.wait().unwrap().success());
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    let mut short = first;
    short.signed_generation += 1;
    short.worker_epoch += 1;
    short.fencing_token += 1;
    short.lease_deadline_mono_ms = monotonic_millis().unwrap() + 500;
    fixture.call(
        &service,
        0,
        Operation::ForwardPrepare {
            infra_id: [11; 16],
            infra_generation: 1,
            owner: short.clone(),
            declaration: declaration(),
        },
    );
    fixture.call(&service, 0, Operation::ForwardCommit { owner: short });
    std::thread::sleep(Duration::from_millis(700));
    assert!(matches!(
        fixture.call(&service, 0, Operation::ForwardStatus),
        Body::ForwardStatus {
            phase: Some(Phase::Revoked),
            ..
        }
    ));
    assert!(matches!(
        fixture.call(&service, 1, Operation::ForwardStatus),
        Body::ForwardStatus {
            phase: Some(Phase::Active),
            ..
        }
    ));
    assert_eq!(healthy_before, fixture.snapshot(1));
    let mut original = first_before["interface"].clone();
    let mut retained = fixture.snapshot(0)["interface"].clone();
    // Reattaching a queue can report UNKNOWN -> UP without changing carrier or identity.
    for interfaces in [&mut original, &mut retained] {
        for interface in interfaces.as_array_mut().unwrap() {
            assert!(matches!(
                interface["operstate"].as_str(),
                Some("UP" | "UNKNOWN")
            ));
            interface.as_object_mut().unwrap().remove("operstate");
        }
    }
    assert_eq!(original, retained);
    assert_eq!(
        host_forward,
        fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap()
    );
    let host_after = fs::metadata("/proc/thread-self/ns/net").unwrap();
    assert_eq!(
        (host_namespace.dev(), host_namespace.ino()),
        (host_after.dev(), host_after.ino())
    );
    fs::write(fixture.path.join("io-1-1.stop"), b"stop").unwrap();
    assert!(second_io.wait().unwrap().success());
    drop(service);
}

#[test]
#[ignore = "requires isolated root Linux namespaces, TUN and nftables"]
fn real_one_and_four_explicit_namespace_domains_activate_independently() {
    for count in [1, 4] {
        let fixture = Fixture::new(count);
        let threads_before = fs::read_dir("/proc/self/task").unwrap().count();
        let descriptors_before = fs::read_dir("/proc/self/fd").unwrap().count();
        let rss_before = resident_kib();
        let service = MultiDomainService::new(0, 0, fixture.config.clone()).unwrap();
        let service = Arc::new(service);
        let _front = FrontDispatcher::new(service.clone()).unwrap();
        assert!(matches!(
            fixture
                .raw_call(&service, Operation::Capabilities)
                .unwrap()
                .0,
            Body::Capabilities {
                multi_domain: true,
                independent_infrastructure: true,
                version: 2
            }
        ));
        for domain in 0..usize::from(count) {
            fixture.activate(&service, domain, &owner(domain as u8 + 1));
            assert!(matches!(
                fixture.call(&service, domain, Operation::ForwardStatus),
                Body::ForwardStatus {
                    phase: Some(Phase::Active),
                    ..
                }
            ));
            assert!(command(&[
                "-n",
                &fixture.names[domain],
                "route",
                "show",
                "table",
                "20000"
            ])
            .contains("10.2.0.0/16 dev candy0"));
        }
        let thread_delta = fs::read_dir("/proc/self/task").unwrap().count() - threads_before;
        let descriptor_delta = fs::read_dir("/proc/self/fd").unwrap().count() - descriptors_before;
        assert_eq!(
            thread_delta,
            usize::from(count) + fixture.config.budgets.front_control_threads
        );
        println!("resource_observation domains={count} control_thread_delta={thread_delta} fd_delta={descriptor_delta} rss_delta_kib={} scope=netd_control_only profile=debug", resident_kib().saturating_sub(rss_before));
        drop(_front);
        drop(service);
    }
}

fn resident_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}
