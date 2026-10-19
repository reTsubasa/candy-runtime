use candy_netd::v2::{InfrastructureBackend, InfrastructureJournal, InfrastructureService};
use candy_netd::{
    NetworkBackend, NetworkError, PeerCredentials, PlatformError, SysctlChange, TunFactory,
};
use candy_netd_proto::v2::{Body, ForwardOwner, InfraSpec, Operation, Phase, Request};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, PrepareDeclaration, RouteDeclaration, RouteKind, UnderlayExclusion,
    UnderlayKind,
};
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Observed {
    ifindex: Option<u32>,
    events: Vec<&'static str>,
    fail_commit: bool,
    firewall_present: bool,
    fail_firewall_once: bool,
    fail_restore_prefix_once: Option<[u8; 4]>,
    active_declaration: Option<PrepareDeclaration>,
    ownership_marker: Option<String>,
    failed_prefixes: Vec<Ipv4Prefix>,
    fail_prefix_update_once: bool,
    fail_prefix_update: bool,
    fail_stamp_once: bool,
    guarded: bool,
}

struct Backend(Arc<Mutex<Observed>>);
impl Backend {
    fn event(&mut self, value: &'static str) -> Result<(), NetworkError> {
        self.0.lock().unwrap().events.push(value);
        Ok(())
    }
}

impl NetworkBackend for Backend {
    fn preflight(&mut self, _: &PrepareDeclaration) -> Result<Vec<SysctlChange>, NetworkError> {
        self.event("preflight")?;
        Ok(vec![])
    }
    fn prepare_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        panic!("forwarding may not prepare TUN")
    }
    fn prepare_routes(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("routes")
    }
    fn prepare_firewall(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        let mut observed = self.0.lock().unwrap();
        if observed.firewall_present {
            return Err(NetworkError::Backend);
        }
        observed.firewall_present = true;
        observed.events.push("firewall");
        if std::mem::take(&mut observed.fail_firewall_once) {
            return Err(NetworkError::Backend);
        }
        Ok(())
    }
    fn prepare_sysctls(
        &mut self,
        _: &PrepareDeclaration,
        _: &[SysctlChange],
    ) -> Result<(), NetworkError> {
        self.event("sysctls")
    }
    fn activate_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        panic!("forwarding may not activate TUN")
    }
    fn install_policy_rule(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("policy")
    }
    fn remove_policy_rule(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("remove_policy")
    }
    fn deactivate_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        panic!("forwarding may not down TUN")
    }
    fn remove_firewall(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        let mut observed = self.0.lock().unwrap();
        observed.firewall_present = false;
        observed.events.push("remove_firewall");
        Ok(())
    }
    fn remove_routes(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("remove_routes")
    }
    fn remove_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        panic!("forwarding may not delete TUN")
    }
    fn restore_sysctls(
        &mut self,
        _: &PrepareDeclaration,
        _: &[SysctlChange],
    ) -> Result<(), NetworkError> {
        self.event("restore_sysctls")
    }
}

impl InfrastructureBackend for Backend {
    fn restore_forwarding_with_failures(
        &mut self,
        declaration: &PrepareDeclaration,
        failed: &[Ipv4Prefix],
    ) -> Result<(), NetworkError> {
        self.restore_forwarding(declaration)?;
        self.0.lock().unwrap().failed_prefixes = failed.to_vec();
        Ok(())
    }
    fn update_failed_forward_prefixes(
        &mut self,
        _: &PrepareDeclaration,
        _: &[Ipv4Prefix],
        failed: &[Ipv4Prefix],
    ) -> Result<(), NetworkError> {
        let mut observed = self.0.lock().unwrap();
        if observed.fail_prefix_update || std::mem::take(&mut observed.fail_prefix_update_once) {
            return Err(NetworkError::Backend);
        }
        observed.failed_prefixes = failed.to_vec();
        observed.events.push("prefix_routes");
        Ok(())
    }
    fn interface_ownership_marker(&mut self) -> Result<Option<String>, NetworkError> {
        let observed = self.0.lock().unwrap();
        Ok(observed.ifindex.and(observed.ownership_marker.clone()))
    }
    fn stamp_infrastructure_ownership(&mut self, marker: &str) -> Result<(), NetworkError> {
        let mut observed = self.0.lock().unwrap();
        if std::mem::take(&mut observed.fail_stamp_once) {
            return Err(NetworkError::Backend);
        }
        observed.ifindex = Some(17);
        observed.ownership_marker = Some(marker.to_owned());
        Ok(())
    }
    fn validate_forwarding_replacement(
        &mut self,
        _: &PrepareDeclaration,
        _: &PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        Ok(())
    }
    fn interface_identity(&mut self) -> Result<Option<u32>, NetworkError> {
        Ok(self.0.lock().unwrap().ifindex)
    }
    fn ensure_infrastructure(&mut self, _: &InfraSpec) -> Result<u32, NetworkError> {
        self.0.lock().unwrap().ifindex = Some(17);
        self.event("infra_ensure")?;
        Ok(17)
    }
    fn retire_infrastructure(&mut self) -> Result<(), NetworkError> {
        self.0.lock().unwrap().ifindex = None;
        self.event("infra_retire")
    }
    fn reject_forwarding(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("reject_routes")
    }
    fn guard_forwarding(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        let mut observed = self.0.lock().unwrap();
        observed.guarded = true;
        observed.active_declaration = Some(declaration.clone());
        observed.events.push("guard_routes_preserve_tun");
        Ok(())
    }
    fn restore_forwarding(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        let mut observed = self.0.lock().unwrap();
        if observed.fail_commit {
            return Err(NetworkError::Backend);
        }
        if observed.fail_restore_prefix_once.is_some_and(|prefix| {
            declaration
                .routes
                .iter()
                .any(|route| route.prefix.network == prefix)
        }) {
            observed.fail_restore_prefix_once = None;
            return Err(NetworkError::Backend);
        }
        observed.active_declaration = Some(declaration.clone());
        observed.events.push("restore_routes");
        Ok(())
    }
}

struct Factory;
impl TunFactory for Factory {
    fn create_exclusive(&mut self) -> Result<OwnedFd, PlatformError> {
        self.create()
    }
    fn enable_persistence(&mut self, _: &OwnedFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn create(&mut self) -> Result<OwnedFd, PlatformError> {
        Ok(fs::File::open("/dev/null")?.into())
    }
    fn create_persistent(&mut self) -> Result<OwnedFd, PlatformError> {
        self.create()
    }
}

struct Fixture {
    path: PathBuf,
    observed: Arc<Mutex<Observed>>,
    service: InfrastructureService<Factory, Backend>,
}
impl Fixture {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("candy-netd-v2-{}-{label}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let observed = Arc::new(Mutex::new(Observed::default()));
        let service = Self::service(&path, observed.clone());
        Self {
            path,
            observed,
            service,
        }
    }
    fn service(
        path: &std::path::Path,
        observed: Arc<Mutex<Observed>>,
    ) -> InfrastructureService<Factory, Backend> {
        InfrastructureService::new(
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
            Factory,
            Backend(observed),
            InfrastructureJournal::new(path.join("infra.journal")).unwrap(),
        )
        .unwrap()
    }
    fn call(
        &mut self,
        operation: Operation,
        now: u64,
    ) -> Result<(Body, Option<OwnedFd>), candy_netd::v2::InfrastructureError> {
        let pid = std::process::id();
        self.service.process(
            Request {
                request_id: 1,
                caller_instance_id: [1; 16],
                caller_pid: pid,
                operation,
            },
            PeerCredentials {
                pid,
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
            },
            now,
        )
    }
    fn ensure(&mut self) {
        self.call(Operation::InfraEnsure(spec()), 1).unwrap();
    }
    fn prepare(&mut self) {
        self.call(
            Operation::ForwardPrepare {
                infra_id: [2; 16],
                infra_generation: 1,
                owner: owner(),
                declaration: declaration(),
            },
            2,
        )
        .unwrap();
    }
    fn commit(&mut self) {
        self.call(Operation::ForwardCommit { owner: owner() }, 3)
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn spec() -> InfraSpec {
    #[cfg(target_os = "linux")]
    let namespace = fs::metadata("/proc/self/ns/net").unwrap();
    #[cfg(not(target_os = "linux"))]
    let namespace = fs::metadata("/tmp").unwrap();
    InfraSpec {
        infra_id: [2; 16],
        generation: 1,
        netns_device: namespace.dev(),
        netns_inode: namespace.ino(),
        overlay_router_ipv4: [100, 64, 0, 10],
        mtu: 1398,
    }
}
fn owner() -> ForwardOwner {
    ForwardOwner {
        domain_id: [3; 16],
        signed_generation: 10,
        worker_epoch: 4,
        fencing_token: 8,
        auth_deadline_mono_ms: 2000,
        lease_deadline_mono_ms: 1000,
    }
}
fn declaration() -> PrepareDeclaration {
    PrepareDeclaration {
        table_id: 20000,
        overlay_router_ipv4: [100, 64, 0, 10],
        effective_mtu: 1398,
        routes: vec![RouteDeclaration {
            prefix: Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap(),
            kind: RouteKind::Remote,
        }],
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

fn candidate() -> (ForwardOwner, PrepareDeclaration) {
    let mut next_owner = owner();
    next_owner.signed_generation += 1;
    next_owner.worker_epoch += 1;
    next_owner.fencing_token += 1;
    let mut next_policy = declaration();
    next_policy.routes[0].prefix = Ipv4Prefix::new([10, 3, 0, 0], 16).unwrap();
    next_policy.exclusions[0].prefix = Ipv4Prefix::new([192, 0, 2, 2], 32).unwrap();
    next_policy.firewall.clamp_tcp_mss = false;
    (next_owner, next_policy)
}

fn prepare_candidate(
    fixture: &mut Fixture,
    owner: &ForwardOwner,
    declaration: &PrepareDeclaration,
) {
    fixture
        .call(
            Operation::ForwardPrepare {
                infra_id: [2; 16],
                infra_generation: 1,
                owner: owner.clone(),
                declaration: declaration.clone(),
            },
            4,
        )
        .unwrap();
}

#[test]
fn candidate_preparation_has_no_kernel_side_effects_and_failed_commit_restores_old_policy() {
    let mut fixture = Fixture::new("candidate_rollback");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let before = fixture.observed.lock().unwrap().events.clone();
    let (next_owner, next_policy) = candidate();
    prepare_candidate(&mut fixture, &next_owner, &next_policy);
    assert_eq!(before, fixture.observed.lock().unwrap().events);
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 5).unwrap().0,
        Body::ForwardStatus { owner: Some(active), phase: Some(Phase::Active), candidate_owner: Some(prepared), .. }
        if active == owner() && prepared == next_owner)
    );
    fixture.observed.lock().unwrap().fail_restore_prefix_once = Some([10, 3, 0, 0]);
    assert!(fixture
        .call(
            Operation::ForwardCommit {
                owner: next_owner.clone()
            },
            6
        )
        .is_err());
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 7).unwrap().0,
        Body::ForwardStatus { owner: Some(active), phase: Some(Phase::Active), candidate_owner: None, last_fencing_token, .. }
        if active == owner() && last_fencing_token == next_owner.fencing_token)
    );
    assert_eq!(
        fixture.observed.lock().unwrap().active_declaration,
        Some(declaration())
    );
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
    assert!(
        fixture
            .call(
                Operation::ForwardPrepare {
                    infra_id: [2; 16],
                    infra_generation: 1,
                    owner: next_owner.clone(),
                    declaration: next_policy.clone(),
                },
                8
            )
            .is_err(),
        "failed candidate fence must not be reused"
    );
    let mut retry_owner = next_owner;
    retry_owner.fencing_token += 1;
    prepare_candidate(&mut fixture, &retry_owner, &next_policy);
    fixture
        .call(
            Operation::ForwardCommit {
                owner: retry_owner.clone(),
            },
            9,
        )
        .unwrap();
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 10).unwrap().0,
        Body::ForwardStatus { owner: Some(active), phase: Some(Phase::Active), candidate_owner: None, last_fencing_token, .. }
        if active == retry_owner && last_fencing_token == retry_owner.fencing_token)
    );
}

#[test]
fn policy_candidate_commit_changes_only_forwarding_and_rejects_old_fence() {
    let mut fixture = Fixture::new("candidate_commit");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let (next_owner, next_policy) = candidate();
    prepare_candidate(&mut fixture, &next_owner, &next_policy);
    fixture
        .call(
            Operation::ForwardCommit {
                owner: next_owner.clone(),
            },
            6,
        )
        .unwrap();
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 7).unwrap().0,
        Body::ForwardStatus { owner: Some(active), phase: Some(Phase::Active), candidate_owner: None, .. }
        if active == next_owner)
    );
    assert_eq!(
        fixture.observed.lock().unwrap().active_declaration,
        Some(next_policy)
    );
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
    assert!(fixture
        .call(Operation::ForwardRevoke { owner: owner() }, 8)
        .is_err());
}

#[test]
fn restart_and_expired_candidate_preserve_live_previous_policy() {
    let mut fixture = Fixture::new("candidate_restart");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let (next_owner, next_policy) = candidate();
    prepare_candidate(&mut fixture, &next_owner, &next_policy);
    fixture.service = Fixture::service(&fixture.path, fixture.observed.clone());
    let before = fixture.observed.lock().unwrap().events.clone();
    assert!(fixture.service.recover_expired(6).unwrap());
    assert_eq!(before, fixture.observed.lock().unwrap().events);
    let mut newer = next_owner.clone();
    newer.fencing_token += 1;
    newer.lease_deadline_mono_ms = 100;
    prepare_candidate(&mut fixture, &newer, &next_policy);
    assert!(fixture.service.recover_expired(100).unwrap());
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 101).unwrap().0,
        Body::ForwardStatus { owner: Some(active), phase: Some(Phase::Active), candidate_owner: None, .. }
        if active == owner())
    );
}

#[test]
fn interrupted_commit_repair_is_retried_after_netd_restart() {
    let mut fixture = Fixture::new("candidate_repair");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let (next_owner, next_policy) = candidate();
    prepare_candidate(&mut fixture, &next_owner, &next_policy);
    fixture.observed.lock().unwrap().fail_commit = true;
    assert!(fixture
        .call(Operation::ForwardCommit { owner: next_owner }, 6)
        .is_err());
    fixture.observed.lock().unwrap().fail_commit = false;
    fixture.service = Fixture::service(&fixture.path, fixture.observed.clone());
    assert!(fixture.service.recover_expired(7).unwrap());
    assert_eq!(
        fixture.observed.lock().unwrap().active_declaration,
        Some(declaration())
    );
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 8).unwrap().0,
        Body::ForwardStatus { owner: Some(active), phase: Some(Phase::Active), candidate_owner: None, .. }
        if active == owner())
    );
}

#[test]
fn interrupted_firewall_preparation_can_retry_without_recreating_infrastructure() {
    let mut fixture = Fixture::new("firewall_retry");
    fixture.ensure();
    fixture.observed.lock().unwrap().fail_firewall_once = true;
    assert!(fixture
        .call(
            Operation::ForwardPrepare {
                infra_id: [2; 16],
                infra_generation: 1,
                owner: owner(),
                declaration: declaration(),
            },
            2,
        )
        .is_err());
    assert!(fixture.observed.lock().unwrap().firewall_present);
    fixture.prepare();
    fixture.commit();
    let observed = fixture.observed.lock().unwrap();
    assert_eq!(observed.ifindex, Some(17));
    assert_eq!(
        observed
            .events
            .iter()
            .filter(|&&event| event == "infra_ensure")
            .count(),
        1
    );
    assert_eq!(
        observed
            .events
            .iter()
            .filter(|&&event| event == "firewall")
            .count(),
        2
    );
}

#[test]
fn revoking_or_expiring_forwarding_preserves_infrastructure_identity() {
    let mut fixture = Fixture::new("expiry");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    assert!(fixture.service.recover_expired(1000).unwrap());
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
    assert!(matches!(
        fixture.call(Operation::ForwardStatus, 1001).unwrap().0,
        Body::ForwardStatus {
            phase: Some(Phase::Revoked),
            ..
        }
    ));
    let events = &fixture.observed.lock().unwrap().events;
    assert!(!events.contains(&"remove_routes"));
    assert!(!events.contains(&"infra_retire"));
    assert!(events.contains(&"reject_routes"));
}

#[test]
fn prepared_then_commit_is_valid_and_stale_or_cross_domain_owners_are_rejected() {
    let mut fixture = Fixture::new("fencing");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let mut stale = owner();
    stale.worker_epoch -= 1;
    assert!(fixture
        .call(Operation::ForwardRevoke { owner: stale }, 4)
        .is_err());
    fixture
        .call(Operation::ForwardRevoke { owner: owner() }, 4)
        .unwrap();
    let mut other = owner();
    other.domain_id = [5; 16];
    other.fencing_token += 1;
    assert!(fixture
        .call(
            Operation::ForwardPrepare {
                infra_id: [2; 16],
                infra_generation: 1,
                owner: other,
                declaration: declaration()
            },
            5
        )
        .is_err());
    let mut next = owner();
    next.fencing_token += 1;
    next.worker_epoch += 1;
    fixture
        .call(
            Operation::ForwardPrepare {
                infra_id: [2; 16],
                infra_generation: 1,
                owner: next.clone(),
                declaration: declaration(),
            },
            5,
        )
        .unwrap();
    fixture
        .call(Operation::ForwardCommit { owner: next }, 6)
        .unwrap();
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
}

#[test]
fn identical_active_policy_owner_handoff_never_reinstalls_kernel_rules() {
    let mut fixture = Fixture::new("owner_only");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let mut next = owner();
    next.worker_epoch += 1;
    next.fencing_token += 1;
    let before = fixture.observed.lock().unwrap().events.clone();
    prepare_candidate(&mut fixture, &next, &declaration());
    assert_eq!(before, fixture.observed.lock().unwrap().events);
    fixture
        .call(
            Operation::ForwardCommit {
                owner: next.clone(),
            },
            6,
        )
        .unwrap();
    assert_eq!(before, fixture.observed.lock().unwrap().events);
    fixture
        .call(
            Operation::ForwardCommit {
                owner: next.clone(),
            },
            7,
        )
        .unwrap();
    assert_eq!(before, fixture.observed.lock().unwrap().events);
    fixture.service = Fixture::service(&fixture.path, fixture.observed.clone());
    assert!(!fixture.service.recover_expired(8).unwrap());
    assert_eq!(before, fixture.observed.lock().unwrap().events);
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 9).unwrap().0,
        Body::ForwardStatus { owner: Some(actual), phase: Some(Phase::Active), candidate_owner: None, .. } if actual == next)
    );
}

#[test]
fn owner_only_journal_failure_preserves_kernel_policy_and_exact_candidate() {
    let mut fixture = Fixture::new("owner_only_journal");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let mut next = owner();
    next.worker_epoch += 1;
    next.fencing_token += 1;
    prepare_candidate(&mut fixture, &next, &declaration());
    let before = fixture.observed.lock().unwrap().events.clone();
    let journal = fs::read(fixture.path.join("infra.journal")).unwrap();
    let temporary = fixture
        .path
        .join(format!("infra.v2-tmp-{}", std::process::id()));
    fs::create_dir(&temporary).unwrap();
    assert!(fixture
        .call(
            Operation::ForwardCommit {
                owner: next.clone()
            },
            6
        )
        .is_err());
    assert_eq!(before, fixture.observed.lock().unwrap().events);
    assert_eq!(
        journal,
        fs::read(fixture.path.join("infra.journal")).unwrap()
    );
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 7).unwrap().0,
        Body::ForwardStatus { owner: Some(actual), phase: Some(Phase::Active), candidate_owner: Some(candidate), .. } if actual == owner() && candidate == next)
    );
    fs::remove_dir(temporary).unwrap();
    fixture
        .call(
            Operation::ForwardCommit {
                owner: next.clone(),
            },
            8,
        )
        .unwrap();
    assert_eq!(before, fixture.observed.lock().unwrap().events);
}

#[test]
fn identical_declaration_with_changed_failed_routes_requires_kernel_transition() {
    let mut fixture = Fixture::new("owner_only_failures");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let mut next = owner();
    next.worker_epoch += 1;
    next.fencing_token += 1;
    prepare_candidate(&mut fixture, &next, &declaration());
    let failed = declaration().routes[0].prefix;
    fixture
        .call(
            Operation::ForwardFailedPrefixes {
                owner: next.clone(),
                failure_revision: 1,
                failed_prefixes: vec![failed],
            },
            5,
        )
        .unwrap();
    let before = fixture.observed.lock().unwrap().events.len();
    fixture
        .call(Operation::ForwardCommit { owner: next }, 6)
        .unwrap();
    let observed = fixture.observed.lock().unwrap();
    assert!(observed.events[before..].contains(&"reject_routes"));
    assert_eq!(observed.failed_prefixes, vec![failed]);
}

#[test]
fn live_forward_guard_preserves_tun_route_and_allows_exact_fenced_replacement() {
    let mut fixture = Fixture::new("guard");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let exact = owner();
    fixture
        .call(
            Operation::ForwardGuard {
                owner: exact.clone(),
            },
            4,
        )
        .unwrap();
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 5).unwrap().0,
        Body::ForwardStatus { owner: Some(current), phase: Some(Phase::Guarded), .. } if current == exact)
    );
    {
        let observed = fixture.observed.lock().unwrap();
        assert!(observed.guarded);
        assert_eq!(observed.active_declaration.as_ref(), Some(&declaration()));
        assert!(observed.events.contains(&"guard_routes_preserve_tun"));
        assert!(!observed
            .events
            .iter()
            .rev()
            .take(2)
            .any(|event| *event == "reject_routes"));
    }
    let (next_owner, next_policy) = candidate();
    fixture
        .call(
            Operation::ForwardPrepare {
                infra_id: [2; 16],
                infra_generation: 1,
                owner: next_owner.clone(),
                declaration: next_policy.clone(),
            },
            6,
        )
        .unwrap();
    fixture
        .call(
            Operation::ForwardCommit {
                owner: next_owner.clone(),
            },
            7,
        )
        .unwrap();
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 8).unwrap().0,
        Body::ForwardStatus { owner: Some(current), phase: Some(Phase::Active), .. } if current == next_owner)
    );
    assert_eq!(
        fixture.observed.lock().unwrap().active_declaration.as_ref(),
        Some(&next_policy)
    );
}

#[test]
fn forward_guard_rejects_stale_owner_and_expired_authority() {
    let mut fixture = Fixture::new("guard-owner");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let mut stale = owner();
    stale.worker_epoch += 1;
    assert!(fixture
        .call(Operation::ForwardGuard { owner: stale }, 4)
        .is_err());
    let mut expired = owner();
    expired.lease_deadline_mono_ms = 2;
    expired.auth_deadline_mono_ms = 2;
    assert!(fixture
        .call(Operation::ForwardGuard { owner: expired }, 5)
        .is_err());
    assert!(matches!(
        fixture.call(Operation::ForwardStatus, 6).unwrap().0,
        Body::ForwardStatus {
            phase: Some(Phase::Active),
            ..
        }
    ));
}

#[test]
fn restart_reconciles_ambiguous_preparation_and_preserves_live_committed_policy() {
    let mut fixture = Fixture::new("restart");
    fixture.ensure();
    fixture.prepare();
    fixture.service = Fixture::service(&fixture.path, fixture.observed.clone());
    assert!(fixture.service.recover_expired(3).unwrap());
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
    let mut next = owner();
    next.fencing_token += 1;
    fixture
        .call(
            Operation::ForwardPrepare {
                infra_id: [2; 16],
                infra_generation: 1,
                owner: next.clone(),
                declaration: declaration(),
            },
            4,
        )
        .unwrap();
    fixture
        .call(Operation::ForwardCommit { owner: next }, 5)
        .unwrap();
    fixture.service = Fixture::service(&fixture.path, fixture.observed.clone());
    assert!(!fixture.service.recover_expired(6).unwrap());
    assert!(matches!(
        fixture.call(Operation::ForwardStatus, 7).unwrap().0,
        Body::ForwardStatus {
            phase: Some(Phase::Active),
            ..
        }
    ));
}

#[test]
fn live_io_owner_cannot_obtain_two_readers_or_be_retired() {
    let mut fixture = Fixture::new("io-owner");
    fixture.ensure();
    let (_, fd) = fixture
        .call(
            Operation::InfraAcquireIoFd {
                infra_id: [2; 16],
                generation: 1,
                io_epoch: 1,
            },
            2,
        )
        .unwrap();
    assert!(fd.is_some());
    assert!(fixture
        .call(
            Operation::InfraAcquireIoFd {
                infra_id: [2; 16],
                generation: 1,
                io_epoch: 2
            },
            3
        )
        .is_err());
    assert!(fixture
        .call(
            Operation::InfraReleaseIo {
                infra_id: [2; 16],
                generation: 1,
                io_epoch: 1
            },
            3
        )
        .is_err());
    assert!(fixture
        .call(
            Operation::InfraRetire {
                infra_id: [2; 16],
                generation: 1
            },
            3
        )
        .is_err());
}

#[test]
fn backend_commit_failure_does_not_delete_infrastructure_or_publish_active() {
    let mut fixture = Fixture::new("backend-failure");
    fixture.ensure();
    fixture.prepare();
    fixture.observed.lock().unwrap().fail_commit = true;
    assert!(fixture
        .call(Operation::ForwardCommit { owner: owner() }, 3)
        .is_err());
    assert!(matches!(
        fixture.call(Operation::ForwardStatus, 4).unwrap().0,
        Body::ForwardStatus {
            phase: Some(Phase::Prepared),
            ..
        }
    ));
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an isolated privileged Linux namespace; never run on a production host"]
fn real_linux_tun_survives_forward_revoke_and_netd_restart() {
    use candy_netd::{LinuxNetworkBackend, SystemTunFactory};
    use std::process::Command;
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1"),
        "explicit isolated namespace acknowledgement required"
    );
    let path = std::env::temp_dir().join(format!("candy-netd-v2-kernel-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let make_service = || {
        InfrastructureService::new(
            0,
            0,
            SystemTunFactory,
            LinuxNetworkBackend::new().unwrap(),
            InfrastructureJournal::new(path.join("kernel.journal")).unwrap(),
        )
        .unwrap()
    };
    let mut service = make_service();
    let pid = std::process::id();
    let peer = PeerCredentials {
        pid,
        uid: 0,
        gid: 0,
    };
    let call = |service: &mut InfrastructureService<SystemTunFactory, LinuxNetworkBackend>,
                operation| {
        let description = format!("{operation:?}");
        service
            .process(
                Request {
                    request_id: 1,
                    caller_instance_id: [1; 16],
                    caller_pid: pid,
                    operation,
                },
                peer,
                1,
            )
            .unwrap_or_else(|error| panic!("v2 operation {description} failed: {error}"))
    };
    call(&mut service, Operation::InfraEnsure(spec()));
    let command = |arguments: &[&str]| {
        let output = Command::new("ip").args(arguments).output().unwrap();
        assert!(
            output.status.success(),
            "ip failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    let before_link = command(&["-j", "link", "show", "dev", "candy0"]);
    let before_addr = command(&["-j", "addr", "show", "dev", "candy0"]);
    call(
        &mut service,
        Operation::ForwardPrepare {
            infra_id: [2; 16],
            infra_generation: 1,
            owner: owner(),
            declaration: declaration(),
        },
    );
    call(&mut service, Operation::ForwardCommit { owner: owner() });
    assert!(command(&["route", "show", "table", "20000"]).contains("dev candy0"));
    // Exercise the actual connected local UDP socket that failed when a
    // transient handoff installed unreachable routes. Keep this socket and
    // the same TUN queue alive through guard and netd journal recovery.
    let (_, guard_io_fd) = call(
        &mut service,
        Operation::InfraAcquireIoFd {
            infra_id: [2; 16],
            generation: 1,
            io_epoch: 1,
        },
    );
    let guard_io_fd = guard_io_fd.unwrap();
    let udp = std::net::UdpSocket::bind("100.64.0.10:0").unwrap();
    udp.connect("10.2.0.20:9898").unwrap();
    let assert_udp_reaches_tun = |payload: &[u8]| {
        use std::os::fd::AsRawFd;
        assert_eq!(udp.send(payload).unwrap(), payload.len());
        let mut descriptor = nix::libc::pollfd {
            fd: guard_io_fd.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { nix::libc::poll(&mut descriptor, 1, 1000) }, 1);
        let mut packet = [0_u8; 2048];
        let size = unsafe {
            nix::libc::read(
                guard_io_fd.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
            )
        };
        assert!(size >= payload.len() as isize);
        assert!(packet[..size as usize].ends_with(payload));
    };
    assert_udp_reaches_tun(b"before-guard");
    let guard_routes = command(&["-j", "route", "show", "table", "20000"]);
    call(&mut service, Operation::ForwardGuard { owner: owner() });
    assert_eq!(
        guard_routes,
        command(&["-j", "route", "show", "table", "20000"])
    );
    for _ in 0..8 {
        assert_udp_reaches_tun(b"during-guard");
    }
    drop(service);
    let mut service = make_service();
    assert!(matches!(
        call(&mut service, Operation::ForwardStatus).0,
        Body::ForwardStatus {
            phase: Some(Phase::Guarded),
            ..
        }
    ));
    assert_udp_reaches_tun(b"after-guard-recovery");
    drop(udp);
    let before_routes = command(&["-j", "route", "show", "table", "20000"]);
    let (next_owner, next_policy) = candidate();
    call(
        &mut service,
        Operation::ForwardPrepare {
            infra_id: [2; 16],
            infra_generation: 1,
            owner: next_owner.clone(),
            declaration: next_policy,
        },
    );
    assert_eq!(
        before_routes,
        command(&["-j", "route", "show", "table", "20000"])
    );
    call(
        &mut service,
        Operation::ForwardCommit {
            owner: next_owner.clone(),
        },
    );
    let switched_routes = command(&["route", "show", "table", "20000"]);
    assert!(switched_routes.contains("10.3.0.0/16 dev candy0"));
    assert!(!switched_routes.contains("10.2.0.0/16"));
    assert!(
        switched_routes.contains("throw 192.0.2.2"),
        "candidate routes: {switched_routes}"
    );
    assert!(!switched_routes.contains("192.0.2.1"));
    call(
        &mut service,
        Operation::ForwardRevoke {
            owner: next_owner.clone(),
        },
    );
    assert!(command(&["route", "show", "table", "20000"]).contains("unreachable 10.3.0.0/16"));
    let mut renewed_owner = next_owner;
    renewed_owner.fencing_token += 1;
    renewed_owner.worker_epoch += 1;
    renewed_owner.signed_generation += 1;
    call(
        &mut service,
        Operation::ForwardPrepare {
            infra_id: [2; 16],
            infra_generation: 1,
            owner: renewed_owner.clone(),
            declaration: declaration(),
        },
    );
    call(
        &mut service,
        Operation::ForwardCommit {
            owner: renewed_owner,
        },
    );
    assert!(service.recover_expired(1000).unwrap());
    assert!(command(&["route", "show", "table", "20000"]).contains("unreachable 10.2.0.0/16"));
    let before_ifindex =
        serde_json::from_str::<serde_json::Value>(&before_link).unwrap()[0]["ifindex"].clone();
    assert_eq!(
        before_link,
        command(&["-j", "link", "show", "dev", "candy0"])
    );
    assert_eq!(
        before_addr,
        command(&["-j", "addr", "show", "dev", "candy0"])
    );
    drop(service);
    // The real I/O owner remains alive while netd restarts.
    assert_eq!(
        before_ifindex,
        serde_json::from_str::<serde_json::Value>(&command(&[
            "-j", "link", "show", "dev", "candy0"
        ]))
        .unwrap()[0]["ifindex"]
    );
    let service = make_service();
    let io_fd = guard_io_fd;
    let reopened = serde_json::from_str::<serde_json::Value>(&command(&[
        "-j", "link", "show", "dev", "candy0",
    ]))
    .unwrap();
    let initial = serde_json::from_str::<serde_json::Value>(&before_link).unwrap();
    for field in ["ifindex", "ifname", "flags", "mtu"] {
        assert_eq!(
            initial[0][field], reopened[0][field],
            "infrastructure property {field} changed"
        );
    }
    // With a healthy I/O fd retained, netd restart must not alter the queue or issue another reader.
    drop(service);
    let mut service = make_service();
    let duplicate = service.process(
        Request {
            request_id: 2,
            caller_instance_id: [1; 16],
            caller_pid: pid,
            operation: Operation::InfraAcquireIoFd {
                infra_id: [2; 16],
                generation: 1,
                io_epoch: 2,
            },
        },
        peer,
        2,
    );
    assert!(duplicate.is_err());
    assert_eq!(
        before_ifindex,
        serde_json::from_str::<serde_json::Value>(&command(&[
            "-j", "link", "show", "dev", "candy0"
        ]))
        .unwrap()[0]["ifindex"]
    );
    drop(io_fd);
    drop(service);
    // Explicit test cleanup; persistent lifecycle is intentionally independent of service exit.
    command(&["link", "del", "candy0"]);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn missing_owned_device_repair_is_explicit_and_leaves_forwarding_revoked() {
    let mut fixture = Fixture::new("missing-device");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    fixture.observed.lock().unwrap().ifindex = None;
    assert!(fixture
        .call(Operation::ForwardCommit { owner: owner() }, 4)
        .is_err());
    fixture.call(Operation::InfraEnsure(spec()), 5).unwrap();
    assert!(matches!(
        fixture.call(Operation::ForwardStatus, 6).unwrap().0,
        Body::ForwardStatus {
            phase: Some(Phase::Revoked),
            ..
        }
    ));
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
}

#[test]
fn marker_conflicts_and_unjournaled_devices_are_never_adopted() {
    let mut fixture = Fixture::new("ownership_conflict");
    fixture.observed.lock().unwrap().ifindex = Some(17);
    assert!(fixture.call(Operation::InfraEnsure(spec()), 1).is_err());
    assert!(fixture.observed.lock().unwrap().events.is_empty());
    fixture.observed.lock().unwrap().ifindex = None;
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    fixture.observed.lock().unwrap().ownership_marker = Some("external-owner".into());
    let before = fixture.observed.lock().unwrap().events.clone();
    assert!(fixture
        .call(Operation::ForwardCommit { owner: owner() }, 4)
        .is_err());
    assert_eq!(before, fixture.observed.lock().unwrap().events);
}

#[test]
fn transient_marker_failure_retries_owned_creation_without_service_restart() {
    let mut fixture = Fixture::new("marker_retry");
    fixture.observed.lock().unwrap().fail_stamp_once = true;
    assert!(fixture.call(Operation::InfraEnsure(spec()), 1).is_err());
    assert!(fixture.observed.lock().unwrap().ifindex.is_none());
    fixture.service.recover_expired(2).unwrap();
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
    assert!(fixture.observed.lock().unwrap().ownership_marker.is_some());
    let durable: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.path.join("infra.journal")).unwrap()).unwrap();
    assert_eq!(durable["state"]["creation_pending"], false);
}

#[test]
fn exact_failed_prefix_updates_only_routes_and_survive_restart() {
    let mut fixture = Fixture::new("prefix_scope");
    fixture.ensure();
    let mut policy = declaration();
    policy.routes.push(RouteDeclaration {
        prefix: Ipv4Prefix::new([10, 4, 0, 0], 16).unwrap(),
        kind: RouteKind::Remote,
    });
    fixture
        .call(
            Operation::ForwardPrepare {
                infra_id: [2; 16],
                infra_generation: 1,
                owner: owner(),
                declaration: policy.clone(),
            },
            2,
        )
        .unwrap();
    fixture.commit();
    let failed = Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap();
    let before = fixture.observed.lock().unwrap().events.len();
    fixture
        .call(
            Operation::ForwardFailedPrefixes {
                owner: owner(),
                failure_revision: 1,
                failed_prefixes: vec![failed],
            },
            4,
        )
        .unwrap();
    assert_eq!(
        &fixture.observed.lock().unwrap().events[before..],
        &["prefix_routes"]
    );
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 5).unwrap().0,
        Body::ForwardStatus { phase: Some(Phase::Active), failed_prefixes, pending_failed_prefixes: None, .. } if failed_prefixes == vec![failed])
    );
    fixture.service = Fixture::service(&fixture.path, fixture.observed.clone());
    assert!(!fixture.service.recover_expired(6).unwrap());
    let before = fixture.observed.lock().unwrap().events.len();
    assert!(fixture
        .call(
            Operation::ForwardFailedPrefixes {
                owner: owner(),
                failure_revision: 2,
                failed_prefixes: vec![Ipv4Prefix::new([10, 2, 0, 0], 24).unwrap()]
            },
            7
        )
        .is_err());
    let mut stale = owner();
    stale.fencing_token -= 1;
    assert!(fixture
        .call(
            Operation::ForwardFailedPrefixes {
                owner: stale,
                failure_revision: 2,
                failed_prefixes: vec![]
            },
            7
        )
        .is_err());
    assert_eq!(before, fixture.observed.lock().unwrap().events.len());
    fixture
        .call(
            Operation::ForwardFailedPrefixes {
                owner: owner(),
                failure_revision: 2,
                failed_prefixes: vec![],
            },
            8,
        )
        .unwrap();
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
    assert!(fixture.observed.lock().unwrap().failed_prefixes.is_empty());
    assert_eq!(
        &fixture.observed.lock().unwrap().events[before..],
        &["prefix_routes"]
    );
}

#[test]
fn authoritative_failure_revision_recovers_in_same_generation_and_rejects_replay() {
    let mut fixture = Fixture::new("failure_revision");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let failed = Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap();
    let snapshot = |revision, failed_prefixes| Operation::ForwardFailedPrefixes {
        owner: owner(),
        failure_revision: revision,
        failed_prefixes,
    };
    fixture.call(snapshot(10, vec![failed]), 4).unwrap();
    let before = fixture.observed.lock().unwrap().events.len();
    fixture.call(snapshot(10, vec![failed]), 5).unwrap();
    assert_eq!(before, fixture.observed.lock().unwrap().events.len());
    assert!(fixture.call(snapshot(9, vec![]), 6).is_err());
    assert!(fixture.call(snapshot(10, vec![]), 6).is_err());
    fixture.call(snapshot(11, vec![]), 7).unwrap();
    fixture.service = Fixture::service(&fixture.path, fixture.observed.clone());
    assert!(fixture.call(snapshot(10, vec![failed]), 8).is_err());
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 9).unwrap().0,
        Body::ForwardStatus { owner: Some(active), failure_revision: 11,
            pending_failure_revision: None, failed_prefixes, .. }
            if active == owner() && failed_prefixes.is_empty())
    );
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
}

#[test]
fn capabilities_probe_does_not_recover_or_mutate_live_infrastructure() {
    let mut fixture = Fixture::new("read_only_probe");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let journal = fs::read(fixture.path.join("infra.journal")).unwrap();
    let events = fixture.observed.lock().unwrap().events.clone();
    // Even an overdue lease is recovered by the maintenance loop, never by a probe.
    let (body, fd) = fixture.call(Operation::Capabilities, 3000).unwrap();
    assert_eq!(
        body,
        Body::Capabilities {
            version: 2,
            independent_infrastructure: true,
            multi_domain: false
        }
    );
    assert!(fd.is_none());
    assert_eq!(
        fs::read(fixture.path.join("infra.journal")).unwrap(),
        journal
    );
    let observed = fixture.observed.lock().unwrap();
    assert_eq!(observed.events, events);
    assert_eq!(observed.ifindex, Some(17));
    assert!(observed.firewall_present);
}

#[test]
fn lease_renewal_cannot_change_authorization_cap_or_mutate_rejected_state() {
    let mut fixture = Fixture::new("lease_authorization_cap");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let original_status = fixture.call(Operation::ForwardStatus, 4).unwrap().0;
    let original_journal = fs::read(fixture.path.join("infra.journal")).unwrap();
    let original_events = fixture.observed.lock().unwrap().events.clone();
    let original_policy = fixture.observed.lock().unwrap().active_declaration.clone();
    for (cap, lease) in [(3000, 1100), (1900, 1100), (3000, 2500), (2000, 2001)] {
        let mut rejected = owner();
        rejected.auth_deadline_mono_ms = cap;
        rejected.lease_deadline_mono_ms = lease;
        assert!(fixture
            .call(Operation::ForwardLeaseRenew { owner: rejected }, 5)
            .is_err());
        assert_eq!(
            fixture.call(Operation::ForwardStatus, 6).unwrap().0,
            original_status
        );
        assert_eq!(
            fs::read(fixture.path.join("infra.journal")).unwrap(),
            original_journal
        );
        let observed = fixture.observed.lock().unwrap();
        assert_eq!(observed.events, original_events);
        assert_eq!(observed.active_declaration, original_policy);
        assert_eq!(observed.ifindex, Some(17));
        assert!(observed.firewall_present);
    }
    let mut renewed = owner();
    renewed.lease_deadline_mono_ms = renewed.auth_deadline_mono_ms;
    fixture
        .call(
            Operation::ForwardLeaseRenew {
                owner: renewed.clone(),
            },
            7,
        )
        .unwrap();
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 8).unwrap().0,
        Body::ForwardStatus { owner: Some(active), phase: Some(Phase::Active), .. }
        if active == renewed)
    );
    assert_eq!(fixture.observed.lock().unwrap().events, original_events);
    fixture.service = Fixture::service(&fixture.path, fixture.observed.clone());
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 9).unwrap().0,
        Body::ForwardStatus { owner: Some(active), .. } if active == renewed)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn signed_authority_requires_exact_actual_receipt_and_rejects_old_commit() {
    use candy_netd_proto::v2::{ForwardAuthority, ForwardAuthorityReceipt};
    use sha2::{Digest, Sha256};
    let mut fixture = Fixture::new("authority_receipt");
    fixture.ensure();
    let (_body, fd) = fixture
        .call(
            Operation::InfraAcquireIoFd {
                infra_id: [2; 16],
                generation: 1,
                io_epoch: 1,
            },
            1,
        )
        .unwrap();
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let ticks = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    fixture.prepare();
    let authority = ForwardAuthority {
        transaction_id: "a".repeat(32),
        authority_revision: 1,
        signed_control_hash: "b".repeat(64),
        declaration_hash: format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&declaration()).unwrap())
        ),
        snapshot_closure_hash: "c".repeat(64),
        io_epoch: 1,
        io_pid: std::process::id(),
        io_start_ticks: ticks,
        candidate_pid: std::process::id(),
        candidate_start_ticks: ticks,
    };
    fixture
        .call(
            Operation::ForwardAuthorize {
                owner: owner(),
                authority: authority.clone(),
            },
            3,
        )
        .unwrap();
    let original = fs::read(fixture.path.join("infra.journal")).unwrap();
    let original_events = fixture.observed.lock().unwrap().events.clone();
    assert!(fixture
        .call(Operation::ForwardCommit { owner: owner() }, 4)
        .is_err());
    let receipt = ForwardAuthorityReceipt {
        authority: authority.clone(),
        owner_active: true,
        authorization_deadline_mono_ms: owner().auth_deadline_mono_ms,
        packet_proof_reported_mono_ms: 4,
    };
    for index in 0..5 {
        let mut bad = receipt.clone();
        match index {
            0 => bad.authority.transaction_id = "d".repeat(32),
            1 => bad.authority.candidate_start_ticks += 1,
            2 => bad.owner_active = false,
            3 => bad.authorization_deadline_mono_ms += 1,
            _ => bad.packet_proof_reported_mono_ms = 1000,
        }
        assert!(fixture
            .call(
                Operation::ForwardCommitAuthorized {
                    owner: owner(),
                    receipt: bad
                },
                5
            )
            .is_err());
        assert_eq!(
            fs::read(fixture.path.join("infra.journal")).unwrap(),
            original
        );
        assert_eq!(fixture.observed.lock().unwrap().events, original_events);
    }
    fixture
        .call(
            Operation::ForwardCommitAuthorized {
                owner: owner(),
                receipt,
            },
            5,
        )
        .unwrap();
    assert!(matches!(
        fixture.call(Operation::ForwardStatus, 6).unwrap().0,
        Body::ForwardStatus {
            phase: Some(Phase::Active),
            ..
        }
    ));
    drop(fd);
}

#[test]
fn failed_prefix_repair_does_not_block_lease_renewal_and_retries_after_restart() {
    let mut fixture = Fixture::new("prefix_repair");
    fixture.ensure();
    fixture.prepare();
    fixture.commit();
    let failed = Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap();
    fixture.observed.lock().unwrap().fail_prefix_update = true;
    assert!(fixture
        .call(
            Operation::ForwardFailedPrefixes {
                owner: owner(),
                failure_revision: 1,
                failed_prefixes: vec![failed]
            },
            4
        )
        .is_err());
    // A replay does not replace retained intent, and a delayed snapshot cannot clear it.
    assert!(fixture
        .call(
            Operation::ForwardFailedPrefixes {
                owner: owner(),
                failure_revision: 1,
                failed_prefixes: vec![failed],
            },
            4
        )
        .is_err());
    assert!(fixture
        .call(
            Operation::ForwardFailedPrefixes {
                owner: owner(),
                failure_revision: 1,
                failed_prefixes: vec![],
            },
            4
        )
        .is_err());
    let mut renewed = owner();
    renewed.lease_deadline_mono_ms = 1100;
    fixture
        .call(
            Operation::ForwardLeaseRenew {
                owner: renewed.clone(),
            },
            5,
        )
        .unwrap();
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 6).unwrap().0,
        Body::ForwardStatus { owner: Some(active), phase: Some(Phase::Active), pending_failed_prefixes: Some(pending), .. } if active == renewed && pending == vec![failed])
    );
    fixture.observed.lock().unwrap().fail_prefix_update = false;
    fixture.service = Fixture::service(&fixture.path, fixture.observed.clone());
    assert!(fixture.service.recover_expired(7).unwrap());
    assert!(
        matches!(fixture.call(Operation::ForwardStatus, 8).unwrap().0,
        Body::ForwardStatus { phase: Some(Phase::Active), failure_revision: 1, pending_failure_revision: None, failed_prefixes, pending_failed_prefixes: None, .. } if failed_prefixes == vec![failed])
    );
    assert_eq!(fixture.observed.lock().unwrap().ifindex, Some(17));
}

#[test]
fn prepared_failures_are_never_activated_by_commit_and_survive_failed_replacement() {
    let mut fixture = Fixture::new("prefix_prepare");
    fixture.ensure();
    fixture.prepare();
    let failed = Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap();
    let before = fixture.observed.lock().unwrap().events.len();
    fixture
        .call(
            Operation::ForwardFailedPrefixes {
                owner: owner(),
                failure_revision: 1,
                failed_prefixes: vec![failed],
            },
            2,
        )
        .unwrap();
    assert_eq!(before, fixture.observed.lock().unwrap().events.len());
    fixture.commit();
    assert_eq!(
        fixture.observed.lock().unwrap().failed_prefixes,
        vec![failed]
    );
    let (next_owner, next_policy) = candidate();
    prepare_candidate(&mut fixture, &next_owner, &next_policy);
    fixture.observed.lock().unwrap().fail_restore_prefix_once = Some([10, 3, 0, 0]);
    assert!(fixture
        .call(Operation::ForwardCommit { owner: next_owner }, 6)
        .is_err());
    assert_eq!(
        fixture.observed.lock().unwrap().failed_prefixes,
        vec![failed]
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "only run as subprocess of the isolated kernel creation test"]
fn real_linux_creation_crash_child() {
    use candy_netd::{LinuxNetworkBackend, SystemTunFactory};
    let Ok(phase) = std::env::var("CANDY_NETD_CREATION_CRASH_PHASE") else {
        return;
    };
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1")
    );
    struct CrashFactory {
        phase: String,
    }
    impl CrashFactory {
        fn checkpoint(&self, phase: &str) {
            if self.phase == phase {
                assert_eq!(
                    unsafe { nix::libc::kill(std::process::id() as i32, nix::libc::SIGKILL) },
                    0
                );
                unreachable!();
            }
        }
    }
    impl TunFactory for CrashFactory {
        fn create(&mut self) -> Result<OwnedFd, PlatformError> {
            SystemTunFactory.create()
        }
        fn create_persistent(&mut self) -> Result<OwnedFd, PlatformError> {
            SystemTunFactory.create_persistent()
        }
        fn create_exclusive(&mut self) -> Result<OwnedFd, PlatformError> {
            self.checkpoint("before_create");
            let fd = SystemTunFactory.create_exclusive()?;
            self.checkpoint("after_create");
            Ok(fd)
        }
        fn enable_persistence(&mut self, fd: &OwnedFd) -> Result<(), PlatformError> {
            self.checkpoint("after_marker");
            SystemTunFactory.enable_persistence(fd)?;
            self.checkpoint("after_persistence");
            Ok(())
        }
    }
    let path = PathBuf::from(std::env::var("CANDY_NETD_CREATION_JOURNAL").unwrap());
    let mut service = InfrastructureService::new(
        0,
        0,
        CrashFactory { phase },
        LinuxNetworkBackend::new().unwrap(),
        InfrastructureJournal::new(path).unwrap(),
    )
    .unwrap();
    let pid = std::process::id();
    service
        .process(
            Request {
                request_id: 1,
                caller_instance_id: [1; 16],
                caller_pid: pid,
                operation: Operation::InfraEnsure(spec()),
            },
            PeerCredentials {
                pid,
                uid: 0,
                gid: 0,
            },
            1,
        )
        .unwrap();
    panic!("creation crash checkpoint was not reached");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Linux namespace, root, TUN and writable sysctls"]
fn real_linux_creation_crash_recovery_requires_durable_owned_marker() {
    use candy_netd::{LinuxNetworkBackend, SystemTunFactory};
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1")
    );
    assert_eq!(nix::unistd::geteuid().as_raw(), 0);
    for phase in [
        "before_create",
        "after_create",
        "after_marker",
        "after_persistence",
        "external_device",
    ] {
        let path = std::env::temp_dir().join(format!(
            "candy-netd-creation-{}-{phase}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let journal = path.join("infra.journal");
        let child_phase = if phase == "external_device" {
            "before_create"
        } else {
            phase
        };
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "real_linux_creation_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("CANDY_NETD_CREATION_CRASH_PHASE", child_phase)
            .env("CANDY_NETD_CREATION_JOURNAL", &journal)
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL), "phase={phase}");
        let durable: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(durable["state"]["creation_pending"], true);
        assert!(durable["state"]["ownership_marker"]
            .as_str()
            .unwrap()
            .starts_with("candy-infra-v2:"));
        let mut backend = LinuxNetworkBackend::new().unwrap();
        let before_ifindex = backend.interface_identity().unwrap();
        assert_eq!(
            before_ifindex.is_some(),
            phase == "after_persistence",
            "nonpersistent creation leaked at {phase}"
        );
        if phase == "external_device" {
            assert!(Command::new("ip")
                .args(["tuntap", "add", "dev", "candy0", "mode", "tun"])
                .status()
                .unwrap()
                .success());
        }
        let mut service = InfrastructureService::new(
            0,
            0,
            SystemTunFactory,
            LinuxNetworkBackend::new().unwrap(),
            InfrastructureJournal::new(&journal).unwrap(),
        )
        .unwrap();
        if phase == "external_device" {
            assert!(service
                .recover_expired(2)
                .unwrap_err()
                .to_string()
                .contains("infra_ownership_conflict"));
            assert!(
                backend.interface_identity().unwrap().is_some(),
                "foreign device was deleted"
            );
            assert!(
                backend.interface_ownership_marker().unwrap().is_none(),
                "foreign device was marked"
            );
            assert!(Command::new("ip")
                .args(["link", "del", "candy0"])
                .status()
                .unwrap()
                .success());
        } else {
            service.recover_expired(2).unwrap();
            let restored_ifindex = backend.interface_identity().unwrap().unwrap();
            if let Some(old) = before_ifindex {
                assert_eq!(old, restored_ifindex, "owned persistent identity changed");
            }
            assert_eq!(
                backend.interface_ownership_marker().unwrap().as_deref(),
                durable["state"]["ownership_marker"].as_str()
            );
            let pid = std::process::id();
            service
                .process(
                    Request {
                        request_id: 2,
                        caller_instance_id: [1; 16],
                        caller_pid: pid,
                        operation: Operation::InfraRetire {
                            infra_id: [2; 16],
                            generation: 1,
                        },
                    },
                    PeerCredentials {
                        pid,
                        uid: 0,
                        gid: 0,
                    },
                    3,
                )
                .unwrap();
            assert!(backend.interface_identity().unwrap().is_none());
        }
        drop(service);
        fs::remove_dir_all(path).unwrap();
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Linux namespace, root, TUN and writable sysctls"]
fn real_linux_failed_prefix_only_changes_its_route_and_retains_healthy_prefix() {
    use candy_netd::{LinuxNetworkBackend, SystemTunFactory};
    use std::process::Command;
    assert_eq!(
        std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref(),
        Ok("1")
    );
    let path =
        std::env::temp_dir().join(format!("candy-netd-prefix-kernel-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let make_service = || {
        InfrastructureService::new(
            0,
            0,
            SystemTunFactory,
            LinuxNetworkBackend::new().unwrap(),
            InfrastructureJournal::new(path.join("infra.journal")).unwrap(),
        )
        .unwrap()
    };
    let mut service = make_service();
    let pid = std::process::id();
    let call = |service: &mut InfrastructureService<SystemTunFactory, LinuxNetworkBackend>,
                operation| {
        service
            .process(
                Request {
                    request_id: 1,
                    caller_instance_id: [1; 16],
                    caller_pid: pid,
                    operation,
                },
                PeerCredentials {
                    pid,
                    uid: 0,
                    gid: 0,
                },
                1,
            )
            .unwrap()
    };
    let command = |args: &[&str]| {
        let result = Command::new("ip").args(args).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()
    };
    call(&mut service, Operation::InfraEnsure(spec()));
    let mut policy = declaration();
    let failed = policy.routes[0].prefix;
    policy.routes.push(RouteDeclaration {
        prefix: Ipv4Prefix::new([10, 4, 0, 0], 16).unwrap(),
        kind: RouteKind::Remote,
    });
    call(
        &mut service,
        Operation::ForwardPrepare {
            infra_id: [2; 16],
            infra_generation: 1,
            owner: owner(),
            declaration: policy.clone(),
        },
    );
    call(&mut service, Operation::ForwardCommit { owner: owner() });
    let (_, io_fd) = call(
        &mut service,
        Operation::InfraAcquireIoFd {
            infra_id: [2; 16],
            generation: 1,
            io_epoch: 1,
        },
    );
    let link = command(&["-j", "link", "show", "dev", "candy0"]);
    let address = command(&["-j", "addr", "show", "dev", "candy0"]);
    let rules = command(&["-j", "rule", "show"]);
    let before = command(&["-j", "route", "show", "table", "20000"]);
    let route = |routes: &serde_json::Value, prefix: &str| {
        routes
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["dst"] == prefix)
            .cloned()
            .unwrap()
    };
    let healthy = route(&before, "10.4.0.0/16");
    let original_failed = route(&before, "10.2.0.0/16");
    call(
        &mut service,
        Operation::ForwardFailedPrefixes {
            owner: owner(),
            failure_revision: 1,
            failed_prefixes: vec![failed],
        },
    );
    let withdrawn = command(&["-j", "route", "show", "table", "20000"]);
    assert_eq!(route(&withdrawn, "10.2.0.0/16")["type"], "unreachable");
    assert_eq!(route(&withdrawn, "10.4.0.0/16"), healthy);
    assert_eq!(command(&["-j", "link", "show", "dev", "candy0"]), link);
    assert_eq!(command(&["-j", "addr", "show", "dev", "candy0"]), address);
    assert_eq!(command(&["-j", "rule", "show"]), rules);
    drop(service);
    let mut service = make_service();
    assert!(!service.recover_expired(2).unwrap());
    assert_eq!(
        command(&["-j", "route", "show", "table", "20000"]),
        withdrawn
    );
    call(
        &mut service,
        Operation::ForwardFailedPrefixes {
            owner: owner(),
            failure_revision: 2,
            failed_prefixes: vec![],
        },
    );
    let recovered = command(&["-j", "route", "show", "table", "20000"]);
    assert_eq!(route(&recovered, "10.2.0.0/16"), original_failed);
    assert_eq!(route(&recovered, "10.4.0.0/16"), healthy);
    assert_eq!(command(&["-j", "rule", "show"]), rules);
    assert_eq!(command(&["-j", "link", "show", "dev", "candy0"]), link);
    drop(io_fd);
    drop(service);
    let durable: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("infra.journal")).unwrap()).unwrap();
    let sysctls: Vec<SysctlChange> =
        serde_json::from_value(durable["state"]["sysctls"].clone()).unwrap();
    // Explicit isolated test teardown after all fd holders exited; production retains infrastructure.
    let mut cleanup = LinuxNetworkBackend::new().unwrap();
    cleanup.remove_firewall(&policy).unwrap();
    cleanup.retire_forwarding(&policy).unwrap();
    cleanup.restore_sysctls(&policy, &sysctls).unwrap();
    assert!(Command::new("ip")
        .args(["link", "del", "candy0"])
        .status()
        .unwrap()
        .success());
    fs::remove_dir_all(path).unwrap();
}
