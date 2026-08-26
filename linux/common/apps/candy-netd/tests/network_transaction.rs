use candy_netd::{
    restore_sysctl_value, NetworkBackend, NetworkError, NetworkJournal, NetworkTransaction,
    TransactionRecord,
};
use candy_netd_proto::{
    FirewallPolicy, Ipv4Prefix, LeaseOwner, PrepareDeclaration, RouteDeclaration, RouteKind,
    UnderlayExclusion, UnderlayKind, CANDY_TABLE_MIN,
};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
struct RecordingBackend(Rc<RefCell<Vec<&'static str>>>);

impl RecordingBackend {
    fn event(&self, value: &'static str) {
        self.0.borrow_mut().push(value);
    }
}

struct FailingBackend {
    inner: RecordingBackend,
    fail_at: &'static str,
}

struct CleanupFailingBackend {
    inner: RecordingBackend,
    fail_at: &'static str,
}

impl CleanupFailingBackend {
    fn cleanup(&self, step: &'static str) -> Result<(), NetworkError> {
        self.inner.event(step);
        if step == self.fail_at {
            Err(NetworkError::Backend)
        } else {
            Ok(())
        }
    }
}

impl FailingBackend {
    fn check(&self, step: &'static str) -> Result<(), NetworkError> {
        self.inner.event(step);
        if step == self.fail_at {
            Err(NetworkError::Backend)
        } else {
            Ok(())
        }
    }
}

impl NetworkBackend for FailingBackend {
    fn preflight(
        &mut self,
        _declaration: &PrepareDeclaration,
    ) -> Result<Vec<candy_netd::SysctlChange>, NetworkError> {
        self.check("preflight")?;
        Ok(Vec::new())
    }

    fn prepare_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.check("prepare_link")
    }
    fn prepare_routes(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.check("prepare_routes")
    }
    fn prepare_firewall(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.check("prepare_firewall")
    }
    fn prepare_sysctls(
        &mut self,
        _: &PrepareDeclaration,
        _: &[candy_netd::SysctlChange],
    ) -> Result<(), NetworkError> {
        self.check("prepare_sysctls")
    }
    fn activate_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.check("activate_link")
    }
    fn install_policy_rule(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.check("install_policy_rule")
    }
    fn remove_policy_rule(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.inner.event("remove_policy_rule");
        Ok(())
    }
    fn deactivate_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.inner.event("deactivate_link");
        Ok(())
    }
    fn remove_firewall(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.inner.event("remove_firewall");
        Ok(())
    }
    fn remove_routes(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.inner.event("remove_routes");
        Ok(())
    }
    fn remove_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.inner.event("remove_link");
        Ok(())
    }
    fn restore_sysctls(
        &mut self,
        _: &PrepareDeclaration,
        _: &[candy_netd::SysctlChange],
    ) -> Result<(), NetworkError> {
        self.inner.event("restore_sysctls");
        Ok(())
    }
}

impl NetworkBackend for RecordingBackend {
    fn preflight(
        &mut self,
        _declaration: &PrepareDeclaration,
    ) -> Result<Vec<candy_netd::SysctlChange>, NetworkError> {
        self.event("preflight");
        Ok(Vec::new())
    }

    fn prepare_link(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("prepare_link");
        Ok(())
    }

    fn prepare_routes(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("prepare_routes");
        Ok(())
    }

    fn prepare_firewall(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("prepare_firewall");
        Ok(())
    }

    fn prepare_sysctls(
        &mut self,
        _declaration: &PrepareDeclaration,
        _changes: &[candy_netd::SysctlChange],
    ) -> Result<(), NetworkError> {
        self.event("prepare_sysctls");
        Ok(())
    }

    fn activate_link(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("activate_link");
        Ok(())
    }

    fn install_policy_rule(
        &mut self,
        _declaration: &PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        self.event("install_policy_rule");
        Ok(())
    }

    fn remove_policy_rule(
        &mut self,
        _declaration: &PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        self.event("remove_policy_rule");
        Ok(())
    }

    fn deactivate_link(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("deactivate_link");
        Ok(())
    }

    fn remove_firewall(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("remove_firewall");
        Ok(())
    }

    fn remove_routes(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("remove_routes");
        Ok(())
    }

    fn remove_link(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.event("remove_link");
        Ok(())
    }

    fn restore_sysctls(
        &mut self,
        _declaration: &PrepareDeclaration,
        _changes: &[candy_netd::SysctlChange],
    ) -> Result<(), NetworkError> {
        self.event("restore_sysctls");
        Ok(())
    }
}

impl NetworkBackend for CleanupFailingBackend {
    fn preflight(
        &mut self,
        _declaration: &PrepareDeclaration,
    ) -> Result<Vec<candy_netd::SysctlChange>, NetworkError> {
        Ok(Vec::new())
    }

    fn prepare_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        Ok(())
    }
    fn prepare_routes(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        Ok(())
    }
    fn prepare_firewall(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        Ok(())
    }
    fn prepare_sysctls(
        &mut self,
        _: &PrepareDeclaration,
        _: &[candy_netd::SysctlChange],
    ) -> Result<(), NetworkError> {
        Ok(())
    }
    fn activate_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        Ok(())
    }
    fn install_policy_rule(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        Ok(())
    }
    fn remove_policy_rule(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.cleanup("remove_policy_rule")
    }
    fn deactivate_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.cleanup("deactivate_link")
    }
    fn remove_firewall(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.cleanup("remove_firewall")
    }
    fn remove_routes(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.cleanup("remove_routes")
    }
    fn remove_link(&mut self, _: &PrepareDeclaration) -> Result<(), NetworkError> {
        self.cleanup("remove_link")
    }
    fn restore_sysctls(
        &mut self,
        _: &PrepareDeclaration,
        _: &[candy_netd::SysctlChange],
    ) -> Result<(), NetworkError> {
        self.cleanup("restore_sysctls")
    }
}

#[derive(Clone, Default)]
struct MemoryJournal(Rc<RefCell<Option<TransactionRecord>>>);

impl NetworkJournal for MemoryJournal {
    fn load(&self) -> Result<Option<TransactionRecord>, NetworkError> {
        Ok(self.0.borrow().clone())
    }

    fn store(&mut self, record: &TransactionRecord) -> Result<(), NetworkError> {
        *self.0.borrow_mut() = Some(record.clone());
        Ok(())
    }

    fn clear(&mut self) -> Result<(), NetworkError> {
        *self.0.borrow_mut() = None;
        Ok(())
    }
}

fn owner() -> LeaseOwner {
    LeaseOwner {
        instance_id: [1; 16],
        pid: 4242,
        generation: 7,
        lease_deadline_mono_ms: 50_000,
    }
}

fn declaration() -> PrepareDeclaration {
    PrepareDeclaration {
        table_id: CANDY_TABLE_MIN,
        overlay_router_ipv4: [100, 64, 0, 10],
        effective_mtu: 1180,
        routes: vec![
            RouteDeclaration {
                prefix: Ipv4Prefix::new([10, 1, 0, 0], 16).unwrap(),
                kind: RouteKind::Local,
            },
            RouteDeclaration {
                prefix: Ipv4Prefix::new([10, 2, 0, 0], 16).unwrap(),
                kind: RouteKind::Remote,
            },
        ],
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
    }
}

#[test]
fn commit_installs_policy_rule_only_after_all_prepared_state() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let backend = RecordingBackend(events.clone());
    let journal = MemoryJournal::default();
    let mut transaction = NetworkTransaction::new(backend, journal).unwrap();
    transaction.prepare(owner(), declaration()).unwrap();
    transaction.commit(owner()).unwrap();
    assert_eq!(
        *events.borrow(),
        [
            "preflight",
            "prepare_link",
            "prepare_routes",
            "prepare_firewall",
            "prepare_sysctls",
            "activate_link",
            "install_policy_rule",
        ]
    );
}

#[test]
fn rollback_restores_interface_sysctls_before_removing_link() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let backend = RecordingBackend(events.clone());
    let journal = MemoryJournal::default();
    let mut transaction = NetworkTransaction::new(backend, journal).unwrap();
    transaction.prepare(owner(), declaration()).unwrap();
    transaction.commit(owner()).unwrap();
    events.borrow_mut().clear();
    transaction.rollback(owner()).unwrap();
    assert_eq!(
        *events.borrow(),
        [
            "remove_policy_rule",
            "deactivate_link",
            "restore_sysctls",
            "remove_firewall",
            "remove_routes",
            "remove_link",
        ]
    );
}

#[test]
fn orphan_recovery_uses_persisted_steps_and_clears_journal() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let backend = RecordingBackend(events.clone());
    let journal = MemoryJournal::default();
    let retained = journal.clone();
    let mut transaction = NetworkTransaction::new(backend, journal).unwrap();
    transaction.prepare(owner(), declaration()).unwrap();
    drop(transaction);

    let backend = RecordingBackend(events.clone());
    let mut recovered = NetworkTransaction::new(backend, retained.clone()).unwrap();
    events.borrow_mut().clear();
    assert!(recovered.recover_orphan(false, 49_000).unwrap());
    assert!(retained.load().unwrap().is_none());
    assert_eq!(
        *events.borrow(),
        [
            "deactivate_link",
            "restore_sysctls",
            "remove_firewall",
            "remove_routes",
            "remove_link",
        ]
    );
}

#[test]
fn sysctl_restore_requires_the_value_candy_applied_to_still_be_current() {
    assert_eq!(restore_sysctl_value("0", "1", "1"), Some("0"));
    assert_eq!(restore_sysctl_value("0", "1", "2"), None);
    assert_eq!(restore_sysctl_value("1", "1", "1"), None);
}

#[test]
fn every_mutating_failure_uses_recorded_intent_for_cleanup() {
    for fail_at in [
        "prepare_link",
        "prepare_routes",
        "prepare_firewall",
        "prepare_sysctls",
    ] {
        let events = Rc::new(RefCell::new(Vec::new()));
        let backend = FailingBackend {
            inner: RecordingBackend(events),
            fail_at,
        };
        let journal = MemoryJournal::default();
        let retained = journal.clone();
        let mut transaction = NetworkTransaction::new(backend, journal).unwrap();
        assert!(transaction.prepare(owner(), declaration()).is_err());
        assert!(retained.load().unwrap().is_none(), "failure at {fail_at}");
    }
}

#[test]
fn commit_failure_removes_policy_rule_before_other_state() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let backend = FailingBackend {
        inner: RecordingBackend(events.clone()),
        fail_at: "install_policy_rule",
    };
    let journal = MemoryJournal::default();
    let retained = journal.clone();
    let mut transaction = NetworkTransaction::new(backend, journal).unwrap();
    transaction.prepare(owner(), declaration()).unwrap();
    events.borrow_mut().clear();
    assert!(transaction.commit(owner()).is_err());
    assert_eq!(events.borrow()[2], "remove_policy_rule");
    assert!(retained.load().unwrap().is_none());
}

#[test]
fn cleanup_continues_after_failure_and_retains_only_failed_intent() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let journal = MemoryJournal::default();
    let retained = journal.clone();
    let mut transaction = NetworkTransaction::new(
        CleanupFailingBackend {
            inner: RecordingBackend(events.clone()),
            fail_at: "remove_firewall",
        },
        journal,
    )
    .unwrap();
    transaction.prepare(owner(), declaration()).unwrap();
    transaction.commit(owner()).unwrap();
    assert!(transaction.rollback(owner()).is_err());
    assert_eq!(
        *events.borrow(),
        [
            "remove_policy_rule",
            "deactivate_link",
            "restore_sysctls",
            "remove_firewall",
            "remove_routes",
            "remove_link",
        ]
    );
    assert!(retained.load().unwrap().is_some());

    let mut recovered =
        NetworkTransaction::new(RecordingBackend(events), retained.clone()).unwrap();
    recovered.recover_orphan(false, 0).unwrap();
    assert!(retained.load().unwrap().is_none());
}
