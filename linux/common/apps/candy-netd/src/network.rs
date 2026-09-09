use candy_netd_proto::{Ipv4Prefix, LeaseOwner, PrepareDeclaration};
use thiserror::Error;

const STEP_LINK: u16 = 1 << 0;
const STEP_ROUTES: u16 = 1 << 1;
const STEP_FIREWALL: u16 = 1 << 2;
const STEP_SYSCTLS: u16 = 1 << 3;
const STEP_LINK_ACTIVE: u16 = 1 << 4;
const STEP_POLICY_RULE: u16 = 1 << 5;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TransactionPhase {
    Preparing,
    Prepared,
    Active,
    Suspended,
    RollingBack,
    Draining,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TransactionRecord {
    pub owner: LeaseOwner,
    pub declaration: PrepareDeclaration,
    pub recovery_candidate: Option<PrepareDeclaration>,
    /// Owner for the candidate declaration. The active owner remains in
    /// `owner` until drain completes, but recovery must promote this owner.
    pub recovery_candidate_owner: Option<LeaseOwner>,
    pub phase: TransactionPhase,
    pub completed_steps: u16,
    pub sysctls: Vec<SysctlChange>,
    /// Monotonic deadline after which an old declaration may be retired.
    /// Zero means the caller must explicitly drain without a time gate.
    pub drain_deadline_mono_ms: u64,
    /// Prefixes currently withdrawn from the active declaration.
    pub failed_prefixes: Vec<Ipv4Prefix>,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SysctlKey {
    Ipv4Forward = 1,
    AllRpFilter = 2,
    CandyRpFilter = 3,
}

impl TryFrom<u8> for SysctlKey {
    type Error = NetworkError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ipv4Forward),
            2 => Ok(Self::AllRpFilter),
            3 => Ok(Self::CandyRpFilter),
            _ => Err(NetworkError::Journal),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SysctlChange {
    pub key: SysctlKey,
    pub original: u8,
    pub applied: u8,
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("network transaction owner or generation conflicts with retained state")]
    Conflict,
    #[error("network transaction is invalid for its current phase")]
    InvalidTransition,
    #[error("network backend operation failed")]
    Backend,
    #[error("network transaction journal operation failed")]
    Journal,
    #[error("network transaction is still draining the previous declaration")]
    DrainPending,
}

pub trait NetworkBackend {
    fn preflight(
        &mut self,
        declaration: &PrepareDeclaration,
    ) -> Result<Vec<SysctlChange>, NetworkError>;
    fn prepare_link(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    fn prepare_routes(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    fn prepare_firewall(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    fn prepare_sysctls(
        &mut self,
        declaration: &PrepareDeclaration,
        changes: &[SysctlChange],
    ) -> Result<(), NetworkError>;
    fn activate_link(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    fn update_link_mtu(
        &mut self,
        _declaration: &PrepareDeclaration,
        _effective_mtu: u16,
    ) -> Result<(), NetworkError> {
        Err(NetworkError::Backend)
    }
    fn install_policy_rule(&mut self, declaration: &PrepareDeclaration)
        -> Result<(), NetworkError>;
    fn remove_policy_rule(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    fn deactivate_link(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    fn remove_firewall(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    fn remove_routes(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    fn withdraw_prefixes(
        &mut self,
        declaration: &PrepareDeclaration,
        prefixes: &[Ipv4Prefix],
    ) -> Result<(), NetworkError> {
        let mut scoped = declaration.clone();
        scoped
            .routes
            .retain(|route| prefixes.contains(&route.prefix));
        if scoped.routes.is_empty() {
            return Ok(());
        }
        self.remove_routes(&scoped)
    }
    fn remove_link(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError>;
    fn restore_sysctls(
        &mut self,
        declaration: &PrepareDeclaration,
        changes: &[SysctlChange],
    ) -> Result<(), NetworkError>;
}

pub trait NetworkJournal {
    fn load(&self) -> Result<Option<TransactionRecord>, NetworkError>;
    fn store(&mut self, record: &TransactionRecord) -> Result<(), NetworkError>;
    fn clear(&mut self) -> Result<(), NetworkError>;
}

pub trait NetworkController {
    fn prepare(
        &mut self,
        owner: LeaseOwner,
        declaration: PrepareDeclaration,
    ) -> Result<(), NetworkError>;
    fn commit(&mut self, owner: LeaseOwner) -> Result<(), NetworkError>;
    /// Commit a prepared replacement while retaining the old declaration.
    /// The default keeps older controllers source-compatible.
    fn commit_with_drain(
        &mut self,
        owner: LeaseOwner,
        _now_mono_ms: u64,
        _drain_timeout_ms: u64,
    ) -> Result<(), NetworkError> {
        self.commit(owner)
    }
    fn drain_old(&mut self, _owner: LeaseOwner, _now_mono_ms: u64) -> Result<(), NetworkError> {
        Err(NetworkError::InvalidTransition)
    }
    fn set_failed_prefixes(
        &mut self,
        owner: LeaseOwner,
        prefixes: &[Ipv4Prefix],
    ) -> Result<(), NetworkError> {
        let _ = (owner, prefixes);
        Err(NetworkError::InvalidTransition)
    }
    fn rollback(&mut self, owner: LeaseOwner) -> Result<(), NetworkError>;
    fn renew_lease(&mut self, owner: LeaseOwner) -> Result<(), NetworkError>;
    fn update_mtu(&mut self, owner: LeaseOwner, effective_mtu: u16) -> Result<(), NetworkError>;
    fn suspend(&mut self, _owner: LeaseOwner) -> Result<(), NetworkError> {
        Err(NetworkError::InvalidTransition)
    }
    fn reconfigure(
        &mut self,
        _owner: LeaseOwner,
        _declaration: PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        Err(NetworkError::InvalidTransition)
    }
    fn resume(&mut self, _owner: LeaseOwner) -> Result<(), NetworkError> {
        Err(NetworkError::InvalidTransition)
    }
    fn recover_orphan(
        &mut self,
        owner_is_alive: bool,
        now_mono_ms: u64,
    ) -> Result<bool, NetworkError>;
    fn retained_owner(&self) -> Option<LeaseOwner>;
}

pub struct NetworkTransaction<B, J> {
    backend: B,
    journal: J,
    record: Option<TransactionRecord>,
}

impl<B: NetworkBackend, J: NetworkJournal> NetworkTransaction<B, J> {
    pub fn new(backend: B, journal: J) -> Result<Self, NetworkError> {
        let record = journal.load()?;
        Ok(Self {
            backend,
            journal,
            record,
        })
    }

    pub fn prepare(
        &mut self,
        owner: LeaseOwner,
        declaration: PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        if let Some(record) = &self.record {
            ensure_owner(record.owner, owner)?;
            if record.declaration != declaration {
                return Err(NetworkError::Conflict);
            }
            return match record.phase {
                TransactionPhase::Prepared | TransactionPhase::Active => Ok(()),
                TransactionPhase::Preparing
                | TransactionPhase::Suspended
                | TransactionPhase::RollingBack
                | TransactionPhase::Draining => Err(NetworkError::InvalidTransition),
            };
        }

        declaration.validate().map_err(|_| NetworkError::Backend)?;
        let record = TransactionRecord {
            owner,
            declaration,
            recovery_candidate: None,
            recovery_candidate_owner: None,
            phase: TransactionPhase::Preparing,
            completed_steps: 0,
            sysctls: Vec::new(),
            drain_deadline_mono_ms: 0,
            failed_prefixes: Vec::new(),
        };
        self.journal.store(&record)?;
        self.record = Some(record);

        let result = self.prepare_steps();
        if result.is_err() {
            let _ = self.cleanup_record();
        }
        result
    }

    fn prepare_steps(&mut self) -> Result<(), NetworkError> {
        let declaration = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?
            .declaration
            .clone();
        let sysctls = self.backend.preflight(&declaration)?;
        let record = self
            .record
            .as_mut()
            .ok_or(NetworkError::InvalidTransition)?;
        record.sysctls = sysctls;
        self.journal.store(record)?;
        self.complete_step(STEP_LINK)?;
        self.backend.prepare_link(&declaration)?;
        self.complete_step(STEP_ROUTES)?;
        self.backend.prepare_routes(&declaration)?;
        self.complete_step(STEP_FIREWALL)?;
        self.backend.prepare_firewall(&declaration)?;
        self.complete_step(STEP_SYSCTLS)?;
        let sysctls = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?
            .sysctls
            .clone();
        self.backend.prepare_sysctls(&declaration, &sysctls)?;
        self.set_phase(TransactionPhase::Prepared)
    }

    pub fn commit(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        self.commit_with_drain(owner, 0, 0)
    }

    pub fn commit_with_drain(
        &mut self,
        owner: LeaseOwner,
        now_mono_ms: u64,
        drain_timeout_ms: u64,
    ) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        if record.recovery_candidate.is_some() {
            ensure_reconfigure_owner(record.owner, owner)?;
        } else {
            ensure_owner(record.owner, owner)?;
        }
        if record.phase == TransactionPhase::Draining {
            return Ok(());
        }
        if record.phase == TransactionPhase::Prepared {
            if let Some(candidate) = record.recovery_candidate.clone() {
                let result = (|| {
                    self.backend.activate_link(&candidate)?;
                    self.backend.install_policy_rule(&candidate)?;
                    let record = self
                        .record
                        .as_mut()
                        .ok_or(NetworkError::InvalidTransition)?;
                    record.phase = TransactionPhase::Draining;
                    record.drain_deadline_mono_ms = now_mono_ms.saturating_add(drain_timeout_ms);
                    self.journal.store(record)
                })();
                if result.is_err() {
                    let _ = self.backend.remove_policy_rule(&candidate);
                    let _ = self.backend.remove_firewall(&candidate);
                    let _ = self.backend.remove_routes(&candidate);
                    // Candidate activation is pre-commit from netd's point
                    // of view.  Restore the durable record to the old Active
                    // owner so Runtime can enter its independent Proxy
                    // fallback; leaving Prepared+candidate here makes the
                    // subsequent Suspend request fail and strands recovery.
                    if let Some(record) = self.record.as_mut() {
                        record.recovery_candidate = None;
                        record.recovery_candidate_owner = None;
                        record.phase = TransactionPhase::Active;
                        record.drain_deadline_mono_ms = 0;
                        let _ = self.journal.store(record);
                    }
                }
                return result;
            }
        }
        if record.phase == TransactionPhase::Active {
            return Ok(());
        }
        if record.phase != TransactionPhase::Prepared {
            return Err(NetworkError::InvalidTransition);
        }
        let declaration = record.declaration.clone();
        let result = (|| {
            self.complete_step(STEP_LINK_ACTIVE)?;
            self.backend.activate_link(&declaration)?;
            self.complete_step(STEP_POLICY_RULE)?;
            self.backend.install_policy_rule(&declaration)?;
            self.set_phase(TransactionPhase::Active)
        })();
        if result.is_err() {
            let _ = self.cleanup_record();
        }
        result
    }

    pub fn drain_old(&mut self, owner: LeaseOwner, now_mono_ms: u64) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        if record.recovery_candidate.is_some() {
            ensure_reconfigure_owner(record.owner, owner)?;
        } else {
            ensure_owner(record.owner, owner)?;
        }
        if record.phase != TransactionPhase::Draining {
            return Err(NetworkError::InvalidTransition);
        }
        if record.drain_deadline_mono_ms != 0 && now_mono_ms < record.drain_deadline_mono_ms {
            return Err(NetworkError::DrainPending);
        }
        let candidate = record
            .recovery_candidate
            .clone()
            .ok_or(NetworkError::InvalidTransition)?;
        let candidate_owner = record.recovery_candidate_owner.unwrap_or(owner);
        let previous = record.declaration.clone();
        // The candidate rule is installed first. Removing the old declaration
        // therefore cannot create a forwarding gap; different table IDs keep
        // route/rule deletion scoped to the old generation.
        self.backend.remove_policy_rule(&previous)?;
        self.backend.remove_firewall(&previous)?;
        self.backend.remove_routes(&previous)?;
        let record = self
            .record
            .as_mut()
            .ok_or(NetworkError::InvalidTransition)?;
        record.owner = candidate_owner;
        record.declaration = candidate;
        record.recovery_candidate = None;
        record.recovery_candidate_owner = None;
        record.phase = TransactionPhase::Active;
        record.drain_deadline_mono_ms = 0;
        self.journal.store(record)
    }

    pub fn rollback(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        if record.recovery_candidate.is_some()
            && matches!(
                record.phase,
                TransactionPhase::Preparing | TransactionPhase::Prepared
            )
        {
            ensure_reconfigure_owner(record.owner, owner)?;
            let candidate = record
                .recovery_candidate
                .clone()
                .ok_or(NetworkError::InvalidTransition)?;
            self.backend.remove_firewall(&candidate)?;
            self.backend.remove_routes(&candidate)?;
            let record = self
                .record
                .as_mut()
                .ok_or(NetworkError::InvalidTransition)?;
            record.recovery_candidate = None;
            record.recovery_candidate_owner = None;
            record.phase = TransactionPhase::Active;
            record.drain_deadline_mono_ms = 0;
            self.journal.store(record)?;
            return Ok(());
        }
        ensure_owner(record.owner, owner)?;
        self.cleanup_record()
    }

    pub fn withdraw_prefixes(
        &mut self,
        owner: LeaseOwner,
        prefixes: &[Ipv4Prefix],
    ) -> Result<(), NetworkError> {
        if prefixes.is_empty() {
            return Err(NetworkError::InvalidTransition);
        }
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        ensure_owner(record.owner, owner)?;
        if record.phase != TransactionPhase::Active {
            return Err(NetworkError::InvalidTransition);
        }
        let declaration = record.declaration.clone();
        self.backend.withdraw_prefixes(&declaration, prefixes)
    }

    pub fn set_failed_prefixes(
        &mut self,
        owner: LeaseOwner,
        prefixes: &[Ipv4Prefix],
    ) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        ensure_owner(record.owner, owner)?;
        if record.phase != TransactionPhase::Active {
            return Err(NetworkError::InvalidTransition);
        }
        let declaration = record.declaration.clone();
        self.backend.prepare_routes(&declaration)?;
        let record = self
            .record
            .as_mut()
            .ok_or(NetworkError::InvalidTransition)?;
        record.failed_prefixes = prefixes.to_vec();
        record.failed_prefixes.sort();
        record.failed_prefixes.dedup();
        if !record.failed_prefixes.is_empty() {
            self.backend
                .withdraw_prefixes(&declaration, &record.failed_prefixes)?;
        }
        self.journal.store(record)
    }

    pub fn recover_orphan(
        &mut self,
        owner_is_alive: bool,
        now_mono_ms: u64,
    ) -> Result<bool, NetworkError> {
        let Some(record) = &self.record else {
            return Ok(false);
        };
        // A replacement candidate is staged beside the last-good declaration.
        // If the process disappears before commit, discard only the candidate
        // and leave the old owner active; do not run the normal full cleanup.
        if record.recovery_candidate.is_some()
            && matches!(
                record.phase,
                TransactionPhase::Preparing | TransactionPhase::Prepared
            )
        {
            if owner_is_alive && record.owner.lease_deadline_mono_ms > now_mono_ms {
                return Ok(false);
            }
            let candidate = record
                .recovery_candidate
                .clone()
                .ok_or(NetworkError::InvalidTransition)?;
            self.backend.remove_firewall(&candidate)?;
            self.backend.remove_routes(&candidate)?;
            let record = self
                .record
                .as_mut()
                .ok_or(NetworkError::InvalidTransition)?;
            record.recovery_candidate = None;
            record.recovery_candidate_owner = None;
            record.phase = TransactionPhase::Active;
            record.drain_deadline_mono_ms = 0;
            self.journal.store(record)?;
            return Ok(true);
        }
        if record.phase == TransactionPhase::Draining {
            if owner_is_alive
                && (record.drain_deadline_mono_ms == 0
                    || now_mono_ms < record.drain_deadline_mono_ms)
            {
                return Ok(false);
            }
            let candidate_owner = record.recovery_candidate_owner.unwrap_or(record.owner);
            return self.drain_old(candidate_owner, now_mono_ms).map(|_| true);
        }
        // RollingBack is a poisoned reconfigure session, not a healthy lease.
        // Recover it immediately even when the former owner process is still
        // alive; waiting for lease expiry would leave candidate routes behind
        // and the owner cannot safely resume this transaction.
        if record.phase != TransactionPhase::RollingBack
            && owner_is_alive
            && record.owner.lease_deadline_mono_ms > now_mono_ms
        {
            return Ok(false);
        }
        self.cleanup_record()?;
        Ok(true)
    }

    pub fn renew_lease(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_mut()
            .ok_or(NetworkError::InvalidTransition)?;
        if record.recovery_candidate.is_some() {
            ensure_reconfigure_owner(record.owner, owner)?;
        } else {
            ensure_owner(record.owner, owner)?;
        }
        record.owner.lease_deadline_mono_ms = owner.lease_deadline_mono_ms;
        self.journal.store(record)
    }

    pub fn update_mtu(
        &mut self,
        owner: LeaseOwner,
        effective_mtu: u16,
    ) -> Result<(), NetworkError> {
        if !(576..=1400).contains(&effective_mtu) {
            return Err(NetworkError::InvalidTransition);
        }
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        ensure_owner(record.owner, owner)?;
        if record.phase != TransactionPhase::Active
            || effective_mtu >= record.declaration.effective_mtu
        {
            return Err(NetworkError::InvalidTransition);
        }
        let mut declaration = record.declaration.clone();
        self.backend.update_link_mtu(&declaration, effective_mtu)?;
        declaration.effective_mtu = effective_mtu;
        let record = self
            .record
            .as_mut()
            .ok_or(NetworkError::InvalidTransition)?;
        record.declaration = declaration;
        self.journal.store(record)
    }

    pub fn suspend(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        ensure_owner(record.owner, owner)?;
        if record.phase == TransactionPhase::Suspended {
            return Ok(());
        }
        if record.phase != TransactionPhase::Active {
            return Err(NetworkError::InvalidTransition);
        }
        let declaration = record.declaration.clone();
        self.backend.remove_policy_rule(&declaration)?;
        self.clear_step(STEP_POLICY_RULE)?;
        self.set_phase(TransactionPhase::Suspended)
    }

    pub fn reconfigure(
        &mut self,
        owner: LeaseOwner,
        declaration: PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        declaration.validate().map_err(|_| NetworkError::Backend)?;
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        // A suspended replacement is an in-place transaction: the process and
        // instance remain authenticated, while Cloud advances (or rolls back)
        // the immutable generation. The owner is committed below only after
        // the replacement network state has been prepared successfully.
        ensure_reconfigure_owner(record.owner, owner)?;
        if record.phase == TransactionPhase::Active {
            return self.prepare_replacement(owner, declaration);
        }
        if record.phase != TransactionPhase::Suspended {
            return Err(NetworkError::InvalidTransition);
        }
        let previous_record = record.clone();
        let previous = previous_record.declaration.clone();
        if previous == declaration {
            let mut replacement_record = previous_record;
            replacement_record.owner = owner;
            self.journal.store(&replacement_record)?;
            self.record = Some(replacement_record);
            return Ok(());
        }
        // In-place reconfigure owns routes/firewall only. Changing link
        // identity would add a second TUN address or move tables without a
        // reversible backend operation, so require a fresh Prepare instead.
        if previous.firewall != declaration.firewall
            || previous.table_id != declaration.table_id
            || previous.overlay_router_ipv4 != declaration.overlay_router_ipv4
            || previous.effective_mtu != declaration.effective_mtu
        {
            return Err(NetworkError::InvalidTransition);
        }

        // Persist recovery intent before touching either declaration. A crash
        // or a failed restoration must never leave a durable `Suspended`
        // record that a later Resume request could activate. RollingBack is a
        // poisoned session: only rollback/orphan recovery may operate on it.
        {
            let record = self
                .record
                .as_mut()
                .ok_or(NetworkError::InvalidTransition)?;
            record.phase = TransactionPhase::RollingBack;
            record.recovery_candidate = Some(declaration.clone());
            record.recovery_candidate_owner = Some(owner);
            self.journal.store(record)?;
        }
        let applied = (|| {
            // Cleanup may mutate part of the old rules before returning an
            // error. It belongs to the rollback transaction just as much as
            // installing the candidate; never resume a half-removed policy.
            self.backend.remove_firewall(&previous)?;
            self.backend.remove_routes(&previous)?;
            self.backend.prepare_link(&declaration)?;
            self.backend.prepare_routes(&declaration)?;
            self.backend.prepare_firewall(&declaration)
        })();
        if let Err(error) = applied {
            return match self.restore_suspended_after_reconfigure(&previous_record, &declaration) {
                Ok(()) => Err(error),
                Err(recovery_error) => Err(recovery_error),
            };
        }
        let mut replacement_record = previous_record.clone();
        replacement_record.owner = owner;
        replacement_record.declaration = declaration;
        replacement_record.failed_prefixes.clear();
        replacement_record.drain_deadline_mono_ms = 0;
        if let Err(error) = self.journal.store(&replacement_record) {
            // Keep the in-memory record and durable journal aligned with the
            // network state. A journal failure must not leave a new owner
            // generation pointing at a declaration that cannot be recovered.
            return match self.restore_suspended_after_reconfigure(
                &previous_record,
                &replacement_record.declaration,
            ) {
                Ok(()) => Err(error),
                Err(recovery_error) => Err(recovery_error),
            };
        }
        self.record = Some(replacement_record);
        Ok(())
    }

    /// Prepare a replacement while retaining the current active declaration.
    /// A distinct policy table is mandatory because the Linux backend cannot
    /// tag two generations that share the same route/rule key.
    fn prepare_replacement(
        &mut self,
        owner: LeaseOwner,
        declaration: PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        ensure_reconfigure_owner(record.owner, owner)?;
        if record.declaration == declaration {
            // A generation-only retry still transfers lease ownership.  The
            // declaration is already active, so no replacement candidate is
            // needed, but retaining the old owner would make the following
            // Commit/LeaseRenew fail with a generation conflict.
            let mut record = record.clone();
            record.owner = owner;
            self.journal.store(&record)?;
            self.record = Some(record);
            return Ok(());
        }
        if record.declaration.table_id == declaration.table_id
            || record.declaration.firewall != declaration.firewall
            || record.declaration.overlay_router_ipv4 != declaration.overlay_router_ipv4
            || record.declaration.effective_mtu != declaration.effective_mtu
        {
            return Err(NetworkError::InvalidTransition);
        }
        if let Some(candidate) = &record.recovery_candidate {
            return if candidate == &declaration {
                Ok(())
            } else {
                Err(NetworkError::Conflict)
            };
        }
        {
            let record = self
                .record
                .as_mut()
                .ok_or(NetworkError::InvalidTransition)?;
            record.recovery_candidate = Some(declaration.clone());
            record.recovery_candidate_owner = Some(owner);
            record.phase = TransactionPhase::Preparing;
            record.drain_deadline_mono_ms = 0;
            self.journal.store(record)?;
        }
        let prepared = (|| {
            declaration.validate().map_err(|_| NetworkError::Backend)?;
            self.backend.preflight(&declaration)?;
            self.backend.prepare_link(&declaration)?;
            self.backend.prepare_routes(&declaration)?;
            self.backend.prepare_firewall(&declaration)
        })();
        if let Err(error) = prepared {
            let _ = self.backend.remove_firewall(&declaration);
            let _ = self.backend.remove_routes(&declaration);
            let record = self
                .record
                .as_mut()
                .ok_or(NetworkError::InvalidTransition)?;
            record.recovery_candidate = None;
            record.recovery_candidate_owner = None;
            record.phase = TransactionPhase::Active;
            let _ = self.journal.store(record);
            return Err(error);
        }
        let record = self
            .record
            .as_mut()
            .ok_or(NetworkError::InvalidTransition)?;
        record.phase = TransactionPhase::Prepared;
        self.journal.store(record)
    }

    fn restore_suspended_after_reconfigure(
        &mut self,
        previous_record: &TransactionRecord,
        candidate: &PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        let mut first_error = None;
        for result in [
            self.backend.remove_firewall(candidate),
            self.backend.remove_routes(candidate),
            self.backend.prepare_link(&previous_record.declaration),
            self.backend.prepare_routes(&previous_record.declaration),
            self.backend.prepare_firewall(&previous_record.declaration),
        ] {
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            // Keep the in-memory and durable RollingBack phase. In particular,
            // do not install a policy rule over partially restored routes.
            return Err(error);
        }
        self.journal.store(previous_record)?;
        self.record = Some(previous_record.clone());
        Ok(())
    }

    pub fn resume(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        ensure_owner(record.owner, owner)?;
        if record.phase == TransactionPhase::Active {
            return Ok(());
        }
        if record.phase != TransactionPhase::Suspended {
            return Err(NetworkError::InvalidTransition);
        }
        let declaration = record.declaration.clone();
        self.backend.install_policy_rule(&declaration)?;
        self.complete_step(STEP_POLICY_RULE)?;
        self.set_phase(TransactionPhase::Active)
    }

    fn cleanup_record(&mut self) -> Result<(), NetworkError> {
        self.set_phase(TransactionPhase::RollingBack)?;
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?
            .clone();
        let declaration = &record.declaration;
        let steps = record.completed_steps;

        let mut first_error = None;
        if let Some(candidate) = record.recovery_candidate.as_ref() {
            let mut candidate_error = None;
            for result in [
                self.backend.remove_firewall(candidate),
                self.backend.remove_routes(candidate),
            ] {
                if let Err(error) = result {
                    candidate_error.get_or_insert(error);
                }
            }
            if let Some(error) = candidate_error {
                first_error.get_or_insert(error);
            } else {
                let current = self
                    .record
                    .as_mut()
                    .ok_or(NetworkError::InvalidTransition)?;
                current.recovery_candidate = None;
                current.recovery_candidate_owner = None;
                if let Err(error) = self.journal.store(current) {
                    first_error.get_or_insert(error);
                }
            }
        }
        macro_rules! cleanup_step {
            ($needed:expr, $operation:expr, $step:expr) => {
                if $needed {
                    match $operation {
                        Ok(()) => {
                            if let Err(error) = self.clear_step($step) {
                                first_error.get_or_insert(error);
                            }
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    }
                }
            };
        }

        cleanup_step!(
            steps & STEP_POLICY_RULE != 0,
            self.backend.remove_policy_rule(declaration),
            STEP_POLICY_RULE
        );
        cleanup_step!(
            steps & (STEP_LINK | STEP_LINK_ACTIVE) != 0,
            self.backend.deactivate_link(declaration),
            STEP_LINK_ACTIVE
        );
        cleanup_step!(
            steps & STEP_SYSCTLS != 0,
            self.backend.restore_sysctls(declaration, &record.sysctls),
            STEP_SYSCTLS
        );
        cleanup_step!(
            steps & STEP_FIREWALL != 0,
            self.backend.remove_firewall(declaration),
            STEP_FIREWALL
        );
        cleanup_step!(
            steps & STEP_ROUTES != 0,
            self.backend.remove_routes(declaration),
            STEP_ROUTES
        );
        cleanup_step!(
            steps & STEP_LINK != 0,
            self.backend.remove_link(declaration),
            STEP_LINK
        );

        if self.record.as_ref().is_some_and(|record| {
            record.completed_steps == 0 && record.recovery_candidate.is_none()
        }) {
            match self.journal.clear() {
                Ok(()) => self.record = None,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn complete_step(&mut self, step: u16) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_mut()
            .ok_or(NetworkError::InvalidTransition)?;
        record.completed_steps |= step;
        self.journal.store(record)
    }

    fn clear_step(&mut self, step: u16) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_mut()
            .ok_or(NetworkError::InvalidTransition)?;
        record.completed_steps &= !step;
        self.journal.store(record)
    }

    fn set_phase(&mut self, phase: TransactionPhase) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_mut()
            .ok_or(NetworkError::InvalidTransition)?;
        record.phase = phase;
        self.journal.store(record)
    }
}

impl<B: NetworkBackend, J: NetworkJournal> NetworkController for NetworkTransaction<B, J> {
    fn prepare(
        &mut self,
        owner: LeaseOwner,
        declaration: PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        Self::prepare(self, owner, declaration)
    }

    fn commit(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        Self::commit(self, owner)
    }

    fn commit_with_drain(
        &mut self,
        owner: LeaseOwner,
        now_mono_ms: u64,
        drain_timeout_ms: u64,
    ) -> Result<(), NetworkError> {
        Self::commit_with_drain(self, owner, now_mono_ms, drain_timeout_ms)
    }

    fn drain_old(&mut self, owner: LeaseOwner, now_mono_ms: u64) -> Result<(), NetworkError> {
        Self::drain_old(self, owner, now_mono_ms)
    }

    fn set_failed_prefixes(
        &mut self,
        owner: LeaseOwner,
        prefixes: &[candy_netd_proto::Ipv4Prefix],
    ) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        ensure_owner(record.owner, owner)?;
        if record.phase != TransactionPhase::Active {
            return Err(NetworkError::InvalidTransition);
        }
        let declaration = record.declaration.clone();
        if prefixes.is_empty() {
            self.backend.prepare_routes(&declaration)?;
        } else {
            self.backend.withdraw_prefixes(&declaration, prefixes)?;
        }
        Ok(())
    }

    fn rollback(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        Self::rollback(self, owner)
    }

    fn renew_lease(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        Self::renew_lease(self, owner)
    }

    fn update_mtu(&mut self, owner: LeaseOwner, effective_mtu: u16) -> Result<(), NetworkError> {
        Self::update_mtu(self, owner, effective_mtu)
    }

    fn suspend(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        Self::suspend(self, owner)
    }

    fn reconfigure(
        &mut self,
        owner: LeaseOwner,
        declaration: PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        Self::reconfigure(self, owner, declaration)
    }

    fn resume(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        Self::resume(self, owner)
    }

    fn recover_orphan(
        &mut self,
        owner_is_alive: bool,
        now_mono_ms: u64,
    ) -> Result<bool, NetworkError> {
        Self::recover_orphan(self, owner_is_alive, now_mono_ms)
    }

    fn retained_owner(&self) -> Option<LeaseOwner> {
        self.record.as_ref().map(|record| record.owner)
    }
}

fn ensure_owner(retained: LeaseOwner, request: LeaseOwner) -> Result<(), NetworkError> {
    if retained.instance_id == request.instance_id
        && retained.pid == request.pid
        && retained.generation == request.generation
    {
        Ok(())
    } else {
        Err(NetworkError::Conflict)
    }
}

fn ensure_reconfigure_owner(retained: LeaseOwner, request: LeaseOwner) -> Result<(), NetworkError> {
    if retained.instance_id == request.instance_id && retained.pid == request.pid {
        Ok(())
    } else {
        Err(NetworkError::Conflict)
    }
}

pub fn restore_sysctl_value<'a>(
    original: &'a str,
    applied: &str,
    current: &str,
) -> Option<&'a str> {
    (original != applied && current == applied).then_some(original)
}
