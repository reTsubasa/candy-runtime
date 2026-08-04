use candy_netd_proto::{LeaseOwner, PrepareDeclaration};
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
    RollingBack,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TransactionRecord {
    pub owner: LeaseOwner,
    pub declaration: PrepareDeclaration,
    pub phase: TransactionPhase,
    pub completed_steps: u16,
    pub sysctls: Vec<SysctlChange>,
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
    fn rollback(&mut self, owner: LeaseOwner) -> Result<(), NetworkError>;
    fn renew_lease(&mut self, owner: LeaseOwner) -> Result<(), NetworkError>;
    fn update_mtu(&mut self, owner: LeaseOwner, effective_mtu: u16) -> Result<(), NetworkError>;
    fn recover_orphan(
        &mut self,
        owner_is_alive: bool,
        now_mono_ms: u64,
    ) -> Result<bool, NetworkError>;
    fn retained_owner(&self) -> Option<LeaseOwner>;
}

#[derive(Debug, Default)]
pub struct NoopNetworkController;

impl NetworkController for NoopNetworkController {
    fn prepare(
        &mut self,
        _owner: LeaseOwner,
        _declaration: PrepareDeclaration,
    ) -> Result<(), NetworkError> {
        Ok(())
    }

    fn commit(&mut self, _owner: LeaseOwner) -> Result<(), NetworkError> {
        Ok(())
    }

    fn rollback(&mut self, _owner: LeaseOwner) -> Result<(), NetworkError> {
        Ok(())
    }

    fn renew_lease(&mut self, _owner: LeaseOwner) -> Result<(), NetworkError> {
        Ok(())
    }

    fn update_mtu(&mut self, _owner: LeaseOwner, _effective_mtu: u16) -> Result<(), NetworkError> {
        Err(NetworkError::InvalidTransition)
    }

    fn recover_orphan(
        &mut self,
        _owner_is_alive: bool,
        _now_mono_ms: u64,
    ) -> Result<bool, NetworkError> {
        Ok(false)
    }

    fn retained_owner(&self) -> Option<LeaseOwner> {
        None
    }
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
                TransactionPhase::Preparing | TransactionPhase::RollingBack => {
                    Err(NetworkError::InvalidTransition)
                }
            };
        }

        declaration.validate().map_err(|_| NetworkError::Backend)?;
        let record = TransactionRecord {
            owner,
            declaration,
            phase: TransactionPhase::Preparing,
            completed_steps: 0,
            sysctls: Vec::new(),
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
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        ensure_owner(record.owner, owner)?;
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

    pub fn rollback(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        let record = self
            .record
            .as_ref()
            .ok_or(NetworkError::InvalidTransition)?;
        ensure_owner(record.owner, owner)?;
        self.cleanup_record()
    }

    pub fn recover_orphan(
        &mut self,
        owner_is_alive: bool,
        now_mono_ms: u64,
    ) -> Result<bool, NetworkError> {
        let Some(record) = &self.record else {
            return Ok(false);
        };
        if owner_is_alive && record.owner.lease_deadline_mono_ms > now_mono_ms {
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
        ensure_owner(record.owner, owner)?;
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
        cleanup_step!(
            steps & STEP_SYSCTLS != 0,
            self.backend.restore_sysctls(declaration, &record.sysctls),
            STEP_SYSCTLS
        );

        if self
            .record
            .as_ref()
            .is_some_and(|record| record.completed_steps == 0)
        {
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

    fn rollback(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        Self::rollback(self, owner)
    }

    fn renew_lease(&mut self, owner: LeaseOwner) -> Result<(), NetworkError> {
        Self::renew_lease(self, owner)
    }

    fn update_mtu(&mut self, owner: LeaseOwner, effective_mtu: u16) -> Result<(), NetworkError> {
        Self::update_mtu(self, owner, effective_mtu)
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

pub fn restore_sysctl_value<'a>(
    original: &'a str,
    applied: &str,
    current: &str,
) -> Option<&'a str> {
    (original != applied && current == applied).then_some(original)
}
