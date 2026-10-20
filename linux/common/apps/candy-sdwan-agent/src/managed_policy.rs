//! Publish policy on a live packet owner; an uncertain ACK never authorizes replacement.
use super::*;

// Keep the existing owner alive for bounded candidate preparation, installation
// and negotiated drain. This threshold schedules a real renewal, never extends
// the physical cap from a later policy envelope.
const AUTHORITY_RENEWAL_LEAD_SECS: u64 = 120;

pub(super) fn authority_renewal_due(deadline: u64, now: u64) -> bool {
    deadline.saturating_sub(now) <= AUTHORITY_RENEWAL_LEAD_SECS
}

pub(super) fn authority_refresh_needed(current: &Plan, desired: &Plan, now: u64) -> bool {
    desired.auth_deadline_unix > current.auth_deadline_unix
        && authority_renewal_due(current.auth_deadline_unix, now)
}

fn hot_policy_eligible(
    current: &Plan,
    desired: &Plan,
    current_report: &serde_json::Value,
    desired_report: &serde_json::Value,
) -> bool {
    let same_verified_hash = |field: &str| {
        current_report[field]
            .as_str()
            .is_some_and(|hash| hash.len() == 64 && desired_report[field].as_str() == Some(hash))
    };
    current.independent_worker.is_some()
        && current.infrastructure == desired.infrastructure
        && current.domain_id == desired.domain_id
        && same_io_lineage(current, desired)
        && current.core == desired.core
        && current.tunio == desired.tunio
        && current.routing_namespace == desired.routing_namespace
        && current.placement == desired.placement
        && serde_json::to_value(&current.shared_listener).ok()
            == serde_json::to_value(&desired.shared_listener).ok()
        && current.auth_deadline_unix <= desired.auth_deadline_unix
        && desired.signed_generation >= current.signed_generation
        && current.declaration.table_id == desired.declaration.table_id
        && current.declaration.overlay_router_ipv4 == desired.declaration.overlay_router_ipv4
        && current.declaration.effective_mtu == desired.declaration.effective_mtu
        && current.declaration.exclusions == desired.declaration.exclusions
        && current.declaration.firewall == desired.declaration.firewall
        && same_verified_hash("transport_fingerprint")
        && same_verified_hash("trust_sha256")
        && same_verified_hash("resource_contract_sha256")
        && [
            "tenant_id",
            "segment_id",
            "site_id",
            "attachment_id",
            "device_id",
            "device_key_id",
        ]
        .iter()
        .all(|field| {
            current_report[*field].as_str().is_some()
                && current_report[*field] == desired_report[*field]
        })
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
mod linux {
    use super::*;
    use crate::process_record::ManagedProcessRecord;
    use crate::signed_snapshot::Snapshot;
    use candy_process_control::ProcessIdentity;
    use candy_tunio::authority_control::AuthorityControlResponse;

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PolicyJournal {
        schema_version: u8,
        snapshot: Snapshot,
        plan: Plan,
        worker: ManagedProcessRecord,
        owner: ForwardOwner,
        revision: u64,
    }

    fn publish<T: Serialize>(path: &Path, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        anyhow::ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "policy journal exceeds budget"
        );
        let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let result = (|| -> Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            File::open(path.parent().context("policy journal parent absent")?)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn read(path: &Path) -> Result<PolicyJournal> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        anyhow::ensure!(
            meta.is_file()
                && meta.uid() == nix::unistd::geteuid().as_raw()
                && meta.mode() & 0o777 == 0o600
                && meta.len() <= 16 * 1024 * 1024,
            "policy journal must be a private bounded regular file"
        );
        let journal: PolicyJournal = serde_json::from_reader(file.take(16 * 1024 * 1024 + 1))?;
        anyhow::ensure!(journal.schema_version == 1, "policy journal schema differs");
        Ok(journal)
    }

    fn validate_owner(
        plan: &Plan,
        record: &ManagedProcessRecord,
        actual: &AuthorityControlResponse,
        live: bool,
    ) -> Result<()> {
        anyhow::ensure!(
            actual.pending.is_none()
                && actual
                    .owner_transaction
                    .as_ref()
                    .is_none_or(|receipt| receipt.phase != "prepared")
                && actual.retained_owner_binding.is_none(),
            "pending authority prevents policy publication"
        );
        anyhow::ensure!(
            actual
                .owner_highest_revision
                .is_none_or(|revision| revision <= actual.authority_revision.unwrap_or(0)),
            "unknown prepared owner revision prevents policy publication"
        );
        if live {
            record.validate_identity(&plan.core, unix_time()?)?;
            anyhow::ensure!(
                record.business_is_current()?,
                "policy worker is no longer live"
            );
        }
        let binding = actual.current_binding;
        anyhow::ensure!(
            (!live || actual.owner_active)
                && binding.owner_epoch == plan.worker_epoch
                && binding.policy_generation == binding_policy_generation(plan)
                && binding.io_epoch == plan.io_epoch
                && binding.routing_domain_id == plan.domain_id
                && binding.infrastructure_id == plan.infrastructure.infra_id
                && binding.infrastructure_generation == plan.infrastructure.generation
                && (!live
                    || actual
                        .actual_deadline_mono_ms
                        .map_or(plan.authority.is_none(), |cap| monotonic_ms()
                            .is_ok_and(|now| now < cap))),
            "policy publication does not match exact live IO authority"
        );
        let status = record.private_status()?;
        anyhow::ensure!(
            status["schema_version"] == 3
                && status["pid"] == record.pid
                && status["generation"] == binding_policy_generation(plan)
                && status["auth_deadline_unix"] == plan.auth_deadline_unix
                && status["packet_binding"] == serde_json::to_value(binding)?
                && status["readiness_token"].as_str().is_some_and(|token| {
                    use sha2::{Digest, Sha256};
                    format!("{:x}", Sha256::digest(token.as_bytes()))
                        == record.readiness_token_sha256
                }),
            "live policy process status differs from original physical authority"
        );
        match (&plan.authority, &actual.active) {
            (Some(authority), Some(active)) => {
                anyhow::ensure!(
                    actual.applied_transaction_id.as_deref()
                        == Some(authority.transaction_id.as_str())
                        && actual.authority_revision == Some(authority.revision)
                        && active.signed_control_hash == authority.sha256
                        && active.candidate
                            == ProcessIdentity {
                                pid: record.pid,
                                start_ticks: record.process_start_ticks
                            }
                        && active.binding == binding
                        && status["worker_authority_revision"] == authority.revision
                        && status["worker_authority_sha256"] == authority.sha256
                        && status["worker_transaction_id"] == authority.transaction_id,
                    "policy publication differs from original signed owner authority"
                );
            }
            (None, None) => anyhow::ensure!(
                actual.highest_revision == 0
                    && actual.applied_transaction_id.is_none()
                    && status["worker_authority_revision"].is_null(),
                "bootstrap policy authority is not pristine"
            ),
            _ => bail!("policy owner authority is inconsistent"),
        }
        if live {
            validate_worker_placement(plan, record, &status)?;
        }
        Ok(())
    }

    fn same_physical_owner(left: &ForwardOwner, right: &ForwardOwner) -> bool {
        left.domain_id == right.domain_id
            && left.signed_generation == right.signed_generation
            && left.worker_epoch == right.worker_epoch
            && left.fencing_token == right.fencing_token
            && left.auth_deadline_mono_ms == right.auth_deadline_mono_ms
    }

    fn renew_preflight_lease(plan: &Plan) -> Result<bool> {
        let mut netd = NetdControl::new(plan);
        let (status, fd) = netd.exchange(Operation::ForwardStatus)?;
        let Body::ForwardStatus {
            owner: Some(mut owner),
            phase: Some(phase),
            candidate_owner: None,
            pending_policy_revision: None,
            pending_failure_revision: None,
            pending_failed_prefixes: None,
            ..
        } = status
        else {
            bail!("policy preflight requires exact active owner without pending transactions");
        };
        let now = monotonic_ms()?;
        anyhow::ensure!(
            fd.is_none()
                && owner.domain_id == plan.domain_id
                && owner.signed_generation == binding_policy_generation(plan)
                && owner.worker_epoch == plan.worker_epoch
                && owner.fencing_token == plan.fencing_token,
            "policy preflight forwarding authority changed physical identity"
        );
        if phase != candy_netd_proto::v2::Phase::Active
            || now >= owner.auth_deadline_mono_ms
            || now >= owner.lease_deadline_mono_ms
        {
            return Ok(false);
        }
        owner.lease_deadline_mono_ms = now
            .saturating_add(30_000)
            .min(owner.auth_deadline_mono_ms)
            .max(owner.lease_deadline_mono_ms);
        expect_ack(&mut netd, Operation::ForwardLeaseRenew { owner })?;
        Ok(true)
    }

    /// Reconcile mutable lease metadata without changing the frozen policy or physical authority.
    /// A revoked exact owner is terminal only after Netd has fenced every partial policy effect.
    fn reconcile_lease(journal: &mut PolicyJournal, path: &Path) -> Result<Option<Body>> {
        let mut netd = NetdControl::new(&journal.plan);
        let (status, fd) = netd.exchange(Operation::ForwardStatus)?;
        let terminal_evidence = status.clone();
        let Body::ForwardStatus {
            owner: Some(owner),
            phase: Some(phase),
            candidate_owner: None,
            last_fencing_token,
            active_policy_revision,
            active_policy_generation,
            active_policy_hash,
            pending_policy_revision,
            pending_failure_revision: None,
            pending_failed_prefixes: None,
            ..
        } = status
        else {
            bail!("code=managed_policy_owner_unknown module=sdwan_activation action=preserve_original_intent");
        };
        anyhow::ensure!(
            fd.is_none()
                && same_physical_owner(&journal.owner, &owner)
                && last_fencing_token == owner.fencing_token,
            "pending policy forwarding owner changed physical identity"
        );
        let now = monotonic_ms()?;
        if phase == candy_netd_proto::v2::Phase::Revoked {
            anyhow::ensure!(
                pending_policy_revision.is_none()
                    && (now >= owner.lease_deadline_mono_ms || now >= owner.auth_deadline_mono_ms),
                "revoked policy owner lacks terminal expiry evidence"
            );
            return Ok(Some(terminal_evidence));
        }
        anyhow::ensure!(
            phase == candy_netd_proto::v2::Phase::Active
                && now < owner.auth_deadline_mono_ms
                && now < owner.lease_deadline_mono_ms
                && pending_policy_revision.is_none_or(|revision| revision == journal.revision)
                && active_policy_revision <= journal.revision
                && (active_policy_revision != journal.revision
                    || (active_policy_generation == Some(journal.plan.signed_generation)
                        && active_policy_hash.as_deref()
                            == journal.plan.authorization_snapshot_sha256.as_deref())),
            "pending policy requires exact live forwarding owner and revision"
        );
        let mut renewed = owner;
        if renewed.lease_deadline_mono_ms.saturating_sub(now) <= 15_000 {
            renewed.lease_deadline_mono_ms = now
                .saturating_add(30_000)
                .min(renewed.auth_deadline_mono_ms);
            expect_ack(
                &mut netd,
                Operation::ForwardLeaseRenew {
                    owner: renewed.clone(),
                },
            )
            .context(ManagedProofPending)?;
        }
        if journal.owner != renewed {
            journal.owner = renewed;
            publish(path, journal)?;
        }
        Ok(None)
    }

    fn core_ack(plan: &Plan, record: &ManagedProcessRecord) -> Result<()> {
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(policy_reload_socket(plan)?)?;
        let peer =
            nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)?;
        anyhow::ensure!(
            peer.pid() == record.pid as i32
                && peer.uid() == record.uid
                && candy_process_control::process_is_current_confirmed(ProcessIdentity {
                    pid: record.pid,
                    start_ticks: record.process_start_ticks,
                })?,
            "policy ACK socket does not belong to the exact managed process"
        );
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(&serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"action":"policy_update", "config":plan.core_config,
            "status":plan.core_status,
            "policy_revision":plan.policy_revision,
        }))?)?;
        stream.shutdown(Shutdown::Write)?;
        let mut bytes = Vec::new();
        stream.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 64 * 1024, "policy ACK exceeds budget");
        let response: crate::CoreReloadResponse = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(response.schema_version == 1 && response.ok
            && response.generation == Some(binding_policy_generation(plan))
            && response.policy_generation == Some(plan.signed_generation),
            "code=managed_policy_ack_pending module=sdwan_activation detail={} action=retry_exact_policy_preserve_live_owner",
            response.error.as_deref().unwrap_or("invalid_policy_receipt"));
        Ok(())
    }

    /// Returns false before dispatch or after an exact expired owner is provably fenced.
    pub(in crate::experimental_tunio) fn try_update(
        desired: &Plan,
        current: &Plan,
        record: &ManagedProcessRecord,
        actual: &AuthorityControlResponse,
    ) -> Result<bool> {
        let record_path = &desired
            .independent_worker
            .as_ref()
            .context("policy worker absent")?
            .process_record;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(record_path.with_extension("policy-update.lock"))?;
        let metadata = lock.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.uid() == nix::unistd::geteuid().as_raw()
                && metadata.mode() & 0o777 == 0o600,
            "policy transaction lock is not private"
        );
        anyhow::ensure!(
            unsafe { nix::libc::flock(lock.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) }
                == 0,
            "policy transaction already has a controller"
        );
        let journal_path = record_path.with_extension("policy-update.json");
        let mut journal = if journal_path.try_exists()? {
            read(&journal_path)?
        } else {
            if authority_refresh_needed(current, desired, unix_time()?)
                || unix_time()? >= current.auth_deadline_unix
            {
                return Ok(false);
            }
            if !actual.owner_active || !record.business_is_current()? {
                return Ok(false);
            }
            validate_owner(current, record, actual, true)?;
            if !renew_preflight_lease(current)? {
                return Ok(false);
            }
            let (current, current_report) = compile_verified_plan(current.clone())?;
            if !renew_preflight_lease(&current)? {
                return Ok(false);
            }
            let (desired, desired_report) = compile_verified_plan(desired.clone())?;
            if !renew_preflight_lease(&current)? {
                return Ok(false);
            }
            if authority_refresh_needed(&current, &desired, unix_time()?) {
                return Ok(false);
            }
            if !hot_policy_eligible(&current, &desired, &current_report, &desired_report) {
                return Ok(false);
            }
            anyhow::ensure!(
                current_report["authorization_snapshot_sha256"].as_str()
                    == record.authorization_snapshot_sha256.as_deref(),
                "recorded active policy differs from verified current snapshot"
            );
            validate_owner(&current, record, actual, true)?;
            let mut netd = NetdControl::new(&current);
            let (status, fd) = netd.exchange(Operation::ForwardStatus)?;
            let Body::ForwardStatus {
                owner: Some(owner),
                phase: Some(phase),
                candidate_owner: None,
                active_policy_revision,
                active_policy_generation,
                active_policy_hash,
                pending_policy_revision: None,
                pending_failure_revision: None,
                pending_failed_prefixes: None,
                ..
            } = status
            else {
                bail!("pending forwarding transaction prevents policy publication");
            };
            if phase != candy_netd_proto::v2::Phase::Active {
                return Ok(false);
            }
            anyhow::ensure!(
                fd.is_none()
                    && owner.domain_id == current.domain_id
                    && owner.signed_generation == binding_policy_generation(&current)
                    && owner.worker_epoch == current.worker_epoch
                    && active_policy_revision == current.policy_revision
                    && (current.policy_revision == 0
                        || (active_policy_generation == Some(current.signed_generation)
                            && active_policy_hash.as_deref()
                                == current.authorization_snapshot_sha256.as_deref())),
                "policy forwarding owner or active revision differs from live packet owner"
            );
            let parent = record_path
                .parent()
                .context("policy snapshot parent absent")?;
            let snapshot = Snapshot::capture(&desired.core_config, parent)?;
            let mut cleanup = crate::signed_snapshot::CleanupGuard::new(&snapshot);
            let mut verified = desired;
            verified.core_config = snapshot.config.clone();
            let (verified, verified_report) = compile_verified_plan(verified)?;
            if !renew_preflight_lease(&current)? {
                return Ok(false);
            }
            anyhow::ensure!(
                hot_policy_eligible(&current, &verified, &current_report, &verified_report),
                "policy snapshot changed transport identity or original authority cap"
            );
            let mut plan = current.clone();
            plan.signed_generation = verified.signed_generation;
            plan.binding_policy_generation = Some(binding_policy_generation(&current));
            plan.core_config = verified.core_config;
            plan.declaration = verified.declaration;
            plan.authorization_snapshot_sha256 = Some(
                verified_report["authorization_snapshot_sha256"]
                    .as_str()
                    .context("verified policy hash absent")?
                    .to_owned(),
            );
            plan.effective_plan_file = Some(parent.join(format!(
                "policy-{}-plan.json",
                uuid::Uuid::new_v4().simple()
            )));
            let journal = PolicyJournal {
                schema_version: 1,
                snapshot,
                plan,
                worker: record.clone(),
                owner,
                revision: active_policy_revision
                    .checked_add(1)
                    .context("policy revision exhausted")?,
            };
            let mut journal = journal;
            journal.plan.policy_revision = journal.revision;
            // From this durable intent onward every failure is UNKNOWN, never MBB.
            if let Err(error) = publish(&journal_path, &journal) {
                if journal_path.try_exists()? {
                    cleanup.transfer();
                }
                return Err(error);
            }
            cleanup.transfer();
            journal
        };
        journal.snapshot.verify()?;
        anyhow::ensure!(
            record.pid == journal.worker.pid
                && record.process_start_ticks == journal.worker.process_start_ticks
                && current.domain_id == journal.plan.domain_id
                && current.infrastructure == journal.plan.infrastructure,
            "pending policy transaction belongs to a different physical owner"
        );
        anyhow::ensure!(
            actual.pending.is_none()
                && actual.retained_owner_binding.is_none()
                && actual
                    .owner_transaction
                    .as_ref()
                    .is_none_or(|receipt| receipt.phase != "prepared")
                && actual
                    .owner_highest_revision
                    .is_none_or(|revision| revision <= actual.authority_revision.unwrap_or(0))
                && actual.current_binding.owner_epoch == journal.plan.worker_epoch
                && actual.current_binding.policy_generation
                    == binding_policy_generation(&journal.plan)
                && actual.current_binding.io_epoch == journal.plan.io_epoch
                && actual.current_binding.routing_domain_id == journal.plan.domain_id,
            "unresolved IO authority prevents policy recovery"
        );
        validate_owner(&journal.plan, &journal.worker, actual, false)?;
        if let Some(terminal_status) = reconcile_lease(&mut journal, &journal_path)? {
            let terminal = journal_path.with_extension(format!(
                "policy-terminal-{}.json",
                uuid::Uuid::new_v4().simple()
            ));
            publish(
                &terminal,
                &serde_json::json!({
                    "schema_version":1, "code":"managed_policy_owner_expired",
                    "observed_mono_ms":monotonic_ms()?, "netd_status":terminal_status,
                    "io_authority":actual,"intent":journal,
                }),
            )?;
            fs::remove_file(&journal_path)?;
            File::open(
                journal_path
                    .parent()
                    .context("policy journal parent absent")?,
            )?
            .sync_all()?;
            eprintln!("level=warn code=managed_policy_owner_expired module=sdwan_activation policy_revision={} evidence={} action=retain_terminal_intent_and_renew_authority", journal.revision, terminal.display());
            return Ok(false);
        }
        validate_owner(&journal.plan, &journal.worker, actual, true)?;
        // The idempotent exact snapshot also recovers ACK loss and process restart.
        // Publishing a process/Cloud receipt before this response is forbidden.
        anyhow::ensure!(
            actual
                .actual_deadline_mono_ms
                .is_none_or(|cap| journal.owner.auth_deadline_mono_ms <= cap),
            "pending policy owner exceeds original IO authority cap"
        );
        core_ack(&journal.plan, &journal.worker).context(ManagedProofPending)?;
        let acknowledged = journal.worker.private_status()?;
        anyhow::ensure!(
            acknowledged["policy_generation"] == journal.plan.signed_generation
                && acknowledged["policy_revision"] == journal.revision
                && acknowledged["authorization_snapshot_sha256"].as_str()
                    == journal.plan.authorization_snapshot_sha256.as_deref(),
            "Core ACK lacks matching durable active policy status"
        );
        let mut netd = NetdControl::new(&journal.plan);
        expect_ack(
            &mut netd,
            Operation::ForwardPolicyUpdate {
                owner: journal.owner.clone(),
                policy_revision: journal.revision,
                policy_generation: journal.plan.signed_generation,
                authorization_snapshot_sha256: journal
                    .plan
                    .authorization_snapshot_sha256
                    .clone()
                    .context("policy hash absent")?,
                declaration: journal.plan.declaration.clone(),
            },
        )
        .context(ManagedProofPending)?;
        signed_renewal::publish_plan(&journal.plan)?;
        let mut updated = journal.worker;
        updated.policy_generation = journal.plan.signed_generation;
        updated.status_generation = Some(binding_policy_generation(&journal.plan));
        updated.effective_plan_file = journal.plan.effective_plan_file.clone();
        updated.authorization_snapshot_sha256 = journal.plan.authorization_snapshot_sha256.clone();
        crate::process_record::publish(record_path, &updated)?;
        fs::remove_file(&journal_path)?;
        File::open(
            record_path
                .parent()
                .context("policy journal parent absent")?,
        )?
        .sync_all()?;
        eprintln!("level=info code=managed_policy_applied module=sdwan_activation policy_generation={} binding_generation={} worker_pid={} worker_epoch={} action=preserve_tun_io_authority_and_transports", journal.plan.signed_generation, binding_policy_generation(&journal.plan), updated.pid, journal.plan.worker_epoch);
        Ok(true)
    }

    #[cfg(test)]
    mod wire_tests {
        use super::*;
        use std::os::unix::net::UnixListener;

        #[test]
        fn lost_or_rejected_ack_preserves_journal_and_exact_owner_until_retry_ack() {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let mut current = super::super::tests::plan();
            current.core = std::env::current_exe().unwrap();
            current.core_status = root.path().join("status");
            current.netd_socket = root.path().join("netd.sock");
            current.auth_deadline_unix = unix_time().unwrap() + 600;
            current
                .declaration
                .routes
                .push(candy_netd_proto::RouteDeclaration {
                    prefix: crate::parse_prefix("10.10.0.0/24").unwrap(),
                    kind: candy_netd_proto::RouteKind::Remote,
                });
            current
                .declaration
                .exclusions
                .push(candy_netd_proto::UnderlayExclusion {
                    prefix: crate::parse_prefix("192.0.2.1/32").unwrap(),
                    kind: candy_netd_proto::UnderlayKind::CloudApi,
                });
            current.effective_plan_file = Some(root.path().join("old-plan.json"));
            current.independent_supervision = Some(IndependentSupervision {
                control_socket: root.path().join("io.sock"),
                status: root.path().join("io-status"),
                process_record: root.path().join("io-record"),
            });
            current.independent_worker = Some(IndependentWorker {
                control_socket: root.path().join("core.sock"),
                process_record: root.path().join("core-record.json"),
            });
            let record_path = current
                .independent_worker
                .as_ref()
                .unwrap()
                .process_record
                .clone();
            let journal_path = record_path.with_extension("policy-update.json");
            let token = "aa".repeat(16);
            let mut record = ManagedProcessRecord::capture(
                std::process::id(),
                &current.core,
                &current.core_status,
                &token,
                1,
                3,
                current.auth_deadline_unix,
            )
            .unwrap();
            record.worker_epoch = Some(current.worker_epoch);
            record.io_epoch = Some(current.io_epoch);
            record.effective_plan_file = current.effective_plan_file.clone();
            record.authorization_snapshot_sha256 = Some("bb".repeat(32));
            crate::process_record::publish(&record_path, &record).unwrap();
            publish(current.effective_plan_file.as_ref().unwrap(), &current).unwrap();
            let binding = candy_tunio::attach_control::PacketPortBinding {
                infrastructure_id: current.infrastructure.infra_id,
                routing_domain_id: current.domain_id,
                infrastructure_generation: 1,
                io_epoch: 1,
                owner_epoch: current.worker_epoch,
                policy_generation: 3,
            };
            let now = monotonic_ms().unwrap();
            let owner = ForwardOwner {
                domain_id: current.domain_id,
                signed_generation: 3,
                worker_epoch: current.worker_epoch,
                fencing_token: 9,
                auth_deadline_mono_ms: now + 60_000,
                lease_deadline_mono_ms: now + 30_000,
            };
            let identity = ProcessIdentity {
                pid: record.pid,
                start_ticks: record.process_start_ticks,
            };
            let actual: AuthorityControlResponse = serde_json::from_value(serde_json::json!({
                "schema_version":2,"process":identity,"controller":identity,"controller_epoch":1,
                "nonce":"aa".repeat(16),"accepted":true,"code":"ok","detail":"",
                "highest_revision":0,"highest_owner_epoch":7,"highest_policy_generation":3,
                "current_binding":binding,"auth_deadline_unix":current.auth_deadline_unix,
                "owner_active":true,"actual_deadline_mono_ms":owner.auth_deadline_mono_ms
            }))
            .unwrap();
            let status = serde_json::json!({"schema_version":3,"pid":record.pid,"generation":3,
                "policy_generation":3,"auth_deadline_unix":current.auth_deadline_unix,
                "readiness_token":token,"packet_binding":binding,"lifecycle":"active"});
            publish(&current.core_status, &status).unwrap();
            for (name, bytes) in [
                ("segment", "segment-bytes"),
                ("projection", "projection-bytes"),
            ] {
                fs::write(root.path().join(name), bytes).unwrap();
            }
            let config = root.path().join("policy.toml");
            fs::write(
                &config,
                format!(
                    "segment_snapshot={:?}\nsite_projection={:?}\n",
                    root.path().join("segment"),
                    root.path().join("projection")
                ),
            )
            .unwrap();
            let snapshot = Snapshot::capture(&config, root.path()).unwrap();
            let mut plan = current.clone();
            plan.signed_generation = 4;
            plan.policy_revision = 1;
            plan.binding_policy_generation = Some(3);
            plan.authorization_snapshot_sha256 = Some("cc".repeat(32));
            plan.core_config = snapshot.config.clone();
            plan.effective_plan_file = Some(root.path().join("new-plan.json"));
            let journal = PolicyJournal {
                schema_version: 1,
                snapshot,
                plan: plan.clone(),
                worker: record.clone(),
                owner: owner.clone(),
                revision: 1,
            };
            publish(&journal_path, &journal).unwrap();
            let original_record = fs::read(&record_path).unwrap();
            for conflict in ["owner_revision", "retained_owner"] {
                let mut pending = actual.clone();
                if conflict == "owner_revision" {
                    pending.owner_highest_revision = Some(1);
                } else {
                    pending.retained_owner_binding = Some(binding);
                }
                assert!(try_update(&plan, &current, &record, &pending).is_err());
                assert_eq!(fs::read(&record_path).unwrap(), original_record);
                assert!(journal_path.exists());
            }
            // Lease metadata is mutable even while the exact policy revision is frozen.
            // Simulate >30s-old intent, a near expiry lease, and proven terminal revocation.
            for mode in ["advanced", "renew", "revoked"] {
                let mut retained = read(&journal_path).unwrap();
                retained.owner.lease_deadline_mono_ms = now.saturating_sub(1);
                let mut live_owner = owner.clone();
                live_owner.lease_deadline_mono_ms = match mode {
                    "renew" => monotonic_ms().unwrap() + 10_000,
                    "revoked" => now.saturating_sub(1),
                    _ => monotonic_ms().unwrap() + 30_000,
                };
                let listener = UnixListener::bind(&current.netd_socket).unwrap();
                let expected = live_owner.clone();
                let netd = thread::spawn(move || {
                    let (stream, _) = listener.accept().unwrap();
                    let request = candy_netd_client::v2::recv_request(&stream).unwrap();
                    assert!(matches!(request.operation, Operation::ForwardStatus));
                    let body = Body::ForwardStatus {
                        owner: Some(expected.clone()),
                        phase: Some(if mode == "revoked" {
                            candy_netd_proto::v2::Phase::Revoked
                        } else {
                            candy_netd_proto::v2::Phase::Active
                        }),
                        candidate_owner: None,
                        last_fencing_token: expected.fencing_token,
                        failure_revision: 0,
                        failed_prefixes: vec![],
                        pending_failure_revision: None,
                        pending_failed_prefixes: None,
                        active_policy_revision: 0,
                        active_policy_generation: None,
                        active_policy_hash: None,
                        pending_policy_revision: None,
                    };
                    candy_netd_client::v2::send_response(
                        &stream,
                        &candy_netd_proto::v2::Response {
                            request_id: request.request_id,
                            body,
                        },
                        None,
                    )
                    .unwrap();
                    if mode == "renew" {
                        let (stream, _) = listener.accept().unwrap();
                        let request = candy_netd_client::v2::recv_request(&stream).unwrap();
                        let Operation::ForwardLeaseRenew { owner: renewed } = request.operation
                        else {
                            panic!("expected lease renewal");
                        };
                        assert!(same_physical_owner(&expected, &renewed));
                        assert!(renewed.lease_deadline_mono_ms > expected.lease_deadline_mono_ms);
                        assert!(renewed.lease_deadline_mono_ms <= expected.auth_deadline_mono_ms);
                        candy_netd_client::v2::send_response(
                            &stream,
                            &candy_netd_proto::v2::Response {
                                request_id: request.request_id,
                                body: Body::Ack,
                            },
                            None,
                        )
                        .unwrap();
                    }
                });
                assert_eq!(
                    reconcile_lease(&mut retained, &journal_path)
                        .unwrap()
                        .is_none(),
                    mode != "revoked"
                );
                netd.join().unwrap();
                fs::remove_file(&current.netd_socket).unwrap();
                if mode != "revoked" {
                    assert_eq!(read(&journal_path).unwrap().owner, retained.owner);
                    assert_eq!(retained.revision, journal.revision);
                    assert_eq!(
                        retained.plan.auth_deadline_unix,
                        journal.plan.auth_deadline_unix
                    );
                }
                publish(&journal_path, &journal).unwrap();
            }
            for cap_expired in [false, true] {
                let mut expired = read(&journal_path).unwrap();
                expired.owner.lease_deadline_mono_ms = now.saturating_sub(1);
                if cap_expired {
                    expired.owner.auth_deadline_mono_ms = now.saturating_sub(1);
                }
                publish(&journal_path, &expired).unwrap();
                let listener = UnixListener::bind(&current.netd_socket).unwrap();
                let terminal_owner = expired.owner.clone();
                let netd = thread::spawn(move || {
                    let (stream, _) = listener.accept().unwrap();
                    let request = candy_netd_client::v2::recv_request(&stream).unwrap();
                    assert!(matches!(request.operation, Operation::ForwardStatus));
                    candy_netd_client::v2::send_response(
                        &stream,
                        &candy_netd_proto::v2::Response {
                            request_id: request.request_id,
                            body: Body::ForwardStatus {
                                owner: Some(terminal_owner.clone()),
                                phase: Some(candy_netd_proto::v2::Phase::Revoked),
                                candidate_owner: None,
                                last_fencing_token: terminal_owner.fencing_token,
                                failure_revision: 0,
                                failed_prefixes: vec![],
                                pending_failure_revision: None,
                                pending_failed_prefixes: None,
                                active_policy_revision: 0,
                                active_policy_generation: None,
                                active_policy_hash: None,
                                pending_policy_revision: None,
                            },
                        },
                        None,
                    )
                    .unwrap();
                });
                assert!(!try_update(&plan, &current, &record, &actual).unwrap());
                netd.join().unwrap();
                fs::remove_file(&current.netd_socket).unwrap();
                assert!(!journal_path.exists());
                assert_eq!(fs::read(&record_path).unwrap(), original_record);
                let terminal = fs::read_dir(root.path())
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .contains("policy-terminal-")
                    })
                    .count();
                assert_eq!(terminal, if cap_expired { 2 } else { 1 });
                publish(&journal_path, &journal).unwrap();
            }
            let core = UnixListener::bind(policy_reload_socket(&plan).unwrap()).unwrap();
            for mode in ["reject", "lost", "bad_status", "netd_failure", "ack"] {
                let listener = core.try_clone().unwrap();
                let status_path = current.core_status.clone();
                let mut updated_status = status.clone();
                updated_status["policy_generation"] = serde_json::json!(4);
                updated_status["policy_revision"] = serde_json::json!(1);
                updated_status["authorization_snapshot_sha256"] =
                    serde_json::json!("cc".repeat(32));
                if mode == "bad_status" {
                    updated_status["authorization_snapshot_sha256"] =
                        serde_json::json!("ff".repeat(32));
                }
                let expected_config = plan.core_config.clone();
                let server = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut request = Vec::new();
                    stream.read_to_end(&mut request).unwrap();
                    let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
                    assert_eq!(request["action"], "policy_update");
                    assert_eq!(request["config"], expected_config.to_str().unwrap());
                    if mode != "reject" {
                        publish(&status_path, &updated_status).unwrap();
                    }
                    if mode != "lost" {
                        stream.write_all(&serde_json::to_vec(&serde_json::json!({
                            "schema_version":1,"ok":mode!="reject","generation":3,
                            "policy_generation":4,"error":if mode=="reject" {Some("rejected")} else {None},
                        })).unwrap()).unwrap();
                    }
                });
                let netd = Some({
                    let listener = UnixListener::bind(&current.netd_socket).unwrap();
                    let expected_owner = owner.clone();
                    thread::spawn(move || {
                        let (stream, _) = listener.accept().unwrap();
                        let request = candy_netd_client::v2::recv_request(&stream).unwrap();
                        assert!(matches!(request.operation, Operation::ForwardStatus));
                        candy_netd_client::v2::send_response(&stream, &candy_netd_proto::v2::Response {
                            request_id: request.request_id, body: serde_json::from_value(serde_json::json!({
                                "result":"forward_status", "data":{"owner":expected_owner,"phase":"active",
                                "candidate_owner":null,"last_fencing_token":expected_owner.fencing_token,
                                "failed_prefixes":[],"failure_revision":0,
                                "pending_failed_prefixes":null,"pending_failure_revision":null,
                                "active_policy_revision":0,"active_policy_generation":null,"active_policy_hash":null,
                                "pending_policy_revision":null}
                            })).unwrap()
                        }, None).unwrap();
                        if !matches!(mode, "ack" | "netd_failure") {
                            return;
                        }
                        let (stream, _) = listener.accept().unwrap();
                        let request = candy_netd_client::v2::recv_request(&stream).unwrap();
                        assert!(matches!(request.operation, Operation::ForwardPolicyUpdate {
                            owner, policy_revision:1,policy_generation:4, .. } if owner==expected_owner));
                        candy_netd_client::v2::send_response(
                            &stream,
                            &candy_netd_proto::v2::Response {
                                request_id: request.request_id,
                                body: if mode == "ack" {
                                    Body::Ack
                                } else {
                                    Body::Error {
                                        code: "injected_route_failure".into(),
                                        module: "netd_v2".into(),
                                        reason: "retry retained intent".into(),
                                    }
                                },
                            },
                            None,
                        )
                        .unwrap();
                    })
                });
                // A newer Cloud target cannot overwrite an uncertain original intent.
                let mut newer_desired = plan.clone();
                newer_desired.signed_generation = 99;
                newer_desired.auth_deadline_unix += 600;
                newer_desired.core_config = root.path().join("not-the-pending-policy.toml");
                let result = try_update(&newer_desired, &current, &record, &actual);
                if mode == "ack" {
                    assert!(result.is_ok(), "{result:?}");
                }
                server.join().unwrap();
                if let Some(netd) = netd {
                    netd.join().unwrap();
                    fs::remove_file(&current.netd_socket).unwrap();
                }
                if mode != "ack" {
                    assert!(result.is_err());
                    assert_eq!(fs::read(&record_path).unwrap(), original_record);
                    assert!(journal_path.exists());
                    assert!(!plan.effective_plan_file.as_ref().unwrap().exists());
                } else {
                    assert!(result.unwrap());
                    assert!(!journal_path.exists());
                }
            }
            let updated = crate::process_record::read(&record_path).unwrap();
            updated
                .validate_bound_status(&current.core, unix_time().unwrap())
                .unwrap();
            let restored = read_plan(updated.effective_plan_file.as_ref().unwrap()).unwrap();
            assert_eq!(updated.policy_generation, 4);
            assert_eq!(updated.status_generation, Some(3));
            assert_eq!(restored.auth_deadline_unix, current.auth_deadline_unix);
            assert_eq!(binding_policy_generation(&restored), 3);
            assert_eq!(
                (
                    restored.io_epoch,
                    restored.worker_epoch,
                    restored.fencing_token
                ),
                (
                    current.io_epoch,
                    current.worker_epoch,
                    current.fencing_token
                )
            );
            assert_eq!(
                restored.authority.as_ref().map(|proof| &proof.sha256),
                current.authority.as_ref().map(|proof| &proof.sha256)
            );
        }
    }
}

#[cfg(all(feature = "experimental-tunio-rebind", target_os = "linux"))]
pub(super) use linux::try_update;

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn plan() -> Plan {
        serde_json::from_value(serde_json::json!({
            "schema_version":1,"netd_socket":"/tmp/netd","tunio":"/tmp/tunio","core":"/tmp/core",
            "core_config":"/tmp/core.toml","core_status":"/tmp/core-status","binding_file":"/tmp/binding",
            "instance_id":vec![1u8;16],"domain_id":vec![2u8;16],"io_epoch":1,"worker_epoch":7,"fencing_token":9,
            "signed_generation":3,"auth_deadline_unix":9999999999u64,
            "independent_worker":{"control_socket":"/tmp/core.sock","process_record":"/tmp/core-record.json"},
            "infrastructure":{"infra_id":vec![3u8;16],"generation":1,"netns_device":1,"netns_inode":1,"overlay_router_ipv4":[10,0,0,1],"mtu":1398},
            "declaration":{"table_id":20001,"overlay_router_ipv4":[10,0,0,1],"effective_mtu":1398,"routes":[],"exclusions":[],"firewall":{"allow_forward":true,"clamp_tcp_mss":false,"require_ipv4_forwarding":true,"manage_rp_filter":false}}
        })).unwrap()
    }

    fn report() -> serde_json::Value {
        serde_json::json!({
            "transport_fingerprint":"aa".repeat(32),"trust_sha256":"bb".repeat(32),
            "resource_contract_sha256":"cc".repeat(32),
            "tenant_id":"tenant","segment_id":"segment","site_id":"site",
            "attachment_id":"attachment","device_id":"device","device_key_id":"key",
            "authorization_snapshot_sha256":"dd".repeat(32)
        })
    }

    #[test]
    fn catalog_and_routes_may_advance_without_changing_packet_owner() {
        let current = plan();
        let mut desired = current.clone();
        let before = report();
        let mut after = before.clone();
        after["authorization_snapshot_sha256"] = serde_json::json!("ee".repeat(32));
        assert!(hot_policy_eligible(&current, &desired, &before, &after));
        desired.signed_generation = 4;
        desired
            .declaration
            .routes
            .push(candy_netd_proto::RouteDeclaration {
                prefix: crate::parse_prefix("10.10.0.0/24").unwrap(),
                kind: candy_netd_proto::RouteKind::Remote,
            });
        assert!(hot_policy_eligible(&current, &desired, &before, &after));
        desired.binding_policy_generation = Some(binding_policy_generation(&current));
        let restored: Plan =
            serde_json::from_slice(&serde_json::to_vec(&desired).unwrap()).unwrap();
        assert_eq!(restored.signed_generation, 4);
        assert_eq!(binding_policy_generation(&restored), 3);
        assert_eq!(
            (
                restored.io_epoch,
                restored.worker_epoch,
                restored.fencing_token
            ),
            (1, 7, 9)
        );
    }

    #[test]
    fn transport_trust_resource_identity_or_cap_changes_require_mbb() {
        let current = plan();
        let before = report();
        for field in [
            "transport_fingerprint",
            "trust_sha256",
            "resource_contract_sha256",
            "device_key_id",
        ] {
            let mut after = before.clone();
            after[field] = serde_json::json!("ff".repeat(32));
            assert!(
                !hot_policy_eligible(&current, &current, &before, &after),
                "{field}"
            );
        }
        let mut desired = current.clone();
        desired.auth_deadline_unix -= 1;
        assert!(!hot_policy_eligible(&current, &desired, &before, &before));
        desired.auth_deadline_unix = current.auth_deadline_unix + 60;
        assert!(hot_policy_eligible(&current, &desired, &before, &before));
        let mut desired = current.clone();
        desired.infrastructure.mtu = 1200;
        assert!(!hot_policy_eligible(&current, &desired, &before, &before));
        desired = current.clone();
        desired.declaration.table_id += 1;
        assert!(!hot_policy_eligible(&current, &desired, &before, &before));
    }

    #[test]
    fn authority_refresh_is_scheduled_before_original_physical_expiry() {
        assert!(!authority_renewal_due(1_000, 800));
        assert!(authority_renewal_due(1_000, 880));
        assert!(authority_renewal_due(1_000, 1_001));
        let mut current = plan();
        current.auth_deadline_unix = 1_000;
        let mut desired = current.clone();
        assert!(!authority_refresh_needed(&current, &desired, 900));
        desired.auth_deadline_unix = 1_600;
        assert!(authority_refresh_needed(&current, &desired, 900));
        assert!(!authority_refresh_needed(&current, &desired, 800));
    }
}
