use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use notify::{RecursiveMode, Watcher};
use vollcrypt_shield_core::{
    AuditEventKind, MlDsa65KeyPair, MlDsa65PublicKey, MlDsa65SecretKey, PolicyMode,
    SignedBreakGlassCommand, SignedSnapshot, Snapshot, SparseMerkleTree, VerificationReport,
};
use vollcrypt_shield_protocol::control_plane::{
    AgentIntegrityStatus, AgentSummaryClaim, AgentSummaryInput, DataRetentionMode, EnrollmentClaim,
    SignedAgentSummary, SignedEnrollmentRequest,
};
use vollcrypt_shield_protocol::offline::{OfflinePackageInput, SignedOfflinePackage};
use vollcrypt_shield_protocol::witness::{AttestationRequest, WitnessIdentity, WitnessPolicy};

use crate::audit_store::AuditStore;
use crate::config::{AgentConfig, ScopeConfig};
use crate::error::{AgentError, Result};
use crate::ipc::AgentStatus;
#[cfg(unix)]
use crate::ipc::LocalStatusServer;
use crate::pairing::WitnessPairingServer;
use crate::response::{ResponseContext, ResponseEngine, ResponseOutcome};
use crate::scanner::Scanner;
use crate::state::{StateStore, write_atomic};
use crate::witness_registry::{WitnessRegistry, WitnessRegistryEntry};

pub struct ShieldAgent {
    config: AgentConfig,
    agent_secret: MlDsa65SecretKey,
    agent_public: MlDsa65PublicKey,
    break_glass_public: MlDsa65PublicKey,
    state: StateStore,
    audit: AuditStore,
    response: ResponseEngine,
    witnesses: WitnessRegistry,
}

impl ShieldAgent {
    pub fn initialize(config: AgentConfig, break_glass_secret_output: &Path) -> Result<Self> {
        config.validate()?;
        if !break_glass_secret_output.is_absolute()
            || break_glass_secret_output.starts_with(&config.state_dir)
        {
            return Err(AgentError::Config(
                "break-glass secret output must be absolute and outside state_dir".to_owned(),
            ));
        }

        let keys = config.state_dir.join("keys");
        std::fs::create_dir_all(&keys)?;
        secure_directory(&config.state_dir)?;
        secure_directory(&keys)?;
        let agent_seed_path = keys.join("agent.seed");
        let agent_public_path = keys.join("agent.public");
        let break_glass_public_path = keys.join("break-glass.public");
        if agent_seed_path.exists()
            || agent_public_path.exists()
            || break_glass_public_path.exists()
            || break_glass_secret_output.exists()
        {
            return Err(AgentError::Config(
                "refusing to overwrite existing Shield key material".to_owned(),
            ));
        }

        let agent = MlDsa65KeyPair::generate()?;
        let break_glass = MlDsa65KeyPair::generate()?;
        write_secret(&agent_seed_path, agent.secret.expose_seed())?;
        write_atomic(&agent_public_path, agent.public.as_bytes())?;
        write_atomic(&break_glass_public_path, break_glass.public.as_bytes())?;
        write_secret(break_glass_secret_output, break_glass.secret.expose_seed())?;
        write_atomic(
            &break_glass_secret_output.with_extension("public"),
            break_glass.public.as_bytes(),
        )?;
        WitnessRegistry::new(config.state_dir.join("witnesses.cbor")).save(&agent.secret)?;

        Self::load(config)
    }

    pub fn load(config: AgentConfig) -> Result<Self> {
        config.validate()?;
        let keys = config.state_dir.join("keys");
        secure_directory(&config.state_dir)?;
        secure_directory(&keys)?;
        let agent_secret = MlDsa65SecretKey::from_seed(&std::fs::read(keys.join("agent.seed"))?)?;
        let agent_public =
            MlDsa65PublicKey::from_bytes(&std::fs::read(keys.join("agent.public"))?)?;
        if agent_secret.public_key()?.key_id() != agent_public.key_id() {
            return Err(AgentError::Config(
                "agent secret and public keys do not match".to_owned(),
            ));
        }
        let break_glass_public =
            MlDsa65PublicKey::from_bytes(&std::fs::read(keys.join("break-glass.public"))?)?;
        let state = StateStore::load_or_new(config.state_dir.join("state.cbor"), &agent_public)?;
        let audit = AuditStore::load_or_new(config.state_dir.join("audit.log"), &agent_public)?;
        let response = ResponseEngine::new(&config.state_dir, &config.notifications)?;
        let witnesses =
            WitnessRegistry::load(config.state_dir.join("witnesses.cbor"), &agent_public)?;
        Ok(Self {
            config,
            agent_secret,
            agent_public,
            break_glass_public,
            state,
            audit,
            response,
            witnesses,
        })
    }

    pub fn create_baseline(&mut self, scope_id: &str) -> Result<Snapshot> {
        if self.state.is_contained(scope_id) {
            return Err(AgentError::ScopeContained(scope_id.to_owned()));
        }
        let scope = self.scope(scope_id)?.clone();
        let scanner = Scanner::new(&scope)?;
        let result = scanner.full_scan(&scope)?;
        let now = now_unix_ms()?;
        let snapshot = Snapshot::new(&scope.id, result.entries, now)?;
        self.response
            .vault()
            .capture_baseline(&scope, &snapshot, &self.agent_secret)?;
        let signed = SignedSnapshot::sign(&snapshot, &self.agent_secret)?;
        write_atomic(&self.snapshot_path(scope_id), &signed.to_cbor()?)?;
        self.audit.append(
            now,
            scope_id,
            AuditEventKind::BaselineCreated,
            None,
            format!("baseline root={}", hex::encode(snapshot.root)),
            &self.agent_secret,
        )?;
        self.state.save(&self.agent_secret)?;
        Ok(snapshot)
    }

    pub fn load_baseline(&self, scope_id: &str) -> Result<Snapshot> {
        let signed = SignedSnapshot::from_cbor(&std::fs::read(self.snapshot_path(scope_id))?)?;
        if signed.public_key()?.key_id() != self.agent_public.key_id() {
            return Err(AgentError::Config(
                "baseline signer does not match configured agent key".to_owned(),
            ));
        }
        let snapshot = signed.verify()?;
        if snapshot.scope_id != scope_id {
            return Err(AgentError::Config("baseline scope id mismatch".to_owned()));
        }
        Ok(snapshot)
    }

    pub fn verify_scope(
        &mut self,
        scope_id: &str,
    ) -> Result<(VerificationReport, Vec<ResponseOutcome>)> {
        let scope = self.scope(scope_id)?.clone();
        let snapshot = self.load_baseline(scope_id)?;
        let scanner = Scanner::new(&scope)?;
        let observed = match scanner.full_scan(&scope) {
            Ok(observed) => observed,
            Err(error) => {
                self.record_monitoring_failure(&scope, error.to_string())?;
                return Err(error);
            }
        };
        self.process_observation(&scope, &snapshot, &observed)
    }

    fn process_observation(
        &mut self,
        scope: &ScopeConfig,
        snapshot: &Snapshot,
        observed: &crate::scanner::ScanResult,
    ) -> Result<(VerificationReport, Vec<ResponseOutcome>)> {
        let report = Scanner::compare(snapshot, observed);
        let now = now_unix_ms()?;
        let policy_fingerprint = hex::encode(scope.dry_run_fingerprint()?);

        if report.is_match() {
            self.audit.append(
                now,
                &scope.id,
                AuditEventKind::VerificationPassed,
                None,
                format!(
                    "verified root={} policy={policy_fingerprint}",
                    hex::encode(report.observed_root)
                ),
                &self.agent_secret,
            )?;
            self.state.save(&self.agent_secret)?;
            return Ok((report, Vec::new()));
        }

        self.audit.append(
            now,
            &scope.id,
            AuditEventKind::VerificationFailed,
            None,
            format!(
                "{} integrity differences policy={policy_fingerprint}",
                report.differences.len()
            ),
            &self.agent_secret,
        )?;
        let mut context = ResponseContext {
            state: &mut self.state,
            audit: &mut self.audit,
            agent_secret: &self.agent_secret,
            agent_public: &self.agent_public,
        };
        let outcomes = match self.response.handle(
            scope,
            snapshot,
            &observed.entries,
            &report,
            now,
            &mut context,
        ) {
            Ok(outcomes) => outcomes,
            Err(error) => {
                self.response.contain_after_failure(
                    scope,
                    format!("response failure: {error}"),
                    now,
                    &mut context,
                )?;
                self.state.save(&self.agent_secret)?;
                return Err(error);
            }
        };
        self.state.save(&self.agent_secret)?;
        Ok((report, outcomes))
    }

    pub fn send_due_containment_reminders(&mut self) -> Result<usize> {
        let now = now_unix_ms()?;
        let intervals: std::collections::BTreeMap<_, _> = self
            .config
            .scopes
            .iter()
            .map(|scope| (scope.id.clone(), scope.response.reminder_interval_secs))
            .collect();
        let due = self.state.due_reminders(now, |scope_id| {
            intervals.get(scope_id).copied().unwrap_or(300)
        });
        for state in &due {
            self.audit.append(
                now,
                &state.scope_id,
                AuditEventKind::ContainmentReminder,
                None,
                &state.reason,
                &self.agent_secret,
            )?;
            self.response
                .notify_containment_reminder(&state.scope_id, &state.reason, now)?;
        }
        if !due.is_empty() {
            self.state.save(&self.agent_secret)?;
        }
        Ok(due.len())
    }

    pub fn apply_break_glass(&mut self, encoded_command: &[u8], scope_id: &str) -> Result<()> {
        if !self.state.is_contained(scope_id) {
            return Err(AgentError::Config(format!(
                "scope is not contained: {scope_id}"
            )));
        }
        let now = now_unix_ms()?;
        let signed = SignedBreakGlassCommand::from_cbor(encoded_command)?;
        let command = signed.verify(&self.break_glass_public, scope_id, now)?;
        self.state.release_scope(scope_id, command.nonce)?;
        self.audit.append(
            now,
            scope_id,
            AuditEventKind::BreakGlassReleased,
            None,
            format!("nonce={}", hex::encode(command.nonce)),
            &self.agent_secret,
        )?;
        self.response.notify_break_glass_release(scope_id, now)?;
        self.state.save(&self.agent_secret)
    }

    pub fn watch_scope(&mut self, scope_id: &str) -> Result<()> {
        let scope = self.scope(scope_id)?.clone();
        let snapshot = self.load_baseline(scope_id)?;
        let scanner = Scanner::new(&scope)?;
        let initial = match scanner.full_scan(&scope) {
            Ok(result) => result,
            Err(error) => {
                self.record_monitoring_failure(&scope, error.to_string())?;
                return Err(error);
            }
        };
        let mut observed_tree = SparseMerkleTree::from_entries(initial.entries)?;
        let mut last_full_scan = Instant::now();
        #[cfg(unix)]
        let local_status = LocalStatusServer::bind(&self.config.state_dir)?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |event| {
            let _ = sender.send(event);
        })
        .map_err(|error| AgentError::Scan(error.to_string()))?;
        watcher
            .watch(&scope.root, RecursiveMode::Recursive)
            .map_err(|error| AgentError::Scan(error.to_string()))?;
        self.audit.append(
            now_unix_ms()?,
            scope_id,
            AuditEventKind::AgentStarted,
            None,
            "filesystem watcher started",
            &self.agent_secret,
        )?;

        loop {
            match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
                Ok(Ok(event)) => {
                    let mut paths = event.paths;
                    loop {
                        match receiver.recv_timeout(Duration::from_millis(200)) {
                            Ok(Ok(event)) => paths.extend(event.paths),
                            Ok(Err(error)) => {
                                self.record_monitoring_failure(&scope, error.to_string())?;
                                break;
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                return Err(AgentError::Scan(
                                    "filesystem watcher channel disconnected".to_owned(),
                                ));
                            }
                        }
                    }
                    match scanner.incremental_update(&scope, &mut observed_tree, paths) {
                        Ok(observed) => {
                            let (report, _) =
                                self.process_observation(&scope, &snapshot, &observed)?;
                            if !report.is_match() {
                                self.refresh_observed_tree(&scope, &scanner, &mut observed_tree)?;
                            }
                        }
                        Err(error) => {
                            self.record_monitoring_failure(&scope, error.to_string())?;
                        }
                    }
                }
                Ok(Err(error)) => {
                    return Err(AgentError::Scan(error.to_string()));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    self.send_due_containment_reminders()?;
                    if last_full_scan.elapsed()
                        >= Duration::from_secs(scope.full_rescan_interval_secs)
                    {
                        match scanner.full_scan(&scope) {
                            Ok(observed) => {
                                let (report, _) =
                                    self.process_observation(&scope, &snapshot, &observed)?;
                                observed_tree = SparseMerkleTree::from_entries(observed.entries)?;
                                if !report.is_match() {
                                    self.refresh_observed_tree(
                                        &scope,
                                        &scanner,
                                        &mut observed_tree,
                                    )?;
                                }
                            }
                            Err(error) => {
                                self.record_monitoring_failure(&scope, error.to_string())?;
                            }
                        }
                        last_full_scan = Instant::now();
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AgentError::Scan(
                        "filesystem watcher channel disconnected".to_owned(),
                    ));
                }
            }
            #[cfg(unix)]
            local_status.serve_pending(&self.status(scope_id)?)?;
        }
    }

    fn refresh_observed_tree(
        &mut self,
        scope: &ScopeConfig,
        scanner: &Scanner,
        tree: &mut SparseMerkleTree,
    ) -> Result<()> {
        match scanner.full_scan(scope) {
            Ok(observed) => {
                *tree = SparseMerkleTree::from_entries(observed.entries)?;
                Ok(())
            }
            Err(error) => {
                self.record_monitoring_failure(scope, error.to_string())?;
                Err(error)
            }
        }
    }

    fn record_monitoring_failure(&mut self, scope: &ScopeConfig, reason: String) -> Result<()> {
        let now = now_unix_ms()?;
        self.audit.append(
            now,
            &scope.id,
            AuditEventKind::MonitoringFailed,
            None,
            &reason,
            &self.agent_secret,
        )?;
        self.response
            .notify_monitoring_failure(&scope.id, &reason, now)?;
        if cfg!(unix) && scope.response.mode == PolicyMode::Active && !scope.protects_system_path()
        {
            let mut context = ResponseContext {
                state: &mut self.state,
                audit: &mut self.audit,
                agent_secret: &self.agent_secret,
                agent_public: &self.agent_public,
            };
            self.response.contain_after_failure(
                scope,
                format!("monitoring failure: {reason}"),
                now,
                &mut context,
            )?;
        }
        self.state.save(&self.agent_secret)
    }

    pub fn is_contained(&self, scope_id: &str) -> bool {
        self.state.is_contained(scope_id)
    }

    pub fn containment_reason(&self, scope_id: &str) -> Option<&str> {
        self.state
            .containment(scope_id)
            .map(|state| state.reason.as_str())
    }

    pub fn agent_key_id(&self) -> [u8; 32] {
        self.agent_public.key_id()
    }

    pub fn agent_public_key_bytes(&self) -> &[u8] {
        self.agent_public.as_bytes()
    }

    pub fn fleet_enrollment_request(
        &self,
        agent_label: &str,
        issued_at_unix_ms: u64,
    ) -> Result<SignedEnrollmentRequest> {
        let claim = EnrollmentClaim::new(
            agent_label,
            DataRetentionMode::SignedSummary,
            issued_at_unix_ms,
        )?;
        Ok(SignedEnrollmentRequest::sign(&claim, &self.agent_secret)?)
    }

    pub fn fleet_summary(
        &mut self,
        scope_id: &str,
        epoch: u64,
        previous_summary_hash: [u8; 32],
    ) -> Result<(SignedAgentSummary, VerificationReport)> {
        let (report, _) = self.verify_scope(scope_id)?;
        let status = if self.is_contained(scope_id) {
            AgentIntegrityStatus::Contained
        } else if report.is_match() {
            AgentIntegrityStatus::Match
        } else {
            AgentIntegrityStatus::Mismatch
        };
        let difference_count = u64::try_from(report.differences.len())
            .map_err(|_| AgentError::Config("difference count exceeds u64".to_owned()))?;
        let claim = AgentSummaryClaim::new(AgentSummaryInput {
            agent_key_id: self.agent_public.key_id(),
            scope_id: scope_id.to_owned(),
            baseline_root: report.baseline_root,
            observed_root: report.observed_root,
            observed_at_unix_ms: now_unix_ms()?,
            epoch,
            status,
            difference_count,
            previous_summary_hash,
        })?;
        let summary = SignedAgentSummary::sign(&claim, &self.agent_secret)?;
        Ok((summary, report))
    }

    pub fn sign_offline_package(&self, input: OfflinePackageInput) -> Result<SignedOfflinePackage> {
        Ok(SignedOfflinePackage::sign(input, &self.agent_secret)?)
    }

    pub fn registered_witnesses(&self) -> &[WitnessRegistryEntry] {
        self.witnesses.entries()
    }

    pub fn register_witness(
        &mut self,
        witness_id: &str,
        public_key: &[u8],
    ) -> Result<WitnessRegistryEntry> {
        let entry = self.witnesses.register(witness_id, public_key)?;
        self.witnesses.save(&self.agent_secret)?;
        Ok(entry)
    }

    pub fn complete_witness_pairing(
        &mut self,
        server: WitnessPairingServer,
    ) -> Result<WitnessRegistryEntry> {
        let pending = server.accept(self.agent_public.as_bytes())?;
        let witness_id = pending.witness_id().to_owned();
        let witness_public_key = pending.witness_public_key().to_vec();
        let expected_key_id = pending.witness_key_id();
        let entry = self.register_witness(&witness_id, &witness_public_key)?;
        if entry.key_id != expected_key_id {
            return Err(AgentError::Config(
                "paired witness key changed before registry commit".to_owned(),
            ));
        }
        pending.confirm()?;
        Ok(entry)
    }

    pub fn witness_policy(&self, threshold: usize) -> Result<WitnessPolicy> {
        let policy = WitnessPolicy {
            threshold,
            witnesses: self
                .witnesses
                .entries()
                .iter()
                .map(|entry| WitnessIdentity {
                    id: entry.witness_id.clone(),
                    public_key: entry.public_key.clone(),
                })
                .collect(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn attestation_request(&self, scope_id: &str, epoch: u64) -> Result<AttestationRequest> {
        self.scope(scope_id)?;
        let signed = SignedSnapshot::from_cbor(&std::fs::read(self.snapshot_path(scope_id))?)?;
        if signed.public_key()?.key_id() != self.agent_public.key_id() {
            return Err(AgentError::Config(
                "baseline signer does not match configured agent key".to_owned(),
            ));
        }
        let snapshot = signed.verify()?;
        if snapshot.scope_id != scope_id {
            return Err(AgentError::Config("baseline scope id mismatch".to_owned()));
        }
        Ok(AttestationRequest::new(epoch, &signed)?)
    }

    pub fn verify_audit(&self) -> Result<usize> {
        Ok(self.audit.verify()?.len())
    }

    pub fn has_dry_run_evidence(&self, scope_id: &str) -> Result<bool> {
        let scope = self.scope(scope_id)?;
        if scope.response.mode != PolicyMode::DryRun {
            return Ok(false);
        }
        let marker = format!("policy={}", hex::encode(scope.dry_run_fingerprint()?));
        Ok(self.audit.verify()?.iter().any(|event| {
            event.scope_id == scope_id
                && matches!(
                    event.kind,
                    AuditEventKind::VerificationPassed | AuditEventKind::VerificationFailed
                )
                && event.detail.contains(&marker)
        }))
    }

    pub fn record_policy_promotion(&mut self, scope_id: &str) -> Result<()> {
        let scope = self.scope(scope_id)?.clone();
        if scope.response.mode != PolicyMode::Active {
            return Err(AgentError::Config(
                "only an active policy can be recorded as promoted".to_owned(),
            ));
        }
        let now = now_unix_ms()?;
        self.audit.append(
            now,
            scope_id,
            AuditEventKind::PolicyPromoted,
            None,
            format!(
                "policy={} approved_by={}",
                hex::encode(scope.dry_run_fingerprint()?),
                hex::encode(scope.response.approved_by_key_id.ok_or_else(|| {
                    AgentError::Config("active policy has no approving key".to_owned())
                })?)
            ),
            &self.agent_secret,
        )?;
        self.state.save(&self.agent_secret)
    }

    pub fn status(&self, scope_id: &str) -> Result<AgentStatus> {
        self.scope(scope_id)?;
        Ok(AgentStatus {
            scope: scope_id.to_owned(),
            contained: self.is_contained(scope_id),
            reason: self.containment_reason(scope_id).map(str::to_owned),
            audit_records: self.verify_audit()?,
        })
    }

    fn scope(&self, scope_id: &str) -> Result<&ScopeConfig> {
        self.config
            .scopes
            .iter()
            .find(|scope| scope.id == scope_id)
            .ok_or_else(|| AgentError::Config(format!("unknown scope id: {scope_id}")))
    }

    fn snapshot_path(&self, scope_id: &str) -> PathBuf {
        self.config
            .state_dir
            .join("snapshots")
            .join(format!("{scope_id}.snapshot.cbor"))
    }
}

pub fn now_unix_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AgentError::Config(error.to_string()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| AgentError::Config("system time exceeds u64 milliseconds".to_owned()))
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn secure_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use vollcrypt_shield_core::{
        BreakGlassCommand, PolicyMode, ResponseAction, SignedBreakGlassCommand,
    };
    use vollcrypt_shield_core::{MetadataPolicy, ResponsePolicy, ScanProfile};

    fn scope(id: &str, root: PathBuf, response: ResponsePolicy) -> ScopeConfig {
        ScopeConfig {
            id: id.to_owned(),
            root,
            include: vec!["**".to_owned()],
            exclude: vec![],
            metadata: MetadataPolicy {
                ownership: false,
                modified_time: true,
                ..MetadataPolicy::default()
            },
            full_scan: ScanProfile::full_default(),
            incremental_scan: ScanProfile::incremental_default(),
            full_rescan_interval_secs: 300,
            response,
        }
    }

    fn config(state_dir: PathBuf, scopes: Vec<ScopeConfig>) -> AgentConfig {
        AgentConfig {
            state_dir,
            scopes,
            notifications: crate::config::NotificationConfig::default(),
        }
    }

    #[test]
    fn dry_run_never_changes_the_observed_file() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("scope");
        let state = base.path().join("state");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("app.conf"), b"approved").unwrap();
        let break_glass = base.path().join("offline-break-glass.seed");
        let mut agent = ShieldAgent::initialize(
            config(
                state,
                vec![scope("scope", root.clone(), ResponsePolicy::default())],
            ),
            &break_glass,
        )
        .unwrap();
        agent.create_baseline("scope").unwrap();
        std::fs::write(root.join("app.conf"), b"changed").unwrap();
        let (_report, outcomes) = agent.verify_scope("scope").unwrap();
        assert!(
            outcomes
                .iter()
                .any(|outcome| matches!(outcome, ResponseOutcome::DryRun(_)))
        );
        assert_eq!(std::fs::read(root.join("app.conf")).unwrap(), b"changed");
        assert!(!agent.is_contained("scope"));
    }

    #[test]
    fn dry_run_evidence_is_invalidated_when_policy_changes() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("scope");
        let state = base.path().join("state");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("app.conf"), b"approved").unwrap();
        let break_glass = base.path().join("offline-break-glass.seed");
        let mut value = config(state, vec![scope("scope", root, ResponsePolicy::default())]);
        let mut agent = ShieldAgent::initialize(value.clone(), &break_glass).unwrap();
        agent.create_baseline("scope").unwrap();
        agent.verify_scope("scope").unwrap();
        assert!(agent.has_dry_run_evidence("scope").unwrap());
        drop(agent);

        value.scopes[0].include = vec!["*.conf".to_owned()];
        let changed = ShieldAgent::load(value).unwrap();
        assert!(!changed.has_dry_run_evidence("scope").unwrap());
    }

    #[test]
    fn corrupted_existing_vault_object_blocks_new_baseline() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("scope");
        let state = base.path().join("state");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("app.conf"), b"approved").unwrap();
        let break_glass = base.path().join("offline-break-glass.seed");
        let mut agent = ShieldAgent::initialize(
            config(
                state.clone(),
                vec![scope("scope", root, ResponsePolicy::default())],
            ),
            &break_glass,
        )
        .unwrap();
        let snapshot = agent.create_baseline("scope").unwrap();
        let object = state
            .join("vault/objects")
            .join(hex::encode(snapshot.entries[0].content_digest));
        std::fs::write(object, b"corrupted").unwrap();
        assert!(agent.create_baseline("scope").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn active_response_is_reversible_scope_local_and_break_glass_protected() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let base = tempfile::tempdir().unwrap();
        let root_a = base.path().join("scope-a");
        let root_b = base.path().join("scope-b");
        let state = base.path().join("state");
        std::fs::create_dir_all(&root_a).unwrap();
        std::fs::create_dir_all(&root_b).unwrap();
        std::fs::write(root_a.join("app.conf"), b"approved-a").unwrap();
        std::fs::write(root_b.join("app.conf"), b"approved-b").unwrap();
        let protected = root_a.join("app.conf");
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o640)).unwrap();
        let baseline_time = filetime::FileTime::from_unix_time(1_700_000_000, 123_456_789);
        filetime::set_file_times(&protected, baseline_time, baseline_time).unwrap();
        let xattr_supported =
            xattr::set(&protected, "user.vollcrypt-shield-test", b"approved").is_ok();
        let baseline_metadata = std::fs::metadata(&protected).unwrap();

        let mut active = ResponsePolicy {
            actions: vec![
                ResponseAction::Warn,
                ResponseAction::Quarantine,
                ResponseAction::Rollback,
                ResponseAction::ContainScope,
            ],
            ..ResponsePolicy::default()
        };
        active.promote([9; 32], 1).unwrap();
        assert_eq!(active.mode, PolicyMode::Active);

        let break_glass_path = base.path().join("offline-break-glass.seed");
        let mut agent = ShieldAgent::initialize(
            config(
                state,
                vec![
                    scope("scope-a", root_a.clone(), active),
                    scope("scope-b", root_b.clone(), ResponsePolicy::default()),
                ],
            ),
            &break_glass_path,
        )
        .unwrap();
        agent.create_baseline("scope-a").unwrap();
        agent.create_baseline("scope-b").unwrap();

        std::fs::write(root_a.join("app.conf"), b"tampered-a").unwrap();
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o600)).unwrap();
        if xattr_supported {
            xattr::set(&protected, "user.vollcrypt-shield-test", b"tampered").unwrap();
        }
        let (_report, outcomes) = agent.verify_scope("scope-a").unwrap();
        assert!(outcomes.iter().any(|outcome| {
            matches!(outcome, ResponseOutcome::Quarantined(path) if path == "app.conf")
        }));
        assert!(outcomes.iter().any(|outcome| {
            matches!(outcome, ResponseOutcome::RolledBack(path) if path == "app.conf")
        }));
        let quarantine_records = agent
            .response
            .vault()
            .verify_quarantine_records("scope-a", &agent.agent_public)
            .unwrap();
        assert!(
            quarantine_records
                .iter()
                .any(|record| record.original_path == "app.conf")
        );
        assert_eq!(
            std::fs::read(root_a.join("app.conf")).unwrap(),
            b"approved-a"
        );
        let restored_metadata = std::fs::metadata(&protected).unwrap();
        assert_eq!(restored_metadata.mode() & 0o777, 0o640);
        assert_eq!(restored_metadata.uid(), baseline_metadata.uid());
        assert_eq!(restored_metadata.gid(), baseline_metadata.gid());
        assert_eq!(restored_metadata.mtime(), baseline_metadata.mtime());
        assert_eq!(
            restored_metadata.mtime_nsec(),
            baseline_metadata.mtime_nsec()
        );
        if xattr_supported {
            assert_eq!(
                xattr::get(&protected, "user.vollcrypt-shield-test").unwrap(),
                Some(b"approved".to_vec())
            );
        }
        assert!(agent.is_contained("scope-a"));
        assert!(!agent.is_contained("scope-b"));

        let break_secret =
            MlDsa65SecretKey::from_seed(&std::fs::read(&break_glass_path).unwrap()).unwrap();
        let now = now_unix_ms().unwrap();
        let command = BreakGlassCommand::release("scope-a", now, now + 60_000).unwrap();
        let signed = SignedBreakGlassCommand::sign(&command, &break_secret).unwrap();
        let encoded = signed.to_cbor().unwrap();
        agent.apply_break_glass(&encoded, "scope-a").unwrap();
        assert!(!agent.is_contained("scope-a"));

        std::fs::write(root_a.join("app.conf"), b"tampered-again").unwrap();
        let _ = agent.verify_scope("scope-a").unwrap();
        assert!(agent.is_contained("scope-a"));
        assert!(matches!(
            agent.apply_break_glass(&encoded, "scope-a"),
            Err(AgentError::BreakGlassReplay)
        ));
        assert!(agent.verify_audit().unwrap() >= 8);
    }
}
