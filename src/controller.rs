use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    aws::{
        AwsAccessLevel, AwsBroker, AwsConfiguration, AwsLoginStatus, AwsSettings,
        AwsSettingsSummary, validate_aws_profile,
    },
    grants::{
        DEFAULT_GRANT_SECONDS, GRANT_EXTENSION_SECONDS, Grant, GrantStore, MAX_GRANT_SECONDS,
        now_millis,
    },
    process::{
        ProcessIdentity, inspect_processes, is_launchd_process, omit_secretd_client_processes,
        process_is_alive, same_process,
    },
    vault::{SecretSummary, VaultError, VaultStore, normalize_secret_name},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    Deny,
    Once,
    Temporary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestResolution {
    Approved,
    Denied,
    Failed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    AllowedOnce,
    GrantedTemporarily,
    AutoGranted,
    Denied,
    TimedOut,
    Revoked,
    Unblocked,
    AwsAccessChanged(AwsAccessLevel),
}

#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub id: String,
    pub occurred_at: u64,
    pub action: AuditAction,
    pub secret: String,
    pub ttl_seconds: Option<u64>,
    pub process: ProcessIdentity,
}

#[derive(Clone, Debug)]
pub struct PendingRequest {
    pub id: String,
    pub secret: String,
    pub verified: bool,
    pub process_tree: Vec<ProcessIdentity>,
    pub origin: ProcessIdentity,
    pub requested_at: u64,
    /// How many times the process has asked. Repeats wait on this request and share its answer.
    pub asks: usize,
}

#[derive(Clone, Debug)]
pub struct PendingAwsCredentialRequest {
    pub id: String,
    pub profile: String,
    pub verified: bool,
    pub process_tree: Vec<ProcessIdentity>,
    pub origin: ProcessIdentity,
    pub requested_at: u64,
    /// How many times the process has asked. Repeats wait on this request and share its answer.
    pub asks: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AwsRequestResolution {
    Approved(AwsAccessLevel),
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AwsDecision {
    Grant(AwsAccessLevel),
    /// Denies, and doesn't ask the chosen process or its children again for 30 minutes.
    Deny,
    /// Denies this time only.
    Dismiss,
}

pub enum AwsRequestOutcome {
    Immediate(AwsAccessLevel),
    Denied,
    Pending {
        id: String,
        origin: ProcessIdentity,
        receiver: Receiver<AwsRequestResolution>,
    },
}

#[derive(Clone, Debug)]
pub struct AwsCredentialGrant {
    pub id: String,
    pub profile: String,
    pub level: AwsAccessLevel,
    pub process: ProcessIdentity,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
pub struct AwsCredentialDenial {
    pub id: String,
    pub profile: String,
    pub process: ProcessIdentity,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
pub struct AppSnapshot {
    pub vault_exists: bool,
    pub unlocked: bool,
    pub secrets: Vec<SecretSummary>,
    pub pending: Vec<PendingRequest>,
    pub pending_aws: Vec<PendingAwsCredentialRequest>,
    pub grants: Vec<Grant>,
    pub aws_grants: Vec<AwsCredentialGrant>,
    pub aws_denials: Vec<AwsCredentialDenial>,
    pub audit: Vec<AuditEntry>,
    pub max_grant_seconds: u64,
    pub aws: Option<AwsSettingsSummary>,
    pub aws_login: AwsLoginStatus,
}

pub enum RequestOutcome {
    Immediate(Zeroizing<String>),
    Pending {
        id: String,
        origin: ProcessIdentity,
        receiver: Receiver<RequestResolution>,
    },
}

pub struct Controller {
    vault: VaultStore,
    grants: GrantStore,
    pending: HashMap<String, PendingRequest>,
    pending_resolutions: HashMap<String, Vec<Sender<RequestResolution>>>,
    waiting_for_unlock: HashSet<String>,
    audit: Vec<AuditEntry>,
    aws_broker: AwsBroker,
    pending_aws: HashMap<String, PendingAwsCredentialRequest>,
    pending_aws_resolutions: HashMap<String, Vec<Sender<AwsRequestResolution>>>,
    aws_process_decisions: Vec<AwsCredentialGrant>,
    aws_process_denials: Vec<AwsCredentialDenial>,
    aws_login: AwsLoginStatus,
}

impl Controller {
    pub fn new(vault_path: PathBuf) -> Self {
        Self {
            vault: VaultStore::new(vault_path),
            grants: GrantStore::default(),
            pending: HashMap::new(),
            pending_resolutions: HashMap::new(),
            waiting_for_unlock: HashSet::new(),
            audit: Vec::new(),
            aws_broker: AwsBroker::new().expect("AWS runtime should start"),
            pending_aws: HashMap::new(),
            pending_aws_resolutions: HashMap::new(),
            aws_process_decisions: Vec::new(),
            aws_process_denials: Vec::new(),
            aws_login: AwsLoginStatus::Idle,
        }
    }

    pub fn snapshot(&mut self) -> AppSnapshot {
        let now = now_millis();
        self.aws_process_decisions
            .retain(|decision| decision.expires_at > now);
        self.aws_process_denials
            .retain(|denial| denial.expires_at > now);
        let vault_exists = self.vault.exists().unwrap_or(false);
        let unlocked = self.vault.unlocked();
        let secrets = if unlocked {
            self.vault.list().unwrap_or_default()
        } else {
            Vec::new()
        };
        // IDs break ties between requests from the same millisecond, so they don't swap places
        // between refreshes.
        let mut pending: Vec<_> = self.pending.values().cloned().collect();
        pending.sort_by(|left, right| {
            (left.requested_at, &left.id).cmp(&(right.requested_at, &right.id))
        });
        let mut audit = self.audit.clone();
        audit.reverse();
        let mut pending_aws: Vec<_> = self.pending_aws.values().cloned().collect();
        pending_aws.sort_by(|left, right| {
            (left.requested_at, &left.id).cmp(&(right.requested_at, &right.id))
        });
        let aws = if unlocked {
            self.vault
                .aws_settings()
                .ok()
                .flatten()
                .map(|settings| settings.summary())
        } else {
            None
        };
        AppSnapshot {
            vault_exists,
            unlocked,
            secrets,
            pending,
            pending_aws,
            grants: self.grants.list(),
            aws_grants: self.aws_process_decisions.clone(),
            aws_denials: self.aws_process_denials.clone(),
            audit,
            max_grant_seconds: MAX_GRANT_SECONDS,
            aws,
            aws_login: self.aws_login.clone(),
        }
    }

    pub fn create_vault(&mut self, password: &str) -> Result<(), VaultError> {
        self.vault.create(password)?;
        self.prepare_waiting_requests();
        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), VaultError> {
        self.vault.unlock(password)?;
        self.prepare_waiting_requests();
        Ok(())
    }

    pub fn lock(&mut self) {
        self.vault.lock();
        for grant in self.grants.list() {
            self.revoke_grant(&grant.id);
        }
        let pending: Vec<_> = self.pending.keys().cloned().collect();
        for id in pending {
            let _ = self.respond(&id, ApprovalDecision::Deny, None, None);
        }
        for sender in self
            .pending_aws_resolutions
            .drain()
            .flat_map(|(_, senders)| senders)
        {
            let _ = sender.send(AwsRequestResolution::Denied);
        }
        self.pending_aws.clear();
        self.aws_process_decisions.clear();
        self.aws_process_denials.clear();
        self.aws_login = AwsLoginStatus::Idle;
    }

    pub fn save_secret(
        &mut self,
        name: &str,
        value: &str,
        previous_name: Option<&str>,
    ) -> Result<(), VaultError> {
        if let Some(previous) = previous_name
            && normalize_secret_name(previous)? != normalize_secret_name(name)?
        {
            self.vault.rename(previous, name)?;
        }
        self.vault.save_secret(name, value)
    }

    pub fn reveal_secret(&self, name: &str) -> Result<Zeroizing<String>, VaultError> {
        self.vault.reveal(name)
    }

    pub fn delete_secret(&mut self, name: &str) -> Result<(), VaultError> {
        let normalized = normalize_secret_name(name)?;
        self.vault.delete(&normalized)?;
        for grant in self.grants.list() {
            if grant.resource == normalized {
                self.revoke_grant(&grant.id);
            }
        }
        Ok(())
    }

    pub fn change_password(&mut self, password: &str) -> Result<(), VaultError> {
        self.vault.change_password(password)
    }

    pub fn save_aws_configuration(
        &mut self,
        configuration: AwsConfiguration,
    ) -> Result<(), VaultError> {
        let mut settings = match self.vault.aws_settings()? {
            Some(settings) => settings,
            None => AwsSettings::from_configuration(configuration.clone()).map_err(VaultError)?,
        };
        settings
            .update_configuration(configuration)
            .map_err(VaultError)?;
        self.vault.save_aws_settings(settings)?;
        self.aws_process_decisions.clear();
        self.aws_process_denials.clear();
        self.aws_login = AwsLoginStatus::Idle;
        Ok(())
    }

    pub fn save_aws_connection(
        &mut self,
        start_url: String,
        sso_region: String,
    ) -> Result<(), VaultError> {
        let targets = self
            .vault
            .aws_settings()?
            .map_or_else(Vec::new, |settings| settings.targets);
        self.save_aws_configuration(AwsConfiguration {
            start_url,
            sso_region,
            targets,
        })
    }

    pub fn prepare_aws_login(&mut self) -> Result<(AwsBroker, AwsSettings), VaultError> {
        let context = self.preview_aws_login()?;
        self.aws_login = AwsLoginStatus::Starting;
        Ok(context)
    }

    pub fn preview_aws_login(&self) -> Result<(AwsBroker, AwsSettings), VaultError> {
        if matches!(
            self.aws_login,
            AwsLoginStatus::Starting
                | AwsLoginStatus::AwaitingUser(_)
                | AwsLoginStatus::Discovering
        ) {
            return Err(VaultError("AWS SSO login is already in progress".into()));
        }
        let settings = self
            .vault
            .aws_settings()?
            .ok_or_else(|| VaultError("Configure AWS SSO before logging in".into()))?;
        settings.validate().map_err(VaultError)?;
        Ok((self.aws_broker.clone(), settings))
    }

    pub fn set_aws_login_status(&mut self, status: AwsLoginStatus) {
        self.aws_login = status;
    }

    pub fn complete_aws_login(&mut self, result: Result<AwsSettings, String>) {
        match result {
            Ok(settings) => {
                let expires_at = settings
                    .token
                    .as_ref()
                    .map_or(0, |token| token.access_token_expires_at);
                match self.persist_aws_session(&settings, true) {
                    Ok(()) => self.aws_login = AwsLoginStatus::LoggedIn { expires_at },
                    Err(error) => self.aws_login = AwsLoginStatus::Failed(error.to_string()),
                }
            }
            Err(error) => self.aws_login = AwsLoginStatus::Failed(error),
        }
    }

    pub fn complete_aws_discovery_failure(&mut self, settings: &AwsSettings, error: String) {
        self.aws_login = match self.persist_aws_session(settings, false) {
            Ok(()) => AwsLoginStatus::Failed(error),
            Err(persist_error) => AwsLoginStatus::Failed(format!(
                "{error}; the AWS session could not be saved: {persist_error}"
            )),
        };
    }

    pub fn begin_aws_request(
        &mut self,
        profile: &str,
        process_tree: Vec<ProcessIdentity>,
        verified: bool,
    ) -> Result<AwsRequestOutcome, VaultError> {
        let profile = normalize_aws_profile(profile)?;
        self.prune_exited_aws_grants();
        let now = now_millis();
        self.aws_process_denials
            .retain(|denial| denial.expires_at > now);
        let process_tree = omit_secretd_client_processes(&process_tree);
        let origin = requesting_process(&process_tree)?;
        if verified && self.aws_denied(&profile, &process_tree) {
            return Ok(AwsRequestOutcome::Denied);
        }
        if self.vault.unlocked() {
            self.vault
                .aws_settings()?
                .ok_or_else(|| VaultError("AWS SSO is not configured in secretd".into()))?
                .target(&profile)
                .map_err(VaultError)?;
            if verified
                && let Some(level) = self
                    .nearest_aws_grant(&profile, &process_tree)
                    .map(|grant| grant.level)
            {
                self.record_audit(AuditEntry {
                    id: String::new(),
                    occurred_at: 0,
                    action: AuditAction::AutoGranted,
                    secret: aws_audit_resource(&profile),
                    ttl_seconds: None,
                    process: origin,
                });
                return Ok(AwsRequestOutcome::Immediate(level));
            }
        }
        let (sender, receiver) = mpsc::channel();
        // A verified process that asks again while it waits, from the same parents, joins the
        // request it already has. The repeat shares its answer and its first timeout.
        let repeat = self.pending_aws.values_mut().find(|request| {
            verified
                && request.verified
                && request.profile == profile
                && same_tree(&request.process_tree, &process_tree)
        });
        let id = if let Some(request) = repeat {
            request.asks += 1;
            request.id.clone()
        } else {
            let id = Uuid::new_v4().to_string();
            let request = PendingAwsCredentialRequest {
                id: id.clone(),
                profile,
                verified,
                process_tree,
                origin: origin.clone(),
                requested_at: now_millis(),
                asks: 1,
            };
            self.pending_aws.insert(id.clone(), request);
            id
        };
        self.pending_aws_resolutions
            .entry(id.clone())
            .or_default()
            .push(sender);
        Ok(AwsRequestOutcome::Pending {
            id,
            origin,
            receiver,
        })
    }

    /// Whether an active denial covers a request from this process tree.
    fn aws_denied(&self, profile: &str, process_tree: &[ProcessIdentity]) -> bool {
        let now = now_millis();
        self.aws_process_denials.iter().any(|denial| {
            denial.profile == profile
                && denial.expires_at > now
                && process_tree
                    .iter()
                    .any(|process| same_process(process, &denial.process))
        })
    }

    /// The active grant nearest the requester in this process tree.
    fn nearest_aws_grant(
        &self,
        profile: &str,
        process_tree: &[ProcessIdentity],
    ) -> Option<&AwsCredentialGrant> {
        let now = now_millis();
        process_tree.iter().find_map(|process| {
            self.aws_process_decisions.iter().rev().find(|grant| {
                grant.profile == profile
                    && grant.expires_at > now
                    && same_process(&grant.process, process)
            })
        })
    }

    /// Answers waiting requests that a newer grant or denial covers, as if they had just arrived.
    fn settle_covered_aws_requests(&mut self) {
        let mut answers = Vec::new();
        let mut covered = Vec::new();
        for request in self.pending_aws.values().filter(|request| request.verified) {
            if self.aws_denied(&request.profile, &request.process_tree) {
                answers.push((request.id.clone(), AwsRequestResolution::Denied));
            } else if let Some(grant) =
                self.nearest_aws_grant(&request.profile, &request.process_tree)
            {
                covered.push((request, grant));
            }
        }
        // Inspect the covered chains together: each inspection launches two ps calls on macOS.
        let mut pids: Vec<_> = covered
            .iter()
            .flat_map(|(request, _)| request.process_tree.iter().map(|process| process.pid))
            .collect();
        pids.sort_unstable();
        pids.dedup();
        // An inspection failure leaves approvals waiting, but does not prevent denials.
        let live = inspect_processes(&pids).unwrap_or_default();
        answers.extend(
            covered
                .into_iter()
                .filter(|(request, grant)| {
                    still_under(&request.process_tree, &grant.process, &live)
                })
                .map(|(request, grant)| {
                    (
                        request.id.clone(),
                        AwsRequestResolution::Approved(grant.level),
                    )
                }),
        );
        for (id, answer) in answers {
            let Some(request) = self.pending_aws.remove(&id) else {
                continue;
            };
            self.record_audit(AuditEntry {
                id: String::new(),
                occurred_at: 0,
                action: if answer == AwsRequestResolution::Denied {
                    AuditAction::Denied
                } else {
                    AuditAction::AutoGranted
                },
                secret: aws_audit_resource(&request.profile),
                ttl_seconds: None,
                process: request.origin.clone(),
            });
            if answer != AwsRequestResolution::Denied {
                self.record_repeat_releases(
                    request.asks,
                    &aws_audit_resource(&request.profile),
                    &request.origin,
                );
            }
            for sender in self.pending_aws_resolutions.remove(&id).unwrap_or_default() {
                let _ = sender.send(answer);
            }
        }
    }

    pub fn prune_exited_aws_grants(&mut self) {
        let now = now_millis();
        self.aws_process_decisions
            .retain(|decision| decision.expires_at > now && process_is_alive(&decision.process));
    }

    /// Answers several requests with one decision. Each answer names a request and the process the
    /// decision applies to, where `None` means the requester. Requests that are no longer waiting
    /// are skipped, and nothing changes unless every remaining answer is valid.
    pub fn respond_aws_batch(
        &mut self,
        answers: &[(String, Option<ProcessIdentity>)],
        decision: AwsDecision,
        ttl_seconds: Option<u64>,
    ) -> Result<(), VaultError> {
        let answers: Vec<_> = answers
            .iter()
            .filter_map(|(id, process)| Some((self.pending_aws.get(id)?.clone(), process.clone())))
            .collect();
        if answers.is_empty() {
            return Err(VaultError("Request is no longer pending".into()));
        }
        let grant_seconds = if let AwsDecision::Grant(_) = decision {
            if !self.vault.unlocked() {
                return Err(VaultError("Vault is locked".into()));
            }
            let settings = self
                .vault
                .aws_settings()?
                .ok_or_else(|| VaultError("AWS SSO is not configured in secretd".into()))?;
            for (request, _) in &answers {
                settings.target(&request.profile).map_err(VaultError)?;
            }
            validated_grant_seconds(ttl_seconds)?
        } else {
            DEFAULT_GRANT_SECONDS
        };
        // Verified requests get a grant or denial on the chosen process. Others are answered once.
        let mut boundaries = Vec::with_capacity(answers.len());
        for (request, process) in &answers {
            boundaries.push(if request.verified && decision != AwsDecision::Dismiss {
                Some(validated_grant_process(
                    &request.process_tree,
                    &request.origin,
                    process.clone(),
                )?)
            } else {
                None
            });
        }
        let now = now_millis();
        let mut remembered = false;
        for ((request, _), boundary) in answers.into_iter().zip(boundaries) {
            // A request listed twice is answered once.
            if self.pending_aws.remove(&request.id).is_none() {
                continue;
            }
            remembered |= boundary.is_some();
            let (action, ttl, answer) = match (decision, &boundary) {
                (AwsDecision::Grant(level), Some(process)) => {
                    self.aws_process_decisions.retain(|grant| {
                        grant.profile != request.profile || !same_process(&grant.process, process)
                    });
                    self.aws_process_decisions.push(AwsCredentialGrant {
                        id: Uuid::new_v4().to_string(),
                        profile: request.profile.clone(),
                        level,
                        process: process.clone(),
                        created_at: now,
                        expires_at: now.saturating_add(grant_seconds.saturating_mul(1_000)),
                    });
                    (
                        AuditAction::GrantedTemporarily,
                        Some(grant_seconds),
                        AwsRequestResolution::Approved(level),
                    )
                }
                (AwsDecision::Grant(level), None) => (
                    AuditAction::AllowedOnce,
                    None,
                    AwsRequestResolution::Approved(level),
                ),
                (AwsDecision::Deny, Some(process)) => {
                    self.remember_aws_denial(&request.profile, process);
                    (
                        AuditAction::Denied,
                        Some(DEFAULT_GRANT_SECONDS),
                        AwsRequestResolution::Denied,
                    )
                }
                (AwsDecision::Deny | AwsDecision::Dismiss, _) => {
                    (AuditAction::Denied, None, AwsRequestResolution::Denied)
                }
            };
            self.record_audit(AuditEntry {
                id: String::new(),
                occurred_at: 0,
                action,
                secret: aws_audit_resource(&request.profile),
                ttl_seconds: ttl,
                process: boundary.unwrap_or_else(|| request.origin.clone()),
            });
            if answer != AwsRequestResolution::Denied {
                self.record_repeat_releases(
                    request.asks,
                    &aws_audit_resource(&request.profile),
                    &request.origin,
                );
            }
            for sender in self
                .pending_aws_resolutions
                .remove(&request.id)
                .unwrap_or_default()
            {
                let _ = sender.send(answer);
            }
        }
        // Covered requests settle once every answered one has its own grant or denial, so a child
        // ticked along with its parent keeps the grant it was given.
        if remembered {
            self.settle_covered_aws_requests();
        }
        Ok(())
    }

    pub fn timeout_aws_request(&mut self, id: &str) {
        let Some(request) = self.pending_aws.remove(id) else {
            return;
        };
        self.pending_aws_resolutions.remove(id);
        self.record_audit(AuditEntry {
            id: String::new(),
            occurred_at: 0,
            action: AuditAction::TimedOut,
            secret: aws_audit_resource(&request.profile),
            ttl_seconds: request.verified.then_some(DEFAULT_GRANT_SECONDS),
            process: request.origin.clone(),
        });
        // Nobody chose a boundary, so the block covers the requester and its children.
        if request.verified {
            self.remember_aws_denial(&request.profile, &request.origin);
            self.settle_covered_aws_requests();
        }
    }

    /// Drops a request whose process exited or was orphaned before anyone answered it. Unlike a
    /// timeout, it starts no deny cooldown: the request was abandoned, not ignored.
    pub fn withdraw_aws_request(&mut self, id: &str) {
        self.pending_aws.remove(id);
        self.pending_aws_resolutions.remove(id);
    }

    fn remember_aws_denial(&mut self, profile: &str, process: &ProcessIdentity) {
        self.aws_process_denials
            .retain(|denial| denial.profile != profile || !same_process(&denial.process, process));
        let now = now_millis();
        self.aws_process_denials.push(AwsCredentialDenial {
            id: Uuid::new_v4().to_string(),
            profile: profile.to_string(),
            process: process.clone(),
            created_at: now,
            expires_at: now.saturating_add(DEFAULT_GRANT_SECONDS * 1_000),
        });
    }

    pub fn revoke_aws_denial(&mut self, id: &str) {
        let Some(index) = self
            .aws_process_denials
            .iter()
            .position(|denial| denial.id == id)
        else {
            return;
        };
        let denial = self.aws_process_denials.remove(index);
        self.record_audit(AuditEntry {
            id: String::new(),
            occurred_at: 0,
            action: AuditAction::Unblocked,
            secret: aws_audit_resource(&denial.profile),
            ttl_seconds: None,
            process: denial.process,
        });
    }

    pub fn revoke_aws_grant(&mut self, id: &str) {
        let Some(index) = self
            .aws_process_decisions
            .iter()
            .position(|decision| decision.id == id)
        else {
            return;
        };
        let grant = self.aws_process_decisions.remove(index);
        self.record_audit(AuditEntry {
            id: String::new(),
            occurred_at: 0,
            action: AuditAction::Revoked,
            secret: aws_audit_resource(&grant.profile),
            ttl_seconds: None,
            process: grant.process,
        });
    }

    pub fn set_aws_grant_level(
        &mut self,
        id: &str,
        level: AwsAccessLevel,
    ) -> Result<(), VaultError> {
        if !self.vault.unlocked() {
            return Err(VaultError("Vault is locked".into()));
        }
        self.prune_exited_aws_grants();
        let grant = self
            .aws_process_decisions
            .iter_mut()
            .find(|grant| grant.id == id)
            .ok_or_else(|| VaultError("Grant is no longer active".into()))?;
        if grant.level == level {
            return Ok(());
        }
        grant.level = level;
        let profile = grant.profile.clone();
        let process = grant.process.clone();
        self.record_audit(AuditEntry {
            id: String::new(),
            occurred_at: 0,
            action: AuditAction::AwsAccessChanged(level),
            secret: aws_audit_resource(&profile),
            ttl_seconds: None,
            process,
        });
        Ok(())
    }

    pub fn extend_aws_grant(&mut self, id: &str) {
        let now = now_millis();
        if let Some(grant) = self
            .aws_process_decisions
            .iter_mut()
            .find(|grant| grant.id == id && grant.expires_at > now)
        {
            grant.expires_at = grant
                .expires_at
                .saturating_add(GRANT_EXTENSION_SECONDS.saturating_mul(1_000))
                .min(now.saturating_add(MAX_GRANT_SECONDS.saturating_mul(1_000)));
        }
    }

    pub fn aws_credential_context(&self) -> Result<(AwsBroker, AwsSettings), VaultError> {
        let settings = self
            .vault
            .aws_settings()?
            .ok_or_else(|| VaultError("AWS SSO is not configured in secretd".into()))?;
        Ok((self.aws_broker.clone(), settings))
    }

    pub fn persist_aws_settings(&mut self, settings: &AwsSettings) -> Result<(), VaultError> {
        self.persist_aws_session(settings, false)
    }

    fn persist_aws_session(
        &mut self,
        session: &AwsSettings,
        include_discovery: bool,
    ) -> Result<(), VaultError> {
        let mut current = self
            .vault
            .aws_settings()?
            .ok_or_else(|| VaultError("AWS SSO is not configured in secretd".into()))?;
        if current.start_url != session.start_url || current.sso_region != session.sso_region {
            return Err(VaultError(
                "AWS SSO setup changed while the operation was in progress; retry it".into(),
            ));
        }
        current.registration = session.registration.clone();
        current.token = session.token.clone();
        if include_discovery {
            let discovered = session.discovered_accounts.clone();
            current.targets.retain(|target| {
                discovered.iter().any(|account| {
                    account.account_id == target.account_id
                        && account.roles.contains(&target.read_only_role)
                        && account.roles.contains(&target.admin_role)
                })
            });
            current.discovered_accounts = discovered;
            current.discovery_complete = session.discovery_complete;
        }
        self.vault.save_aws_settings(current)
    }

    pub fn revoke_grant(&mut self, id: &str) {
        let Some(grant) = self.grants.revoke(id) else {
            return;
        };
        self.record_audit(AuditEntry {
            id: String::new(),
            occurred_at: 0,
            action: AuditAction::Revoked,
            secret: grant.resource,
            ttl_seconds: None,
            process: grant.process,
        });
    }

    pub fn begin_request(
        &mut self,
        secret_input: &str,
        process_tree: Vec<ProcessIdentity>,
        verified: bool,
    ) -> Result<RequestOutcome, VaultError> {
        let secret = normalize_secret_name(secret_input)?;
        let process_tree = omit_secretd_client_processes(&process_tree);
        let origin = requesting_process(&process_tree)?;
        if !self.vault.unlocked() {
            return Ok(self.queue_request(secret, process_tree, origin, verified, true));
        }
        drop(self.vault.reveal(&secret)?);
        if verified && self.grants.find(&secret, &process_tree).is_some() {
            self.record_audit(AuditEntry {
                id: String::new(),
                occurred_at: 0,
                action: AuditAction::AutoGranted,
                secret: secret.clone(),
                ttl_seconds: None,
                process: origin,
            });
            return Ok(RequestOutcome::Immediate(self.vault.reveal(&secret)?));
        }
        Ok(self.queue_request(secret, process_tree, origin, verified, false))
    }

    fn queue_request(
        &mut self,
        secret: String,
        process_tree: Vec<ProcessIdentity>,
        origin: ProcessIdentity,
        verified: bool,
        waiting_for_unlock: bool,
    ) -> RequestOutcome {
        let (sender, receiver) = mpsc::channel();
        // A verified process that asks again while it waits, from the same parents, joins the
        // request it already has. The repeat shares its answer and its first timeout.
        let repeat = self.pending.values_mut().find(|request| {
            verified
                && request.verified
                && request.secret == secret
                && same_tree(&request.process_tree, &process_tree)
        });
        let id = if let Some(request) = repeat {
            request.asks += 1;
            request.id.clone()
        } else {
            let id = Uuid::new_v4().to_string();
            let request = PendingRequest {
                id: id.clone(),
                secret,
                verified,
                process_tree,
                origin: origin.clone(),
                requested_at: now_millis(),
                asks: 1,
            };
            self.pending.insert(id.clone(), request);
            if waiting_for_unlock {
                self.waiting_for_unlock.insert(id.clone());
            }
            id
        };
        self.pending_resolutions
            .entry(id.clone())
            .or_default()
            .push(sender);
        RequestOutcome::Pending {
            id,
            origin,
            receiver,
        }
    }

    fn prepare_waiting_requests(&mut self) {
        let waiting: Vec<_> = self.waiting_for_unlock.drain().collect();
        for id in waiting {
            let Some(request) = self.pending.get(&id).cloned() else {
                continue;
            };
            let prepared = self.vault.reveal(&request.secret);
            match prepared {
                Ok(value) => drop(value),
                Err(error) => {
                    self.pending.remove(&id);
                    for sender in self.pending_resolutions.remove(&id).unwrap_or_default() {
                        let _ = sender.send(RequestResolution::Failed(error.to_string()));
                    }
                }
            }
        }
    }

    pub fn respond(
        &mut self,
        id: &str,
        decision: ApprovalDecision,
        ttl_seconds: Option<u64>,
        grant_process: Option<ProcessIdentity>,
    ) -> Result<(), VaultError> {
        self.respond_batch(&[(id.to_string(), grant_process)], decision, ttl_seconds)
    }

    /// Answers several secret requests with one decision, the way
    /// [`respond_aws_batch`](Self::respond_aws_batch) answers AWS requests.
    pub fn respond_batch(
        &mut self,
        answers: &[(String, Option<ProcessIdentity>)],
        decision: ApprovalDecision,
        ttl_seconds: Option<u64>,
    ) -> Result<(), VaultError> {
        let answers: Vec<_> = answers
            .iter()
            .filter_map(|(id, process)| Some((self.pending.get(id)?.clone(), process.clone())))
            .collect();
        if answers.is_empty() {
            return Err(VaultError("Request is no longer pending".into()));
        }
        let mut boundaries = Vec::with_capacity(answers.len());
        for (request, process) in &answers {
            if self.waiting_for_unlock.contains(&request.id) && decision != ApprovalDecision::Deny {
                return Err(VaultError("Vault is locked".into()));
            }
            if decision != ApprovalDecision::Temporary {
                boundaries.push(None);
                continue;
            }
            if !request.verified {
                return Err(VaultError(
                    "Unverified requests can only be allowed once".into(),
                ));
            }
            boundaries.push(Some(validated_grant_process(
                &request.process_tree,
                &request.origin,
                process.clone(),
            )?));
        }
        let grant_seconds = if decision == ApprovalDecision::Temporary {
            validated_grant_seconds(ttl_seconds)?
        } else {
            DEFAULT_GRANT_SECONDS
        };
        let answer = if decision == ApprovalDecision::Deny {
            RequestResolution::Denied
        } else {
            RequestResolution::Approved
        };
        let mut granted = false;
        for ((request, _), boundary) in answers.into_iter().zip(boundaries) {
            // A request listed twice is answered once.
            if self.pending.remove(&request.id).is_none() {
                continue;
            }
            self.waiting_for_unlock.remove(&request.id);
            granted |= boundary.is_some();
            if let Some(process) = &boundary {
                self.grants
                    .add(request.secret.clone(), process.clone(), grant_seconds)
                    .map_err(VaultError)?;
            }
            self.record_audit(AuditEntry {
                id: String::new(),
                occurred_at: 0,
                action: match decision {
                    ApprovalDecision::Deny => AuditAction::Denied,
                    ApprovalDecision::Once => AuditAction::AllowedOnce,
                    ApprovalDecision::Temporary => AuditAction::GrantedTemporarily,
                },
                secret: request.secret.clone(),
                ttl_seconds: boundary.is_some().then_some(grant_seconds),
                process: boundary.unwrap_or_else(|| request.origin.clone()),
            });
            if decision != ApprovalDecision::Deny {
                self.record_repeat_releases(request.asks, &request.secret, &request.origin);
            }
            for sender in self
                .pending_resolutions
                .remove(&request.id)
                .unwrap_or_default()
            {
                let _ = sender.send(answer.clone());
            }
        }
        // Covered requests settle once every answered one has its own grant, so a child ticked
        // along with its parent keeps the grant it was given.
        if granted {
            self.settle_covered_requests();
        }
        Ok(())
    }

    /// Answers waiting secret requests that a newer grant covers, as if they had just arrived.
    fn settle_covered_requests(&mut self) {
        let covered: Vec<_> = self
            .pending
            .values()
            .filter(|request| request.verified && !self.waiting_for_unlock.contains(&request.id))
            .filter_map(|request| {
                self.grants
                    .find(&request.secret, &request.process_tree)
                    .map(|grant| (request, grant.process))
            })
            .collect();
        let mut pids: Vec<_> = covered
            .iter()
            .flat_map(|(request, _)| request.process_tree.iter().map(|process| process.pid))
            .collect();
        pids.sort_unstable();
        pids.dedup();
        let live = inspect_processes(&pids).unwrap_or_default();
        let answers: Vec<_> = covered
            .into_iter()
            .filter(|(request, boundary)| still_under(&request.process_tree, boundary, &live))
            .map(|(request, _)| request.id.clone())
            .collect();
        for id in answers {
            let Some(request) = self.pending.remove(&id) else {
                continue;
            };
            self.record_audit(AuditEntry {
                id: String::new(),
                occurred_at: 0,
                action: AuditAction::AutoGranted,
                secret: request.secret.clone(),
                ttl_seconds: None,
                process: request.origin.clone(),
            });
            self.record_repeat_releases(request.asks, &request.secret, &request.origin);
            for sender in self.pending_resolutions.remove(&id).unwrap_or_default() {
                let _ = sender.send(RequestResolution::Approved);
            }
        }
    }

    pub fn timeout_request(&mut self, id: &str) {
        let Some(request) = self.pending.remove(id) else {
            return;
        };
        self.pending_resolutions.remove(id);
        self.waiting_for_unlock.remove(id);
        self.record_audit(AuditEntry {
            id: String::new(),
            occurred_at: 0,
            action: AuditAction::TimedOut,
            secret: request.secret,
            ttl_seconds: None,
            process: request.origin,
        });
    }

    /// Drops a request whose process exited or was orphaned before anyone answered it.
    pub fn withdraw_request(&mut self, id: &str) {
        self.pending.remove(id);
        self.pending_resolutions.remove(id);
        self.waiting_for_unlock.remove(id);
    }

    pub fn release_after_approval(&self, secret: &str) -> Result<Zeroizing<String>, VaultError> {
        self.vault.reveal(secret)
    }

    fn record_audit(&mut self, mut entry: AuditEntry) {
        entry.id = Uuid::new_v4().to_string();
        entry.occurred_at = now_millis();
        self.audit.push(entry);
        if self.audit.len() > 500 {
            self.audit.drain(..self.audit.len() - 500);
        }
    }

    /// Logs the repeats an approval answers after the request's own entry. Each one receives the
    /// secret or its own credentials, so it is logged as released, like a request that a grant
    /// answers when it arrives.
    fn record_repeat_releases(&mut self, asks: usize, resource: &str, process: &ProcessIdentity) {
        for _ in 1..asks {
            self.record_audit(AuditEntry {
                id: String::new(),
                occurred_at: 0,
                action: AuditAction::AutoGranted,
                secret: resource.to_string(),
                ttl_seconds: None,
                process: process.clone(),
            });
        }
    }

    pub fn extend_grant(&mut self, id: &str) {
        let _ = self.grants.extend(id);
    }
}

fn normalize_aws_profile(profile: &str) -> Result<String, VaultError> {
    let profile = profile.trim();
    validate_aws_profile(profile).map_err(VaultError)?;
    Ok(profile.to_string())
}

fn aws_audit_resource(profile: &str) -> String {
    format!("aws/{profile}")
}

fn same_tree(left: &[ProcessIdentity], right: &[ProcessIdentity]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| same_process(left, right))
}

/// Whether a waiting requester still runs under `boundary` through the processes it asked from. A
/// request can wait for minutes, and a parent that exits meanwhile takes its children out of the
/// boundary's subtree. The live snapshot is shared by all requests covered by this settlement.
fn still_under(
    process_tree: &[ProcessIdentity],
    boundary: &ProcessIdentity,
    live: &HashMap<u32, ProcessIdentity>,
) -> bool {
    let Some(depth) = process_tree
        .iter()
        .position(|process| same_process(process, boundary))
    else {
        return false;
    };
    let chain = &process_tree[..=depth];
    // Each link must be the same process with the same parent. The boundary's own parent may
    // change without taking the requester out from under it.
    chain.iter().enumerate().all(|(index, expected)| {
        live.get(&expected.pid).is_some_and(|current| {
            same_process(current, expected) && (index == depth || current.ppid == expected.ppid)
        })
    })
}

fn requesting_process(process_tree: &[ProcessIdentity]) -> Result<ProcessIdentity, VaultError> {
    // launchd adopts secretd when the process that ran it has already exited.
    process_tree
        .first()
        .filter(|process| !is_launchd_process(process))
        .cloned()
        .ok_or_else(|| VaultError("Unable to determine the requesting process".into()))
}

fn validated_grant_process(
    process_tree: &[ProcessIdentity],
    origin: &ProcessIdentity,
    selected: Option<ProcessIdentity>,
) -> Result<ProcessIdentity, VaultError> {
    let selected = selected.unwrap_or_else(|| origin.clone());
    if is_launchd_process(&selected) {
        return Err(VaultError(
            "launchd cannot be used as a grant boundary".into(),
        ));
    }
    process_tree
        .iter()
        .find(|process| same_process(process, &selected))
        .cloned()
        .ok_or_else(|| VaultError("Selected process is not in the verified process tree".into()))
}

fn validated_grant_seconds(seconds: Option<u64>) -> Result<u64, VaultError> {
    let seconds = seconds.unwrap_or(DEFAULT_GRANT_SECONDS);
    if seconds == 0 || seconds > MAX_GRANT_SECONDS {
        return Err(VaultError(format!(
            "Grant duration must be between 1 and {MAX_GRANT_SECONDS} seconds"
        )));
    }
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn process(pid: u32, executable: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            ppid: pid.saturating_sub(1),
            started_at: format!("start-{pid}"),
            executable: executable.into(),
            command: executable.into(),
        }
    }

    fn live_process() -> ProcessIdentity {
        crate::process::inspect_process_tree(std::process::id(), 1)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }

    fn aws_configuration() -> AwsConfiguration {
        AwsConfiguration {
            start_url: "https://example.awsapps.com/start".into(),
            sso_region: "ca-central-1".into(),
            targets: vec![
                crate::aws::AwsTarget {
                    profile: "prod".into(),
                    account_id: "123456789012".into(),
                    read_only_role: "ReadOnly".into(),
                    admin_role: "Administrator".into(),
                    region: "ca-central-1".into(),
                },
                crate::aws::AwsTarget {
                    profile: "dev".into(),
                    account_id: "210987654321".into(),
                    read_only_role: "ReadOnly".into(),
                    admin_role: "Administrator".into(),
                    region: "ca-central-1".into(),
                },
            ],
        }
    }

    /// A `sleep` started by this test, so its ancestry can be checked while it waits.
    struct Running(std::process::Child);

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn running_child() -> (Running, ProcessIdentity) {
        let child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let identity = crate::process::inspect_process_tree(child.id(), 1)
            .unwrap()
            .remove(0);
        (Running(child), identity)
    }

    fn waiting(
        controller: &mut Controller,
        profile: &str,
        process_tree: Vec<ProcessIdentity>,
        verified: bool,
    ) -> (String, Receiver<AwsRequestResolution>) {
        let AwsRequestOutcome::Pending { id, receiver, .. } = controller
            .begin_aws_request(profile, process_tree, verified)
            .unwrap()
        else {
            panic!("request should wait for an answer");
        };
        (id, receiver)
    }

    #[test]
    fn a_waiting_request_requires_its_live_chain_to_the_boundary() {
        let boundary = process(10, "/bin/zsh");
        let mut parent = process(20, "/bin/sh");
        parent.ppid = boundary.pid;
        let mut requester = process(30, "/usr/local/bin/aws");
        requester.ppid = parent.pid;
        let tree = vec![requester, parent.clone(), boundary.clone()];
        let mut live: HashMap<_, _> = tree
            .iter()
            .map(|process| (process.pid, process.clone()))
            .collect();

        assert!(still_under(&tree, &boundary, &live));
        // The boundary can be adopted without changing which processes run under it.
        live.get_mut(&boundary.pid).unwrap().ppid = 1;
        assert!(still_under(&tree, &boundary, &live));

        // An intermediate process moving or being replaced breaks the saved ancestry.
        live.get_mut(&parent.pid).unwrap().ppid = 1;
        assert!(!still_under(&tree, &boundary, &live));
        live.insert(parent.pid, parent.clone());
        live.get_mut(&parent.pid)
            .unwrap()
            .started_at
            .push_str("-reused");
        assert!(!still_under(&tree, &boundary, &live));

        live.remove(&parent.pid);
        assert!(!still_under(&tree, &boundary, &live));
        assert!(!still_under(&tree, &boundary, &HashMap::new()));
    }

    #[test]
    fn aws_role_is_chosen_by_approval_and_pinned_to_the_process() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let terraform = live_process();
        let outcome = controller
            .begin_aws_request("prod", vec![terraform.clone()], true)
            .unwrap();
        let AwsRequestOutcome::Pending { id, receiver, .. } = outcome else {
            panic!("first request should require a decision");
        };
        controller
            .respond_aws_batch(
                &[(id, None)],
                AwsDecision::Grant(AwsAccessLevel::ReadOnly),
                None,
            )
            .unwrap();
        assert_eq!(
            receiver.recv().unwrap(),
            AwsRequestResolution::Approved(AwsAccessLevel::ReadOnly)
        );
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.aws_grants.len(), 1);
        assert_eq!(snapshot.aws_grants[0].profile, "prod");
        assert_eq!(snapshot.aws_grants[0].level, AwsAccessLevel::ReadOnly);
        assert_eq!(
            snapshot.aws_grants[0]
                .expires_at
                .saturating_sub(snapshot.aws_grants[0].created_at),
            DEFAULT_GRANT_SECONDS * 1_000
        );
        let grant_id = snapshot.aws_grants[0].id.clone();
        let original_expiry = snapshot.aws_grants[0].expires_at;
        controller.extend_aws_grant(&grant_id);
        assert_eq!(
            controller.snapshot().aws_grants[0].expires_at,
            original_expiry + GRANT_EXTENSION_SECONDS * 1_000
        );
        controller.extend_aws_grant(&grant_id);
        assert_eq!(
            controller.snapshot().aws_grants[0].expires_at,
            original_expiry + 2 * GRANT_EXTENSION_SECONDS * 1_000
        );
        controller.extend_aws_grant(&grant_id);
        assert!(
            controller.snapshot().aws_grants[0].expires_at
                <= now_millis() + MAX_GRANT_SECONDS * 1_000
        );

        let outcome = controller
            .begin_aws_request("prod", vec![terraform.clone()], true)
            .unwrap();
        assert!(matches!(
            outcome,
            AwsRequestOutcome::Immediate(AwsAccessLevel::ReadOnly)
        ));

        controller.revoke_aws_grant(&grant_id);
        assert!(controller.snapshot().aws_grants.is_empty());
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![terraform], true)
                .unwrap(),
            AwsRequestOutcome::Pending { .. }
        ));
    }

    #[test]
    fn aws_grant_access_can_change_without_changing_scope_or_expiration() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let ancestor = live_process();
        let child = process(20, "/usr/local/bin/terraform");
        for profile in ["prod", "dev"] {
            let AwsRequestOutcome::Pending { id, .. } = controller
                .begin_aws_request(profile, vec![child.clone(), ancestor.clone()], true)
                .unwrap()
            else {
                panic!("first request should require approval");
            };
            controller
                .respond_aws_batch(
                    &[(id, Some(ancestor.clone()))],
                    AwsDecision::Grant(AwsAccessLevel::ReadOnly),
                    None,
                )
                .unwrap();
        }
        let original = controller.snapshot().aws_grants[0].clone();
        let other = controller.snapshot().aws_grants[1].clone();
        for level in [AwsAccessLevel::Admin, AwsAccessLevel::ReadOnly] {
            controller.set_aws_grant_level(&original.id, level).unwrap();
            let snapshot = controller.snapshot();
            assert_eq!(snapshot.aws_grants.len(), 2);
            let grant = &snapshot.aws_grants[0];
            assert_eq!(grant.id, original.id);
            assert_eq!(grant.profile, original.profile);
            assert!(same_process(&grant.process, &original.process));
            assert_eq!(grant.created_at, original.created_at);
            assert_eq!(grant.expires_at, original.expires_at);
            assert_eq!(grant.level, level);
            assert_eq!(snapshot.aws_grants[1].id, other.id);
            assert_eq!(snapshot.aws_grants[1].level, other.level);
            assert_eq!(
                snapshot.audit[0].action,
                AuditAction::AwsAccessChanged(level)
            );
            assert_eq!(snapshot.audit[0].secret, "aws/prod");
            assert!(same_process(&snapshot.audit[0].process, &ancestor));
            assert!(matches!(
                controller
                    .begin_aws_request("prod", vec![child.clone(), ancestor.clone()], true)
                    .unwrap(),
                AwsRequestOutcome::Immediate(actual) if actual == level
            ));
        }
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![child, ancestor], false)
                .unwrap(),
            AwsRequestOutcome::Pending { .. }
        ));
    }

    #[test]
    fn aws_grant_access_changes_reject_inactive_grants_and_a_locked_vault() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        let now = now_millis();
        for (id, process, expires_at) in [
            ("expired", live_process(), now.saturating_sub(1)),
            (
                "exited",
                process(u32::MAX, "/missing/terraform"),
                now + DEFAULT_GRANT_SECONDS * 1_000,
            ),
            (
                "revoked",
                live_process(),
                now + DEFAULT_GRANT_SECONDS * 1_000,
            ),
        ] {
            controller.aws_process_decisions.push(AwsCredentialGrant {
                id: id.into(),
                profile: "prod".into(),
                level: AwsAccessLevel::ReadOnly,
                process,
                created_at: now.saturating_sub(DEFAULT_GRANT_SECONDS * 1_000),
                expires_at,
            });
        }
        controller.revoke_aws_grant("revoked");
        for id in ["expired", "exited", "revoked", "missing"] {
            assert_eq!(
                controller
                    .set_aws_grant_level(id, AwsAccessLevel::Admin)
                    .unwrap_err()
                    .to_string(),
                "Grant is no longer active"
            );
        }
        let snapshot = controller.snapshot();
        assert!(snapshot.aws_grants.is_empty());
        assert_eq!(snapshot.audit.len(), 1);
        assert_eq!(snapshot.audit[0].action, AuditAction::Revoked);
        controller.lock();
        assert_eq!(
            controller
                .set_aws_grant_level("missing", AwsAccessLevel::Admin)
                .unwrap_err()
                .to_string(),
            "Vault is locked"
        );
    }

    #[test]
    fn aws_denial_blocks_the_chosen_process_and_its_children() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let script = live_process();
        let aws = |pid| process(pid, "/usr/local/bin/aws");
        let (id, receiver) = waiting(&mut controller, "prod", vec![aws(20), script.clone()], true);

        // Denying with the default boundary blocks only the requester, not its siblings.
        controller
            .respond_aws_batch(&[(id, None)], AwsDecision::Deny, None)
            .unwrap();

        assert_eq!(receiver.recv().unwrap(), AwsRequestResolution::Denied);
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.audit.len(), 1);
        assert_eq!(snapshot.audit[0].action, AuditAction::Denied);
        assert_eq!(snapshot.audit[0].secret, "aws/prod");
        assert_eq!(snapshot.audit[0].ttl_seconds, Some(DEFAULT_GRANT_SECONDS));
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![aws(20), script.clone()], true)
                .unwrap(),
            AwsRequestOutcome::Denied
        ));
        let (sibling, _) = waiting(&mut controller, "prod", vec![aws(21), script.clone()], true);
        let (_, waiting_sibling) =
            waiting(&mut controller, "prod", vec![aws(22), script.clone()], true);

        // Denying the script blocks everything under it, including requests already waiting.
        controller
            .respond_aws_batch(&[(sibling, Some(script.clone()))], AwsDecision::Deny, None)
            .unwrap();

        assert_eq!(
            waiting_sibling.recv().unwrap(),
            AwsRequestResolution::Denied
        );
        let snapshot = controller.snapshot();
        assert!(snapshot.pending_aws.is_empty());
        let denial_id = snapshot
            .aws_denials
            .iter()
            .find(|denial| same_process(&denial.process, &script))
            .unwrap()
            .id
            .clone();
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![aws(23), script.clone()], true)
                .unwrap(),
            AwsRequestOutcome::Denied
        ));
        assert!(matches!(
            controller
                .begin_aws_request("dev", vec![aws(24), script.clone()], true)
                .unwrap(),
            AwsRequestOutcome::Pending { .. }
        ));
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![aws(25), process(26, "/bin/zsh")], true)
                .unwrap(),
            AwsRequestOutcome::Pending { .. }
        ));

        controller.revoke_aws_denial(&denial_id);

        assert_eq!(
            controller.snapshot().audit[0].action,
            AuditAction::Unblocked
        );
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![aws(27), script], true)
                .unwrap(),
            AwsRequestOutcome::Pending { .. }
        ));
    }

    #[test]
    fn a_parent_grant_preserves_a_child_denial_until_unblocked() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let shell = live_process();
        let child = process(20, "/usr/local/bin/aws");
        let (first, _) = waiting(
            &mut controller,
            "prod",
            vec![child.clone(), shell.clone()],
            true,
        );
        controller
            .respond_aws_batch(&[(first, None)], AwsDecision::Deny, None)
            .unwrap();
        let denial_id = controller.snapshot().aws_denials[0].id.clone();
        let (sibling, _) = waiting(
            &mut controller,
            "prod",
            vec![process(21, "/usr/local/bin/aws"), shell.clone()],
            true,
        );

        controller
            .respond_aws_batch(
                &[(sibling, Some(shell.clone()))],
                AwsDecision::Grant(AwsAccessLevel::Admin),
                None,
            )
            .unwrap();

        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![child.clone(), shell.clone()], true)
                .unwrap(),
            AwsRequestOutcome::Denied
        ));
        assert_eq!(controller.snapshot().aws_denials.len(), 1);
        controller.revoke_aws_denial(&denial_id);
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![child, shell], true)
                .unwrap(),
            AwsRequestOutcome::Immediate(AwsAccessLevel::Admin)
        ));
    }

    #[test]
    fn dismissed_aws_request_denies_only_the_current_command() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let requester = live_process();
        let AwsRequestOutcome::Pending { id, receiver, .. } = controller
            .begin_aws_request("prod", vec![requester.clone()], true)
            .unwrap()
        else {
            panic!("first request should be pending");
        };

        controller
            .respond_aws_batch(&[(id, None)], AwsDecision::Dismiss, None)
            .unwrap();

        assert_eq!(receiver.recv().unwrap(), AwsRequestResolution::Denied);
        let snapshot = controller.snapshot();
        assert!(snapshot.aws_denials.is_empty());
        assert_eq!(snapshot.audit[0].action, AuditAction::Denied);
        assert_eq!(snapshot.audit[0].ttl_seconds, None);
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![requester], true)
                .unwrap(),
            AwsRequestOutcome::Pending { .. }
        ));
    }

    #[test]
    fn aws_timeout_is_audited_and_starts_the_deny_cooldown() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let requester = live_process();
        let (id, _) = waiting(&mut controller, "prod", vec![requester.clone()], true);
        let (_, child) = waiting(
            &mut controller,
            "prod",
            vec![process(20, "/usr/local/bin/aws"), requester.clone()],
            true,
        );

        controller.timeout_aws_request(&id);

        // The block covers the waiting child too, and its denial is logged after the timeout.
        assert_eq!(child.recv().unwrap(), AwsRequestResolution::Denied);
        let snapshot = controller.snapshot();
        assert_eq!(
            snapshot
                .audit
                .iter()
                .map(|entry| entry.action)
                .collect::<Vec<_>>(),
            [AuditAction::Denied, AuditAction::TimedOut]
        );
        assert_eq!(snapshot.audit[1].secret, "aws/prod");
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![requester], true)
                .unwrap(),
            AwsRequestOutcome::Denied
        ));
    }

    #[test]
    fn withdrawn_requests_leave_no_denial_or_audit_entry() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_secret("deploy/token", "secret", None)
            .unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let requester = live_process();
        let helper = process(30, "/usr/local/bin/secretd");
        let RequestOutcome::Pending { id: secret_id, .. } = controller
            .begin_request("deploy/token", vec![requester.clone()], true)
            .unwrap()
        else {
            panic!("secret request should be pending");
        };
        let AwsRequestOutcome::Pending {
            id: aws_id, origin, ..
        } = controller
            .begin_aws_request("prod", vec![helper, requester.clone()], true)
            .unwrap()
        else {
            panic!("AWS request should be pending");
        };
        // The server watches the process that ran secretd, not the secretd helper itself.
        assert_eq!(origin, requester);

        controller.withdraw_request(&secret_id);
        controller.withdraw_aws_request(&aws_id);

        let snapshot = controller.snapshot();
        assert!(snapshot.pending.is_empty());
        assert!(snapshot.pending_aws.is_empty());
        assert!(snapshot.aws_denials.is_empty());
        assert!(snapshot.audit.is_empty());
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![requester], true)
                .unwrap(),
            AwsRequestOutcome::Pending { .. }
        ));
    }

    #[test]
    fn requests_whose_requester_already_exited_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_secret("deploy/token", "secret", None)
            .unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        // The process that ran secretd exited, so launchd adopted the helper.
        let orphaned = vec![
            process(30, "/usr/local/bin/secretd"),
            process(1, "/sbin/launchd"),
        ];

        assert!(
            controller
                .begin_request("deploy/token", orphaned.clone(), true)
                .is_err()
        );
        assert!(
            controller
                .begin_aws_request("prod", orphaned, true)
                .is_err()
        );
        let snapshot = controller.snapshot();
        assert!(snapshot.pending.is_empty());
        assert!(snapshot.pending_aws.is_empty());
    }

    #[test]
    fn repeat_requests_from_one_process_share_one_answer() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let terraform = live_process();
        let (id, first) = waiting(&mut controller, "prod", vec![terraform.clone()], true);
        let (repeat_id, repeat) = waiting(&mut controller, "prod", vec![terraform.clone()], true);
        // Anyone can claim a PID, so an unverified request never joins a verified one.
        let (unverified_id, _) = waiting(&mut controller, "prod", vec![terraform.clone()], false);
        // The same process under different parents is somewhere else, so it waits on its own.
        let (moved_id, _) = waiting(
            &mut controller,
            "prod",
            vec![terraform, process(1, "/sbin/launchd")],
            true,
        );

        assert_eq!(repeat_id, id);
        assert_ne!(unverified_id, id);
        assert_ne!(moved_id, id);
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.pending_aws.len(), 3);
        assert_eq!(
            snapshot
                .pending_aws
                .iter()
                .find(|request| request.id == id)
                .unwrap()
                .asks,
            2
        );

        controller
            .respond_aws_batch(
                &[(id, None)],
                AwsDecision::Grant(AwsAccessLevel::Admin),
                None,
            )
            .unwrap();

        for receiver in [first, repeat] {
            assert_eq!(
                receiver.recv().unwrap(),
                AwsRequestResolution::Approved(AwsAccessLevel::Admin)
            );
        }
        // The grant covers the process itself, so its other request is answered too. The repeat
        // fetched credentials as well, so it is logged as released.
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.pending_aws.len(), 1);
        assert_eq!(
            snapshot
                .audit
                .iter()
                .map(|entry| entry.action)
                .collect::<Vec<_>>(),
            [
                AuditAction::AutoGranted,
                AuditAction::AutoGranted,
                AuditAction::GrantedTemporarily
            ]
        );
    }

    #[test]
    fn a_grant_answers_the_waiting_requests_it_covers() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let script = live_process();
        let (_sibling_process, sibling_identity) = running_child();
        let (_second_sibling_process, second_sibling_identity) = running_child();
        let aws = |pid| process(pid, "/usr/local/bin/aws");
        let (first, _) = waiting(&mut controller, "prod", vec![aws(20), script.clone()], true);
        let (_, sibling) = waiting(
            &mut controller,
            "prod",
            vec![sibling_identity.clone(), script.clone()],
            true,
        );
        let (_, sibling_repeat) = waiting(
            &mut controller,
            "prod",
            vec![sibling_identity, script.clone()],
            true,
        );
        let (_, second_sibling) = waiting(
            &mut controller,
            "prod",
            vec![second_sibling_identity, script.clone()],
            true,
        );
        let (_, other_profile) =
            waiting(&mut controller, "dev", vec![aws(22), script.clone()], true);
        let (_, unverified) = waiting(
            &mut controller,
            "prod",
            vec![aws(23), script.clone()],
            false,
        );
        // It was recorded under a parent that still runs, but it no longer runs under that parent.
        let (_parent_process, parent) = running_child();
        let (_moved_process, mut moved_identity) = running_child();
        moved_identity.ppid = parent.pid;
        let (_, moved) = waiting(
            &mut controller,
            "prod",
            vec![moved_identity, parent, script.clone()],
            true,
        );

        controller
            .respond_aws_batch(
                &[(first, Some(script.clone()))],
                AwsDecision::Grant(AwsAccessLevel::ReadOnly),
                None,
            )
            .unwrap();

        for receiver in [sibling, sibling_repeat, second_sibling] {
            assert_eq!(
                receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
                AwsRequestResolution::Approved(AwsAccessLevel::ReadOnly)
            );
        }
        assert!(other_profile.try_recv().is_err());
        assert!(unverified.try_recv().is_err());
        assert!(moved.try_recv().is_err());
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.pending_aws.len(), 3);
        assert_eq!(
            snapshot
                .audit
                .iter()
                .map(|entry| entry.action)
                .collect::<Vec<_>>(),
            [
                AuditAction::AutoGranted,
                AuditAction::AutoGranted,
                AuditAction::AutoGranted,
                AuditAction::GrantedTemporarily,
            ]
        );
    }

    #[test]
    fn a_shared_boundary_grants_an_aws_profile_once() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let shell = live_process();
        let (_first_process, first_identity) = running_child();
        let (_second_process, second_identity) = running_child();
        let (_third_process, third_identity) = running_child();
        let (first, first_answer) = waiting(
            &mut controller,
            "prod",
            vec![first_identity, shell.clone()],
            true,
        );
        let (second, second_answer) = waiting(
            &mut controller,
            "prod",
            vec![second_identity, shell.clone()],
            true,
        );

        controller
            .respond_aws_batch(
                &[(first, Some(shell.clone())), (second, Some(shell.clone()))],
                AwsDecision::Grant(AwsAccessLevel::ReadOnly),
                None,
            )
            .unwrap();

        for receiver in [first_answer, second_answer] {
            assert_eq!(
                receiver.recv().unwrap(),
                AwsRequestResolution::Approved(AwsAccessLevel::ReadOnly)
            );
        }
        let grants = controller.snapshot().aws_grants;
        assert_eq!(grants.len(), 1);
        assert!(same_process(&grants[0].process, &shell));

        // One revocation ends the access.
        controller.revoke_aws_grant(&grants[0].id);
        assert!(controller.snapshot().aws_grants.is_empty());
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![third_identity, shell], true)
                .unwrap(),
            AwsRequestOutcome::Pending { .. }
        ));
    }

    #[test]
    fn each_requesting_process_gets_its_own_grant_under_another_one() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        controller
            .save_secret("deploy/token", "secret", None)
            .unwrap();
        let script = live_process();
        let (_child_process, child) = running_child();
        let (parent, parent_answer) = waiting(&mut controller, "prod", vec![script.clone()], true);
        let (child_id, child_answer) = waiting(
            &mut controller,
            "prod",
            vec![child.clone(), script.clone()],
            true,
        );

        // The parent's grant would cover the child, but the child was given its own.
        controller
            .respond_aws_batch(
                &[(parent, None), (child_id, None)],
                AwsDecision::Grant(AwsAccessLevel::ReadOnly),
                None,
            )
            .unwrap();

        for receiver in [parent_answer, child_answer] {
            assert_eq!(
                receiver.recv().unwrap(),
                AwsRequestResolution::Approved(AwsAccessLevel::ReadOnly)
            );
        }
        let grants = controller.snapshot().aws_grants;
        assert_eq!(grants.len(), 2);
        assert!(
            grants
                .iter()
                .any(|grant| same_process(&grant.process, &child))
        );

        let mut wait = |process_tree| {
            let RequestOutcome::Pending { id, .. } = controller
                .begin_request("deploy/token", process_tree, true)
                .unwrap()
            else {
                panic!("request should wait for an answer");
            };
            id
        };
        let parent = wait(vec![script.clone()]);
        let child_id = wait(vec![child.clone(), script]);

        controller
            .respond_batch(
                &[(parent, None), (child_id, None)],
                ApprovalDecision::Temporary,
                None,
            )
            .unwrap();

        let grants = controller.snapshot().grants;
        assert_eq!(grants.len(), 2);
        assert!(
            grants
                .iter()
                .any(|grant| same_process(&grant.process, &child))
        );
    }

    #[test]
    fn one_batch_answers_several_profiles_through_a_shared_process() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let script = live_process();
        let (_covered_process, covered_identity) = running_child();
        let aws = |pid| process(pid, "/usr/local/bin/aws");
        let (prod, prod_answer) =
            waiting(&mut controller, "prod", vec![aws(20), script.clone()], true);
        let (_, covered_answer) = waiting(
            &mut controller,
            "prod",
            vec![covered_identity, script.clone()],
            true,
        );
        let (dev, dev_answer) =
            waiting(&mut controller, "dev", vec![aws(22), script.clone()], true);
        let (elsewhere, _) = waiting(
            &mut controller,
            "prod",
            vec![aws(23), process(24, "/bin/zsh")],
            true,
        );
        let read_only = AwsDecision::Grant(AwsAccessLevel::ReadOnly);

        // The script isn't in every request's tree, so nothing is answered.
        assert!(
            controller
                .respond_aws_batch(
                    &[
                        (prod.clone(), Some(script.clone())),
                        (elsewhere, Some(script.clone())),
                    ],
                    read_only,
                    None,
                )
                .is_err()
        );
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.pending_aws.len(), 4);
        assert!(snapshot.aws_grants.is_empty());

        // Requests that are already gone are skipped.
        controller
            .respond_aws_batch(
                &[
                    ("gone".into(), None),
                    (prod, Some(script.clone())),
                    (dev, Some(script.clone())),
                ],
                read_only,
                None,
            )
            .unwrap();

        for receiver in [prod_answer, covered_answer, dev_answer] {
            assert_eq!(
                receiver.recv().unwrap(),
                AwsRequestResolution::Approved(AwsAccessLevel::ReadOnly)
            );
        }
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.pending_aws.len(), 1);
        assert_eq!(snapshot.aws_grants.len(), 2);
        assert!(
            snapshot
                .aws_grants
                .iter()
                .all(|grant| same_process(&grant.process, &script))
        );
    }

    #[test]
    fn aws_grant_for_an_ancestor_is_reused_by_another_child() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let ancestor = live_process();
        let first_child = process(20, "/usr/local/bin/terraform");
        let AwsRequestOutcome::Pending { id, .. } = controller
            .begin_aws_request("prod", vec![first_child, ancestor.clone()], true)
            .unwrap()
        else {
            panic!("first child should require approval");
        };
        controller
            .respond_aws_batch(
                &[(id, Some(ancestor.clone()))],
                AwsDecision::Grant(AwsAccessLevel::Admin),
                None,
            )
            .unwrap();

        let second_child = process(21, "/usr/local/bin/terraform");
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![second_child, ancestor], true)
                .unwrap(),
            AwsRequestOutcome::Immediate(AwsAccessLevel::Admin)
        ));
    }

    #[test]
    fn explicit_cleanup_prunes_exited_aws_grants() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.aws_process_decisions.push(AwsCredentialGrant {
            id: "stale".into(),
            profile: "prod".into(),
            level: AwsAccessLevel::Admin,
            process: process(u32::MAX, "/missing/terraform"),
            created_at: now_millis(),
            expires_at: now_millis().saturating_add(DEFAULT_GRANT_SECONDS * 1_000),
        });
        controller.aws_process_decisions.push(AwsCredentialGrant {
            id: "expired".into(),
            profile: "prod".into(),
            level: AwsAccessLevel::ReadOnly,
            process: live_process(),
            created_at: now_millis().saturating_sub(DEFAULT_GRANT_SECONDS * 1_000),
            expires_at: now_millis().saturating_sub(1),
        });

        let snapshot = controller.snapshot();
        assert_eq!(snapshot.aws_grants.len(), 1);
        assert_eq!(snapshot.aws_grants[0].id, "stale");

        controller.prune_exited_aws_grants();

        assert!(controller.snapshot().aws_grants.is_empty());
    }

    #[test]
    fn aws_session_refresh_does_not_overwrite_newer_profile_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let (_, mut stale) = controller.aws_credential_context().unwrap();

        let mut updated = aws_configuration();
        updated.targets[0].admin_role = "NewAdministrator".into();
        controller.save_aws_configuration(updated).unwrap();
        stale.token = Some(crate::aws::AwsSsoToken {
            access_token: "access".into(),
            access_token_expires_at: u64::MAX,
            refresh_token: "refresh".into(),
        });
        controller.persist_aws_settings(&stale).unwrap();

        let settings = controller.vault.aws_settings().unwrap().unwrap();
        assert_eq!(settings.targets[0].admin_role, "NewAdministrator");
        assert_eq!(
            settings
                .token
                .as_ref()
                .map(|token| token.access_token.as_str()),
            Some("access")
        );
    }

    #[test]
    fn secret_grant_for_an_ancestor_is_reused_by_another_child() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_secret("deploy/token", "secret", None)
            .unwrap();
        let ancestor = process(10, "/bin/zsh");
        let first_child = process(20, "/usr/local/bin/terraform");
        let RequestOutcome::Pending { id, .. } = controller
            .begin_request("deploy/token", vec![first_child, ancestor.clone()], true)
            .unwrap()
        else {
            panic!("first child should require approval");
        };
        controller
            .respond(
                &id,
                ApprovalDecision::Temporary,
                Some(300),
                Some(ancestor.clone()),
            )
            .unwrap();

        let second_child = process(21, "/usr/local/bin/terraform");
        assert!(matches!(
            controller
                .begin_request("deploy/token", vec![second_child, ancestor], true)
                .unwrap(),
            RequestOutcome::Immediate(_)
        ));
    }

    #[test]
    fn a_secret_grant_answers_repeats_and_the_waiting_requests_it_covers() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_secret("deploy/token", "secret", None)
            .unwrap();
        let shell = live_process();
        let terraform = process(20, "/usr/local/bin/terraform");
        let (_sibling_process, sibling_identity) = running_child();
        let (_second_sibling_process, second_sibling_identity) = running_child();
        let mut wait = |process_tree| {
            let RequestOutcome::Pending { id, receiver, .. } = controller
                .begin_request("deploy/token", process_tree, true)
                .unwrap()
            else {
                panic!("request should wait for an answer");
            };
            (id, receiver)
        };
        let (id, first) = wait(vec![terraform.clone(), shell.clone()]);
        let (repeat_id, repeat) = wait(vec![terraform, shell.clone()]);
        let (_, sibling) = wait(vec![sibling_identity.clone(), shell.clone()]);
        let (_, sibling_repeat) = wait(vec![sibling_identity, shell.clone()]);
        let (_, second_sibling) = wait(vec![second_sibling_identity, shell.clone()]);

        assert_eq!(repeat_id, id);
        controller
            .respond(&id, ApprovalDecision::Temporary, None, Some(shell))
            .unwrap();

        for receiver in [first, repeat, sibling, sibling_repeat, second_sibling] {
            assert_eq!(
                receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
                RequestResolution::Approved
            );
        }
        let snapshot = controller.snapshot();
        assert!(snapshot.pending.is_empty());
        // Repeats of both the selected and automatically settled requests received the secret.
        assert_eq!(
            snapshot
                .audit
                .iter()
                .map(|entry| entry.action)
                .collect::<Vec<_>>(),
            [
                AuditAction::AutoGranted,
                AuditAction::AutoGranted,
                AuditAction::AutoGranted,
                AuditAction::AutoGranted,
                AuditAction::GrantedTemporarily
            ]
        );
    }

    #[test]
    fn a_shared_boundary_grants_a_secret_once() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_secret("deploy/token", "secret", None)
            .unwrap();
        let shell = live_process();
        let (_first_process, first_identity) = running_child();
        let (_second_process, second_identity) = running_child();
        let (_third_process, third_identity) = running_child();
        let mut wait = |process_tree| {
            let RequestOutcome::Pending { id, receiver, .. } = controller
                .begin_request("deploy/token", process_tree, true)
                .unwrap()
            else {
                panic!("request should wait for an answer");
            };
            (id, receiver)
        };
        let (first, first_answer) = wait(vec![first_identity, shell.clone()]);
        let (second, second_answer) = wait(vec![second_identity, shell.clone()]);

        controller
            .respond_batch(
                &[(first, Some(shell.clone())), (second, Some(shell.clone()))],
                ApprovalDecision::Temporary,
                None,
            )
            .unwrap();

        for receiver in [first_answer, second_answer] {
            assert_eq!(receiver.recv().unwrap(), RequestResolution::Approved);
        }
        let grants = controller.snapshot().grants;
        assert_eq!(grants.len(), 1);
        assert!(same_process(&grants[0].process, &shell));

        // One revocation ends the access.
        controller.revoke_grant(&grants[0].id);

        assert!(controller.snapshot().grants.is_empty());
        assert!(matches!(
            controller
                .begin_request("deploy/token", vec![third_identity, shell], true)
                .unwrap(),
            RequestOutcome::Pending { .. }
        ));
    }

    #[test]
    fn launchd_cannot_be_selected_as_a_grant_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller.save_secret("token", "secret", None).unwrap();
        let launchd = process(1, "/sbin/launchd");
        let RequestOutcome::Pending { id, .. } = controller
            .begin_request(
                "token",
                vec![process(20, "/usr/local/bin/tool"), launchd.clone()],
                true,
            )
            .unwrap()
        else {
            panic!("request should require approval");
        };

        let error = controller
            .respond(&id, ApprovalDecision::Temporary, Some(300), Some(launchd))
            .unwrap_err();
        assert!(error.to_string().contains("launchd"));
    }

    #[test]
    fn locked_request_waits_for_unlock_and_then_requires_approval() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_secret("qwer", "correct password", None)
            .unwrap();
        controller.lock();

        let outcome = controller
            .begin_request("qwer", vec![process(20, "/usr/local/bin/tool")], true)
            .unwrap();
        let RequestOutcome::Pending { id, receiver, .. } = outcome else {
            panic!("locked request should wait for unlock");
        };
        assert_eq!(controller.snapshot().pending.len(), 1);

        controller.unlock("correct horse").unwrap();
        controller
            .respond(&id, ApprovalDecision::Once, None, None)
            .unwrap();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            RequestResolution::Approved
        );
        assert_eq!(
            &*controller.release_after_approval("qwer").unwrap(),
            "correct password"
        );
    }

    #[test]
    fn locked_request_reports_validation_error_after_unlock() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller.lock();

        let outcome = controller
            .begin_request("missing", vec![process(20, "/usr/local/bin/tool")], true)
            .unwrap();
        let RequestOutcome::Pending { receiver, .. } = outcome else {
            panic!("locked request should wait for unlock");
        };

        controller.unlock("correct horse").unwrap();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            RequestResolution::Failed("Secret not found".into())
        );
        assert!(controller.snapshot().pending.is_empty());
    }

    #[test]
    fn grant_durations_default_to_thirty_minutes_and_cannot_start_over_one_hour() {
        assert_eq!(
            validated_grant_seconds(None).unwrap(),
            DEFAULT_GRANT_SECONDS
        );
        assert_eq!(
            validated_grant_seconds(Some(MAX_GRANT_SECONDS)).unwrap(),
            MAX_GRANT_SECONDS
        );
        assert!(validated_grant_seconds(Some(MAX_GRANT_SECONDS + 1)).is_err());
    }

    #[test]
    fn aws_parent_decisions_resolve_only_pending_requests_within_the_selected_scope() {
        for level in [
            None,
            Some(AwsAccessLevel::ReadOnly),
            Some(AwsAccessLevel::Admin),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let mut controller = Controller::new(directory.path().join("vault.json"));
            controller.create_vault("correct horse").unwrap();
            controller
                .save_aws_configuration(aws_configuration())
                .unwrap();
            let parent = live_process();
            let shared_ancestor = process(10, "/bin/zsh");
            let mut covered = Vec::new();
            let mut children = Vec::new();
            for _ in 20..44 {
                let (child, identity) = running_child();
                children.push(child);
                let AwsRequestOutcome::Pending { id, receiver, .. } = controller
                    .begin_aws_request(
                        "prod",
                        vec![identity, parent.clone(), shared_ancestor.clone()],
                        true,
                    )
                    .unwrap()
                else {
                    panic!("child should require a decision");
                };
                covered.push((id, receiver));
            }
            let mut reused_pid = parent.clone();
            reused_pid.started_at.push_str("-reused");
            let mut changed_executable = parent.clone();
            changed_executable.executable.push_str("-other");
            let mut excluded = Vec::new();
            for (profile, tree, verified) in [
                ("dev", vec![parent.clone()], true),
                ("prod", vec![parent.clone()], false),
                (
                    "prod",
                    vec![process(50, "/usr/local/bin/tool"), shared_ancestor],
                    true,
                ),
                ("prod", vec![reused_pid], true),
                ("prod", vec![changed_executable], true),
            ] {
                let AwsRequestOutcome::Pending { id, receiver, .. } = controller
                    .begin_aws_request(profile, tree, verified)
                    .unwrap()
                else {
                    panic!("unrelated request should remain pending");
                };
                excluded.push((id, receiver));
            }

            controller
                .respond_aws_batch(
                    &[(covered[0].0.clone(), Some(parent.clone()))],
                    level.map_or(AwsDecision::Deny, AwsDecision::Grant),
                    None,
                )
                .unwrap();

            let resolution =
                level.map_or(AwsRequestResolution::Denied, AwsRequestResolution::Approved);
            for (_, receiver) in covered {
                assert_eq!(
                    receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
                    resolution
                );
            }
            let snapshot = controller.snapshot();
            assert_eq!(snapshot.pending_aws.len(), excluded.len());
            assert_eq!(snapshot.audit.len(), 24);
            assert!(snapshot.audit.iter().all(|entry| entry.action
                == if level.is_some() {
                    if same_process(&entry.process, &parent) {
                        AuditAction::GrantedTemporarily
                    } else {
                        AuditAction::AutoGranted
                    }
                } else {
                    AuditAction::Denied
                }));
            for (id, receiver) in excluded {
                assert!(snapshot.pending_aws.iter().any(|request| request.id == id));
                assert!(matches!(
                    receiver.try_recv(),
                    Err(mpsc::TryRecvError::Empty)
                ));
            }
            if level.is_none() {
                assert_eq!(snapshot.aws_denials.len(), 1);
                assert_eq!(snapshot.aws_denials[0].process, parent);
            } else {
                assert_eq!(snapshot.aws_grants.len(), 1);
                assert_eq!(snapshot.aws_grants[0].process, parent);
            }
            let outcome = controller
                .begin_aws_request("prod", vec![parent], true)
                .unwrap();
            match level {
                Some(level) => assert!(
                    matches!(outcome, AwsRequestOutcome::Immediate(actual) if actual == level)
                ),
                None => assert!(matches!(outcome, AwsRequestOutcome::Denied)),
            }
        }
    }

    #[test]
    fn default_aws_denial_does_not_cover_sibling_requests() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        let parent = process(10, "/bin/zsh");
        let requester = process(20, "/usr/local/bin/tool");
        let AwsRequestOutcome::Pending { id, .. } = controller
            .begin_aws_request("prod", vec![requester.clone(), parent.clone()], true)
            .unwrap()
        else {
            panic!("request should be pending");
        };
        let AwsRequestOutcome::Pending {
            id: sibling_id,
            receiver,
            ..
        } = controller
            .begin_aws_request(
                "prod",
                vec![process(21, "/usr/local/bin/tool"), parent.clone()],
                true,
            )
            .unwrap()
        else {
            panic!("sibling should be pending");
        };

        controller
            .respond_aws_batch(&[(id.clone(), None)], AwsDecision::Deny, None)
            .unwrap();

        assert_eq!(controller.snapshot().aws_denials[0].process, requester);
        assert!(
            controller
                .snapshot()
                .pending_aws
                .iter()
                .any(|request| request.id == sibling_id)
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![parent], true)
                .unwrap(),
            AwsRequestOutcome::Pending { .. }
        ));
    }

    #[test]
    fn aws_block_rejects_a_boundary_outside_the_verified_tree_or_launchd() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        let launchd = process(1, "/sbin/launchd");
        let AwsRequestOutcome::Pending { id, receiver, .. } = controller
            .begin_aws_request(
                "prod",
                vec![process(20, "/usr/local/bin/tool"), launchd.clone()],
                true,
            )
            .unwrap()
        else {
            panic!("request should be pending");
        };

        for boundary in [launchd, process(99, "/usr/local/bin/other")] {
            assert!(
                controller
                    .respond_aws_batch(&[(id.clone(), Some(boundary))], AwsDecision::Deny, None)
                    .is_err()
            );
            assert!(controller.snapshot().aws_denials.is_empty());
            assert_eq!(controller.snapshot().pending_aws.len(), 1);
            assert!(matches!(
                receiver.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
        }
    }

    #[test]
    fn temporary_secret_grants_resolve_covered_pending_requests_but_allow_once_does_not() {
        for decision in [ApprovalDecision::Once, ApprovalDecision::Temporary] {
            let directory = tempfile::tempdir().unwrap();
            let mut controller = Controller::new(directory.path().join("vault.json"));
            controller.create_vault("correct horse").unwrap();
            controller.save_secret("token", "secret", None).unwrap();
            controller.save_secret("other", "secret", None).unwrap();
            let parent = live_process();
            let (_sibling_process, sibling_identity) = running_child();
            let shared_ancestor = process(1, "/sbin/launchd");
            let RequestOutcome::Pending { id, receiver, .. } = controller
                .begin_request(
                    "token",
                    vec![
                        process(20, "/usr/local/bin/tool"),
                        parent.clone(),
                        shared_ancestor.clone(),
                    ],
                    true,
                )
                .unwrap()
            else {
                panic!("request should be pending");
            };
            let RequestOutcome::Pending {
                id: sibling_id,
                receiver: sibling_receiver,
                ..
            } = controller
                .begin_request(
                    "token",
                    vec![sibling_identity, parent.clone(), shared_ancestor.clone()],
                    true,
                )
                .unwrap()
            else {
                panic!("sibling should be pending");
            };
            let mut excluded = Vec::new();
            for (secret, tree, verified) in [
                ("other", vec![parent.clone()], true),
                ("token", vec![parent.clone()], false),
                (
                    "token",
                    vec![process(30, "/usr/local/bin/tool"), shared_ancestor],
                    true,
                ),
            ] {
                let RequestOutcome::Pending { id, receiver, .. } =
                    controller.begin_request(secret, tree, verified).unwrap()
                else {
                    panic!("unrelated request should be pending");
                };
                excluded.push((id, receiver));
            }

            controller
                .respond(&id, decision, None, Some(parent))
                .unwrap();

            assert_eq!(
                receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
                RequestResolution::Approved
            );
            if decision == ApprovalDecision::Temporary {
                assert_eq!(
                    sibling_receiver
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap(),
                    RequestResolution::Approved
                );
                assert_eq!(
                    controller.snapshot().audit[0].action,
                    AuditAction::AutoGranted
                );
                assert!(
                    !controller
                        .snapshot()
                        .pending
                        .iter()
                        .any(|request| request.id == sibling_id)
                );
            } else {
                assert!(matches!(
                    sibling_receiver.try_recv(),
                    Err(mpsc::TryRecvError::Empty)
                ));
                assert!(
                    controller
                        .snapshot()
                        .pending
                        .iter()
                        .any(|request| request.id == sibling_id)
                );
            }
            for (id, receiver) in excluded {
                assert!(
                    controller
                        .snapshot()
                        .pending
                        .iter()
                        .any(|request| request.id == id)
                );
                assert!(matches!(
                    receiver.try_recv(),
                    Err(mpsc::TryRecvError::Empty)
                ));
            }
        }
    }

    #[test]
    fn unverified_aws_decisions_only_resolve_the_current_request() {
        for level in [None, Some(AwsAccessLevel::ReadOnly)] {
            let directory = tempfile::tempdir().unwrap();
            let mut controller = Controller::new(directory.path().join("vault.json"));
            controller.create_vault("correct horse").unwrap();
            controller
                .save_aws_configuration(aws_configuration())
                .unwrap();
            let parent = live_process();
            let AwsRequestOutcome::Pending { id, receiver, .. } = controller
                .begin_aws_request("prod", vec![parent.clone()], false)
                .unwrap()
            else {
                panic!("request should be pending");
            };
            let AwsRequestOutcome::Pending {
                id: sibling_id,
                receiver: sibling_receiver,
                ..
            } = controller
                .begin_aws_request("prod", vec![parent.clone()], true)
                .unwrap()
            else {
                panic!("sibling should be pending");
            };

            controller
                .respond_aws_batch(
                    &[(id.clone(), Some(parent))],
                    level.map_or(AwsDecision::Deny, AwsDecision::Grant),
                    None,
                )
                .unwrap();

            assert_eq!(
                receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
                level.map_or(AwsRequestResolution::Denied, AwsRequestResolution::Approved)
            );
            let snapshot = controller.snapshot();
            assert!(snapshot.aws_grants.is_empty());
            assert!(snapshot.aws_denials.is_empty());
            assert_eq!(snapshot.pending_aws.len(), 1);
            assert_eq!(snapshot.pending_aws[0].id, sibling_id);
            assert!(matches!(
                sibling_receiver.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
        }
    }
}
