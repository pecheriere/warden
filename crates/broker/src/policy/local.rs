//! [`SecretBackend`] backed by files on the broker's host.
//!
//! Weaker than 1Password, and never the default: the secrets are on the host,
//! so a compromised host gets them, and there is no read-only token between
//! warden and the policy. `docs/threat-model.md` says what is lost.
//!
//! The policy is a TOML file naming targets and API secrets; each secret is a
//! file of its own in one directory. Everything is read again on every call
//! and nothing is cached, so an edit applies at once and a removed secret stops
//! working at once. Entries become the same items 1Password yields and pass
//! through the same validators, so the two backends cannot drift apart.
//!
//! The policy and a secret are two reads, not one as with a 1Password item. A
//! secret always comes from the file named by the policy it is checked against,
//! but changing what a file holds and what the policy says are two steps: see
//! `docs/local-backend.md` for how to rotate.
//!
//! A policy file ends with a digest of itself, so that a read which mixes two
//! versions, or holds a part of one, is refused: see `verify_seal` and [`seal_policy_file`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use ssh_key::HashAlg;
use warden_broker_proto::{SecretName, TargetName};
use zeroize::Zeroizing;

use super::commit_signing_key::compare_with_ca;
use super::onepassword::{
    ApiItem, ItemUrl, SecretField, TargetItem, parse_api_secret, parse_private_key, parse_target,
};
use super::{
    ApiSecretPolicy, CaKey, CaProbe, CommitSigningKey, CommitSigningProbe, PolicyError,
    RelayCredential, SecretBackend, SecretValue, SshMode, SshTarget, not_a_relay_target,
};
use crate::audit::{AuditEvent, AuditLog};
use crate::config::LocalSettings;

mod files;
mod seal;

pub use seal::{ACCESS_NOTE, SealError, SealedPolicy, Unverified, seal_policy_file, seal_text};

use files::{Refusal, check_file_name, one_line, read_policy, read_secret};

/// The last line but one of a policy file. A file cut at any byte has lost it or
/// the digest after it, so it cannot pass for a complete one: a prefix of a valid
/// policy can otherwise be a valid and wider policy, because leaving out a
/// setting takes its default. TOML allows the table once, and an occurrence
/// inside an unfinished string does not parse, so no earlier cut can end with
/// this line and still load.
const END_MARKER: &str = "[end_of_policy]";

/// What the last line of a policy file starts with, before the digest in
/// lower-case hex and a closing quote.
const DIGEST_LINE_START: &str = "sha256 = \"";

/// Shown whenever a policy file's end cannot be trusted.
const HOW_TO_SEAL: &str = "to change it, check a draft and run warden-server seal-policy --from \
                           <draft> <file>; to see what this file allows, run warden-server \
                           seal-policy <file>";

/// What the audit log calls this backend.
const AUDIT_CONTEXT: &str = "local secret backend";

/// The policy file. Unknown settings are refused, so a secret pasted in as
/// `credential = "…"` stops the file from loading rather than sitting there.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    ca: Option<CaEntry>,
    commit_signing: Option<CaEntry>,
    #[serde(default)]
    targets: BTreeMap<String, TargetEntry>,
    #[serde(default)]
    api_secrets: BTreeMap<String, ApiEntry>,
    /// Checked before parsing: see `verify_seal`.
    #[serde(rename = "end_of_policy")]
    _end_of_policy: EndOfPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndOfPolicy {
    #[serde(rename = "sha256")]
    _sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaEntry {
    private_key_file: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetEntry {
    address: Option<String>,
    mode: Option<String>,
    users: Option<Vec<String>>,
    max_window: Option<String>,
    host_keys: Option<Vec<String>>,
    private_key_file: Option<String>,
    password_file: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiEntry {
    website: Option<String>,
    credential_file: Option<String>,
    max_window: Option<String>,
    header: Option<String>,
    format: Option<String>,
    methods: Option<Vec<String>>,
    path_prefix: Option<String>,
    ca_pem: Option<String>,
}

fn invalid(item: &str, field: &str, reason: impl Into<String>) -> PolicyError {
    PolicyError::Invalid {
        item: item.to_owned(),
        field: field.to_owned(),
        reason: reason.into(),
    }
}

/// A field of an item, as 1Password would hand it over.
fn field(label: &str, value: Zeroizing<String>) -> SecretField {
    SecretField {
        id: String::new(),
        label: Some(label.to_owned()),
        value: Some(value),
    }
}

fn plain_field(label: &str, value: &str) -> SecretField {
    field(label, Zeroizing::new(value.to_owned()))
}

/// An optional setting that is present must say something. For a 1Password
/// item a blank field takes the default, because a field cannot be removed from
/// some item categories; here it can, and `path_prefix = ""` must not silently
/// mean the widest prefix.
fn optional_field(
    item: &str,
    label: &str,
    value: Option<&str>,
) -> Result<Option<SecretField>, PolicyError> {
    match value {
        None => Ok(None),
        Some(text) if text.trim().is_empty() => Err(invalid(
            item,
            label,
            "is blank; remove the setting to take its default",
        )),
        Some(text) => Ok(Some(plain_field(label, text))),
    }
}

/// A name from the policy file, safe to show: it may be anything.
fn shown_name(name: &str) -> String {
    name.escape_default().take(64).collect()
}

/// What `warden-server doctor` and the startup check find.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalProbe {
    /// The policy file cannot be used at all. Holds the reason.
    Unreadable(String),
    /// The policy file parsed.
    Read {
        /// Entries under `[targets]`.
        targets: usize,
        /// Entries under `[api_secrets]`.
        api_secrets: usize,
        /// What is wrong with each unusable entry. Never a secret.
        problems: Vec<String>,
        /// Whether the CA key loads, or is needed.
        ca: CaProbe,
        /// Whether the commit signing key loads, or is configured.
        commit_signing: CommitSigningProbe,
    },
}

impl LocalProbe {
    /// Everything that keeps the server from starting.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        match self {
            Self::Unreadable(reason) => vec![reason.clone()],
            Self::Read {
                problems,
                ca,
                commit_signing,
                ..
            } => {
                let ca = match ca {
                    CaProbe::Loaded { .. } | CaProbe::NotNeeded => None,
                    CaProbe::Missing { cert_targets } => Some(format!(
                        "{cert_targets} certificate target(s) need a [ca] section"
                    )),
                    CaProbe::Invalid(reason) | CaProbe::Unknown(reason) => {
                        Some(format!("SSH CA: {reason}"))
                    }
                };
                let commit_signing = match commit_signing {
                    CommitSigningProbe::Loaded { .. } | CommitSigningProbe::NotConfigured => None,
                    CommitSigningProbe::Invalid(reason) | CommitSigningProbe::Unknown(reason) => {
                        Some(format!("commit signing key: {reason}"))
                    }
                };
                problems
                    .iter()
                    .cloned()
                    .chain(ca)
                    .chain(commit_signing)
                    .collect()
            }
        }
    }
}

/// The digest line for `sealed`, which is everything before that line.
fn digest_line(sealed: &str) -> String {
    let digest = hex::encode(Sha256::digest(sealed));
    format!("{DIGEST_LINE_START}{digest}\"")
}

/// Whether `text` is whole: it ends with [`END_MARKER`] and then the digest of
/// every byte before the digest line, which is the last line. A read that mixes
/// two versions of the file, in any proportion, holds bytes that do not match the
/// digest it ended with, unless they are that version's bytes. Checked on the very
/// bytes that get parsed, so nothing can change in between. The digest shows that
/// the file is what its last writer finished, not who that was: anyone who can
/// write the file can seal it.
fn verify_seal(text: &str) -> Result<(), String> {
    let complete = text.strip_suffix('\n').unwrap_or(text);
    let line_start = complete.rfind('\n').map_or(0, |at| at + 1);
    let (sealed, last_line) = complete.split_at(line_start);
    let ends_with_marker = sealed
        .strip_suffix('\n')
        .and_then(|rest| rest.strip_suffix(END_MARKER))
        .is_some_and(|before| before.is_empty() || before.ends_with('\n'));
    if !ends_with_marker || !last_line.starts_with(DIGEST_LINE_START) {
        return Err(format!(
            "does not end with the line {END_MARKER} and then its digest, so it may be cut short \
             or was never sealed; {HOW_TO_SEAL}"
        ));
    }
    if last_line != digest_line(sealed) {
        return Err(format!(
            "does not match the digest on its last line: it was changed without sealing, or read \
             while being overwritten; {HOW_TO_SEAL}"
        ));
    }
    Ok(())
}

/// A complete policy file, or what is wrong with it. The parser's message is
/// never used: it can quote the file, and a secret may have been pasted into it.
fn parse_policy(text: &str) -> Result<PolicyFile, String> {
    verify_seal(text)?;
    toml::from_str(text).map_err(|e| {
        let line = e
            .span()
            .and_then(|span| text.get(..span.start))
            .map_or(1, |before| before.matches('\n').count() + 1);
        format!(
            "cannot be used, at line {line}: a syntax error, an unknown or missing setting, a \
             repeated key or a wrong type"
        )
    })
}

/// The two paths, and who this process is. Everything here blocks.
#[derive(Clone)]
struct Files {
    policy_file: PathBuf,
    secrets_dir: PathBuf,
    euid: u32,
}

impl Files {
    /// The policy file, parsed.
    fn policy(&self) -> Result<PolicyFile, PolicyError> {
        let shown = |what: String| PolicyError::Unavailable(format!("the policy file {what}"));
        let text = read_policy(&self.policy_file, self.euid).map_err(|e| shown(e.to_string()))?;
        parse_policy(&text).map_err(shown)
    }

    /// The secret file `name`, for `field` of `item`.
    fn secret(
        &self,
        item: &str,
        field: &str,
        name: &str,
    ) -> Result<Zeroizing<String>, PolicyError> {
        check_file_name(name).map_err(|reason| invalid(item, field, reason))?;
        read_secret(&self.secrets_dir, name, self.euid)
            .map_err(|refusal| secret_refused(item, field, refusal))
    }

    /// An entry as a validated target, reading its credential.
    fn parse_target(
        &self,
        name: &TargetName,
        entry: &TargetEntry,
    ) -> Result<(SshTarget, Option<RelayCredential>), PolicyError> {
        let item = name.as_str();
        let mut fields: Vec<SecretField> = [
            ("address", entry.address.as_deref()),
            ("mode", entry.mode.as_deref()),
            ("max_window", entry.max_window.as_deref()),
        ]
        .into_iter()
        .filter_map(|(label, value)| value.map(|value| plain_field(label, value)))
        .collect();
        if let Some(users) = &entry.users {
            fields.push(plain_field("users", &users.join(",")));
        }
        if let Some(keys) = &entry.host_keys {
            fields.push(plain_field("host_keys", &keys.join("\n")));
        }
        if let Some(file) = &entry.private_key_file {
            let text = self.secret(item, "private_key_file", file)?;
            fields.push(field("private_key", text));
        }
        if let Some(file) = &entry.password_file {
            let text = self.secret(item, "password_file", file)?;
            let line =
                one_line(text).map_err(|refusal| secret_refused(item, "password_file", refusal))?;
            fields.push(field("password", line));
        }
        parse_target(
            name,
            &TargetItem {
                title: item.to_owned(),
                fields,
            },
        )
    }

    /// An entry as a validated API secret, reading its value.
    fn parse_api(
        &self,
        name: &SecretName,
        entry: &ApiEntry,
    ) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
        let item = name.as_str();
        let methods = match &entry.methods {
            Some(list) if list.is_empty() => {
                return Err(invalid(
                    item,
                    "methods",
                    "is empty; remove the setting to take its default",
                ));
            }
            Some(list) => Some(list.join(",")),
            None => None,
        };
        let mut fields = Vec::new();
        for (label, value) in [
            ("max_window", entry.max_window.as_deref()),
            ("header", entry.header.as_deref()),
            ("format", entry.format.as_deref()),
            ("methods", methods.as_deref()),
            ("path_prefix", entry.path_prefix.as_deref()),
            ("ca_pem", entry.ca_pem.as_deref()),
        ] {
            fields.extend(optional_field(item, label, value)?);
        }
        let file = entry
            .credential_file
            .as_deref()
            .ok_or_else(|| invalid(item, "credential_file", "missing"))?;
        fields.push(field(
            "credential",
            self.secret(item, "credential_file", file)?,
        ));
        let urls = vec![ItemUrl {
            primary: true,
            href: entry.website.clone(),
        }];
        parse_api_secret(name, &ApiItem { urls, fields })
    }

    fn target(
        &self,
        name: &TargetName,
    ) -> Result<(SshTarget, Option<RelayCredential>), PolicyError> {
        let policy = self.policy()?;
        let entry = policy
            .targets
            .get(name.as_str())
            .ok_or_else(|| PolicyError::NotFound(name.as_str().to_owned()))?;
        self.parse_target(name, entry)
    }

    fn api(&self, name: &SecretName) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
        let policy = self.policy()?;
        let entry = policy
            .api_secrets
            .get(name.as_str())
            .ok_or_else(|| PolicyError::UnknownSecret(name.as_str().to_owned()))?;
        self.parse_api(name, entry)
    }

    /// The CA key the policy names.
    fn ca(&self, entry: &CaEntry) -> Result<CaKey, PolicyError> {
        let ca_error = |reason: &str| PolicyError::Ca(format!("private_key_file {reason}"));
        let file = entry.private_key_file.as_str();
        check_file_name(file).map_err(ca_error)?;
        let text =
            read_secret(&self.secrets_dir, file, self.euid).map_err(|refusal| match refusal {
                Refusal::Io(_) => PolicyError::Unavailable(format!("SSH CA: {refusal}")),
                Refusal::Rule(_) | Refusal::Missing => ca_error(&refusal.to_string()),
            })?;
        let key = parse_private_key(&text)
            .ok_or_else(|| ca_error("is not a readable OpenSSH or PKCS#8 Ed25519 key"))?;
        CaKey::new(key)
    }

    /// The commit signing key the policy names.
    fn commit_signing(&self, entry: &CaEntry) -> Result<CommitSigningKey, PolicyError> {
        let key_error =
            |reason: &str| PolicyError::CommitSigningKey(format!("private_key_file {reason}"));
        let file = entry.private_key_file.as_str();
        check_file_name(file).map_err(key_error)?;
        let text =
            read_secret(&self.secrets_dir, file, self.euid).map_err(|refusal| match refusal {
                Refusal::Io(_) => {
                    PolicyError::Unavailable(format!("commit signing key: {refusal}"))
                }
                Refusal::Rule(_) | Refusal::Missing => key_error(&refusal.to_string()),
            })?;
        let key = parse_private_key(&text)
            .ok_or_else(|| key_error("is not a readable OpenSSH or PKCS#8 Ed25519 key"))?;
        CommitSigningKey::new(key)
    }

    /// Read everything: the policy, each entry with its secrets, and the CA.
    fn probe(&self) -> LocalProbe {
        let policy = match self.policy() {
            Ok(policy) => policy,
            Err(e) => return LocalProbe::Unreadable(e.to_string()),
        };
        let mut problems = Vec::new();
        let mut cert_targets = 0;
        for (key, entry) in &policy.targets {
            let Ok(name) = TargetName::try_from(key.clone()) else {
                problems.push(format!(
                    "[targets]: \"{}\" is not a valid target name",
                    shown_name(key)
                ));
                continue;
            };
            match self.parse_target(&name, entry) {
                Ok((target, _credential)) => {
                    cert_targets += usize::from(target.mode == SshMode::Cert);
                }
                Err(e) => problems.push(e.to_string()),
            }
        }
        for (key, entry) in &policy.api_secrets {
            let Ok(name) = SecretName::try_from(key.clone()) else {
                problems.push(format!(
                    "[api_secrets]: \"{}\" is not a valid secret name",
                    shown_name(key)
                ));
                continue;
            };
            if let Err(e) = self.parse_api(&name, entry) {
                problems.push(e.to_string());
            }
        }
        let ca = match &policy.ca {
            None if cert_targets == 0 => CaProbe::NotNeeded,
            None => CaProbe::Missing { cert_targets },
            Some(entry) => match self.ca(entry) {
                Ok(key) => CaProbe::Loaded {
                    fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
                },
                Err(PolicyError::Ca(reason)) => CaProbe::Invalid(reason),
                Err(e) => CaProbe::Unknown(e.to_string()),
            },
        };
        LocalProbe::Read {
            targets: policy.targets.len(),
            api_secrets: policy.api_secrets.len(),
            problems,
            ca,
            commit_signing: match &policy.commit_signing {
                None => CommitSigningProbe::NotConfigured,
                Some(entry) => {
                    CommitSigningProbe::of(self.commit_signing(entry).and_then(|key| {
                        // The server does not start on this, as `problems` says.
                        match &policy.ca {
                            Some(ca) => compare_with_ca(&key, self.ca(ca)).map(|()| key),
                            None => Ok(key),
                        }
                    }))
                }
            },
        }
    }
}

/// The error for a secret file that was not read. A failure of the system may
/// pass; anything else means this entry cannot be used as it stands.
fn secret_refused(item: &str, field: &str, refusal: Refusal) -> PolicyError {
    match refusal {
        Refusal::Io(_) => {
            PolicyError::Unavailable(format!("item \"{item}\": field \"{field}\": {refusal}"))
        }
        Refusal::Rule(_) | Refusal::Missing => invalid(item, field, refusal.to_string()),
    }
}

/// Reads policy and secrets from files on this host. Nothing is cached.
pub struct LocalBackend {
    files: Files,
    /// Where a refusal is recorded. Doctor records nothing.
    audit: Option<Arc<AuditLog>>,
}

impl LocalBackend {
    /// A backend for the server: reads everything first, and refuses to start
    /// when any of it is invalid, unreadable or too open.
    ///
    /// # Errors
    /// [`PolicyError::Unavailable`] listing every problem, after recording them
    /// in the audit log.
    pub async fn open(settings: &LocalSettings, audit: Arc<AuditLog>) -> Result<Self, PolicyError> {
        let backend = Self {
            files: Self::files(settings),
            audit: Some(audit),
        };
        let problems = backend.probe().await.problems();
        if problems.is_empty() {
            return Ok(backend);
        }
        for problem in &problems {
            backend.record(problem).await;
        }
        Err(PolicyError::Unavailable(problems.join("; ")))
    }

    /// A backend for read-only checks: it records nothing and checks nothing
    /// up front.
    #[must_use]
    pub fn unaudited(settings: &LocalSettings) -> Self {
        Self {
            files: Self::files(settings),
            audit: None,
        }
    }

    fn files(settings: &LocalSettings) -> Files {
        Files {
            policy_file: settings.policy_file.clone(),
            secrets_dir: settings.secrets_dir.clone(),
            euid: rustix::process::geteuid().as_raw(),
        }
    }

    /// Read and validate everything, without recording anything.
    pub async fn probe(&self) -> LocalProbe {
        let files = self.files.clone();
        tokio::task::spawn_blocking(move || files.probe())
            .await
            .unwrap_or_else(|_| LocalProbe::Unreadable("the read task failed".to_owned()))
    }

    /// Write a refusal to the audit log. The caller refuses whether or not
    /// this works.
    async fn record(&self, message: &str) {
        let Some(audit) = &self.audit else {
            return;
        };
        let event = AuditEvent::Error {
            context: AUDIT_CONTEXT.to_owned(),
            message: message.to_owned(),
        };
        if let Err(e) = audit.append(event).await {
            tracing::error!(error = %e, "could not audit a refusal of the local secret backend");
        }
    }

    /// Run `work` off the async workers, and audit what it refuses. A name that
    /// does not exist is an answer to the caller, not a broken state.
    async fn read<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Files) -> Result<T, PolicyError> + Send + 'static,
    ) -> Result<T, PolicyError> {
        let files = self.files.clone();
        let result = tokio::task::spawn_blocking(move || work(&files))
            .await
            .unwrap_or_else(|_| Err(PolicyError::Unavailable("the read task failed".to_owned())));
        if let Err(e) = &result
            && !matches!(e, PolicyError::NotFound(_) | PolicyError::UnknownSecret(_))
        {
            tracing::warn!(error = %e, "local secret backend refused");
            self.record(&e.to_string()).await;
        }
        result
    }
}

#[async_trait]
impl SecretBackend for LocalBackend {
    async fn ssh_target(&self, name: &TargetName) -> Result<SshTarget, PolicyError> {
        let name = name.clone();
        self.read(move |files| files.target(&name))
            .await
            .map(|(target, _credential)| target)
    }

    async fn relay_target_with_credential(
        &self,
        name: &TargetName,
    ) -> Result<(SshTarget, RelayCredential), PolicyError> {
        let name = name.clone();
        self.read(move |files| match files.target(&name)? {
            (target, Some(credential)) => Ok((target, credential)),
            (_, None) => Err(not_a_relay_target(name.as_str())),
        })
        .await
    }

    async fn ssh_ca(&self) -> Result<CaKey, PolicyError> {
        self.read(|files| match files.policy()?.ca {
            Some(entry) => files.ca(&entry),
            None => Err(PolicyError::Ca(
                "the policy file has no [ca] section".to_owned(),
            )),
        })
        .await
    }

    async fn has_ssh_ca(&self) -> Result<bool, PolicyError> {
        self.read(|files| Ok(files.policy()?.ca.is_some())).await
    }

    async fn has_commit_signing_key(&self) -> Result<bool, PolicyError> {
        self.read(|files| Ok(files.policy()?.commit_signing.is_some()))
            .await
    }

    async fn commit_signing_key(&self) -> Result<CommitSigningKey, PolicyError> {
        self.read(|files| match files.policy()?.commit_signing {
            Some(entry) => files.commit_signing(&entry),
            None => Err(PolicyError::NoCommitSigningKey),
        })
        .await
    }

    async fn api_secret(&self, name: &SecretName) -> Result<ApiSecretPolicy, PolicyError> {
        let name = name.clone();
        self.read(move |files| files.api(&name))
            .await
            .map(|(policy, _value)| policy)
    }

    async fn api_secret_with_value(
        &self,
        name: &SecretName,
    ) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
        let name = name.clone();
        self.read(move |files| files.api(&name)).await
    }
}

#[cfg(test)]
mod integrity_tests;
#[cfg(test)]
mod tests;
