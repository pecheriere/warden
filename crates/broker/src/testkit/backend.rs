//! [`FakeBackend`], an in-memory policy backend tests can change at any time.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use url::Url;
use warden_broker_proto::{SecretName, TargetName, UnixUser, Window};
use zeroize::Zeroizing;

use super::{NAS_HOST, PI_HOST};
use crate::policy::{
    ApiSecretPolicy, CaKey, CommitSigningKey, PolicyError, RelayCredential, SecretBackend,
    SecretValue, SshMode, SshTarget, ValueFormat, not_a_relay_target,
};

/// An in-memory [`SecretBackend`]: targets (with relay credentials) and API
/// secrets can be changed at any time, the CA key is generated per backend,
/// and target or CA lookups can be made to fail as if the backend were down.
pub struct FakeBackend {
    targets: Mutex<HashMap<String, (SshTarget, Option<RelayCredential>)>>,
    api_secrets: Mutex<HashMap<String, (ApiSecretPolicy, Zeroizing<String>)>>,
    api_swap: Mutex<Option<(ApiSecretPolicy, Zeroizing<String>)>>,
    ca: PrivateKey,
    commit_signing: Mutex<Option<PrivateKey>>,
    commit_signing_outage: Mutex<Option<String>>,
    commit_signing_reads: std::sync::atomic::AtomicUsize,
    target_outage: Mutex<Option<String>>,
    ca_outage: Mutex<Option<String>>,
    ca_state: Mutex<CaState>,
    api_outage: Mutex<Option<String>>,
    relay_read_delay: Mutex<Option<Duration>>,
}

/// What [`FakeBackend`] has for an SSH CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaState {
    /// A usable key.
    Usable,
    /// None configured.
    Absent,
    /// Configured but unusable, as with two items or a malformed key.
    Unusable,
}

impl FakeBackend {
    /// A backend holding [`FakeBackend::pi_target`] and a fresh Ed25519 CA.
    ///
    /// # Panics
    /// If no key can be generated.
    #[must_use]
    pub fn new() -> Self {
        let pi = Self::pi_target();
        Self {
            targets: Mutex::new(HashMap::from([(pi.name.as_str().to_owned(), (pi, None))])),
            api_secrets: Mutex::new(HashMap::new()),
            api_swap: Mutex::new(None),
            ca: PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("CA key generation"),
            commit_signing: Mutex::new(Some(
                PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("key generation"),
            )),
            commit_signing_outage: Mutex::new(None),
            commit_signing_reads: std::sync::atomic::AtomicUsize::new(0),
            target_outage: Mutex::new(None),
            ca_outage: Mutex::new(None),
            ca_state: Mutex::new(CaState::Usable),
            api_outage: Mutex::new(None),
            relay_read_delay: Mutex::new(None),
        }
    }

    /// Target `pi`: cert mode, users `alice` and `admin`, max window 1h,
    /// `192.0.2.10:22`, one random host key.
    ///
    /// # Panics
    /// If no key can be generated.
    #[must_use]
    pub fn pi_target() -> SshTarget {
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("host key generation")
            .public_key()
            .clone();
        SshTarget {
            name: TargetName::try_from("pi".to_owned()).expect("valid target name"),
            host: PI_HOST.to_owned(),
            port: 22,
            mode: SshMode::Cert,
            users: ["alice", "admin"]
                .into_iter()
                .map(|u| UnixUser::try_from(u.to_owned()).expect("valid user"))
                .collect(),
            max_window: Window::H1,
            host_keys: vec![host_key],
        }
    }

    /// Target `nas`: relay mode, user `backup`, max window 1h,
    /// `192.0.2.20:22`, one random host key. Not added to any backend by
    /// itself; see [`FakeBackend::set_relay_target`].
    ///
    /// # Panics
    /// If no key can be generated.
    #[must_use]
    pub fn relay_target() -> SshTarget {
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("host key generation")
            .public_key()
            .clone();
        SshTarget {
            name: TargetName::try_from("nas".to_owned()).expect("valid target name"),
            host: NAS_HOST.to_owned(),
            port: 22,
            mode: SshMode::Relay,
            users: vec![UnixUser::try_from("backup".to_owned()).expect("valid user")],
            max_window: Window::H1,
            host_keys: vec![host_key],
        }
    }

    /// Add or replace a target, without a relay credential.
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_target(&self, target: SshTarget) {
        self.targets
            .lock()
            .expect("targets lock poisoned")
            .insert(target.name.as_str().to_owned(), (target, None));
    }

    /// Add or replace a relay target together with its onward credential.
    ///
    /// # Panics
    /// If the target is not in relay mode or the lock is poisoned.
    pub fn set_relay_target(&self, target: SshTarget, credential: RelayCredential) {
        assert_eq!(target.mode, SshMode::Relay, "not a relay target");
        self.targets
            .lock()
            .expect("targets lock poisoned")
            .insert(target.name.as_str().to_owned(), (target, Some(credential)));
    }

    /// The current definition of target `name`.
    ///
    /// # Panics
    /// If there is no such target or the lock is poisoned.
    #[must_use]
    pub fn target(&self, name: &str) -> SshTarget {
        self.targets
            .lock()
            .expect("targets lock poisoned")
            .get(name)
            .map(|(target, _)| target.clone())
            .expect("no such fake target")
    }

    /// API secret `github`: origin `https://api.example.com`, header
    /// `Authorization: Bearer {{secret}}`, `GET` only, path prefix `/`, no
    /// pinned CA, max window 1h. Not added to any backend by itself.
    ///
    /// # Panics
    /// Never: every part is a valid constant.
    #[must_use]
    pub fn example_api_secret() -> ApiSecretPolicy {
        ApiSecretPolicy {
            name: SecretName::try_from("github".to_owned()).expect("valid secret name"),
            origin: Url::parse("https://api.example.com")
                .expect("valid origin")
                .origin(),
            header: http::header::AUTHORIZATION,
            format: ValueFormat::default(),
            methods: vec![http::Method::GET],
            path_prefix: "/".to_owned(),
            ca_pem: None,
            max_window: Window::H1,
        }
    }

    /// Add or replace an API secret and its value.
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_api_secret(&self, policy: ApiSecretPolicy, value: &str) {
        self.api_secrets
            .lock()
            .expect("api secrets lock poisoned")
            .insert(
                policy.name.as_str().to_owned(),
                (policy, Zeroizing::new(value.to_owned())),
            );
    }

    /// Remove API secret `name`, as if its item were deleted in 1Password.
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn remove_api_secret(&self, name: &str) {
        self.api_secrets
            .lock()
            .expect("api secrets lock poisoned")
            .remove(name);
    }

    /// Make API secret lookups fail with [`PolicyError::Unavailable`]
    /// carrying `detail` (`None` restores them).
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_api_outage(&self, detail: Option<&str>) {
        *self.api_outage.lock().expect("outage lock poisoned") = detail.map(str::to_owned);
    }

    /// Add or replace an API secret and its value right after the next API
    /// secret read, as if the item were edited in 1Password between two
    /// reads.
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_api_secret_after_next_read(&self, policy: ApiSecretPolicy, value: &str) {
        *self.api_swap.lock().expect("api swap lock poisoned") =
            Some((policy, Zeroizing::new(value.to_owned())));
    }

    /// Read API secret `name` through `pick`, then apply any change queued
    /// by [`FakeBackend::set_api_secret_after_next_read`].
    fn api_entry<T>(
        &self,
        name: &SecretName,
        pick: impl FnOnce(&(ApiSecretPolicy, Zeroizing<String>)) -> T,
    ) -> Result<T, PolicyError> {
        let poisoned = || PolicyError::Unavailable("fake backend lock poisoned".to_owned());
        Self::outage(&self.api_outage)?;
        let mut secrets = self.api_secrets.lock().map_err(|_| poisoned())?;
        let picked = secrets
            .get(name.as_str())
            .map(pick)
            .ok_or_else(|| PolicyError::UnknownSecret(name.as_str().to_owned()));
        if let Some((policy, value)) = self.api_swap.lock().map_err(|_| poisoned())?.take() {
            secrets.insert(policy.name.as_str().to_owned(), (policy, value));
        }
        picked
    }

    /// The CA's public key.
    #[must_use]
    pub fn ca_public_key(&self) -> &PublicKey {
        self.ca.public_key()
    }

    /// Make target lookups fail with [`PolicyError::Unavailable`] carrying
    /// `detail` (`None` restores them).
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_target_outage(&self, detail: Option<&str>) {
        *self.target_outage.lock().expect("outage lock poisoned") = detail.map(str::to_owned);
    }

    /// Make CA lookups fail with [`PolicyError::Unavailable`] carrying
    /// `detail` (`None` restores them).
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_ca_outage(&self, detail: Option<&str>) {
        *self.ca_outage.lock().expect("outage lock poisoned") = detail.map(str::to_owned);
    }

    /// Make commit signing key lookups fail with [`PolicyError::Unavailable`]
    /// carrying `detail` (`None` restores them).
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_commit_signing_outage(&self, detail: Option<&str>) {
        *self
            .commit_signing_outage
            .lock()
            .expect("outage lock poisoned") = detail.map(str::to_owned);
    }

    /// Replace the commit signing key (`None`: no key is configured).
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_commit_signing_key(&self, key: Option<PrivateKey>) {
        *self.commit_signing.lock().expect("key lock poisoned") = key;
    }

    /// How many times the commit signing private key has been read.
    #[must_use]
    pub fn commit_signing_reads(&self) -> usize {
        self.commit_signing_reads
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The SSH CA's private key, to configure the same key for something else.
    #[must_use]
    pub fn ca_private_key(&self) -> PrivateKey {
        self.ca.clone()
    }

    /// The commit signing key's public half.
    ///
    /// # Panics
    /// If the lock is poisoned or no key is configured.
    #[must_use]
    pub fn commit_signing_public_key(&self) -> PublicKey {
        self.commit_signing
            .lock()
            .expect("key lock poisoned")
            .as_ref()
            .expect("a commit signing key")
            .public_key()
            .clone()
    }

    /// The commit signing key's private half, so that a test can look for it in
    /// what the broker wrote.
    ///
    /// # Panics
    /// If the lock is poisoned or no key is configured.
    #[must_use]
    pub fn commit_signing_private_key(&self) -> PrivateKey {
        self.commit_signing
            .lock()
            .expect("key lock poisoned")
            .clone()
            .expect("a commit signing key")
    }

    /// Say whether the SSH CA is there, and usable.
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_ca_state(&self, state: CaState) {
        *self.ca_state.lock().expect("CA state lock poisoned") = state;
    }

    /// Make every read of a relay target with its credential take `delay`
    /// before answering, as a slow secret backend would (`None` restores
    /// them).
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_relay_read_delay(&self, delay: Option<Duration>) {
        *self.relay_read_delay.lock().expect("delay lock poisoned") = delay;
    }

    fn outage(slot: &Mutex<Option<String>>) -> Result<(), PolicyError> {
        match slot
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?
            .as_ref()
        {
            Some(detail) => Err(PolicyError::Unavailable(detail.clone())),
            None => Ok(()),
        }
    }
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretBackend for FakeBackend {
    async fn ssh_target(&self, name: &TargetName) -> Result<SshTarget, PolicyError> {
        Self::outage(&self.target_outage)?;
        self.targets
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?
            .get(name.as_str())
            .map(|(target, _)| target.clone())
            .ok_or_else(|| PolicyError::NotFound(name.as_str().to_owned()))
    }

    async fn relay_target_with_credential(
        &self,
        name: &TargetName,
    ) -> Result<(SshTarget, RelayCredential), PolicyError> {
        let delay = *self
            .relay_read_delay
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?;
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        Self::outage(&self.target_outage)?;
        let targets = self
            .targets
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?;
        let (target, credential) = targets
            .get(name.as_str())
            .ok_or_else(|| PolicyError::NotFound(name.as_str().to_owned()))?;
        if target.mode != SshMode::Relay {
            return Err(not_a_relay_target(name.as_str()));
        }
        let credential = match credential {
            Some(RelayCredential::Key(key)) => RelayCredential::Key(key.clone()),
            Some(RelayCredential::Password(password)) => {
                RelayCredential::Password(password.clone())
            }
            None => {
                return Err(PolicyError::Invalid {
                    item: name.as_str().to_owned(),
                    field: "password".to_owned(),
                    reason: "missing: a relay target needs a credential".to_owned(),
                });
            }
        };
        Ok((target.clone(), credential))
    }

    async fn ssh_ca(&self) -> Result<CaKey, PolicyError> {
        Self::outage(&self.ca_outage)?;
        let state = *self
            .ca_state
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?;
        match state {
            CaState::Usable => CaKey::new(self.ca.clone()),
            CaState::Absent => Err(PolicyError::Ca("no item is tagged".to_owned())),
            CaState::Unusable => Err(PolicyError::Ca("2 items are tagged".to_owned())),
        }
    }

    async fn has_ssh_ca(&self) -> Result<bool, PolicyError> {
        Self::outage(&self.ca_outage)?;
        let state = *self
            .ca_state
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?;
        Ok(state != CaState::Absent)
    }

    async fn has_commit_signing_key(&self) -> Result<bool, PolicyError> {
        Self::outage(&self.commit_signing_outage)?;
        Ok(self
            .commit_signing
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?
            .is_some())
    }

    async fn commit_signing_key(&self) -> Result<CommitSigningKey, PolicyError> {
        Self::outage(&self.commit_signing_outage)?;
        self.commit_signing_reads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let key = self
            .commit_signing
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?
            .clone()
            .ok_or(PolicyError::NoCommitSigningKey)?;
        CommitSigningKey::new(key)
    }

    async fn api_secret(&self, name: &SecretName) -> Result<ApiSecretPolicy, PolicyError> {
        self.api_entry(name, |(policy, _)| policy.clone())
    }

    async fn api_secret_with_value(
        &self,
        name: &SecretName,
    ) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
        self.api_entry(name, |(policy, value)| {
            (policy.clone(), SecretValue::new(value.clone()))
        })
    }
}
