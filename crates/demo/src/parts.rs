//! The stand-ins for what a deployment gets from its environment: who the
//! owner is, what the vault holds and how the owner hears about a request.
//! They live here, outside the broker, so `warden-server` cannot use them.

use async_trait::async_trait;
use axum::http::{HeaderMap, header};
use tokio::sync::mpsc;
use warden_broker::identity::IdentitySource;
use warden_broker::notify::{Doorbell, Notifier, NotifyError};
use warden_broker::policy::{
    ApiSecretPolicy, CaKey, CommitSigningKey, PolicyError, RelayCredential, SecretBackend,
    SecretValue, SshTarget,
};
use warden_broker_proto::{SecretName, TargetName};
use zeroize::Zeroizing;

/// Stands in for Tailscale Serve: a request addressed to one of the demo's own
/// listeners comes from the owner, because nothing but this machine can reach
/// them.
///
/// The `Host` check keeps web pages out. A page in any browser on this machine
/// can send requests to loopback, and DNS rebinding can make them look
/// same-origin, but it cannot make the browser send the demo's `Host`.
#[derive(Debug, Clone)]
pub struct LoopbackOwner {
    owner: String,
    hosts: [String; 2],
}

impl LoopbackOwner {
    /// The caller is `owner` when `Host` is exactly one of `hosts`.
    #[must_use]
    pub fn new(owner: &str, hosts: [String; 2]) -> Self {
        Self {
            owner: owner.to_owned(),
            hosts,
        }
    }
}

impl IdentitySource for LoopbackOwner {
    fn caller(&self, headers: &HeaderMap) -> Option<String> {
        let host = headers.get(header::HOST)?.to_str().ok()?;
        self.hosts
            .iter()
            .any(|known| known == host)
            .then(|| self.owner.clone())
    }
}

/// Stands in for the 1Password vault: one API secret, and no SSH targets.
pub struct DemoBackend {
    policy: ApiSecretPolicy,
    value: Zeroizing<String>,
}

impl DemoBackend {
    /// A vault holding only `policy` with its secret `value`.
    #[must_use]
    pub const fn new(policy: ApiSecretPolicy, value: Zeroizing<String>) -> Self {
        Self { policy, value }
    }

    fn find(&self, name: &SecretName) -> Result<&ApiSecretPolicy, PolicyError> {
        if *name == self.policy.name {
            Ok(&self.policy)
        } else {
            Err(PolicyError::UnknownSecret(name.as_str().to_owned()))
        }
    }
}

#[async_trait]
impl SecretBackend for DemoBackend {
    async fn ssh_target(&self, name: &TargetName) -> Result<SshTarget, PolicyError> {
        Err(PolicyError::NotFound(name.as_str().to_owned()))
    }

    async fn relay_target_with_credential(
        &self,
        name: &TargetName,
    ) -> Result<(SshTarget, RelayCredential), PolicyError> {
        Err(PolicyError::NotFound(name.as_str().to_owned()))
    }

    async fn has_ssh_ca(&self) -> Result<bool, PolicyError> {
        Ok(false)
    }

    async fn has_commit_signing_key(&self) -> Result<bool, PolicyError> {
        Ok(false)
    }

    async fn commit_signing_key(&self) -> Result<CommitSigningKey, PolicyError> {
        Err(PolicyError::NoCommitSigningKey)
    }

    async fn ssh_ca(&self) -> Result<CaKey, PolicyError> {
        Err(PolicyError::Ca("the demo has no SSH CA".to_owned()))
    }

    async fn api_secret(&self, name: &SecretName) -> Result<ApiSecretPolicy, PolicyError> {
        self.find(name).cloned()
    }

    async fn api_secret_with_value(
        &self,
        name: &SecretName,
    ) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
        let policy = self.find(name)?.clone();
        Ok((policy, SecretValue::new(self.value.clone())))
    }
}

/// Stands in for the notification channels: hands each notification to the
/// demo, which prints it in its terminal.
pub struct TerminalNotifier {
    tx: mpsc::UnboundedSender<Doorbell>,
}

impl TerminalNotifier {
    /// A notifier and the receiving end of what it rings.
    #[must_use]
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Doorbell>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

#[async_trait]
impl Notifier for TerminalNotifier {
    fn name(&self) -> &'static str {
        "terminal"
    }

    async fn ring(&self, d: &Doorbell) -> Result<&'static str, NotifyError> {
        self.tx.send(d.clone()).map_err(|_| NotifyError::Request {
            notifier: self.name(),
            reason: "the demo is stopping".to_owned(),
        })?;
        Ok(self.name())
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};
    use warden_broker::identity::IdentitySource as _;

    use super::LoopbackOwner;

    fn owner() -> LoopbackOwner {
        LoopbackOwner::new(
            "owner@demo.invalid",
            ["localhost:8081".to_owned(), "127.0.0.1:8080".to_owned()],
        )
    }

    fn with_host(host: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_str(host).unwrap());
        headers
    }

    #[test]
    fn own_listeners_are_the_owner() {
        for host in ["localhost:8081", "127.0.0.1:8080"] {
            assert_eq!(
                owner().caller(&with_host(host)).as_deref(),
                Some("owner@demo.invalid"),
                "{host}"
            );
        }
    }

    #[test]
    fn any_other_host_has_no_identity() {
        for host in [
            "evil.example:8081",
            "localhost",
            "localhost:9999",
            "127.0.0.1:8081",
            "localhost:8081.evil.example",
            "LOCALHOST:8081",
            "",
        ] {
            assert_eq!(owner().caller(&with_host(host)), None, "{host:?}");
        }
    }

    #[test]
    fn no_host_has_no_identity() {
        assert_eq!(owner().caller(&HeaderMap::new()), None);
    }

    #[test]
    fn the_tailscale_header_means_nothing_here() {
        let mut headers = with_host("evil.example:8081");
        headers.insert(
            "Tailscale-User-Login",
            HeaderValue::from_static("owner@demo.invalid"),
        );
        assert_eq!(owner().caller(&headers), None);
    }
}
