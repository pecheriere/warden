//! Read-only questions `warden-server doctor` asks the Connect server. They
//! tell apart what the request paths of [`OnePasswordConnect`] treat alike
//! (a refused token, an unreachable server), and never quote a response body.

use http::StatusCode;
use secrecy::ExposeSecret;
use ssh_key::HashAlg;
use warden_broker_proto::TargetName;
use zeroize::Zeroizing;

use super::{CA_TAG, OnePasswordConnect, TARGET_TAG, Vault};
use crate::policy::{
    CommitSigningProbe, PolicyError, SecretBackend, SshMode, check_separate_from_ca,
};

/// What Connect says about the configured token and vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultProbe {
    /// The token was accepted and the vault is visible to it.
    Found,
    /// The token was accepted, but it sees no vault of that name.
    Missing,
    /// Connect answered and refused the token.
    TokenRefused {
        /// The HTTP status.
        status: u16,
    },
    /// No answer from Connect. Holds the transport error, without the URL.
    Unreachable(String),
    /// Connect answered with an error or something unreadable. Holds the
    /// status or error class, never the body.
    Unhealthy(String),
    /// The vault name cannot be asked for: it holds a quote or a backslash.
    UnusableName,
}

/// Whether the SSH CA key loads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaProbe {
    /// The key loaded. Holds the public key's fingerprint.
    Loaded {
        /// `SHA256:…`.
        fingerprint: String,
    },
    /// There is no CA item, and no target in certificate mode needs one.
    NotNeeded,
    /// There is no CA item, and this many certificate targets need one.
    Missing {
        /// Certificate targets in the vault.
        cert_targets: usize,
    },
    /// The CA item is ambiguous or its key is unusable. The reason never holds
    /// key material, but may hold the item's title.
    Invalid(String),
    /// Connect could not answer, or a target item cannot be read, so the
    /// answer is not known.
    Unknown(String),
}

impl OnePasswordConnect {
    /// Ask Connect for the configured vault, classifying the answer.
    pub async fn probe_vault(&self) -> VaultProbe {
        if !self.vault_name_is_usable() {
            return VaultProbe::UnusableName;
        }
        let filter = self.vault_filter();
        let url = match self.url(&["v1", "vaults"], &[("filter", &filter)]) {
            Ok(url) => url,
            Err(e) => return VaultProbe::Unhealthy(e.to_string()),
        };
        let response = self
            .client
            .get(url)
            .bearer_auth(self.token.expose_secret())
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(e) => return VaultProbe::Unreachable(e.without_url().to_string()),
        };
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return VaultProbe::TokenRefused {
                status: status.as_u16(),
            };
        }
        if !status.is_success() {
            return VaultProbe::Unhealthy(format!("HTTP {status}"));
        }
        let body = match response.bytes().await {
            Ok(body) => Zeroizing::new(body.to_vec()),
            Err(e) => {
                return VaultProbe::Unhealthy(format!(
                    "the response was cut short: {}",
                    e.without_url()
                ));
            }
        };
        match serde_json::from_slice::<Vec<Vault>>(&body) {
            Ok(vaults) if vaults.iter().any(|v| v.name == self.vault) => VaultProbe::Found,
            Ok(_) => VaultProbe::Missing,
            // Never the serde error's text: it can quote a value.
            Err(e) => {
                VaultProbe::Unhealthy(format!("an unreadable response ({:?} error)", e.classify()))
            }
        }
    }

    /// Load the CA key and drop it, or tell whether a missing one matters.
    pub async fn probe_ca(&self) -> CaProbe {
        let items = match self.tagged(CA_TAG).await {
            Ok(items) => items,
            Err(e) => return CaProbe::Unknown(e.to_string()),
        };
        if items.is_empty() {
            return match self.cert_targets().await {
                Ok(0) => CaProbe::NotNeeded,
                Ok(cert_targets) => CaProbe::Missing { cert_targets },
                Err(e) => CaProbe::Unknown(e.to_string()),
            };
        }
        match self.ssh_ca().await {
            Ok(key) => CaProbe::Loaded {
                fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
            },
            Err(PolicyError::Ca(reason)) => CaProbe::Invalid(reason),
            Err(e) => CaProbe::Unknown(e.to_string()),
        }
    }

    /// Load the commit signing key, check that it is not the CA key, and drop both.
    pub async fn probe_commit_signing(&self) -> CommitSigningProbe {
        let read = match self.commit_signing_key().await {
            Ok(key) => check_separate_from_ca(self, &key).await.map(|()| key),
            Err(e) => Err(e),
        };
        CommitSigningProbe::of(read)
    }

    /// How many target items in the vault are in certificate mode. A title
    /// that is not a valid target name cannot be requested, so it does not
    /// count; any other item that cannot be read is an error.
    async fn cert_targets(&self) -> Result<usize, PolicyError> {
        let mut count = 0;
        for item in self.tagged(TARGET_TAG).await? {
            let Ok(name) = TargetName::try_from(item.title) else {
                continue;
            };
            if self.ssh_target(&name).await?.mode == SshMode::Cert {
                count += 1;
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use serde_json::json;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    use url::Url;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{CaProbe, CommitSigningProbe, OnePasswordConnect, VaultProbe};

    const TOKEN: &str = "test-connect-token-do-not-leak";
    const VAULT_ID: &str = "vault0000000000000000000a1";
    const ITEMS: &str = "/v1/vaults/vault0000000000000000000a1/items";

    fn connect(server: &MockServer) -> OnePasswordConnect {
        OnePasswordConnect::new(
            Url::parse(&server.uri()).unwrap(),
            SecretString::from(TOKEN),
            "Warden".to_owned(),
        )
    }

    async fn answer(server: &MockServer, at: &str, status: u16, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(at.to_owned()))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(server)
            .await;
    }

    async fn with_vault() -> MockServer {
        let server = MockServer::start().await;
        answer(
            &server,
            "/v1/vaults",
            200,
            json!([{"id": VAULT_ID, "name": "Warden"}]),
        )
        .await;
        server
    }

    #[tokio::test]
    async fn vault_found() {
        let server = with_vault().await;
        assert_eq!(connect(&server).probe_vault().await, VaultProbe::Found);
    }

    #[tokio::test]
    async fn vault_missing_when_the_token_sees_another_one() {
        let server = MockServer::start().await;
        answer(
            &server,
            "/v1/vaults",
            200,
            json!([{"id": VAULT_ID, "name": "Other"}]),
        )
        .await;
        assert_eq!(connect(&server).probe_vault().await, VaultProbe::Missing);
    }

    #[tokio::test]
    async fn refused_tokens_are_told_from_other_errors() {
        for status in [401, 403] {
            let server = MockServer::start().await;
            answer(&server, "/v1/vaults", status, json!({"message": "no"})).await;
            assert_eq!(
                connect(&server).probe_vault().await,
                VaultProbe::TokenRefused { status }
            );
        }
    }

    #[tokio::test]
    async fn an_error_answer_never_quotes_the_body() {
        let server = MockServer::start().await;
        answer(&server, "/v1/vaults", 500, json!({"echo": TOKEN})).await;
        let VaultProbe::Unhealthy(reason) = connect(&server).probe_vault().await else {
            panic!("expected Unhealthy");
        };
        assert!(reason.contains("500"), "{reason}");
        assert!(!reason.contains(TOKEN), "{reason}");
    }

    #[tokio::test]
    async fn an_unreadable_answer_never_quotes_the_body() {
        let server = MockServer::start().await;
        Mock::given(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(200).set_body_string(TOKEN))
            .mount(&server)
            .await;
        let VaultProbe::Unhealthy(reason) = connect(&server).probe_vault().await else {
            panic!("expected Unhealthy");
        };
        assert!(!reason.contains(TOKEN), "{reason}");
    }

    #[tokio::test]
    async fn no_listener_is_unreachable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let probe = OnePasswordConnect::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            SecretString::from(TOKEN),
            "Warden".to_owned(),
        )
        .probe_vault()
        .await;
        assert!(matches!(probe, VaultProbe::Unreachable(_)), "{probe:?}");
    }

    #[tokio::test]
    async fn a_name_with_a_quote_is_not_asked_for() {
        let server = MockServer::start().await;
        let probe = OnePasswordConnect::new(
            Url::parse(&server.uri()).unwrap(),
            SecretString::from(TOKEN),
            "We\"ird".to_owned(),
        )
        .probe_vault()
        .await;
        assert_eq!(probe, VaultProbe::UnusableName);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    fn ca_summary() -> serde_json::Value {
        json!([{"id": "ca1", "title": "warden-ssh-ca", "tags": ["warden:ssh-ca"]}])
    }

    #[tokio::test]
    async fn ca_loads_and_only_its_public_fingerprint_comes_back() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
        let server = with_vault().await;
        answer(&server, ITEMS, 200, ca_summary()).await;
        answer(
            &server,
            &format!("{ITEMS}/ca1"),
            200,
            json!({"fields": [{"id": "private_key", "value": pem}]}),
        )
        .await;
        let probe = connect(&server).probe_ca().await;
        assert_eq!(
            probe,
            CaProbe::Loaded {
                fingerprint: key
                    .public_key()
                    .fingerprint(ssh_key::HashAlg::Sha256)
                    .to_string()
            }
        );
    }

    #[tokio::test]
    async fn an_unusable_ca_key_is_invalid_and_never_quoted() {
        let server = with_vault().await;
        answer(&server, ITEMS, 200, ca_summary()).await;
        answer(
            &server,
            &format!("{ITEMS}/ca1"),
            200,
            json!({"fields": [{"id": "private_key", "value": "secret-not-a-key"}]}),
        )
        .await;
        let CaProbe::Invalid(reason) = connect(&server).probe_ca().await else {
            panic!("expected Invalid");
        };
        assert!(!reason.contains("secret-not-a-key"), "{reason}");
    }

    #[tokio::test]
    async fn the_commit_signing_key_loads_and_is_never_quoted() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
        let summary = json!([{"id": "cs1", "title": "warden-commit-signing", "tags": ["warden:commit-signing"]}]);
        let server = with_vault().await;
        answer(&server, ITEMS, 200, summary.clone()).await;
        answer(
            &server,
            &format!("{ITEMS}/cs1"),
            200,
            json!({"fields": [{"id": "private_key", "value": pem}]}),
        )
        .await;
        assert_eq!(
            connect(&server).probe_commit_signing().await,
            CommitSigningProbe::Loaded {
                fingerprint: key
                    .public_key()
                    .fingerprint(ssh_key::HashAlg::Sha256)
                    .to_string()
            }
        );

        let server = with_vault().await;
        answer(&server, ITEMS, 200, summary).await;
        answer(
            &server,
            &format!("{ITEMS}/cs1"),
            200,
            json!({"fields": [{"id": "private_key", "value": "secret-not-a-key"}]}),
        )
        .await;
        let CommitSigningProbe::Invalid(reason) = connect(&server).probe_commit_signing().await
        else {
            panic!("expected Invalid");
        };
        assert!(!reason.contains("secret-not-a-key"), "{reason}");
    }

    #[tokio::test]
    async fn the_ca_key_cannot_also_be_the_commit_signing_key() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
        // One item tagged for both.
        let both = json!([{
            "id": "ca1",
            "title": "shared",
            "tags": ["warden:ssh-ca", "warden:commit-signing"],
        }]);
        let server = with_vault().await;
        answer(&server, ITEMS, 200, both).await;
        answer(
            &server,
            &format!("{ITEMS}/ca1"),
            200,
            json!({"fields": [{"id": "private_key", "value": pem}]}),
        )
        .await;
        let CommitSigningProbe::Invalid(reason) = connect(&server).probe_commit_signing().await
        else {
            panic!("expected Invalid");
        };
        assert!(reason.contains("also the SSH CA key"), "{reason}");
    }

    #[tokio::test]
    async fn a_ca_that_cannot_be_used_refuses_the_commit_signing_key() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
        let signing = json!({"id": "cs1", "title": "s", "tags": ["warden:commit-signing"]});
        let ca = |id: &str| json!({"id": id, "title": id, "tags": ["warden:ssh-ca"]});
        for items in [
            // Two CA items.
            json!([signing, ca("ca1"), ca("ca2")]),
            // One whose key does not parse.
            json!([signing, ca("ca1")]),
        ] {
            let server = with_vault().await;
            answer(&server, ITEMS, 200, items).await;
            answer(
                &server,
                &format!("{ITEMS}/cs1"),
                200,
                json!({"fields": [{"id": "private_key", "value": pem}]}),
            )
            .await;
            answer(
                &server,
                &format!("{ITEMS}/ca1"),
                200,
                json!({"fields": [{"id": "private_key", "value": "not-a-key"}]}),
            )
            .await;
            let CommitSigningProbe::Invalid(reason) = connect(&server).probe_commit_signing().await
            else {
                panic!("expected Invalid");
            };
            assert!(reason.contains("SSH CA cannot be read"), "{reason}");
        }
    }

    #[tokio::test]
    async fn no_commit_signing_item_leaves_signing_off_and_two_are_an_error() {
        let server = with_vault().await;
        answer(&server, ITEMS, 200, json!([])).await;
        assert_eq!(
            connect(&server).probe_commit_signing().await,
            CommitSigningProbe::NotConfigured
        );
        let server = with_vault().await;
        let two = json!([
            {"id": "cs1", "title": "one", "tags": ["warden:commit-signing"]},
            {"id": "cs2", "title": "two", "tags": ["warden:commit-signing"]},
        ]);
        answer(&server, ITEMS, 200, two).await;
        assert!(matches!(
            connect(&server).probe_commit_signing().await,
            CommitSigningProbe::Invalid(_)
        ));
    }

    #[tokio::test]
    async fn no_ca_and_no_target_needs_none() {
        let server = with_vault().await;
        answer(&server, ITEMS, 200, json!([])).await;
        assert_eq!(connect(&server).probe_ca().await, CaProbe::NotNeeded);
    }

    #[tokio::test]
    async fn no_ca_with_a_certificate_target_is_missing() {
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        let server = with_vault().await;
        answer(
            &server,
            ITEMS,
            200,
            json!([{"id": "t1", "title": "pi", "tags": ["warden:ssh-target"]}]),
        )
        .await;
        let item =
            include_str!("../../../tests/fixtures/item-pi.json").replace("{{HOST_KEY}}", &host_key);
        answer(
            &server,
            &format!("{ITEMS}/t1"),
            200,
            serde_json::from_str(&item).unwrap(),
        )
        .await;
        assert_eq!(
            connect(&server).probe_ca().await,
            CaProbe::Missing { cert_targets: 1 }
        );
    }

    #[tokio::test]
    async fn no_ca_with_an_unreadable_target_is_unknown() {
        let server = with_vault().await;
        answer(
            &server,
            ITEMS,
            200,
            json!([{"id": "t1", "title": "pi", "tags": ["warden:ssh-target"]}]),
        )
        .await;
        answer(&server, &format!("{ITEMS}/t1"), 200, json!({"title": "pi"})).await;
        let probe = connect(&server).probe_ca().await;
        assert!(matches!(probe, CaProbe::Unknown(_)), "{probe:?}");
    }

    #[tokio::test]
    async fn connect_failing_is_unknown() {
        let server = with_vault().await;
        answer(&server, ITEMS, 503, json!({})).await;
        let probe = connect(&server).probe_ca().await;
        assert!(matches!(probe, CaProbe::Unknown(_)), "{probe:?}");
    }
}
