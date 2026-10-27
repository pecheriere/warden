//! [`SecretBackend`] backed by a 1Password Connect server.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderName, Method, StatusCode};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};
use tokio::sync::Mutex;
use url::{Origin, Url};
use warden_broker_proto::{SecretName, TargetName, UnixUser, Window};
use zeroize::Zeroizing;

use super::{
    ApiSecretPolicy, CaKey, PolicyError, RelayCredential, SecretBackend, SecretValue, SshMode,
    SshTarget, ValueFormat, check_path_prefix, is_header_text, is_reserved_header,
    not_a_relay_target, parse_method,
};

const TARGET_TAG: &str = "warden:ssh-target";
const CA_TAG: &str = "warden:ssh-ca";
const API_TAG: &str = "warden:api-secret";
const MIN_CREDENTIAL_CHARS: usize = 12;
const CA_FIELD_ID: &str = "private_key";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct Vault {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct ItemSummary {
    id: String,
    title: String,
    #[serde(default)]
    tags: Vec<String>,
}

/// An SSH target item, decoded so that a relay target's credential never
/// lives in a plain `String`.
#[derive(Deserialize)]
struct TargetItem {
    title: String,
    #[serde(default)]
    fields: Vec<SecretField>,
}

/// The CA item, decoded so that no private-key text lives in a plain `String`.
#[derive(Deserialize)]
struct CaItem {
    #[serde(default)]
    fields: Vec<SecretField>,
}

/// An API secret item, decoded so that the credential never lives in a plain
/// `String`.
#[derive(Deserialize)]
struct ApiItem {
    #[serde(default)]
    urls: Vec<ItemUrl>,
    #[serde(default)]
    fields: Vec<SecretField>,
}

/// An entry of an item's `urls` array (the website fields in 1Password).
#[derive(Deserialize)]
struct ItemUrl {
    #[serde(default)]
    primary: bool,
    href: Option<String>,
}

/// A field whose value may be secret: held in memory wiped on drop.
#[derive(Deserialize)]
struct SecretField {
    #[serde(default)]
    id: String,
    label: Option<String>,
    #[serde(default, deserialize_with = "secret_string")]
    value: Option<Zeroizing<String>>,
}

fn secret_string<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.map(Zeroizing::new))
}

/// Reads policy from a 1Password Connect server. Items are fetched on every
/// call; only the vault id is cached, and it is resolved again when Connect
/// stops knowing it (the vault was recreated).
pub struct OnePasswordConnect {
    client: reqwest::Client,
    base: Url,
    token: SecretString,
    vault: String,
    /// The resolved vault id. The lock is held while resolving, so concurrent
    /// callers share one lookup (single flight).
    vault_id: Mutex<Option<String>>,
}

impl OnePasswordConnect {
    /// Create a client for `vault` on the Connect server at `url`.
    ///
    /// # Panics
    /// If the TLS backend cannot be initialised, which only happens on a
    /// broken platform configuration.
    #[must_use]
    pub fn new(url: Url, token: SecretString, vault: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            // The bearer token must never follow a redirect to another host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client with static configuration");
        Self {
            client,
            base: url,
            token,
            vault,
            vault_id: Mutex::new(None),
        }
    }

    async fn get<T: DeserializeOwned>(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<T, PolicyError> {
        let body = self.get_bytes(segments, query).await?;
        // Never interpolate the serde error itself: it can quote a field value.
        serde_json::from_slice(&body).map_err(|e| unreadable(&e))
    }

    /// GET and return the raw body in memory that is wiped on drop.
    async fn get_bytes(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<Zeroizing<Vec<u8>>, PolicyError> {
        self.get_found(segments, query).await?.ok_or_else(|| {
            PolicyError::Unavailable(format!(
                "1Password Connect returned HTTP {}",
                StatusCode::NOT_FOUND
            ))
        })
    }

    /// Like [`Self::get_bytes`], but `Ok(None)` for a 404, so that callers
    /// can tell "not found" from a failure.
    async fn get_found(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, PolicyError> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| PolicyError::Unavailable("Connect URL cannot be a base".into()))?
            .pop_if_empty()
            .extend(segments);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let mut response = self
            .client
            .get(url)
            .bearer_auth(self.token.expose_secret())
            .send()
            .await
            // Strip the URL; the error text is the only thing we surface.
            .map_err(|e| {
                PolicyError::Unavailable(format!(
                    "1Password Connect request failed: {}",
                    e.without_url()
                ))
            })?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(PolicyError::Unavailable(format!(
                "1Password Connect returned HTTP {status}"
            )));
        }
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            PolicyError::Unavailable(format!(
                "1Password Connect response was cut short: {}",
                e.without_url()
            ))
        })? {
            body.extend_from_slice(&chunk);
        }
        Ok(Some(body))
    }

    /// The cached vault id, resolved by name on first use.
    async fn vault_id(&self) -> Result<String, PolicyError> {
        let mut cached = self.vault_id.lock().await;
        if let Some(id) = cached.as_ref() {
            return Ok(id.clone());
        }
        let id = self.resolve_vault().await?;
        *cached = Some(id.clone());
        Ok(id)
    }

    /// Resolve the vault again after Connect answered 404 for `stale`.
    /// Returns the current id, which equals `stale` when the vault still has
    /// it (the 404 was for something else). Callers that saw the same stale
    /// id queue on the lock; the first one resolves and the rest find the
    /// new id already cached. A vault that no longer resolves clears the
    /// cache and fails.
    async fn refresh_vault_id(&self, stale: &str) -> Result<String, PolicyError> {
        let mut cached = self.vault_id.lock().await;
        if let Some(id) = cached.as_ref().filter(|id| id.as_str() != stale) {
            return Ok(id.clone());
        }
        *cached = None;
        let id = self.resolve_vault().await?;
        *cached = Some(id.clone());
        Ok(id)
    }

    async fn resolve_vault(&self) -> Result<String, PolicyError> {
        if self.vault.contains(['"', '\\']) {
            return Err(PolicyError::Unavailable(
                "vault name contains unsupported characters".into(),
            ));
        }
        let filter = format!("name eq \"{}\"", self.vault);
        let vaults: Vec<Vault> = self.get(&["v1", "vaults"], &[("filter", &filter)]).await?;
        let vault = vaults
            .into_iter()
            .find(|v| v.name == self.vault)
            .ok_or_else(|| {
                PolicyError::Unavailable(format!("vault \"{}\" not found", self.vault))
            })?;
        check_id(&vault.id)?;
        Ok(vault.id)
    }

    /// GET `/v1/vaults/{vault}/{tail…}`. On a 404 the vault id is resolved
    /// again; if the vault has a new id the request is repeated once with it.
    /// Otherwise (same id, or a second 404) the 404 is reported as it is, so
    /// a vault that is truly gone fails closed without a retry loop.
    async fn vault_bytes(&self, tail: &[&str]) -> Result<Zeroizing<Vec<u8>>, PolicyError> {
        let mut vault_id = self.vault_id().await?;
        for retry in [true, false] {
            let mut segments = vec!["v1", "vaults", vault_id.as_str()];
            segments.extend_from_slice(tail);
            if let Some(body) = self.get_found(&segments, &[]).await? {
                return Ok(body);
            }
            if !retry {
                break;
            }
            let current = self.refresh_vault_id(&vault_id).await?;
            if current == vault_id {
                break;
            }
            vault_id = current;
        }
        Err(PolicyError::Unavailable(format!(
            "1Password Connect returned HTTP {}",
            StatusCode::NOT_FOUND
        )))
    }

    /// [`Self::vault_bytes`], decoded. Never interpolates the serde error: it
    /// can quote a field value.
    async fn vault_get<T: DeserializeOwned>(&self, tail: &[&str]) -> Result<T, PolicyError> {
        let body = self.vault_bytes(tail).await?;
        serde_json::from_slice(&body).map_err(|e| unreadable(&e))
    }

    /// Summaries of all items in the vault carrying `tag`.
    async fn tagged(&self, tag: &str) -> Result<Vec<ItemSummary>, PolicyError> {
        let items: Vec<ItemSummary> = self.vault_get(&["items"]).await?;
        Ok(items
            .into_iter()
            .filter(|i| i.tags.iter().any(|t| t == tag))
            .collect())
    }

    /// The one item tagged `tag` and titled `title`; `Ok(None)` if there is
    /// none, [`PolicyError::Invalid`] if there are several.
    async fn tagged_titled(
        &self,
        tag: &str,
        title: &str,
        what: &str,
    ) -> Result<Option<ItemSummary>, PolicyError> {
        let mut matches: Vec<ItemSummary> = self
            .tagged(tag)
            .await?
            .into_iter()
            .filter(|i| i.title == title)
            .collect();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(Some(matches.remove(0))),
            _ => Err(invalid(
                title,
                "title",
                &format!("more than one item is tagged as {what} with this title"),
            )),
        }
    }

    /// Fetch and validate the API secret item `name`. The body and the
    /// credential stay in `Zeroizing` buffers throughout.
    async fn api_item(
        &self,
        name: &SecretName,
    ) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
        let summary = self
            .tagged_titled(API_TAG, name.as_str(), "an API secret")
            .await?
            .ok_or_else(|| PolicyError::UnknownSecret(name.as_str().to_owned()))?;
        check_id(&summary.id)?;
        let body = self.vault_bytes(&["items", &summary.id]).await?;
        // Never interpolate the serde error: it can quote the credential.
        let item: ApiItem = serde_json::from_slice(&body).map_err(|_| {
            PolicyError::Unavailable(format!(
                "1Password Connect sent an unreadable item for API secret \"{name}\""
            ))
        })?;
        drop(body);
        parse_api_secret(name, &item)
    }

    /// Fetch and validate the SSH target item `name`. The body and any
    /// relay credential stay in `Zeroizing` buffers throughout.
    async fn target_item(
        &self,
        name: &TargetName,
    ) -> Result<(SshTarget, Option<RelayCredential>), PolicyError> {
        let summary = self
            .tagged_titled(TARGET_TAG, name.as_str(), "a target")
            .await?
            .ok_or_else(|| PolicyError::NotFound(name.as_str().to_owned()))?;
        check_id(&summary.id)?;
        let body = self.vault_bytes(&["items", &summary.id]).await?;
        // Never interpolate the serde error: it can quote the credential.
        let item: TargetItem = serde_json::from_slice(&body).map_err(|_| {
            PolicyError::Unavailable(format!(
                "1Password Connect sent an unreadable item for target \"{name}\""
            ))
        })?;
        drop(body);
        parse_target(name, &item)
    }
}

/// The error for a response that is not the JSON we expect. Only the position
/// and class of the serde error are used: its text can quote a field value.
fn unreadable(e: &serde_json::Error) -> PolicyError {
    PolicyError::Unavailable(format!(
        "1Password Connect sent an unreadable response ({:?} error at line {}, column {})",
        e.classify(),
        e.line(),
        e.column()
    ))
}

/// Connect ids are 26 lowercase alphanumerics; refuse anything that could
/// alter the request path.
fn check_id(id: &str) -> Result<(), PolicyError> {
    if !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(PolicyError::Unavailable(
            "1Password Connect sent a malformed id".into(),
        ))
    }
}

#[async_trait]
impl SecretBackend for OnePasswordConnect {
    async fn ssh_target(&self, name: &TargetName) -> Result<SshTarget, PolicyError> {
        self.target_item(name)
            .await
            .map(|(target, _credential)| target)
    }

    async fn relay_target_with_credential(
        &self,
        name: &TargetName,
    ) -> Result<(SshTarget, RelayCredential), PolicyError> {
        match self.target_item(name).await? {
            (target, Some(credential)) => Ok((target, credential)),
            (_, None) => Err(not_a_relay_target(name.as_str())),
        }
    }

    async fn ssh_ca(&self) -> Result<CaKey, PolicyError> {
        let mut items = self.tagged(CA_TAG).await?;
        let summary = match items.len() {
            0 => return Err(PolicyError::Ca(format!("no item is tagged \"{CA_TAG}\""))),
            1 => items.remove(0),
            n => {
                return Err(PolicyError::Ca(format!(
                    "{n} items are tagged \"{CA_TAG}\"; exactly one is required"
                )));
            }
        };
        let ca_error =
            |reason: &str| PolicyError::Ca(format!("item \"{}\": {reason}", summary.title));
        check_id(&summary.id)?;
        let body = self.vault_bytes(&["items", &summary.id]).await?;
        // Never interpolate the serde error: it can quote a field value.
        let item: CaItem =
            serde_json::from_slice(&body).map_err(|_| ca_error("unreadable CA item"))?;
        drop(body);
        let text = item
            .fields
            .iter()
            .find(|f| f.id == CA_FIELD_ID)
            .and_then(|f| f.value.as_deref().map(String::as_str))
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                ca_error(&format!(
                    "field with id \"{CA_FIELD_ID}\" is missing or empty"
                ))
            })?;
        let key = parse_private_key(text).ok_or_else(|| {
            ca_error("the private key is not a readable OpenSSH or PKCS#8 Ed25519 key")
        })?;
        CaKey::new(key).map_err(|e| match e {
            PolicyError::Ca(reason) => ca_error(&reason),
            other => other,
        })
    }

    async fn api_secret(&self, name: &SecretName) -> Result<ApiSecretPolicy, PolicyError> {
        self.api_item(name).await.map(|(policy, _value)| policy)
    }

    async fn api_secret_with_value(
        &self,
        name: &SecretName,
    ) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
        self.api_item(name).await
    }
}

/// Parse an OpenSSH or PKCS#8 PEM private key. Returns `None` for anything
/// unreadable; the input is never echoed. PKCS#8 is only supported for
/// Ed25519, so a PKCS#8 RSA or ECDSA key is rejected as unreadable.
fn parse_private_key(text: &str) -> Option<PrivateKey> {
    let text = text.trim();
    if text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        PrivateKey::from_openssh(text).ok()
    } else if text.starts_with("-----BEGIN PRIVATE KEY-----") {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let signing = ed25519_dalek::SigningKey::from_pkcs8_pem(text).ok()?;
        let keypair = ssh_key::private::Ed25519Keypair::from(signing);
        Some(PrivateKey::from(keypair))
    } else {
        None
    }
}

fn invalid(item: &str, field: &str, reason: &str) -> PolicyError {
    PolicyError::Invalid {
        item: item.to_owned(),
        field: field.to_owned(),
        reason: reason.to_owned(),
    }
}

/// Validate an SSH target item. Returns the onward credential exactly when
/// the target is in relay mode. Reasons never quote a field value.
fn parse_target(
    name: &TargetName,
    item: &TargetItem,
) -> Result<(SshTarget, Option<RelayCredential>), PolicyError> {
    let title = item.title.as_str();
    let mut by_label: HashMap<&str, &str> = HashMap::new();
    for field in &item.fields {
        let (Some(label), Some(value)) = (field.label.as_deref(), field.value.as_deref()) else {
            continue;
        };
        if by_label.insert(label, value.as_str()).is_some() {
            return Err(invalid(title, label, "the field appears more than once"));
        }
    }
    let required = |label: &str| -> Result<&str, PolicyError> {
        match by_label.get(label).map(|v| v.trim()) {
            None => Err(invalid(title, label, "missing")),
            Some("") => Err(invalid(title, label, "empty")),
            Some(v) => Ok(v),
        }
    };

    let (host, port) =
        parse_address(required("address")?).map_err(|reason| invalid(title, "address", reason))?;

    let mode = match required("mode")? {
        "cert" => SshMode::Cert,
        "relay" => SshMode::Relay,
        _ => return Err(invalid(title, "mode", "must be \"cert\" or \"relay\"")),
    };

    let users = required("users")?
        .split(',')
        .map(|u| UnixUser::try_from(u.trim().to_owned()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| invalid(title, "users", &e.to_string()))?;

    let max_window = required("max_window")?
        .parse::<Window>()
        .map_err(|e| invalid(title, "max_window", &e.to_string()))?;

    let host_keys = required("host_keys")?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            PublicKey::from_openssh(l).map_err(|_| {
                invalid(
                    title,
                    "host_keys",
                    "a line is not a valid OpenSSH public key",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if host_keys.is_empty() {
        return Err(invalid(title, "host_keys", "no keys listed"));
    }

    let credential = parse_credential(title, mode, &by_label)?;

    let target = SshTarget {
        name: name.clone(),
        host,
        port,
        mode,
        users,
        max_window,
        host_keys,
    };
    Ok((target, credential))
}

/// The onward credential: exactly one of `private_key` and `password` for a
/// relay target, neither for a cert target. A blank field counts as absent.
/// The password is taken verbatim; the key is trimmed, checked (Ed25519
/// only) and normalised to OpenSSH format.
fn parse_credential(
    title: &str,
    mode: SshMode,
    by_label: &HashMap<&str, &str>,
) -> Result<Option<RelayCredential>, PolicyError> {
    let key = by_label
        .get("private_key")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty());
    let password = by_label.get("password").copied().filter(|v| !v.is_empty());
    let cert_only =
        "only relay targets hold an onward credential; remove the field or set mode to \"relay\"";
    match (mode, key, password) {
        (SshMode::Cert, None, None) => Ok(None),
        (SshMode::Cert, Some(_), _) => Err(invalid(title, "private_key", cert_only)),
        (SshMode::Cert, None, Some(_)) => Err(invalid(title, "password", cert_only)),
        (SshMode::Relay, None, None) => Err(invalid(
            title,
            "password",
            "missing: a relay target needs a \"password\" or a \"private_key\" field",
        )),
        (SshMode::Relay, Some(_), Some(_)) => Err(invalid(
            title,
            "private_key",
            "set either \"private_key\" or \"password\", not both",
        )),
        (SshMode::Relay, Some(text), None) => parse_relay_key(text)
            .map(|key| Some(RelayCredential::Key(key)))
            .map_err(|reason| invalid(title, "private_key", reason)),
        (SshMode::Relay, None, Some(password)) => Ok(Some(RelayCredential::Password(
            Zeroizing::new(password.to_owned()),
        ))),
    }
}

/// Check a relay target's login key and return it in OpenSSH format. Only
/// unencrypted Ed25519 keys are accepted, as OpenSSH or PKCS#8 PEM: warden
/// performs no RSA or NIST-curve private-key operation. The key type is read
/// from the container (the OpenSSH public key, the PKCS#8 algorithm
/// identifier) before any private key material is decoded, so another key
/// type is refused without being loaded. The input is never echoed.
fn parse_relay_key(text: &str) -> Result<Zeroizing<String>, &'static str> {
    const UNREADABLE: &str = "is not a readable OpenSSH or PKCS#8 PEM private key";
    const NOT_ED25519: &str =
        "relay keys must be Ed25519; use a password for targets that need another key type";
    let is_ed25519 = if text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        openssh_key_type(text).ok_or(UNREADABLE)? == b"ssh-ed25519"
    } else if text.starts_with("-----BEGIN PRIVATE KEY-----") {
        pkcs8_algorithm(text).ok_or(UNREADABLE)? == ed25519_dalek::pkcs8::ALGORITHM_OID
    } else {
        return Err(UNREADABLE);
    };
    if !is_ed25519 {
        return Err(NOT_ED25519);
    }
    let key = parse_private_key(text).ok_or(UNREADABLE)?;
    if key.is_encrypted() {
        return Err("is passphrase-protected; an unencrypted key is required");
    }
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(NOT_ED25519);
    }
    key.to_openssh(LineEnding::LF).map_err(|_| UNREADABLE)
}

/// The key type of an OpenSSH private key file (`ssh-ed25519`, `ssh-rsa`,
/// ...), read from the public key that precedes the private section. Only
/// single-key files are accepted.
fn openssh_key_type(text: &str) -> Option<Vec<u8>> {
    let body = Zeroizing::new(
        text.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>(),
    );
    let bytes = Zeroizing::new(STANDARD.decode(body.as_bytes()).ok()?);
    let mut rest = bytes.strip_prefix(b"openssh-key-v1\0")?;
    // Cipher name, KDF name and KDF options.
    for _ in 0..3 {
        ssh_string(&mut rest)?;
    }
    let count = rest.get(..4)?;
    if count != 1_u32.to_be_bytes() {
        return None;
    }
    rest = &rest[4..];
    let mut public_key = ssh_string(&mut rest)?;
    ssh_string(&mut public_key).map(<[u8]>::to_vec)
}

/// Take one length-prefixed SSH `string` off the front of `input`.
fn ssh_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, rest) = input.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    let (value, rest) = rest.split_at_checked(len)?;
    *input = rest;
    Some(value)
}

/// The algorithm identifier of a PKCS#8 PEM private key, without decoding
/// the private key it wraps.
fn pkcs8_algorithm(text: &str) -> Option<ed25519_dalek::pkcs8::ObjectIdentifier> {
    let (label, document) = ed25519_dalek::pkcs8::SecretDocument::from_pem(text).ok()?;
    if label != "PRIVATE KEY" {
        return None;
    }
    let info = ed25519_dalek::pkcs8::PrivateKeyInfo::try_from(document.as_bytes()).ok()?;
    Some(info.algorithm.oid)
}

/// Validate an API secret item. Optional fields that are absent or blank
/// take their default; the credential, `max_window` and the website never do.
/// Reasons never quote a field value.
fn parse_api_secret(
    name: &SecretName,
    item: &ApiItem,
) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
    const LABELS: [&str; 7] = [
        "credential",
        "max_window",
        "header",
        "format",
        "methods",
        "path_prefix",
        "ca_pem",
    ];
    let title = name.as_str();
    let fail = |field: &str, reason: &str| invalid(title, field, reason);
    let mut by_label: HashMap<&str, &str> = HashMap::new();
    for field in &item.fields {
        let (Some(label), Some(value)) = (field.label.as_deref(), field.value.as_deref()) else {
            continue;
        };
        if LABELS.contains(&label) && by_label.insert(label, value.as_str()).is_some() {
            return Err(fail(label, "the field appears more than once"));
        }
    }
    // Blank counts as absent.
    let get = |label: &str| {
        by_label
            .get(label)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
    };
    let required = |label: &str| get(label).ok_or_else(|| fail(label, "missing or empty"));

    let credential = required("credential")?;
    if credential.chars().count() < MIN_CREDENTIAL_CHARS {
        return Err(fail(
            "credential",
            &format!("must be at least {MIN_CREDENTIAL_CHARS} characters"),
        ));
    }
    if !credential.chars().all(is_header_text) {
        return Err(fail("credential", "must be printable ASCII"));
    }
    let value = SecretValue::new(Zeroizing::new(credential.to_owned()));

    let max_window = required("max_window")?
        .parse::<Window>()
        .map_err(|e| fail("max_window", &e.to_string()))?;

    let origin = parse_website(item).map_err(|reason| fail("website", reason))?;

    let header = match get("header") {
        None => http::header::AUTHORIZATION,
        Some(h) => HeaderName::from_bytes(h.as_bytes())
            .map_err(|_| fail("header", "not a valid HTTP header name"))?,
    };
    if is_reserved_header(&header) {
        return Err(fail(
            "header",
            "is a connection or framing header and cannot carry the secret",
        ));
    }

    let format = match get("format") {
        None => ValueFormat::default(),
        Some(f) => ValueFormat::parse(f).map_err(|reason| fail("format", reason))?,
    };

    let methods = match get("methods") {
        None => vec![Method::GET],
        Some(m) => parse_methods(m).map_err(|reason| fail("methods", reason))?,
    };

    let path_prefix = match get("path_prefix") {
        None => "/".to_owned(),
        Some(p) => {
            check_path_prefix(p).map_err(|reason| fail("path_prefix", reason))?;
            p.to_owned()
        }
    };

    let ca_pem = match get("ca_pem") {
        None => None,
        Some(pem) => {
            check_ca_pem(pem).map_err(|reason| fail("ca_pem", reason))?;
            Some(pem.to_owned())
        }
    };

    let policy = ApiSecretPolicy {
        name: name.clone(),
        origin,
        header,
        format,
        methods,
        path_prefix,
        ca_pem,
        max_window,
    };
    Ok((policy, value))
}

/// The item's primary website (else its first one) as a bare `https` origin.
fn parse_website(item: &ApiItem) -> Result<Origin, &'static str> {
    let href = item
        .urls
        .iter()
        .find(|u| u.primary)
        .or_else(|| item.urls.first())
        .and_then(|u| u.href.as_deref())
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .ok_or("missing; set the item's website to https://host[:port]")?;
    let url = Url::parse(href).map_err(|_| "not a valid URL")?;
    if url.scheme() != "https" {
        return Err("must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain a user name or password");
    }
    if url.host().is_none() {
        return Err("must name a host");
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err("must be only https://host[:port], without path, query or fragment");
    }
    match url.origin() {
        origin @ Origin::Tuple(..) => Ok(origin),
        Origin::Opaque(_) => Err("must be only https://host[:port]"),
    }
}

/// A comma-separated list of uppercase method tokens; duplicates are dropped.
fn parse_methods(list: &str) -> Result<Vec<Method>, &'static str> {
    let mut methods: Vec<Method> = Vec::new();
    for token in list.split(',').map(str::trim) {
        let method = parse_method(token)
            .ok_or("must be a comma-separated list of uppercase method names, such as GET, POST")?;
        if !methods.contains(&method) {
            methods.push(method);
        }
    }
    Ok(methods)
}

/// One or more PEM certificates, each usable as a TLS trust anchor.
fn check_ca_pem(pem: &str) -> Result<(), &'static str> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "is not readable PEM")?;
    if certs.is_empty() {
        return Err("contains no PEM certificate");
    }
    for cert in &certs {
        webpki::anchor_from_trusted_cert(cert)
            .map_err(|_| "contains a certificate that is not a valid X.509 CA certificate")?;
    }
    Ok(())
}

/// Split `host`, `host:port` or `[ipv6]:port`; the port defaults to 22.
fn parse_address(s: &str) -> Result<(String, u16), &'static str> {
    let (host, port) = parse_host_port(s)?;
    Ok((host, port.unwrap_or(22)))
}

/// Split `host`, `host:port` or `[ipv6]:port` into the host (without
/// brackets) and the port, if one is given. The host must be a plausible
/// host name or IP address; the port 1-65535.
///
/// # Errors
/// Why the address is unusable, as a fixed message that never echoes it.
pub(crate) fn parse_host_port(s: &str) -> Result<(String, Option<u16>), &'static str> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or("unterminated '[' in address")?;
        host.parse::<Ipv6Addr>()
            .map_err(|_| "not a valid IPv6 address")?;
        let port = match tail {
            "" => None,
            t => Some(t.strip_prefix(':').ok_or("expected ':port' after ']'")?),
        };
        (host, port)
    } else {
        match s.split_once(':') {
            None => (s, None),
            Some((_, p)) if p.contains(':') => {
                return Err("IPv6 addresses must be written as [addr]:port");
            }
            Some((h, p)) => (h, Some(p)),
        }
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
    if !host_ok {
        return Err("host is empty or contains unsupported characters");
    }
    let port = match port {
        None => None,
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n != 0 => Some(n),
            _ => return Err("port must be 1-65535"),
        },
    };
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::parse_address;

    #[test]
    fn addresses() {
        assert_eq!(parse_address("pi.lan"), Ok(("pi.lan".into(), 22)));
        assert_eq!(
            parse_address("10.0.0.1:2222"),
            Ok(("10.0.0.1".into(), 2222))
        );
        assert_eq!(parse_address("[::1]"), Ok(("::1".into(), 22)));
        assert_eq!(
            parse_address("[fe80::1]:2200"),
            Ok(("fe80::1".into(), 2200))
        );
    }

    #[test]
    fn bad_addresses() {
        for bad in [
            "",
            ":22",
            "-oProxyCommand=x",
            "host:0",
            "host:70000",
            "host:x",
            "::1",
            "[::1",
            "[::1]x",
            "[nope]",
            "a b",
            "host:22:23",
        ] {
            assert!(parse_address(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
