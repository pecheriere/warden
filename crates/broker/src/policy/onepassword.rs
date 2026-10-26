//! [`SecretBackend`] backed by a 1Password Connect server.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::Duration;

use async_trait::async_trait;
use http::{HeaderName, Method};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use ssh_key::{PrivateKey, PublicKey};
use tokio::sync::OnceCell;
use url::{Origin, Url};
use warden_broker_proto::{SecretName, TargetName, UnixUser, Window};
use zeroize::Zeroizing;

use super::{
    ApiSecretPolicy, CaKey, PolicyError, SecretBackend, SecretValue, SshMode, SshTarget,
    ValueFormat, is_header_text, is_reserved_header,
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

#[derive(Deserialize)]
struct Item {
    title: String,
    #[serde(default)]
    fields: Vec<Field>,
}

#[derive(Deserialize)]
struct Field {
    label: Option<String>,
    value: Option<String>,
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
/// call; only the vault id is cached.
pub struct OnePasswordConnect {
    client: reqwest::Client,
    base: Url,
    token: SecretString,
    vault: String,
    vault_id: OnceCell<String>,
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
            vault_id: OnceCell::new(),
        }
    }

    async fn get<T: DeserializeOwned>(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<T, PolicyError> {
        let body = self.get_bytes(segments, query).await?;
        // Never interpolate the serde error itself: it can quote a field value.
        serde_json::from_slice(&body).map_err(|e| {
            PolicyError::Unavailable(format!(
                "1Password Connect sent an unreadable response ({:?} error at line {}, column {})",
                e.classify(),
                e.line(),
                e.column()
            ))
        })
    }

    /// GET and return the raw body in memory that is wiped on drop.
    async fn get_bytes(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<Zeroizing<Vec<u8>>, PolicyError> {
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
        Ok(body)
    }

    async fn vault_id(&self) -> Result<&str, PolicyError> {
        self.vault_id
            .get_or_try_init(|| async {
                if self.vault.contains(['"', '\\']) {
                    return Err(PolicyError::Unavailable(
                        "vault name contains unsupported characters".into(),
                    ));
                }
                let filter = format!("name eq \"{}\"", self.vault);
                let vaults: Vec<Vault> =
                    self.get(&["v1", "vaults"], &[("filter", &filter)]).await?;
                let vault = vaults
                    .into_iter()
                    .find(|v| v.name == self.vault)
                    .ok_or_else(|| {
                        PolicyError::Unavailable(format!("vault \"{}\" not found", self.vault))
                    })?;
                check_id(&vault.id)?;
                Ok(vault.id)
            })
            .await
            .map(String::as_str)
    }

    /// Summaries of all items in the vault carrying `tag`.
    async fn tagged(&self, tag: &str) -> Result<Vec<ItemSummary>, PolicyError> {
        let vault_id = self.vault_id().await?;
        let items: Vec<ItemSummary> = self.get(&["v1", "vaults", vault_id, "items"], &[]).await?;
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
        let vault_id = self.vault_id().await?;
        let body = self
            .get_bytes(&["v1", "vaults", vault_id, "items", &summary.id], &[])
            .await?;
        // Never interpolate the serde error: it can quote the credential.
        let item: ApiItem = serde_json::from_slice(&body).map_err(|_| {
            PolicyError::Unavailable(format!(
                "1Password Connect sent an unreadable item for API secret \"{name}\""
            ))
        })?;
        drop(body);
        parse_api_secret(name, &item)
    }

    async fn full_item(&self, id: &str) -> Result<Item, PolicyError> {
        check_id(id)?;
        let vault_id = self.vault_id().await?;
        self.get(&["v1", "vaults", vault_id, "items", id], &[])
            .await
    }
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
        let summary = self
            .tagged_titled(TARGET_TAG, name.as_str(), "a target")
            .await?
            .ok_or_else(|| PolicyError::NotFound(name.as_str().to_owned()))?;
        let item = self.full_item(&summary.id).await?;
        parse_target(name, &item)
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
        let vault_id = self.vault_id().await?;
        let body = self
            .get_bytes(&["v1", "vaults", vault_id, "items", &summary.id], &[])
            .await?;
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

    async fn api_secret_value(&self, name: &SecretName) -> Result<SecretValue, PolicyError> {
        self.api_item(name).await.map(|(_policy, value)| value)
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

fn parse_target(name: &TargetName, item: &Item) -> Result<SshTarget, PolicyError> {
    let title = item.title.as_str();
    let mut by_label: HashMap<&str, &str> = HashMap::new();
    for field in &item.fields {
        let (Some(label), Some(value)) = (field.label.as_deref(), field.value.as_deref()) else {
            continue;
        };
        if by_label.insert(label, value).is_some() {
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

    Ok(SshTarget {
        name: name.clone(),
        host,
        port,
        mode,
        users,
        max_window,
        host_keys,
    })
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
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(
                "must be a comma-separated list of uppercase method names, such as GET, POST",
            );
        }
        let method =
            Method::from_bytes(token.as_bytes()).map_err(|_| "contains an invalid method name")?;
        if !methods.contains(&method) {
            methods.push(method);
        }
    }
    Ok(methods)
}

/// An absolute path without query, fragment, empty or dot segments, or
/// characters that need quoting.
fn check_path_prefix(prefix: &str) -> Result<(), &'static str> {
    if !prefix.starts_with('/') {
        return Err("must start with /");
    }
    if !prefix
        .chars()
        .all(|c| c.is_ascii_graphic() && !matches!(c, '?' | '#' | '\\'))
    {
        return Err("must be printable ASCII without spaces, ?, # or \\");
    }
    // The leading "/" yields one empty first segment; a trailing "/" one
    // empty last segment. Any other empty segment is a "//".
    let segments: Vec<&str> = prefix.split('/').skip(1).collect();
    let (last, inner) = segments.split_last().unwrap_or((&"", &[]));
    if inner.iter().any(|s| s.is_empty()) {
        return Err("must not contain //");
    }
    if inner.iter().chain([last]).any(|s| matches!(*s, "." | "..")) {
        return Err("must not contain . or .. segments");
    }
    Ok(())
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
        None => 22,
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n != 0 => n,
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
