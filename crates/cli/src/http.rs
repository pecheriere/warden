//! `warden http`: have the broker call an HTTPS API through an api grant.
//!
//! The broker holds the secret, injects it and redacts it from the answer;
//! this side only names the grant, the call and where the output goes. Api
//! grants are recorded in `<state>/api-grants/<grant_id>.json` (0600, no
//! secrets).

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory as _};
use url::Url;
use warden_broker_proto::{ApiGrant, Id, ProxyRequest, ProxyResponse, SecretName, under_prefix};

use crate::agent::{private_dir, state_dir, write_new_private};

/// Largest request body the CLI sends, in bytes.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// What an api grant's record holds. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRecord {
    /// Grant identifier.
    pub grant_id: Id,
    /// Secret the broker injects for this grant.
    pub secret: SecretName,
    /// Only origin the broker will call.
    pub origin: String,
    /// End of validity, Unix seconds.
    pub not_after: i64,
    /// Methods the grant allows, uppercase. A record written before grants
    /// were scoped reads as `GET` only: the CLI never widens it.
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
    /// Path prefix the grant is limited to; `/` for a record written before
    /// grants were scoped.
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,
}

fn default_methods() -> Vec<String> {
    vec!["GET".to_owned()]
}

fn default_path_prefix() -> String {
    "/".to_owned()
}

impl ApiRecord {
    /// The record for `grant`, valid until `not_after`.
    #[must_use]
    pub fn new(grant_id: Id, api: &ApiGrant, not_after: i64) -> Self {
        Self {
            grant_id,
            secret: api.secret.clone(),
            origin: api.origin.clone(),
            not_after,
            methods: api.methods.clone(),
            path_prefix: api.path_prefix.clone(),
        }
    }

    /// Whether the grant covers `method` (any case) on `path`.
    fn covers(&self, method: &str, path: &str) -> bool {
        self.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
            && under_prefix(path, &self.path_prefix)
    }
}

/// `<state>/api-grants`, created 0700.
///
/// # Errors
/// As [`state_dir`].
pub fn api_grants_dir() -> Result<PathBuf> {
    let dir = state_dir()?.join("api-grants");
    private_dir(&dir)?;
    Ok(dir)
}

fn record_path(dir: &Path, grant_id: &Id) -> PathBuf {
    dir.join(format!("{grant_id}.json"))
}

/// Write the record of an approved api grant (0600).
///
/// # Errors
/// If the file cannot be written.
pub fn save(record: &ApiRecord) -> Result<()> {
    save_in(&api_grants_dir()?, record)
}

fn save_in(dir: &Path, record: &ApiRecord) -> Result<()> {
    write_new_private(
        &record_path(dir, &record.grant_id),
        &serde_json::to_vec_pretty(record)?,
    )
}

/// Every readable record under `dir`, and the error for each record file
/// that is not one. Hidden files (records still being written) are not
/// records.
fn load_in(dir: &Path) -> Vec<(PathBuf, Result<ApiRecord>)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| {
            let path = e.path();
            !e.file_name().to_string_lossy().starts_with('.')
                && path.extension().is_some_and(|ext| ext == "json")
        })
        .map(|e| {
            let path = e.path();
            let record = fs::read(&path)
                .with_context(|| format!("cannot read {}", path.display()))
                .and_then(|raw| serde_json::from_slice(&raw).context("invalid api grant record"));
            (path, record)
        })
        .collect()
}

/// The recorded api grants, newest last by end of validity, and the errors
/// for unreadable files.
///
/// # Errors
/// If the state directory is unusable.
pub fn load() -> Result<Vec<(PathBuf, Result<ApiRecord>)>> {
    Ok(load_in(&api_grants_dir()?))
}

/// The grants for `secret` still valid at `now`, newest first.
#[must_use]
pub fn active_in(dir: &Path, secret: &SecretName, now: i64) -> Vec<ApiRecord> {
    let mut records: Vec<ApiRecord> = load_in(dir)
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .filter(|r| &r.secret == secret && r.not_after > now)
        .collect();
    records.sort_by_key(|r| std::cmp::Reverse(r.not_after));
    records
}

/// The active grants for `secret`, newest first.
///
/// # Errors
/// If the state directory is unusable.
pub fn active(secret: &SecretName, now: i64) -> Result<Vec<ApiRecord>> {
    Ok(active_in(&api_grants_dir()?, secret, now))
}

/// The first of `active` (newest first) that allows `method` on `path`.
#[must_use]
pub fn covering<'a>(active: &'a [ApiRecord], method: &str, path: &str) -> Option<&'a ApiRecord> {
    active.iter().find(|r| r.covers(method, path))
}

/// The error for a call no active grant of `secret` covers.
#[must_use]
pub fn no_covering_message(secret: &SecretName, method: &str, path: &str) -> String {
    let method = method.to_ascii_uppercase();
    format!(
        "no active grant for {secret} allows {method} {path}; run: warden request api {secret} --methods {method} --for <window> --goal <text>"
    )
}

/// Delete the record of `grant_id`, if this machine holds it.
///
/// # Errors
/// If the file cannot be removed.
pub fn discard(grant_id: &Id) -> Result<bool> {
    let path = record_path(&api_grants_dir()?, grant_id);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("cannot remove {}", path.display())),
    }
}

/// Delete the records of grants ended by `now`. A record that cannot be
/// read is kept, with a warning on `warn`.
///
/// # Errors
/// If the state directory is unusable or a record cannot be removed; every
/// record is still attempted.
pub fn cleanup_expired(now: i64, warn: &mut impl std::io::Write) -> Result<()> {
    cleanup_expired_in(&api_grants_dir()?, now, warn)
}

fn cleanup_expired_in(dir: &Path, now: i64, warn: &mut impl std::io::Write) -> Result<()> {
    let mut failures = Vec::new();
    for (path, record) in load_in(dir) {
        match record {
            Ok(r) if r.not_after <= now => {
                if let Err(e) = fs::remove_file(&path) {
                    failures.push(format!("{}: {e}", path.display()));
                }
            }
            Ok(_) => {}
            Err(e) => writeln!(
                warn,
                "warden: warning: skipping {}: {}",
                sanitize(&path.display().to_string()),
                sanitize(&format!("{e:#}"))
            )
            .context("cannot write a warning")?,
        }
    }
    ensure!(
        failures.is_empty(),
        "cannot clean up api grants: {}",
        failures.join("; ")
    );
    Ok(())
}

/// Parse `-H 'Name: value'`: split at the first colon, name must be a
/// non-empty HTTP token, value has leading blanks trimmed and no control
/// characters.
///
/// # Errors
/// If there is no colon, the name is empty or not a token, or the value
/// holds control characters.
pub fn parse_header(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| format!("header {raw:?} must look like 'Name: value'"))?;
    let name = name.trim();
    if name.is_empty() {
        return Err("header name is empty".to_owned());
    }
    if !name.bytes().all(is_token_byte) {
        return Err(format!("header name {name:?} has invalid characters"));
    }
    let value = value.trim_matches([' ', '\t']);
    if value.chars().any(|c| c.is_control() && c != '\t') {
        return Err(format!("value of header {name} has control characters"));
    }
    Ok((name.to_owned(), value.to_owned()))
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The request body from `-d` or `--data-file` (`-` is stdin), at most
/// [`MAX_BODY_BYTES`].
///
/// # Errors
/// If the file or stdin cannot be read or the body is over 1 MiB.
pub fn read_body(data: Option<&str>, data_file: Option<&str>) -> Result<Option<Vec<u8>>> {
    let body = match (data, data_file) {
        (Some(data), _) => data.as_bytes().to_vec(),
        (None, Some("-")) => read_limited(std::io::stdin().lock(), "standard input")?,
        (None, Some(path)) => {
            let file =
                fs::File::open(path).with_context(|| format!("cannot open data file {path}"))?;
            read_limited(file, path)?
        }
        (None, None) => return Ok(None),
    };
    ensure!(
        body.len() <= MAX_BODY_BYTES,
        "the request body is larger than 1 MiB; refusing to send it"
    );
    Ok(Some(body))
}

fn read_limited(reader: impl std::io::Read, what: &str) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    reader
        .take(MAX_BODY_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .with_context(|| format!("cannot read {what}"))?;
    ensure!(
        body.len() <= MAX_BODY_BYTES,
        "the request body ({what}) is larger than 1 MiB; refusing to send it"
    );
    Ok(body)
}

/// The call for the broker: method upper-cased, URL parsed and `https`.
///
/// # Errors
/// If the method is not a token or the URL is not an absolute https URL.
pub fn proxy_request(
    method: &str,
    url: &str,
    headers: Vec<(String, String)>,
    body: Option<&[u8]>,
) -> Result<ProxyRequest> {
    ensure!(
        !method.is_empty() && method.bytes().all(is_token_byte),
        "{method:?} is not an HTTP method"
    );
    let parsed = Url::parse(url).with_context(|| format!("{url:?} is not an absolute URL"))?;
    if parsed.scheme() != "https" {
        bail!("only https URLs are supported, not {}", parsed.scheme());
    }
    Ok(ProxyRequest {
        method: method.to_ascii_uppercase(),
        url: parsed.to_string(),
        headers,
        body_b64: body.map(|b| STANDARD.encode(b)),
    })
}

/// The broker's answer, decoded: status, printable header lines and body.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    /// Upstream status code.
    pub status: u16,
    /// `name: value` lines with control characters replaced, so an upstream
    /// cannot drive the terminal.
    pub head: Vec<String>,
    /// Raw body.
    pub body: Vec<u8>,
}

/// Decode `resp`.
///
/// # Errors
/// If the body is not valid base64.
pub fn decode(resp: &ProxyResponse) -> Result<Reply> {
    let body = STANDARD
        .decode(&resp.body_b64)
        .context("the broker sent an invalid response body")?;
    let head = resp
        .headers
        .iter()
        .map(|(n, v)| sanitize(&format!("{n}: {v}")))
        .collect();
    Ok(Reply {
        status: resp.status,
        head,
        body,
    })
}

/// `text` safe to print on a terminal: control characters (C0, C1),
/// invisible format characters (bidi overrides, zero-width marks) and line
/// and paragraph separators are each replaced by `?`.
#[must_use]
pub fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            let unsafe_char = c.is_control()
                || matches!(
                    c.general_category(),
                    GeneralCategory::Format
                        | GeneralCategory::LineSeparator
                        | GeneralCategory::ParagraphSeparator
                );
            if unsafe_char { '?' } else { c }
        })
        .collect()
}

/// Write the body raw to `out`; with `include`, the status line and headers
/// to `err`.
///
/// # Errors
/// If writing fails.
pub fn emit(
    reply: &Reply,
    include: bool,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> Result<()> {
    if include {
        writeln!(err, "HTTP {}", reply.status)?;
        for line in &reply.head {
            writeln!(err, "{line}")?;
        }
        writeln!(err)?;
    }
    out.write_all(&reply.body)?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::{Id, ProxyResponse, SecretName};

    use super::{
        ApiRecord, MAX_BODY_BYTES, active_in, cleanup_expired_in, covering, decode, emit,
        parse_header, proxy_request, read_body, read_limited, sanitize, save_in,
    };

    fn scoped(secret: &str, not_after: i64, methods: &[&str], prefix: &str) -> ApiRecord {
        ApiRecord {
            grant_id: Id::random(),
            secret: SecretName::try_from(secret.to_owned()).unwrap(),
            origin: "https://api.example.com".to_owned(),
            not_after,
            methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            path_prefix: prefix.to_owned(),
        }
    }

    fn record(secret: &str, not_after: i64) -> ApiRecord {
        scoped(secret, not_after, &["GET"], "/")
    }

    #[test]
    fn old_record_reads_as_read_only() {
        let old = format!(
            r#"{{"grant_id":"{}","secret":"svc","origin":"https://api.example.com","not_after":9}}"#,
            Id::random()
        );
        let rec: ApiRecord = serde_json::from_str(&old).unwrap();
        assert_eq!(rec.methods, ["GET"]);
        assert_eq!(rec.path_prefix, "/");
    }

    #[test]
    fn http_picks_covering_grant() {
        let dir = tempfile::tempdir().unwrap();
        let name = SecretName::try_from("svc".to_owned()).unwrap();
        let read = scoped("svc", 900, &["GET", "HEAD"], "/");
        let write = scoped("svc", 500, &["GET", "POST"], "/v1/items");
        let narrow = scoped("svc", 800, &["GET"], "/v1/other");
        for r in [&read, &write, &narrow] {
            save_in(dir.path(), r).unwrap();
        }
        let active = active_in(dir.path(), &name, 100);
        // GET: the newest of either grant that covers the path.
        assert_eq!(covering(&active, "get", "/v1/items/3"), Some(&read));
        assert_eq!(covering(&active, "GET", "/v1/other/x"), Some(&read));
        // POST: only the write grant, and only under its prefix.
        assert_eq!(covering(&active, "POST", "/v1/items"), Some(&write));
        assert_eq!(covering(&active, "POST", "/v1/items/3"), Some(&write));
        assert_eq!(covering(&active, "POST", "/v1/itemsx"), None);
        assert_eq!(covering(&active, "POST", "/v1/other"), None);
        assert_eq!(covering(&active, "DELETE", "/v1/items"), None);
    }

    #[test]
    fn http_no_covering_grant_suggests_request() {
        let active = [record("svc", 500)];
        assert_eq!(covering(&active, "POST", "/x"), None);
        let secret = SecretName::try_from("svc".to_owned()).unwrap();
        assert_eq!(
            super::no_covering_message(&secret, "POST", "/x"),
            "no active grant for svc allows POST /x; run: warden request api svc --methods POST --for <window> --goal <text>"
        );
    }

    #[test]
    fn header_splits_at_first_colon() {
        assert_eq!(
            parse_header("X-Time: 12:30:00").unwrap(),
            ("X-Time".to_owned(), "12:30:00".to_owned())
        );
        assert_eq!(
            parse_header("Accept:application/json").unwrap(),
            ("Accept".to_owned(), "application/json".to_owned())
        );
        assert_eq!(
            parse_header("X-Empty:").unwrap(),
            ("X-Empty".to_owned(), String::new())
        );
    }

    #[test]
    fn header_rejects_bad_input() {
        for bad in [
            ": value",
            "  : value",
            "no colon",
            "Bad Name: v",
            "X: a\r\nInjected: b",
            "X: a\0b",
        ] {
            assert!(parse_header(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn body_limit_is_one_mib() {
        let at = "a".repeat(MAX_BODY_BYTES);
        assert_eq!(
            read_body(Some(&at), None).unwrap().unwrap().len(),
            MAX_BODY_BYTES
        );
        let over = "a".repeat(MAX_BODY_BYTES + 1);
        let err = read_body(Some(&over), None).unwrap_err();
        assert!(err.to_string().contains("1 MiB"), "{err}");
        assert!(
            read_limited(std::io::repeat(b'x'), "x")
                .unwrap_err()
                .to_string()
                .contains("1 MiB")
        );
        assert_eq!(read_body(None, None).unwrap(), None);
    }

    #[test]
    fn body_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b");
        std::fs::write(&path, b"\xff\x00raw").unwrap();
        assert_eq!(
            read_body(None, Some(path.to_str().unwrap())).unwrap(),
            Some(b"\xff\x00raw".to_vec())
        );
        assert!(read_body(None, Some("/nonexistent/warden")).is_err());
    }

    #[test]
    fn request_is_validated() {
        let ok =
            proxy_request("get", "https://api.example.com/v1/x?a=1", Vec::new(), None).unwrap();
        assert_eq!(ok.method, "GET");
        assert_eq!(ok.url, "https://api.example.com/v1/x?a=1");
        assert!(proxy_request("GET", "http://api.example.com/", Vec::new(), None).is_err());
        assert!(proxy_request("GET", "/relative", Vec::new(), None).is_err());
        assert!(proxy_request("GE T", "https://a.example/", Vec::new(), None).is_err());
        let with_body =
            proxy_request("POST", "https://a.example/", Vec::new(), Some(b"hi")).unwrap();
        assert_eq!(with_body.body_b64.as_deref(), Some("aGk="));
    }

    #[test]
    fn non_utf8_body_is_written_raw_and_head_is_sanitised() {
        let resp = ProxyResponse {
            status: 200,
            headers: vec![("x-evil".to_owned(), "a\u{1b}[31mb".to_owned())],
            body_b64: "//4AgA==".to_owned(),
            redactions: 0,
        };
        let reply = decode(&resp).unwrap();
        assert_eq!(reply.body, [0xff, 0xfe, 0x00, 0x80]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        emit(&reply, true, &mut out, &mut err).unwrap();
        assert_eq!(out, [0xff, 0xfe, 0x00, 0x80]);
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "HTTP 200\nx-evil: a?[31mb\n\n"
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        emit(&reply, false, &mut out, &mut err).unwrap();
        assert!(err.is_empty());
        assert!(
            decode(&ProxyResponse {
                body_b64: "!!".to_owned(),
                ..resp
            })
            .is_err()
        );
    }

    #[test]
    fn sanitize_replaces_control_format_and_separator_characters() {
        assert_eq!(sanitize("plain text: ok"), "plain text: ok");
        // C0 and C1 controls.
        assert_eq!(sanitize("a\u{1b}[31mb\r\n\0"), "a?[31mb???");
        assert_eq!(sanitize("a\u{9b}2Jb\u{85}"), "a?2Jb?");
        // Format characters: bidi overrides and isolates, zero-width.
        assert_eq!(sanitize("x\u{202e}y\u{2066}z\u{200b}w\u{feff}"), "x?y?z?w?");
        // Line and paragraph separators.
        assert_eq!(sanitize("x\u{2028}y\u{2029}z"), "x?y?z");
        // Other non-ASCII text is kept.
        assert_eq!(
            sanitize("caf\u{e9} \u{5e9}\u{5dc}"),
            "caf\u{e9} \u{5e9}\u{5dc}"
        );
    }

    #[test]
    fn newest_active_grant_for_the_secret_wins() {
        let dir = tempfile::tempdir().unwrap();
        let name = SecretName::try_from("svc".to_owned()).unwrap();
        let (old, new, other, ended) = (
            record("svc", 200),
            record("svc", 300),
            record("other", 900),
            record("svc", 50),
        );
        for r in [&old, &new, &other, &ended] {
            save_in(dir.path(), r).unwrap();
        }
        assert_eq!(active_in(dir.path(), &name, 100), [new.clone(), old]);
        assert_eq!(active_in(dir.path(), &name, 300), []);
    }

    fn names_in(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn cleanup_removes_only_ended_records() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let (live, ended) = (record("svc", 500), record("svc", 100));
        save_in(dir.path(), &live).unwrap();
        save_in(dir.path(), &ended).unwrap();
        let mut warnings = Vec::new();
        cleanup_expired_in(dir.path(), 200, &mut warnings).unwrap();
        assert!(warnings.is_empty());
        let left = names_in(dir.path());
        assert_eq!(left, [format!("{}.json", live.grant_id)]);
        let mode = std::fs::metadata(dir.path().join(left[0].as_str()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// A record that cannot be read may be one another `warden` is writing,
    /// or one the user wants to look at: it is left alone, with a warning.
    #[test]
    fn cleanup_keeps_unparseable_record_and_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("junk.json"), "{").unwrap();
        let mut warnings = Vec::new();
        cleanup_expired_in(dir.path(), 200, &mut warnings).unwrap();
        assert_eq!(names_in(dir.path()), ["junk.json"]);
        let warnings = String::from_utf8(warnings).unwrap();
        assert!(
            warnings.starts_with("warden: warning: skipping ") && warnings.contains("junk.json"),
            "{warnings}"
        );
        assert_eq!(warnings.lines().count(), 1, "{warnings}");
    }

    /// Two `warden request api` runs for the same secret can receive the
    /// same grant: saving its identical record again succeeds.
    #[test]
    fn saving_the_same_record_twice_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let rec = record("svc", 500);
        save_in(dir.path(), &rec).unwrap();
        save_in(dir.path(), &rec).unwrap();
        assert_eq!(names_in(dir.path()), [format!("{}.json", rec.grant_id)]);
        let changed = ApiRecord {
            not_after: 600,
            ..rec.clone()
        };
        assert!(save_in(dir.path(), &changed).is_err());
        let secret = SecretName::try_from("svc".to_owned()).unwrap();
        assert_eq!(active_in(dir.path(), &secret, 100), [rec]);
    }
}
