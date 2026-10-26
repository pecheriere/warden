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
use url::Url;
use warden_broker_proto::{ApiGrant, Id, ProxyRequest, ProxyResponse, SecretName};

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
        }
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

/// The newest grant for `secret` still valid at `now`.
#[must_use]
pub fn active_in(dir: &Path, secret: &SecretName, now: i64) -> Option<ApiRecord> {
    load_in(dir)
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .filter(|r| &r.secret == secret && r.not_after > now)
        .max_by_key(|r| r.not_after)
}

/// The newest active grant for `secret`.
///
/// # Errors
/// If the state directory is unusable.
pub fn active(secret: &SecretName, now: i64) -> Result<Option<ApiRecord>> {
    Ok(active_in(&api_grants_dir()?, secret, now))
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

fn sanitize(line: &str) -> String {
    line.chars()
        .map(|c| if c.is_control() { '?' } else { c })
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
        ApiRecord, MAX_BODY_BYTES, active_in, cleanup_expired_in, decode, emit, parse_header,
        proxy_request, read_body, read_limited, save_in,
    };

    fn record(secret: &str, not_after: i64) -> ApiRecord {
        ApiRecord {
            grant_id: Id::random(),
            secret: SecretName::try_from(secret.to_owned()).unwrap(),
            origin: "https://api.example.com".to_owned(),
            not_after,
        }
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
        assert_eq!(active_in(dir.path(), &name, 100), Some(new));
        assert_eq!(active_in(dir.path(), &name, 300), None);
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
        assert_eq!(active_in(dir.path(), &secret, 100), Some(rec));
    }
}
