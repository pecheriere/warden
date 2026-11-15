//! HTTP signals: `covered-api` and `uncovered-host` for `curl`, `wget`,
//! `http`, `https` and `xh`.

use url::Url;

use super::Match;
use super::args::{self, Item, is_loopback, is_plain_host};
use crate::context::Context;
use crate::settings::Signal;

const CURL_SHORT: &str = "HdXuoAebcFTwxmKEDrCzYyUPtQ";
const CURL_LONG: &[&str] = &[
    "header",
    "data",
    "data-raw",
    "data-binary",
    "data-ascii",
    "data-urlencode",
    "json",
    "request",
    "user",
    "output",
    "user-agent",
    "referer",
    "cookie",
    "cookie-jar",
    "form",
    "form-string",
    "upload-file",
    "write-out",
    "proxy",
    "max-time",
    "config",
    "url",
    "oauth2-bearer",
    "cacert",
    "cert",
    "key",
    "connect-timeout",
    "retry",
    "resolve",
    "range",
    "continue-at",
    "dump-header",
    "proxy-user",
    "request-target",
    "aws-sigv4",
];
const WGET_SHORT: &str = "OoatTwPUeBiIXQl";
const WGET_LONG: &[&str] = &[
    "header",
    "user",
    "password",
    "http-user",
    "http-password",
    "output-document",
    "output-file",
    "user-agent",
    "referer",
    "post-data",
    "post-file",
    "method",
    "body-data",
    "body-file",
    "directory-prefix",
    "tries",
    "timeout",
    "wait",
    "input-file",
];
const HTTPIE_SHORT: &str = "aAops";
const HTTPIE_LONG: &[&str] = &[
    "auth",
    "auth-type",
    "output",
    "print",
    "style",
    "proxy",
    "timeout",
    "session",
    "session-read-only",
    "verify",
    "cert",
    "cert-key",
    "bearer",
    "pretty",
    "max-redirects",
    "default-scheme",
];

/// A URL the command reaches, reduced to what the signals need.
struct Target {
    host: String,
    /// The URL carries a user name or a password.
    credentials: bool,
}

/// Reads one URL word; a word without a scheme is read as `http://`.
fn target(word: &str) -> Option<Target> {
    let text = if word.contains("://") {
        word.to_owned()
    } else {
        format!("http://{word}")
    };
    let url = Url::parse(&text).ok()?;
    if !matches!(url.scheme(), "http" | "https" | "ftp" | "ftps") {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    is_plain_host(&host).then_some(Target {
        host,
        credentials: !url.username().is_empty() || url.password().is_some(),
    })
}

/// Whether a `curl`/`wget` word is a URL: it names a scheme, or it is a
/// dotted host name and so unlikely to be anything else.
fn is_url_word(word: &str) -> bool {
    word.contains("://")
        || (word.contains('.') && word.starts_with(|c: char| c.is_ascii_alphanumeric()))
}

fn is_authorization(header: &str) -> bool {
    let name = header.split(':').next().unwrap_or_default().trim();
    header.contains(':')
        && (name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("proxy-authorization"))
}

/// What the words of the command reach and whether they carry credentials.
struct Reading {
    urls: Vec<Target>,
    authorized: bool,
}

fn read(program: &str, args: &[String]) -> Reading {
    let httpie = matches!(program, "http" | "https" | "xh" | "xhs");
    let (short, long) = match program {
        "curl" => (CURL_SHORT, CURL_LONG),
        "wget" => (WGET_SHORT, WGET_LONG),
        _ => (HTTPIE_SHORT, HTTPIE_LONG),
    };
    let mut reading = Reading {
        urls: Vec::new(),
        authorized: false,
    };
    let mut positionals = 0_usize;
    for item in args::read(args, short, long) {
        match item {
            Item::Opt { name, value } => match (name.as_str(), value) {
                ("-H" | "--header", Some(header)) if is_authorization(header) => {
                    reading.authorized = true;
                }
                (
                    "-u" | "--user" | "--oauth2-bearer" | "--password" | "--http-user"
                    | "--http-password" | "-a" | "--auth" | "--bearer",
                    _,
                ) => {
                    reading.authorized = true;
                }
                ("--url", Some(word)) => reading.urls.extend(target(word)),
                _ => {}
            },
            Item::Positional(word) if httpie => {
                positionals += 1;
                let is_method = positionals == 1
                    && word.chars().all(|c| c.is_ascii_uppercase())
                    && !word.is_empty();
                if is_method {
                    continue;
                }
                if reading.urls.is_empty() {
                    reading.urls.extend(target(word));
                } else if is_authorization(word) {
                    reading.authorized = true;
                }
            }
            Item::Positional(word) => {
                if is_url_word(word) {
                    reading.urls.extend(target(word));
                }
            }
        }
    }
    reading
}

/// Matches of an HTTP client. They need the offers: with none, nothing is
/// known to be covered or uncovered.
pub(super) fn detect(program: &str, args: &[String], ctx: &Context) -> Vec<Match> {
    let Some(coverage) = &ctx.coverage else {
        return Vec::new();
    };
    let reading = read(program, args);
    let mut found = Vec::new();
    for url in &reading.urls {
        if coverage.api_for(&url.host).is_some() {
            found.push(Match {
                signal: Signal::CoveredApi,
                subject: url.host.clone(),
            });
        } else if (reading.authorized || url.credentials) && !is_loopback(&url.host) {
            found.push(Match {
                signal: Signal::UncoveredHost,
                subject: url.host.clone(),
            });
        }
    }
    found
}
