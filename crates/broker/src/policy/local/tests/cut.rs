//! Sealed policy files cut at any byte, the end marker and parser limits.

use super::{API_ENTRY, Setup, ed25519_pem, host_key, seal, secret, target};
use crate::policy::SecretBackend;
use crate::policy::local::{END_MARKER, LocalProbe, digest_line, parse_policy};

/// Every setting that has a default, each narrowing it, and every kind of entry.
fn full_policy() -> String {
    seal(&format!(
        r#"# A comment with a non-ASCII character: café, and # [end_of_policy]
[ca]
private_key_file = "ssh-ca"

[targets.web-01]
address = "web-01.example.com"
mode = "cert"
users = ["deploy"]
max_window = "1h"
host_keys = ["{key}"]

[targets.switch-01]
address = "switch-01.example.com"
mode = "relay"
users = ["admin"]
max_window = "1h"
host_keys = ["{key}"]
password_file = "switch-password"

[api_secrets.home-api]
website = "https://home.example.com"
credential_file = "home-api"
max_window = "30m"
ca_pem = """
{ca}"""
format = "token {{{{secret}}}}"
header = "X-Api-Key"
methods = ["GET"]
path_prefix = "/api/"

{END_MARKER}
"#,
        key = host_key(),
        ca = include_str!("../../../../tests/fixtures/throwaway-test-only-ca.pem"),
    ))
}

/// A file cut at any byte, however the cut came about, must not load: neither
/// narrower nor, above all, wider than the file it was cut from. Every byte
/// through the parser; the file system is far slower, so below at line ends.
#[test]
fn a_policy_cut_at_any_byte_does_not_parse() {
    let full = full_policy();
    assert!(parse_policy(&full).is_ok());
    let complete = full.trim_end().len();
    for cut in 0..complete {
        // A cut inside a character is refused earlier, as invalid UTF-8.
        if let Ok(text) = std::str::from_utf8(&full.as_bytes()[..cut]) {
            assert!(parse_policy(text).is_err(), "cut at byte {cut} loaded");
        }
    }
    for cut in complete..=full.len() {
        assert!(parse_policy(&full[..cut]).is_ok(), "{cut}");
    }
}

/// The same through the backend: nothing is served from a cut file, and a whole
/// one is served unchanged.
#[tokio::test]
async fn a_cut_policy_file_is_refused_at_every_line_and_inside_the_marker() {
    let setup = Setup::new("");
    setup.secret("ssh-ca", &ed25519_pem());
    setup.secret("switch-password", "a-password\n");
    let full = full_policy();
    setup.write_raw(full.as_bytes());
    let probe = setup.backend.probe().await;
    assert_eq!(probe.problems(), Vec::<String>::new());
    let name = secret("home-api");
    let whole = setup.backend.api_secret(&name).await.unwrap();

    let complete = full.trim_end().len();
    let line_ends = full
        .match_indices('\n')
        .map(|(at, _)| at)
        .filter(|at| *at < complete);
    let marker = full.rfind(END_MARKER).unwrap()..complete;
    let inside_the_character = full.find('\u{e9}').unwrap() + 1;
    for cut in line_ends.chain(marker).chain([0, inside_the_character]) {
        setup.write_raw(&full.as_bytes()[..cut]);
        let probe = setup.backend.probe().await;
        assert!(
            matches!(probe, LocalProbe::Unreadable(_)),
            "cut at byte {cut} loaded: {probe:?}"
        );
        assert!(setup.backend.api_secret(&name).await.is_err(), "{cut}");
        let target = target("web-01");
        assert!(setup.backend.ssh_target(&target).await.is_err(), "{cut}");
        assert!(setup.backend.ssh_ca().await.is_err(), "{cut}");
    }
    setup.write_raw(&full.as_bytes()[..complete]);
    let same = setup.backend.api_secret(&name).await.unwrap();
    assert_eq!(same.destination_digest(), whole.destination_digest());
    assert_eq!(same.path_prefix, "/api/");
}

/// The attack as first found: the last line of the entry narrows the prefix.
#[tokio::test]
async fn a_cut_can_never_widen_a_prefix_or_change_a_header() {
    let setup = Setup::new("");
    let entry = format!(
        "{}header = \"X-Api-Key\"\npath_prefix = \"/api/\"\n",
        API_ENTRY.replace("path_prefix = \"/api/\"\n", "")
    );
    for lines in 1..entry.lines().count() {
        let cut: Vec<&str> = entry.lines().take(lines).collect();
        setup.write_raw(cut.join("\n").as_bytes());
        assert!(
            setup.backend.api_secret(&secret("home-api")).await.is_err(),
            "{lines} lines"
        );
    }
}

/// A line reading like the marker inside a string is not the marker: a cut just
/// after it leaves the string open, sealed or not.
#[tokio::test]
async fn the_marker_inside_a_string_does_not_complete_a_cut_file() {
    let setup = Setup::new("");
    let text = format!(
        "[api_secrets.home-api]\nwebsite = \"https://home.example.com\"\n\
         credential_file = \"home-api\"\nmax_window = \"30m\"\n\
         format = \"\"\"\n{END_MARKER}\nx {{{{secret}}}}\"\"\"\n{END_MARKER}\n"
    );
    let cut = text.find(END_MARKER).unwrap() + END_MARKER.len();
    for cut_file in [text[..cut].to_owned(), seal(&text[..cut])] {
        setup.write_raw(cut_file.as_bytes());
        let probe = setup.backend.probe().await;
        assert!(matches!(probe, LocalProbe::Unreadable(_)), "{probe:?}");
    }
}

#[tokio::test]
async fn the_marker_must_be_the_last_line_and_empty() {
    let setup = Setup::new("");
    for bad in [
        format!("{END_MARKER}\n{API_ENTRY}"),
        format!("{API_ENTRY}\n{END_MARKER} # done\n"),
        format!("{API_ENTRY}\n{END_MARKER}\nx = 1\n"),
        format!("{API_ENTRY}\n{END_MARKER}\n{END_MARKER}\n"),
        format!("{API_ENTRY}\n[end_of_policy.more]\n{END_MARKER}\n"),
    ] {
        // With a digest that matches: the marker's rules hold by themselves.
        let digest = digest_line(&bad);
        setup.write_raw(format!("{bad}{digest}\n").as_bytes());
        let probe = setup.backend.probe().await;
        assert!(
            matches!(probe, LocalProbe::Unreadable(_)),
            "{bad}: {probe:?}"
        );
    }
}

/// Parsing runs on a blocking thread of the broker: a file at the size limit,
/// nested as deep as it can be, must be refused rather than crash the process.
#[tokio::test]
async fn deep_nesting_is_refused() {
    let setup = Setup::new("");
    for depth in [200_usize, 5_000, 500_000] {
        let brackets = format!("a = {}{}", "[".repeat(depth), "]".repeat(depth));
        setup.write_policy(&brackets);
        let probe = setup.backend.probe().await;
        assert!(matches!(probe, LocalProbe::Unreadable(_)), "{depth}");
    }
}
