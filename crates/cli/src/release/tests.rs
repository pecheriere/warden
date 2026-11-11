//! Tests of the release step commands.

use clap::Parser as _;
use warden_broker_proto::release::{MAX_MANIFEST_BYTES, ReleaseTag, RepoName};

use super::manifest_request;
use crate::cli::{Cli, Cmd, ReleaseCmd};

fn repository() -> RepoName {
    "example-owner/example-repo".parse().unwrap()
}

fn tag() -> ReleaseTag {
    "v1.2.3".parse().unwrap()
}

#[test]
fn sign_manifest_refuses_large_file_locally() {
    let dir = tempfile::tempdir().unwrap();
    let at_limit = dir.path().join("at-limit");
    std::fs::write(&at_limit, vec![b'a'; MAX_MANIFEST_BYTES]).unwrap();
    assert!(manifest_request(repository(), tag(), &at_limit).is_ok());

    let over = dir.path().join("over");
    std::fs::write(&over, vec![b'a'; MAX_MANIFEST_BYTES + 1]).unwrap();
    let error = manifest_request(repository(), tag(), &over).unwrap_err();
    assert!(
        format!("{error:#}").contains(&MAX_MANIFEST_BYTES.to_string()),
        "{error:#}"
    );

    let missing = dir.path().join("missing");
    assert!(manifest_request(repository(), tag(), &missing).is_err());
}

#[test]
fn sign_manifest_sends_base_name() {
    use base64::Engine as _;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("warden-1.2.3-SHA256SUMS");
    let content = format!("{}  warden-1.2.3.tar.gz\n", "a".repeat(64));
    std::fs::write(&file, &content).unwrap();
    let request = manifest_request(repository(), tag(), &file).unwrap();
    assert_eq!(request.name, "warden-1.2.3-SHA256SUMS");
    assert_eq!(request.repository, repository());
    assert_eq!(request.tag, tag());
    let sent = base64::engine::general_purpose::STANDARD
        .decode(&request.content_b64)
        .unwrap();
    assert_eq!(sent, content.as_bytes());
}

#[test]
fn commands_validate_repository_and_tag() {
    for line in [
        "tag example-owner/example-repo v1.2.3",
        "publish example-owner/example-repo v1.2.3-rc.1",
        "sign-manifest example-owner/example-repo v1.2.3 SHA256SUMS",
    ] {
        let args = std::iter::once("warden")
            .chain(["release"])
            .chain(line.split(' '));
        let cli = Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{line}: {e}"));
        assert!(matches!(
            cli.command,
            Cmd::Release {
                what: ReleaseCmd::Tag { .. }
                    | ReleaseCmd::Publish { .. }
                    | ReleaseCmd::SignManifest { .. }
            }
        ));
    }
    for line in [
        "tag not-a-repo v1.2.3",
        "tag ../repo v1.2.3",
        "tag example-owner/example-repo 1.2.3",
        "publish example-owner/example-repo v1.2",
        "sign-manifest example-owner/example-repo main SHA256SUMS",
        "sign-manifest example-owner/example-repo v1.2.3",
    ] {
        let args = std::iter::once("warden")
            .chain(["release"])
            .chain(line.split(' '));
        assert!(Cli::try_parse_from(args).is_err(), "{line}");
    }
}
