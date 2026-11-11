use std::path::Path;
use std::process::{Command, Stdio};

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use warden_broker_proto::release::{CommitId, ReleaseTag};

mod manifest;

use super::{sign_tag, tag_object_id, tag_payload};
use crate::policy::ReleaseSigningKey;

const REPO: &str = "example-owner/example-repo";
const TIME: i64 = 1_794_000_000;

fn git(dir: &Path, args: &[&str], input: Option<&[u8]>) -> String {
    let mut child = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input.unwrap_or_default()).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn tag() -> ReleaseTag {
    ReleaseTag::try_from("v1.2.3".to_owned()).unwrap()
}

#[test]
fn tag_payload_has_git_layout() {
    let commit = CommitId::try_from("a".repeat(40)).unwrap();
    let payload = tag_payload(
        &commit,
        &tag(),
        "Release Bot",
        "release@example.com",
        TIME,
        "example-repo 1.2.3",
    );
    assert_eq!(
        String::from_utf8(payload).unwrap(),
        format!(
            "object {}\ntype commit\ntag v1.2.3\ntagger Release Bot <release@example.com> {TIME} +0000\n\nexample-repo 1.2.3\n",
            "a".repeat(40)
        )
    );
}

#[test]
fn tag_payload_matches_git() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    git(path, &["init", "--quiet", "."], None);
    git(
        path,
        &[
            "-c",
            "user.name=Dev",
            "-c",
            "user.email=dev@example.com",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "start",
        ],
        None,
    );
    let commit = CommitId::try_from(git(path, &["rev-parse", "HEAD"], None)).unwrap();
    let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public = private.public_key().to_openssh().unwrap();
    let key = ReleaseSigningKey::for_tests(REPO, private, None, false);
    let payload = tag_payload(
        &commit,
        &tag(),
        key.tagger_name(),
        key.tagger_email(),
        TIME,
        "example-repo 1.2.3",
    );
    let signature = sign_tag(&key, &payload).unwrap();
    assert!(signature.starts_with("-----BEGIN SSH SIGNATURE-----\n"));
    assert!(signature.ends_with("-----END SSH SIGNATURE-----\n"));
    assert!(!signature.contains('\r'));

    let mut object = payload.clone();
    object.extend_from_slice(signature.as_bytes());
    let id = git(path, &["mktag"], Some(&object));
    assert_eq!(id, tag_object_id(&payload, &signature));
    assert_eq!(git(path, &["cat-file", "tag", &id], None).as_bytes(), {
        // `git cat-file` prints the object and `trim` took the last newline.
        let mut shown = object.clone();
        shown.pop();
        shown
    });

    let signers = path.join("allowed-signers");
    std::fs::write(
        &signers,
        format!("{} namespaces=\"git\" {public}\n", key.tagger_email()),
    )
    .unwrap();
    git(path, &["update-ref", "refs/tags/v1.2.3", &id], None);
    git(
        path,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("gpg.ssh.allowedSignersFile={}", signers.display()),
            "verify-tag",
            "v1.2.3",
        ],
        None,
    );
}

#[test]
fn the_release_key_verifies_what_it_signed() {
    let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let key = ReleaseSigningKey::for_tests(REPO, private, None, false);
    let commit = CommitId::try_from("b".repeat(40)).unwrap();
    let payload = tag_payload(&commit, &tag(), "A", "a@example.com", TIME, "m");
    let signature = sign_tag(&key, &payload).unwrap();
    let mut object = payload;
    object.extend_from_slice(signature.as_bytes());
    assert!(key.verifies_tag(&object));
}
