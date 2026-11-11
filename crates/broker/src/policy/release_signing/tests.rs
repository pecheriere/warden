use serde_json::{Value, json};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

use super::{check_distinct, parse_item};
use crate::policy::CommitSigningKey;
use crate::policy::onepassword::SecretField;

fn key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
}

fn openssh(key: &PrivateKey) -> String {
    key.to_openssh(LineEnding::LF).unwrap().to_string()
}

fn fields(values: &[(&str, &str)]) -> Vec<SecretField> {
    let list: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(i, (label, value))| json!({"id": format!("f{i}"), "label": label, "value": value}))
        .collect();
    serde_json::from_value(Value::Array(list)).unwrap()
}

const PAIRS: [(&str, &str); 3] = [
    ("repository", "example-owner/example-repo"),
    ("tagger_name", "Release Bot"),
    ("tagger_email", "release@example.com"),
];

fn full_with(private: &str, extra: &[(&str, &str)]) -> Vec<SecretField> {
    let mut all = vec![("private_key", private)];
    all.extend_from_slice(&PAIRS);
    all.extend_from_slice(extra);
    fields(&all)
}

fn item_for(repo: &str, private: &PrivateKey) -> super::ReleaseSigningKey {
    let pem = openssh(private);
    let list = fields(&[
        ("private_key", &pem),
        ("repository", repo),
        ("tagger_name", "Release Bot"),
        ("tagger_email", "release@example.com"),
    ]);
    parse_item("item", &list).unwrap()
}

const FULL_EXTRA: [(&str, &str); 3] = [
    ("manifest", "warden-{version}-SHA256SUMS"),
    ("manifest_namespace", "warden-release"),
    ("publish", "true"),
];

#[test]
fn parses_a_full_item() {
    let private = key();
    let item = parse_item("warden", &full_with(&openssh(&private), &FULL_EXTRA)).unwrap();
    assert_eq!(item.repository().as_str(), "example-owner/example-repo");
    assert_eq!(item.tagger_name(), "Release Bot");
    assert_eq!(item.tagger_email(), "release@example.com");
    assert!(item.publish());
    let manifest = item.manifest().unwrap();
    assert_eq!(manifest.namespace(), "warden-release");
    assert_eq!(
        item.fingerprint(),
        private
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
    );
    assert_eq!(item.destination_digest().len(), 64);
}

#[test]
fn parses_a_tag_only_item() {
    let item = parse_item("landfall", &full_with(&openssh(&key()), &[])).unwrap();
    assert!(item.manifest().is_none());
    assert!(!item.publish());
}

#[test]
fn manifest_file_name() {
    let item = parse_item("warden", &full_with(&openssh(&key()), &FULL_EXTRA)).unwrap();
    assert_eq!(
        item.manifest().unwrap().file_name("0.12.0"),
        "warden-0.12.0-SHA256SUMS"
    );
}

fn refused(extra: &[(&str, &str)]) -> String {
    parse_item("warden", &full_with(&openssh(&key()), extra)).unwrap_err()
}

#[test]
fn refuses_manifest_without_version_placeholder() {
    let err = refused(&[
        ("manifest", "SHA256SUMS"),
        ("manifest_namespace", "warden-release"),
    ]);
    assert!(err.contains("manifest"), "{err}");
}

#[test]
fn refuses_manifest_with_slash() {
    for pattern in ["a/{version}", "..\\{version}", "{version}/x"] {
        let err = refused(&[
            ("manifest", pattern),
            ("manifest_namespace", "warden-release"),
        ]);
        assert!(err.contains("manifest"), "{pattern}: {err}");
    }
}

#[test]
fn refuses_manifest_without_namespace() {
    let err = refused(&[("manifest", "warden-{version}-SHA256SUMS")]);
    assert!(err.contains("manifest_namespace"), "{err}");
}

#[test]
fn refuses_namespace_outside_pattern() {
    let long = "a".repeat(65);
    // A blank namespace counts as absent, and a pattern needs one.
    for namespace in ["", "Warden", "-x", "has space", &long] {
        let err = refused(&[
            ("manifest", "warden-{version}-SHA256SUMS"),
            ("manifest_namespace", namespace),
        ]);
        assert!(err.contains("manifest_namespace"), "{namespace}: {err}");
    }
    let err = refused(&[("manifest_namespace", "warden-release")]);
    assert!(err.contains("manifest_namespace"), "{err}");
}

#[test]
fn refuses_non_ed25519_key() {
    let ecdsa = include_str!("../../../tests/fixtures/throwaway-test-only-ecdsa.key");
    let err = parse_item("warden", &full_with(ecdsa, &[])).unwrap_err();
    assert!(err.contains("private_key"), "{err}");
}

#[test]
fn refuses_bad_publish_value() {
    let err = refused(&[("publish", "yes")]);
    assert!(err.contains("publish"), "{err}");
}

#[test]
fn refuses_repeated_field() {
    let mut list = full_with(&openssh(&key()), &[]);
    list.extend(fields(&[("repository", "example-owner/other")]));
    let err = parse_item("warden", &list).unwrap_err();
    assert!(err.contains("more than once"), "{err}");
}

#[test]
fn refuses_missing_and_bad_required_fields() {
    let private = openssh(&key());
    for missing in ["private_key", "repository", "tagger_name", "tagger_email"] {
        let mut list: Vec<(&str, &str)> = vec![("private_key", &private)];
        list.extend_from_slice(&PAIRS);
        list.retain(|(label, _)| *label != missing);
        let err = parse_item("warden", &fields(&list)).unwrap_err();
        assert!(err.contains(missing), "{missing}: {err}");
    }
    for (label, value) in [
        ("repository", "not-a-repo"),
        ("tagger_name", "Bot <x>"),
        ("tagger_name", "two\nlines"),
        ("tagger_email", "no at sign"),
        ("tagger_email", "a@b.c>"),
    ] {
        let mut list: Vec<(&str, &str)> = vec![("private_key", &private)];
        list.extend(PAIRS.iter().filter(|(l, _)| *l != label));
        list.push((label, value));
        let err = parse_item("warden", &fields(&list)).unwrap_err();
        assert!(err.contains(label), "{label}: {err}");
    }
}

#[test]
fn errors_never_quote_values() {
    let private = openssh(&key());
    let secret = "SENTINEL-VALUE-7731";
    let cases: Vec<Vec<SecretField>> = vec![
        fields(&[("private_key", secret)]),
        fields(&[("private_key", &private), ("repository", secret)]),
        full_with(&private, &[("publish", secret)]),
        full_with(
            &private,
            &[("manifest", secret), ("manifest_namespace", "ns")],
        ),
        full_with(
            &private,
            &[("manifest", "a-{version}"), ("manifest_namespace", secret)],
        ),
        full_with(&private, &[("manifest_namespace", secret)]),
        fields(&[
            ("private_key", &private),
            ("repository", "example-owner/example-repo"),
            ("tagger_name", secret),
            ("tagger_email", secret),
        ]),
    ];
    for case in cases {
        let err = parse_item("warden", &case).unwrap_err();
        assert!(!err.contains(secret), "{err}");
        assert!(!err.contains("BEGIN"), "{err}");
    }
}

#[test]
fn digest_changes_with_every_part() {
    let private = openssh(&key());
    let base = parse_item("w", &full_with(&private, &FULL_EXTRA)).unwrap();
    let variants: [&[(&str, &str)]; 3] = [
        &[
            ("publish", "false"),
            ("manifest", "warden-{version}-SHA256SUMS"),
            ("manifest_namespace", "warden-release"),
        ],
        &[
            ("publish", "true"),
            ("manifest", "x-{version}-SHA256SUMS"),
            ("manifest_namespace", "warden-release"),
        ],
        &[
            ("publish", "true"),
            ("manifest", "warden-{version}-SHA256SUMS"),
            ("manifest_namespace", "other"),
        ],
    ];
    for extra in variants {
        let other = parse_item("w", &full_with(&private, extra)).unwrap();
        assert_ne!(base.destination_digest(), other.destination_digest());
    }
    // The key and the tagger are part of it too.
    let other_key = openssh(&key());
    let mut other_name = full_with(&private, &FULL_EXTRA);
    other_name.retain(|f| f.label.as_deref() != Some("tagger_name"));
    other_name.extend(fields(&[("tagger_name", "Other Bot")]));
    let mut other_email = full_with(&private, &FULL_EXTRA);
    other_email.retain(|f| f.label.as_deref() != Some("tagger_email"));
    other_email.extend(fields(&[("tagger_email", "other@example.com")]));
    for list in [full_with(&other_key, &FULL_EXTRA), other_name, other_email] {
        let other = parse_item("w", &list).unwrap();
        assert_ne!(base.destination_digest(), other.destination_digest());
    }
    let same_other_case = {
        let mut list = full_with(&private, &FULL_EXTRA);
        list.retain(|f| f.label.as_deref() != Some("repository"));
        list.extend(fields(&[("repository", "Example-Owner/Example-Repo")]));
        parse_item("w", &list).unwrap()
    };
    assert_eq!(
        base.destination_digest(),
        same_other_case.destination_digest()
    );
}

#[test]
fn debug_never_shows_the_key() {
    let item = item_for("example-owner/example-repo", &key());
    let shown = format!("{item:?}");
    assert!(shown.contains("example-owner/example-repo"));
    assert!(
        !shown.contains("PRIVATE") && !shown.contains("Ed25519"),
        "{shown}"
    );
}

#[test]
fn check_distinct_accepts_separate_keys() {
    let keys = [
        item_for("example-owner/one", &key()),
        item_for("example-owner/two", &key()),
    ];
    let commit = CommitSigningKey::new(key()).unwrap();
    let ca = key();
    check_distinct(&keys, Some(&commit), Some(ca.public_key())).unwrap();
    check_distinct(&keys, None, None).unwrap();
}

#[test]
fn check_distinct_refuses_two_items_for_one_repository() {
    let keys = [
        item_for("Example/Repo", &key()),
        item_for("example/repo", &key()),
    ];
    let err = check_distinct(&keys, None, None).unwrap_err();
    assert!(err.contains("more than one item"), "{err}");
}

#[test]
fn check_distinct_refuses_shared_key() {
    let shared = key();
    let keys = [
        item_for("example-owner/one", &shared),
        item_for("example-owner/two", &shared),
    ];
    let err = check_distinct(&keys, None, None).unwrap_err();
    assert!(err.contains("same key"), "{err}");
}

#[test]
fn check_distinct_refuses_commit_signing_key() {
    let shared = key();
    let keys = [item_for("example-owner/one", &shared)];
    let commit = CommitSigningKey::new(shared).unwrap();
    let err = check_distinct(&keys, Some(&commit), None).unwrap_err();
    assert!(err.contains("commit signing key"), "{err}");
}

#[test]
fn check_distinct_refuses_ca_key() {
    let shared = key();
    let keys = [item_for("example-owner/one", &shared)];
    let err = check_distinct(&keys, None, Some(shared.public_key())).unwrap_err();
    assert!(err.contains("SSH CA"), "{err}");
}

/// A simulated CA outage or an unreadable CA makes the fake backend refuse, as the
/// 1Password backend does, instead of skipping the CA check.
// The fake backend is only built with the `testkit` feature. The crate's own
// dev-dependency on warden-broker enables it for every test build (see Cargo.toml).
#[cfg(feature = "testkit")]
#[tokio::test]
async fn fake_backend_refuses_when_the_ca_cannot_be_read() {
    use crate::policy::{PolicyError, SecretBackend as _};
    use crate::testkit::CaState;
    use crate::testkit::FakeBackend;
    use warden_broker_proto::release::RepoName;

    let repo = RepoName::try_from("example-owner/one".to_owned()).unwrap();
    let fake = FakeBackend::new().with_release_key(item_for("example-owner/one", &key()));
    fake.release_signing(&repo).await.unwrap();

    fake.set_ca_state(CaState::Unusable);
    let err = fake.release_signing(&repo).await.unwrap_err();
    assert!(
        matches!(&err, PolicyError::ReleaseKey(r) if r.contains("SSH CA")),
        "{err:?}"
    );

    fake.set_ca_state(CaState::Absent);
    fake.release_signing(&repo).await.unwrap();

    fake.set_ca_state(CaState::Usable);
    fake.set_ca_outage(Some("down"));
    let err = fake.release_signing(&repo).await.unwrap_err();
    assert!(matches!(err, PolicyError::Unavailable(_)), "{err:?}");
}

/// An unreadable commit signing key makes the fake backend refuse the release keys,
/// as the 1Password backend does, instead of skipping the comparison.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn fake_backend_refuses_when_the_commit_signing_key_cannot_be_read() {
    use crate::policy::{PolicyError, SecretBackend as _};
    use crate::testkit::FakeBackend;
    use warden_broker_proto::release::RepoName;

    let repo = RepoName::try_from("example-owner/one".to_owned()).unwrap();
    let fake = FakeBackend::new().with_release_key(item_for("example-owner/one", &key()));
    fake.release_signing(&repo).await.unwrap();

    // Only ssh-ed25519 commit signing keys are accepted, so an ECDSA one cannot be read.
    let ecdsa = crate::test_keys::random_key(crate::test_keys::P256);
    fake.set_commit_signing_key(Some(ecdsa));
    let err = fake.release_signing(&repo).await.unwrap_err();
    assert!(
        matches!(&err, PolicyError::ReleaseKey(r) if r.contains("commit signing key")),
        "{err:?}"
    );

    fake.set_commit_signing_key(None);
    fake.release_signing(&repo).await.unwrap();
}
