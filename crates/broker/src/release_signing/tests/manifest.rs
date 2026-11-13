use std::fmt::Write as _;
use std::process::Command;

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};

use crate::policy::ReleaseSigningKey;
use crate::release_signing::{ManifestError, check_manifest, sign_manifest};

const NAME: &str = "warden-1.2.3-SHA256SUMS";
const VERSION: &str = "1.2.3";
const DIGEST_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DIGEST_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn check(bytes: &str) -> Result<(), ManifestError> {
    check_manifest(NAME, VERSION, NAME, bytes.as_bytes())
}

fn warden() -> String {
    format!(
        "{DIGEST_A}  warden-1.2.3-x86_64-unknown-linux-gnu.tar.gz\n{DIGEST_B}  ghcr.io/example-owner/example-repo:1.2.3\n"
    )
}

#[test]
fn accepts_warden_manifest() {
    assert_eq!(check(&warden()), Ok(()));
}

#[test]
fn accepts_a_single_file_line() {
    assert_eq!(check(&format!("{DIGEST_A}  a_b-c+d_1.2.3.x\n")), Ok(()));
}

#[test]
fn accepts_file_names_that_carry_the_version() {
    for good in [
        "1.2.3",
        "warden-1.2.3",
        "warden-1.2.3.tar.gz",
        "warden_1.2.3_amd64.deb",
        "warden-1.2.3-1.x86_64.rpm",
        "warden-server-1.2.3-aarch64-apple-darwin.tar.gz",
        "x-0.0.1-1.2.3-y",
    ] {
        assert_eq!(check(&format!("{DIGEST_A}  {good}\n")), Ok(()), "{good}");
    }
    assert_eq!(
        check_manifest(
            "x-1.2.3-rc.1-SHA256SUMS",
            "1.2.3-rc.1",
            "x-1.2.3-rc.1-SHA256SUMS",
            format!("{DIGEST_A}  x-1.2.3-rc.1-linux.tar.gz\n").as_bytes()
        ),
        Ok(())
    );
}

#[test]
fn refuses_file_names_without_the_version() {
    for bad in [
        "warden.tar.gz",
        "warden-1.2.4-x86_64.tar.gz",
        "warden-11.2.3.tar.gz",
        "warden-1.2.30.tar.gz",
        "warden-1.2.3.4.tar.gz",
        "warden.1.2.3.tar.gz",
        "warden-1.2.3+build.tar.gz",
        "warden1.2.3.tar.gz",
    ] {
        assert_eq!(
            check(&format!("{DIGEST_A}  {bad}\n")),
            Err(ManifestError::BadName { line: 1 }),
            "{bad}"
        );
    }
    // A later line is checked the same way.
    assert_eq!(
        check(&format!(
            "{DIGEST_A}  warden-1.2.3.tar.gz\n{DIGEST_B}  warden-0.9.0.tar.gz\n"
        )),
        Err(ManifestError::BadName { line: 2 })
    );
}

#[test]
fn refuses_wrong_name() {
    assert_eq!(
        check_manifest(NAME, VERSION, "other-SHA256SUMS", warden().as_bytes()),
        Err(ManifestError::WrongName)
    );
}

#[test]
fn refuses_oversized() {
    let line = format!("{DIGEST_A}  a\n");
    let many = line.repeat(65_536 / line.len() + 1);
    assert!(many.len() > 65_536);
    assert_eq!(check(&many), Err(ManifestError::TooLarge));
    // A line of names that are unique would pass but for the size.
    let mut exact = String::new();
    let mut i = 0_u32;
    while exact.len() + 80 <= 65_536 {
        writeln!(exact, "{DIGEST_A}  f{i}-1.2.3").unwrap();
        i += 1;
    }
    assert!(exact.len() <= 65_536);
    assert_eq!(check(&exact), Ok(()));
}

#[test]
fn refuses_uppercase_hex() {
    let upper = DIGEST_A.to_uppercase();
    assert_eq!(
        check(&format!("{upper}  a\n")),
        Err(ManifestError::BadLine { line: 1 })
    );
}

#[test]
fn refuses_short_and_long_digests() {
    assert_eq!(
        check(&format!("{}  a\n", &DIGEST_A[1..])),
        Err(ManifestError::BadLine { line: 1 })
    );
    assert_eq!(
        check(&format!("{DIGEST_A}0  a\n")),
        Err(ManifestError::BadLine { line: 1 })
    );
}

#[test]
fn refuses_single_space() {
    assert_eq!(
        check(&format!("{DIGEST_A} a\n")),
        Err(ManifestError::BadLine { line: 1 })
    );
}

#[test]
fn refuses_three_spaces_and_binary_marker() {
    assert_eq!(
        check(&format!("{DIGEST_A}   a\n")),
        Err(ManifestError::BadName { line: 1 })
    );
    assert_eq!(
        check(&format!("{DIGEST_A} *a\n")),
        Err(ManifestError::BadLine { line: 1 })
    );
}

#[test]
fn refuses_path_in_name() {
    for bad in [
        "../x",
        "a/b",
        "/etc/passwd",
        "a//b:1.2.3",
        "./x:1.2.3",
        "a/../b:1.2.3",
    ] {
        assert_eq!(
            check(&format!("{DIGEST_A}  {bad}\n")),
            Err(ManifestError::BadName { line: 1 }),
            "{bad}"
        );
    }
}

#[test]
fn refuses_dot_names_and_odd_characters() {
    for bad in [".", "..", "a b", "a\tb", "a:b", "é", "a*"] {
        assert_eq!(
            check(&format!("{DIGEST_A}  {bad}\n")),
            Err(ManifestError::BadName { line: 1 }),
            "{bad:?}"
        );
    }
}

#[test]
fn refuses_image_with_other_tag() {
    for bad in [
        "ghcr.io/example-owner/example-repo:1.2.4",
        "ghcr.io/example-owner/example-repo:latest",
        "ghcr.io/example-owner/example-repo:",
        "ghcr.io/example-owner/example-repo",
        "ghcr.io/Example-Owner/example-repo:1.2.3",
        "ghcr.io/example-owner/example-repo:1.2.3:1.2.3",
    ] {
        assert_eq!(
            check(&format!("{DIGEST_A}  {bad}\n")),
            Err(ManifestError::BadName { line: 1 }),
            "{bad}"
        );
    }
}

#[test]
fn refuses_duplicate_name() {
    assert_eq!(
        check(&format!(
            "{DIGEST_A}  a-1.2.3\n{DIGEST_B}  b-1.2.3\n{DIGEST_B}  a-1.2.3\n"
        )),
        Err(ManifestError::DuplicateName { line: 3 })
    );
}

#[test]
fn refuses_empty() {
    assert_eq!(check(""), Err(ManifestError::Empty));
    assert_eq!(check("\n"), Err(ManifestError::BadLine { line: 1 }));
}

#[test]
fn refuses_blank_lines() {
    assert_eq!(
        check(&format!("{DIGEST_A}  a-1.2.3\n\n")),
        Err(ManifestError::BadLine { line: 2 })
    );
}

#[test]
fn refuses_missing_final_newline() {
    assert_eq!(
        check(&format!("{DIGEST_A}  a")),
        Err(ManifestError::MissingFinalNewline)
    );
}

#[test]
fn refuses_crlf() {
    assert_eq!(
        check(&format!("{DIGEST_A}  a\r\n")),
        Err(ManifestError::CarriageReturn)
    );
}

#[test]
fn refuses_text_that_is_not_utf8() {
    assert_eq!(
        check_manifest(NAME, VERSION, NAME, b"\xff\xfe\n"),
        Err(ManifestError::NotUtf8)
    );
}

#[test]
fn error_messages_never_quote_the_manifest() {
    let secret = "SECRET-CONTENT";
    let err = check(&format!("{DIGEST_A}  {secret}/x\n")).unwrap_err();
    assert!(!err.to_string().contains(secret));
}

#[test]
fn the_signature_verifies_with_ssh_keygen() {
    let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public = private.public_key().to_openssh().unwrap();
    let key = ReleaseSigningKey::for_tests("example-owner/example-repo", private, None, false);
    let bytes = warden();
    let signature = sign_manifest(&key, "warden-release", bytes.as_bytes()).unwrap();
    assert!(signature.starts_with("-----BEGIN SSH SIGNATURE-----\n"));
    assert!(!signature.contains('\r'));

    let dir = tempfile::tempdir().unwrap();
    let signers = dir.path().join("allowed-signers");
    std::fs::write(
        &signers,
        format!("release@example.com namespaces=\"warden-release\" {public}\n"),
    )
    .unwrap();
    let sig = dir.path().join("manifest.sig");
    std::fs::write(&sig, &signature).unwrap();
    let verify = |namespace: &str, data: &str| {
        use std::io::Write as _;
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-f"])
            .arg(&signers)
            .args(["-I", "release@example.com", "-n", namespace, "-s"])
            .arg(&sig)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(data.as_bytes())
            .unwrap();
        child.wait().unwrap().success()
    };
    assert!(verify("warden-release", &bytes));
    assert!(!verify("git", &bytes));
    assert!(!verify("warden-release", "changed\n"));
}
