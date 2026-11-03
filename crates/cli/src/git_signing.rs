//! `warden` as git's `gpg.ssh.program`.
//!
//! Git runs this program with `ssh-keygen`'s arguments, on one path and no shell:
//!
//! - to sign: `-Y sign -n git -f <key> [-U] <file>`, which must write the signature
//!   to `<file>.sig` and exit 0. `-U` says `<key>` is a public key, as it always is
//!   here. The broker signs; the key never reaches this machine.
//! - to verify: `-Y find-principals`, `-Y verify`, `-Y check-novalidate` and any other
//!   `-Y` operation, which need no key and go to the real `ssh-keygen` as they are.
//!
//! When the signature cannot be made, this exits non-zero and git stops with the
//! message written here, so `git commit` fails. That is on purpose: nothing here
//! makes a commit without a signature look like one with it.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ssh_key::{PublicKey, SshSig};
use warden_broker_proto::commit_signing::{MAX_PAYLOAD_BYTES, NO_ACTIVE_GRANT, SignCommitRequest};

use crate::client::{CallError, Client};
use crate::config;

/// Exit code when the agent has no active grant: as for `warden ssh`.
const EXIT_NO_GRANT: u8 = 5;

/// Longest public key file read, in bytes.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// What git asks of the program.
#[derive(Debug, PartialEq, Eq)]
enum Call<'a> {
    /// Sign `file` in `namespace`.
    Sign {
        namespace: &'a str,
        key: &'a Path,
        file: &'a Path,
    },
    /// Anything else `ssh-keygen -Y` does: none of it uses a private key.
    PassThrough,
}

/// Whether the command line is git's, not a person's: `warden` has no `-Y` of its own.
pub fn is_program_call(args: &[OsString]) -> bool {
    args.first().is_some_and(|first| first == "-Y")
}

/// What `args` asks for.
///
/// # Errors
/// A signing call in any shape git does not use: rather than guess what was meant,
/// and never by passing it on, since `ssh-keygen` would look for a private key.
fn parse(args: &[OsString]) -> Result<Call<'_>> {
    let as_strs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    let sign = OsStr::new("sign");
    if as_strs.get(1) != Some(&sign) {
        return Ok(Call::PassThrough);
    }
    let (namespace, key, file) = match as_strs[2..] {
        [n, namespace, f, key, u, file] if n == "-n" && f == "-f" && u == "-U" => {
            (namespace, key, file)
        }
        [n, namespace, f, key, file] if n == "-n" && f == "-f" => (namespace, key, file),
        _ => bail!("unexpected arguments to -Y sign; this program signs as git calls it"),
    };
    Ok(Call::Sign {
        namespace: namespace
            .to_str()
            .ok_or_else(|| anyhow!("the namespace is not valid UTF-8"))?,
        key: Path::new(key),
        file: Path::new(file),
    })
}

/// Do what git asked and give git its exit code.
pub async fn run(args: &[OsString]) -> ExitCode {
    let failed = match parse(args) {
        Ok(Call::PassThrough) => {
            // Only comes back if `ssh-keygen` could not be started.
            let error = Command::new("ssh-keygen").args(args).exec();
            Failure::from(anyhow!("cannot run ssh-keygen: {error}"))
        }
        Ok(Call::Sign {
            namespace,
            key,
            file,
        }) => match sign(namespace, key, file).await {
            Ok(()) => return ExitCode::SUCCESS,
            Err(failure) => failure,
        },
        Err(e) => Failure::from(e),
    };
    // Git shows this when the signature fails, and shows nothing written here when
    // it succeeds, so there is no place to say anything but failures.
    eprintln!("warden: {}", failed.message);
    ExitCode::from(failed.code)
}

/// Why no signature was written.
struct Failure {
    code: u8,
    message: String,
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        Self {
            code: 1,
            message: format!("cannot sign this commit: {e:#}"),
        }
    }
}

impl Failure {
    /// What to say about `e` from the broker, as `agent`.
    fn from_call(e: &CallError, agent: &str) -> Self {
        let reason = e.to_string();
        if reason.contains(NO_ACTIVE_GRANT) {
            return Self {
                code: EXIT_NO_GRANT,
                message: format!(
                    "cannot sign this commit: agent {agent} has no active commit signing grant. \
                     Ask the owner for one with: warden request signing --goal \"<why this agent \
                     commits>\""
                ),
            };
        }
        let message = match e {
            CallError::Unavailable(_) => format!(
                "cannot sign this commit: {reason}. Signing needs the broker: `warden doctor` \
                 checks the connection; commit again once the broker answers"
            ),
            _ => format!("cannot sign this commit: {reason}"),
        };
        Self { code: 1, message }
    }
}

/// Have the broker sign `file`, check what comes back, write `<file>.sig`.
async fn sign(namespace: &str, key: &Path, file: &Path) -> Result<(), Failure> {
    let payload = read_payload(file)?;
    let expected = read_public_key(key)?;
    let config = config::load()?;
    let client = Client::for_config(&config)?;
    let request = SignCommitRequest {
        namespace: namespace.to_owned(),
        payload_b64: STANDARD.encode(&payload),
    };
    let signed = client
        .sign_commit(&request)
        .await
        .map_err(|e| Failure::from_call(&e, config.agent.as_str()))?;
    check_signature(&signed.signature, &expected, namespace, &payload)?;
    write_signature(file, &signed.signature)?;
    Ok(())
}

/// The bytes git wants signed. Larger than the broker takes is refused here.
fn read_payload(file: &Path) -> Result<Vec<u8>> {
    let limit = u64::try_from(MAX_PAYLOAD_BYTES).context("the size limit is out of range")?;
    let mut payload = Vec::new();
    fs::File::open(file)
        .and_then(|f| f.take(limit + 1).read_to_end(&mut payload))
        .with_context(|| format!("cannot read {}", file.display()))?;
    ensure!(
        payload.len() <= MAX_PAYLOAD_BYTES,
        "the commit is too large to sign"
    );
    Ok(payload)
}

/// The public key git was told to sign with: `user.signingkey`, which git hands over
/// as a file.
fn read_public_key(path: &Path) -> Result<PublicKey> {
    let mut text = String::new();
    fs::File::open(path)
        .and_then(|f| f.take(MAX_KEY_FILE_BYTES).read_to_string(&mut text))
        .with_context(|| format!("cannot read the key {}", path.display()))?;
    PublicKey::from_openssh(text.trim())
        .map_err(|_| anyhow!("user.signingkey is not a public key; run `warden setup git`"))
}

/// Whether `signature` is `expected`'s over `payload` in `namespace`. A broker signing
/// with another key than the one configured here would give a commit that does not
/// verify, and it is better to stop now than to find out on the pull request.
fn check_signature(
    signature: &str,
    expected: &PublicKey,
    namespace: &str,
    payload: &[u8],
) -> Result<()> {
    let parsed: SshSig = signature
        .parse()
        .map_err(|_| anyhow!("the broker sent an unreadable signature"))?;
    expected.verify(namespace, payload, &parsed).map_err(|_| {
        anyhow!(
            "the broker signs with another key than user.signingkey; it may have changed. Run \
             `warden setup git`"
        )
    })
}

/// Where git looks for the signature of `file`.
fn signature_path(file: &Path) -> PathBuf {
    let mut path = file.as_os_str().to_owned();
    path.push(".sig");
    PathBuf::from(path)
}

/// Write `signature` where git looks for it, refusing whatever is there already: git
/// makes a new name for each signature, and removes the file afterwards.
fn write_signature(file: &Path, signature: &str) -> Result<()> {
    let path = signature_path(file);
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| match e.kind() {
            ErrorKind::AlreadyExists => anyhow!("{} already exists", path.display()),
            _ => anyhow!("cannot write {}: {e}", path.display()),
        })?;
    out.write_all(signature.as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::Path;

    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    use super::{
        Call, EXIT_NO_GRANT, Failure, check_signature, is_program_call, parse, read_public_key,
        signature_path, write_signature,
    };
    use crate::client::CallError;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn only_a_y_option_first_is_gits() {
        assert!(is_program_call(&args(&["-Y", "sign"])));
        assert!(!is_program_call(&args(&["status"])));
        assert!(!is_program_call(&args(&["ssh", "-Y"])));
        assert!(!is_program_call(&[]));
    }

    #[test]
    fn signing_takes_the_two_shapes_git_uses() {
        let plain = args(&["-Y", "sign", "-n", "git", "-f", "key.pub", "buffer"]);
        let expected = Call::Sign {
            namespace: "git",
            key: Path::new("key.pub"),
            file: Path::new("buffer"),
        };
        assert_eq!(parse(&plain).unwrap(), expected);
        let literal = args(&["-Y", "sign", "-n", "git", "-f", "key.pub", "-U", "buffer"]);
        assert_eq!(parse(&literal).unwrap(), expected);
    }

    #[test]
    fn signing_in_any_other_shape_is_refused_not_passed_on() {
        for call in [
            args(&["-Y", "sign"]),
            args(&["-Y", "sign", "-f", "k", "-n", "git", "buffer"]),
            args(&["-Y", "sign", "-n", "git", "-f", "k"]),
            args(&["-Y", "sign", "-n", "git", "-f", "k", "-O", "x", "buffer"]),
            args(&["-Y", "sign", "-n", "git", "-f", "k", "buffer", "more"]),
        ] {
            assert!(parse(&call).is_err(), "{call:?}");
        }
    }

    #[test]
    fn everything_else_goes_to_ssh_keygen() {
        for call in [
            args(&["-Y", "verify", "-n", "git", "-f", "a", "-I", "p", "-s", "s"]),
            args(&["-Y", "find-principals", "-f", "a", "-s", "s"]),
            args(&["-Y", "check-novalidate", "-n", "git", "-s", "s"]),
            args(&["-Y"]),
        ] {
            assert_eq!(parse(&call).unwrap(), Call::PassThrough, "{call:?}");
        }
    }

    #[test]
    fn no_grant_says_how_to_ask() {
        let e = CallError::Refused(
            "broker refused (403): no active commit signing grant for this agent".to_owned(),
        );
        let failure = Failure::from_call(&e, "build-agent");
        assert_eq!(failure.code, EXIT_NO_GRANT);
        assert!(failure.message.contains("warden request signing"));
        assert!(failure.message.contains("build-agent"));
    }

    #[test]
    fn an_unreachable_broker_says_what_is_missing_and_offers_no_way_around() {
        let e = CallError::Unavailable("cannot reach the broker: refused".to_owned());
        let failure = Failure::from_call(&e, "build-agent");
        assert_eq!(failure.code, 1);
        assert!(failure.message.contains("cannot reach the broker"));
        assert!(!failure.message.contains("no-gpg-sign"));
    }

    fn key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    fn signature(key: &PrivateKey, namespace: &str, payload: &[u8]) -> String {
        key.sign(namespace, HashAlg::Sha512, payload)
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap()
    }

    #[test]
    fn a_signature_must_be_the_configured_keys_over_this_payload() {
        let (ours, other) = (key(), key());
        let good = signature(&ours, "git", b"payload");
        assert!(check_signature(&good, ours.public_key(), "git", b"payload").is_ok());
        assert!(check_signature(&good, other.public_key(), "git", b"payload").is_err());
        assert!(check_signature(&good, ours.public_key(), "git", b"other").is_err());
        assert!(check_signature(&good, ours.public_key(), "file", b"payload").is_err());
        assert!(check_signature("garbage", ours.public_key(), "git", b"payload").is_err());
    }

    #[test]
    fn the_signature_goes_next_to_the_file_and_never_over_anything() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("buffer");
        write_signature(&file, "sig\n").unwrap();
        let written = signature_path(&file);
        assert_eq!(written, dir.path().join("buffer.sig"));
        assert_eq!(std::fs::read_to_string(&written).unwrap(), "sig\n");
        assert!(write_signature(&file, "other\n").is_err());
        assert_eq!(std::fs::read_to_string(&written).unwrap(), "sig\n");
    }

    #[test]
    fn a_private_key_is_not_a_signing_key_here() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let key = key();
        std::fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        assert!(read_public_key(&path).is_err());
        std::fs::write(&path, key.public_key().to_openssh().unwrap()).unwrap();
        assert!(read_public_key(&path).is_ok());
    }
}
