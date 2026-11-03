//! End to end: real `git` calling the real `warden` binary as its signing program,
//! against an in-process broker holding a key generated for the test. Git runs in a
//! throwaway `HOME`, with its global configuration in that directory and the system
//! one off, so nothing here reads or changes the configuration of whoever runs it.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use sha2::{Digest as _, Sha256};
use ssh_key::rand_core::OsRng;
use tempfile::TempDir;
use warden_broker::testkit::{CapturingNotifier, TestBroker};
use warden_broker_proto::Window;

const AGENT: &str = "build-agent";
const EMAIL: &str = "build-agent@example.com";

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A throwaway home with a logged-in CLI and a git repository.
struct Machine {
    root: TempDir,
    key: String,
}

impl Machine {
    fn new(server: &url::Url, key: String) -> Self {
        let root = tempfile::Builder::new()
            .prefix("wdg")
            .tempdir_in("/tmp")
            .unwrap();
        for sub in ["home", "config/warden", "state", "tmp", "repo"] {
            fs::create_dir_all(root.path().join(sub)).unwrap();
        }
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join("config/warden/config.toml"))
            .unwrap();
        write!(f, "server = \"{server}\"\nagent = \"{AGENT}\"\n").unwrap();
        let machine = Self { root, key };
        machine.git_ok(&["init", "-q"]);
        machine
    }

    fn repo(&self) -> PathBuf {
        self.root.path().join("repo")
    }

    fn env(&self, cmd: &mut Command) {
        cmd.env("HOME", self.root.path().join("home"))
            .env("GIT_CONFIG_GLOBAL", self.root.path().join("home/gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("TMPDIR", self.root.path().join("tmp"))
            .env("WARDEN_AGENT_KEY", &self.key)
            .env("GIT_AUTHOR_NAME", AGENT)
            .env("GIT_AUTHOR_EMAIL", EMAIL)
            .env("GIT_COMMITTER_NAME", AGENT)
            .env("GIT_COMMITTER_EMAIL", EMAIL)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .current_dir(self.repo())
            .stdin(Stdio::null());
    }

    fn warden(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_warden"));
        self.env(&mut cmd);
        cmd
    }

    fn git(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new("git");
        self.env(&mut cmd);
        cmd.args(args).output().unwrap()
    }

    fn git_ok(&self, args: &[&str]) -> String {
        let out = self.git(args);
        assert!(out.status.success(), "git {args:?}: {}", text(&out.stderr));
        text(&out.stdout).trim().to_owned()
    }

    fn setup(&self) -> Output {
        self.warden().args(["setup", "git"]).output().unwrap()
    }

    fn commit(&self, message: &str) -> Output {
        self.git(&["commit", "--allow-empty", "-m", message])
    }

    /// Everything the machine holds containing `needle`.
    fn files_containing(&self, needle: &[u8]) -> Vec<PathBuf> {
        fn walk(dir: &Path, needle: &[u8], hits: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                let kind = entry.file_type().unwrap();
                if kind.is_dir() {
                    walk(&path, needle, hits);
                } else if kind.is_file()
                    && fs::read(&path)
                        .unwrap()
                        .windows(needle.len())
                        .any(|w| w == needle)
                {
                    hits.push(path);
                }
            }
        }
        let mut hits = Vec::new();
        walk(self.root.path(), needle, &mut hits);
        hits
    }

    fn spawn_request(&self) -> Child {
        self.warden()
            .args(["request", "signing", "--goal", "sign my commits"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }
}

struct Setup {
    broker: TestBroker,
    machine: Machine,
}

async fn setup() -> Setup {
    let broker = TestBroker::new().await;
    let key = broker.add_agent(AGENT).await;
    let urls = broker.spawn_behind_serve().await;
    let machine = Machine::new(&urls.api, key);
    Setup { broker, machine }
}

/// `warden request signing`, approved with a passkey as the owner would.
async fn get_grant(s: &Setup) -> Output {
    let child = s.machine.spawn_request();
    let token = CapturingNotifier::token(&s.broker.capture.next().await);
    let approved = s.broker.approve(&token, Window::D30).await;
    assert!(approved.status.is_success(), "{}", approved.body);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    out
}

fn audit_entries(s: &Setup, kind: &str) -> Vec<serde_json::Value> {
    fs::read_to_string(s.broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
        .filter(|event| event["type"] == kind)
        .collect()
}

/// A file naming the broker's key as allowed to sign for the test's email.
fn allowed_signers(s: &Setup) -> PathBuf {
    let path = s.machine.root.path().join("allowed_signers");
    let public = s.broker.backend.commit_signing_public_key();
    fs::write(
        &path,
        format!(
            "{EMAIL} namespaces=\"git\" {}\n",
            public.to_openssh().unwrap()
        ),
    )
    .unwrap();
    path
}

/// A commit object without its signature header, which is what was signed.
fn without_signature(object: &[u8]) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut in_signature = false;
    for line in object.split_inclusive(|b| *b == b'\n') {
        in_signature = line.starts_with(b"gpgsig ") || (in_signature && line.starts_with(b" "));
        if !in_signature {
            kept.extend_from_slice(line);
        }
    }
    kept
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_git_commit_is_signed_through_the_broker_and_verifies() {
    let s = setup().await;
    get_grant(&s).await;
    let set_up = s.machine.setup();
    assert_eq!(set_up.status.code(), Some(0), "{}", text(&set_up.stderr));
    let said = text(&set_up.stdout);
    assert!(said.contains("not that anyone reviewed"), "{said}");

    let out = s.machine.commit("signed by warden");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let head = s.machine.git_ok(&["rev-parse", "HEAD"]);

    // The object holds an SSH signature.
    let object = s.machine.git_ok(&["cat-file", "commit", "HEAD"]);
    assert!(
        object.contains("gpgsig -----BEGIN SSH SIGNATURE-----"),
        "{object}"
    );

    // It verifies with git, going through this program to the real ssh-keygen: the
    // find-principals and verify calls.
    let allowed = allowed_signers(&s);
    s.machine.git_ok(&[
        "config",
        "gpg.ssh.allowedSignersFile",
        allowed.to_str().unwrap(),
    ]);
    let verified = s.machine.git(&["verify-commit", "--raw", "HEAD"]);
    assert!(
        verified.status.success(),
        "{}{}",
        text(&verified.stdout),
        text(&verified.stderr)
    );
    let shown = s.machine.git_ok(&["log", "-1", "--format=%G?|%GS"]);
    assert_eq!(shown, format!("G|{EMAIL}"));

    // With no signer listed, git asks for check-novalidate, which still works: the
    // signature is good, the key is just not trusted.
    fs::write(&allowed, "").unwrap();
    let unknown = s.machine.git_ok(&["log", "-1", "--format=%G?"]);
    assert_eq!(unknown, "U");

    // The audit log names the very commit git made, with its fields.
    let signed = audit_entries(&s, "commit_signed");
    assert_eq!(signed.len(), 1);
    assert_eq!(signed[0]["commit"], head.as_str());
    // What was signed can be told from the commit itself, whatever its id.
    let object = s.machine.git(&["cat-file", "commit", "HEAD"]).stdout;
    assert_eq!(
        signed[0]["payload_sha256"],
        hex::encode(Sha256::digest(without_signature(&object)))
    );
    assert_eq!(signed[0]["agent"], AGENT);
    assert_eq!(
        signed[0]["tree"],
        s.machine.git_ok(&["rev-parse", "HEAD^{tree}"]).as_str()
    );
    assert!(signed[0]["author"].as_str().unwrap().contains(EMAIL));

    // A second commit has a parent, on record too.
    assert!(s.machine.commit("second").status.success());
    let signed = audit_entries(&s, "commit_signed");
    assert_eq!(signed[1]["parents"], serde_json::json!([head]));
    assert_eq!(
        signed[1]["commit"],
        s.machine.git_ok(&["rev-parse", "HEAD"]).as_str()
    );

    // The key never reached this machine.
    let private = s.broker.backend.commit_signing_private_key();
    let pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
    for line in pem.lines().filter(|l| !l.starts_with("-----")) {
        assert_eq!(
            s.machine.files_containing(line.as_bytes()),
            [] as [PathBuf; 0]
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sha256_repository_gets_the_right_header_and_id() {
    let s = setup().await;
    get_grant(&s).await;
    assert_eq!(s.machine.setup().status.code(), Some(0));
    fs::remove_dir_all(s.machine.repo().join(".git")).unwrap();
    s.machine.git_ok(&["init", "-q", "--object-format=sha256"]);
    let out = s.machine.commit("sha-256");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let object = s.machine.git_ok(&["cat-file", "commit", "HEAD"]);
    assert!(object.contains("gpgsig-sha256 -----BEGIN"), "{object}");
    let signed = audit_entries(&s, "commit_signed");
    assert_eq!(
        signed[0]["commit"],
        s.machine.git_ok(&["rev-parse", "HEAD"]).as_str()
    );
}

/// What a failed commit must look like: git stops, nothing was made, and the message
/// says why and how to ask. It offers no way to commit without a signature.
fn assert_commit_failed(s: &Setup, out: &Output, says: &str) {
    assert!(!out.status.success(), "the commit went through");
    let stderr = text(&out.stderr);
    assert!(stderr.contains(says), "{stderr}");
    assert!(!stderr.contains("no-gpg-sign"), "{stderr}");
    assert!(
        !s.machine
            .git(&["rev-parse", "--verify", "-q", "HEAD"])
            .status
            .success(),
        "a commit was made"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_grant_fails_the_commit_and_says_how_to_ask() {
    let s = setup().await;
    get_grant(&s).await;
    assert_eq!(s.machine.setup().status.code(), Some(0));
    s.broker.clock.advance(30 * 86_400);
    let out = s.machine.commit("not signed");
    assert_commit_failed(&s, &out, "warden request signing");
    assert_eq!(audit_entries(&s, "commit_signing_refused").len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_grant_fails_the_next_commit() {
    let s = setup().await;
    let granted = text(&get_grant(&s).await.stdout);
    assert_eq!(s.machine.setup().status.code(), Some(0));
    let grant = granted
        .strip_prefix("approved: grant ")
        .and_then(|r| r.split_once(" until "))
        .unwrap()
        .0
        .to_owned();
    assert!(s.machine.commit("before").status.success());
    let revoke = s
        .machine
        .warden()
        .args(["revoke", &grant])
        .output()
        .unwrap();
    assert_eq!(revoke.status.code(), Some(0), "{}", text(&revoke.stderr));
    let out = s.machine.commit("after");
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("warden request signing"));
    assert_eq!(s.machine.git_ok(&["log", "--format=%s"]), "before");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_broker_fails_the_commit_and_says_so() {
    let s = setup().await;
    get_grant(&s).await;
    assert_eq!(s.machine.setup().status.code(), Some(0));
    // Port 9 on loopback: nothing listens, and the connection is refused at once.
    fs::write(
        s.machine.root.path().join("config/warden/config.toml"),
        format!("server = \"http://127.0.0.1:9/\"\nagent = \"{AGENT}\"\n"),
    )
    .unwrap();
    let out = s.machine.commit("not signed");
    assert_commit_failed(&s, &out, "cannot reach the broker");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotated_key_fails_the_commit_until_setup_runs_again() {
    let s = setup().await;
    get_grant(&s).await;
    assert_eq!(s.machine.setup().status.code(), Some(0));
    s.broker.backend.set_commit_signing_key(Some(
        ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap(),
    ));
    let out = s.machine.commit("old key");
    assert_commit_failed(&s, &out, "key changed");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_signing_program_refuses_a_tag_object_and_another_namespace() {
    let s = setup().await;
    get_grant(&s).await;
    assert_eq!(s.machine.setup().status.code(), Some(0));
    let key_file = s.machine.root.path().join("signing.pub");
    let public = s.broker.backend.commit_signing_public_key();
    fs::write(&key_file, public.to_openssh().unwrap()).unwrap();
    let buffer = s.machine.root.path().join("buffer");
    fs::write(
        &buffer,
        "object 1111111111111111111111111111111111111111\ntype commit\ntag v1\n\
         tagger a <a@example.com> 1 +0000\n\nrelease\n",
    )
    .unwrap();
    let run = |namespace: &str| {
        s.machine
            .warden()
            .args(["-Y", "sign", "-n", namespace, "-f"])
            .arg(&key_file)
            .arg(&buffer)
            .output()
            .unwrap()
    };
    let tag = run("git");
    assert!(!tag.status.success());
    assert!(
        text(&tag.stderr).contains("tag object"),
        "{}",
        text(&tag.stderr)
    );
    assert!(!buffer.with_extension("sig").exists());
    let commit = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
        author a <a@example.com> 1 +0000\ncommitter a <a@example.com> 1 +0000\n\nm\n";
    fs::write(&buffer, commit).unwrap();
    let other = run("file");
    assert!(!other.status.success());
    assert!(
        text(&other.stderr).contains("namespace"),
        "{}",
        text(&other.stderr)
    );
    assert_eq!(audit_entries(&s, "commit_signing_refused").len(), 2);
    assert_eq!(audit_entries(&s, "commit_signed").len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_changes_only_the_throwaway_config_and_doctor_reads_it() {
    let s = setup().await;
    let doctor = |machine: &Machine| {
        let out = machine.warden().arg("doctor").output().unwrap();
        (out.status.code(), text(&out.stdout))
    };
    let (_, before) = doctor(&s.machine);
    assert!(
        before.contains("Git does not sign through warden"),
        "{before}"
    );

    get_grant(&s).await;
    assert_eq!(s.machine.setup().status.code(), Some(0));
    let config = fs::read_to_string(s.machine.root.path().join("home/gitconfig")).unwrap();
    let public = s.broker.backend.commit_signing_public_key();
    assert!(config.contains(&public.to_openssh().unwrap()), "{config}");
    assert_eq!(s.machine.git_ok(&["config", "gpg.format"]), "ssh");
    assert_eq!(s.machine.git_ok(&["config", "commit.gpgsign"]), "true");
    assert_eq!(
        s.machine
            .git_ok(&["config", "user.signingkey"])
            .split_once("::")
            .unwrap()
            .0,
        "key"
    );
    let program = s.machine.git_ok(&["config", "gpg.ssh.program"]);
    assert!(Path::new(&program).is_absolute(), "{program}");

    let (_, granted) = doctor(&s.machine);
    assert!(granted.contains("Git signs through warden"), "{granted}");

    // --local leaves the global file alone.
    fs::remove_file(s.machine.root.path().join("home/gitconfig")).unwrap();
    let local = s
        .machine
        .warden()
        .args(["setup", "git", "--local"])
        .output()
        .unwrap();
    assert_eq!(local.status.code(), Some(0), "{}", text(&local.stderr));
    assert!(!s.machine.root.path().join("home/gitconfig").exists());
    assert_eq!(
        s.machine.git_ok(&["config", "--local", "gpg.format"]),
        "ssh"
    );

    s.broker.clock.advance(30 * 86_400);
    let (code, no_grant) = doctor(&s.machine);
    assert_eq!(code, Some(1), "{no_grant}");
    assert!(
        no_grant.contains("no active commit signing grant"),
        "{no_grant}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_leaves_git_alone_without_a_grant() {
    let s = setup().await;
    let out = s.machine.setup();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("warden request signing"),
        "{}",
        text(&out.stderr)
    );
    assert!(!s.machine.root.path().join("home/gitconfig").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_leaves_git_alone_when_the_broker_has_no_key() {
    let s = setup().await;
    get_grant(&s).await;
    s.broker.backend.set_commit_signing_key(None);
    let out = s.machine.setup();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("commit signing is not configured"),
        "{}",
        text(&out.stderr)
    );
    assert!(!s.machine.root.path().join("home/gitconfig").exists());
}
