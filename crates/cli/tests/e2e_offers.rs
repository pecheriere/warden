//! End to end: `warden list` and `warden prime` from the real `warden` binary,
//! against an in-process broker (behind a stand-in for Tailscale Serve) whose
//! GitHub is a local HTTPS server. Git runs with its global configuration in a
//! throwaway file and the system one off, so nothing here reads the
//! configuration of whoever runs it.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tempfile::TempDir;
use warden_broker::github_app::GithubApi;
use warden_broker::policy::Listing;
use warden_broker::testkit::github_app::token_answer;
use warden_broker::testkit::upstream::HttpsUpstream;
use warden_broker::testkit::{FakeBackend, TestBroker, github_app_key};

const AGENT: &str = "build-agent";
const REPO: &str = "example-org/example-repo";

struct Setup {
    // Held so the broker and the fake GitHub outlive every command.
    _broker: TestBroker,
    upstream: HttpsUpstream,
    /// Everything the CLI and git write, under one throwaway root.
    root: TempDir,
    key: String,
}

/// A broker with one target per listing, `home-api` listed in full, commit
/// signing on (the fake backend's default), and an agent App that GitHub says
/// covers [`REPO`].
async fn setup() -> Setup {
    let upstream = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    );
    let broker = TestBroker::with_github_api(api).await;
    broker.clock.set(now());
    broker.backend.set_github_app(Some(github_app_key().0));
    for (name, host, listing) in [
        ("web-01", "web-01.example.internal", Listing::Full),
        ("switch-01", "switch-01.example.internal", Listing::Name),
        // The fake backend's own target, now hidden.
        ("pi", "pi.example.internal", Listing::Hidden),
        ("db-01", "db-01.example.internal", Listing::Invalid),
    ] {
        let mut target = FakeBackend::pi_target();
        target.name = name.to_owned().try_into().unwrap();
        host.clone_into(&mut target.host);
        target.listing = listing;
        broker.backend.set_target(target);
    }
    let mut secret = FakeBackend::example_api_secret();
    secret.name = "home-api".to_owned().try_into().unwrap();
    secret.listing = Listing::Full;
    broker.backend.set_api_secret(secret, "e2e-secret-value");
    let key = broker.add_agent(AGENT).await;
    let urls = broker.spawn_behind_serve().await;
    let root = tempfile::Builder::new()
        .prefix("wof")
        .tempdir_in("/tmp")
        .unwrap();
    for sub in ["config/warden", "state", "tmp", "cwd"] {
        fs::create_dir_all(root.path().join(sub)).unwrap();
    }
    let mut config = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.path().join("config/warden/config.toml"))
        .unwrap();
    write!(config, "server = \"{}\"\nagent = \"{AGENT}\"\n", urls.api).unwrap();
    fs::write(root.path().join("gitconfig"), "").unwrap();
    Setup {
        _broker: broker,
        upstream,
        root,
        key,
    }
}

impl Setup {
    /// GitHub's answer to the next token request: the installation covers [`REPO`].
    fn github_covers_repo(&self) {
        self.upstream.script_github_token(token_answer(
            "ghs_e2eResolve0123456789",
            now() + 3600,
            &[(1001, REPO)],
            &[("metadata", "read")],
            "selected",
        ));
    }

    /// How many token requests the fake GitHub has received.
    fn github_calls(&self) -> usize {
        self.upstream
            .received()
            .iter()
            .filter(|r| r.path_and_query.ends_with("/access_tokens"))
            .count()
    }

    fn git_env(&self, cmd: &mut Command) {
        cmd.env("GIT_CONFIG_GLOBAL", self.root.path().join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE");
    }

    /// A git checkout whose `origin` is [`REPO`] on GitHub.
    fn checkout(&self) -> PathBuf {
        let dir = self.root.path().join("checkout");
        fs::create_dir(&dir).unwrap();
        for args in [
            &["init", "-q"][..],
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/example-org/example-repo.git",
            ],
        ] {
            let mut git = Command::new("git");
            self.git_env(&mut git);
            let out = git.arg("-C").arg(&dir).args(args).output().unwrap();
            assert!(out.status.success(), "{}", text(&out.stderr));
        }
        dir
    }

    /// A directory outside any git checkout.
    fn outside(&self) -> PathBuf {
        self.root.path().join("cwd")
    }

    /// `warden <args>` run in `dir`, which must not be inside this repository's
    /// own checkout: `list` and `prime` ask about the checkout they run in.
    fn warden_in(&self, dir: &Path, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_warden"));
        self.git_env(&mut cmd);
        let out = cmd
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("TMPDIR", self.root.path().join("tmp"))
            .env("WARDEN_AGENT_KEY", &self.key)
            .env_remove("WARDEN_SESSION")
            .stdin(Stdio::null())
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        out
    }
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_list_json_shows_only_what_is_listed() {
    let s = setup().await;
    let out = s.warden_in(&s.outside(), &["list", "--json"]);
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();

    let targets = json["offers"]["ssh_targets"].as_array().unwrap();
    let names: Vec<&str> = targets
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    for expected in ["web-01", "switch-01"] {
        assert!(names.contains(&expected), "{names:?}");
    }
    let target = |n: &str| targets.iter().find(|t| t["name"] == n).unwrap();
    assert_eq!(
        target("web-01")["destination"]["host"],
        "web-01.example.internal"
    );
    assert!(target("switch-01")["destination"].is_null());
    let secrets = json["offers"]["api_secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0]["name"], "home-api");
    assert_eq!(json["offers"]["github"]["configured"], true);
    assert_eq!(json["offers"]["commit_signing"]["available"], true);
    assert_eq!(json["offers"]["unavailable"].as_array().unwrap().len(), 0);
    // Outside a checkout, no repository is asked about.
    assert!(json["repository"].is_null());
    assert_eq!(s.github_calls(), 0);

    let stdout = text(&out.stdout);
    for absent in ["pi.example.internal", "db-01", "e2e-secret-value"] {
        assert!(!stdout.contains(absent), "{absent} in {stdout}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_list_repo_and_prime() {
    let s = setup().await;
    s.github_covers_repo();
    let listed = text(&s.warden_in(&s.outside(), &["list", "--repo", REPO]).stdout);
    assert!(
        listed.contains(&format!("This repository ({REPO}):")),
        "{listed}"
    );
    assert!(
        listed.contains("GitHub tokens: the GitHub App covers it"),
        "{listed}"
    );
    assert_eq!(s.github_calls(), 1);

    // In a checkout of the same repository the answer comes from the broker's
    // cache, with no second call to GitHub.
    let checkout = s.checkout();
    let primed = text(&s.warden_in(&checkout, &["prime"]).stdout);
    for expected in [
        "## Privileged access: warden",
        "### GitHub, if this machine uses warden for it",
        "### Commits, if this machine signs through warden",
        "web-01",
        "home-api",
        &format!("This repository ({REPO}):"),
        "GitHub tokens: the GitHub App covers it",
    ] {
        assert!(primed.contains(expected), "{expected} missing in {primed}");
    }
    // No release signing item exists, so the release section is left out.
    assert!(!primed.contains("### Releases"), "{primed}");
    for absent in ["warden:section", "warden:offers", "db-01"] {
        assert!(!primed.contains(absent), "{absent} in {primed}");
    }
    assert_eq!(s.github_calls(), 1);

    let brief = text(&s.warden_in(&checkout, &["prime", "--brief"]).stdout);
    assert!(brief.len() < primed.len() / 4, "{brief}");
    for expected in ["web-01", "switch-01", "home-api"] {
        assert!(brief.contains(expected), "{expected} missing in {brief}");
    }
    // Names only: no destinations, and no question about the repository.
    for absent in ["example.internal", "api.example.com", REPO, "### "] {
        assert!(!brief.contains(absent), "{absent} in {brief}");
    }
    assert_eq!(s.github_calls(), 1);
}

/// `prime` exits 0 even when its output has nowhere to go: a session-start hook
/// that closed the pipe must not see a failure.
#[test]
fn e2e_prime_exits_0_with_stdout_closed() {
    let root = tempfile::tempdir().unwrap();
    let (reader, writer) = std::io::pipe().unwrap();
    // Closed before the command starts, so every write it makes fails.
    drop(reader);
    for args in [&["prime"][..], &["prime", "--brief"]] {
        let status = Command::new(env!("CARGO_BIN_EXE_warden"))
            .env("XDG_CONFIG_HOME", root.path().join("config"))
            .env("XDG_STATE_HOME", root.path().join("state"))
            .env_remove("WARDEN_AGENT_KEY")
            .stdin(Stdio::null())
            .stdout(writer.try_clone().unwrap())
            .stderr(Stdio::null())
            .current_dir(root.path())
            .args(args)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(0), "{args:?}");
    }
}
