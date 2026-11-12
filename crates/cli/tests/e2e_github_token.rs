//! End to end: the real `warden` binary as git's credential helper and as the
//! source of `gh`'s token, against an in-process broker whose GitHub is a local
//! HTTPS server. Everything runs in a throwaway `HOME`, with git's global
//! configuration in that directory and the system one off, so nothing here reads
//! or changes the configuration of whoever runs it.

use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use tempfile::TempDir;
use warden_broker::github_app::GithubApi;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::github_app::{minted_answer, token_answer};
use warden_broker::testkit::upstream::HttpsUpstream;
use warden_broker::testkit::{CapturingNotifier, TestBroker, github_app_key};
use warden_broker_proto::Window;

const AGENT: &str = "build-agent";
const TOKEN: &str = "ghs_e2eToken0123456789";
const REPO: &str = "example-owner/example-repo";
const REPO_ID: u64 = 1001;
const OTHER: &str = "example-owner/homebrew-tap";
const OTHER_ID: u64 = 1002;
const GITHUB_INPUT: &str =
    "protocol=https\nhost=github.com\npath=example-owner/example-repo.git\n\n";
const OTHER_INPUT: &str =
    "protocol=https\nhost=github.com\npath=example-owner/homebrew-tap.git\n\n";

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
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

/// A throwaway home with a logged-in CLI, a git repository and a fake `gh` that
/// prints the token it was given and its arguments.
struct Machine {
    root: TempDir,
    key: String,
}

impl Machine {
    fn new(server: &url::Url, key: String) -> Self {
        let root = tempfile::Builder::new()
            .prefix("wgh")
            .tempdir_in("/tmp")
            .unwrap();
        for sub in [
            "home/.local",
            "config/warden",
            "state",
            "tmp",
            "repo",
            "bin",
        ] {
            fs::create_dir_all(root.path().join(sub)).unwrap();
        }
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join("config/warden/config.toml"))
            .unwrap();
        write!(f, "server = \"{server}\"\nagent = \"{AGENT}\"\n").unwrap();
        let gh = root.path().join("bin/gh");
        fs::write(
            &gh,
            "#!/bin/sh\n: > \"$(dirname \"$0\")/gh-ran\"\nprintf 'token=%s\\n' \"$GH_TOKEN\"\nprintf 'args=%s\\n' \"$*\"\n",
        )
        .unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o755)).unwrap();
        Self { root, key }
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn cache(&self) -> PathBuf {
        self.root.path().join("state/warden/github-token.json")
    }

    /// `~/.local/bin` first, then the fake `gh`, then the system.
    fn path_var(&self) -> String {
        format!(
            "{}:{}:/usr/bin:/bin",
            self.home().join(".local/bin").display(),
            self.root.path().join("bin").display()
        )
    }

    fn env(&self, cmd: &mut Command) {
        cmd.env("HOME", self.home())
            .env("PATH", self.path_var())
            .env("GIT_CONFIG_GLOBAL", self.home().join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("TMPDIR", self.root.path().join("tmp"))
            .env("WARDEN_AGENT_KEY", &self.key)
            .env_remove("WARDEN_SESSION")
            .env_remove("GH_TOKEN")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .current_dir(self.root.path().join("repo"));
    }

    fn warden(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_warden"));
        self.env(&mut cmd);
        cmd.stdin(Stdio::null());
        cmd
    }

    fn credential(&self, op: &str, input: &str) -> Output {
        let mut cmd = self.warden();
        cmd.args(["git-credential", op]);
        run_with_input(cmd, input)
    }

    fn git(&self, args: &[&str], input: &str) -> Output {
        let mut cmd = Command::new("git");
        self.env(&mut cmd);
        cmd.args(args);
        run_with_input(cmd, input)
    }
}

/// Run `cmd`, with `input` on its stdin.
fn run_with_input(mut cmd: Command, input: &str) -> Output {
    spawn_with_input(&mut cmd, input)
        .wait_with_output()
        .unwrap()
}

/// Start `cmd`, with `input` on its stdin and its output captured.
fn spawn_with_input(cmd: &mut Command, input: &str) -> Child {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child
}

struct Setup {
    broker: TestBroker,
    upstream: HttpsUpstream,
    machine: Machine,
}

async fn setup() -> Setup {
    setup_with_max(Window::GITHUB_TOKEN_DEFAULT).await
}

/// A broker allowing GitHub token grants of up to `max`.
async fn setup_with_max(max: Window) -> Setup {
    let upstream = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    );
    let broker = TestBroker::with_github(api, max, 60).await;
    broker.backend.set_github_app(Some(github_app_key().0));
    // Token expiry is judged by the local clock, so the broker keeps the real time.
    broker.clock.set(now());
    let key = broker.add_agent(AGENT).await;
    let urls = broker.spawn_behind_serve().await;
    let machine = Machine::new(&urls.api, key);
    Setup {
        broker,
        upstream,
        machine,
    }
}

/// Queue GitHub's answer for the next mint: `token` for repository `(id, name)`,
/// ending an hour from now.
fn script_token(s: &Setup, token: &str, repository: (u64, &str)) {
    s.upstream.script_github_token(minted_answer(
        token,
        s.broker.clock.now() + 3600,
        &[repository],
    ));
}

/// Approve the request `token` for `window` as the owner would, with GitHub
/// resolving `repositories` (`(id, name)`) when the page asks and then minting
/// `mints` (`(token, repository)`) for the agent, in order.
async fn approve_for(
    s: &Setup,
    token: &str,
    window: Window,
    repositories: &[(u64, &str)],
    mints: &[(&str, (u64, &str))],
) {
    s.upstream.script_github_token(token_answer(
        "ghs_resolve_0123456789",
        s.broker.clock.now() + 3600,
        repositories,
        &[("metadata", "read")],
        "selected",
    ));
    for (mint, repository) in mints {
        script_token(s, mint, *repository);
    }
    let approved = s.broker.approve(token, window).await;
    assert!(approved.status.is_success(), "{}", approved.body);
}

async fn wait(child: Child) -> Output {
    tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap()
}

/// `warden request github` for [`REPO`], approved with a passkey as the owner would.
async fn get_grant(s: &Setup) -> Output {
    let child = s
        .machine
        .warden()
        .args(["request", "github", REPO, "--goal", "push the fix"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let token = CapturingNotifier::token(&s.broker.capture.next().await);
    approve_for(s, &token, Window::D30, &[(REPO_ID, REPO)], &[]).await;
    let out = wait(child).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_request_github_then_git_credential() {
    let s = setup().await;
    let requested = get_grant(&s).await;
    let said = text(&requested.stdout);
    assert!(said.contains("approved: grant"), "{said}");
    assert!(said.contains("warden setup github"), "{said}");

    let set_up = s
        .machine
        .warden()
        .args(["setup", "github"])
        .output()
        .unwrap();
    assert_eq!(set_up.status.code(), Some(0), "{}", text(&set_up.stderr));

    // Real git asks the helper and gets the token.
    script_token(&s, TOKEN, (REPO_ID, REPO));
    let filled = s.machine.git(&["credential", "fill"], GITHUB_INPUT);
    assert!(filled.status.success(), "{}", text(&filled.stderr));
    let out = text(&filled.stdout);
    assert!(out.contains("username=x-access-token\n"), "{out}");
    assert!(out.contains(&format!("password={TOKEN}\n")), "{out}");

    // The cache is private, and serves the next call without a mint.
    let mode = fs::metadata(s.machine.cache())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7777, 0o600);
    let again = s.machine.credential("get", GITHUB_INPUT);
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
    assert_eq!(
        text(&again.stdout),
        format!("username=x-access-token\npassword={TOKEN}\n")
    );
    let token = s
        .machine
        .warden()
        .args(["github", "token", "--repo", REPO])
        .output()
        .unwrap();
    assert_eq!(token.status.code(), Some(0), "{}", text(&token.stderr));
    assert_eq!(text(&token.stdout), format!("{TOKEN}\n"));

    // Plain `gh` runs the wrapper, which hands the real one the token.
    let mut gh = Command::new("gh");
    s.machine.env(&mut gh);
    let gh = gh.args(["pr", "list", "-R", REPO]).output().unwrap();
    assert!(gh.status.success(), "{}", text(&gh.stderr));
    assert_eq!(
        text(&gh.stdout),
        format!("token={TOKEN}\nargs=pr list -R {REPO}\n")
    );
    // The approval page's lookup, then one mint; the cache serves the rest.
    assert_eq!(s.upstream.received().len(), 2, "one mint, then the cache");

    // Revoking the grant here drops its cached token.
    let minted = fs::read_to_string(s.machine.cache()).unwrap();
    let grant: serde_json::Value = serde_json::from_str(&minted).unwrap();
    assert_eq!(grant["version"], 2);
    assert_eq!(grant["entries"][0]["repository"], REPO);
    assert_eq!(grant["entries"][0]["repository_id"], REPO_ID);
    let grant = grant["entries"][0]["grant_id"].as_str().unwrap().to_owned();
    let revoked = s
        .machine
        .warden()
        .args(["revoke", &grant])
        .output()
        .unwrap();
    assert_eq!(revoked.status.code(), Some(0), "{}", text(&revoked.stderr));
    assert!(!s.machine.cache().exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn token_without_grant_asks_the_owner_and_serves_once_approved() {
    let s = setup().await;
    let child = s
        .machine
        .warden()
        .args(["github", "token", "--repo", REPO])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let token = CapturingNotifier::token(&s.broker.capture.next().await);
    // The request it filed is a 30-day one, with the fixed goal and the directory.
    let status = s.machine.warden().arg("status").output().unwrap();
    let listed = text(&status.stdout);
    assert!(
        listed.contains(&format!("github token for {REPO} for 30d")),
        "{listed}"
    );
    assert!(
        listed.contains("requested automatically by the gh wrapper"),
        "{listed}"
    );
    approve_for(
        &s,
        &token,
        Window::D30,
        &[(REPO_ID, REPO)],
        &[(TOKEN, (REPO_ID, REPO))],
    )
    .await;
    let out = wait(child).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("{TOKEN}\n"), "only the token");
    let said = text(&out.stderr);
    assert!(said.contains("waiting for approval"), "{said}");
    assert!(said.contains("request "), "{said}");
    assert!(!said.contains(TOKEN), "{said}");
}

#[tokio::test(flavor = "multi_thread")]
async fn token_without_grant_exits_5_with_guidance_when_denied() {
    let s = setup().await;
    let mut cmd = s.machine.warden();
    cmd.args(["git-credential", "get"]);
    let child = spawn_with_input(&mut cmd, GITHUB_INPUT);
    let token = CapturingNotifier::token(&s.broker.capture.next().await);
    let denied = s.broker.deny(&token).await;
    assert!(denied.status.is_success(), "{}", denied.body);
    let out = wait(child).await;
    assert_eq!(out.status.code(), Some(5), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "", "nothing for git on stdout");
    let said = text(&out.stderr);
    assert!(said.contains("denied"), "{said}");
    assert!(said.contains("Do not retry"), "{said}");
    assert!(said.contains("ask the owner"), "{said}");
    assert!(s.upstream.received().is_empty());
    assert!(!s.machine.cache().exists());
}

/// Read `child`'s stderr until it says it is waiting for approval. Returns what it
/// said so far and the rest of the stream.
async fn waiting(child: &mut Child) -> (String, BufReader<ChildStderr>) {
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    tokio::task::spawn_blocking(move || {
        let mut said = String::new();
        while !said.contains("waiting for approval") {
            let read = stderr.read_line(&mut said).unwrap();
            assert!(read > 0, "ended without waiting: {said}");
        }
        (said, stderr)
    })
    .await
    .unwrap()
}

fn spawn_token(s: &Setup, dir: &str) -> Child {
    let dir = s.machine.root.path().join(dir);
    fs::create_dir_all(&dir).unwrap();
    s.machine
        .warden()
        .args(["github", "token", "--repo", REPO])
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_automatic_request_waits_on_one_already_pending_and_leaves_it_on_ctrl_c() {
    let s = setup().await;
    let first = s
        .machine
        .warden()
        .args(["request", "github", REPO, "--goal", "push the fix"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let token = CapturingNotifier::token(&s.broker.capture.next().await);

    // An explicit request with another fingerprint still refuses to wait on it.
    let other = s
        .machine
        .warden()
        .args(["request", "github", REPO, "--goal", "something else"])
        .output()
        .unwrap();
    assert_eq!(other.status.code(), Some(1), "{}", text(&other.stderr));
    assert!(
        text(&other.stderr).contains("fingerprint differs"),
        "{}",
        text(&other.stderr)
    );

    // Ctrl-C on a command waiting on a request made elsewhere leaves it pending.
    let mut interrupted = spawn_token(&s, "elsewhere");
    let (said, mut rest) = waiting(&mut interrupted).await;
    assert!(said.contains("made elsewhere"), "{said}");
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&interrupted),
        rustix::process::Signal::INT,
    )
    .unwrap();
    let out = wait(interrupted).await;
    assert_eq!(out.status.code(), Some(130));
    let mut said = String::new();
    rest.read_to_string(&mut said).unwrap();
    assert!(said.contains("left pending"), "{said}");
    assert_eq!(text(&out.stdout), "");

    // The gh wrapper, from another directory, waits on the same request; one
    // approval serves both.
    let mut second = spawn_token(&s, "another/repo");
    let (said, _rest) = waiting(&mut second).await;
    assert!(said.contains("made elsewhere"), "{said}");
    approve_for(
        &s,
        &token,
        Window::D30,
        &[(REPO_ID, REPO)],
        &[(TOKEN, (REPO_ID, REPO))],
    )
    .await;
    let first = wait(first).await;
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));
    let second = wait(second).await;
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(text(&second.stdout), format!("{TOKEN}\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn other_kinds_still_refuse_a_pending_request_of_another_fingerprint() {
    let s = setup().await;
    let mut first = s
        .machine
        .warden()
        .args(["request", "signing", "--goal", "sign my commits"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    s.broker.capture.next().await;
    let other = s
        .machine
        .warden()
        .args(["request", "signing", "--goal", "something else"])
        .output()
        .unwrap();
    first.kill().unwrap();
    first.wait().unwrap();
    assert_eq!(other.status.code(), Some(1), "{}", text(&other.stderr));
    assert!(
        text(&other.stderr).contains("fingerprint differs"),
        "{}",
        text(&other.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_automatic_request_asks_for_no_more_than_the_broker_allows() {
    let s = setup_with_max(Window::D7).await;
    let mut cmd = s.machine.warden();
    cmd.args(["git-credential", "get"]);
    let child = spawn_with_input(&mut cmd, GITHUB_INPUT);
    let token = CapturingNotifier::token(&s.broker.capture.next().await);
    let status = s.machine.warden().arg("status").output().unwrap();
    let listed = text(&status.stdout);
    assert!(
        listed.contains(&format!("github token for {REPO} for 7d")),
        "{listed}"
    );
    approve_for(
        &s,
        &token,
        Window::D7,
        &[(REPO_ID, REPO)],
        &[(TOKEN, (REPO_ID, REPO))],
    )
    .await;
    let out = wait(child).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("username=x-access-token\npassword={TOKEN}\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn git_push_gets_token_for_its_repository() {
    let s = setup().await;
    get_grant(&s).await;
    script_token(&s, TOKEN, (REPO_ID, REPO));
    let out = s.machine.credential("get", GITHUB_INPUT);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("username=x-access-token\npassword={TOKEN}\n")
    );
    // GitHub was asked for that repository's id alone: the page's lookup, then one mint.
    let received = s.upstream.received();
    assert_eq!(received.len(), 2, "{received:?}");
    let body: serde_json::Value = serde_json::from_slice(&received[1].body).unwrap();
    assert_eq!(body["repository_ids"], json!([REPO_ID]));

    // The same repository spelled in another case is served from the cache.
    let again = s.machine.credential(
        "get",
        "protocol=https\nhost=github.com\npath=Example-Owner/EXAMPLE-repo.git\n\n",
    );
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
    assert_eq!(text(&again.stdout), text(&out.stdout));
    assert_eq!(s.upstream.received().len(), 2, "no second mint");
}

#[tokio::test(flavor = "multi_thread")]
async fn second_repository_files_its_own_request() {
    let s = setup().await;
    get_grant(&s).await;
    script_token(&s, TOKEN, (REPO_ID, REPO));
    let first = s.machine.credential("get", GITHUB_INPUT);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));

    // The grant covers the first repository only: the second one asks the owner.
    let mut cmd = s.machine.warden();
    cmd.args(["git-credential", "get"]);
    let child = spawn_with_input(&mut cmd, OTHER_INPUT);
    let token = CapturingNotifier::token(&s.broker.capture.next().await);
    let status = s.machine.warden().arg("status").output().unwrap();
    let listed = text(&status.stdout);
    assert!(listed.contains(OTHER), "{listed}");
    let second = "ghs_e2eSecondRepo0123456789";
    approve_for(
        &s,
        &token,
        Window::D30,
        &[(OTHER_ID, OTHER)],
        &[(second, (OTHER_ID, OTHER))],
    )
    .await;
    let out = wait(child).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("username=x-access-token\npassword={second}\n")
    );

    // Each repository keeps its own token in the cache.
    let before = s.upstream.received().len();
    let a = s.machine.credential("get", GITHUB_INPUT);
    let b = s.machine.credential("get", OTHER_INPUT);
    assert!(text(&a.stdout).contains(TOKEN), "{}", text(&a.stdout));
    assert!(text(&b.stdout).contains(second), "{}", text(&b.stdout));
    assert_eq!(s.upstream.received().len(), before, "both from the cache");
}

/// A broker that predates repository-scoped grants, local: serves `/v1/info`
/// without the flag and records every request line it gets. Stops with the guard.
struct OldBroker {
    url: url::Url,
    seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    address: std::net::SocketAddr,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl OldBroker {
    fn start() -> Self {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (log, halt) = (seen.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if halt.load(Ordering::SeqCst) {
                    break;
                }
                let mut stream = stream.unwrap();
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    request.push(byte[0]);
                }
                let first = text(&request).lines().next().unwrap_or_default().to_owned();
                log.lock().unwrap().push(first);
                let body = r#"{"protocols":["warden-request-v1"],"audience":"40ad20029e94984d193159667b296d8a"}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Self {
            url: format!("http://{address}/").parse().unwrap(),
            seen,
            stop,
            address,
            thread: Some(thread),
        }
    }

    /// The request lines received so far.
    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for OldBroker {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wake the accept loop so that it sees the flag.
        let _ = std::net::TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn an_old_broker_is_refused_before_any_request_is_created() {
    let broker = OldBroker::start();
    let machine = Machine::new(&broker.url, format!("wdn_{}", "S".repeat(43)));
    let out = machine
        .warden()
        .args(["request", "github", REPO, "--goal", "push the fix"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let said = text(&out.stderr);
    assert!(
        said.contains(
            "the broker does not support repository-scoped GitHub grants: upgrade the broker \
             before asking for GitHub access"
        ),
        "{said}"
    );
    assert_eq!(
        broker.requests(),
        ["GET /v1/info HTTP/1.1"],
        "nothing but the capability check reached the broker"
    );

    // The same for a token, which is not served from a cache.
    let token = machine
        .warden()
        .args(["github", "token", "--repo", REPO])
        .output()
        .unwrap();
    assert_eq!(token.status.code(), Some(1), "{}", text(&token.stderr));
    assert_eq!(text(&token.stdout), "");
    assert!(
        broker
            .requests()
            .iter()
            .all(|line| line.starts_with("GET /v1/info")),
        "{:?}",
        broker.requests()
    );
}

/// No broker is configured here: answering at all would mean calling one.
fn offline() -> Machine {
    let machine = Machine::new(&"http://127.0.0.1:9/".parse().unwrap(), String::new());
    fs::remove_file(machine.root.path().join("config/warden/config.toml")).unwrap();
    machine
}

#[test]
fn the_gh_wrapper_refuses_without_a_repository_and_never_starts_the_real_gh() {
    let machine = offline();
    let set_up = machine.warden().args(["setup", "github"]).output().unwrap();
    assert_eq!(set_up.status.code(), Some(0), "{}", text(&set_up.stderr));

    // No `-R`, no `GH_REPO`, and a directory with no `origin`.
    let mut gh = Command::new("gh");
    machine.env(&mut gh);
    let out = gh
        .env_remove("GH_REPO")
        .args(["pr", "list"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let said = text(&out.stderr);
    assert!(
        said.contains("cannot tell which repository; pass -R owner/name"),
        "{said}"
    );
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    assert!(
        !machine.root.path().join("bin/gh-ran").exists(),
        "the real gh was started"
    );
}

#[test]
fn credential_for_anything_but_https_github_prints_nothing() {
    let machine = offline();
    for input in [
        "protocol=https\nhost=gitlab.com\n\n",
        "protocol=https\nhost=github.com.example.com\n\n",
        "protocol=https\nhost=github.com:443\n\n",
        "protocol=http\nhost=github.com\n\n",
        "protocol=ssh\nhost=github.com\n\n",
        "host=github.com\n\n",
        "protocol=https\n\n",
        "protocol=https\nnot a key value line\nhost=github.com\n\n",
        "protocol=https\nhost=github.com\nhost=gitlab.com\n\n",
        "",
    ] {
        let out = machine.credential("get", input);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{input:?}: {}",
            text(&out.stderr)
        );
        assert_eq!(text(&out.stdout), "", "{input:?}");
        assert_eq!(text(&out.stderr), "", "{input:?}");
    }
}

#[test]
fn credential_store_and_erase_are_silent() {
    let machine = offline();
    let stored =
        format!("protocol=https\nhost=github.com\nusername=x-access-token\npassword={TOKEN}\n\n");
    for op in ["store", "erase", "other"] {
        let out = machine.credential(op, &stored);
        assert_eq!(out.status.code(), Some(0), "{op}: {}", text(&out.stderr));
        assert_eq!(text(&out.stdout), "", "{op}");
        assert_eq!(text(&out.stderr), "", "{op}");
    }
    assert!(!machine.cache().exists());
}

fn global_helpers(machine: &Machine) -> Vec<String> {
    let out = machine.git(
        &[
            "config",
            "--global",
            "--get-all",
            "credential.https://github.com.helper",
        ],
        "",
    );
    text(&out.stdout).lines().map(ToOwned::to_owned).collect()
}

#[test]
fn setup_github_writes_helper_and_wrapper() {
    let machine = offline();
    let out = machine.warden().args(["setup", "github"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let exe = fs::canonicalize(env!("CARGO_BIN_EXE_warden")).unwrap();
    let exe = exe.to_str().unwrap();
    assert_eq!(
        global_helpers(&machine),
        [String::new(), format!("!'{exe}' git-credential")]
    );
    let wrapper = machine.home().join(".local/bin/gh");
    let mode = fs::metadata(&wrapper).unwrap().permissions().mode();
    assert_eq!(mode & 0o7777, 0o755);
    let script = fs::read_to_string(&wrapper).unwrap();
    let real = machine.root.path().join("bin/gh");
    assert!(
        script.contains(&format!("'{exe}' github token")),
        "{script}"
    );
    assert!(
        script.contains(&format!("exec '{}' \"$@\"", real.display())),
        "{script}"
    );
    let said = text(&out.stdout);
    assert!(
        said.contains("credential.https://github.com.helper"),
        "{said}"
    );
    assert!(said.contains(&wrapper.display().to_string()), "{said}");
    assert!(
        !text(&out.stderr).contains("warning"),
        "{}",
        text(&out.stderr)
    );

    // Again: the same values, and the wrapper it wrote is its own to replace.
    let again = machine.warden().args(["setup", "github"]).output().unwrap();
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
    assert_eq!(global_helpers(&machine).len(), 2);
    assert_eq!(fs::read_to_string(&wrapper).unwrap(), script);
}

#[test]
fn setup_github_warns_when_the_wrapper_is_not_first_on_path() {
    let machine = offline();
    let path = format!(
        "{}:{}:/usr/bin:/bin",
        machine.root.path().join("bin").display(),
        machine.home().join(".local/bin").display()
    );
    let out = machine
        .warden()
        .args(["setup", "github"])
        .env("PATH", path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let warned = text(&out.stderr);
    assert!(warned.contains("warning"), "{warned}");
    assert!(warned.contains("PATH"), "{warned}");
}

#[test]
fn setup_github_refuses_foreign_wrapper() {
    let machine = offline();
    let bin = machine.home().join(".local/bin");
    fs::create_dir_all(&bin).unwrap();
    let foreign = "#!/bin/sh\necho mine\n";
    fs::write(bin.join("gh"), foreign).unwrap();
    let out = machine.warden().args(["setup", "github"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("not written by warden"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(fs::read_to_string(bin.join("gh")).unwrap(), foreign);
    assert!(
        global_helpers(&machine).is_empty(),
        "git was left as it was"
    );
}
