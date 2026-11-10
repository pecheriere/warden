//! `warden-broker serve` runs the relay only when it is configured.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// A running `warden-server serve`, with the lines it has printed so far.
struct Server {
    child: tokio::process::Child,
    lines: mpsc::UnboundedReceiver<String>,
    output: Vec<String>,
}

/// Send each line `stream` prints to `lines` (invalid UTF-8 replaced), until it
/// closes. Reading all of it also keeps the server from blocking on a full pipe.
fn forward_lines(
    stream: impl AsyncRead + Unpin + Send + 'static,
    lines: mpsc::UnboundedSender<String>,
) {
    tokio::spawn(async move {
        // By bytes, so a line that is not UTF-8 does not end the reading: the
        // server would then write into a closed pipe.
        let mut reader = BufReader::new(stream).split(b'\n');
        while let Ok(Some(line)) = reader.next_segment().await {
            if lines
                .send(String::from_utf8_lossy(&line).into_owned())
                .is_err()
            {
                break;
            }
        }
    });
}

/// The address a log line gives for `field`, as in `api=127.0.0.1:41234`.
fn address(line: &str, field: &str) -> SocketAddr {
    let prefix = format!("{field}=");
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no {field} address in {line:?}"))
        .parse()
        .unwrap_or_else(|e| panic!("{field} address in {line:?}: {e}"))
}

fn host_key(dir: &Path) -> PathBuf {
    dir.join("relay_host_ed25519")
}

impl Server {
    /// Run `warden-server serve` with a minimal configuration (the relay's
    /// public address only if `relay_public` is set). Every listener binds
    /// port 0, so the server takes ports nothing else holds, and logs them.
    fn spawn(dir: &Path, relay_public: bool) -> Self {
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_warden-server"));
        // Only `cargo llvm-cov` sets this: without it, this process reports no coverage.
        cmd.arg("serve")
            .env_clear()
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|file| ("LLVM_PROFILE_FILE", file)))
            .env("WARDEN_DB_PATH", dir.join("warden.db"))
            .env("WARDEN_AUDIT_PATH", dir.join("audit.jsonl"))
            .env("WARDEN_PUBLIC_URL", "https://warden.example.ts.net")
            .env("WARDEN_OWNER_LOGIN", "alice@example.com")
            .env("WARDEN_OP_CONNECT_URL", "http://127.0.0.1:9")
            .env("WARDEN_OP_CONNECT_TOKEN", "unused")
            .env("WARDEN_NOTIFY", "ntfy")
            .env("WARDEN_NOTIFY_NTFY_URL", "https://ntfy.invalid/warden")
            .env("WARDEN_API_LISTEN", "127.0.0.1:0")
            .env("WARDEN_APPROVAL_LISTEN", "127.0.0.1:0")
            .env("WARDEN_RELAY_LISTEN", "127.0.0.1:0")
            .env("WARDEN_RELAY_HOST_KEY_PATH", host_key(dir))
            .env("WARDEN_AUDIENCE_PATH", dir.join("audience"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if relay_public {
            cmd.env("WARDEN_RELAY_PUBLIC_ADDR", "relay.example.ts.net:2222");
        }
        let mut child = cmd.spawn().unwrap();
        let (tx, lines) = mpsc::unbounded_channel();
        forward_lines(child.stdout.take().unwrap(), tx.clone());
        forward_lines(child.stderr.take().unwrap(), tx);
        Self {
            child,
            lines,
            output: Vec::new(),
        }
    }

    /// The first line the server prints that contains `needle`. Fails as soon
    /// as the server exits without printing it, showing all it printed.
    async fn line(&mut self, needle: &str) -> String {
        if let Some(line) = self.output.iter().find(|line| line.contains(needle)) {
            return line.clone();
        }
        // Only a guard against a hung server: a healthy one starts in well
        // under a second, and one that fails exits.
        let waited = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    line = self.lines.recv() => {
                        // Both streams closed: the server is exiting.
                        let line = line?;
                        self.output.push(line.clone());
                        if line.contains(needle) {
                            return Some(line);
                        }
                    }
                    status = self.child.wait() => {
                        status.unwrap();
                        return None;
                    }
                }
            }
        })
        .await;
        let Ok(found) = waited else {
            panic!(
                "warden-server did not print {needle:?} within 60 s:\n{}",
                self.output.join("\n")
            );
        };
        if let Some(line) = found {
            return line;
        }
        let status = self.child.wait().await.unwrap();
        // The exit can win the race against a line still in the pipe: read the
        // rest of the output before concluding that the line was not printed.
        let output = self.rest_of_output().await;
        if let Some(line) = self.output.iter().find(|line| line.contains(needle)) {
            return line.clone();
        }
        panic!("warden-server exited with {status} before printing {needle:?}:\n{output}");
    }

    /// All the server printed, once both of its streams have closed. Only a
    /// guard against a process that inherited a stream and keeps it open.
    async fn rest_of_output(&mut self) -> String {
        let closed = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(line) = self.lines.recv().await {
                self.output.push(line);
            }
        })
        .await;
        let output = self.output.join("\n");
        assert!(
            closed.is_ok(),
            "warden-server's output did not close within 15 s of its exit:\n{output}"
        );
        output
    }

    /// Stop the server with SIGTERM, check that it exits cleanly, and return
    /// all it printed.
    async fn terminate(mut self) -> String {
        let pid = rustix::process::Pid::from_raw(i32::try_from(self.child.id().unwrap()).unwrap())
            .unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        let status: ExitStatus = tokio::time::timeout(Duration::from_secs(15), self.child.wait())
            .await
            .expect("warden-server stopped")
            .unwrap();
        let output = self.rest_of_output().await;
        assert!(
            status.success(),
            "warden-server exited with {status}:\n{output}"
        );
        output
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_runs_the_relay_only_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = Server::spawn(dir.path(), true);
    let api = address(&server.line("warden-server listening").await, "api");
    // The relay listener is bound just after the HTTP ones.
    let relay = address(&server.line("SSH relay listening").await, "relay");
    TcpStream::connect(api).await.unwrap();
    let mut conn = TcpStream::connect(relay).await.unwrap();
    let mut banner = [0_u8; 16];
    conn.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-warden\r\n");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(host_key(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    server.terminate().await;
    // Stopping closed the relay's connections too.
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut rest))
        .await
        .expect("connection closed")
        .ok();

    let dir = tempfile::tempdir().unwrap();
    let mut server = Server::spawn(dir.path(), false);
    let api = address(&server.line("warden-server listening").await, "api");
    TcpStream::connect(api).await.unwrap();
    // The relay would be bound before the server handles the signal, so its
    // whole output shows whether it ever listened.
    let output = server.terminate().await;
    assert!(!output.contains("SSH relay listening"), "{output}");
    assert!(!host_key(dir.path()).exists());
}
