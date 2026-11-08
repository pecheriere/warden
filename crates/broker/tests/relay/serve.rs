//! `warden-broker serve` runs the relay only when it is configured.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt as _;
use tokio::net::TcpStream;

/// A loopback port nothing listens on (yet).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Run `warden-server serve` with a minimal configuration (the relay's
/// public address only if `relay_public` is set); return it with its
/// relay listen port and host key path once its agent API answers.
async fn spawn_server(dir: &Path, relay_public: bool) -> (tokio::process::Child, u16, PathBuf) {
    let (api, approval, relay) = (free_port(), free_port(), free_port());
    let host_key = dir.join("relay_host_ed25519");
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
        .env("WARDEN_API_LISTEN", format!("127.0.0.1:{api}"))
        .env("WARDEN_APPROVAL_LISTEN", format!("127.0.0.1:{approval}"))
        .env("WARDEN_RELAY_LISTEN", format!("127.0.0.1:{relay}"))
        .env("WARDEN_RELAY_HOST_KEY_PATH", &host_key)
        .env("WARDEN_AUDIENCE_PATH", dir.join("audience"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if relay_public {
        cmd.env("WARDEN_RELAY_PUBLIC_ADDR", "relay.example.ts.net:2222");
    }
    let child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", api)).await.is_err() {
        assert!(Instant::now() < deadline, "warden-server did not start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (child, relay, host_key)
}

async fn terminate(mut child: tokio::process::Child) {
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id().unwrap()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .expect("warden-server stopped")
        .unwrap();
    assert!(status.success(), "{status}");
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_runs_the_relay_only_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    let (server, relay, host_key) = spawn_server(dir.path(), true).await;
    // The relay listener is bound just after the HTTP ones.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut conn = loop {
        match TcpStream::connect(("127.0.0.1", relay)).await {
            Ok(conn) => break conn,
            Err(e) => assert!(Instant::now() < deadline, "relay not listening: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let mut banner = [0_u8; 16];
    conn.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-warden\r\n");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&host_key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    terminate(server).await;
    // Stopping closed the relay's connections too.
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut rest))
        .await
        .expect("connection closed")
        .ok();

    let dir = tempfile::tempdir().unwrap();
    let (server, relay, host_key) = spawn_server(dir.path(), false).await;
    assert!(TcpStream::connect(("127.0.0.1", relay)).await.is_err());
    assert!(!host_key.exists());
    terminate(server).await;
}
