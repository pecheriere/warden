//! A broker that predates repository-scoped grants, and the refusal it earns.

use std::io::{Read as _, Write as _};

use super::{Machine, REPO, text};

/// A broker that predates repository-scoped grants, local: serves `/v1/info`
/// without the flag and records every request line it gets. Stops with the guard.
pub(super) struct OldBroker {
    pub(super) url: url::Url,
    seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    address: std::net::SocketAddr,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl OldBroker {
    pub(super) fn start() -> Self {
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
    pub(super) fn requests(&self) -> Vec<String> {
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
