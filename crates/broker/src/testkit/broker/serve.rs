//! Serving a [`TestBroker`] on loopback: its HTTP listeners and SSH relay.

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use url::Url;

use super::{BaseUrls, TestBroker};
use crate::relay::{RelayLimits, RelayServer, host_key};
use crate::testkit::TEST_OWNER;

impl TestBroker {
    /// Serve both routers on ephemeral loopback ports until the broker is
    /// dropped. The in-process helpers keep working alongside.
    ///
    /// # Panics
    /// If a listener cannot be bound.
    pub async fn spawn(&self) -> BaseUrls {
        self.serve([self.api_router.clone(), self.router.clone()], None)
            .await
    }

    /// Like [`TestBroker::spawn`], but every request reaching either listener
    /// first passes through a stand-in for Tailscale Serve: any
    /// `Tailscale-User-Login` header the client sent is replaced with
    /// [`TEST_OWNER`], as Serve does for the authenticated tailnet peer. Use
    /// it to drive the broker with a client (such as the `warden` CLI) that,
    /// like in production, never sets the identity header itself.
    ///
    /// # Panics
    /// If a listener cannot be bound.
    pub async fn spawn_behind_serve(&self) -> BaseUrls {
        self.serve(self.serve_routers(), None).await
    }

    /// Like [`TestBroker::spawn_behind_serve`], on the ports of `urls`: for
    /// example those of this broker before [`TestBroker::restart`], so that
    /// clients see the same broker come back.
    ///
    /// # Panics
    /// If a listener cannot be bound, for instance because the port is in use.
    pub async fn spawn_behind_serve_at(&self, urls: &BaseUrls) -> BaseUrls {
        let port = |url: &Url| url.port().expect("loopback URL has a port");
        self.serve(
            self.serve_routers(),
            Some([port(&urls.api), port(&urls.approval)]),
        )
        .await
    }

    fn serve_routers(&self) -> [Router; 2] {
        [
            self.api_router
                .clone()
                .layer(axum::middleware::map_request(as_owner)),
            self.router
                .clone()
                .layer(axum::middleware::map_request(as_owner)),
        ]
    }

    /// Serve `routers` on loopback, on `ports` or ephemeral ones. Stopping a
    /// server (on drop or restart) also drops its open connections, in-flight
    /// requests included, as a process exit would.
    async fn serve(&self, routers: [Router; 2], ports: Option<[u16; 2]>) -> BaseUrls {
        let ports = ports.unwrap_or([0, 0]);
        let mut bound = Vec::new();
        for (router, port) in routers.into_iter().zip(ports) {
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .expect("bind loopback listener");
            let addr = listener.local_addr().expect("listener address");
            let task = tokio::spawn(serve_connections(listener, router));
            self.servers
                .lock()
                .expect("servers lock poisoned")
                .push(task.abort_handle());
            bound.push(Url::parse(&format!("http://{addr}/")).expect("loopback URL"));
        }
        let approval = bound.pop().expect("approval listener");
        let api = bound.pop().expect("api listener");
        BaseUrls { api, approval }
    }

    /// Run the SSH relay with the default limits on an ephemeral loopback
    /// port until the broker is dropped or [`TestBroker::stop_relay`] is
    /// called; returns its address. It presents the host key relay grants
    /// carry.
    ///
    /// # Panics
    /// If the host key cannot be loaded or the listener cannot be bound.
    pub async fn spawn_relay(&self) -> std::net::SocketAddr {
        self.spawn_relay_with(RelayLimits::default()).await
    }

    /// Like [`TestBroker::spawn_relay`], with `limits`.
    ///
    /// # Panics
    /// If the host key cannot be loaded or the listener cannot be bound.
    pub async fn spawn_relay_with(&self, limits: RelayLimits) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind relay listener");
        let addr = listener.local_addr().expect("relay listener address");
        self.serve_relay(listener, limits).await;
        addr
    }

    /// Run the SSH relay with `limits` on `listener` until the broker is
    /// dropped or [`TestBroker::stop_relay`] is called.
    pub(super) async fn serve_relay(&self, listener: tokio::net::TcpListener, limits: RelayLimits) {
        let key = host_key::load_or_create(self.db_path.with_file_name("relay_host_ed25519"))
            .await
            .expect("relay host key");
        let server = RelayServer::new(
            self.state.requests.clone(),
            self.backend.clone(),
            self.state.audit.clone(),
            &key,
            limits,
        )
        .expect("relay server");
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(server.serve(listener, stop_rx));
        self.relays
            .lock()
            .expect("relays lock poisoned")
            .push((stop, task));
    }

    /// Stop every relay this broker runs, as on shutdown, and wait until
    /// they have ended their sessions.
    ///
    /// # Panics
    /// If a relay task failed.
    pub async fn stop_relay(&self) {
        let relays = std::mem::take(&mut *self.relays.lock().expect("relays lock poisoned"));
        for (stop, task) in relays {
            stop.send_replace(true);
            task.await.expect("relay task");
        }
    }
}

/// Accept HTTP/1 connections for `router` until aborted. The connections are
/// owned by this task, so aborting it closes them all.
async fn serve_connections(listener: tokio::net::TcpListener, router: Router) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let service = hyper_util::service::TowerToHyperService::new(router.clone());
                connections.spawn(async move {
                    // A connection error only ends that connection.
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// Stand-in for Tailscale Serve: the caller is always the owner, whatever
/// identity header the client sent.
async fn as_owner(mut req: Request<Body>) -> Request<Body> {
    req.headers_mut().insert(
        "Tailscale-User-Login",
        axum::http::HeaderValue::from_static(TEST_OWNER),
    );
    req
}
