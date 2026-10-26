//! Container health probe: `GET /healthz` on the agent API listener.
//!
//! The runtime image has no shell or curl, so the orchestrator runs
//! `warden-server healthcheck`, which needs only `WARDEN_API_LISTEN`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// Environment variable naming the agent API listen address.
const API_LISTEN_VAR: &str = "WARDEN_API_LISTEN";

/// Same default as [`crate::config::Config`].
const API_LISTEN_DEFAULT: &str = "127.0.0.1:8080";

/// Overall deadline for the probe, connect and response included.
const TIMEOUT: Duration = Duration::from_secs(3);

/// The agent API listen address, read through `lookup` (variable name to
/// value) with the server's default when unset or blank.
///
/// # Errors
///
/// If the value is not a socket address.
pub fn api_listen(lookup: impl Fn(&str) -> Option<String>) -> Result<SocketAddr> {
    let value = lookup(API_LISTEN_VAR)
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| API_LISTEN_DEFAULT.to_owned());
    value
        .parse()
        .with_context(|| format!("{API_LISTEN_VAR} is not a socket address"))
}

/// The address to connect to for a listener bound to `listen`: an
/// unspecified address (`0.0.0.0`, `::`) cannot be dialled, so use loopback.
#[must_use]
pub fn probe_target(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, listen.port())
}

/// `GET /healthz` on `listen` within three seconds.
///
/// # Errors
///
/// If the connection fails, times out, or the response is not a success.
pub async fn probe(listen: SocketAddr) -> Result<()> {
    let target = probe_target(listen);
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building the HTTP client")?;
    let response = client
        .get(format!("http://{target}/healthz"))
        .send()
        .await
        .with_context(|| format!("requesting http://{target}/healthz"))?;
    if !response.status().is_success() {
        bail!("http://{target}/healthz returned {}", response.status());
    }
    Ok(())
}
