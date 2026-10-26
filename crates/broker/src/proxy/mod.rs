//! The HTTP proxy for API secrets: checking an agent's request against the
//! secret's policy, sending it with the secret, and removing the secret
//! from what comes back.

pub mod client;
pub mod redact;
pub mod rules;

pub use client::{ProxyError, ProxyLimits, Upstream, forward, redact_response};
pub use redact::{Needles, redact};
pub use rules::{OUTBOUND_ACCEPT_ENCODING, Prepared, Refusal, check};
