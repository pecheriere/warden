//! The HTTP proxy for API secrets: checking an agent's request against the
//! secret's policy, and removing the secret from what comes back.

pub mod redact;
pub mod rules;

pub use redact::{Needles, redact};
pub use rules::{Prepared, Refusal, check};
