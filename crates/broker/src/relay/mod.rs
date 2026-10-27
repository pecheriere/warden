//! SSH relay mode: for targets that cannot trust the warden CA, the broker
//! relays the agent's session and logs in to the target with a credential
//! that never leaves it.
//!
//! The agent authenticates to the relay with the ephemeral public key bound
//! into the request the owner approved; see
//! [`crate::requests::Requests::active_relay_grant`].

use crate::config::RelayAddress;

use self::host_key::RelayHostKey;

pub mod host_key;
mod onward;
mod read_ahead;
mod server;
mod session;

pub use server::{RelayLimits, RelayServer};
pub(crate) use session::LiveSessions;

/// What a relay grant tells the agent: where the relay listens for it and
/// the relay's host key to pin. Public information only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    /// Host name or IP address agents connect to.
    pub host: String,
    /// Port agents connect to.
    pub port: u16,
    /// The relay's host public key, OpenSSH format.
    pub host_key: String,
}

impl RelayEndpoint {
    /// The endpoint at public address `addr` with host key `key`.
    ///
    /// # Errors
    /// If the public key cannot be encoded.
    pub fn new(addr: &RelayAddress, key: &RelayHostKey) -> Result<Self, host_key::HostKeyError> {
        Ok(Self {
            host: addr.host.clone(),
            port: addr.port,
            host_key: key.public_key_openssh()?,
        })
    }
}
