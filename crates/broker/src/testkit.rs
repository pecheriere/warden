//! Test helpers: a settable clock, notifiers that capture or fail, a fake
//! policy backend and an in-process broker driven with soft passkeys.
//!
//! Compiled only with the `testkit` feature; never part of a release build.

mod backend;
mod broker;
mod clock;
mod notify;
pub mod sshd;
pub mod upstream;

pub use backend::{CaState, FakeBackend};
pub use broker::{BaseUrls, LiveHold, TestBroker, TestResponse, request_signature};
pub use clock::ManualClock;
pub use notify::{CapturingNotifier, FailingNotifier};
pub use upstream::{HttpsUpstream, Received};

use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

/// Owner login the test broker accepts.
pub const TEST_OWNER: &str = "owner@example.com";

/// Public URL (and `WebAuthn` origin) of the test broker.
pub const TEST_ORIGIN: &str = "https://warden.test";

/// Time the test broker's clock starts at, Unix seconds.
pub const TEST_START: i64 = 1_800_000_000;

/// Host of the default `pi` target.
pub const PI_HOST: &str = "192.0.2.10";

/// Host of [`FakeBackend::relay_target`].
pub const NAS_HOST: &str = "192.0.2.20";

/// Host of the relay's public address in a [`TestBroker`] (unless built
/// without a relay).
pub const RELAY_PUBLIC_HOST: &str = "relay.warden.test";

/// Port of the relay's public address in a [`TestBroker`].
pub const RELAY_PUBLIC_PORT: u16 = 2222;

/// A software passkey that claims user verification, as Face ID would.
pub type SoftAuthenticator = WebauthnAuthenticator<SoftPasskey>;
