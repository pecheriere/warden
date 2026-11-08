//! Looking into a [`TestBroker`]: its state, live sessions and calls, and audit log.

use std::path::Path;

use serde_json::Value;
use warden_broker_proto::{AgentName, Id, TargetName, UnixUser};

use super::TestBroker;
use crate::AppState;
use crate::proxy::CallInfo;
use crate::requests::{Clock, RelayGrantRecord};

/// Keeps a relay session or proxy call listed as live while it is held.
#[derive(Debug)]
#[must_use]
pub struct LiveHold {
    _held: Box<dyn std::any::Any + Send>,
}

impl TestBroker {
    /// Shared state of the broker.
    #[must_use]
    pub const fn state(&self) -> &AppState {
        &self.state
    }

    /// The bytes `(to the target, from the target)` of each live relay
    /// session, oldest first.
    #[must_use]
    pub fn live_relay_bytes(&self) -> Vec<(u64, u64)> {
        self.state
            .requests
            .live_sessions()
            .snapshot()
            .into_iter()
            .map(|s| (s.bytes_to_target, s.bytes_from_target))
            .collect()
    }

    /// When bytes last moved (Unix seconds) in each live relay session,
    /// oldest first.
    #[must_use]
    pub fn live_relay_last_activity(&self) -> Vec<i64> {
        self.state
            .requests
            .live_sessions()
            .snapshot()
            .into_iter()
            .map(|s| s.last_activity)
            .collect()
    }

    /// List a relay session of `grant_id` (held by `agent`) as live, from
    /// now, until the returned hold is dropped.
    ///
    /// The target `pi`, user `alice` and empty destination digest are
    /// placeholders: the live listing never reads them. `not_after` is
    /// `i64::MAX` so that the expiry check never ends the hold; the grant
    /// itself expires as usual, which is what drops it from the listing.
    ///
    /// # Panics
    /// If the fixed sample target or user is invalid.
    pub fn hold_live_session(&self, grant_id: &Id, agent: &str) -> LiveHold {
        let grant = RelayGrantRecord {
            grant_id: grant_id.clone(),
            agent: AgentName::try_from(agent.to_owned()).expect("valid agent name"),
            target: TargetName::try_from("pi".to_owned()).expect("valid target name"),
            user: UnixUser::try_from("alice".to_owned()).expect("valid user"),
            destination_digest: String::new(),
            not_after: i64::MAX,
        };
        let registration = self
            .state
            .requests
            .live_sessions()
            .register(&grant, self.clock.now());
        LiveHold {
            _held: Box::new(registration),
        }
    }

    /// List an in-flight proxy call of `method` to `path` of `grant_id`
    /// (held by `agent`) from now, until the returned hold is dropped. Like
    /// the proxy, [`CallInfo::new`] drops anything from a `?` or `#` on.
    ///
    /// # Panics
    /// If the agent name is invalid or the proxy call limits are reached.
    pub fn hold_live_call(&self, grant_id: &Id, agent: &str, method: &str, path: &str) -> LiveHold {
        let agent = AgentName::try_from(agent.to_owned()).expect("valid agent name");
        let call = CallInfo::new(
            grant_id.clone(),
            method.to_owned(),
            path.to_owned(),
            self.clock.now(),
        );
        let slot = self
            .state
            .requests
            .proxy_calls()
            .try_acquire(&agent, call)
            .expect("proxy call slot");
        LiveHold {
            _held: Box::new(slot),
        }
    }

    /// Path of the audit log.
    #[must_use]
    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    /// The `type` of every audit entry, oldest first.
    ///
    /// # Panics
    /// If the log cannot be read.
    #[must_use]
    pub fn audit_types(&self) -> Vec<String> {
        std::fs::read_to_string(&self.audit_path)
            .expect("read audit log")
            .lines()
            .map(|line| {
                let v: Value = serde_json::from_str(line).expect("audit line is JSON");
                v["event"]["type"].as_str().expect("event type").to_owned()
            })
            .collect()
    }

    /// The `summary` of every `request_created` audit entry, oldest first.
    ///
    /// # Panics
    /// If the log cannot be read.
    #[must_use]
    pub fn audit_summaries(&self) -> Vec<String> {
        std::fs::read_to_string(&self.audit_path)
            .expect("read audit log")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
            .filter(|v| v["event"]["type"] == "request_created")
            .map(|v| v["event"]["summary"].as_str().expect("summary").to_owned())
            .collect()
    }
}
