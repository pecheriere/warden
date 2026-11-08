//! What the CLI tells an agent when access ended or is missing: what happened
//! and what to do next, so it needs no person to explain. The next step is
//! never a way around the owner's decision.
//!
//! These messages hold names, ids and the broker's sanitized words, never a
//! secret.

use warden_broker_proto::{CreatedResponse, Id, RequestStatus, SecretName, TargetName};

use crate::request::{PENDING_EXPIRY_SECS, status_word};

/// Explains the placeholders of a suggested `warden request`.
pub const REQUEST_PLACEHOLDERS: &str = "window: the shortest of 15m, 30m, 1h or 4h that covers \
                                        the work; goal: what you will do and why";

/// The error for a request that ended without a grant.
pub fn request_ended(status: &RequestStatus) -> String {
    match status {
        RequestStatus::Denied => "request denied by the owner. Do not send the same request \
                                  again or look for another way in: ask the owner what to change"
            .to_owned(),
        RequestStatus::Expired => "request expired: the owner did not decide in time and may be \
                                   away. Tell the owner you need the access, and try again \
                                   later, not in a loop"
            .to_owned(),
        RequestStatus::Revoked => "request revoked: its grant was ended, or this agent was \
                                   disabled. Ask the owner before requesting access again"
            .to_owned(),
        other => format!("request {}", status_word(other)),
    }
}

/// Said when the broker's request is this one without its session label and link.
pub const CONTEXT_NOT_SHOWN: &str = "the owner does not see this session label or link: this \
     broker may be too old to know them, or the same request without them is already pending";

/// The error for a request the broker answered with `pending`, whose
/// fingerprint is not the one this request has. `subject` names the target or
/// secret. All the CLI knows is that the fingerprints differ, so this says no
/// more about why, or about when `pending` was made. The broker's answer has no
/// expiry time, so this gives the upper limit.
pub fn already_pending(subject: &str, pending: &CreatedResponse) -> String {
    format!(
        "a request {subject} is pending (id {id}, fingerprint {words} ({fingerprint})), and its \
         fingerprint differs from this request's, so warden is not waiting on it. It expires within {minutes} \
         minutes of being made, unless the owner decides it first. To withdraw it: warden request \
         cancel {id}",
        id = pending.id,
        words = pending.fingerprint.words(),
        fingerprint = pending.fingerprint,
        minutes = PENDING_EXPIRY_SECS / 60,
    )
}

/// The error for `warden ssh` without an active grant for `target`.
pub fn no_ssh_grant(target: &TargetName) -> String {
    format!(
        "no active grant for {target}: none was requested from this machine, or it expired or \
         was revoked. If the task needs it, ask the owner with: warden request ssh {target} \
         --user <user> --for <window> --goal <goal> (user: the least privileged account; \
         {REQUEST_PLACEHOLDERS})"
    )
}

/// The error for `warden ssh-config --min-remaining` when even the active
/// grant for `target` that stays valid longest, `grant`, ends within `wanted`:
/// it has `remaining` left.
pub fn ssh_grant_ends_too_soon(
    target: &TargetName,
    grant: &Id,
    remaining: jiff::SignedDuration,
    wanted: jiff::SignedDuration,
) -> String {
    format!(
        "the active grant for {target} ({grant}) ends in {remaining:#}, sooner than the \
         {wanted:#} asked for with --min-remaining. If the task needs longer, ask the owner \
         with: warden request ssh {target} --user <user> --for <window> --goal <goal> (user: \
         the least privileged account; {REQUEST_PLACEHOLDERS})"
    )
}

/// The error for `warden http` without an active grant for the item `name`.
pub fn no_api_grant(name: &SecretName) -> String {
    format!(
        "no active api grant for {name}: none was requested from this machine, or it expired \
         or was revoked. If the task needs it, ask the owner with: warden request api {name} \
         --for <window> --goal <goal> (read-only; add --methods only for a change the task must \
         make; {REQUEST_PLACEHOLDERS})"
    )
}

/// The error for a call refused because `grant` was revoked. `broker` is the
/// broker's message.
pub fn api_grant_revoked(grant: &Id, name: &SecretName, broker: &str) -> String {
    // Only a call already out can have reached the API; one refused at the door
    // cannot have.
    let out = if broker.ends_with(DURING_THE_CALL) {
        " No response was returned, and the call was already out, so it may have taken \
         effect: find out before repeating it."
    } else {
        ""
    };
    format!(
        "grant {grant} for {name} was revoked on the broker ({broker}).{out} The owner may have \
         ended it on purpose: check with them, then if the task still needs it use: warden \
         request api {name} --for <window> --goal <goal> ({REQUEST_PLACEHOLDERS})"
    )
}

/// How the broker's message ends for a grant that ended while the call was out.
const DURING_THE_CALL: &str = "during the call";

/// The error for a call the broker stopped while it was out, as it could not
/// tell if `grant` still holds. `broker` is the broker's message.
pub fn api_call_stopped(grant: &Id, name: &SecretName, broker: &str) -> String {
    format!(
        "the broker stopped this call using grant {grant} for {name} ({broker}). No response was \
         returned, and the call was already out, so it may have taken effect: find out before \
         repeating it. The broker could not read the grant's state: if it stays this way, tell \
         the owner."
    )
}

/// The error for a call refused because `grant` ran out, which the local
/// clock did not expect or which happened while the call was out. `broker` is
/// the broker's message.
pub fn api_grant_expired(grant: &Id, name: &SecretName, broker: &str) -> String {
    format!(
        "grant {grant} for {name} has expired ({broker}). No response was returned, and a call \
         that was already out may have taken effect. If the task still needs it, ask the owner \
         with: warden request api {name} --for <window> --goal <goal> ({REQUEST_PLACEHOLDERS})"
    )
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use warden_broker_proto::{CreatedResponse, Id, RequestStatus};

    use super::{
        already_pending, api_call_stopped, api_grant_expired, api_grant_revoked, no_api_grant,
        no_ssh_grant, request_ended,
    };
    use crate::Cli;
    use crate::config::Config;

    #[test]
    fn only_a_call_already_out_warns_it_may_have_taken_effect() {
        let id = Id::random();
        let name = warden_broker_proto::SecretName::try_from("svc".to_owned()).unwrap();
        let warning = "may have taken effect";
        let refused = api_grant_revoked(&id, &name, "broker refused (409): grant revoked");
        assert!(!refused.contains(warning), "{refused}");
        let stopped = api_grant_revoked(
            &id,
            &name,
            "broker refused (409): grant revoked during the call",
        );
        assert!(stopped.contains(warning), "{stopped}");
        let unknown = api_call_stopped(
            &id,
            &name,
            "broker error (503 Service Unavailable): grant state unavailable during the call",
        );
        assert!(unknown.contains(warning), "{unknown}");
    }

    #[test]
    fn denied_says_not_to_retry_and_whom_to_ask() {
        let message = request_ended(&RequestStatus::Denied);
        assert!(message.contains("denied"), "{message}");
        assert!(
            message.contains("Do not send the same request"),
            "{message}"
        );
        assert!(message.contains("ask the owner"), "{message}");
    }

    #[test]
    fn expired_request_says_not_to_loop() {
        let message = request_ended(&RequestStatus::Expired);
        assert!(message.contains("expired"), "{message}");
        assert!(message.contains("not in a loop"), "{message}");
    }

    #[test]
    fn revoked_request_sends_the_agent_to_the_owner() {
        let message = request_ended(&RequestStatus::Revoked);
        assert!(message.contains("revoked"), "{message}");
        assert!(message.contains("Ask the owner"), "{message}");
    }

    #[test]
    fn cancelled_stays_plain() {
        assert_eq!(
            request_ended(&RequestStatus::Cancelled),
            "request cancelled"
        );
    }

    /// The command a message suggests, with its placeholders filled in as an
    /// agent would, must be one the CLI takes.
    fn assert_suggests_a_valid_command(message: &str) {
        let (_, rest) = message.split_once("warden ").unwrap();
        let (command, _) = rest.split_once(" (").unwrap();
        let line = format!("warden {command}")
            .replace("<user>", "build-agent")
            .replace("<window>", "15m")
            .replace("<goal>", "goal");
        let parsed = Cli::try_parse_from(line.split_whitespace());
        assert!(parsed.is_ok(), "{line}: {:?}", parsed.err());
    }

    #[test]
    fn no_grant_messages_name_a_valid_request_and_the_reasons() {
        let ssh = no_ssh_grant(&"web-01".parse().unwrap());
        assert_suggests_a_valid_command(&ssh);
        let api = no_api_grant(&"home-api".parse().unwrap());
        assert_suggests_a_valid_command(&api);
        for message in [ssh, api] {
            assert!(message.contains("expired or"), "{message}");
            assert!(message.contains("the shortest of"), "{message}");
        }
    }

    /// The vectors the proto and broker tests share, computed outside the Rust.
    #[test]
    fn already_pending_shows_both_forms_of_the_shared_vectors() {
        let raw = include_str!("../../proto/tests/fixtures/fingerprint-words-v1.json");
        let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let message = already_pending(
                "for switch-01",
                &CreatedResponse {
                    id: Id::random(),
                    fingerprint: vector["hex"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                        .try_into()
                        .unwrap(),
                },
            );
            let shown = format!(
                "fingerprint {} ({})",
                vector["words"].as_str().unwrap(),
                vector["hex"].as_str().unwrap()
            );
            assert!(message.contains(&shown), "{shown}: {message}");
        }
    }

    #[test]
    fn already_pending_names_the_id_the_expiry_and_a_valid_cancel() {
        let id = Id::random();
        let message = already_pending(
            "for switch-01",
            &CreatedResponse {
                id: id.clone(),
                fingerprint: "ab02-cd02-ef02".to_owned().try_into().unwrap(),
            },
        );
        assert!(message.contains("for switch-01"), "{message}");
        assert!(message.contains("ab02-cd02-ef02"), "{message}");
        assert!(message.contains("within 10 minutes"), "{message}");
        assert!(message.contains("not waiting on it"), "{message}");
        let (_, command) = message.rsplit_once(": ").unwrap();
        assert_eq!(command, format!("warden request cancel {id}"));
        let parsed = Cli::try_parse_from(command.split_whitespace());
        assert!(parsed.is_ok(), "{command}: {:?}", parsed.err());
    }

    #[test]
    fn covering_message_names_a_valid_request() {
        let message =
            crate::http::no_covering_message(&"home-api".parse().unwrap(), "post", "/api/x");
        assert_suggests_a_valid_command(&message);
    }

    #[test]
    fn ended_grant_messages_name_the_grant_and_a_valid_request() {
        let id = Id::random();
        let name = "home-api".parse().unwrap();
        for message in [
            api_grant_revoked(&id, &name, "broker refused (409): grant revoked"),
            api_grant_expired(&id, &name, "broker refused (409): grant expired"),
        ] {
            assert!(message.contains(&id.to_string()), "{message}");
            assert!(message.contains("broker refused (409)"), "{message}");
            assert_suggests_a_valid_command(&message);
        }
    }

    /// A shell-like split: spaces separate words, except inside quotes.
    fn words(line: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut word: Option<String> = None;
        let mut quote = None;
        for c in line.chars() {
            match (quote, c) {
                (Some(q), c) if c == q => quote = None,
                (None, '"' | '\'') => {
                    quote = Some(c);
                    word.get_or_insert_default();
                }
                (None, c) if c.is_whitespace() => words.extend(word.take()),
                (_, c) => word.get_or_insert_default().push(c),
            }
        }
        assert!(quote.is_none(), "unbalanced quote in {line}");
        words.extend(word);
        words
    }

    /// Fill in a placeholder the documents use, so the word parses. A quoted
    /// goal placeholder holds spaces, is a valid goal and stays as it is.
    fn filled(word: &str) -> String {
        match word {
            "<target>" => "web-01".to_owned(),
            "<user>" => "build-agent".to_owned(),
            "<window>" => "15m".to_owned(),
            "<secret>" => "home-api".to_owned(),
            "<METHOD>" => "GET".to_owned(),
            "<url>" => "https://home.example.com/api/states".to_owned(),
            "<prefix>" => "/api/".to_owned(),
            "<grant-id>" | "<request-id>" => Id::random().to_string(),
            "<command>" => "uptime".to_owned(),
            other => {
                assert!(
                    !other.starts_with('<') || other.contains(' '),
                    "unknown placeholder {other}"
                );
                other.to_owned()
            }
        }
    }

    /// Every `warden` command line in `doc`, with its continuation lines.
    fn commands(doc: &str) -> Vec<String> {
        const SUBCOMMANDS: [&str; 7] = [
            "login", "request", "ssh", "http", "status", "revoke", "doctor",
        ];
        let mut found = Vec::new();
        let mut lines = doc.lines();
        while let Some(line) = lines.next() {
            let line = line.trim_start();
            let is_command = line
                .strip_prefix("warden ")
                .is_some_and(|rest| SUBCOMMANDS.iter().any(|s| rest.starts_with(s)));
            if !is_command {
                continue;
            }
            let mut command = line.to_owned();
            while command.ends_with('\\') {
                command.pop();
                command.push_str(lines.next().unwrap());
            }
            found.push(command);
        }
        found
    }

    /// The documents an agent copies from must only hold commands the CLI
    /// accepts, with goals, windows and names it accepts.
    #[test]
    fn documented_commands_match_the_cli() {
        for (name, doc, least) in [
            (
                "agent-instructions",
                include_str!("../../../docs/agent-instructions.md"),
                6,
            ),
            (
                "agent-examples",
                include_str!("../../../docs/agent-examples.md"),
                8,
            ),
        ] {
            let commands = commands(doc);
            assert!(commands.len() >= least, "{name}: {commands:?}");
            for command in commands {
                let args: Vec<String> = words(&command).iter().map(|w| filled(w)).collect();
                if let Err(e) = Cli::try_parse_from(&args) {
                    panic!("{name}: {command}: {e}");
                }
            }
        }
    }

    /// What `warden-server agent add` prints must be a command this CLI
    /// takes, whichever way the agent authenticates.
    #[test]
    fn enrollment_commands_match_the_cli() {
        use warden_broker::enrollment::{
            bearer_login_command, key_login_command, parse_agent_api_url,
        };
        let agent = "build-agent".parse().unwrap();
        let server = parse_agent_api_url("https://warden-api.example.ts.net").unwrap();
        let audience = "0123456789abcdef0123456789abcdef".parse().unwrap();
        for command in [
            bearer_login_command(&agent, Some(&server)),
            key_login_command(&agent, Some(&server), None),
            key_login_command(&agent, Some(&server), Some(&audience)),
        ] {
            let parsed = Cli::try_parse_from(command.split_whitespace());
            assert!(parsed.is_ok(), "{command}: {:?}", parsed.err());
        }
    }

    /// The Linux setup `agent add` prints for a bearer key is a configuration
    /// this CLI reads.
    #[test]
    fn enrollment_bearer_config_matches_the_cli() {
        use warden_broker::enrollment::{bearer_next_steps, parse_agent_api_url};
        let agent = "build-agent".parse().unwrap();
        let server = parse_agent_api_url("https://warden-api.example.ts.net").unwrap();
        let steps = bearer_next_steps(&agent, Some(&server));
        let toml = steps
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("server = ") || line.starts_with("agent = "))
            .collect::<Vec<_>>()
            .join("\n");
        let config: Config = toml::from_str(&toml).unwrap();
        assert_eq!(config.agent, agent);
        assert_eq!(config.server, server);
        assert!(config.ssh_key.is_none());
    }
}
