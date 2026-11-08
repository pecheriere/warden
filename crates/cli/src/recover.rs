//! Picking up after a `warden request` that is gone: listing what is pending
//! on the broker, and starting to use what the owner approved meanwhile.
//!
//! An api grant needs nothing but the agent's own login, so it can be collected
//! later. An SSH grant cannot: `warden request ssh` makes its key for the run and
//! keeps it only in memory, by design (see `docs/threat-model.md`), so the key is
//! lost with the run.

use anyhow::Result;
use warden_broker_proto::doctor::sanitize;
use warden_broker_proto::{Access, GrantAccess, GrantView, Id, PendingRequest};

use crate::client::Client;
use crate::request::{announce, api_scope};
use crate::{EXIT_ERROR, EXIT_NO_GRANT, Exit, agent, client, http, local_time};

/// The ids of the grants recorded on this machine. A record that cannot be read
/// counts for nothing here; `warden status` shows it as unreadable.
pub fn local_grant_ids() -> Result<Vec<Id>> {
    let ssh = agent::load_grants(&agent::grants_dir()?)
        .into_iter()
        .filter_map(|(_, record)| record.ok().map(|r| r.grant_id));
    let api = http::load()?
        .into_iter()
        .filter_map(|(_, record)| record.ok().map(|r| r.grant_id));
    Ok(ssh.chain(api).collect())
}

/// What `warden status` adds to a live grant of this agent that is not recorded
/// on this machine, which is empty for one that is.
pub fn elsewhere_note(grant: &GrantView, local: &[Id]) -> String {
    let id = &grant.grant_id;
    if local.contains(id) {
        return String::new();
    }
    match grant.access {
        GrantAccess::Api(_) => {
            format!("  (not on this machine; to use it: warden request collect {id})")
        }
        GrantAccess::Ssh(_) | GrantAccess::Relay(_) => format!(
            "  (not on this machine; if the `warden request` for it is gone, so is its key: \
             warden revoke {id})"
        ),
        // The broker signs under the grant: there is nothing to have on a machine.
        GrantAccess::CommitSigning(_) => String::new(),
    }
}

/// One line of `warden status` about an api grant recorded here. The origin is a
/// plain string from the broker, kept as it came, so it is made safe to print.
pub fn api_record_line(record: &http::ApiRecord) -> String {
    sanitize(&format!(
        "  api:{}  {}  grant {}  until {}",
        record.secret,
        record.origin,
        record.grant_id,
        local_time(record.not_after)
    ))
}

/// One line of `warden status` about a live grant on the broker, given the grants
/// `local` to this machine. Hosts and key fingerprints are plain strings from the
/// broker, so the line is made safe to print.
pub fn broker_grant_line(grant: &GrantView, local: &[Id]) -> String {
    let subject = match &grant.access {
        GrantAccess::Ssh(ssh) => format!("{}@{}:{}", ssh.user, ssh.host, ssh.port),
        GrantAccess::Api(api) => format!("api:{}", api.secret),
        GrantAccess::Relay(relay) => format!("{}@{} via relay", relay.user, relay.target),
        GrantAccess::CommitSigning(signing) => {
            format!("commit signing with {}", signing.key_fingerprint)
        }
    };
    sanitize(&format!(
        "  {subject}  grant {}  until {}{}",
        grant.grant_id,
        local_time(grant.not_after),
        elsewhere_note(grant, local)
    ))
}

/// The access of a pending request, in one line. Names are validated when they
/// are parsed; the rest of an api scope is not, so it is made safe to print.
fn access_summary(access: &Access) -> String {
    match access {
        Access::Ssh { target, user, .. } => format!("ssh {user}@{target}"),
        Access::Api {
            secret,
            methods,
            path_prefix,
        } => {
            let methods = methods
                .as_ref()
                .map_or_else(|| "read-only".to_owned(), |m| sanitize(&m.join(",")));
            match path_prefix {
                Some(path) => format!("api:{secret} {methods} under {}", sanitize(path)),
                None => format!("api:{secret} {methods}"),
            }
        }
        Access::CommitSigning {} => "commit signing".to_owned(),
    }
}

/// One line about a pending request. It holds all that the fingerprint depends on,
/// so that the same command can be written again from it. A goal may hold line and
/// paragraph separators, and a stored request with one must stay readable, so the
/// line is made safe to print here, where an agent's text must not pass for a line
/// of its own.
fn pending_line(request: &PendingRequest) -> String {
    let session = request
        .session
        .as_ref()
        .map_or_else(String::new, |label| format!("  session: {label}"));
    let link = request
        .link
        .as_ref()
        .map_or_else(String::new, |link| format!("  link: {link}"));
    sanitize(&format!(
        "  {} for {}  request {}  fingerprint {} ({})  made {}  expires {}{session}{link}  goal: {}",
        access_summary(&request.access),
        request.window.label(),
        request.id,
        request.fingerprint.words(),
        request.fingerprint,
        local_time(request.created_at),
        local_time(request.expires_at),
        request.goal,
    ))
}

/// The `warden status` section on the agent's pending requests.
///
/// # Errors
/// If the broker cannot be reached or refuses.
pub async fn print_pending(client: &Client) -> Result<()> {
    match client.pending().await? {
        Some(requests) => {
            println!("pending requests:");
            for request in &requests {
                println!("{}", pending_line(request));
            }
        }
        None => println!("pending requests: this broker cannot list them; it needs an upgrade"),
    }
    Ok(())
}

/// What collecting `grant_id` comes to, given this agent's `live` grants and the
/// grants `local` to this machine.
enum Collected {
    AlreadyHere(GrantView),
    NewApiRecord(GrantView, http::ApiRecord),
    /// A live grant that works with nothing on this machine, so nothing is written.
    NothingToCollect(String),
}

fn plan(grant_id: &Id, live: Vec<GrantView>, local: &[Id]) -> Result<Collected, String> {
    let Some(grant) = live.into_iter().find(|g| g.grant_id == *grant_id) else {
        return Err(format!(
            "no live grant {grant_id} for this agent: it expired, was revoked or is not yours. \
             `warden status` lists your grants and pending requests"
        ));
    };
    if local.contains(grant_id) {
        return Ok(Collected::AlreadyHere(grant));
    }
    match &grant.access {
        GrantAccess::Api(api) => {
            let record = http::ApiRecord::new(grant_id.clone(), api, grant.not_after);
            Ok(Collected::NewApiRecord(grant, record))
        }
        GrantAccess::Ssh(_) | GrantAccess::Relay(_) => Err(format!(
            "grant {grant_id} cannot be collected: its key was made by the `warden request ssh` \
             that asked for it and kept only in that run's memory. If that run is gone, so is the \
             key, and nothing can use this grant. End it with `warden revoke {grant_id}`, then \
             make a new request if the task still needs the access"
        )),
        GrantAccess::CommitSigning(_) => Ok(Collected::NothingToCollect(format!(
            "grant {grant_id} has nothing to collect: it is live, and the broker signs under it, \
             so it needs nothing on this machine. Once `warden setup git` has run here, `git \
             commit` uses it"
        ))),
    }
}

/// `warden request collect`: record a live api grant of this agent on this
/// machine, so `warden http` can use it. This gives no access the agent did not
/// have: the grant is already approved and answers to the agent's login anywhere.
///
/// # Errors
/// [`Exit`] with [`EXIT_NO_GRANT`] when no usable grant can be collected, which
/// calls for a new request, and with [`EXIT_ERROR`] for a commit signing grant,
/// which does not; a failed call or write.
pub async fn collect(grant_id: &Id) -> Result<()> {
    let (_, client) = client()?;
    let live = client.grants().await?;
    let grant = match plan(grant_id, live, &local_grant_ids()?) {
        Ok(Collected::AlreadyHere(grant)) => grant,
        Ok(Collected::NewApiRecord(grant, record)) => {
            http::save(&record)?;
            grant
        }
        Ok(Collected::NothingToCollect(message)) => {
            return Err(Exit::new(EXIT_ERROR, message).into());
        }
        Err(message) => return Err(Exit::new(EXIT_NO_GRANT, message).into()),
    };
    announce(&grant);
    if let GrantAccess::Api(api) = &grant.access {
        println!("{}", api_scope(api));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::{
        ApiGrant, CommitSigningGrant, GrantAccess, GrantView, Id, RelayGrant, Window,
    };

    use super::{
        Collected, access_summary, api_record_line, broker_grant_line, elsewhere_note,
        pending_line, plan,
    };
    use crate::http::ApiRecord;
    use warden_broker_proto::{Access, PendingRequest};

    fn api_grant() -> GrantView {
        GrantView {
            grant_id: Id::random(),
            not_before: 100,
            not_after: 200,
            access: GrantAccess::Api(ApiGrant {
                secret: "home-api".parse().unwrap(),
                origin: "https://api.example.com".to_owned(),
                methods: vec!["GET".to_owned()],
                path_prefix: "/".to_owned(),
                header: "Authorization".to_owned(),
                digest: "d".repeat(64),
            }),
        }
    }

    fn relay_grant() -> GrantView {
        GrantView {
            grant_id: Id::random(),
            not_before: 100,
            not_after: 200,
            access: GrantAccess::Relay(RelayGrant {
                target: "switch-01".parse().unwrap(),
                user: "build-agent".parse().unwrap(),
                relay_host: "warden.example.ts.net".to_owned(),
                relay_port: 2222,
                relay_host_key: "ssh-ed25519 AAAA".to_owned(),
                digest: "d".repeat(64),
            }),
        }
    }

    #[test]
    fn an_api_grant_is_collected_and_records_its_scope() {
        let grant = api_grant();
        let id = grant.grant_id.clone();
        let Ok(Collected::NewApiRecord(_, record)) = plan(&id, vec![grant], &[]) else {
            panic!("expected a new record");
        };
        assert_eq!(record.grant_id, id);
        assert_eq!(record.not_after, 200);
    }

    #[test]
    fn a_grant_already_here_is_not_recorded_again() {
        for grant in [api_grant(), relay_grant()] {
            let id = grant.grant_id.clone();
            assert!(matches!(
                plan(&id, vec![grant], std::slice::from_ref(&id)),
                Ok(Collected::AlreadyHere(_))
            ));
        }
    }

    #[test]
    fn an_ssh_grant_from_a_lost_run_says_the_key_is_gone_and_how_to_end_it() {
        let grant = relay_grant();
        let id = grant.grant_id.clone();
        let Err(message) = plan(&id, vec![grant], &[]) else {
            panic!("expected a refusal");
        };
        assert!(
            message.contains("kept only in that run's memory"),
            "{message}"
        );
        assert!(
            message.contains(&format!("warden revoke {id}")),
            "{message}"
        );
    }

    #[test]
    fn a_signing_grant_has_nothing_to_collect_and_no_note() {
        let grant = GrantView {
            grant_id: Id::random(),
            not_before: 100,
            not_after: 200,
            access: GrantAccess::CommitSigning(CommitSigningGrant {
                key_fingerprint: "SHA256:abc".to_owned(),
                digest: "d".repeat(64),
            }),
        };
        assert_eq!(elsewhere_note(&grant, &[]), "");
        let id = grant.grant_id.clone();
        let Ok(Collected::NothingToCollect(message)) = plan(&id, vec![grant], &[]) else {
            panic!("expected nothing to collect");
        };
        assert!(message.contains(&id.to_string()), "{message}");
        assert!(message.contains("warden setup git"), "{message}");
    }

    /// Whether `line` could pass for more than one line to any parser: Python's
    /// `splitlines()`, for one, also splits on these two.
    fn is_one_clean_line(line: &str) -> bool {
        !line
            .chars()
            .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
    }

    #[test]
    fn a_goal_cannot_forge_a_line_of_status() {
        for separator in ['\u{2028}', '\u{2029}'] {
            let goal = format!("read it{separator}  ssh root@switch-01 for 4h  request x");
            let line = pending_line(&PendingRequest {
                id: Id::random(),
                fingerprint: "ab02-cd02-ef02".to_owned().try_into().unwrap(),
                goal: goal.try_into().unwrap(),
                access: Access::CommitSigning {},
                window: Window::M15,
                session: None,
                link: None,
                created_at: 100,
                expires_at: 700,
            });
            assert!(is_one_clean_line(&line), "{line:?}");
            assert!(
                line.contains("goal: read it?  ssh root@switch-01"),
                "{line:?}"
            );
        }
    }

    #[test]
    fn an_origin_from_the_broker_cannot_reach_the_terminal_raw() {
        let mut grant = api_grant();
        let GrantAccess::Api(api) = &mut grant.access else {
            panic!("expected an api grant");
        };
        api.origin = "https://api.example.com\u{1b}[2J\n\u{2028}  forged".to_owned();
        let record = ApiRecord::new(grant.grant_id.clone(), api, grant.not_after);
        let line = api_record_line(&record);
        assert!(is_one_clean_line(&line), "{line:?}");
        assert!(line.contains("https://api.example.com"), "{line:?}");
        assert!(line.contains(&grant.grant_id.to_string()), "{line:?}");
    }

    #[test]
    fn a_broker_grant_line_is_made_safe_and_keeps_its_note() {
        let mut signing = GrantView {
            grant_id: Id::random(),
            not_before: 100,
            not_after: 200,
            access: GrantAccess::CommitSigning(CommitSigningGrant {
                key_fingerprint: "SHA256:abc\u{1b}[2J\u{2029}forged".to_owned(),
                digest: "d".repeat(64),
            }),
        };
        let line = broker_grant_line(&signing, &[]);
        assert!(is_one_clean_line(&line), "{line:?}");
        assert!(line.contains("commit signing with SHA256:abc"), "{line:?}");
        signing.access = api_grant().access;
        let line = broker_grant_line(&signing, &[]);
        assert!(line.contains("warden request collect"), "{line:?}");
    }

    #[test]
    fn a_pending_signing_request_says_what_it_is_for() {
        assert_eq!(access_summary(&Access::CommitSigning {}), "commit signing");
    }

    #[test]
    fn a_grant_that_is_not_live_is_refused() {
        let Err(message) = plan(&Id::random(), vec![api_grant()], &[]) else {
            panic!("expected a refusal");
        };
        assert!(message.contains("no live grant"), "{message}");
    }

    #[test]
    fn only_grants_missing_here_get_a_note_and_it_fits_their_kind() {
        let api = api_grant();
        assert_eq!(
            elsewhere_note(&api, std::slice::from_ref(&api.grant_id)),
            ""
        );
        assert!(elsewhere_note(&api, &[]).contains("warden request collect"));
        assert!(elsewhere_note(&relay_grant(), &[]).contains("so is its key"));
    }

    #[test]
    fn an_api_scope_from_the_broker_cannot_reach_the_terminal_raw() {
        let summary = access_summary(&Access::Api {
            secret: "home-api".parse().unwrap(),
            methods: Some(vec!["POST\u{1b}[2J".to_owned()]),
            path_prefix: Some("/api/\u{1b}]0;x\u{7}".to_owned()),
        });
        assert!(!summary.chars().any(char::is_control), "{summary:?}");
        assert!(summary.starts_with("api:home-api POST"), "{summary:?}");
    }

    #[test]
    fn the_scope_collect_prints_cannot_reach_the_terminal_raw() {
        let scope = crate::request::api_scope(&ApiGrant {
            secret: "home-api".parse().unwrap(),
            origin: "https://api.example.com\u{1b}[2J".to_owned(),
            methods: vec!["POST\u{1b}[2J".to_owned(), "GET\u{202e}".to_owned()],
            path_prefix: "/api/\u{1b}]0;x\u{7}\n".to_owned(),
            header: "Authorization".to_owned(),
            digest: "d".repeat(64),
        });
        assert_eq!(scope, warden_broker_proto::doctor::sanitize(&scope));
        assert!(!scope.chars().any(char::is_control), "{scope:?}");
        assert!(!scope.contains('\u{202e}'), "{scope:?}");
        assert!(scope.starts_with("scope: can modify: POST"), "{scope:?}");
        assert!(scope.contains("https://api.example.com"), "{scope:?}");
    }

    #[test]
    fn a_pending_line_names_what_an_agent_needs_to_act() {
        let line = pending_line(&PendingRequest {
            id: Id::random(),
            fingerprint: "ab02-cd02-ef02".to_owned().try_into().unwrap(),
            goal: "read the thermostat".to_owned().try_into().unwrap(),
            access: Access::Api {
                secret: "home-api".parse().unwrap(),
                methods: None,
                path_prefix: None,
            },
            window: Window::M15,
            session: Some("build-work".to_owned().try_into().unwrap()),
            link: Some("https://git.example.com/a".to_owned().try_into().unwrap()),
            created_at: 100,
            expires_at: 700,
        });
        for part in [
            "api:home-api read-only for 15m",
            "(ab02-cd02-ef02)",
            "session: build-work",
            "link: https://git.example.com/a",
            "goal: read the thermostat",
        ] {
            assert!(line.contains(part), "{line}");
        }
    }
}
