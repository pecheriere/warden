//! What `warden request` can say about where a request comes from: the session's
//! label and a link. Both are the agent's claim, for the owner to read.

use std::ffi::OsString;

use clap::Args;
use warden_broker_proto::{
    AgentName, CreateRequest, Fingerprint, SessionLabel, SessionLink, fingerprint,
};

/// Sets the label for every request made from this environment. An empty value
/// counts as unset, so a setup can export whatever it has.
pub const SESSION_ENV: &str = "WARDEN_SESSION";

/// The options, as given on the command line.
#[derive(Debug, Clone, Default, Args)]
pub struct RequestContext {
    /// This session's name, shown to the owner as stated by the agent, not as
    /// verified: one line, at most 64 characters. Default: `WARDEN_SESSION`.
    #[arg(long, value_name = "LABEL")]
    pub session: Option<SessionLabel>,
    /// A page about this work, shown to the owner as stated by the agent:
    /// https, no query or fragment, to a host the broker's owner has listed. Any
    /// other host refuses the request.
    // Parsed afterwards, not by clap, whose error would quote the value, which
    // could hold a credential.
    #[arg(long, value_name = "URL")]
    pub link: Option<String>,
}

impl RequestContext {
    /// The label and link to send, the label from `env` (the value of
    /// [`SESSION_ENV`]) if the option did not give one.
    ///
    /// # Errors
    /// What is wrong with them, without quoting the value.
    pub fn resolve(
        self,
        env: Option<OsString>,
    ) -> Result<(Option<SessionLabel>, Option<SessionLink>), String> {
        let session = match self.session {
            Some(session) => Some(session),
            None => session_from_env(env)?,
        };
        let link = self
            .link
            .map(|link| SessionLink::try_from(link).map_err(|e| format!("--link: {e}")))
            .transpose()?;
        Ok((session, link))
    }
}

fn session_from_env(env: Option<OsString>) -> Result<Option<SessionLabel>, String> {
    let Some(value) = env else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| format!("{SESSION_ENV}: not valid UTF-8"))?;
    if value.trim().is_empty() {
        return Ok(None);
    }
    SessionLabel::try_from(value)
        .map(Some)
        .map_err(|e| format!("{SESSION_ENV}: {e}"))
}

/// How the request a broker answered with compares to the one this CLI made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answered {
    /// The same request.
    Same,
    /// The same request without its label and link: the owner sees it so.
    WithoutContext,
    /// Another request.
    Other,
}

/// Compare `answered`, the fingerprint a broker answered with, to `req`. A broker
/// that does not know labels and links hashes the request without them.
#[must_use]
pub fn compare(answered: &Fingerprint, agent: &AgentName, req: &CreateRequest) -> Answered {
    if *answered == fingerprint(agent, req) {
        return Answered::Same;
    }
    let bare = CreateRequest {
        session: None,
        link: None,
        ..req.clone()
    };
    if *answered == fingerprint(agent, &bare) {
        Answered::WithoutContext
    } else {
        Answered::Other
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    use warden_broker_proto::{Access, AgentName, CreateRequest, Goal, Window, fingerprint};

    use super::{Answered, RequestContext, compare};

    fn context(session: Option<&str>, link: Option<&str>) -> RequestContext {
        RequestContext {
            session: session.map(|s| s.parse().unwrap()),
            link: link.map(ToOwned::to_owned),
        }
    }

    fn env(value: &str) -> OsString {
        OsString::from(value)
    }

    #[test]
    fn the_option_wins_over_the_environment() {
        let (session, _) = context(Some("flag"), None)
            .resolve(Some(env("from-env")))
            .unwrap();
        assert_eq!(session.unwrap().as_str(), "flag");
    }

    #[test]
    fn the_environment_fills_in_and_blank_counts_as_unset() {
        let (session, link) = context(None, None)
            .resolve(Some(env(" from-env ")))
            .unwrap();
        assert_eq!(session.unwrap().as_str(), "from-env");
        assert!(link.is_none());
        for blank in [None, Some(env("")), Some(env("   "))] {
            let (session, _) = context(None, None).resolve(blank).unwrap();
            assert!(session.is_none());
        }
    }

    #[test]
    fn a_bad_environment_value_is_refused_by_name() {
        let long = "x".repeat(65);
        for bad in [env(&long), env("a\nb"), env("a\u{202E}b")] {
            let message = context(None, None).resolve(Some(bad)).unwrap_err();
            assert!(message.starts_with("WARDEN_SESSION: "), "{message}");
        }
        let not_utf8 = OsString::from_vec(vec![0xff]);
        assert!(context(None, None).resolve(Some(not_utf8)).is_err());
        // The option's value makes the variable's irrelevant.
        assert!(
            context(Some("flag"), None)
                .resolve(Some(env(&long)))
                .is_ok()
        );
    }

    #[test]
    fn a_bad_link_is_refused_without_quoting_it() {
        for bad in [
            "http://example.com/hunter2",
            "https://user:hunter2@example.com/",
            "https://example.com/?hunter2",
        ] {
            let message = context(None, Some(bad)).resolve(None).unwrap_err();
            assert!(message.starts_with("--link: "), "{message}");
            assert!(!message.contains("hunter2"), "{message}");
        }
    }

    #[test]
    fn an_answer_is_this_request_this_request_without_context_or_another() {
        let agent: AgentName = "bot".parse().unwrap();
        let bare = CreateRequest {
            goal: "read the repos".parse::<Goal>().unwrap(),
            access: Access::Api {
                secret: "github".parse().unwrap(),
                methods: None,
                path_prefix: None,
            },
            window: Window::M15,
            session: None,
            link: None,
        };
        let labelled = CreateRequest {
            session: Some("one".parse().unwrap()),
            ..bare.clone()
        };
        let other_session = CreateRequest {
            session: Some("two".parse().unwrap()),
            ..bare.clone()
        };
        let other_goal = CreateRequest {
            goal: "something else".parse().unwrap(),
            ..bare.clone()
        };
        let of = |req: &CreateRequest| fingerprint(&agent, req);
        assert_eq!(compare(&of(&labelled), &agent, &labelled), Answered::Same);
        assert_eq!(compare(&of(&bare), &agent, &bare), Answered::Same);
        assert_eq!(
            compare(&of(&bare), &agent, &labelled),
            Answered::WithoutContext
        );
        assert_eq!(
            compare(&of(&other_session), &agent, &labelled),
            Answered::Other
        );
        assert_eq!(
            compare(&of(&other_goal), &agent, &labelled),
            Answered::Other
        );
        assert_eq!(compare(&of(&other_goal), &agent, &bare), Answered::Other);
        // A plain request does not take a labelled one for its own.
        assert_eq!(compare(&of(&labelled), &agent, &bare), Answered::Other);
    }

    #[test]
    fn a_good_link_is_normalized() {
        let (_, link) = context(None, Some("https://Git.Example.com"))
            .resolve(None)
            .unwrap();
        assert_eq!(link.unwrap().as_str(), "https://git.example.com/");
    }
}
