//! What `warden-server agent add` tells the owner to run on the agent machine.
//!
//! Nothing here takes a secret, so nothing here can print one. A bearer key
//! goes to stdout alone, as it always has; these texts go to stderr and use
//! only the agent's name, the agent API's URL and the broker's audience, none
//! of which is secret (`GET /v1/info` publishes the audience).
//!
//! The owner pastes the commands into a shell, so everything in them must be
//! safe there: agent names and audiences are validated by their types, and
//! [`parse_agent_api_url`] accepts only a plain origin.

use url::{Host, Url};
use warden_broker_proto::AgentName;
use warden_broker_proto::signing::Audience;

/// Stands for the agent API's URL when the owner did not give it.
const SERVER_PLACEHOLDER: &str = "<agent-api-url>";

/// Why a value is not the agent API's URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidAgentApiUrl(&'static str);

/// Parse the agent API's URL as agents log in with it: https (or http on
/// loopback), the root of the origin, and a host that means nothing to a
/// shell.
///
/// # Errors
/// [`InvalidAgentApiUrl`] saying what is wrong.
pub fn parse_agent_api_url(value: &str) -> Result<Url, InvalidAgentApiUrl> {
    let url = Url::parse(value).map_err(|_| InvalidAgentApiUrl("not a valid URL"))?;
    let loopback = match url.host() {
        Some(Host::Domain(name)) => {
            let plain = name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
            if !plain {
                return Err(InvalidAgentApiUrl(
                    "the host name may only have letters, digits, dots and hyphens",
                ));
            }
            name == "localhost"
        }
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err(InvalidAgentApiUrl("the URL has no host")),
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => {
            return Err(InvalidAgentApiUrl(
                "must use https, or http to a loopback address",
            ));
        }
    }
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(InvalidAgentApiUrl(
            "must be the root of the origin, such as https://warden-api.example.ts.net",
        ));
    }
    Ok(url)
}

fn server_text(server: Option<&Url>) -> &str {
    server.map_or(SERVER_PLACEHOLDER, |url| url.as_str().trim_end_matches('/'))
}

fn placeholder_note(server: Option<&Url>) -> String {
    if server.is_some() {
        String::new()
    } else {
        format!(
            "\nReplace {SERVER_PLACEHOLDER} with the agent API's URL. Next time, `agent add --server \
             <url>` fills it in.\n"
        )
    }
}

/// The login command for an agent that signs with an SSH key. The server
/// does not know where the `.pub` file is on the agent machine: the command
/// uses the path the documentation uses.
#[must_use]
pub fn key_login_command(
    agent: &AgentName,
    server: Option<&Url>,
    audience: Option<&Audience>,
) -> String {
    let server = server_text(server);
    let pin = audience.map_or_else(String::new, |audience| format!(" --audience {audience}"));
    format!("warden login --server {server} --agent {agent} --ssh-key ~/.ssh/{agent}.pub{pin}")
}

/// The login command for an agent with a bearer key. The key is not part of
/// it: `warden login` prompts for the key without echoing it, or reads it
/// from stdin.
#[must_use]
pub fn bearer_login_command(agent: &AgentName, server: Option<&Url>) -> String {
    format!(
        "warden login --server {} --agent {agent}",
        server_text(server)
    )
}

/// What to do on the machine of an agent that signs with an SSH key.
#[must_use]
pub fn key_next_steps(
    agent: &AgentName,
    server: Option<&Url>,
    audience: Option<&Audience>,
) -> String {
    let command = key_login_command(agent, server, audience);
    let note = placeholder_note(server);
    format!(
        "On the agent machine, run:\n\n  {command}\n\n--ssh-key is the path of the key's .pub \
         file there; change it if the file is elsewhere. The private key stays in the ssh-agent.\
         \nThen `warden doctor` checks the setup.\n{note}"
    )
}

/// What to do on the machine of an agent with a bearer key. Takes no key, so
/// the text cannot contain one.
#[must_use]
pub fn bearer_next_steps(agent: &AgentName, server: Option<&Url>) -> String {
    let command = bearer_login_command(agent, server);
    let note = placeholder_note(server);
    let server = server_text(server);
    format!(
        "On the agent machine:\n\n\
         macOS: run this, then paste the key at the prompt, or pipe the key into it from a \
         password manager. It goes into the login Keychain:\n\n  {command}\n\n\
         Linux: there is no Keychain, so `warden login` cannot store a bearer key. A signing key \
         is the better choice there (see `agent set-key`). Otherwise write \
         ~/.config/warden/config.toml, mode 0600:\n\n  \
         server = \"{server}\"\n  agent = \"{agent}\"\n\n\
         and set WARDEN_AGENT_KEY from a secret manager whenever warden runs.\n\n\
         Never put the key on a command line or in a repository. A bearer key works only from \
         a device of the owner's Tailscale login, not from a tagged machine.\n\
         Then `warden doctor` checks the setup.\n{note}"
    )
}

#[cfg(test)]
mod tests {
    use url::Url;
    use warden_broker_proto::AgentName;
    use warden_broker_proto::signing::Audience;

    use super::{
        bearer_login_command, bearer_next_steps, key_login_command, key_next_steps,
        parse_agent_api_url,
    };

    fn agent() -> AgentName {
        "build-agent".parse().unwrap()
    }

    fn server() -> Url {
        parse_agent_api_url("https://warden-api.example.ts.net").unwrap()
    }

    fn audience() -> Audience {
        "0123456789abcdef0123456789abcdef".parse().unwrap()
    }

    #[test]
    fn origins_are_accepted() {
        for good in [
            "https://warden-api.example.ts.net",
            "https://warden-api.example.ts.net/",
            "https://warden-api.example.ts.net:8443",
            "https://192.0.2.1",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(parse_agent_api_url(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn urls_that_cannot_be_logged_in_with_are_refused() {
        for bad in [
            "warden-api.example.ts.net",
            "http://warden-api.example.ts.net",
            "http://192.0.2.1:8080",
            "ftp://warden-api.example.ts.net",
            "https://warden-api.example.ts.net/api",
            "https://warden-api.example.ts.net/?a=b",
            "https://warden-api.example.ts.net/#a",
            "https://user:pass@warden-api.example.ts.net",
            "file:///etc/passwd",
        ] {
            assert!(parse_agent_api_url(bad).is_err(), "{bad}");
        }
    }

    /// The owner pastes the command into a shell.
    #[test]
    fn hosts_with_shell_characters_are_refused() {
        for bad in [
            "https://a$(id).example.com",
            "https://a`id`.example.com",
            "https://a;id.example.com",
            "https://a&id.example.com",
            "https://a'b.example.com",
        ] {
            assert!(parse_agent_api_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn key_command_is_exact() {
        assert_eq!(
            key_login_command(&agent(), Some(&server()), Some(&audience())),
            "warden login --server https://warden-api.example.ts.net --agent build-agent \
             --ssh-key ~/.ssh/build-agent.pub --audience 0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            key_login_command(&agent(), Some(&server()), None),
            "warden login --server https://warden-api.example.ts.net --agent build-agent \
             --ssh-key ~/.ssh/build-agent.pub"
        );
    }

    #[test]
    fn bearer_command_is_exact_and_holds_no_key() {
        assert_eq!(
            bearer_login_command(&agent(), Some(&server())),
            "warden login --server https://warden-api.example.ts.net --agent build-agent"
        );
    }

    #[test]
    fn steps_say_what_to_replace_only_when_the_url_is_unknown() {
        let known = key_next_steps(&agent(), Some(&server()), None);
        assert!(known.contains("--server https://warden-api.example.ts.net "));
        assert!(!known.contains("<agent-api-url>"), "{known}");
        let unknown = key_next_steps(&agent(), None, None);
        assert!(unknown.contains("--server <agent-api-url> "), "{unknown}");
        assert!(unknown.contains("Replace <agent-api-url>"), "{unknown}");

        let known = bearer_next_steps(&agent(), Some(&server()));
        assert!(!known.contains("<agent-api-url>"), "{known}");
        let unknown = bearer_next_steps(&agent(), None);
        assert!(unknown.contains("Replace <agent-api-url>"), "{unknown}");
    }

    #[test]
    fn steps_end_with_the_setup_check() {
        for steps in [
            key_next_steps(&agent(), Some(&server()), None),
            bearer_next_steps(&agent(), Some(&server())),
        ] {
            assert!(steps.contains("`warden doctor`"), "{steps}");
        }
    }

    #[test]
    fn bearer_steps_cover_both_platforms() {
        let steps = bearer_next_steps(&agent(), Some(&server()));
        assert!(
            steps.contains(
                "warden login --server https://warden-api.example.ts.net --agent build-agent"
            ),
            "{steps}"
        );
        assert!(steps.contains("Linux"), "{steps}");
        assert!(steps.contains("WARDEN_AGENT_KEY"), "{steps}");
        assert!(steps.contains("server = \"https://warden-api.example.ts.net\""));
        assert!(steps.contains("agent = \"build-agent\""), "{steps}");
    }
}
