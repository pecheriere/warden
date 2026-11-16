//! The text the agent reads when a signal fires.
//!
//! It depends on the command only through the [`Match`]es: a subject is a
//! host or a tool name, so nothing else of the command can reach the text.
//! The next step is always `warden`, or the owner, never a way around either.

use std::fmt::Write as _;

use crate::context::Coverage;
use crate::detect::Match;
use crate::settings::Signal;

/// The most matches the message lists; the rest are counted.
const MAX_LISTED: usize = 8;

const CLOSING: &str = "Never look for another way in.";

fn covered_ssh(target: &str, coverage: Option<&Coverage>) -> String {
    let cover = coverage.and_then(|c| c.ssh.iter().find(|cover| cover.name == target));
    let host = cover
        .and_then(|cover| cover.host.as_deref())
        .map_or_else(String::new, |host| format!(" ({host})"));
    let user = match cover.map(|cover| cover.users.as_slice()) {
        Some([only]) => only.clone(),
        Some([first, ..]) => format!("{first} (or another user the owner lists)"),
        _ => "<user>".to_owned(),
    };
    format!(
        "covered-ssh: this command reaches {target}{host} over SSH, and warden covers that \
         target. Run `warden status`; if no grant is active, ask the owner with `warden request \
         ssh {target} --user {user} --for 15m --goal \"<what and why>\"`, then run the command \
         through `warden ssh {target} -- <command>`."
    )
}

fn covered_api(host: &str, coverage: Option<&Coverage>) -> String {
    let cover = coverage.and_then(|c| c.api_for(host));
    let secret = cover.map_or("<secret>", |cover| cover.name.as_str());
    let url = cover.and_then(|cover| cover.origin.as_deref()).map_or_else(
        || format!("https://{host}/<path>"),
        |o| format!("{}/<path>", o.trim_end_matches('/')),
    );
    format!(
        "covered-api: this command calls {host}, and warden covers it through the API item \
         {secret}. Run `warden status`; if no grant is active, ask the owner with `warden \
         request api {secret} --for 15m --goal \"<what and why>\"`, then call it with `warden \
         http {secret} <METHOD> {url} --fail`."
    )
}

fn owner_credentials(signal: Signal, subject: &str) -> String {
    format!(
        "{}: `{subject}` uses the owner's own credentials. If warden covers what you need, use \
         warden (`warden list` shows what it offers). If not, ask the owner to add it to warden \
         (docs/1password-items.md). Do not use the owner's credentials meanwhile.",
        signal.key()
    )
}

/// The lines that point one checkout's git at warden for github.com, as
/// `docs/agent-usage.md` gives them.
const LOCAL_HELPER: &str = "  git config --local credential.https://github.com.helper \"\"\n  \
     git config --local --add credential.https://github.com.helper \"!$(command -v warden) \
     git-credential\"\n  git config --local credential.https://github.com.useHttpPath true";

fn owner_github(tool: &str) -> String {
    if tool == "git" {
        format!(
            "owner-github: this `git push` to github.com would use the owner's own GitHub \
             credential: git here does not ask warden for it. Run `warden status`, then point \
             this checkout at warden, once, and push again:\n{LOCAL_HELPER}\nWith no grant \
             active, the push asks the owner itself; to word the request, run `warden request \
             github <owner/name> --goal \"<what and why>\"` first."
        )
    } else {
        "owner-github: `gh` runs here with the owner's own GitHub login. Run `warden status`, \
         then give it a token from warden: `GH_TOKEN=$(warden github token --repo <owner/name>) \
         gh \u{2026}`. With no grant active, `warden github token` asks the owner itself; to \
         word the request, run `warden request github <owner/name> --goal \"<what and why>\"` \
         first."
            .to_owned()
    }
}

fn uncovered_host(host: &str) -> String {
    format!(
        "uncovered-host: {host}: warden does not list this host here. If the task needs it, ask \
         the owner to add a target or API secret item (docs/1password-items.md) so the next \
         session goes through warden. Do not use the owner's credentials for it meanwhile."
    )
}

/// The message for `matches`: one paragraph each, then the closing line.
/// Empty when there are no matches. `coverage` names the exact target or
/// secret from the offers when it is known.
#[must_use]
pub fn render(matches: &[Match], coverage: Option<&Coverage>) -> String {
    if matches.is_empty() {
        return String::new();
    }
    let mut text = String::new();
    for found in matches.iter().take(MAX_LISTED) {
        let paragraph = match found.signal {
            Signal::CoveredSsh => covered_ssh(&found.subject, coverage),
            Signal::CoveredApi => covered_api(&found.subject, coverage),
            Signal::UncoveredHost => uncovered_host(&found.subject),
            Signal::OwnerGithub => owner_github(&found.subject),
            Signal::OwnerSshKey | Signal::SecretStore | Signal::TokenRead => {
                owner_credentials(found.signal, &found.subject)
            }
        };
        // Writing to a String cannot fail.
        let _ = write!(text, "{paragraph}\n\n");
    }
    if let Some(more) = matches.len().checked_sub(MAX_LISTED).filter(|n| *n > 0) {
        let _ = write!(text, "\u{2026} and {more} more.\n\n");
    }
    text.push_str(CLOSING);
    text
}
