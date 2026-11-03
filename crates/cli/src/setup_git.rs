//! `warden setup git`: make git sign commits through the broker.
//!
//! Sets four values in git's global configuration, or the repository's with
//! `--local`. It writes nothing else: no hook, no alias, no key.

use std::process::{Command, Output};

use anyhow::{Context as _, Result, anyhow, bail};
use warden_broker_proto::commit_signing::NO_ACTIVE_GRANT;

use crate::client::Client;

/// Which of git's configuration files to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// `git config --global`.
    Global,
    /// `git config --local`.
    Local,
}

impl Scope {
    const fn flag(self) -> &'static str {
        match self {
            Self::Global => "--global",
            Self::Local => "--local",
        }
    }
}

/// The values to set: what makes git call this program with the broker's public key,
/// for every commit.
fn settings(program: &str, public_key: &str) -> [(&'static str, String); 4] {
    [
        ("gpg.format", "ssh".to_owned()),
        ("gpg.ssh.program", program.to_owned()),
        ("user.signingkey", format!("key::{public_key}")),
        ("commit.gpgsign", "true".to_owned()),
    ]
}

fn git_config(args: &[&str]) -> Result<Output> {
    Command::new("git")
        .arg("config")
        .args(args)
        .output()
        .context("cannot run git")
}

/// The value of `name`, as git would use it.
pub fn current_value(name: &str) -> Result<Option<String>> {
    let out = git_config(&["--get", name])?;
    Ok(out
        .status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned()))
}

/// Configure git for `client`'s broker, in `scope`.
///
/// # Errors
/// If the agent has no active grant or the broker no key, nothing is changed. If git
/// refuses a value,
/// the message names it; what was set before it stays set.
pub async fn run(client: &Client, scope: Scope) -> Result<()> {
    let key = match client.commit_signing_key().await {
        Ok(key) => key,
        Err(e) if e.to_string().contains(NO_ACTIVE_GRANT) => bail!(
            "this agent has no active commit signing grant, which this needs to read the \
             broker's key, so git was left as it was. Ask the owner for one first with: warden \
             request signing --goal \"<why this agent commits>\""
        ),
        Err(e) => {
            return Err(e)
                .context("cannot read the broker's commit signing key, so git was left as it was");
        }
    };
    let program = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("cannot tell where this program is")?;
    let program = program
        .to_str()
        .ok_or_else(|| anyhow!("the path of this program is not valid UTF-8"))?;
    for (name, value) in settings(program, &key.public_key) {
        if let Some(old) = current_value(name)?
            && old != value
        {
            println!("{name}: was {old}");
        }
        let out = git_config(&[scope.flag(), name, &value])?;
        if !out.status.success() {
            bail!(
                "git config {name} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        println!("{name} = {value}");
    }
    println!(
        "commits are now signed by the broker with key {}. Register it as a signing key on the \
         account that commits, or they show as unverified.",
        key.fingerprint
    );
    println!(
        "A signature means warden signed the commit for this agent, not that anyone reviewed \
         the change."
    );
    if current_value("tag.gpgsign")?.as_deref() == Some("true") {
        println!(
            "tag.gpgsign is on, but warden signs commits only, so creating a tag will fail until \
             it is off."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Scope, settings};

    #[test]
    fn git_is_told_to_sign_every_commit_with_the_brokers_key() {
        let values = settings("/opt/bin/warden", "ssh-ed25519 AAAA");
        let got: Vec<(&str, &str)> = values.iter().map(|(n, v)| (*n, v.as_str())).collect();
        assert_eq!(
            got,
            [
                ("gpg.format", "ssh"),
                ("gpg.ssh.program", "/opt/bin/warden"),
                ("user.signingkey", "key::ssh-ed25519 AAAA"),
                ("commit.gpgsign", "true"),
            ]
        );
    }

    #[test]
    fn the_scope_is_git_configs_flag() {
        assert_eq!(Scope::Global.flag(), "--global");
        assert_eq!(Scope::Local.flag(), "--local");
    }
}
