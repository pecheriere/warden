//! The command line: what `warden` accepts, as clap parses it.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use url::Url;
use warden_broker_proto::release::{CommitId, ReleaseTag, RepoName};
use warden_broker_proto::signing::Audience;
use warden_broker_proto::{AgentName, Goal, Id, SecretName, TargetName, UnixUser, Window};

use crate::request_context::RequestContext;
use crate::{http, ssh_config};

/// Ask the owner for short-lived access, then use it.
#[derive(Debug, Parser)]
#[command(name = "warden", version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Cmd,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Cmd {
    /// Set up this machine as an agent. With --ssh-key: pin the broker's
    /// audience, check that the ssh-agent holds the key and that the broker
    /// accepts a signed call, and remember all of it (nothing secret).
    /// Without: store the agent's bearer key (read from stdin) in the
    /// Keychain.
    Login {
        /// Broker agent API URL (https, or http on loopback); with --ssh-key,
        /// the root of the origin, with no path.
        #[arg(long)]
        server: Url,
        /// Agent name.
        #[arg(long)]
        agent: AgentName,
        /// Sign requests with this key: the path of its public key (.pub),
        /// enrolled on the broker with `warden-server agent add <name>
        /// --public-key`. The private key stays in the ssh-agent.
        #[arg(long, value_name = "PATH")]
        ssh_key: Option<PathBuf>,
        /// The ssh-agent socket holding the key (default: `SSH_AUTH_SOCK`
        /// whenever warden runs).
        #[arg(long, value_name = "PATH", requires = "ssh_key")]
        ssh_agent_socket: Option<PathBuf>,
        /// The broker's audience as the owner gave it; the login fails if
        /// the broker reports another. Needed to pin a new audience over a
        /// different one pinned earlier.
        #[arg(long, requires = "ssh_key")]
        audience: Option<Audience>,
    },
    /// Ask the owner for access and wait for the decision.
    Request {
        #[command(subcommand)]
        kind: RequestKind,
    },
    /// Run ssh to a target through its active grant that stays valid longest.
    Ssh {
        /// Target name.
        target: TargetName,
        /// Remote command, after `--`.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Print an `ssh_config` Host block for the grant `warden ssh` would use,
    /// for tools that run ssh themselves (`ssh -F <file> <target>`). Make it
    /// right before connecting: it holds this grant's agent socket, which
    /// changes with every grant.
    SshConfig(ssh_config::Request),
    /// Call an HTTPS API through the broker, which adds the secret.
    Http {
        /// Secret name.
        secret: SecretName,
        /// HTTP method.
        method: String,
        /// Absolute https URL.
        url: String,
        /// Request header, `Name: value`; repeatable.
        #[arg(short = 'H', long = "header", value_parser = http::parse_header)]
        headers: Vec<(String, String)>,
        /// Request body.
        #[arg(short = 'd', long = "data", conflicts_with = "data_file")]
        data: Option<String>,
        /// Read the request body from a file, or from standard input for `-`.
        #[arg(long)]
        data_file: Option<String>,
        /// Print the status line and response headers to stderr.
        #[arg(short = 'i', long)]
        include: bool,
        /// Exit 22 when the status is 400 or more (the body is still written).
        #[arg(long)]
        fail: bool,
    },
    /// Check this machine's setup without changing anything: server reachable,
    /// audience pinned, key available, agent accepted. Exits 1 when a check
    /// failed, otherwise 0, listing what could not be checked and how to check
    /// it by hand.
    Doctor {
        /// Exit 7 when nothing failed but some check could not run.
        #[arg(long)]
        strict: bool,
    },
    /// Set something up to work through warden.
    Setup {
        #[command(subcommand)]
        what: SetupWhat,
    },
    /// Use GitHub through warden.
    Github {
        #[command(subcommand)]
        what: GithubCmd,
    },
    /// Take the steps of a release the owner approved with `warden request
    /// release`: the broker creates the signed tag, signs the manifest of the
    /// release's files and publishes the draft, each once.
    Release {
        #[command(subcommand)]
        what: ReleaseCmd,
    },
    /// Show what this agent may ask the broker for. Asks no one and changes
    /// nothing.
    List {
        /// Print the broker's answer as JSON.
        #[arg(long)]
        json: bool,
        /// Ask about this repository (`owner/name`) instead of the checkout's.
        #[arg(long)]
        repo: Option<String>,
    },
    /// Show local grants, and the broker's view of this agent's grants and
    /// pending requests.
    Status,
    /// Revoke a grant on the broker and stop its local agent.
    Revoke {
        /// Grant identifier.
        grant: Id,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ReleaseCmd {
    /// Have the broker sign the tag and create it at the approved commit. Prints
    /// the tag and the id of the tag object.
    Tag {
        /// The repository, `owner/name`.
        repository: RepoName,
        /// The tag, as approved.
        tag: ReleaseTag,
    },
    /// Have the broker sign the manifest of the release's files and attach it,
    /// with its signature, to the draft release. Prints the manifest's name, its
    /// signature's name and the manifest's SHA-256. The manifest is a file of
    /// lines `<sha256>  <name>`, at most 64 KiB; its base name is the name the
    /// owner approved.
    SignManifest {
        /// The repository, `owner/name`.
        repository: RepoName,
        /// The tag, as approved.
        tag: ReleaseTag,
        /// The manifest file.
        file: PathBuf,
    },
    /// Have the broker publish the draft release. Prints the tag.
    Publish {
        /// The repository, `owner/name`.
        repository: RepoName,
        /// The tag, as approved.
        tag: ReleaseTag,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum GithubCmd {
    /// Print a GitHub token on stdout, and nothing else: the cached one while it
    /// has 5 minutes left, otherwise a new one from the broker. Without an active
    /// grant, it asks the owner for one (30 days) and waits; it exits 5 if the
    /// owner does not approve. The `gh` wrapper of `warden setup github` runs it.
    ///
    /// The token is for one repository: --repo, else `GH_REPO`, else the `origin`
    /// remote of the current directory. When none of them names a repository on
    /// github.com, it prints nothing and exits 1.
    Token {
        /// The repository the token is for, `owner/name`.
        #[arg(long, conflicts_with = "gh_args")]
        repo: Option<RepoName>,
        /// What follows `--` are `gh`'s own arguments: the repository is read from
        /// their `-R`/`--repo`, as the `gh` wrapper passes them.
        #[arg(long)]
        gh_args: bool,
        /// `gh`'s arguments, with --gh-args.
        #[arg(last = true, requires = "gh_args")]
        args: Vec<OsString>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum SetupWhat {
    /// Have git sign every commit through the broker, which holds the key:
    /// this program becomes `gpg.ssh.program`. A commit then fails, saying why,
    /// whenever this agent has no active grant or the broker cannot be reached.
    Git {
        /// Change this repository's configuration, not the global one.
        #[arg(long)]
        local: bool,
    },
    /// Have git and gh use GitHub tokens from warden: this program becomes git's
    /// credential helper for GitHub over HTTPS, the only one git consults for it,
    /// and ~/.local/bin/gh a wrapper that runs the real gh with a token. Changes
    /// git's global configuration; never replaces a ~/.local/bin/gh it did not write.
    Github,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RequestKind {
    /// SSH access as a user on a target: a certificate, or for a relay
    /// target a session through the broker's relay.
    Ssh {
        /// Target name.
        target: TargetName,
        /// Unix account to log in as.
        #[arg(long)]
        user: UnixUser,
        /// Window length: 15m, 30m, 1h or 4h.
        #[arg(long = "for")]
        window: Window,
        /// What the access is for, shown to the owner.
        #[arg(long)]
        goal: Goal,
        #[command(flatten)]
        context: RequestContext,
    },
    /// Brokered HTTPS calls that use a stored API secret.
    Api {
        /// Secret name.
        secret: SecretName,
        /// Methods to allow, comma separated (default: read-only, GET and
        /// HEAD); the broker refuses any the secret does not allow.
        #[arg(long, value_delimiter = ',')]
        methods: Option<Vec<String>>,
        /// Limit the grant to this path prefix (default: the secret's).
        #[arg(long)]
        path: Option<String>,
        /// Window length: 15m, 30m, 1h or 4h.
        #[arg(long = "for")]
        window: Window,
        /// What the access is for, shown to the owner.
        #[arg(long)]
        goal: Goal,
        #[command(flatten)]
        context: RequestContext,
    },
    /// Commit signing by the broker's key, for much longer than other access: no
    /// prompt per commit. A signature means warden signed the commit for this
    /// agent, not that anyone reviewed the change.
    Signing {
        /// Window length: 1d, 7d, 30d or 90d, up to what the server allows.
        #[arg(long = "for", default_value = "30d", value_parser = Window::commit_signing)]
        window: Window,
        /// What the access is for, shown to the owner.
        #[arg(long)]
        goal: Goal,
        #[command(flatten)]
        context: RequestContext,
    },
    /// GitHub tokens for git and gh (contents, pull requests and issues of the
    /// repositories named), minted by the broker for an hour at a time, for much
    /// longer than other access. git and gh also ask for this by themselves, for the
    /// repository they work on, once set up with `warden setup github`.
    Github {
        /// The repositories, `owner/name`: at least one, at most 10.
        #[arg(required = true)]
        repositories: Vec<RepoName>,
        /// Window length: 1d, 7d or 30d, up to what the server allows.
        #[arg(long = "for", default_value = "30d", value_parser = Window::github_token)]
        window: Window,
        /// What the access is for, shown to the owner.
        #[arg(long)]
        goal: Goal,
        #[command(flatten)]
        context: RequestContext,
    },
    /// A release made by the broker: the owner approves one tag at one commit of
    /// one repository on their phone, and the grant lasts a day. The broker holds
    /// the signing key and the GitHub App; the agent never sees either.
    Release {
        /// The repository, `owner/name`.
        repository: RepoName,
        /// The tag to release, such as v1.2.3.
        tag: ReleaseTag,
        /// The commit the tag points at: 40 lowercase hex characters, on the
        /// repository's default branch.
        #[arg(long)]
        commit: CommitId,
        /// What the access is for, shown to the owner.
        #[arg(long)]
        goal: Goal,
        #[command(flatten)]
        context: RequestContext,
    },
    /// Withdraw one of this agent's pending requests, so its approval link
    /// stops working.
    Cancel {
        /// Request identifier, as printed while `warden request` waits or
        /// listed by `warden status`.
        id: Id,
    },
    /// Start using an api grant the owner approved after the `warden request`
    /// that asked for it was gone. An SSH grant cannot be collected, as its key
    /// was lost with that run.
    Collect {
        /// Grant identifier, as listed by `warden status`.
        grant: Id,
    },
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Cli, Cmd, GithubCmd};

    #[test]
    fn token_command_takes_repo_and_gh_args() {
        let cli = Cli::try_parse_from([
            "warden",
            "github",
            "token",
            "--gh-args",
            "--",
            "pr",
            "view",
            "-R",
            "o/r",
        ])
        .unwrap();
        let Cmd::Github {
            what:
                GithubCmd::Token {
                    repo,
                    gh_args,
                    args,
                },
        } = cli.command
        else {
            panic!("not the token command");
        };
        assert_eq!(repo, None);
        assert!(gh_args);
        assert_eq!(args, ["pr", "view", "-R", "o/r"]);

        let cli = Cli::try_parse_from(["warden", "github", "token", "--repo", "o/r"]).unwrap();
        let Cmd::Github {
            what: GithubCmd::Token { repo, gh_args, .. },
        } = cli.command
        else {
            panic!("not the token command");
        };
        assert_eq!(repo.unwrap().as_str(), "o/r");
        assert!(!gh_args);
    }

    #[test]
    fn token_command_refuses_what_does_not_fit() {
        for args in [
            &["warden", "github", "token", "--repo", "bad"][..],
            &["warden", "github", "token", "--", "pr", "view"],
            &["warden", "github", "token", "--repo", "o/r", "--gh-args"],
        ] {
            assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
        }
    }
}
