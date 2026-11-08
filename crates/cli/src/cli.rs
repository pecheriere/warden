//! The command line: what `warden` accepts, as clap parses it.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use url::Url;
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
pub(crate) enum SetupWhat {
    /// Have git sign every commit through the broker, which holds the key:
    /// this program becomes `gpg.ssh.program`. A commit then fails, saying why,
    /// whenever this agent has no active grant or the broker cannot be reached.
    Git {
        /// Change this repository's configuration, not the global one.
        #[arg(long)]
        local: bool,
    },
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
