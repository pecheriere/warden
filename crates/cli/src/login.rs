//! `warden login`: set this machine up as an agent, with a bearer key or a
//! signing key held by the ssh-agent.

use std::io::{BufRead as _, IsTerminal as _};
use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use url::Url;
use warden_broker_proto::AgentName;
use warden_broker_proto::signing::{Audience, PROTOCOL};
use zeroize::Zeroizing;

use crate::client::{self, Auth, Client};
use crate::config::{self, Config, SshKeyConfig};
use crate::sign::{self, Signer};

pub(crate) fn login(server: Url, agent: AgentName) -> Result<()> {
    config::check_server_url(&server)?;
    let config = Config {
        server,
        agent,
        ssh_key: None,
    };
    let key = if std::io::stdin().is_terminal() {
        eprint!("agent key for {}: ", config.agent);
        Zeroizing::new(rpassword::read_password().context("cannot read the agent key")?)
    } else {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("cannot read the agent key from stdin")?;
        Zeroizing::new(line.trim().to_owned())
    };
    config::check_agent_key(&key)?;
    config::store_agent_key(&config, &key)?;
    let path = config::save(&config)?;
    eprintln!(
        "logged in as {} at {} ({})",
        config.agent,
        config.server,
        path.display()
    );
    Ok(())
}

/// What `warden login --ssh-key` was given.
pub(crate) struct KeyLogin {
    pub(crate) server: Url,
    pub(crate) agent: AgentName,
    pub(crate) public_key: PathBuf,
    pub(crate) agent_socket: Option<PathBuf>,
    pub(crate) audience: Option<Audience>,
}

/// Set up a key-signed agent: read the public key, pin the broker's
/// audience (refusing one that differs from what the owner gave or from
/// what was pinned before), check that the ssh-agent holds the key and that
/// the broker accepts a signed call, then write the configuration.
pub(crate) async fn login_with_key(login: KeyLogin) -> Result<()> {
    let KeyLogin {
        server,
        agent,
        public_key,
        agent_socket,
        audience,
    } = login;
    config::check_server_url(&server)?;
    config::check_root_url(&server)?;
    if let Some(socket) = &agent_socket {
        config::check_socket_path(socket)?;
    }
    let key = sign::read_signing_key(&public_key)?;

    let info = client::fetch_info(&server)
        .await
        .with_context(|| format!("cannot read the broker's /v1/info at {server}"))?;
    ensure!(
        info.protocols.iter().any(|p| p == PROTOCOL),
        "the broker at {server} does not accept signed requests ({PROTOCOL}); upgrade it to \
         0.6 or later"
    );
    let previous = config::load_existing()?;
    let pinned = previous
        .as_ref()
        .filter(|old| old.server == server)
        .and_then(|old| old.ssh_key.as_ref())
        .map(|old| old.audience.clone());
    match (&audience, &pinned) {
        (Some(expected), _) if *expected != info.audience => bail!(
            "the broker at {server} reports audience {}, not {expected} as given: this is \
             another broker; check the URL with the owner",
            info.audience
        ),
        (None, Some(old)) if *old != info.audience => bail!(
            "the broker at {server} reports audience {}, but {old} was pinned before: this is \
             another broker, or its data was reset. Ask the owner for the broker's audience, \
             then log in again with --audience <audience>",
            info.audience
        ),
        _ => {}
    }

    let signer = Signer::new(
        agent.clone(),
        info.audience.clone(),
        key.clone(),
        sign::agent_socket(agent_socket.as_deref())?,
    );
    signer.check_key_loaded().await?;
    let fingerprint = signer.fingerprint();
    let client = Client::new(&server, Auth::Signed(Box::new(signer)))?;
    client.grants().await.with_context(|| {
        format!(
            "the broker did not accept a call signed by agent {agent} with key {fingerprint}; \
             the owner enrolls it with `warden-server agent add {agent} --public-key '<.pub \
             line>'` (or `agent set-key`)"
        )
    })?;

    let audience = info.audience;
    let config = Config {
        server,
        agent,
        ssh_key: Some(SshKeyConfig {
            public_key: key
                .to_openssh()
                .map_err(|e| anyhow!("cannot encode the public key: {e}"))?,
            agent_socket,
            audience: audience.clone(),
        }),
    };
    let path = config::save(&config)?;
    eprintln!(
        "logged in as {} at {} with key {fingerprint}, audience {audience} ({})",
        config.agent,
        config.server,
        path.display()
    );
    #[cfg(target_os = "macos")]
    if let Some(command) = previous.as_ref().and_then(config::keychain_cleanup_command) {
        eprintln!(
            "the bearer key of the previous login may still be in the Keychain, unused; once \
             you no longer need it, delete it with:\n  {command}"
        );
    }
    Ok(())
}
