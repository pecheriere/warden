//! Installing an approved SSH grant here: its agent, key, certificate and
//! pinned host keys.

use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use ssh_key::{Certificate, PrivateKey};
use warden_broker_proto::{GrantAccess, GrantView, TargetName, UnixUser};

use crate::{agent, unix_now};

/// What to install locally for an approved SSH grant.
#[derive(Debug)]
struct SshSetup<'a> {
    /// Straight to the target, or through the relay.
    route: agent::Route,
    /// Where ssh connects: the target's or the relay's address.
    host: &'a str,
    port: u16,
    /// Host keys pinned for `host:port`.
    host_keys: &'a [String],
    /// The certificate loaded with the key (direct grants only: the relay
    /// authenticates the bound key itself).
    certificate: Option<Certificate>,
}

/// Check that `grant` is an SSH grant for `target` as `user` and say how
/// to install it.
///
/// # Errors
/// If the grant is for something else or carries an invalid host or
/// certificate.
fn ssh_setup<'a>(
    target: &TargetName,
    user: &UnixUser,
    grant: &'a GrantView,
) -> Result<SshSetup<'a>> {
    let (setup, granted_user) = match &grant.access {
        GrantAccess::Ssh(ssh) => (
            SshSetup {
                route: agent::Route::Direct,
                host: &ssh.host,
                port: ssh.port,
                host_keys: &ssh.host_keys,
                certificate: Some(
                    Certificate::from_openssh(&ssh.certificate)
                        .map_err(|e| anyhow!("the grant's certificate is invalid: {e}"))?,
                ),
            },
            &ssh.user,
        ),
        GrantAccess::Relay(relay) => {
            ensure!(
                &relay.target == target,
                "the grant is for target {}, not {target}",
                relay.target
            );
            (
                SshSetup {
                    route: agent::Route::Relay,
                    host: &relay.relay_host,
                    port: relay.relay_port,
                    host_keys: std::slice::from_ref(&relay.relay_host_key),
                    certificate: None,
                },
                &relay.user,
            )
        }
        GrantAccess::Api(_) | GrantAccess::CommitSigning(_) => {
            bail!("the broker returned a non-ssh grant for an ssh request")
        }
    };
    ensure!(
        granted_user == user,
        "the grant is for user {granted_user}, not {user}"
    );
    ensure!(
        agent::is_safe_host(setup.host),
        "the grant's host {:?} is invalid",
        setup.host
    );
    ensure!(setup.port != 0, "the grant's port is invalid");
    Ok(setup)
}

/// Start the grant's agent, load the key (and, for a direct grant, its
/// certificate) into it, pin the host keys of where ssh connects and record
/// the grant. On failure nothing is left behind.
pub(crate) async fn install_grant(
    target: &TargetName,
    user: &UnixUser,
    key: &PrivateKey,
    grant: &GrantView,
) -> Result<()> {
    let setup = ssh_setup(target, user, grant)?;
    let remaining = grant.not_after.saturating_sub(unix_now());
    let lifetime = Duration::from_secs(
        u64::try_from(remaining)
            .ok()
            .filter(|s| *s > 0)
            .context("the grant has already ended")?,
    );

    let agent = agent::start(&grant.grant_id, lifetime)?;
    let install = async {
        agent::record(
            &agent,
            &agent::GrantRecord {
                grant_id: grant.grant_id.clone(),
                target: target.clone(),
                route: setup.route,
                host: setup.host.to_owned(),
                port: setup.port,
                user: user.clone(),
                not_after: grant.not_after,
                socket: agent.socket.clone(),
                pid: agent.pid,
            },
        )?;
        match &setup.certificate {
            Some(cert) => agent::add_cert(&agent, key, cert, lifetime).await?,
            None => agent::add_key(&agent, key, lifetime).await?,
        }
        agent::write_known_hosts(&agent.dir, setup.host, setup.port, setup.host_keys)?;
        Ok::<_, anyhow::Error>(())
    };
    if let Err(e) = install.await {
        if let Err(cleanup) = agent::discard(&agent.dir, &agent.socket, agent.pid) {
            eprintln!("warden: warning: {cleanup:#}");
        }
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey, certificate};
    use warden_broker_proto::{GrantAccess, GrantView, Id, RelayGrant, SshGrant};

    use super::ssh_setup;
    use crate::agent::Route;

    fn relay_view(relay: RelayGrant) -> GrantView {
        GrantView {
            grant_id: Id::random(),
            not_before: 0,
            not_after: 1,
            access: GrantAccess::Relay(relay),
        }
    }

    fn nas_relay() -> RelayGrant {
        RelayGrant {
            target: "nas".parse().unwrap(),
            user: "backup".parse().unwrap(),
            relay_host: "relay.example.com".to_owned(),
            relay_port: 2222,
            relay_host_key: PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap(),
            digest: "ab".repeat(32),
        }
    }

    /// A direct grant for `alice@pi` reaching `pi.example.com:<port>`, with
    /// a certificate signed by a throwaway CA.
    fn pi_direct(port: u16) -> GrantView {
        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut cert =
            certificate::Builder::new_with_random_nonce(&mut OsRng, key.public_key(), 0, 1)
                .unwrap();
        cert.cert_type(certificate::CertType::User).unwrap();
        cert.valid_principal("alice").unwrap();
        GrantView {
            grant_id: Id::random(),
            not_before: 0,
            not_after: 1,
            access: GrantAccess::Ssh(SshGrant {
                certificate: cert.sign(&ca).unwrap().to_openssh().unwrap(),
                host: "pi.example.com".to_owned(),
                port,
                user: "alice".parse().unwrap(),
                host_keys: Vec::new(),
            }),
        }
    }

    #[test]
    fn direct_grant_with_port_zero_is_refused() {
        let (target, user) = ("pi".parse().unwrap(), "alice".parse().unwrap());
        let ok = pi_direct(22);
        let setup = ssh_setup(&target, &user, &ok).unwrap();
        assert_eq!(setup.route, Route::Direct);
        assert_eq!((setup.host, setup.port), ("pi.example.com", 22));
        assert!(setup.certificate.is_some());

        let no_port = pi_direct(0);
        let refused = ssh_setup(&target, &user, &no_port).unwrap_err();
        assert!(refused.to_string().contains("port"), "{refused}");
    }

    /// A relay grant connects to the relay, pins only the relay's host key
    /// and loads no certificate.
    #[test]
    fn relay_grant_installs_relay_address_and_key_without_certificate() {
        let relay = nas_relay();
        let view = relay_view(relay.clone());
        let setup = ssh_setup(&relay.target, &relay.user, &view).unwrap();
        assert_eq!(setup.route, Route::Relay);
        assert_eq!(setup.host, "relay.example.com");
        assert_eq!(setup.port, 2222);
        assert_eq!(setup.host_keys, [relay.relay_host_key]);
        assert!(setup.certificate.is_none());
    }

    #[test]
    fn relay_grant_for_something_else_is_refused() {
        let relay = nas_relay();
        let user = relay.user.clone();
        let target = relay.target.clone();
        let refused = |view: GrantView| ssh_setup(&target, &user, &view).unwrap_err().to_string();

        let other_target = relay_view(RelayGrant {
            target: "pi".parse().unwrap(),
            ..relay.clone()
        });
        assert!(refused(other_target).contains("target pi"));
        let other_user = relay_view(RelayGrant {
            user: "root".parse().unwrap(),
            ..relay.clone()
        });
        assert!(refused(other_user).contains("user root"));
        for host in ["-oProxyCommand=x", "a b", ""] {
            let bad = relay_view(RelayGrant {
                relay_host: host.to_owned(),
                ..relay.clone()
            });
            assert!(refused(bad).contains("host"), "{host:?}");
        }
        let no_port = relay_view(RelayGrant {
            relay_port: 0,
            ..relay
        });
        assert!(refused(no_port).contains("port"));
    }
}
