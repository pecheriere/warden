//! Who may log in, and the target checked again before a session starts:
//! pinned host keys, the onward login, and a policy or destination changed
//! since approval.

use std::process::Output;

use russh::client::AuthResult;
use ssh_key::PublicKey;
use warden_broker::policy::{RelayCredential, SshMode, SshTarget};
use warden_broker::testkit::TestBroker;
use warden_broker::testkit::sshd::{HostKeyType, Sshd, SshdLogin};
use warden_broker_proto::UnixUser;

use super::{
    Agent, OpenSsh, Setup, TARGET, approved_agent, await_events, connect, events_of, key_target,
    nas, nas_pinned, openssh_private, random_key, russh_key, sshd_connections, text,
};

#[tokio::test(flavor = "multi_thread")]
async fn relay_refuses_unbound_key_and_inactive_grant() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let refused = |out: &Output| {
        assert_eq!(out.status.code(), Some(255), "{}", text(&out.stderr));
        assert_eq!(out.stdout, [] as [u8; 0]);
        assert!(
            text(&out.stderr).contains("Permission denied (publickey)"),
            "{}",
            text(&out.stderr)
        );
    };

    // A key nobody approved, the approved key for an unknown target, a
    // cert-mode target and a malformed name: all refused the same way.
    let stranger = random_key();
    let other = OpenSsh::new(&s.broker, s.relay, &stranger);
    refused(&other.run(&["true"]).await);
    for user in ["nosuch", "pi", "Not A Target"] {
        refused(&ssh.run_as(user, &[], &["true"], b"").await);
    }

    // The approved key works ...
    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(text(&out.stdout), "ok\n", "{}", text(&out.stderr));

    // ... until its grant is revoked.
    s.broker
        .state()
        .requests
        .revoke_grant(&agent.grant_id, "test")
        .await
        .unwrap();
    refused(&ssh.run(&["true"]).await);

    // An expired grant is refused too.
    let late = approved_agent(&s.broker, "late").await;
    let late_ssh = OpenSsh::new(&s.broker, s.relay, &late.key);
    s.broker.clock.advance(15 * 60);
    refused(&late_ssh.run(&["true"]).await);

    // At most 3 attempts per connection: the 4th, with the right key,
    // never gets a chance.
    s.broker.clock.advance(-15 * 60);
    let mut c = connect(&s.broker, s.relay).await;
    for _ in 0..3 {
        let auth = c
            .handle
            .authenticate_publickey(TARGET, russh_key(&random_key()))
            .await
            .unwrap();
        assert!(!matches!(auth, AuthResult::Success));
    }
    let fourth = c
        .handle
        .authenticate_publickey(TARGET, russh_key(&late.key))
        .await;
    assert!(!matches!(fourth, Ok(AuthResult::Success)), "{fourth:?}");

    // Only the one accepted session ever reached the target.
    assert_eq!(sshd_connections(&s.sshd), 1, "{}", s.sshd.log());
    assert_eq!(events_of(&s.broker, "relay_session_started").len(), 1);
    // Refused logins are audited, without key material.
    let refusals = await_events(&s.broker, "relay_login_refused", 7).await;
    let users: Vec<&str> = refusals
        .iter()
        .map(|e| e["user"].as_str().unwrap())
        .collect();
    for user in [TARGET, "nosuch", "pi", "<invalid>"] {
        assert!(users.contains(&user), "{users:?}");
    }
    let log = std::fs::read_to_string(s.broker.audit_path()).unwrap();
    for key in [&stranger, &agent.key, &late.key] {
        let public = key.public_key().to_openssh().unwrap();
        let base64 = public.split(' ').nth(1).unwrap();
        assert!(!log.contains(base64), "public key in the audit log");
        let fingerprint = key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        assert!(!log.contains(&fingerprint));
    }
    drop(c);
}

#[tokio::test(flavor = "multi_thread")]
async fn onward_host_key_mismatch_aborts_before_auth() {
    let s = key_target().await;
    // The target presents a key other than the pinned one: a
    // man-in-the-middle, or a re-imaged appliance.
    s.broker.backend.set_relay_target(
        nas_pinned(&s.sshd, random_key().public_key().clone()),
        RelayCredential::Key(openssh_private(&s.onward)),
    );
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["echo", "ok"]).await;
    assert_ne!(out.status.code(), Some(0));
    assert_eq!(out.stdout, [] as [u8; 0]);
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("warden relay: the target's host key does not match"),
        "{stderr}"
    );

    // The relay reached the target but never tried to log in.
    let log = s.sshd.log();
    assert_eq!(sshd_connections(&s.sshd), 1, "{log}");
    for auth in [
        "Accepted",
        "Failed",
        "Postponed",
        "Invalid user",
        "publickey",
    ] {
        assert!(!log.contains(auth), "{auth}: {log}");
    }
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["reason"], "host key mismatch");
    assert_eq!(ended[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(ended[0]["bytes_to_target"], 0);
}

/// A broker whose `nas` is an `sshd` with `host_keys`, of which `pin`
/// chooses the pinned ones, plus an approved agent's OpenSSH client.
async fn host_key_target(
    host_keys: &[HostKeyType],
    pin: impl FnOnce(&Sshd) -> Vec<PublicKey>,
) -> (Setup, OpenSsh) {
    let broker = TestBroker::new().await;
    let onward = random_key();
    let sshd = Sshd::start_with(&SshdLogin::Key(onward.public_key().clone()), host_keys);
    let mut target = nas(&sshd);
    target.host_keys = pin(&sshd);
    broker
        .backend
        .set_relay_target(target, RelayCredential::Key(openssh_private(&onward)));
    let relay = broker.spawn_relay().await;
    let agent = approved_agent(&broker, "bot").await;
    let ssh = OpenSsh::new(&broker, relay, &agent.key);
    let setup = Setup {
        broker,
        sshd,
        relay,
        onward,
    };
    (setup, ssh)
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_pins_ecdsa_when_target_also_has_ed25519() {
    // The target offers Ed25519 too, but only its ECDSA key is pinned: the
    // relay must ask for ECDSA rather than fail on the Ed25519 key.
    let (_s, ssh) = host_key_target(&[HostKeyType::Ed25519, HostKeyType::EcdsaP256], |sshd| {
        vec![sshd.host_keys()[1].clone()]
    })
    .await;
    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ok\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_verifies_rsa_host_key() {
    let (s, ssh) = host_key_target(&[HostKeyType::Rsa], |sshd| sshd.host_keys().to_vec()).await;
    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ok\n");
    let log = s.sshd.log();
    assert!(log.contains("Accepted publickey"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unpinned_algorithm_still_mismatch() {
    // A different ECDSA key, from another host.
    let other_ecdsa = Sshd::start_with(
        &SshdLogin::Key(random_key().public_key().clone()),
        &[HostKeyType::EcdsaP256],
    )
    .host_key()
    .clone();
    // Pinned while the target has Ed25519 and (another) ECDSA key ...
    let (s, ssh) = host_key_target(&[HostKeyType::Ed25519, HostKeyType::EcdsaP256], |_| {
        vec![other_ecdsa.clone()]
    })
    .await;
    // ... and while the target has only Ed25519 (no common algorithm).
    let (t, ssh2) = host_key_target(&[HostKeyType::Ed25519], |_| vec![other_ecdsa.clone()]).await;
    for (setup, client) in [(&s, &ssh), (&t, &ssh2)] {
        let out = client.run(&["true"]).await;
        assert_ne!(out.status.code(), Some(0));
        assert!(
            text(&out.stderr).contains("warden relay: the target's host key does not match"),
            "{}",
            text(&out.stderr)
        );
        let log = setup.sshd.log();
        for auth in ["Accepted", "Failed", "Postponed"] {
            assert!(!log.contains(auth), "{auth}: {log}");
        }
        let ended = await_events(&setup.broker, "relay_session_ended", 1).await;
        assert_eq!(ended[0]["reason"], "host key mismatch");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn onward_login_failure_is_reported_and_audited() {
    let s = key_target().await;
    // The item's key is not the one the target authorizes.
    s.broker.backend.set_relay_target(
        nas(&s.sshd),
        RelayCredential::Key(openssh_private(&random_key())),
    );
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["echo", "ok"]).await;
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("warden relay: the target refused the relay's login"),
        "{}",
        text(&out.stderr)
    );
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["reason"], "onward login refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn session_refused_when_target_policy_changed() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);

    // The approved user is no longer allowed on the target.
    let mut changed = nas(&s.sshd);
    changed.users = vec![UnixUser::try_from("someone-else".to_owned()).unwrap()];
    s.broker
        .backend
        .set_relay_target(changed, RelayCredential::Key(openssh_private(&s.onward)));
    let out = ssh.run(&["true"]).await;
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("warden relay: this access is no longer valid"),
        "{}",
        text(&out.stderr)
    );

    // The target is no longer a relay target.
    let mut cert = nas(&s.sshd);
    cert.mode = SshMode::Cert;
    s.broker.backend.set_target(cert);
    let out = ssh.run(&["true"]).await;
    assert!(
        text(&out.stderr).contains("warden relay: this access is no longer valid"),
        "{}",
        text(&out.stderr)
    );

    let refused = await_events(&s.broker, "relay_session_refused", 2).await;
    assert_eq!(refused[0]["reason"], "user no longer allowed on the target");
    assert_eq!(refused[1]["reason"], "target is no longer a relay target");
    assert_eq!(sshd_connections(&s.sshd), 0, "{}", s.sshd.log());
    assert_eq!(
        events_of(&s.broker, "relay_session_started"),
        [] as [serde_json::Value; 0]
    );
}

/// Replace target `nas` with `changed` after `agent` was approved, then
/// check that a session is refused before the relay connects anywhere,
/// on record as `target policy changed`.
async fn assert_refused_after_destination_change(s: &Setup, agent: &Agent, changed: SshTarget) {
    s.broker
        .backend
        .set_relay_target(changed, RelayCredential::Key(openssh_private(&s.onward)));
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["echo", "ok"]).await;
    assert_ne!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("warden relay: this access is no longer valid"),
        "{}",
        text(&out.stderr)
    );
    let refused = await_events(&s.broker, "relay_session_refused", 1).await;
    assert_eq!(refused[0]["reason"], "target policy changed");
    assert_eq!(refused[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(
        events_of(&s.broker, "relay_session_started"),
        [] as [serde_json::Value; 0]
    );
    assert_eq!(sshd_connections(&s.sshd), 0, "{}", s.sshd.log());
}

#[tokio::test(flavor = "multi_thread")]
async fn session_refused_when_address_changed_after_approval() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    // Another name for the same sshd: the relay would reach it, but it is
    // not the address the owner approved.
    let mut moved = nas(&s.sshd);
    moved.host = "localhost".to_owned();
    assert_refused_after_destination_change(&s, &agent, moved).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn session_refused_when_host_keys_changed_after_approval() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    // The sshd's own key is still pinned, next to one the owner never saw.
    let mut repinned = nas(&s.sshd);
    repinned.host_keys.push(random_key().public_key().clone());
    assert_refused_after_destination_change(&s, &agent, repinned).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rotated_credential_alone_still_works() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    // The target's login key is rotated after approval: the destination
    // is unchanged, so the session runs with the new credential.
    let rotated = random_key();
    s.sshd.authorize_only(rotated.public_key());
    s.broker.backend.set_relay_target(
        nas(&s.sshd),
        RelayCredential::Key(openssh_private(&rotated)),
    );
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["echo", "rotated"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "rotated\n");
    assert_eq!(
        events_of(&s.broker, "relay_session_refused"),
        [] as [serde_json::Value; 0]
    );
    await_events(&s.broker, "relay_session_ended", 1).await;
}
