//! Creating requests: policy checks, key binding, dedupe and notification.

use std::sync::Arc;
use std::task::{Context, Waker};
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use warden_broker::audit;
use warden_broker::notify::{Fallback, Notifier};
use warden_broker::requests::{Destination, RequestError};
use warden_broker::testkit::{CapturingNotifier, FailingNotifier};
use warden_broker_proto::{Access, RequestStatus, Window, fingerprint};

use super::{
    CREDENTIAL, ECDSA_PUBLIC, START, TOKEN, agent, api_request, audit_types, broken_connect,
    connect_with_credential, create_notified, ed25519_public, grant_for, harness, harness_with,
    harness_with_relay, healthy_connect, message, pi_request, row_count, ssh_request, wait_for,
};

#[tokio::test]
async fn api_request_is_stored_and_rings_without_the_secret() {
    let h = harness().await;
    let req = api_request("github", Window::M30);
    let created = h.requests.create(&agent("bot"), req.clone()).await.unwrap();
    assert_eq!(created.fingerprint, fingerprint(&agent("bot"), &req));

    let bell = h.capture.next().await;
    assert_eq!(bell.title, "warden: bot wants api github (read-only)");
    assert_eq!(bell.message, "list the open pull requests");
    for text in [&bell.title, &bell.message, &bell.url.to_string()] {
        assert!(!text.contains(CREDENTIAL), "secret in notification");
    }
    let view = h
        .requests
        .pending_for_token(&CapturingNotifier::token(&bell))
        .await
        .unwrap();
    assert_eq!(view.request, req);
    let Destination::Api(policy) = &view.destination else {
        panic!("expected an api destination, got {:?}", view.destination);
    };
    assert_eq!(policy.name.as_str(), "github");
    assert_eq!(view.destination.digest(), policy.destination_digest());
    let key: String = sqlx::query("SELECT dedupe_key FROM requests WHERE id = ?")
        .bind(created.id.as_str())
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(key, "bot|api|github|GET|/");
}

#[tokio::test]
async fn api_window_over_max_rejected() {
    let h = harness().await;
    // The `github` item allows at most 30m.
    let err = h
        .requests
        .create(&agent("bot"), api_request("github", Window::H1))
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::Rejected(_)), "{err:?}");
    assert_eq!(message(&err), "window 1h exceeds max 30m for secret github");
    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert_eq!(h.capture.rung(), [] as [warden_broker::notify::Doorbell; 0]);
}

#[tokio::test]
async fn unknown_secret_not_found_without_notifying() {
    let h = harness().await;
    let err = h
        .requests
        .create(&agent("bot"), api_request("nope", Window::M15))
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::UnknownSecret(_)), "{err:?}");
    assert_eq!(message(&err), "unknown API secret nope");
    // An SSH target of that name is no API secret either.
    let err = h
        .requests
        .create(&agent("bot"), api_request("pi", Window::M15))
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::UnknownSecret(_)), "{err:?}");
    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert_eq!(h.capture.rung(), [] as [warden_broker::notify::Doorbell; 0]);
}

#[tokio::test]
async fn invalid_api_item_is_named_as_a_secret() {
    let h = harness_with(connect_with_credential("x9q7").await, None).await;
    let err = h
        .requests
        .create(&agent("bot"), api_request("github", Window::M15))
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::SecretInvalid { .. }), "{err:?}");
    assert!(
        message(&err).starts_with("secret github: field credential invalid: "),
        "{err}"
    );
    assert!(!message(&err).contains("x9q7"), "credential echoed: {err}");
    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert_eq!(h.capture.rung(), [] as [warden_broker::notify::Doorbell; 0]);
}

#[tokio::test]
async fn create_notifies_with_link_and_no_secret() {
    let h = harness().await;
    let req = pi_request();
    let Access::Ssh { public_key, .. } = &req.access else {
        panic!("pi_request is an ssh request");
    };
    let public_key = public_key.clone();
    let created = h.requests.create(&agent("bot"), req.clone()).await.unwrap();
    assert_eq!(created.fingerprint, fingerprint(&agent("bot"), &req));

    let bell = h.capture.next().await;
    let link = bell.url.as_str();
    assert!(link.starts_with("https://warden.test/approve/"), "{link}");
    let token = CapturingNotifier::token(&bell);
    assert_eq!(token.len(), 43, "32 bytes base64url without padding");
    assert!(bell.title.contains("bot") && bell.title.contains("alice@pi"));
    assert_eq!(bell.message, "restart the backup job");
    for text in [&bell.title, &bell.message, &link.to_owned()] {
        assert!(!text.contains(TOKEN), "Connect token leaked");
        assert!(!text.contains(&public_key), "public key in notification");
    }

    let stored: String = sqlx::query("SELECT approval_token_hash FROM requests WHERE id = ?")
        .bind(created.id.as_str())
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, hex::encode(Sha256::digest(token.as_bytes())));
    let dump: Vec<String> = sqlx::query("SELECT body || approval_token_hash FROM requests")
        .fetch_all(&h.pool)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert!(
        dump.iter().all(|row| !row.contains(&token)),
        "raw token stored"
    );

    let status = h
        .requests
        .status(&agent("bot"), &created.id, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(status, RequestStatus::Pending);
    let view = h.requests.pending_for_token(&token).await.unwrap();
    assert_eq!(view.id, created.id);
    assert_eq!(view.agent, agent("bot"));
    assert_eq!(view.request, req);
    let Destination::Ssh(target) = &view.destination else {
        panic!("expected an ssh destination, got {:?}", view.destination);
    };
    assert_eq!(target.name.as_str(), "pi");
    assert_eq!(view.expires_at, START + 600);
}

#[tokio::test]
async fn create_rejects_user_not_allowed() {
    let h = harness().await;
    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("pi", "root", Window::M30, &ed25519_public()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::Rejected(_)), "{err:?}");
    assert_eq!(message(&err), "user root not allowed for target pi");
    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert_eq!(h.capture.rung(), [] as [warden_broker::notify::Doorbell; 0]);
}

#[tokio::test]
async fn create_rejects_window_over_max() {
    let h = harness().await;
    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("pi", "alice", Window::H4, &ed25519_public()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::Rejected(_)), "{err:?}");
    assert_eq!(message(&err), "window 4h exceeds max 1h for target pi");
    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert_eq!(h.capture.rung(), [] as [warden_broker::notify::Doorbell; 0]);
}

#[tokio::test]
async fn create_rejects_non_ed25519_key() {
    let h = harness().await;
    for key in [ECDSA_PUBLIC, "not a key", ""] {
        let err = h
            .requests
            .create(&agent("bot"), ssh_request("pi", "alice", Window::M30, key))
            .await
            .unwrap_err();
        assert!(matches!(err, RequestError::Rejected(_)), "{err:?}");
        assert!(message(&err).contains("ssh-ed25519"), "{err}");
    }
    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert_eq!(h.capture.rung(), [] as [warden_broker::notify::Doorbell; 0]);
}

#[tokio::test]
async fn relay_request_is_created_and_notified() {
    let h = harness().await;
    let (created, _) = create_notified(
        &h,
        "bot",
        ssh_request("nas", "backup", Window::M30, &ed25519_public()),
    )
    .await;
    assert_eq!(row_count(&h.pool, "requests").await, 1);
    let status = h
        .requests
        .status(&agent("bot"), &created.id, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(status, RequestStatus::Pending);
}

#[tokio::test]
async fn relay_not_configured_rejected_without_notifying() {
    let h = harness_with_relay(healthy_connect().await, None, None).await;
    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("nas", "backup", Window::M30, &ed25519_public()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::Rejected(_)), "{err:?}");
    assert_eq!(message(&err), "target nas: relay is not configured");
    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert_eq!(h.capture.rung(), [] as [warden_broker::notify::Doorbell; 0]);
    assert_eq!(audit_types(&h), [] as [std::string::String; 0]);

    // Cert targets are unaffected.
    create_notified(&h, "bot", pi_request()).await;
}

/// `public_key` with its comment replaced: the same key, spelled differently.
fn recommented(public_key: &str) -> String {
    let mut key = ssh_key::PublicKey::from_openssh(public_key).unwrap();
    key.set_comment("someone-else@example.com");
    key.to_openssh().unwrap()
}

#[tokio::test]
async fn public_key_bound_once_across_agents() {
    let h = harness().await;
    let key = ed25519_public();
    let (created, token) =
        create_notified(&h, "bot", ssh_request("pi", "alice", Window::M30, &key)).await;

    // Another agent cannot bind the same key (whatever its comment), to
    // the same target or another one, while bot's request is pending.
    for (target, user) in [("pi", "alice"), ("nas", "backup")] {
        let err = h
            .requests
            .create(
                &agent("other"),
                ssh_request(target, user, Window::M30, &recommented(&key)),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, RequestError::KeyInUse), "{err:?}");
        assert_eq!(
            message(&err),
            "this public key is already bound to another request or grant"
        );
    }
    assert_eq!(row_count(&h.pool, "requests").await, 1);
    assert_eq!(h.capture.rung().len(), 1);

    // bot repeating its own request is the dedupe path, as before.
    let again = h
        .requests
        .create(&agent("bot"), ssh_request("pi", "alice", Window::M30, &key))
        .await
        .unwrap();
    assert_eq!(again.id, created.id);

    // Approved: the active grant still holds the key.
    let grant = grant_for(&h, Window::M15);
    h.requests
        .mark_approved(&token, Window::M15, grant.clone(), "pk1")
        .await
        .unwrap();
    let err = h
        .requests
        .create(
            &agent("other"),
            ssh_request("pi", "alice", Window::M30, &key),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::KeyInUse), "{err:?}");

    // Once the grant has ended the key is free again.
    h.requests
        .revoke_grant(&grant.grant_id, "test")
        .await
        .unwrap();
    create_notified(&h, "other", ssh_request("pi", "alice", Window::M30, &key)).await;
}

#[tokio::test]
async fn same_agent_same_target_live_grant_key_refused() {
    let h = harness().await;
    let key = ed25519_public();
    let (_, token) =
        create_notified(&h, "bot", ssh_request("pi", "alice", Window::M30, &key)).await;
    let grant = grant_for(&h, Window::M15);
    h.requests
        .mark_approved(&token, Window::M15, grant.clone(), "pk1")
        .await
        .unwrap();
    // No pending request holds the slot any more, but the live grant still
    // holds the key: a second request with it, even from the same agent for
    // the same target, would bind one key to two grants.
    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("pi", "alice", Window::M30, &recommented(&key)),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::KeyInUse), "{err:?}");
    assert_eq!(row_count(&h.pool, "requests").await, 1);

    h.requests
        .revoke_grant(&grant.grant_id, "test")
        .await
        .unwrap();
    create_notified(&h, "bot", ssh_request("pi", "alice", Window::M30, &key)).await;
}

#[tokio::test]
async fn bound_key_freed_when_pending_request_expires() {
    let h = harness().await;
    let key = ed25519_public();
    create_notified(&h, "bot", ssh_request("pi", "alice", Window::M30, &key)).await;
    h.clock.advance(600);
    // The stale pending row no longer binds the key.
    create_notified(&h, "other", ssh_request("pi", "alice", Window::M30, &key)).await;
}

#[tokio::test]
async fn same_agent_reuse_for_other_target_refused() {
    let h = harness().await;
    let key = ed25519_public();
    create_notified(&h, "bot", ssh_request("pi", "alice", Window::M30, &key)).await;
    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("nas", "backup", Window::M30, &key),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::KeyInUse), "{err:?}");
    assert_eq!(row_count(&h.pool, "requests").await, 1);
    assert_eq!(h.capture.rung().len(), 1);
    // A different key for the other target is fine.
    create_notified(
        &h,
        "bot",
        ssh_request("nas", "backup", Window::M30, &ed25519_public()),
    )
    .await;
}

#[tokio::test]
async fn connect_down_fails_request_without_notifying() {
    let down = harness_with(broken_connect().await, None).await;
    let err = down
        .requests
        .create(&agent("bot"), pi_request())
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::Unavailable(_)), "{err:?}");
    assert!(message(&err).contains("HTTP 500"), "{err}");
    assert!(!message(&err).contains(TOKEN));
    assert_eq!(row_count(&down.pool, "requests").await, 0);
    assert_eq!(
        down.capture.rung(),
        [] as [warden_broker::notify::Doorbell; 0]
    );

    let h = harness().await;
    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("nousers", "alice", Window::M30, &ed25519_public()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::TargetInvalid { .. }), "{err:?}");
    assert!(
        message(&err).starts_with("target nousers: field users invalid: "),
        "{err}"
    );

    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("nope", "alice", Window::M30, &ed25519_public()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::UnknownTarget(_)), "{err:?}");
    assert_eq!(message(&err), "unknown target nope");

    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert_eq!(h.capture.rung(), [] as [warden_broker::notify::Doorbell; 0]);
}

#[tokio::test]
async fn duplicate_pending_returns_same_id() {
    let h = harness().await;
    let (first, token) = create_notified(&h, "bot", pi_request()).await;

    let bot = agent("bot");
    let (a, b, c) = tokio::join!(
        h.requests.create(&bot, pi_request()),
        h.requests.create(&bot, pi_request()),
        h.requests.create(&bot, pi_request()),
    );
    for again in [a, b, c] {
        assert_eq!(again.unwrap(), first);
    }
    assert_eq!(row_count(&h.pool, "requests").await, 1);
    assert_eq!(h.capture.rung().len(), 1, "duplicates must not notify");

    // Another agent's request for the same target is separate.
    let (theirs, _) = create_notified(&h, "other", pi_request()).await;
    assert_ne!(theirs.id, first.id);

    // Once decided, a new request takes the slot.
    h.requests.deny(&token).await.unwrap();
    let (next, _) = create_notified(&h, "bot", pi_request()).await;
    assert_ne!(next.id, first.id);
}

#[tokio::test]
async fn duplicate_of_stale_pending_expires_it_first() {
    let h = harness().await;
    let (first, _) = create_notified(&h, "bot", pi_request()).await;
    h.clock.advance(600);
    let (second, _) = create_notified(&h, "bot", pi_request()).await;
    assert_ne!(second.id, first.id);
    let status = h
        .requests
        .status(&agent("bot"), &first.id, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(status, RequestStatus::Expired);
}

#[tokio::test]
async fn notify_failure_ends_in_error() {
    let h = harness_with(healthy_connect().await, Some(Arc::new(FailingNotifier))).await;
    let created = h
        .requests
        .create(&agent("bot"), pi_request())
        .await
        .unwrap();
    let status = h
        .requests
        .status(&agent("bot"), &created.id, Duration::from_secs(30))
        .await
        .unwrap();
    let RequestStatus::Error { message } = status else {
        panic!("expected error, got {status:?}");
    };
    assert!(message.contains("failing returned HTTP 503"), "{message}");
    // The change that ended the request comes first; its entry follows.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !audit_types(&h).contains(&"notify_failed".to_owned()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the entry was written");
    // The token was never delivered, but even so it is no longer usable.
    assert_eq!(row_count(&h.pool, "requests").await, 1);
}

#[tokio::test]
async fn notified_audit_names_the_channel_that_delivered() {
    let capture = Arc::new(CapturingNotifier::new());
    let chain: Arc<dyn Notifier> = Arc::new(Fallback::new(
        Arc::new(FailingNotifier),
        vec![capture.clone()],
    ));
    let h = harness_with(healthy_connect().await, Some(chain)).await;
    let mut rx = h.requests.bus().subscribe();
    let created = h
        .requests
        .create(&agent("bot"), pi_request())
        .await
        .unwrap();
    wait_for(&mut rx, &created.id).await;
    capture.next().await;
    let channels: Vec<String> = std::fs::read_to_string(&h.audit_path)
        .unwrap()
        .lines()
        .filter_map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            (v["event"]["type"] == "notified").then(|| v["event"]["channel"].to_string())
        })
        .collect();
    assert_eq!(channels, [r#""capture""#]);
}

#[tokio::test]
async fn dropped_deny_future_leaves_log_usable() {
    let h = harness().await;
    let (created, token) = create_notified(&h, "bot", pi_request()).await;

    // Poll deny exactly once, then drop it mid-flight. A zero timeout is not
    // one poll: its deadline rounds up to the next timer tick, and until then
    // it re-polls deny, whose database and audit work runs off the runtime
    // and can finish in that window.
    let mut deny = Box::pin(h.requests.deny(&token));
    let first = deny.as_mut().poll(&mut Context::from_waker(Waker::noop()));
    assert!(first.is_pending(), "deny finished on its first poll");
    drop(deny);

    // The transition still lands as a whole.
    assert_eq!(
        h.requests
            .status(&agent("bot"), &created.id, Duration::from_secs(5))
            .await
            .unwrap(),
        RequestStatus::Denied
    );
    // And the next transition works on an intact log.
    let (_, token) = create_notified(&h, "bot", pi_request()).await;
    h.requests.deny(&token).await.unwrap();
    assert_eq!(
        audit_types(&h),
        [
            "request_created",
            "notified",
            "denied",
            "request_created",
            "notified",
            "denied"
        ]
    );
    audit::verify(&h.audit_path).unwrap();
}
