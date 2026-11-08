//! Expiry, agent revocation and the audit trail of every transition.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use warden_broker::requests::RequestError;
use warden_broker::testkit::CapturingNotifier;
use warden_broker::{agents, audit};
use warden_broker_proto::{RequestStatus, Window};

use super::{
    START, agent, audit_types, create_notified, grant_for, harness, pi_request, wait_for,
    wait_for_waiter,
};

#[tokio::test]
async fn sweep_expires_after_600s() {
    let h = harness().await;
    let (created, token) = create_notified(&h, "bot", pi_request()).await;
    let mut rx = h.requests.bus().subscribe();

    h.clock.advance(599);
    assert_eq!(h.requests.sweep_expired().await.unwrap(), 0);
    assert_eq!(
        h.requests
            .status(&agent("bot"), &created.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Pending
    );

    h.clock.advance(1);
    assert_eq!(h.requests.sweep_expired().await.unwrap(), 1);
    wait_for(&mut rx, &created.id).await;
    assert_eq!(
        h.requests
            .status(&agent("bot"), &created.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Expired
    );
    assert_eq!(h.requests.sweep_expired().await.unwrap(), 0);
    assert!(matches!(
        h.requests.pending_for_token(&token).await,
        Err(RequestError::NotFound)
    ));
}

#[tokio::test]
async fn revoking_agent_cancels_pending_and_wakes_waiters() {
    let h = Arc::new(harness().await);
    // One approved request with an active grant, then a pending one.
    let (approved, token) = create_notified(&h, "bot", pi_request()).await;
    let grant = grant_for(&h, Window::M30);
    h.requests
        .mark_approved(&token, Window::M30, grant.clone(), "pk1")
        .await
        .unwrap();
    let (pending, pending_token) = create_notified(&h, "bot", pi_request()).await;
    let (theirs, _) = create_notified(&h, "other", pi_request()).await;

    let poller = {
        let h = h.clone();
        let id = pending.id.clone();
        tokio::spawn(async move {
            h.requests
                .status(&agent("bot"), &id, Duration::from_secs(30))
                .await
        })
    };
    wait_for_waiter(&h).await;
    h.requests.revoke_agent(&agent("bot")).await.unwrap();

    let woke = tokio::time::timeout(Duration::from_secs(5), poller)
        .await
        .expect("long-poll not woken")
        .unwrap();
    assert_eq!(woke.unwrap(), RequestStatus::Revoked);
    assert_eq!(
        h.requests
            .status(&agent("bot"), &approved.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Revoked
    );
    let revoked_at: Option<i64> = sqlx::query("SELECT revoked_at FROM grants WHERE id = ?")
        .bind(grant.grant_id.as_str())
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(revoked_at, Some(START));
    assert!(matches!(
        agents::authenticate(&h.pool, &h.bot_key).await,
        Err(agents::AgentError::Revoked)
    ));
    // Other agents are untouched.
    assert_eq!(
        h.requests
            .status(&agent("other"), &theirs.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Pending
    );
    // The cancelled request cannot be approved, and no new one can be made.
    assert!(matches!(
        h.requests
            .mark_approved(
                &pending_token,
                Window::M30,
                grant_for(&h, Window::M30),
                "pk1"
            )
            .await,
        Err(RequestError::AlreadyDecided)
    ));
    assert!(matches!(
        h.requests.create(&agent("bot"), pi_request()).await,
        Err(RequestError::AgentRevoked)
    ));
    let types = audit_types(&h);
    assert!(types.contains(&"agent_revoked".to_owned()));
    assert!(types.contains(&"grant_revoked".to_owned()));
    assert!(matches!(
        h.requests.revoke_agent(&agent("nobody")).await,
        Err(RequestError::UnknownAgent(_))
    ));
}

#[tokio::test]
async fn every_transition_is_audited() {
    let h = harness().await;
    let (_, token) = create_notified(&h, "bot", pi_request()).await;
    h.requests.deny(&token).await.unwrap();

    let (_, token) = create_notified(&h, "bot", pi_request()).await;
    let grant = grant_for(&h, Window::M30);
    h.requests
        .mark_approved(&token, Window::M30, grant.clone(), "pk1")
        .await
        .unwrap();
    h.requests
        .revoke_grant(&grant.grant_id, "owner")
        .await
        .unwrap();

    create_notified(&h, "bot", pi_request()).await;
    h.clock.advance(600);
    h.requests.sweep_expired().await.unwrap();

    create_notified(&h, "bot", pi_request()).await;
    h.requests.revoke_agent(&agent("bot")).await.unwrap();

    assert_eq!(
        audit_types(&h),
        [
            "request_created",
            "notified",
            "denied",
            "request_created",
            "notified",
            "approved",
            "cert_issued",
            "grant_revoked",
            "request_created",
            "notified",
            "expired",
            "request_created",
            "notified",
            "agent_revoked",
        ]
    );
    assert_eq!(audit::verify(&h.audit_path).unwrap(), 14);
}

#[tokio::test]
async fn dropped_create_still_rings() {
    let h = harness().await;
    // Hold the audit log's file lock so the insert blocks inside its
    // transaction, after the row is written but before it commits.
    let lock = std::fs::File::open(&h.audit_path).unwrap();
    lock.try_lock().unwrap();
    let create = tokio::spawn({
        let requests = h.requests.clone();
        async move { requests.create(&agent("bot"), pi_request()).await }
    });
    // Policy lookup against the local mock takes milliseconds; give the
    // create ample time to reach the blocked insert, then drop the caller.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!create.is_finished());
    create.abort();
    assert!(create.await.unwrap_err().is_cancelled());
    lock.unlock().unwrap();

    // The insert still commits, and the owner is still notified about it.
    let bell = h.capture.next().await;
    let token = CapturingNotifier::token(&bell);
    let pending: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM requests WHERE status = 'pending' AND approval_token_hash = ?",
    )
    .bind(hex::encode(Sha256::digest(token.as_bytes())))
    .fetch_one(&h.pool)
    .await
    .unwrap()
    .get("n");
    assert_eq!(pending, 1);
}
