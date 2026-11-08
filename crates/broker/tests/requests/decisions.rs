//! A request's status long-poll and its approval.

use std::sync::Arc;
use std::time::Duration;

use sqlx::Row as _;
use warden_broker::requests::RequestError;
use warden_broker_proto::{Id, RequestStatus, Window};

use super::{agent, create_notified, grant_for, harness, pi_request, row_count, wait_for_waiter};

// --- status -----------------------------------------------------------------

#[tokio::test]
async fn status_long_poll_wakes_on_deny() {
    let h = Arc::new(harness().await);
    let (created, token) = create_notified(&h, "bot", pi_request()).await;

    let poller = {
        let h = h.clone();
        let id = created.id.clone();
        tokio::spawn(async move {
            h.requests
                .status(&agent("bot"), &id, Duration::from_secs(30))
                .await
        })
    };
    wait_for_waiter(&h).await;
    h.requests.deny(&token).await.unwrap();

    // Short of the 30 s wait, whose end would also find the request denied.
    let status = tokio::time::timeout(Duration::from_secs(20), poller)
        .await
        .expect("the deny woke the poller")
        .unwrap();
    assert_eq!(status.unwrap(), RequestStatus::Denied);
    assert!(matches!(
        h.requests.deny(&token).await,
        Err(RequestError::AlreadyDecided)
    ));
    assert!(matches!(
        h.requests.pending_for_token(&token).await,
        Err(RequestError::NotFound)
    ));
}

#[tokio::test]
async fn status_long_poll_times_out_pending() {
    let h = harness().await;
    let (created, _) = create_notified(&h, "bot", pi_request()).await;
    let started = std::time::Instant::now();
    let status = h
        .requests
        .status(&agent("bot"), &created.id, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(status, RequestStatus::Pending);
    assert!(started.elapsed() >= Duration::from_millis(200));
}

#[tokio::test]
async fn status_of_other_agents_request_is_not_found() {
    let h = harness().await;
    let (created, _) = create_notified(&h, "bot", pi_request()).await;
    assert!(matches!(
        h.requests
            .status(&agent("other"), &created.id, Duration::ZERO)
            .await,
        Err(RequestError::NotFound)
    ));
    assert!(matches!(
        h.requests
            .status(&agent("bot"), &Id::random(), Duration::ZERO)
            .await,
        Err(RequestError::NotFound)
    ));
}

// --- approval ---------------------------------------------------------------

#[tokio::test]
async fn mark_approved_is_single_use_and_returns_grant() {
    let h = harness().await;
    let (created, token) = create_notified(&h, "bot", pi_request()).await;
    let grant = grant_for(&h, Window::M15);
    let other = grant_for(&h, Window::M15);

    let (a, b) = tokio::join!(
        h.requests
            .mark_approved(&token, Window::M15, grant.clone(), "pk1"),
        h.requests
            .mark_approved(&token, Window::M15, other.clone(), "pk1"),
    );
    let oks = [&a, &b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(oks, 1, "{a:?} {b:?}");
    assert!(
        [a, b]
            .into_iter()
            .any(|r| matches!(r, Err(RequestError::AlreadyDecided)))
    );
    assert_eq!(row_count(&h.pool, "grants").await, 1);

    let RequestStatus::Approved(view) = h
        .requests
        .status(&agent("bot"), &created.id, Duration::ZERO)
        .await
        .unwrap()
    else {
        panic!("expected approved");
    };
    assert!(view == grant || view == other);
    let window: i64 = sqlx::query("SELECT window_secs FROM grants")
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(window, 900);
    assert!(matches!(
        h.requests
            .mark_approved(
                "unknown-token",
                Window::M15,
                grant_for(&h, Window::M15),
                "pk1"
            )
            .await,
        Err(RequestError::NotFound)
    ));
}

#[tokio::test]
async fn mark_approved_rejects_grant_not_spanning_the_window() {
    let h = harness().await;
    let (created, token) = create_notified(&h, "bot", pi_request()).await;
    let mut longer = grant_for(&h, Window::M15);
    longer.not_after += 1;
    let shifted = grant_for(&h, Window::H1);
    for grant in [longer, shifted] {
        assert!(matches!(
            h.requests
                .mark_approved(&token, Window::M15, grant, "pk1")
                .await,
            Err(RequestError::Internal(_))
        ));
    }
    assert_eq!(row_count(&h.pool, "grants").await, 0);
    assert_eq!(
        h.requests
            .status(&agent("bot"), &created.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Pending
    );
}

#[tokio::test]
async fn mark_approved_after_expiry_leaves_no_grant() {
    let h = harness().await;
    let (_, token) = create_notified(&h, "bot", pi_request()).await;
    h.clock.advance(600);
    assert!(matches!(
        h.requests
            .mark_approved(&token, Window::M30, grant_for(&h, Window::M30), "pk1")
            .await,
        Err(RequestError::AlreadyDecided)
    ));
    assert_eq!(row_count(&h.pool, "grants").await, 0);
}

#[tokio::test]
async fn revoke_grant_marks_request_revoked() {
    let h = harness().await;
    let (created, token) = create_notified(&h, "bot", pi_request()).await;
    let grant = grant_for(&h, Window::M30);
    h.requests
        .mark_approved(&token, Window::M30, grant.clone(), "pk1")
        .await
        .unwrap();
    h.requests
        .revoke_grant(&grant.grant_id, "owner")
        .await
        .unwrap();
    assert_eq!(
        h.requests
            .status(&agent("bot"), &created.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Revoked
    );
    // Idempotent; unknown grants are not found.
    h.requests
        .revoke_grant(&grant.grant_id, "owner")
        .await
        .unwrap();
    assert!(matches!(
        h.requests.revoke_grant(&Id::random(), "owner").await,
        Err(RequestError::NotFound)
    ));
}
