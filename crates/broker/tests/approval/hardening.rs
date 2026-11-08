//! Owner-only access, Funnel refusal, cross-origin requests and security
//! headers on every route.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use warden_broker::testkit::{TEST_ORIGIN, TEST_OWNER};
use warden_broker_proto::{Id, RequestStatus, Window};

use super::{CSP, pending, status};

fn every_route(token: &str) -> Vec<(&'static str, String)> {
    let grant = Id::random();
    let request = Id::random();
    vec![
        ("GET", "/pending".to_owned()),
        ("GET", "/pending/live".to_owned()),
        ("POST", format!("/pending/{}/open", request.as_str())),
        ("POST", format!("/pending/{}/deny", request.as_str())),
        ("GET", format!("/approve/{token}")),
        ("POST", format!("/approve/{token}/begin")),
        ("POST", format!("/approve/{token}/finish")),
        ("POST", format!("/approve/{token}/deny")),
        ("GET", "/grants".to_owned()),
        ("GET", "/grants/live".to_owned()),
        ("POST", format!("/grants/{}/revoke", grant.as_str())),
        ("GET", "/history".to_owned()),
        ("GET", "/enroll".to_owned()),
        ("POST", "/enroll/begin".to_owned()),
        ("POST", "/enroll/finish".to_owned()),
        ("GET", "/static/warden.js".to_owned()),
        ("GET", "/static/warden.css".to_owned()),
        ("GET", "/no-such-page".to_owned()),
    ]
}

#[tokio::test]
async fn non_owner_gets_403_everywhere() {
    let (broker, created, token) = pending().await;
    for login in [None, Some("mallory@example.com"), Some("OWNER@example.com")] {
        for (method, path) in every_route(&token) {
            let mut req = Request::builder()
                .method(method)
                .uri(&path)
                .header("Origin", TEST_ORIGIN)
                .header("Content-Type", "application/json");
            if let Some(login) = login {
                req = req.header("Tailscale-User-Login", login);
            }
            let resp = broker
                .send(req.body(Body::from(r#"{"window":"15m"}"#)).unwrap())
                .await;
            assert_eq!(
                resp.status,
                StatusCode::FORBIDDEN,
                "{method} {path} as {login:?}"
            );
            assert_eq!(resp.header("content-security-policy"), CSP);
        }
    }
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
}

/// Every route refuses a request that came through Funnel, whatever login it
/// carries, on its own check and not because a login is missing. The refusal
/// carries the page's security headers like any other answer.
#[tokio::test]
async fn funnel_requests_refused_on_every_approval_route() {
    let (broker, created, token) = pending().await;
    for (method, path) in every_route(&token) {
        for login in [Some(TEST_OWNER), None] {
            for funnel in ["?1", ""] {
                let mut req = Request::builder()
                    .method(method)
                    .uri(&path)
                    .header("Tailscale-Funnel-Request", funnel)
                    .header("Origin", TEST_ORIGIN)
                    .header("Content-Type", "application/json");
                if let Some(login) = login {
                    req = req.header("Tailscale-User-Login", login);
                }
                let resp = broker.send(req.body(Body::from("{}")).unwrap()).await;
                assert_eq!(
                    resp.status,
                    StatusCode::UNAUTHORIZED,
                    "{method} {path} login={login:?} funnel={funnel:?}: {resp:?}"
                );
                assert_eq!(resp.header("content-security-policy"), CSP, "{path}");
            }
        }
    }
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
}

/// The same requests without the header reach the owner's page.
#[tokio::test]
async fn the_funnel_refusal_does_not_touch_tailnet_requests() {
    let (broker, _, _) = pending().await;
    assert_eq!(broker.get("/grants").await.status, StatusCode::OK);
}

#[tokio::test]
async fn cross_origin_post_rejected() {
    let (broker, created, token) = pending().await;
    let post = |origin: Option<&'static str>, content_type: &'static str, path: String| {
        let mut req = Request::post(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Content-Type", content_type);
        if let Some(origin) = origin {
            req = req.header("Origin", origin);
        }
        req.body(Body::from("{}")).unwrap()
    };
    for (_, path) in every_route(&token)
        .into_iter()
        .filter(|(m, _)| *m == "POST")
    {
        for origin in [
            None,
            Some("https://evil.test"),
            Some("null"),
            Some("http://warden.test"),
            Some("https://warden.test:8443"),
            Some("https://sub.warden.test"),
        ] {
            let resp = broker
                .send(post(origin, "application/json", path.clone()))
                .await;
            assert_eq!(resp.status, StatusCode::FORBIDDEN, "{path} from {origin:?}");
        }
        for content_type in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
        ] {
            let resp = broker
                .send(post(Some(TEST_ORIGIN), content_type, path.clone()))
                .await;
            assert_eq!(
                resp.status,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{path} as {content_type}"
            );
        }
    }
    // A charset parameter is fine.
    let resp = broker
        .send(post(
            Some(TEST_ORIGIN),
            "application/json; charset=utf-8",
            format!("/approve/{token}/deny"),
        ))
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Denied);
}

#[tokio::test]
async fn csp_header_present() {
    let (broker, _, token) = pending().await;
    let responses = vec![
        broker.get(&format!("/approve/{token}")).await,
        broker.get("/approve/unknown").await,
        broker.get("/grants").await,
        broker.get("/history").await,
        broker.get("/enroll").await,
        broker.get("/static/warden.js").await,
        broker.get("/static/warden.css").await,
        broker.get("/no-such-page").await,
        broker.begin_approval(&token, Window::M15).await,
        broker.deny(&token).await,
        broker
            .send(Request::get("/grants").body(Body::empty()).unwrap())
            .await,
    ];
    for resp in &responses {
        assert_eq!(resp.header("content-security-policy"), CSP, "{resp:?}");
        assert_eq!(resp.header("referrer-policy"), "no-referrer");
        assert_eq!(resp.header("cache-control"), "no-store");
        assert_eq!(resp.header("x-content-type-options"), "nosniff");
    }
    let js = &responses[5];
    assert_eq!(js.status, StatusCode::OK);
    assert_eq!(js.header("content-type"), "text/javascript; charset=utf-8");
    assert!(js.body.contains("navigator.credentials"));
}
