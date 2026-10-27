//! Notifiers against wiremock servers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use secrecy::SecretString;
use serde_json::json;
use url::Url;
use warden_broker::config::SecretUrl;
use warden_broker::notify::{
    ChannelSettings, Doorbell, Fallback, HaWebhook, Notifier, NotifyError, Ntfy, doorbell,
};
use warden_broker_proto::{Access, AgentName, CreateRequest, Goal, TargetName, UnixUser, Window};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const HOOK_ID: &str = "secret-webhook-id-do-not-leak";

fn bell() -> Doorbell {
    Doorbell {
        title: "warden: bot wants ssh root@pi".to_owned(),
        message: "update packages".to_owned(),
        url: Url::parse("https://warden.example/approve/abc").unwrap(),
    }
}

fn ha(server: &MockServer) -> Arc<dyn Notifier> {
    let url = Url::parse(&format!("{}/api/webhook/{HOOK_ID}", server.uri())).unwrap();
    Arc::new(HaWebhook::new(SecretUrl::new(url)).unwrap())
}

fn ntfy(server: &MockServer) -> Arc<dyn Notifier> {
    let url = Url::parse(&format!("{}/warden", server.uri())).unwrap();
    Arc::new(Ntfy::new(url, None).unwrap())
}

fn request(goal: &str) -> CreateRequest {
    CreateRequest {
        goal: Goal::try_from(goal.to_owned()).unwrap(),
        access: Access::Ssh {
            target: TargetName::try_from("pi".to_owned()).unwrap(),
            user: UnixUser::try_from("root".to_owned()).unwrap(),
            public_key: "ssh-ed25519 AAAA".to_owned(),
        },
        window: Window::M15,
    }
}

#[tokio::test]
async fn ha_posts_expected_json() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/webhook/{HOOK_ID}")))
        .and(body_json(json!({
            "title": "warden: bot wants ssh root@pi",
            "message": "update packages",
            "url": "https://warden.example/approve/abc",
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(ha(&server).ring(&bell()).await.unwrap(), "homeassistant");
}

#[tokio::test]
async fn ntfy_sets_click_title_priority_and_bearer() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/warden"))
        .and(header("Title", "warden: bot wants ssh root@pi"))
        .and(header("Click", "https://warden.example/approve/abc"))
        .and(header("Priority", "high"))
        .and(header("Tags", "lock"))
        .and(header("Authorization", "Bearer tk_secret"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let url = Url::parse(&format!("{}/warden", server.uri())).unwrap();
    let n = Ntfy::new(url, Some(SecretString::from("tk_secret".to_owned()))).unwrap();
    assert_eq!(n.ring(&bell()).await.unwrap(), "ntfy");
    let received = server.received_requests().await.unwrap();
    assert_eq!(received[0].body, b"update packages");
}

#[tokio::test]
async fn ntfy_encodes_non_ascii_title() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("Title", "=?UTF-8?B?d2FyZGVuOiBow6l5?="))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let mut b = bell();
    b.title = "warden: héy".to_owned();
    ntfy(&server).ring(&b).await.unwrap();
}

#[tokio::test]
async fn fallback_uses_secondary_on_primary_500() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&primary)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&secondary)
        .await;
    let f = Fallback::new(ha(&primary), vec![ntfy(&secondary)]);
    assert_eq!(f.ring(&bell()).await.unwrap(), "ntfy");
}

#[tokio::test]
async fn fallback_uses_secondary_on_primary_timeout() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(6)))
        .mount(&primary)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&secondary)
        .await;
    let f = Fallback::new(ha(&primary), vec![ntfy(&secondary)]);
    let start = Instant::now();
    assert_eq!(f.ring(&bell()).await.unwrap(), "ntfy");
    assert!(start.elapsed() < Duration::from_secs(7));
}

#[tokio::test]
async fn fallback_reports_both_failures() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&primary)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&secondary)
        .await;
    let f = Fallback::new(ha(&primary), vec![ntfy(&secondary)]);
    let err = f.ring(&bell()).await.unwrap_err();
    let NotifyError::AllFailed(failures) = &err else {
        panic!("expected AllFailed, got {err:?}");
    };
    assert_eq!(
        failures,
        &[
            NotifyError::Status {
                notifier: "homeassistant",
                status: 500
            },
            NotifyError::Status {
                notifier: "ntfy",
                status: 503
            },
        ]
    );
    let text = err.to_string();
    assert!(
        text.contains("homeassistant returned HTTP 500") && text.contains("ntfy returned HTTP 503"),
        "{text}"
    );
}

#[tokio::test]
async fn fallback_without_secondary_returns_primary_error() {
    let primary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&primary)
        .await;
    let err = Fallback::new(ha(&primary), vec![])
        .ring(&bell())
        .await
        .unwrap_err();
    assert!(matches!(err, NotifyError::Status { status: 500, .. }));
}

#[test]
fn doorbell_truncates_goal_at_200_chars() {
    let agent = AgentName::try_from("bot".to_owned()).unwrap();
    let url = Url::parse("https://warden.example/approve/abc").unwrap();

    let exact = "é".repeat(200);
    let d = doorbell(&agent, "ssh root@pi", &request(&exact), url.clone());
    assert_eq!(d.message, exact);
    assert_eq!(d.title, "warden: bot wants ssh root@pi");
    assert_eq!(d.url, url);

    let long = "é".repeat(201);
    let d = doorbell(&agent, "ssh root@pi", &request(&long), url);
    assert_eq!(d.message, format!("{}…", "é".repeat(200)));
}

#[tokio::test]
async fn webhook_url_not_in_error_messages() {
    // Non-2xx response.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let err = ha(&server).ring(&bell()).await.unwrap_err();
    assert!(!format!("{err} {err:?}").contains(HOOK_ID));

    // Redirects are not followed.
    let redirect = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "http://127.0.0.1:1/x"))
        .mount(&redirect)
        .await;
    let err = ha(&redirect).ring(&bell()).await.unwrap_err();
    assert!(matches!(err, NotifyError::Status { status: 302, .. }));

    // Connection failure: the transport error must not echo the URL.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let url = Url::parse(&format!("{dead}/api/webhook/{HOOK_ID}")).unwrap();
    let n = HaWebhook::new(SecretUrl::new(url)).unwrap();
    let err = n.ring(&bell()).await.unwrap_err();
    assert!(matches!(err, NotifyError::Request { .. }));
    assert!(!format!("{err} {err:?}").contains(HOOK_ID));
    assert!(!format!("{n:?}").contains(HOOK_ID));
}

fn built(settings: &ChannelSettings) -> Arc<dyn Notifier> {
    settings.build().unwrap()
}

fn ha_settings(server: &MockServer) -> ChannelSettings {
    ChannelSettings::HomeAssistant {
        webhook_url: SecretUrl::new(
            Url::parse(&format!("{}/api/webhook/{HOOK_ID}", server.uri())).unwrap(),
        ),
    }
}

fn ntfy_settings(server: &MockServer) -> ChannelSettings {
    ChannelSettings::Ntfy {
        url: Url::parse(&format!("{}/warden", server.uri())).unwrap(),
        token: None,
    }
}

async fn answering(status: u16, expected_calls: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(status))
        .expect(expected_calls)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn a_single_built_channel_works_alone() {
    let server = answering(200, 1).await;
    let chain = Fallback::new(built(&ntfy_settings(&server)), vec![]);
    assert_eq!(chain.ring(&bell()).await.unwrap(), "ntfy");
}

#[tokio::test]
async fn chain_stops_at_the_first_channel_that_accepts() {
    let (first, second, third) = (
        answering(500, 1).await,
        answering(200, 1).await,
        answering(200, 0).await,
    );
    let chain = Fallback::new(
        built(&ha_settings(&first)),
        vec![built(&ntfy_settings(&second)), built(&ha_settings(&third))],
    );
    assert_eq!(chain.ring(&bell()).await.unwrap(), "ntfy");
}

#[tokio::test]
async fn chain_tries_channels_in_configured_order_and_reports_every_failure() {
    let (first, second, third) = (
        answering(502, 1).await,
        answering(503, 1).await,
        answering(504, 1).await,
    );
    let chain = Fallback::new(
        built(&ntfy_settings(&first)),
        vec![built(&ha_settings(&second)), built(&ntfy_settings(&third))],
    );
    let err = chain.ring(&bell()).await.unwrap_err();
    let NotifyError::AllFailed(failures) = &err else {
        panic!("expected AllFailed, got {err:?}");
    };
    let statuses: Vec<u16> = failures
        .iter()
        .map(|f| match f {
            NotifyError::Status { status, .. } => *status,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(statuses, [502, 503, 504]);
    assert!(!err.to_string().contains(HOOK_ID));
}
