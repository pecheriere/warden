//! What the approval pages say about a signing request.

use axum::http::StatusCode;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::Window;

#[tokio::test]
async fn the_pages_say_what_a_signature_means() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("sign my commits", Window::D30),
        )
        .await;
    let fingerprint = broker
        .backend
        .commit_signing_public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK);
    for says in [
        fingerprint.as_str(),
        "not that you reviewed the change",
        "Signs without asking",
        "30 days",
    ] {
        assert!(page.body.contains(says), "{says}: {}", page.body);
    }
    // Beyond the server's maximum, so not offered.
    assert!(!page.body.contains("90 days"), "{}", page.body);
    // None of the windows of other grants is offered.
    assert!(!page.body.contains("value=\"4h\""), "{}", page.body);
    let pending = broker.get("/pending").await;
    assert!(pending.body.contains("not that you reviewed the change"));

    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let grants = broker.get("/grants").await;
    for says in [
        fingerprint.as_str(),
        "not that you reviewed the change",
        "audit log",
        "does not undo",
        "class=\"renew\"",
        "(in 30 days)",
    ] {
        assert!(grants.body.contains(says), "{says}: {}", grants.body);
    }
    let history = broker.get("/history").await;
    assert!(history.body.contains("commit signing"), "{}", history.body);
    assert!(history.body.contains("30d"), "{}", history.body);
}

/// A signing grant's request says who asks like any other, as a claim, and the
/// fingerprint is the words people compare.
#[tokio::test]
async fn the_pages_show_the_stated_session_link_and_fingerprint_words() {
    let broker = TestBroker::with_link_hosts("git.example.com").await;
    let key = broker.add_agent("bot").await;
    let mut asked = TestBroker::commit_signing_request("sign my commits", Window::D30);
    asked.session = Some("release-work".parse().unwrap());
    asked.link = Some("https://git.example.com/pulls/1".parse().unwrap());
    let created = broker
        .api_post_json(&key, "/v1/requests", &serde_json::to_value(&asked).unwrap())
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let printed: warden_broker_proto::Fingerprint =
        serde_json::from_value(created.json()["fingerprint"].clone()).unwrap();
    assert_eq!(
        printed,
        warden_broker_proto::fingerprint(&"bot".parse().unwrap(), &asked),
        "the label and link are bound to what is approved"
    );
    let bell = broker.capture.next().await;
    let token = warden_broker::testkit::CapturingNotifier::token(&bell);
    let shown = |html: &str| {
        for says in [
            "release-work",
            "git.example.com/pulls/1",
            printed.words().as_str(),
        ] {
            assert!(html.contains(says), "{says}: {html}");
        }
    };
    shown(&broker.get(&format!("/approve/{token}")).await.body);
    shown(&broker.get("/pending").await.body);
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    shown(&broker.get("/grants").await.body);
    shown(&broker.get("/history").await.body);

    // A link to a host off the list is refused, as for any other request.
    asked.link = Some("https://other.example.org/x".parse().unwrap());
    let refused = broker
        .api_post_json(&key, "/v1/requests", &serde_json::to_value(&asked).unwrap())
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
}
