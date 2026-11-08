//! Talking to Connect: errors, the token, and caching and re-resolving the vault id.

use secrecy::SecretString;
use serde_json::{Value, json};
use url::Url;
use warden_broker::policy::{OnePasswordConnect, PolicyError, SecretBackend};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::{
    ITEM_PI, TOKEN, VAULT_ID, VAULTS, backend, connect_mock, fill, host_key_line, list,
    mount_items, target, with_targets,
};

#[tokio::test]
async fn connect_500_is_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_string(format!("boom {TOKEN}")))
        .mount(&server)
        .await;
    let err = backend(&server)
        .ssh_target(&target("pi"))
        .await
        .unwrap_err();
    assert!(matches!(&err, PolicyError::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains(TOKEN), "token leaked: {err}");
}

#[tokio::test]
async fn connection_refused_is_unavailable_without_token() {
    // A port that was just free and has no listener. (A dropped MockServer
    // would not do: wiremock pools servers, so another test may answer.)
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let backend = OnePasswordConnect::new(
        Url::parse(&format!("http://{addr}")).unwrap(),
        SecretString::from(TOKEN.to_owned()),
        "Warden".to_owned(),
    );
    let err = backend.ssh_target(&target("pi")).await.unwrap_err();
    assert!(matches!(&err, PolicyError::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains(TOKEN));
}

#[tokio::test]
async fn unknown_vault_is_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    let err = backend(&server)
        .ssh_target(&target("pi"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::Unavailable(m) if m.contains("Warden")),
        "{err:?}"
    );
}

#[tokio::test]
async fn sends_bearer_token() {
    // The mocks only match when the Authorization header carries the token;
    // an unmatched request would be a 404 and surface as Unavailable.
    let server = with_targets().await;
    backend(&server).ssh_target(&target("pi")).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3, "vault lookup, item list, item fetch");
    for r in requests {
        assert_eq!(
            r.headers.get("authorization").unwrap().to_str().unwrap(),
            format!("Bearer {TOKEN}")
        );
    }
}

#[tokio::test]
async fn vault_id_is_cached_but_items_are_fresh() {
    let server = with_targets().await;
    let b = backend(&server);
    b.ssh_target(&target("pi")).await.unwrap();
    b.ssh_target(&target("pi")).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    let vault_lookups = requests
        .iter()
        .filter(|r| r.url.path() == "/v1/vaults")
        .count();
    assert_eq!(vault_lookups, 1);
    assert_eq!(requests.len(), 5);
}

const NEW_VAULT_ID: &str = "vault0000000000000000000b2";

/// Serve the `Warden` vault under `id`: lookup by name, the item list and the
/// `pi` item (every other path is a 404, as for an id Connect does not know).
async fn serve_vault_as(server: &MockServer, id: &str) {
    let mut vault: Value = serde_json::from_str::<Value>(VAULTS).unwrap()[0].clone();
    vault["id"] = json!(id);
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .and(query_param("filter", r#"name eq "Warden""#))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([vault])))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vaults/{id}/items")))
        .respond_with(ResponseTemplate::new(200).set_body_json(list()))
        .mount(server)
        .await;
    let item = fill(ITEM_PI, "{{HOST_KEY}}", &host_key_line());
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/vaults/{id}/items/pi00000000000000000000000a"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(item))
        .mount(server)
        .await;
}

fn count_requests(requests: &[wiremock::Request], path: &str) -> usize {
    requests.iter().filter(|r| r.url.path() == path).count()
}

#[tokio::test]
async fn vault_recreated_is_re_resolved_once() {
    let server = MockServer::start().await;
    serve_vault_as(&server, VAULT_ID).await;
    let b = backend(&server);
    b.ssh_target(&target("pi")).await.unwrap();

    // The owner recreates the vault: the cached id now answers 404.
    server.reset().await;
    serve_vault_as(&server, NEW_VAULT_ID).await;
    b.ssh_target(&target("pi")).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(count_requests(&requests, "/v1/vaults"), 1, "one re-resolve");
    assert_eq!(
        count_requests(&requests, &format!("/v1/vaults/{VAULT_ID}/items")),
        1,
        "the stale id is tried once"
    );

    // The new id is cached: no further lookups.
    b.ssh_target(&target("pi")).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(count_requests(&requests, "/v1/vaults"), 1);
}

#[tokio::test]
async fn concurrent_callers_re_resolve_a_recreated_vault_once() {
    let server = MockServer::start().await;
    serve_vault_as(&server, VAULT_ID).await;
    let b = std::sync::Arc::new(backend(&server));
    b.ssh_target(&target("pi")).await.unwrap();

    server.reset().await;
    serve_vault_as(&server, NEW_VAULT_ID).await;
    let calls: Vec<_> = (0..8)
        .map(|_| {
            let b = std::sync::Arc::clone(&b);
            tokio::spawn(async move { b.ssh_target(&target("pi")).await })
        })
        .collect();
    for call in calls {
        call.await.unwrap().unwrap();
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(count_requests(&requests, "/v1/vaults"), 1, "single flight");
}

#[tokio::test]
async fn vault_gone_fails_closed_without_retry_loop() {
    let server = MockServer::start().await;
    serve_vault_as(&server, VAULT_ID).await;
    let b = backend(&server);
    b.ssh_target(&target("pi")).await.unwrap();

    // The vault is deleted: its id is 404 and the name no longer resolves.
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    let err = b.ssh_target(&target("pi")).await.unwrap_err();
    assert!(
        matches!(&err, PolicyError::Unavailable(m) if m.contains("Warden")),
        "{err:?}"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2, "list on the stale id, then one lookup");
}

#[tokio::test]
async fn vault_found_again_under_same_id_does_not_loop() {
    // Connect keeps answering 404 for an id that the name lookup still
    // returns: one retry, then the existing error.
    let server = connect_mock().await;
    let b = backend(&server);
    let err = b.ssh_target(&target("pi")).await.unwrap_err();
    assert!(
        matches!(&err, PolicyError::Unavailable(m) if m.contains("404")),
        "{err:?}"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3, "lookup, list (404), lookup; no retry");
}

#[tokio::test]
async fn missing_item_in_an_existing_vault_is_not_retried() {
    let server = connect_mock().await;
    mount_items(&server, &list()).await;
    // The item list names the item, but fetching it is a 404.
    let b = backend(&server);
    let err = b.ssh_target(&target("pi")).await.unwrap_err();
    assert!(matches!(err, PolicyError::Unavailable(_)), "{err:?}");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        4,
        "lookup, list, item (404), one probe lookup"
    );
}
