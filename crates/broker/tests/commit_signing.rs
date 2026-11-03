//! Commit signing through the agent API. Keys are generated for each test; time only
//! moves through the broker's manual clock.

use std::fs;
use std::io::Write as _;
use std::process::{Command, Stdio};

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sha2::Digest as _;
use ssh_key::LineEnding;
use ssh_key::rand_core::OsRng;
use warden_broker::testkit::{CaState, FakeBackend, TestBroker, TestResponse};
use warden_broker_proto::Window;
use warden_broker_proto::commit_signing::{NO_ACTIVE_GRANT, NOT_CONFIGURED};

const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const PARENT: &str = "1111111111111111111111111111111111111111";
const AUTHOR: &str = "build-agent <build-agent@example.com> 1800000000 +0000";

fn commit() -> String {
    format!("tree {TREE}\nparent {PARENT}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\nFix the thing\n")
}

fn body(namespace: &str, payload: &[u8]) -> Value {
    json!({"namespace": namespace, "payload_b64": STANDARD.encode(payload)})
}

async fn sign_as(broker: &TestBroker, key: &str, namespace: &str, payload: &[u8]) -> TestResponse {
    broker
        .api_post_json(key, "/v1/commit-signing/sign", &body(namespace, payload))
        .await
}

async fn sign(broker: &TestBroker, key: &str) -> TestResponse {
    sign_as(broker, key, "git", commit().as_bytes()).await
}

/// A broker and an agent with an active 30-day grant; returns the agent's key and
/// the grant.
async fn granted() -> (TestBroker, String, String) {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let grant = approve(&broker, "bot").await;
    (broker, key, grant)
}

/// Ask for and approve commit signing for `agent`, returning the grant.
async fn approve(broker: &TestBroker, agent: &str) -> String {
    let (created, token) = broker
        .create_request(
            agent,
            TestBroker::commit_signing_request("sign my commits", Window::D30),
        )
        .await;
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let agent_name = agent.parse().unwrap();
    let status = broker
        .state()
        .requests
        .status(&agent_name, &created.id, std::time::Duration::ZERO)
        .await
        .unwrap();
    let warden_broker_proto::RequestStatus::Approved(view) = status else {
        panic!("not approved: {status:?}");
    };
    view.grant_id.to_string()
}

/// Every audit entry of type `kind`, oldest first.
fn entries(broker: &TestBroker, kind: &str) -> Vec<Value> {
    fs::read_to_string(broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["event"].clone())
        .filter(|event| event["type"] == kind)
        .collect()
}

/// Assert `resp` was refused with `status`, carries no signature, and was recorded
/// with its reason.
fn assert_refused(broker: &TestBroker, resp: &TestResponse, status: StatusCode, says: &str) {
    assert_eq!(resp.status, status, "{}", resp.body);
    assert!(resp.body.contains(says), "{}", resp.body);
    assert!(!resp.body.contains("SSH SIGNATURE"), "{}", resp.body);
    let refused = entries(broker, "commit_signing_refused");
    let last = refused.last().expect("a refusal entry");
    assert!(
        last["reason"].as_str().unwrap().contains(says),
        "{last}: {says}"
    );
}

#[tokio::test]
async fn a_signature_verifies_with_ssh_keygen_and_is_recorded() {
    let (broker, key, grant) = granted().await;
    let resp = sign(&broker, &key).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let signed = resp.json();
    assert_eq!(signed["grant_id"], grant);

    let dir = tempfile::tempdir().unwrap();
    let public = broker.backend.commit_signing_public_key();
    let allowed = dir.path().join("allowed");
    fs::write(
        &allowed,
        format!(
            "build-agent@example.com namespaces=\"git\" {}\n",
            public.to_openssh().unwrap()
        ),
    )
    .unwrap();
    let signature = dir.path().join("sig");
    fs::write(&signature, signed["signature"].as_str().unwrap()).unwrap();
    let mut verify = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-n", "git", "-I", "build-agent@example.com"])
        .arg("-f")
        .arg(&allowed)
        .arg("-s")
        .arg(&signature)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ssh-keygen (OpenSSH) is needed for this test");
    verify
        .stdin
        .take()
        .unwrap()
        .write_all(commit().as_bytes())
        .unwrap();
    let out = verify.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let recorded = entries(&broker, "commit_signed");
    assert_eq!(recorded.len(), 1);
    let entry = &recorded[0];
    assert_eq!(entry["grant_id"], grant);
    assert_eq!(entry["agent"], "bot");
    assert_eq!(entry["commit"], signed["commit"]);
    assert_eq!(
        entry["payload_sha256"],
        hex::encode(sha2::Sha256::digest(commit().as_bytes()))
    );
    assert_eq!(entry["tree"], TREE);
    assert_eq!(entry["parents"], json!([PARENT]));
    assert_eq!(entry["author"], AUTHOR);
    assert_eq!(
        entry["key_fingerprint"],
        public.fingerprint(ssh_key::HashAlg::Sha256).to_string()
    );
    assert_eq!(entries(&broker, "commit_signing_refused"), [] as [Value; 0]);
}

#[tokio::test]
async fn no_grant_is_refused_and_recorded() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let resp = sign(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::FORBIDDEN, NO_ACTIVE_GRANT);
    let refused = entries(&broker, "commit_signing_refused");
    assert_eq!(refused[0]["agent"], "bot");
    assert_eq!(refused[0]["grant_id"], Value::Null);
    assert_eq!(refused[0]["payload_sha256"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn the_window_ends_signing_to_the_second() {
    let (broker, key, _) = granted().await;
    broker.clock.advance(30 * 86_400 - 1);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);
    broker.clock.advance(1);
    let resp = sign(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::FORBIDDEN, NO_ACTIVE_GRANT);
}

#[tokio::test]
async fn revoking_stops_the_next_signature() {
    let (broker, key, grant) = granted().await;
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);
    let revoked = broker
        .post_json(&format!("/grants/{grant}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
    let resp = sign(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::FORBIDDEN, NO_ACTIVE_GRANT);
    // Revoking stops new ones; what was signed stays on record.
    assert_eq!(entries(&broker, "commit_signed").len(), 1);
}

#[tokio::test]
async fn revoking_the_agent_stops_its_signatures() {
    let (broker, key, _) = granted().await;
    let name = "bot".parse().unwrap();
    broker.state().requests.revoke_agent(&name).await.unwrap();
    let resp = sign(&broker, &key).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{}", resp.body);
    assert!(!resp.body.contains("SSH SIGNATURE"));
}

#[tokio::test]
async fn another_agents_grant_does_not_work() {
    let (broker, _, _) = granted().await;
    let other = broker.add_agent("other").await;
    let resp = sign(&broker, &other).await;
    assert_refused(&broker, &resp, StatusCode::FORBIDDEN, NO_ACTIVE_GRANT);
    let refused = entries(&broker, "commit_signing_refused");
    assert_eq!(refused[0]["agent"], "other");
}

#[tokio::test]
async fn a_tag_object_is_refused_and_recorded_under_an_active_grant() {
    let (broker, key, grant) = granted().await;
    let tag = format!("object {PARENT}\ntype commit\ntag v1.0.0\ntagger {AUTHOR}\n\nrelease\n");
    let resp = sign_as(&broker, &key, "git", tag.as_bytes()).await;
    assert_refused(&broker, &resp, StatusCode::BAD_REQUEST, "tag object");
    let refused = entries(&broker, "commit_signing_refused");
    assert_eq!(refused[0]["grant_id"], grant);
    // The tag's name is the agent's text, and only its digest is kept.
    assert!(!refused[0].to_string().contains("v1.0.0"));
    assert_eq!(entries(&broker, "commit_signed"), [] as [Value; 0]);
}

#[tokio::test]
async fn another_namespace_is_refused_and_recorded() {
    let (broker, key, _) = granted().await;
    for namespace in ["file", "warden-request-v1", "GIT", "git ", ""] {
        let resp = sign_as(&broker, &key, namespace, commit().as_bytes()).await;
        assert_refused(
            &broker,
            &resp,
            StatusCode::BAD_REQUEST,
            "namespace is signed",
        );
    }
    assert_eq!(entries(&broker, "commit_signed"), [] as [Value; 0]);
}

#[tokio::test]
async fn malformed_and_ambiguous_payloads_are_refused_and_recorded() {
    let (broker, key, _) = granted().await;
    let mut with_nul = commit().into_bytes();
    with_nul.extend_from_slice(b"\0tree evil\n");
    for payload in [
        with_nul,
        b"hello".to_vec(),
        b"".to_vec(),
        format!("tree {TREE}\ncommitter {AUTHOR}\nauthor {AUTHOR}\n\nm\n").into_bytes(),
        format!("tree {TREE}\ntree {TREE}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\nm\n")
            .into_bytes(),
        format!("tree {TREE}\nauthor {AUTHOR}\ncommitter {AUTHOR}\ngpgsig x\n\nm\n").into_bytes(),
        format!("certificate version 0.1\npusher {AUTHOR}\n\n").into_bytes(),
    ] {
        let resp = sign_as(&broker, &key, "git", &payload).await;
        assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
        assert!(!resp.body.contains("SSH SIGNATURE"));
    }
    assert_eq!(entries(&broker, "commit_signing_refused").len(), 7);
    assert_eq!(entries(&broker, "commit_signed"), [] as [Value; 0]);
}

#[tokio::test]
async fn a_body_that_does_not_parse_is_refused_and_recorded() {
    let (broker, key, _) = granted().await;
    for body in [
        json!({"namespace": "git"}),
        json!({"namespace": "git", "payload_b64": 7}),
    ] {
        let resp = broker
            .api_post_json(&key, "/v1/commit-signing/sign", &body)
            .await;
        assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    }
    let not_base64 = json!({"namespace": "git", "payload_b64": "***"});
    let resp = broker
        .api_post_json(&key, "/v1/commit-signing/sign", &not_base64)
        .await;
    assert_refused(&broker, &resp, StatusCode::BAD_REQUEST, "not base64");
    assert_eq!(entries(&broker, "commit_signing_refused").len(), 3);
}

#[tokio::test]
async fn too_large_a_commit_is_refused_and_recorded() {
    let (broker, key, _) = granted().await;
    let mut huge = commit().into_bytes();
    huge.resize(
        warden_broker_proto::commit_signing::MAX_PAYLOAD_BYTES + 1,
        b'x',
    );
    let resp = sign_as(&broker, &key, "git", &huge).await;
    assert_refused(&broker, &resp, StatusCode::PAYLOAD_TOO_LARGE, "too large");
}

#[tokio::test]
async fn refused_calls_cannot_fill_the_audit_log() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    for _ in 0..35 {
        let resp = sign(&broker, &key).await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    }
    assert_eq!(entries(&broker, "commit_signing_refused").len(), 30);
    broker.state().requests.flush_refusals(false).await;
    let held = entries(&broker, "commit_signing_refusals_held");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0]["agent"], "bot");
    assert_eq!(held[0]["count"], 5);
}

#[tokio::test]
async fn thirty_days_is_for_signing_only() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "not-a-real-secret");
    // Asked for at the API, whatever the CLI would send.
    for (request, says) in [
        (TestBroker::pi_request("goal", Window::D30), "exceeds max"),
        (
            TestBroker::relay_request("goal", Window::D30),
            "exceeds max",
        ),
        (
            TestBroker::api_request("github", "goal", Window::D30),
            "exceeds max",
        ),
    ] {
        let resp = broker
            .api_post_json(
                &key,
                "/v1/requests",
                &serde_json::to_value(&request).unwrap(),
            )
            .await;
        assert_ne!(resp.status, StatusCode::CREATED, "{}", resp.body);
        assert!(
            resp.status == StatusCode::NOT_FOUND || resp.body.contains(says),
            "{}",
            resp.body
        );
    }
    // Chosen at approval: refused before any passkey is asked for.
    let (_, token) = broker
        .create_request("bot", TestBroker::pi_request("goal", Window::M15))
        .await;
    broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::D30).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    // A policy cannot say so either.
    assert!("30d".parse::<Window>().is_err());
}

#[tokio::test]
async fn a_grant_lasts_exactly_the_window_approved() {
    let (broker, key, grant) = granted().await;
    let list = broker.api_get(&key, "/v1/grants").await.json();
    assert_eq!(list[0]["grant_id"], grant);
    assert_eq!(list[0]["access"]["kind"], "commit_signing");
    let (not_before, not_after) = (
        list[0]["not_before"].as_i64().unwrap(),
        list[0]["not_after"].as_i64().unwrap(),
    );
    assert_eq!(not_after - not_before, 30 * 86_400);
}

#[tokio::test]
async fn signing_grants_only_take_their_own_windows() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let short = TestBroker::commit_signing_request("goal", Window::H4);
    let resp = broker
        .api_post_json(&key, "/v1/requests", &serde_json::to_value(&short).unwrap())
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("goal", Window::D7),
        )
        .await;
    broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::H1).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
}

#[tokio::test]
async fn the_server_setting_is_the_maximum() {
    let body =
        |window| serde_json::to_value(TestBroker::commit_signing_request("goal", window)).unwrap();
    // The default: 30 days, not 90.
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let resp = broker
        .api_post_json(&key, "/v1/requests", &body(Window::D90))
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(resp.body.contains("exceeds max 30d"), "{}", resp.body);

    let short = TestBroker::with_commit_signing_max(Window::D7).await;
    let key = short.add_agent("bot").await;
    let resp = short
        .api_post_json(&key, "/v1/requests", &body(Window::D30))
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    let resp = short
        .api_post_json(&key, "/v1/requests", &body(Window::D7))
        .await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.body);

    let long = TestBroker::with_commit_signing_max(Window::D90).await;
    let key = long.add_agent("bot").await;
    let resp = long
        .api_post_json(&key, "/v1/requests", &body(Window::D90))
        .await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.body);
}

#[tokio::test]
async fn a_broker_without_a_key_says_so_and_signs_nothing() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    broker.backend.set_commit_signing_key(None);
    let asked = TestBroker::commit_signing_request("goal", Window::D30);
    let resp = broker
        .api_post_json(&key, "/v1/requests", &serde_json::to_value(&asked).unwrap())
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(resp.body.contains(NOT_CONFIGURED), "{}", resp.body);
    // With a grant, as the key can then go missing, it says that too.
    let (broker, key, _) = granted().await;
    broker.backend.set_commit_signing_key(None);
    let public = broker.api_get(&key, "/v1/commit-signing/key").await;
    assert!(public.body.contains(NOT_CONFIGURED), "{}", public.body);
}

#[tokio::test]
async fn an_agent_with_no_grant_cannot_make_the_broker_read_the_key() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let public = broker.api_get(&key, "/v1/commit-signing/key").await;
    assert_eq!(public.status, StatusCode::FORBIDDEN, "{}", public.body);
    assert!(public.body.contains(NO_ACTIVE_GRANT), "{}", public.body);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::FORBIDDEN);
    let asked =
        serde_json::to_value(TestBroker::commit_signing_request("goal", Window::D30)).unwrap();
    let created = broker.api_post_json(&key, "/v1/requests", &asked).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(broker.backend.commit_signing_reads(), 0);
    // Nor once a grant has ended.
    let (broker, key, _) = granted().await;
    broker.clock.advance(30 * 86_400);
    let reads = broker.backend.commit_signing_reads();
    let public = broker.api_get(&key, "/v1/commit-signing/key").await;
    assert_eq!(public.status, StatusCode::FORBIDDEN, "{}", public.body);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::FORBIDDEN);
    assert_eq!(broker.backend.commit_signing_reads(), reads);
}

#[tokio::test]
async fn a_grant_stops_at_its_daily_limit_and_the_owner_hears_once() {
    let broker = TestBroker::with_commit_signing_per_day(2).await;
    let key = broker.add_agent("bot").await;
    let grant = approve(&broker, "bot").await;
    let other = broker.add_agent("other").await;
    approve(&broker, "other").await;
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);

    let reads = broker.backend.commit_signing_reads();
    let resp = sign(&broker, &key).await;
    assert_refused(
        &broker,
        &resp,
        StatusCode::TOO_MANY_REQUESTS,
        "limit of signatures",
    );
    assert_eq!(broker.backend.commit_signing_reads(), reads, "no key read");
    let bell = broker.capture.next().await;
    assert_eq!(bell.title, "warden: bot reached its commit signing limit");
    assert!(bell.url.path().ends_with("/grants"));
    assert_eq!(entries(&broker, "commit_signed").len(), 2);
    assert_eq!(
        sign(&broker, &key).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let reached = entries(&broker, "commit_signing_limit_reached");
    assert_eq!(reached.len(), 1, "once a day");
    assert_eq!(reached[0]["grant_id"], grant);
    assert_eq!(reached[0]["limit"], 2);

    // Per grant: another agent's goes on.
    assert_eq!(sign(&broker, &other).await.status, StatusCode::OK);

    // The next UTC day starts again, and can be told about again.
    broker.clock.advance(86_400);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);
    assert_eq!(
        sign(&broker, &key).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(entries(&broker, "commit_signing_limit_reached").len(), 2);
}

#[tokio::test]
async fn the_daily_limit_holds_for_concurrent_calls() {
    let broker = TestBroker::with_commit_signing_per_day(3).await;
    let key = broker.add_agent("bot").await;
    approve(&broker, "bot").await;
    let (first, second, third, fourth, fifth) = tokio::join!(
        sign(&broker, &key),
        sign(&broker, &key),
        sign(&broker, &key),
        sign(&broker, &key),
        sign(&broker, &key),
    );
    let ok = [first, second, third, fourth, fifth]
        .iter()
        .filter(|r| r.status == StatusCode::OK)
        .count();
    assert_eq!(ok, 3);
}

#[tokio::test]
async fn a_ca_that_cannot_be_used_blocks_approval_and_having_none_does_not() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("goal", Window::D30),
        )
        .await;
    broker.enroll_soft_passkey().await;
    broker.backend.set_ca_state(CaState::Unusable);
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(
        page.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        page.body
    );
    assert!(page.body.contains("SSH CA cannot be read"), "{}", page.body);
    let begin = broker.begin_approval(&token, Window::D30).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(
        begin.body.contains("SSH CA cannot be read"),
        "{}",
        begin.body
    );
    // With no CA at all, there is nothing it could be the same as.
    broker.backend.set_ca_state(CaState::Absent);
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
}

#[tokio::test]
async fn the_ca_key_cannot_be_approved_for_signing() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let good = broker.backend.commit_signing_private_key();
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("goal", Window::D30),
        )
        .await;
    broker.enroll_soft_passkey().await;
    broker
        .backend
        .set_commit_signing_key(Some(broker.backend.ca_private_key()));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(
        page.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        page.body
    );
    assert!(page.body.contains("also the SSH CA key"), "{}", page.body);
    let begin = broker.begin_approval(&token, Window::D30).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(begin.body.contains("also the SSH CA key"), "{}", begin.body);
    // A CA that cannot be read refuses too: nothing says the keys differ.
    broker.backend.set_commit_signing_key(Some(good));
    broker.backend.set_ca_outage(Some("out"));
    let begin = broker.begin_approval(&token, Window::D30).await;
    assert_eq!(
        begin.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        begin.body
    );
    broker.backend.set_ca_outage(None);
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
}

#[tokio::test]
async fn an_unreadable_key_refuses_with_nothing_about_why() {
    let (broker, key, grant) = granted().await;
    broker
        .backend
        .set_commit_signing_outage(Some("connect at 192.0.2.7 refused"));
    let resp = sign(&broker, &key).await;
    assert_refused(
        &broker,
        &resp,
        StatusCode::SERVICE_UNAVAILABLE,
        "secret backend unavailable",
    );
    assert!(!resp.body.contains("192.0.2.7"));
    let refused = entries(&broker, "commit_signing_refused");
    assert_eq!(refused[0]["grant_id"], grant);
    assert!(!refused[0].to_string().contains("192.0.2.7"));
    broker.backend.set_commit_signing_outage(None);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_new_key_ends_what_was_approved_for_the_old_one() {
    let (broker, key, _) = granted().await;
    broker.backend.set_commit_signing_key(Some(
        ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap(),
    ));
    let resp = sign(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::CONFLICT, "key changed");
    assert_eq!(entries(&broker, "commit_signed"), [] as [Value; 0]);
}

#[tokio::test]
async fn an_entry_that_cannot_be_written_keeps_the_signature_back() {
    let (broker, key, _) = granted().await;
    let stall = broker.state().audit.stall_appends(|event| {
        matches!(event, warden_broker::audit::AuditEvent::CommitSigned { .. })
    });
    let asked = body("git", commit().as_bytes());
    let pending = broker.api_post_json(&key, "/v1/commit-signing/sign", &asked);
    tokio::pin!(pending);
    // The signature is not out while its entry is being written; revoking then means
    // it never is.
    tokio::select! {
        biased;
        resp = &mut pending => panic!("answered before the entry was written: {}", resp.body),
        () = stall.until_holding(1) => {}
    }
    let grants = broker.state().requests.active_grants().await.unwrap();
    broker
        .state()
        .requests
        .revoke_grant(&grants[0].grant_id, "owner")
        .await
        .unwrap();
    drop(stall);
    let resp = pending.await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(!resp.body.contains("SSH SIGNATURE"));
}

#[tokio::test]
async fn no_signature_leaves_the_broker_without_its_audit_entry() {
    let (broker, key, _) = granted().await;
    let good = fs::read(broker.audit_path()).unwrap();
    let mut corrupt = good.clone();
    corrupt.extend_from_slice(b"not an audit line\n");
    fs::write(broker.audit_path(), &corrupt).unwrap();
    let resp = sign(&broker, &key).await;
    assert!(resp.status.is_server_error(), "{}", resp.body);
    assert!(!resp.body.contains("SSH SIGNATURE"), "{}", resp.body);
    assert!(resp.body.contains("internal error"), "{}", resp.body);
    fs::write(broker.audit_path(), &good).unwrap();
    let resp = sign(&broker, &key).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(entries(&broker, "commit_signed").len(), 1);
}

#[tokio::test]
async fn the_key_stays_out_of_every_answer_and_the_audit_log() {
    let (broker, key, grant) = granted().await;
    let private = broker.backend.commit_signing_private_key();
    let pem = private.to_openssh(LineEnding::LF).unwrap();
    // The lines of the armor, each long enough not to turn up by chance.
    let needles: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    assert_ne!(needles, [] as [&str; 0]);
    let mut seen = vec![
        sign(&broker, &key).await.body,
        broker.api_get(&key, "/v1/commit-signing/key").await.body,
        broker.api_get(&key, "/v1/grants").await.body,
        broker.get("/grants").await.body,
        broker.get("/history").await.body,
    ];
    let tag = format!("object {PARENT}\ntype commit\ntag v1\ntagger {AUTHOR}\n\nm\n");
    seen.push(sign_as(&broker, &key, "git", tag.as_bytes()).await.body);
    seen.push(fs::read_to_string(broker.audit_path()).unwrap());
    seen.push(format!(
        "{:?}",
        broker.state().backend.commit_signing_key().await.unwrap()
    ));
    let views: Vec<String> = sqlx::query_scalar("SELECT view FROM grants")
        .fetch_all(&broker.state().pool)
        .await
        .unwrap();
    seen.extend(views);
    assert!(seen.iter().any(|text| text.contains(&grant)));
    for text in &seen {
        for needle in &needles {
            assert!(!text.contains(needle), "the key is in: {text}");
        }
    }
}

#[tokio::test]
async fn the_public_key_is_what_setup_needs() {
    let (broker, key, _) = granted().await;
    let view = broker.api_get(&key, "/v1/commit-signing/key").await;
    assert_eq!(view.status, StatusCode::OK, "{}", view.body);
    let view = view.json();
    let public = broker.backend.commit_signing_public_key();
    assert_eq!(view["public_key"], public.to_openssh().unwrap());
    assert_eq!(
        view["fingerprint"],
        public.fingerprint(ssh_key::HashAlg::Sha256).to_string()
    );
    // Agents only.
    let anonymous = broker.api_get("nope", "/v1/commit-signing/key").await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}

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

/// The approval token at the end of `link`.
fn token_of(link: &str) -> String {
    link.rsplit('/').next().unwrap().to_owned()
}

#[tokio::test]
async fn renewing_takes_one_passkey_approval_and_replaces_the_grant() {
    let (broker, key, old) = granted().await;
    broker.clock.advance(28 * 86_400);
    let rung_before = broker.capture.rung().len();
    let renewed = broker
        .post_json(&format!("/grants/{old}/renew"), &json!({}))
        .await;
    assert_eq!(renewed.status, StatusCode::OK, "{}", renewed.body);
    let link = renewed.json()["link"].as_str().unwrap().to_owned();
    // The same length as the grant it renews.
    let page = broker.get(&format!("/approve/{}", token_of(&link))).await;
    assert!(
        page.body.contains(r#"value="30d" checked"#),
        "{}",
        page.body
    );
    assert!(page.body.contains("Renew commit signing"), "{}", page.body);
    // Starting it rings nobody, grants nothing and leaves the old grant working.
    assert_eq!(broker.capture.rung().len(), rung_before);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);

    let approved = broker.approve(&token_of(&link), Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let list = broker.api_get(&key, "/v1/grants").await.json();
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 1, "one grant at a time: {list:?}");
    assert_ne!(list[0]["grant_id"], old.as_str());
    let new = list[0]["grant_id"].as_str().unwrap().to_owned();
    let ended = entries(&broker, "grant_revoked");
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0]["grant_id"], old.as_str());
    assert_eq!(ended[0]["by"], "renewed");
    let approvals = entries(&broker, "approved");
    assert_eq!(approvals.len(), 2);
    assert_eq!(approvals[1]["grant_id"], new.as_str());

    // Past the end of the old window, signing goes on under the new one.
    broker.clock.advance(3 * 86_400);
    let resp = sign(&broker, &key).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["grant_id"], new.as_str());

    // Revoking the one there is stops signing: nothing is left behind it.
    let revoked = broker
        .post_json(&format!("/grants/{new}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn only_an_active_signing_grant_can_be_renewed() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (created, token) = broker
        .create_request("bot", TestBroker::pi_request("goal", Window::M15))
        .await;
    assert_eq!(
        broker.approve(&token, Window::M15).await.status,
        StatusCode::OK
    );
    let name = "bot".parse().unwrap();
    let status = broker
        .state()
        .requests
        .status(&name, &created.id, std::time::Duration::ZERO)
        .await
        .unwrap();
    let warden_broker_proto::RequestStatus::Approved(ssh) = status else {
        panic!("not approved");
    };
    let resp = broker
        .post_json(&format!("/grants/{}/renew", ssh.grant_id), &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);

    let signing = approve(&broker, "bot").await;
    broker.clock.advance(30 * 86_400);
    let resp = broker
        .post_json(&format!("/grants/{signing}/renew"), &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
}

#[tokio::test]
async fn a_request_already_waiting_is_what_renewing_opens() {
    let (broker, _, old) = granted().await;
    let (created, stale) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("again", Window::D7),
        )
        .await;
    let renewed = broker
        .post_json(&format!("/grants/{old}/renew"), &json!({}))
        .await;
    assert_eq!(renewed.status, StatusCode::OK, "{}", renewed.body);
    let link = renewed.json()["link"].as_str().unwrap().to_owned();
    // The same request, on a new link.
    assert_ne!(token_of(&link), stale);
    let pending = broker.state().requests.pending_expiries().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, created.id);
    // With the goal and window its agent gave, not the grant's, and the page says so.
    let page = broker.get(&format!("/approve/{}", token_of(&link))).await;
    assert!(page.body.contains("again"), "{}", page.body);
    assert!(page.body.contains(r#"value="7d" checked"#), "{}", page.body);
}

fn renewal_notices(broker: &TestBroker) -> Vec<warden_broker::notify::Doorbell> {
    broker
        .capture
        .rung()
        .into_iter()
        .filter(|bell| bell.title.contains("ends soon"))
        .collect()
}

#[tokio::test]
async fn the_owner_hears_once_a_few_days_before_a_grant_ends() {
    let (broker, _, grant) = granted().await;
    let requests = broker.state().requests.clone();

    broker.clock.advance(27 * 86_400 - 1);
    requests.notify_ending_commit_signing().await;
    assert_eq!(renewal_notices(&broker), []);

    broker.clock.advance(1);
    requests.notify_ending_commit_signing().await;
    let notices = renewal_notices(&broker);
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].title, "warden: commit signing for bot ends soon");
    assert!(
        notices[0].message.contains("3 days"),
        "{}",
        notices[0].message
    );
    assert!(notices[0].url.path().ends_with("/grants"));
    let told = entries(&broker, "commit_signing_renewal_notified");
    assert_eq!(told.len(), 1);
    assert_eq!(told[0]["grant_id"], grant);

    broker.clock.advance(86_400);
    requests.notify_ending_commit_signing().await;
    assert_eq!(renewal_notices(&broker).len(), 1, "told once");
}

#[tokio::test]
async fn a_short_grant_is_told_about_late_and_a_revoked_one_not_at_all() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("goal", Window::D1),
        )
        .await;
    assert_eq!(
        broker.approve(&token, Window::D1).await.status,
        StatusCode::OK
    );
    let requests = broker.state().requests.clone();
    requests.notify_ending_commit_signing().await;
    assert_eq!(
        renewal_notices(&broker),
        [],
        "not as soon as it is approved"
    );
    broker.clock.advance(18 * 3600);
    requests.notify_ending_commit_signing().await;
    assert_eq!(renewal_notices(&broker).len(), 1);

    let (other, _, grant) = granted().await;
    other.clock.advance(28 * 86_400);
    let revoked = other
        .post_json(&format!("/grants/{grant}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
    other.state().requests.notify_ending_commit_signing().await;
    assert_eq!(renewal_notices(&other), []);
}

#[tokio::test]
async fn other_grants_are_never_told_about() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (_, token) = broker
        .create_request("bot", TestBroker::pi_request("goal", Window::H1))
        .await;
    assert_eq!(
        broker.approve(&token, Window::H1).await.status,
        StatusCode::OK
    );
    broker.clock.advance(3599);
    broker.state().requests.notify_ending_commit_signing().await;
    assert_eq!(renewal_notices(&broker), []);
}
