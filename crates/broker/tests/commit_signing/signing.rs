//! Signing under a grant, every call refused and recorded, and the audit entry
//! a signature waits for.

use std::fs;
use std::io::Write as _;
use std::process::{Command, Stdio};

use axum::http::StatusCode;
use serde_json::{Value, json};
use sha2::Digest as _;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::commit_signing::NO_ACTIVE_GRANT;

use super::{AUTHOR, PARENT, TREE, assert_refused, body, commit, entries, granted, sign, sign_as};

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
