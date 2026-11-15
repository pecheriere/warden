//! The GitHub App item.

use serde_json::{Value, json};
use warden_broker::policy::{GithubAppProbe, GithubPermissionPolicy, PolicyError, SecretBackend};
use warden_broker::testkit::github_app::{APP_ID, INSTALLATION_ID, RSA2048_PKCS1, RSA2048_PKCS8};
use warden_broker_proto::github_permissions::PermissionSet;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::{TOKEN, VAULT_ID, backend, connect_mock, mount_item, mount_items};

fn summaries(ids: &[&str]) -> Value {
    Value::Array(
        ids.iter()
            .map(|id| {
                json!({
                    "id": id, "title": format!("github-app-{id}"), "category": "API_CREDENTIAL",
                    "vault": {"id": VAULT_ID}, "tags": ["warden:github-app"]
                })
            })
            .collect(),
    )
}

/// A field as the 1Password apps make it: a random id, and the label the owner typed.
fn field(label: &str, value: &str) -> Value {
    json!({"id": format!("x{}", label.len()), "type": "CONCEALED", "label": label, "value": value})
}

fn item(id: &str, fields: &[Value]) -> Value {
    json!({
        "id": id, "title": format!("github-app-{id}"), "vault": {"id": VAULT_ID},
        "tags": ["warden:github-app"], "fields": fields
    })
}

fn full(pem: &[u8]) -> Vec<Value> {
    vec![
        field("app_id", APP_ID),
        field("installation_id", &INSTALLATION_ID.to_string()),
        field("private_key", std::str::from_utf8(pem).unwrap()),
    ]
}

async fn with_item(fields: Vec<Value>) -> MockServer {
    let server = connect_mock().await;
    mount_items(&server, &summaries(&["ga1"])).await;
    mount_item(&server, "ga1", &item("ga1", &fields)).await;
    server
}

fn reason(err: &PolicyError) -> &str {
    match err {
        PolicyError::GithubApp(reason) => reason,
        other => panic!("not a GitHub App error: {other:?}"),
    }
}

#[tokio::test]
async fn github_app_loads_from_the_tagged_item() {
    let server = with_item(full(RSA2048_PKCS1)).await;
    let key = backend(&server).github_app().await.unwrap();
    assert!(format!("{key:?}").contains(APP_ID));
    assert!(backend(&server).has_github_app().await.unwrap());
}

#[tokio::test]
async fn github_app_absent_is_not_configured() {
    let server = connect_mock().await;
    mount_items(&server, &summaries(&[])).await;
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(matches!(err, PolicyError::NoGithubApp), "{err:?}");
    assert!(!backend(&server).has_github_app().await.unwrap());
}

#[tokio::test]
async fn two_github_app_items_is_an_error() {
    let server = connect_mock().await;
    mount_items(&server, &summaries(&["ga1", "ga2"])).await;
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(reason(&err).contains("exactly one"), "{err:?}");
    assert!(backend(&server).has_github_app().await.unwrap());
}

#[tokio::test]
async fn github_app_missing_field_is_invalid() {
    for missing in ["app_id", "installation_id", "private_key"] {
        let mut fields = full(RSA2048_PKCS8);
        fields.retain(|f| f["label"] != missing);
        let server = with_item(fields).await;
        let err = backend(&server).github_app().await.unwrap_err();
        assert!(reason(&err).contains(missing), "{missing}: {err:?}");

        let mut blank = full(RSA2048_PKCS8);
        for f in &mut blank {
            if f["label"] == missing {
                f["value"] = json!("  ");
            }
        }
        let server = with_item(blank).await;
        let err = backend(&server).github_app().await.unwrap_err();
        assert!(reason(&err).contains(missing), "{missing}: {err:?}");
    }
}

#[tokio::test]
async fn github_app_fields_are_matched_by_label_not_id() {
    // The id says app_id, the label says something else: not the field.
    let mut fields = full(RSA2048_PKCS8);
    fields[0] = json!({"id": "app_id", "type": "STRING", "label": "App", "value": APP_ID});
    let server = with_item(fields).await;
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(reason(&err).contains("field \"app_id\""), "{err:?}");
}

#[tokio::test]
async fn github_app_repeated_label_is_refused() {
    let mut fields = full(RSA2048_PKCS8);
    fields.push(field("installation_id", "999"));
    let server = with_item(fields).await;
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(
        reason(&err).contains("\"installation_id\" appears more than once"),
        "{err:?}"
    );
}

#[tokio::test]
async fn github_app_repeated_label_is_refused_even_without_a_value() {
    for empty in [
        json!({"id": "y1", "type": "STRING", "label": "private_key"}),
        json!({"id": "y2", "type": "STRING", "label": "private_key", "value": ""}),
    ] {
        for first in [true, false] {
            let mut fields = full(RSA2048_PKCS8);
            if first {
                fields.insert(0, empty.clone());
            } else {
                fields.push(empty.clone());
            }
            let server = with_item(fields).await;
            let err = backend(&server).github_app().await.unwrap_err();
            assert!(
                reason(&err).contains("\"private_key\" appears more than once"),
                "{empty} first={first}: {err:?}"
            );
        }
    }
}

#[tokio::test]
async fn github_app_non_numeric_installation_is_invalid() {
    for bad in ["abc", "-1", "0", "1.5", "99999999999999999999999"] {
        let mut fields = full(RSA2048_PKCS8);
        fields[1] = field("installation_id", bad);
        let server = with_item(fields).await;
        let err = backend(&server).github_app().await.unwrap_err();
        assert!(reason(&err).contains("installation_id"), "{bad}: {err:?}");
        assert!(!err.to_string().contains(bad), "echoed {bad}: {err}");
    }
}

#[tokio::test]
async fn github_app_bad_key_is_invalid_and_never_quoted() {
    let mut fields = full(RSA2048_PKCS8);
    fields[2] = field("private_key", "SECRET-NOT-A-KEY");
    let server = with_item(fields).await;
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(reason(&err).contains("private_key"), "{err:?}");
    assert!(!err.to_string().contains("SECRET-NOT-A-KEY"), "{err}");
    assert!(!err.to_string().contains(TOKEN), "{err}");
}

#[tokio::test]
async fn github_app_read_once_per_call() {
    let server = with_item(full(RSA2048_PKCS8)).await;
    let connect = backend(&server);
    connect.github_app().await.unwrap();
    connect.github_app().await.unwrap();
    let item_path = format!("/v1/vaults/{VAULT_ID}/items/ga1");
    let reads = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == item_path)
        .count();
    assert_eq!(reads, 2);
    // Asking only whether there is one reads no item at all.
    connect.has_github_app().await.unwrap();
    let reads_after = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == item_path)
        .count();
    assert_eq!(reads_after, 2);
}

#[tokio::test]
async fn github_app_unreadable_item_never_quotes_it() {
    let server = connect_mock().await;
    mount_items(&server, &summaries(&["ga1"])).await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vaults/{VAULT_ID}/items/ga1")))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"fields\": SECRET"))
        .mount(&server)
        .await;
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(!err.to_string().contains("SECRET"), "{err}");
}

fn with_permissions(default: Option<&str>, extra: Option<&str>) -> Vec<Value> {
    let mut fields = full(RSA2048_PKCS8);
    if let Some(value) = default {
        fields.push(field("default_permissions", value));
    }
    if let Some(value) = extra {
        fields.push(field("extra_permissions", value));
    }
    fields
}

#[tokio::test]
async fn permission_fields_missing_mean_legacy_and_no_extras() {
    let server = with_item(full(RSA2048_PKCS8)).await;
    let policy = backend(&server).github_permissions().await.unwrap();
    assert_eq!(policy, GithubPermissionPolicy::legacy());
    assert_eq!(policy.default, PermissionSet::legacy());
    assert!(policy.allowed_extras.is_only_metadata());
    let key = backend(&server).github_app().await.unwrap();
    assert_eq!(key.permissions(), &policy);
}

#[tokio::test]
async fn permission_fields_parse() {
    let server = with_item(with_permissions(
        Some("contents:write,pull_requests:write,issues:write,checks:read"),
        Some("actions:read,statuses:read"),
    ))
    .await;
    let policy = backend(&server).github_permissions().await.unwrap();
    assert_eq!(
        policy.default,
        PermissionSet::parse("checks:read,contents:write,issues:write,pull_requests:write")
            .unwrap()
    );
    assert_eq!(
        policy.allowed_extras,
        PermissionSet::parse("actions:read,statuses:read").unwrap()
    );
    assert_eq!(
        backend(&server).github_app().await.unwrap().permissions(),
        &policy
    );
}

#[tokio::test]
async fn bad_permission_field_makes_the_app_unusable() {
    // Each value is a typo or a refusal the owner could plausibly make; none may be
    // quoted back, and the field's label must be named.
    let bad = [
        "contents:wirte",
        "contnets:read",
        "contents",
        "contents:read,,issues:read",
        "contents:read,contents:write",
        "metadata:write",
        "contents:admin",
        // Levels GitHub does not document for these names.
        "workflows:read",
        "organization_copilot_requests:write",
        "organization_events:write",
        "organization_plan:write",
        "  ",
        "",
    ];
    for label in ["default_permissions", "extra_permissions"] {
        for value in bad {
            let mut fields = full(RSA2048_PKCS8);
            fields.push(field(label, value));
            let server = with_item(fields).await;
            for err in [
                backend(&server).github_permissions().await.unwrap_err(),
                backend(&server).github_app().await.unwrap_err(),
            ] {
                let why = reason(&err);
                assert!(
                    why.contains(&format!("field \"{label}\"")),
                    "{label} {value:?}: {why}"
                );
                let quoted = value.trim();
                assert!(
                    quoted.is_empty() || !why.contains(quoted),
                    "{label} {value:?}: echoed in {why}"
                );
            }
        }
    }
}

const SENSITIVE_SAMPLE: [&str; 4] = [
    "workflows:write",
    "administration:read",
    "secrets:read",
    "organization_plan:read",
];

#[tokio::test]
async fn sensitive_in_allowlist_is_usable() {
    for sensitive in SENSITIVE_SAMPLE {
        let server = with_item(with_permissions(None, Some(sensitive))).await;
        let policy = backend(&server).github_permissions().await.unwrap();
        assert_eq!(policy.default, PermissionSet::legacy());
        assert_eq!(
            policy.allowed_extras,
            PermissionSet::parse(sensitive).unwrap(),
            "{sensitive}"
        );
        backend(&server).github_app().await.unwrap();
    }
}

#[tokio::test]
async fn sensitive_in_default_makes_the_app_unusable() {
    for sensitive in SENSITIVE_SAMPLE {
        let server = with_item(with_permissions(Some(sensitive), None)).await;
        for err in [
            backend(&server).github_permissions().await.unwrap_err(),
            backend(&server).github_app().await.unwrap_err(),
        ] {
            let why = reason(&err);
            assert!(why.contains("field \"default_permissions\""), "{why}");
            assert!(!why.contains(sensitive), "{why}");
            assert!(why.contains("never in the default"), "{why}");
        }
    }
}

#[tokio::test]
async fn repeated_permission_label_is_refused() {
    let mut fields = with_permissions(Some("contents:read"), None);
    fields.push(field("default_permissions", "issues:read"));
    let server = with_item(fields).await;
    let err = backend(&server).github_permissions().await.unwrap_err();
    assert!(
        reason(&err).contains("\"default_permissions\" appears more than once"),
        "{err:?}"
    );
}

#[tokio::test]
async fn github_permissions_does_not_need_the_key() {
    let mut fields = with_permissions(Some("contents:read"), Some("checks:read"));
    for existing in &mut fields {
        if existing["label"] == "private_key" {
            *existing = field("private_key", "SECRET-NOT-A-KEY");
        }
    }
    let server = with_item(fields).await;
    let policy = backend(&server).github_permissions().await.unwrap();
    assert_eq!(
        policy.default,
        PermissionSet::parse("contents:read").unwrap()
    );
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(reason(&err).contains("private_key"), "{err:?}");
}

#[tokio::test]
async fn github_permissions_absent_app_is_not_configured() {
    let server = connect_mock().await;
    mount_items(&server, &summaries(&[])).await;
    let err = backend(&server).github_permissions().await.unwrap_err();
    assert!(matches!(err, PolicyError::NoGithubApp), "{err:?}");
}

#[tokio::test]
async fn doctor_probe_names_the_bad_permission_field() {
    let server = with_item(with_permissions(Some("contents:wirte"), None)).await;
    let GithubAppProbe::Invalid(why) = backend(&server).probe_github_app().await else {
        panic!("a bad permission field must make the probe fail");
    };
    assert!(why.contains("default_permissions"), "{why}");
    assert!(!why.contains("wirte"), "{why}");
    let server = with_item(with_permissions(Some("contents:read"), Some("checks:read"))).await;
    assert!(matches!(
        backend(&server).probe_github_app().await,
        GithubAppProbe::Loaded { .. }
    ));
}
