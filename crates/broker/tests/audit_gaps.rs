//! An action that gives access does not happen without its audit entry.
//!
//! The audit log is made to fail by adding a line it cannot read: appends then
//! refuse at once, and removing the line makes them work again.

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions as _, Row as _};
use ssh_key::Certificate;
use warden_broker::agents;
use warden_broker::approval::passkeys::{self, PasskeyError};
use warden_broker::requests::{AuditOutcome, Clock as _, RequestError, RequestLimits, sha256_hex};
use warden_broker::testkit::{FakeBackend, SoftAuthenticator, TestBroker, TestResponse};
use warden_broker_proto::{
    AgentName, CreatedResponse, GrantAccess, GrantView, Id, RequestStatus, SshGrant, UnixUser,
    Window,
};

/// Make every append to the audit log fail until the returned bytes are put
/// back.
fn break_audit_log(broker: &TestBroker) -> Vec<u8> {
    let good = std::fs::read(broker.audit_path()).unwrap();
    let mut corrupt = good.clone();
    corrupt.extend_from_slice(b"not an audit line\n");
    std::fs::write(broker.audit_path(), &corrupt).unwrap();
    good
}

fn repair_audit_log(broker: &TestBroker, good: &[u8]) {
    std::fs::write(broker.audit_path(), good).unwrap();
}

fn audit_events(broker: &TestBroker) -> Vec<Value> {
    std::fs::read_to_string(broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["event"].clone())
        .collect()
}

/// Wait until the request's notification is recorded, the last entry the broker
/// writes on its own, so that the log stays as a test saves it.
async fn notification_recorded(broker: &TestBroker) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !broker.audit_types().iter().any(|t| t == "notified") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("notification recorded within 5 s");
}

async fn pending(window: Window) -> (TestBroker, SoftAuthenticator, CreatedResponse, String) {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let auth = broker.enroll_soft_passkey().await;
    let (created, token) = broker
        .create_request("bot", TestBroker::pi_request("restart the job", window))
        .await;
    notification_recorded(&broker).await;
    (broker, auth, created, token)
}

async fn approve(broker: &TestBroker, auth: &mut SoftAuthenticator, token: &str) -> TestResponse {
    let begin = broker.begin_approval(token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let (ceremony, credential) = TestBroker::sign(auth, &begin);
    broker
        .post_json(
            &format!("/approve/{token}/finish"),
            &json!({"ceremony": ceremony, "credential": credential}),
        )
        .await
}

async fn status(broker: &TestBroker, created: &CreatedResponse) -> RequestStatus {
    let bot = AgentName::try_from("bot".to_owned()).unwrap();
    broker
        .state()
        .requests
        .status(&bot, &created.id, Duration::ZERO)
        .await
        .unwrap()
}

async fn row_count(broker: &TestBroker, table: &str) -> i64 {
    let sql = match table {
        "grants" => "SELECT COUNT(*) FROM grants",
        "enrollment_codes" => "SELECT COUNT(*) FROM enrollment_codes",
        other => panic!("no count query for {other}"),
    };
    sqlx::query_scalar(sql)
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn no_certificate_leaves_the_broker_without_its_audit_entry() {
    let (broker, mut auth, created, token) = pending(Window::M30).await;
    let good = break_audit_log(&broker);

    let refused = approve(&broker, &mut auth, &token).await;
    assert_eq!(
        refused.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        refused.body
    );
    let message = refused.json()["error"].as_str().unwrap().to_owned();
    assert!(message.contains("no access was given"), "{message}");

    // Nothing is stored, and the agent still sees the truth: nothing decided.
    assert_eq!(row_count(&broker, "grants").await, 0);
    assert_eq!(status(&broker, &created).await, RequestStatus::Pending);

    // Once the log works, the owner approves again and all of it is recorded.
    repair_audit_log(&broker, &good);
    let approved = approve(&broker, &mut auth, &token).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let RequestStatus::Approved(view) = status(&broker, &created).await else {
        panic!("expected approved");
    };
    let GrantAccess::Ssh(ssh) = &view.access else {
        panic!("expected an ssh grant");
    };
    let events = audit_events(&broker);
    let approved_at = events
        .iter()
        .position(|e| e["type"] == "approved")
        .expect("approved entry");
    let issued = &events[approved_at + 1];
    assert_eq!(issued["type"], "cert_issued", "{events:?}");
    assert_eq!(issued["grant_id"], view.grant_id.as_str());
    assert_eq!(issued["not_after"], view.not_after);
    // What is recorded is what the certificate says.
    let cert = Certificate::from_openssh(&ssh.certificate).unwrap();
    assert_eq!(issued["key_id"], cert.key_id());
    warden_broker::audit::verify(broker.audit_path()).unwrap();
}

#[tokio::test]
async fn one_certificate_gets_one_entry() {
    let (broker, mut auth, created, token) = pending(Window::M15).await;
    let approved = approve(&broker, &mut auth, &token).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(
        broker
            .audit_types()
            .iter()
            .filter(|t| *t == "cert_issued")
            .count(),
        1
    );
    assert!(matches!(
        status(&broker, &created).await,
        RequestStatus::Approved(_)
    ));
}

#[tokio::test]
async fn denying_takes_effect_and_says_so_when_the_log_cannot_be_written() {
    let (broker, _auth, created, token) = pending(Window::M15).await;
    let good = break_audit_log(&broker);
    let denied = broker.deny(&token).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.body);
    let message = denied.json()["message"].as_str().unwrap().to_owned();
    assert!(message.contains("not on record"), "{message}");
    assert_eq!(status(&broker, &created).await, RequestStatus::Denied);
    assert!(grants_page(&broker).await.contains("Not in the audit log"));

    repair_audit_log(&broker, &good);
    broker.state().requests.flush_waiting_entries().await;
    assert!(broker.audit_types().iter().any(|t| t == "denied"));
    assert!(!grants_page(&broker).await.contains("Not in the audit log"));
}

#[tokio::test]
async fn a_request_expires_when_the_log_cannot_be_written() {
    let (broker, _auth, created, _token) = pending(Window::M15).await;
    broker.clock.advance(601);
    let good = break_audit_log(&broker);
    assert_eq!(status(&broker, &created).await, RequestStatus::Expired);
    repair_audit_log(&broker, &good);
    broker.state().requests.flush_waiting_entries().await;
    assert!(broker.audit_types().iter().any(|t| t == "expired"));
}

#[tokio::test]
async fn the_first_sweep_after_a_start_writes_what_a_crash_left_waiting() {
    let (broker, _key, created, grant) = api_grant().await;
    let good = break_audit_log(&broker);
    broker
        .state()
        .requests
        .revoke_grant(&grant, "owner")
        .await
        .unwrap();
    repair_audit_log(&broker, &good);
    let broker = broker.restart().await;
    // A sweep period no test waits for: only the first tick can do this.
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let sweeper = tokio::spawn(warden_broker::requests::sweep_loop(
        broker.state().requests.clone(),
        Duration::from_secs(3600),
        stopped,
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        while broker
            .state()
            .requests
            .unwritten_entry_count()
            .await
            .unwrap()
            > 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the entry was written");
    stop.send(true).unwrap();
    sweeper.await.unwrap();
    assert!(broker.audit_types().iter().any(|t| t == "grant_revoked"));
    assert_eq!(status(&broker, &created).await, RequestStatus::Revoked);
}

#[tokio::test]
async fn making_an_enrollment_code_is_audited_without_the_code() {
    let broker = TestBroker::new().await;
    let code = broker.enrollment_code().await;
    let events = audit_events(&broker);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["type"], "enrollment_code_created");
    assert_eq!(events[0]["expires_at"], broker.clock.now() + 600);
    let log = std::fs::read_to_string(broker.audit_path()).unwrap();
    assert!(!log.contains(&code), "{log}");
    assert!(!log.contains(&sha256_hex(&code)), "{log}");
}

#[tokio::test]
async fn no_enrollment_code_exists_without_its_audit_entry() {
    let broker = TestBroker::new().await;
    let good = break_audit_log(&broker);
    let got = broker
        .state()
        .passkeys
        .create_enrollment_code(broker.clock.now())
        .await;
    assert!(matches!(got, Err(PasskeyError::Audit(_))), "{got:?}");
    assert_eq!(row_count(&broker, "enrollment_codes").await, 0);

    repair_audit_log(&broker, &good);
    broker.enrollment_code().await;
    assert_eq!(row_count(&broker, "enrollment_codes").await, 1);
}

#[tokio::test]
async fn no_passkey_is_removed_without_its_audit_entry() {
    let broker = TestBroker::new().await;
    broker.enroll_soft_passkey().await;
    let state = broker.state();
    let id = passkeys::list(&state.pool).await.unwrap()[0].id.clone();

    let good = break_audit_log(&broker);
    let got = passkeys::remove(&state.pool, &state.audit, &id).await;
    assert!(matches!(got, Err(PasskeyError::Audit(_))), "{got:?}");
    assert_eq!(passkeys::list(&state.pool).await.unwrap().len(), 1);

    repair_audit_log(&broker, &good);
    passkeys::remove(&state.pool, &state.audit, &id)
        .await
        .unwrap();
    assert_eq!(passkeys::list(&state.pool).await.unwrap().len(), 0);
    assert!(broker.audit_types().contains(&"passkey_removed".to_owned()));
}

// --- revocation works without the log ---------------------------------------

/// A broker with agent `bot` (its key returned too), holding an approved API
/// grant.
async fn api_grant() -> (TestBroker, String, CreatedResponse, Id) {
    let broker = TestBroker::new().await;
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "not-a-real-secret");
    let key = broker.add_agent("bot").await;
    broker.enroll_soft_passkey().await;
    let (created, token) = broker
        .create_request(
            "bot",
            TestBroker::api_request("github", "list issues", Window::M15),
        )
        .await;
    notification_recorded(&broker).await;
    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let RequestStatus::Approved(view) = status(&broker, &created).await else {
        panic!("expected approved");
    };
    (broker, key, created, view.grant_id)
}

async fn call(broker: &TestBroker, key: &str, grant: &Id) -> TestResponse {
    broker
        .api_post_json(
            key,
            &format!("/v1/grants/{grant}/http"),
            &json!({"method": "GET", "url": "https://api.example.com/issues", "headers": []}),
        )
        .await
}

#[tokio::test]
async fn the_owner_can_revoke_an_api_grant_when_the_log_cannot_be_written() {
    let (broker, key, created, grant) = api_grant().await;
    let entries = broker.audit_types().len();
    break_audit_log(&broker);

    let revoked = broker
        .post_json(&format!("/grants/{grant}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
    let message = revoked.json()["message"].as_str().unwrap().to_owned();
    assert!(message.contains("access has stopped"), "{message}");
    assert!(message.contains("not on record"), "{message}");
    // A repeat says the same while the entry is missing.
    let again = broker
        .post_json(&format!("/grants/{grant}/revoke"), &json!({}))
        .await;
    assert_eq!(again.json()["message"], revoked.json()["message"]);

    // Access has stopped everywhere the broker decides.
    assert_eq!(status(&broker, &created).await, RequestStatus::Revoked);
    let refused = call(&broker, &key, &grant).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert_eq!(refused.json()["error"], "grant revoked");

    // The owner is told out of band too, without anything an agent wrote.
    let bell = broker.capture.next().await;
    assert!(bell.title.contains("audit log failed"), "{bell:?}");
    assert!(bell.message.contains(grant.as_str()), "{bell:?}");
    assert_eq!(bell.url.path(), "/grants");

    // Nothing was added to the log: the entry really is missing.
    let good = std::fs::read_to_string(broker.audit_path()).unwrap();
    let lines = good.lines().count();
    assert_eq!(lines, entries + 1, "only the line added to break it");
}

#[tokio::test]
async fn an_agent_can_revoke_its_own_grant_and_the_owner_is_told() {
    let (broker, key, _created, grant) = api_grant().await;
    break_audit_log(&broker);
    let revoked = broker
        .api_post(&key, &format!("/v1/grants/{grant}/revoke"))
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{}", revoked.body);
    assert_eq!(
        call(&broker, &key, &grant).await.status,
        StatusCode::CONFLICT
    );
    let bell = broker.capture.next().await;
    assert!(bell.title.contains("audit log failed"), "{bell:?}");
}

#[tokio::test]
async fn revoking_an_agent_stops_its_key_grants_and_requests_when_the_log_fails() {
    let (broker, key, created, grant) = api_grant().await;
    let (waiting, _token) = broker
        .create_request("bot", TestBroker::pi_request("another task", Window::M15))
        .await;
    let bot = AgentName::try_from("bot".to_owned()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while broker
            .audit_types()
            .iter()
            .filter(|t| *t == "notified")
            .count()
            < 2
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("notifications recorded within 5 s");
    break_audit_log(&broker);

    let outcome = broker.state().requests.revoke_agent(&bot).await.unwrap();
    assert_eq!(outcome, AuditOutcome::Missing);

    assert_eq!(status(&broker, &created).await, RequestStatus::Revoked);
    assert_eq!(status(&broker, &waiting).await, RequestStatus::Revoked);
    // The key no longer works at all.
    let refused = call(&broker, &key, &grant).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{}", refused.body);
    let bell = broker.capture.next().await;
    assert!(bell.message.contains("bot"), "{bell:?}");
}

#[tokio::test]
async fn revoking_an_ssh_grant_works_when_the_log_cannot_be_written() {
    let (broker, mut auth, created, token) = pending(Window::M15).await;
    let approved = approve(&broker, &mut auth, &token).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let RequestStatus::Approved(view) = status(&broker, &created).await else {
        panic!("expected approved");
    };
    break_audit_log(&broker);
    let outcome = broker
        .state()
        .requests
        .revoke_grant(&view.grant_id, "owner")
        .await
        .unwrap();
    assert_eq!(outcome, AuditOutcome::Missing);
    assert_eq!(status(&broker, &created).await, RequestStatus::Revoked);
}

#[tokio::test]
async fn a_revocation_the_log_accepts_is_recorded_as_before() {
    let (broker, _key, created, grant) = api_grant().await;
    let revoked = broker
        .post_json(&format!("/grants/{grant}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
    assert_eq!(revoked.json()["message"], "Revoked.");
    assert!(broker.audit_types().iter().any(|t| t == "grant_revoked"));
    assert_eq!(status(&broker, &created).await, RequestStatus::Revoked);
    assert!(
        broker
            .capture
            .rung()
            .iter()
            .all(|bell| !bell.title.contains("audit log failed"))
    );
}

/// The grants page, as the owner gets it.
async fn grants_page(broker: &TestBroker) -> String {
    let page = broker.get("/grants").await;
    assert_eq!(page.status, StatusCode::OK);
    page.body
}

#[tokio::test]
async fn the_warning_stays_on_the_page_until_the_entry_is_in_the_log() {
    let (broker, _key, _created, grant) = api_grant().await;
    assert!(!grants_page(&broker).await.contains("Not in the audit log"));
    let good = break_audit_log(&broker);
    let revoked = broker
        .post_json(&format!("/grants/{grant}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);

    // However often the page reloads, and although no grant is left on it. A new
    // grant does not clear it either.
    for _ in 0..2 {
        assert!(grants_page(&broker).await.contains("Not in the audit log"));
    }
    broker.state().requests.flush_waiting_entries().await;
    assert!(grants_page(&broker).await.contains("Not in the audit log"));

    // Once the log works, the sweep writes the entry, noting it is late.
    broker.clock.advance(120);
    repair_audit_log(&broker, &good);
    broker.state().requests.flush_waiting_entries().await;
    assert!(!grants_page(&broker).await.contains("Not in the audit log"));
    let events = audit_events(&broker);
    let at = events
        .iter()
        .position(|e| e["type"] == "grant_revoked")
        .expect("the entry was written");
    assert_eq!(events[at]["grant_id"], grant.as_str());
    let note = events[at + 1]["message"].as_str().unwrap();
    assert!(note.contains("written late"), "{note}");
    assert!(note.contains(grant.as_str()), "{note}");
    warden_broker::audit::verify(broker.audit_path()).unwrap();
}

#[tokio::test]
async fn an_audit_log_that_has_stalled_does_not_stop_a_revocation() {
    let (broker, key, created, grant) = api_grant().await;
    // Another writer holds the log's lock: appends wait, as on a stalled volume.
    let holder = std::fs::File::open(broker.audit_path()).unwrap();
    holder.lock().unwrap();

    let outcome = broker
        .state()
        .requests
        .revoke_grant(&grant, "owner")
        .await
        .unwrap();
    assert_eq!(outcome, AuditOutcome::Missing);
    assert_eq!(status(&broker, &created).await, RequestStatus::Revoked);
    let refused = call(&broker, &key, &grant).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);

    // The entry follows once the log answers.
    drop(holder);
    tokio::time::timeout(Duration::from_secs(20), async {
        while broker
            .state()
            .requests
            .unwritten_entry_count()
            .await
            .unwrap()
            > 0
        {
            broker.state().requests.flush_waiting_entries().await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the entry was written");
    assert!(broker.audit_types().iter().any(|t| t == "grant_revoked"));
}

// --- writing the log never holds up the database ------------------------------

/// Hold the audit log's lock, as a log that has stalled would, while `work` runs,
/// and check the whole time that another writer can still get into the database,
/// as a revocation must.
async fn assert_no_write_lock_while_log_waits<T: Send + 'static>(
    broker: &TestBroker,
    work: impl Future<Output = T> + Send + 'static,
) {
    let holder = std::fs::File::open(broker.audit_path()).unwrap();
    holder.lock().unwrap();
    let file: String = sqlx::query("PRAGMA database_list")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
        .get("file");
    let mut other = SqliteConnectOptions::new()
        .filename(file)
        // Long enough for a short write to finish, far less than a log can stall.
        .busy_timeout(Duration::from_secs(1))
        .connect()
        .await
        .unwrap();
    let task = tokio::spawn(work);
    while !task.is_finished() {
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut other)
            .await
            .expect("a writer holds the database while it waits for the audit log");
        sqlx::query("ROLLBACK").execute(&mut other).await.unwrap();
        tokio::task::yield_now().await;
    }
    drop(holder);
    task.await.unwrap();
}

#[tokio::test]
async fn creating_a_request_holds_no_write_lock_while_the_log_waits() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let requests = broker.state().requests.clone();
    let bot = AgentName::try_from("bot".to_owned()).unwrap();
    let request = TestBroker::pi_request("restart the job", Window::M15);
    assert_no_write_lock_while_log_waits(&broker, async move {
        drop(requests.create(&bot, request).await);
    })
    .await;
}

#[tokio::test]
async fn approving_holds_no_write_lock_while_the_log_waits() {
    let (broker, _auth, _created, token) = pending(Window::M15).await;
    let now = broker.clock.now();
    let grant = GrantView {
        grant_id: Id::random(),
        not_before: now,
        not_after: now + 900,
        access: GrantAccess::Ssh(SshGrant {
            certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".to_owned(),
            host: "192.0.2.10".to_owned(),
            port: 22,
            user: UnixUser::try_from("alice".to_owned()).unwrap(),
            host_keys: vec![],
        }),
    };
    let requests = broker.state().requests.clone();
    assert_no_write_lock_while_log_waits(&broker, async move {
        drop(
            requests
                .mark_approved(&token, Window::M15, grant, "passkey")
                .await,
        );
    })
    .await;
}

#[tokio::test]
async fn making_an_enrollment_code_holds_no_write_lock_while_the_log_waits() {
    let broker = TestBroker::new().await;
    let passkeys = broker.state().passkeys.clone();
    let now = broker.clock.now();
    assert_no_write_lock_while_log_waits(&broker, async move {
        drop(passkeys.create_enrollment_code(now).await);
    })
    .await;
}

#[tokio::test]
async fn denying_holds_no_write_lock_while_the_log_waits() {
    let (broker, _auth, _created, token) = pending(Window::M15).await;
    let requests = broker.state().requests.clone();
    assert_no_write_lock_while_log_waits(&broker, async move {
        drop(requests.deny(&token).await);
    })
    .await;
}

#[tokio::test]
async fn adding_a_key_signed_agent_holds_no_write_lock_while_the_log_waits() {
    let broker = TestBroker::new().await;
    let pool = broker.state().pool.clone();
    let audit = broker.state().audit.clone();
    let name = AgentName::try_from("new".to_owned()).unwrap();
    let key = agents::AgentPublicKey::parse(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh0zJ+xlPfFH6uwtZmJ2O9GrkMxjqMwPQTsBVmbbBrE new@host",
    )
    .unwrap();
    assert_no_write_lock_while_log_waits(&broker, async move {
        drop(agents::add_key_audited(&pool, &audit, &name, &key).await);
    })
    .await;
}

#[tokio::test]
async fn a_refused_request_holds_no_write_lock_while_the_log_waits() {
    let broker = TestBroker::with_request_limits(RequestLimits {
        max_pending: 1,
        max_new: 10,
        window_secs: 600,
    })
    .await;
    broker.add_agent("bot").await;
    broker
        .create_request("bot", TestBroker::pi_request("restart", Window::M15))
        .await;
    notification_recorded(&broker).await;
    let requests = broker.state().requests.clone();
    let bot = AgentName::try_from("bot".to_owned()).unwrap();
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "not-a-real-secret");
    let refused = TestBroker::api_request("github", "list issues", Window::M15);
    assert_no_write_lock_while_log_waits(&broker, async move {
        let got = requests.create(&bot, refused).await;
        assert!(
            matches!(got, Err(RequestError::Limited(_))),
            "{:?}",
            got.map(|created| created.id)
        );
    })
    .await;
}

#[tokio::test]
async fn a_revocation_goes_through_while_another_writer_waits_for_the_log() {
    let (broker, _key, created, grant) = api_grant().await;
    let holder = std::fs::File::open(broker.audit_path()).unwrap();
    holder.lock().unwrap();
    // A writer that must have its entry first, waiting for the log.
    let passkeys = broker.state().passkeys.clone();
    let now = broker.clock.now();
    let other = tokio::spawn(async move { passkeys.create_enrollment_code(now).await });
    let outcome = broker
        .state()
        .requests
        .revoke_grant(&grant, "owner")
        .await
        .unwrap();
    assert_eq!(outcome, AuditOutcome::Missing);
    assert_eq!(status(&broker, &created).await, RequestStatus::Revoked);
    drop(holder);
    drop(other.await.unwrap());
}

#[tokio::test]
async fn the_sweep_goes_on_expiring_while_the_log_has_stalled() {
    let broker = TestBroker::with_request_limits(RequestLimits {
        max_pending: 1,
        max_new: 10,
        window_secs: 600,
    })
    .await;
    broker.add_agent("bot").await;
    let (created, _token) = broker
        .create_request("bot", TestBroker::pi_request("restart", Window::M15))
        .await;
    notification_recorded(&broker).await;
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "not-a-real-secret");
    let bot = AgentName::try_from("bot".to_owned()).unwrap();
    // Two refusals, the second counted and not yet written.
    for _ in 0..2 {
        let refused = TestBroker::api_request("github", "list issues", Window::M15);
        let got = broker.state().requests.create(&bot, refused).await;
        assert!(matches!(got, Err(RequestError::Limited(_))));
    }
    let holder = std::fs::File::open(broker.audit_path()).unwrap();
    holder.lock().unwrap();
    // Those refusals are due, and the request past its time.
    broker.clock.advance(601);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let sweeper = tokio::spawn(warden_broker::requests::sweep_loop(
        broker.state().requests.clone(),
        Duration::from_millis(10),
        stopped,
    ));
    let requests = broker.state().requests.clone();
    tokio::time::timeout(Duration::from_secs(20), async {
        while requests
            .history(10)
            .await
            .unwrap()
            .iter()
            .all(|entry| entry.status != "expired")
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the request expired");
    drop(holder);
    stop.send(true).unwrap();
    sweeper.await.unwrap();
    assert_eq!(status(&broker, &created).await, RequestStatus::Expired);
}
