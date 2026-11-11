//! Tests of `warden request`: the scope check, the wait for a decision and
//! the withdrawal on Ctrl-C.

use std::time::{Duration, Instant};

use warden_broker_proto::{ApiGrant, RequestStatus};

use super::{CallError, check_scope_not_wider, next_retry_delay, wait_for_decision};

#[tokio::test(flavor = "multi_thread")]
async fn interrupt_after_approval_revokes_the_grant() {
    use warden_broker::testkit::{CapturingNotifier, TestBroker};
    use warden_broker_proto::Window;
    use zeroize::Zeroizing;

    use super::withdraw_after_interrupt;
    use crate::EXIT_INTERRUPTED;
    use crate::client::Client;

    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let urls = broker.spawn_behind_serve().await;
    let client = Client::new(&urls.api, crate::client::Auth::Bearer(Zeroizing::new(key))).unwrap();
    let req = TestBroker::pi_request("restart the backup job", Window::M30);
    let created = client.create(&req).await.unwrap();
    let token = CapturingNotifier::token(&broker.capture.next().await);
    let approved = broker.approve(&token, Window::M30).await;
    assert!(approved.status.is_success(), "{}", approved.body);

    // The owner approved before the cancel: the grant is revoked, not left.
    let exit = withdraw_after_interrupt(&client, &created.id).await;
    assert_eq!(exit.code, EXIT_INTERRUPTED);
    assert!(
        exit.message
            .contains("approved before it could be cancelled")
            && exit.message.contains("revoked"),
        "{}",
        exit.message
    );
    assert_eq!(
        client.status(&created.id, 0).await,
        Ok(RequestStatus::Revoked)
    );
    assert_eq!(
        client.grants().await.unwrap(),
        [] as [warden_broker_proto::GrantView; 0]
    );

    // A request decided otherwise is just reported.
    let again = client.create(&req).await.unwrap();
    assert_eq!(client.cancel(&again.id).await, Ok(()));
    let exit = withdraw_after_interrupt(&client, &again.id).await;
    assert!(
        exit.message.contains("already cancelled"),
        "{}",
        exit.message
    );
}

#[test]
fn retry_delay_doubles_up_to_15s() {
    let delays: Vec<u64> =
        std::iter::successors(Some(Duration::from_secs(1)), |d| Some(next_retry_delay(*d)))
            .take(7)
            .map(|d| d.as_secs())
            .collect();
    assert_eq!(delays, [1, 2, 4, 8, 15, 15, 15]);
}

/// A poll that answers with `script`, in order, then stays pending.
fn scripted(
    script: Vec<Result<RequestStatus, CallError>>,
) -> (
    impl FnMut() -> std::future::Ready<Result<RequestStatus, CallError>>,
    std::rc::Rc<std::cell::Cell<usize>>,
) {
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let seen = calls.clone();
    let mut script = script.into_iter();
    let poll = move || {
        seen.set(seen.get() + 1);
        std::future::ready(script.next().unwrap_or(Ok(RequestStatus::Pending)))
    };
    (poll, calls)
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[tokio::test]
async fn unavailable_broker_is_retried_until_a_decision() {
    let down = || Err(CallError::Unavailable("connection refused".to_owned()));
    let (poll, calls) = scripted(vec![
        Ok(RequestStatus::Pending),
        down(),
        down(),
        Err(CallError::Unavailable("broker refused (500)".to_owned())),
        Ok(RequestStatus::Pending),
        Ok(RequestStatus::Denied),
    ]);
    let got = wait_for_decision(poll, soon(), Duration::from_millis(1)).await;
    assert_eq!(got, Ok(RequestStatus::Denied));
    assert_eq!(calls.get(), 6);
}

#[tokio::test]
async fn refusal_ends_the_wait_at_once() {
    let (poll, calls) = scripted(vec![
        Ok(RequestStatus::Pending),
        Err(CallError::Refused(
            "broker refused (404 Not Found)".to_owned(),
        )),
        Ok(RequestStatus::Denied),
    ]);
    let got = wait_for_decision(poll, soon(), Duration::from_millis(1)).await;
    assert_eq!(got, Err("broker refused (404 Not Found)".to_owned()));
    assert_eq!(calls.get(), 2);
}

#[tokio::test]
async fn deadline_ends_retries() {
    let (poll, _) = scripted(Vec::new());
    let deadline = Instant::now() + Duration::from_millis(30);
    let got = wait_for_decision(poll, deadline, Duration::from_millis(1)).await;
    assert_eq!(got, Err("no decision within 11 minutes".to_owned()));

    let always_down = || std::future::ready(Err(CallError::Unavailable("down".to_owned())));
    let started = Instant::now();
    let got = wait_for_decision(
        always_down,
        started + Duration::from_millis(50),
        Duration::from_secs(15),
    )
    .await;
    assert!(got.is_err());
    // The pause before a retry never runs past the deadline.
    assert!(started.elapsed() < Duration::from_secs(2));
}

fn api_grant(methods: &[&str], prefix: &str) -> ApiGrant {
    ApiGrant {
        secret: "github".parse().unwrap(),
        origin: "https://api.example.com".to_owned(),
        methods: methods.iter().map(|m| (*m).to_owned()).collect(),
        path_prefix: prefix.to_owned(),
        header: "authorization".to_owned(),
        digest: String::new(),
    }
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn narrow_grants_pass_the_scope_check() {
    let get = api_grant(&["GET", "HEAD"], "/v1/");
    assert!(check_scope_not_wider(&get, None, None).is_ok());
    let post = api_grant(&["POST"], "/v1/repos");
    let asked = strings(&["POST", "GET"]);
    assert!(check_scope_not_wider(&post, Some(&asked), Some("/v1/")).is_ok());
}

#[test]
fn older_broker_grant_wider_than_requested_is_refused() {
    // Default request, broker ignored the missing scope and granted write.
    let full = api_grant(&["GET", "POST", "DELETE"], "/");
    assert_eq!(
        check_scope_not_wider(&full, None, None).unwrap_err(),
        "methods POST, DELETE"
    );
    // An empty method list is not read-only either.
    assert!(check_scope_not_wider(&api_grant(&[], "/"), None, None).is_err());
    // Requested GET only, got more.
    let asked = strings(&["GET"]);
    assert_eq!(
        check_scope_not_wider(&full, Some(&asked), None).unwrap_err(),
        "methods POST, DELETE"
    );
    // Requested a path, got a wider one.
    let wide = api_grant(&["GET"], "/");
    assert_eq!(
        check_scope_not_wider(&wide, None, Some("/v1/")).unwrap_err(),
        "path / is not under /v1/"
    );
    assert!(check_scope_not_wider(&api_grant(&["GET"], "/v1x"), None, Some("/v1")).is_err());
}

#[test]
fn a_request_for_git_or_gh_asks_for_no_more_than_the_broker_allows() {
    use warden_broker_proto::Window;

    use super::tool_window;

    assert_eq!(tool_window(None), Window::D30);
    assert_eq!(tool_window(Some(Window::D30)), Window::D30);
    assert_eq!(tool_window(Some(Window::D7)), Window::D7);
    assert_eq!(tool_window(Some(Window::D1)), Window::D1);
    // A broker that allowed longer still gets at most 30 days.
    assert_eq!(tool_window(Some(Window::D90)), Window::D30);
}

#[test]
fn only_a_request_made_here_is_withdrawn() {
    use warden_broker_proto::{CreatedResponse, Id};

    use super::made_here;
    use crate::request_context::Answered;

    let answer = |created| CreatedResponse {
        id: Id::random(),
        fingerprint: "ab02-cd02-ef02".to_owned().try_into().unwrap(),
        created,
    };
    for answered in [Answered::Same, Answered::WithoutContext, Answered::Other] {
        // The broker says which: its word stands, whatever the fingerprint.
        assert!(made_here(&answer(Some(true)), answered), "{answered:?}");
        assert!(!made_here(&answer(Some(false)), answered), "{answered:?}");
    }
    // A broker older than the flag: the fingerprint decides, as before it.
    assert!(made_here(&answer(None), Answered::Same));
    assert!(made_here(&answer(None), Answered::WithoutContext));
    assert!(!made_here(&answer(None), Answered::Other));
}

/// What `warden request release ...` parses to, or the usage error.
fn parse_release(args: &[&str]) -> Result<crate::cli::RequestKind, clap::Error> {
    use clap::Parser as _;

    let mut line = vec!["warden", "request", "release"];
    line.extend_from_slice(args);
    match crate::cli::Cli::try_parse_from(line)?.command {
        crate::cli::Cmd::Request { kind } => Ok(kind),
        other => panic!("not a request: {other:?}"),
    }
}

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn request_release_validates_arguments() {
    let good = ["example-owner/example-repo", "v1.2.3"];
    let with = |repo: &'static str, tag: &'static str, commit: &'static str| {
        parse_release(&[repo, tag, "--commit", commit, "--goal", "Release 1.2.3"])
    };
    with(good[0], good[1], COMMIT).unwrap();
    for (repo, tag, commit, what) in [
        ("example-repo", "v1.2.3", COMMIT, "no owner"),
        ("example-owner/..", "v1.2.3", COMMIT, "a dot name"),
        ("bad_owner/example-repo", "v1.2.3", COMMIT, "a bad owner"),
        ("example-owner/example-repo", "1.2.3", COMMIT, "no v"),
        ("example-owner/example-repo", "v1.2", COMMIT, "two parts"),
        (
            "example-owner/example-repo",
            "v1.2.3",
            "0123abc",
            "short commit",
        ),
        (
            "example-owner/example-repo",
            "v1.2.3",
            "0123456789ABCDEF0123456789abcdef01234567",
            "upper case commit",
        ),
        (
            "example-owner/example-repo",
            "v1.2.3",
            "main",
            "a branch name",
        ),
    ] {
        let refused = with(repo, tag, commit).expect_err(what);
        assert_eq!(
            refused.kind(),
            clap::error::ErrorKind::ValueValidation,
            "{what}"
        );
    }
    // The commit and the goal are not optional, and the window is not chosen.
    parse_release(&[good[0], good[1], "--goal", "Release 1.2.3"]).expect_err("no commit");
    parse_release(&[good[0], good[1], "--commit", COMMIT]).expect_err("no goal");
    parse_release(&[
        good[0],
        good[1],
        "--commit",
        COMMIT,
        "--goal",
        "Release 1.2.3",
        "--for",
        "4h",
    ])
    .expect_err("a release lasts a day");
}

#[test]
fn request_release_sends_access() {
    use warden_broker_proto::release::{CommitId, ReleaseTag, RepoName};
    use warden_broker_proto::{Access, SessionLabel, Window};

    let crate::cli::RequestKind::Release {
        repository,
        tag,
        commit,
        goal,
        context,
    } = parse_release(&[
        "example-owner/example-repo",
        "v1.2.3",
        "--commit",
        COMMIT,
        "--goal",
        "Release 1.2.3",
        "--session",
        "release run",
    ])
    .unwrap()
    else {
        panic!("not a release request");
    };
    let request = crate::release::release_request(
        repository,
        tag,
        commit,
        goal,
        context.session.clone(),
        None,
    );
    assert_eq!(
        request.access,
        Access::Release {
            repository: RepoName::try_from("example-owner/example-repo".to_owned()).unwrap(),
            tag: ReleaseTag::try_from("v1.2.3".to_owned()).unwrap(),
            commit: CommitId::try_from(COMMIT.to_owned()).unwrap(),
        }
    );
    assert_eq!(request.window, Window::D1);
    assert_eq!(request.goal.as_str(), "Release 1.2.3");
    assert_eq!(
        request.session.as_ref().map(SessionLabel::as_str),
        Some("release run")
    );
    let json = serde_json::to_value(&request.access).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "kind": "release",
            "repository": "example-owner/example-repo",
            "tag": "v1.2.3",
            "commit": COMMIT,
        })
    );
}
