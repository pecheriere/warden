use std::cell::Cell;
use std::fs;
use std::future::ready;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use warden_broker_proto::Id;
use warden_broker_proto::github_token::GithubTokenResponse;
use warden_broker_proto::release::RepoName;

use super::{
    Caller, Held, Identity, MIN_REMAINING_SECS, Stored, explain, goal_for, read_cache,
    repository_for, serve_from, well_formed, write_cache,
};
use crate::client::CallError;
use crate::{EXIT_ERROR, EXIT_NO_GRANT, Exit};

const NOW: i64 = 1_800_000_000;
const CACHED: &str = "ghs_cached";
const FRESH: &str = "ghs_fresh";

struct Dir {
    _dir: TempDir,
    cache: PathBuf,
}

fn dir() -> Dir {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("github-token.json");
    Dir { _dir: dir, cache }
}

fn identity() -> Identity {
    Identity {
        agent: "build-agent".to_owned(),
        server: "https://warden.example.ts.net/".to_owned(),
    }
}

fn token(token: &str, expires_at: i64) -> Held {
    let response = GithubTokenResponse {
        token: token.to_owned(),
        expires_at,
        grant_id: Id::random(),
    };
    Held::new(response, identity())
}

/// Serve from `path` at [`NOW`] as [`identity`], minting [`FRESH`] when needed;
/// returns the token and whether a mint happened.
async fn serve(path: &Path) -> (String, bool) {
    serve_as(path, &identity()).await
}

async fn serve_as(path: &Path, identity: &Identity) -> (String, bool) {
    let minted = Cell::new(false);
    let token = serve_from(path, NOW, identity, || {
        minted.set(true);
        ready(Ok(GithubTokenResponse {
            token: FRESH.to_owned(),
            expires_at: NOW + 3600,
            grant_id: Id::random(),
        }))
    })
    .await
    .unwrap();
    (token.to_string(), minted.get())
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn stored_token(path: &Path) -> String {
    let stored: Stored = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    stored.token
}

#[tokio::test]
async fn cache_reused_until_five_minutes_left() {
    let d = dir();
    write_cache(&d.cache, &token(CACHED, NOW + MIN_REMAINING_SECS)).unwrap();
    assert_eq!(serve(&d.cache).await, (CACHED.to_owned(), false));

    write_cache(&d.cache, &token(CACHED, NOW + MIN_REMAINING_SECS - 1)).unwrap();
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
    assert_eq!(stored_token(&d.cache), FRESH, "the fresh token replaced it");
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), false));
}

#[tokio::test]
async fn cache_with_wrong_mode_or_garbage_is_replaced() {
    for loose in [0o640, 0o644, 0o604, 0o400, 0o700, 0o4600] {
        let d = dir();
        write_cache(&d.cache, &token(CACHED, NOW + 3600)).unwrap();
        fs::set_permissions(&d.cache, fs::Permissions::from_mode(loose)).unwrap();
        assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true), "{loose:o}");
        assert_eq!(mode(&d.cache), 0o600, "{loose:o}");
        assert_eq!(stored_token(&d.cache), FRESH, "{loose:o}");
    }
    let bad_token = format!(
        r#"{{"token":"ghs_a\nb","expires_at":{},"grant_id":"{}","agent":"build-agent","server":"https://warden.example.ts.net/"}}"#,
        NOW + 3600,
        Id::random()
    );
    let unknown_field = format!(
        r#"{{"token":"ghs_a","expires_at":{},"grant_id":"{}","agent":"build-agent","server":"https://warden.example.ts.net/","x":1}}"#,
        NOW + 3600,
        Id::random()
    );
    let huge = format!(r#"{{"token":"{}"}}"#, "a".repeat(20_000));
    for garbage in ["", "not json", "{}", &bad_token, &unknown_field, &huge] {
        let d = dir();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&d.cache)
            .unwrap();
        fs::write(&d.cache, garbage).unwrap();
        assert_eq!(
            serve(&d.cache).await,
            (FRESH.to_owned(), true),
            "{garbage:.40}"
        );
        assert_eq!(stored_token(&d.cache), FRESH);
    }
}

#[tokio::test]
async fn cache_for_another_agent_or_broker_is_replaced() {
    let others = [
        Identity {
            agent: "other-agent".to_owned(),
            ..identity()
        },
        Identity {
            server: "https://other.example.ts.net/".to_owned(),
            ..identity()
        },
    ];
    for other in others {
        let d = dir();
        write_cache(&d.cache, &token(CACHED, NOW + 3600)).unwrap();
        assert_eq!(
            serve_as(&d.cache, &identity()).await,
            (CACHED.to_owned(), false)
        );
        assert_eq!(
            serve_as(&d.cache, &other).await,
            (FRESH.to_owned(), true),
            "{other:?}"
        );
        assert_eq!(stored_token(&d.cache), FRESH);
        // Now the cache is the other identity's, and this one's is not served.
        assert_eq!(
            serve_as(&d.cache, &identity()).await,
            (FRESH.to_owned(), true)
        );
    }
}

#[tokio::test]
async fn cache_that_is_a_symlink_or_a_directory_is_never_followed_or_served() {
    let d = dir();
    let elsewhere = d.cache.with_file_name("elsewhere.json");
    write_cache(&elsewhere, &token(CACHED, NOW + 3600)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &d.cache).unwrap();
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
    assert!(fs::symlink_metadata(&d.cache).unwrap().is_file());
    assert_eq!(
        stored_token(&elsewhere),
        CACHED,
        "the target was left alone"
    );

    let d = dir();
    fs::create_dir(&d.cache).unwrap();
    // A directory cannot be renamed over: the token is served, the cache not kept.
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
}

#[tokio::test]
async fn cache_file_created_0600() {
    let d = dir();
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
    assert_eq!(mode(&d.cache), 0o600);
    let leftovers: Vec<_> = fs::read_dir(d.cache.parent().unwrap())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[tokio::test]
async fn a_token_that_is_not_well_formed_is_refused_and_not_cached() {
    let d = dir();
    let refused = serve_from(&d.cache, NOW, &identity(), || {
        ready(Ok(GithubTokenResponse {
            token: "ghs_a\npassword=other".to_owned(),
            expires_at: NOW + 3600,
            grant_id: Id::random(),
        }))
    })
    .await
    .unwrap_err();
    assert!(!refused.to_string().contains("ghs_a"), "{refused}");
    assert!(!d.cache.exists());
    assert!(well_formed("ghs_0123abcXYZ"));
    for bad in ["", "a b", "a\tb", "é", &"a".repeat(1025)] {
        assert!(!well_formed(bad), "{bad:?}");
    }
}

#[tokio::test]
async fn a_failed_mint_keeps_its_call_error() {
    let d = dir();
    let e = serve_from(&d.cache, NOW, &identity(), || {
        ready(Err(CallError::Refused("broker refused (403)".to_owned())))
    })
    .await
    .unwrap_err();
    assert!(e.downcast_ref::<CallError>().is_some());
    assert!(read_cache(&d.cache, NOW, &identity()).is_none());
}

fn exit_of(e: CallError) -> (u8, String) {
    let e = explain(anyhow::Error::from(e));
    let exit = e.downcast_ref::<Exit>().unwrap();
    (exit.code, exit.message.clone())
}

#[test]
fn failures_say_what_to_do_and_never_how_to_get_around_the_owner() {
    let (code, message) = exit_of(CallError::Revoked(
        "broker refused (409 Conflict): grant revoked during the call".to_owned(),
    ));
    assert_eq!(code, EXIT_NO_GRANT);
    assert!(message.contains("ask the owner"), "{message}");
    let (code, message) = exit_of(CallError::Refused(
        "broker refused (409 Conflict): the GitHub App changed; request a new grant".to_owned(),
    ));
    assert_eq!(code, EXIT_NO_GRANT);
    assert!(message.contains("warden request github"), "{message}");
    let (code, message) = exit_of(CallError::Unavailable(
        "broker error (503 Service Unavailable): GitHub could not issue a token; try again later"
            .to_owned(),
    ));
    assert_eq!(code, EXIT_ERROR);
    assert!(message.contains("warden doctor"), "{message}");
    let (code, message) = exit_of(CallError::Refused(format!(
        "broker refused (429 Too Many Requests): {}",
        warden_broker_proto::github_token::HOURLY_LIMIT
    )));
    assert_eq!(code, EXIT_ERROR);
    assert!(message.contains("do not retry"), "{message}");
    let (code, _) = exit_of(CallError::Refused(
        "broker refused (400 Bad Request): GitHub tokens are not configured on this broker"
            .to_owned(),
    ));
    assert_eq!(code, EXIT_ERROR);
}

#[test]
fn goal_names_the_repository() {
    let repo: RepoName = "example-owner/example-repo".parse().unwrap();
    let goal = goal_for(Caller::GhWrapper, &repo, Some(Path::new("/src/home-api"))).unwrap();
    assert_eq!(
        goal.as_str(),
        "GitHub token for example-owner/example-repo, requested automatically by the gh \
         wrapper, in /src/home-api"
    );
    let goal = goal_for(Caller::CredentialHelper, &repo, None).unwrap();
    assert_eq!(
        goal.as_str(),
        "GitHub token for example-owner/example-repo, requested automatically by the git \
         credential helper"
    );
    // A directory that does not fit in a goal is left out.
    let long = format!("/{}", "d".repeat(600));
    let goal = goal_for(Caller::GhWrapper, &repo, Some(Path::new(&long))).unwrap();
    assert!(!goal.as_str().contains("ddd"), "{}", goal.as_str());
    assert!(goal.as_str().contains("example-owner/example-repo"));
    let goal = goal_for(Caller::GhWrapper, &repo, Some(Path::new("/a\nb"))).unwrap();
    assert!(!goal.as_str().contains(", in"), "{}", goal.as_str());
}

#[test]
fn a_bad_repo_flag_in_gh_mode_refuses_with_the_fixed_message() {
    for args in [
        &["-R", "ghe.example.com/o/r"][..],
        &["-R", "o"][..],
        &["-R"][..],
    ] {
        let args: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
        let e = repository_for(None, true, &args).unwrap_err();
        let exit = e.downcast_ref::<Exit>().unwrap();
        assert_eq!(exit.code, EXIT_ERROR);
        assert_eq!(exit.message, crate::github_repo::UNDETERMINED_GH);
    }
}
