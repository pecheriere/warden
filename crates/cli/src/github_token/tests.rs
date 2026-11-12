use std::cell::Cell;
use std::fs;
use std::future::ready;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use warden_broker_proto::Id;
use warden_broker_proto::github_token::GithubTokenResponse;
use warden_broker_proto::release::RepoName;

use super::cache::{Cache, Entry, well_formed};
use super::{Caller, Identity, MIN_REMAINING_SECS, explain, goal_for, repository_for, serve_from};
use crate::client::CallError;
use crate::{EXIT_ERROR, EXIT_NO_GRANT, Exit};

const NOW: i64 = 1_800_000_000;
const CACHED: &str = "ghs_cached";
const FRESH: &str = "ghs_fresh";
const REPO: &str = "example-owner/example-repo";
const OTHER_REPO: &str = "example-owner/homebrew-tap";

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

fn repo(name: &str) -> RepoName {
    RepoName::try_from(name.to_owned()).unwrap()
}

fn response(token: &str, expires_at: i64, repository: &str, id: u64) -> GithubTokenResponse {
    GithubTokenResponse {
        token: token.to_owned(),
        expires_at,
        grant_id: Id::random(),
        repository: repo(repository),
        repository_id: id,
    }
}

fn entry(token: &str, expires_at: i64, repository: &str, id: u64) -> Entry {
    Entry::new(response(token, expires_at, repository, id))
}

/// A cache of `entries`, for [`identity`], written to `path`.
fn write_entries(path: &Path, entries: Vec<Entry>) {
    let mut cache = Cache::empty(identity());
    for entry in entries {
        cache.put(entry);
    }
    cache.write(path).unwrap();
}

fn write_one(path: &Path, token: &str, expires_at: i64) {
    write_entries(path, vec![entry(token, expires_at, REPO, 1001)]);
}

/// Serve `repository` from `path` at [`NOW`] as [`identity`], minting [`FRESH`] when
/// needed; returns the token and whether a mint happened.
async fn serve_for(path: &Path, repository: &str) -> (String, bool) {
    serve_as(path, &identity(), repository, repository, 1001).await
}

async fn serve(path: &Path) -> (String, bool) {
    serve_for(path, REPO).await
}

/// As [`serve_for`], for `identity`, with a broker that answers with a token for
/// `answered` (id `id`).
async fn serve_as(
    path: &Path,
    identity: &Identity,
    repository: &str,
    answered: &str,
    id: u64,
) -> (String, bool) {
    let minted = Cell::new(false);
    let token = serve_from(path, NOW, identity, &repo(repository), || {
        minted.set(true);
        ready(Ok(response(FRESH, NOW + 3600, answered, id)))
    })
    .await
    .unwrap();
    (token.to_string(), minted.get())
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn loaded(path: &Path) -> Cache {
    Cache::load(path).expect("the cache is served")
}

fn stored_token(path: &Path, repository: &str) -> Option<String> {
    loaded(path)
        .entries
        .iter()
        .find(|e| e.repository.matches(&repo(repository)))
        .map(|e| e.token.to_string())
}

#[tokio::test]
async fn cache_reused_until_five_minutes_left() {
    let d = dir();
    write_one(&d.cache, CACHED, NOW + MIN_REMAINING_SECS);
    assert_eq!(serve(&d.cache).await, (CACHED.to_owned(), false));

    write_one(&d.cache, CACHED, NOW + MIN_REMAINING_SECS - 1);
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
    assert_eq!(
        stored_token(&d.cache, REPO).as_deref(),
        Some(FRESH),
        "the fresh token replaced it"
    );
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), false));
}

#[tokio::test]
async fn cache_serves_only_its_repository() {
    let d = dir();
    write_one(&d.cache, CACHED, NOW + 3600);
    assert_eq!(serve_for(&d.cache, REPO).await, (CACHED.to_owned(), false));
    let (token, minted) = serve_as(&d.cache, &identity(), OTHER_REPO, OTHER_REPO, 1002).await;
    assert_eq!((token.as_str(), minted), (FRESH, true));
}

#[tokio::test]
async fn cache_lookup_ignores_case() {
    let d = dir();
    write_one(&d.cache, CACHED, NOW + 3600);
    assert_eq!(
        serve_for(&d.cache, "Example-Owner/EXAMPLE-repo").await,
        (CACHED.to_owned(), false)
    );
    // A mint for another spelling of the name replaces the entry, not adds one.
    write_one(&d.cache, CACHED, NOW + 100);
    assert_eq!(
        serve_for(&d.cache, "EXAMPLE-OWNER/example-repo").await,
        (FRESH.to_owned(), true)
    );
    assert_eq!(loaded(&d.cache).entries.len(), 1);
}

#[tokio::test]
async fn cache_keeps_entries_of_other_repositories_on_put() {
    let d = dir();
    write_entries(
        &d.cache,
        vec![
            entry(CACHED, NOW + 100, REPO, 1001),
            entry("ghs_other", NOW + 3600, OTHER_REPO, 1002),
        ],
    );
    // The first repository's entry is about to end: minting replaces it alone.
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
    assert_eq!(stored_token(&d.cache, REPO).as_deref(), Some(FRESH));
    assert_eq!(
        stored_token(&d.cache, OTHER_REPO).as_deref(),
        Some("ghs_other")
    );
}

#[test]
fn put_replaces_an_entry_with_the_same_id_or_name() {
    let mut cache = Cache::empty(identity());
    cache.put(entry("ghs_a", NOW + 3600, REPO, 1001));
    cache.put(entry("ghs_b", NOW + 3600, "Example-Owner/Renamed", 1001));
    assert_eq!(cache.entries.len(), 1, "same id");
    cache.put(entry("ghs_c", NOW + 3600, "EXAMPLE-OWNER/RENAMED", 2002));
    assert_eq!(cache.entries.len(), 1, "same name");
    assert_eq!(cache.entries[0].token.as_str(), "ghs_c");
}

#[test]
fn put_drops_the_entry_ending_soonest_past_the_limits() {
    let mut cache = Cache::empty(identity());
    for i in 0..32_u64 {
        let offset = i64::try_from(i).unwrap();
        cache.put(entry("ghs_x", NOW + 1000 + offset, &format!("o/r{i}"), i));
    }
    assert_eq!(cache.entries.len(), 32);
    cache.put(entry("ghs_y", NOW + 5000, "o/new", 99));
    assert_eq!(cache.entries.len(), 32);
    assert!(
        cache
            .entries
            .iter()
            .all(|e| !e.repository.matches(&repo("o/r0"))),
        "the soonest went"
    );
    // Large tokens are bounded by the file's size, not only by their number.
    let mut big = Cache::empty(identity());
    for i in 0..32_u64 {
        big.put(entry(&"a".repeat(1024), NOW + 3600, &format!("o/r{i}"), i));
    }
    let d = dir();
    big.write(&d.cache).unwrap();
    assert!(
        Cache::load(&d.cache).is_some(),
        "what was written is read back"
    );
}

#[test]
fn discard_drops_only_that_grants_entries() {
    let mut cache = Cache::empty(identity());
    let first = entry("ghs_a", NOW + 3600, REPO, 1001);
    let grant = first.grant_id.clone();
    cache.put(first);
    cache.put(entry("ghs_b", NOW + 3600, OTHER_REPO, 1002));
    assert!(cache.discard(&grant));
    assert_eq!(cache.entries.len(), 1);
    assert_eq!(cache.entries[0].token.as_str(), "ghs_b");
    assert!(!cache.discard(&grant));
}

#[tokio::test]
async fn cache_discards_version_one_file() {
    let d = dir();
    let v1 = format!(
        r#"{{"token":"ghs_old","expires_at":{},"grant_id":"{}","agent":"build-agent","server":"https://warden.example.ts.net/"}}"#,
        NOW + 3600,
        Id::random()
    );
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&d.cache)
        .unwrap();
    fs::write(&d.cache, v1).unwrap();
    assert!(Cache::load(&d.cache).is_none());
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
    assert_eq!(stored_token(&d.cache, REPO).as_deref(), Some(FRESH));
}

#[tokio::test]
async fn cache_refuses_wrong_mode_or_garbage() {
    for loose in [0o640, 0o644, 0o604, 0o400, 0o700, 0o4600] {
        let d = dir();
        write_one(&d.cache, CACHED, NOW + 3600);
        fs::set_permissions(&d.cache, fs::Permissions::from_mode(loose)).unwrap();
        assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true), "{loose:o}");
        assert_eq!(mode(&d.cache), 0o600, "{loose:o}");
        assert_eq!(stored_token(&d.cache, REPO).as_deref(), Some(FRESH));
    }
    let entry_json = |token: &str, extra: &str| {
        format!(
            r#"{{"repository":"{REPO}","repository_id":1001,"grant_id":"{}","token":"{token}","expires_at":{}{extra}}}"#,
            Id::random(),
            NOW + 3600
        )
    };
    let file = |entries: &str, extra: &str, version: u8| {
        format!(
            r#"{{"version":{version},"agent":"build-agent","server":"https://warden.example.ts.net/","entries":[{entries}]{extra}}}"#
        )
    };
    let bad_token = file(&entry_json(r"ghs_a\nb", ""), "", 2);
    let unknown_entry_field = file(&entry_json("ghs_a", r#","x":1"#), "", 2);
    let unknown_field = file(&entry_json("ghs_a", ""), r#","x":1"#, 2);
    let wrong_version = file(&entry_json("ghs_a", ""), "", 3);
    let too_many = file(&vec![entry_json("ghs_a", ""); 33].join(","), "", 2);
    let huge = format!(r#"{{"token":"{}"}}"#, "a".repeat(20_000));
    for garbage in [
        "",
        "not json",
        "{}",
        &bad_token,
        &unknown_entry_field,
        &unknown_field,
        &wrong_version,
        &too_many,
        &huge,
    ] {
        let d = dir();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&d.cache)
            .unwrap();
        fs::write(&d.cache, garbage).unwrap();
        assert!(Cache::load(&d.cache).is_none(), "{garbage:.60}");
        assert_eq!(
            serve(&d.cache).await,
            (FRESH.to_owned(), true),
            "{garbage:.40}"
        );
        assert_eq!(stored_token(&d.cache, REPO).as_deref(), Some(FRESH));
    }
    // The shape is exactly one the tests above could be mistaken about.
    let d = dir();
    fs::write(&d.cache, file(&entry_json("ghs_a", ""), "", 2)).unwrap();
    fs::set_permissions(&d.cache, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Cache::load(&d.cache).is_some());
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
        write_one(&d.cache, CACHED, NOW + 3600);
        assert_eq!(serve(&d.cache).await, (CACHED.to_owned(), false));
        assert_eq!(
            serve_as(&d.cache, &other, REPO, REPO, 1001).await,
            (FRESH.to_owned(), true),
            "{other:?}"
        );
        assert_eq!(stored_token(&d.cache, REPO).as_deref(), Some(FRESH));
        // Now the cache is the other identity's, and this one's is not served.
        assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
    }
}

#[tokio::test]
async fn cache_that_is_a_symlink_or_a_directory_is_never_followed_or_served() {
    let d = dir();
    let elsewhere = d.cache.with_file_name("elsewhere.json");
    write_one(&elsewhere, CACHED, NOW + 3600);
    std::os::unix::fs::symlink(&elsewhere, &d.cache).unwrap();
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
    assert!(fs::symlink_metadata(&d.cache).unwrap().is_file());
    assert_eq!(
        stored_token(&elsewhere, REPO).as_deref(),
        Some(CACHED),
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
    let refused = serve_from(&d.cache, NOW, &identity(), &repo(REPO), || {
        ready(Ok(response(
            "ghs_a\npassword=other",
            NOW + 3600,
            REPO,
            1001,
        )))
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
async fn mint_answer_for_other_repository_is_refused() {
    let d = dir();
    let refused = serve_from(&d.cache, NOW, &identity(), &repo(REPO), || {
        ready(Ok(response(FRESH, NOW + 3600, OTHER_REPO, 1002)))
    })
    .await
    .unwrap_err();
    assert_eq!(
        refused.to_string(),
        "the broker sent a token for another repository"
    );
    assert!(!d.cache.exists(), "nothing was cached");
    // The same repository in another case is the one asked for.
    assert_eq!(
        serve_as(
            &d.cache,
            &identity(),
            "EXAMPLE-owner/example-REPO",
            REPO,
            1001
        )
        .await,
        (FRESH.to_owned(), true)
    );
}

#[tokio::test]
async fn a_failed_mint_keeps_its_call_error() {
    let d = dir();
    let e = serve_from(&d.cache, NOW, &identity(), &repo(REPO), || {
        ready(Err::<GithubTokenResponse, _>(
            CallError::Refused("broker refused (403)".to_owned()).into(),
        ))
    })
    .await
    .unwrap_err();
    assert!(e.downcast_ref::<CallError>().is_some());
    assert!(!d.cache.exists());
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
