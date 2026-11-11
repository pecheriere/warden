//! The release client's REST calls, against the fake GitHub.

use serde_json::{Value, json};
use warden_broker_proto::release::{CommitId, ReleaseTag, RepoName};

use super::{NOW, app, github, repo};
use crate::github_app::GithubApi;
use crate::github_release::{GithubError, ReleaseClient};
use crate::testkit::upstream::{HttpsUpstream, Scripted};

pub(super) const TAGGED_AT: i64 = 1_794_139_200;

pub(super) fn sha(c: char) -> String {
    c.to_string().repeat(40)
}

pub(super) fn id(c: char) -> CommitId {
    sha(c).try_into().unwrap()
}

pub(super) fn tag(name: &str) -> ReleaseTag {
    name.to_owned().try_into().unwrap()
}

/// A fake with the release App installed, a client for it and its repository.
pub(super) async fn fixture() -> (HttpsUpstream, GithubApi, RepoName) {
    let (upstream, api) = github().await;
    (upstream, api, repo())
}

pub(super) async fn connect(api: &GithubApi) -> ReleaseClient<'_> {
    ReleaseClient::connect(api, &app(), &repo(), NOW)
        .await
        .unwrap()
}

/// The tag object the broker's own tags are: UTC, with a signature block at the
/// end of the message.
pub(super) fn signed_tag_object(commit: &str, name: &str, zone: &str) -> Vec<u8> {
    format!(
        "object {commit}\ntype commit\ntag {name}\ntagger Example Tagger <tagger@example.com> \
         {TAGGED_AT} {zone}\n\nexample-repo 1.2.3\n-----BEGIN SSH SIGNATURE-----\n\
         U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg\nZXhhbXBsZXNpZ25hdHVyZQ==\n\
         -----END SSH SIGNATURE-----\n"
    )
    .into_bytes()
}

/// Commits `1` <- `2` <- `3` on `main`, `4` on top of `3` but not on `main`, and
/// `5` on a line of its own.
pub(super) fn history(upstream: &HttpsUpstream) {
    let fake = upstream.github_release();
    let repo = repo();
    let date = "2026-11-07T10:00:00Z";
    fake.add_commit(&repo, &sha('1'), "First", date, &[]);
    fake.add_commit(&repo, &sha('2'), "Second", date, &[&sha('1')]);
    fake.add_commit(&repo, &sha('3'), "Third", date, &[&sha('2')]);
    fake.add_commit(&repo, &sha('4'), "Fourth", date, &[&sha('3')]);
    fake.add_commit(&repo, &sha('5'), "Fifth", date, &[]);
    fake.set_default_branch(&repo, "main", &sha('3'));
}

pub(super) fn requests(upstream: &HttpsUpstream) -> Vec<String> {
    upstream
        .github_release()
        .record()
        .into_iter()
        .skip(2)
        .map(|call| format!("{} {}", call.method, call.path_and_query))
        .collect()
}

#[tokio::test]
async fn commit_gives_the_title_and_date() {
    let (upstream, api, repo) = fixture().await;
    upstream.github_release().add_commit(
        &repo,
        &sha('1'),
        "Add the thing\n\nA longer explanation.",
        "2026-11-07T10:00:00+02:00",
        &[],
    );
    let client = connect(&api).await;
    let info = client.commit(&id('1')).await.unwrap();
    assert_eq!(info.title, "Add the thing");
    assert_eq!(info.date, "2026-11-07T08:00:00Z");
    assert_eq!(
        requests(&upstream),
        [format!(
            "GET /repos/example-owner/example-repo/git/commits/{}",
            sha('1')
        )]
    );
}

#[tokio::test]
async fn commit_title_is_one_short_plain_line() {
    let (upstream, api, repo) = fixture().await;
    let long = "a".repeat(300);
    upstream
        .github_release()
        .add_commit(&repo, &sha('1'), &long, "2026-11-07T10:00:00Z", &[]);
    upstream.github_release().add_commit(
        &repo,
        &sha('2'),
        "\u{202e}evil\u{7}\u{200b} title\r",
        "2026-11-07T10:00:00Z",
        &[],
    );
    let client = connect(&api).await;
    assert_eq!(
        client.commit(&id('1')).await.unwrap().title,
        "a".repeat(200)
    );
    assert_eq!(client.commit(&id('2')).await.unwrap().title, "evil title");
}

#[tokio::test]
async fn commit_unknown_to_github_is_not_found() {
    let (_upstream, api, _repo) = fixture().await;
    let client = connect(&api).await;
    assert_eq!(
        client.commit(&id('1')).await.unwrap_err(),
        GithubError::NotFound
    );
}

#[tokio::test]
async fn commit_answer_for_another_commit_is_refused() {
    let (upstream, api, _repo) = fixture().await;
    let client = connect(&api).await;
    upstream
        .github_release()
        .answer_everything_with(Scripted::with_body(
            200,
            json!({"sha": sha('2'), "message": "m", "committer": {"date": "2026-11-07T10:00:00Z"}})
                .to_string(),
        ));
    assert_eq!(
        client.commit(&id('1')).await.unwrap_err(),
        GithubError::Unreadable
    );
}

#[tokio::test]
async fn on_default_branch_true_for_the_head_and_its_ancestors() {
    let (upstream, api, _repo) = fixture().await;
    history(&upstream);
    let client = connect(&api).await;
    assert!(client.on_default_branch(&id('3')).await.unwrap());
    assert!(client.on_default_branch(&id('1')).await.unwrap());
    assert_eq!(
        requests(&upstream)[..2],
        [
            "GET /repos/example-owner/example-repo".to_owned(),
            format!(
                "GET /repos/example-owner/example-repo/compare/{}...main?per_page=1&page=2",
                sha('3')
            ),
        ]
    );
}

#[tokio::test]
async fn on_default_branch_false_when_behind_or_diverged() {
    let (upstream, api, _repo) = fixture().await;
    history(&upstream);
    let client = connect(&api).await;
    assert!(!client.on_default_branch(&id('4')).await.unwrap());
    assert!(!client.on_default_branch(&id('5')).await.unwrap());
}

#[tokio::test]
async fn a_branch_name_cannot_add_path_segments_or_dots() {
    let (upstream, api, repo) = fixture().await;
    history(&upstream);
    upstream
        .github_release()
        .set_default_branch(&repo, "release/1.x", &sha('3'));
    let client = connect(&api).await;
    assert!(client.on_default_branch(&id('3')).await.unwrap());
    assert!(requests(&upstream)[1].ends_with(&format!(
        "/compare/{}...release%2F1.x?per_page=1&page=2",
        sha('3')
    )));
    for hostile in ["../../x", "a..b", "", "a b", "x\ny", "/x", "x@{y}"] {
        upstream
            .github_release()
            .set_default_branch(&repo, hostile, &sha('3'));
        assert_eq!(
            client.on_default_branch(&id('3')).await.unwrap_err(),
            GithubError::Unreadable,
            "{hostile:?}"
        );
    }
    // Only the repository was read for them: no compare went out.
    assert_eq!(requests(&upstream).len(), 2 + 7);
}

#[tokio::test]
async fn on_default_branch_refuses_a_status_it_does_not_know() {
    let (upstream, api, _repo) = fixture().await;
    history(&upstream);
    let client = connect(&api).await;
    upstream
        .github_release()
        .answer_everything_with(Scripted::with_body(
            200,
            json!({"status": "teleported", "default_branch": "main"}).to_string(),
        ));
    assert_eq!(
        client.on_default_branch(&id('3')).await.unwrap_err(),
        GithubError::Unreadable
    );
}

const CHANGELOG: &str = "# Changelog\n\n## [Unreleased]\n\n- Next.\n\n## [1.2.3] - 2026-11-08\n\n\
                         ### Added\n\n- The thing.\n- Another.\n\n## [1.2.2] - 2026-10-01\n\n- Old.\n";

#[tokio::test]
async fn changelog_section_is_what_is_under_the_version_heading() {
    let (upstream, api, repo) = fixture().await;
    upstream
        .github_release()
        .add_file(&repo, &sha('1'), "CHANGELOG.md", CHANGELOG.as_bytes());
    let client = connect(&api).await;
    let section = client.changelog_section(&id('1'), "1.2.3").await.unwrap();
    assert_eq!(
        section.as_deref(),
        Some("### Added\n\n- The thing.\n- Another.")
    );
    let calls = upstream.github_release().record();
    assert_eq!(calls[2].method, "GET");
    assert_eq!(
        calls[2].path_and_query,
        format!(
            "/repos/example-owner/example-repo/contents/CHANGELOG.md?ref={}",
            sha('1')
        )
    );
    assert_eq!(calls[2].headers["accept"], "application/vnd.github.raw");
}

#[tokio::test]
async fn changelog_section_none_for_missing_version() {
    let (upstream, api, repo) = fixture().await;
    upstream
        .github_release()
        .add_file(&repo, &sha('1'), "CHANGELOG.md", CHANGELOG.as_bytes());
    let client = connect(&api).await;
    assert_eq!(
        client.changelog_section(&id('1'), "9.9.9").await.unwrap(),
        None
    );
    // A prefix of a version is not the version.
    assert_eq!(
        client.changelog_section(&id('1'), "1.2").await.unwrap(),
        None
    );
    // No file at that commit.
    assert_eq!(
        client.changelog_section(&id('2'), "1.2.3").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn changelog_section_none_for_an_empty_section_or_a_file_that_is_not_utf8() {
    let (upstream, api, repo) = fixture().await;
    let fake = upstream.github_release();
    fake.add_file(
        &repo,
        &sha('1'),
        "CHANGELOG.md",
        b"## [1.2.3]\n\n## [1.2.2]\n- Old.\n",
    );
    fake.add_file(&repo, &sha('2'), "CHANGELOG.md", b"## [1.2.3]\n\xff\xfe\n");
    let client = connect(&api).await;
    assert_eq!(
        client.changelog_section(&id('1'), "1.2.3").await.unwrap(),
        None
    );
    assert_eq!(
        client.changelog_section(&id('2'), "1.2.3").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn changelog_section_cut_at_16k() {
    let (upstream, api, repo) = fixture().await;
    // One ASCII byte, then two-byte characters: byte 16384 falls inside one, so
    // the cut must move back to a character boundary (16383).
    let body = format!("a{}", "é".repeat(10_000));
    let file = format!("## [1.2.3]\n{body}\n## [1.2.2]\n- Old.\n");
    upstream
        .github_release()
        .add_file(&repo, &sha('1'), "CHANGELOG.md", file.as_bytes());
    let short = format!("## [1.2.3]\n{}\n", "x".repeat(16 * 1024));
    upstream
        .github_release()
        .add_file(&repo, &sha('2'), "CHANGELOG.md", short.as_bytes());
    let client = connect(&api).await;

    let cut = client
        .changelog_section(&id('1'), "1.2.3")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cut, format!("a{}\n…(cut)", "é".repeat(8191)));
    let body = cut.strip_suffix("\n…(cut)").expect("the cut marker");
    assert!(body.len() <= 16 * 1024);

    // Exactly 16 KiB is kept whole.
    let kept = client
        .changelog_section(&id('2'), "1.2.3")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept, "x".repeat(16 * 1024));
}

#[tokio::test]
async fn changelog_of_more_than_a_mebibyte_is_unreadable() {
    let (upstream, api, repo) = fixture().await;
    let big = format!("## [1.2.3]\n{}\n", "x".repeat(1024 * 1024));
    upstream
        .github_release()
        .add_file(&repo, &sha('1'), "CHANGELOG.md", big.as_bytes());
    let client = connect(&api).await;
    assert_eq!(
        client
            .changelog_section(&id('1'), "1.2.3")
            .await
            .unwrap_err(),
        GithubError::Unreadable
    );
}

#[tokio::test]
async fn release_list_may_be_large_but_other_answers_may_not() {
    let (upstream, api, _repo) = fixture().await;
    let client = connect(&api).await;
    let releases: Vec<Value> = (0..100)
        .map(|n| {
            json!({"id": n, "tag_name": format!("v1.0.{n}"), "draft": false,
                        "assets": [], "body": "x".repeat(2000)})
        })
        .collect();
    let list = Value::Array(releases).to_string();
    assert!(list.len() > 64 * 1024 && list.len() < 1024 * 1024);
    upstream
        .github_release()
        .answer_everything_with(Scripted::with_body(200, list.clone()));
    assert!(
        client
            .release_for_tag(&tag("v1.0.5"))
            .await
            .unwrap()
            .is_some()
    );
    // The same size is too much for a commit.
    upstream
        .github_release()
        .answer_everything_with(Scripted::with_body(200, list));
    assert_eq!(
        client.commit(&id('1')).await.unwrap_err(),
        GithubError::Unreadable
    );
}

#[tokio::test]
async fn every_call_carries_the_release_token_not_the_app_jwt() {
    let (upstream, api, _repo) = fixture().await;
    history(&upstream);
    let client = connect(&api).await;
    client.commit(&id('1')).await.unwrap();
    let calls = upstream.github_release().record();
    let jwt = calls[0].headers["authorization"].to_str().unwrap();
    assert!(jwt.contains("eyJ"));
    let call = &calls[2];
    assert_eq!(
        call.headers["authorization"].to_str().unwrap(),
        format!("Bearer {}", crate::testkit::github_release::TOKEN)
    );
    assert_eq!(call.headers["accept-encoding"], "identity");
}
