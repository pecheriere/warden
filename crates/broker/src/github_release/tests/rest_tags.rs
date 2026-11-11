//! The release client's tag calls, against the fake GitHub.

use std::process::{Command, Stdio};

use http::StatusCode;
use serde_json::{Value, json};

use super::rest::{
    TAGGED_AT, connect, fixture, history, id, requests, sha, signed_tag_object, tag,
};
use crate::github_release::tag_object::{self, GitTagResponse, TaggedObject, Tagger};
use crate::github_release::{CreateTag, GithubError};
use crate::testkit::upstream::Scripted;

#[tokio::test]
async fn tag_target_none_when_absent() {
    let (upstream, api, _repo) = fixture().await;
    let client = connect(&api).await;
    assert_eq!(client.tag_target(&tag("v1.2.3")).await.unwrap(), None);
    assert_eq!(
        requests(&upstream),
        ["GET /repos/example-owner/example-repo/git/ref/tags/v1.2.3"]
    );
}

#[tokio::test]
async fn tag_target_lightweight_has_no_raw() {
    let (upstream, api, repo) = fixture().await;
    history(&upstream);
    upstream
        .github_release()
        .add_lightweight_tag(&repo, "v1.2.3", &sha('2'));
    let client = connect(&api).await;
    let existing = client.tag_target(&tag("v1.2.3")).await.unwrap().unwrap();
    assert_eq!(existing.object_sha, sha('2'));
    assert_eq!(existing.commit, Some(id('2')));
    assert_eq!(existing.raw, None);
    assert_eq!(requests(&upstream).len(), 1);
}

#[tokio::test]
async fn tag_target_annotated_gives_the_object_bytes() {
    let (upstream, api, repo) = fixture().await;
    history(&upstream);
    let raw = signed_tag_object(&sha('2'), "v1.2.3", "+0000");
    let object_sha = upstream
        .github_release()
        .add_annotated_tag(&repo, "v1.2.3", &raw);
    let client = connect(&api).await;
    let existing = client.tag_target(&tag("v1.2.3")).await.unwrap().unwrap();
    assert_eq!(existing.object_sha, object_sha);
    assert_eq!(existing.commit, Some(id('2')));
    assert_eq!(existing.raw, Some(raw));
    assert_eq!(
        requests(&upstream),
        [
            "GET /repos/example-owner/example-repo/git/ref/tags/v1.2.3".to_owned(),
            format!("GET /repos/example-owner/example-repo/git/tags/{object_sha}"),
        ]
    );
}

#[tokio::test]
async fn tag_target_drops_bytes_it_cannot_reproduce() {
    let (upstream, api, repo) = fixture().await;
    history(&upstream);
    // GitHub reports the time in UTC, so a tag made in another zone cannot be
    // rebuilt byte for byte.
    let raw = signed_tag_object(&sha('2'), "v1.2.3", "+0200");
    let object_sha = upstream
        .github_release()
        .add_annotated_tag(&repo, "v1.2.3", &raw);
    let client = connect(&api).await;
    let existing = client.tag_target(&tag("v1.2.3")).await.unwrap().unwrap();
    assert_eq!(existing.object_sha, object_sha);
    assert_eq!(existing.commit, Some(id('2')));
    assert_eq!(existing.raw, None);
}

#[tokio::test]
async fn tag_target_refuses_answers_that_are_not_what_was_asked() {
    let (upstream, api, _repo) = fixture().await;
    let client = connect(&api).await;
    for body in [
        json!({"ref": "refs/tags/v9.9.9", "object": {"sha": sha('1'), "type": "commit"}}),
        json!({"ref": "refs/tags/v1.2.3", "object": {"sha": "abc", "type": "commit"}}),
        json!({"ref": "refs/tags/v1.2.3", "object": {"sha": sha('1'), "type": "tree"}}),
    ] {
        upstream
            .github_release()
            .answer_everything_with(Scripted::with_body(200, body.to_string()));
        assert_eq!(
            client.tag_target(&tag("v1.2.3")).await.unwrap_err(),
            GithubError::Unreadable,
            "{body}"
        );
    }
}

/// `git <args>` in `dir` with `input` on its standard input.
fn git(dir: &std::path::Path, args: &[&str], input: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut child = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Example Author")
        .env("GIT_AUTHOR_EMAIL", "author@example.com")
        .env("GIT_COMMITTER_NAME", "Example Author")
        .env("GIT_COMMITTER_EMAIL", "author@example.com")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run git");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input)
        .expect("write to git");
    let output = child.wait_with_output().expect("wait for git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn git_text(dir: &std::path::Path, args: &[&str], input: &[u8]) -> String {
    String::from_utf8(git(dir, args, input))
        .unwrap()
        .trim()
        .to_owned()
}

#[test]
fn rebuild_matches_git() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    git(path, &["init", "-q"], b"");
    let tree = git_text(path, &["mktree"], b"");
    let commit = git_text(path, &["commit-tree", &tree, "-m", "release"], b"");
    let payload = signed_tag_object(&commit, "v1.2.3", "+0000");
    let object_sha = git_text(path, &["mktag"], &payload);
    // What git stored is what the rebuild must give.
    let stored = git(path, &["cat-file", "tag", &object_sha], b"");
    assert_eq!(stored, payload);

    let message = String::from_utf8(payload.clone())
        .unwrap()
        .split_once("\n\n")
        .unwrap()
        .1
        .to_owned();
    let response = GitTagResponse {
        sha: object_sha.clone(),
        tag: "v1.2.3".to_owned(),
        message,
        tagger: Some(Tagger {
            name: "Example Tagger".to_owned(),
            email: "tagger@example.com".to_owned(),
            date: "2026-11-08T12:00:00Z".to_owned(),
        }),
        object: TaggedObject {
            sha: commit,
            kind: "commit".to_owned(),
        },
    };
    let rebuilt = tag_object::rebuild(&response).unwrap();
    assert_eq!(rebuilt, stored);
    assert_eq!(tag_object::object_id(&rebuilt), object_sha);
}

#[test]
fn rebuild_refuses_what_cannot_be_written_into_an_object() {
    let response = |name: &str, date: &str, kind: &str| GitTagResponse {
        sha: sha('9'),
        tag: "v1.2.3".to_owned(),
        message: "m\n".to_owned(),
        tagger: Some(Tagger {
            name: name.to_owned(),
            email: "tagger@example.com".to_owned(),
            date: date.to_owned(),
        }),
        object: TaggedObject {
            sha: sha('1'),
            kind: kind.to_owned(),
        },
    };
    assert!(tag_object::rebuild(&response("A", "2026-11-08T12:00:00Z", "commit")).is_some());
    assert!(tag_object::rebuild(&response("A\nB", "2026-11-08T12:00:00Z", "commit")).is_none());
    assert!(tag_object::rebuild(&response("A", "yesterday", "commit")).is_none());
    assert!(tag_object::rebuild(&response("A", "2026-11-08T12:00:00Z", "branch")).is_none());
}

fn create_request(commit: char) -> CreateTag {
    CreateTag {
        tag: tag("v1.2.3"),
        message:
            "example-repo 1.2.3\n-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
                .to_owned(),
        object: id(commit),
        tagger_name: "Example Tagger".to_owned(),
        tagger_email: "tagger@example.com".to_owned(),
        tagged_at: jiff::Timestamp::from_second(TAGGED_AT).unwrap(),
    }
}

#[tokio::test]
async fn create_tag_then_ref_makes_a_tag_the_client_reads_back() {
    let (upstream, api, repo) = fixture().await;
    history(&upstream);
    let client = connect(&api).await;
    let request = create_request('2');
    let created = client.create_tag(&request).await.unwrap();

    let expected = format!(
        "object {}\ntype commit\ntag v1.2.3\ntagger Example Tagger <tagger@example.com> \
         {TAGGED_AT} +0000\n\n{}",
        sha('2'),
        request.message
    );
    assert_eq!(
        upstream
            .github_release()
            .tag_object(&repo, &created)
            .as_deref(),
        Some(expected.as_bytes())
    );
    assert_eq!(created, tag_object::object_id(expected.as_bytes()));
    assert_eq!(upstream.github_release().ref_target(&repo, "v1.2.3"), None);

    client.create_ref(&request.tag, &created).await.unwrap();
    assert_eq!(
        upstream.github_release().ref_target(&repo, "v1.2.3"),
        Some(created.clone())
    );

    let calls = upstream.github_release().record();
    let body: Value = serde_json::from_slice(&calls[2].body).unwrap();
    assert_eq!(
        body,
        json!({
            "tag": "v1.2.3",
            "message": request.message,
            "object": sha('2'),
            "type": "commit",
            "tagger": {
                "name": "Example Tagger",
                "email": "tagger@example.com",
                "date": "2026-11-08T12:00:00Z",
            },
        })
    );
    assert_eq!(
        calls[2].path_and_query,
        "/repos/example-owner/example-repo/git/tags"
    );
    let ref_body: Value = serde_json::from_slice(&calls[3].body).unwrap();
    assert_eq!(ref_body, json!({"ref": "refs/tags/v1.2.3", "sha": created}));

    // The tag made is one whose bytes are read back whole.
    let existing = client.tag_target(&request.tag).await.unwrap().unwrap();
    assert_eq!(existing.raw.as_deref(), Some(expected.as_bytes()));
    assert_eq!(existing.commit, Some(id('2')));
}

#[tokio::test]
async fn create_tag_and_ref_refuse_answers_that_do_not_match() {
    let (upstream, api, _repo) = fixture().await;
    history(&upstream);
    let client = connect(&api).await;
    let fake = upstream.github_release();
    fake.answer_everything_with(Scripted::with_body(
        201,
        json!({"sha": "not-a-sha"}).to_string(),
    ));
    assert_eq!(
        client.create_tag(&create_request('2')).await.unwrap_err(),
        GithubError::Unreadable
    );
    fake.answer_everything_with(Scripted::with_body(
        201,
        json!({"ref": "refs/tags/v9.9.9", "object": {"sha": sha('2'), "type": "tag"}}).to_string(),
    ));
    assert_eq!(
        client
            .create_ref(&tag("v1.2.3"), &sha('2'))
            .await
            .unwrap_err(),
        GithubError::Unreadable
    );
    // Back to the real thing: the same client works again.
    fake.answer_normally();
    assert!(client.create_tag(&create_request('2')).await.is_ok());
}

#[tokio::test]
async fn create_ref_for_an_existing_tag_is_refused() {
    let (upstream, api, repo) = fixture().await;
    history(&upstream);
    upstream
        .github_release()
        .add_lightweight_tag(&repo, "v1.2.3", &sha('1'));
    let client = connect(&api).await;
    assert_eq!(
        client
            .create_ref(&tag("v1.2.3"), &sha('2'))
            .await
            .unwrap_err(),
        GithubError::Refused(StatusCode::UNPROCESSABLE_ENTITY)
    );
}
