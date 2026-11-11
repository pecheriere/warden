//! The release client's release and asset calls, against the fake GitHub.

use serde_json::{Value, json};

use super::rest::{connect, fixture, requests, tag};
use crate::github_app::GithubApi;
use crate::github_release::GithubError;
use crate::testkit::upstream::{HttpsUpstream, Scripted};

#[tokio::test]
async fn release_for_tag_finds_draft() {
    let (upstream, api, repo) = fixture().await;
    let fake = upstream.github_release();
    let other = fake.add_release(&repo, "v1.2.2", false);
    fake.add_asset(&repo, other, "not this one", b"x");
    let draft = fake.add_release(&repo, "v1.2.3", true);
    fake.add_asset(&repo, draft, "warden-1.2.3-SHA256SUMS", b"sums");
    let client = connect(&api).await;
    let release = client
        .release_for_tag(&tag("v1.2.3"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(release.id, draft);
    assert!(release.draft);
    assert_eq!(release.assets.len(), 1);
    assert_eq!(release.assets[0].name, "warden-1.2.3-SHA256SUMS");
    assert!(
        release.assets[0]
            .digest
            .as_deref()
            .is_some_and(|d| d.starts_with("sha256:"))
    );
    assert_eq!(
        requests(&upstream),
        ["GET /repos/example-owner/example-repo/releases?per_page=20"]
    );
    assert_eq!(client.release_for_tag(&tag("v9.9.9")).await.unwrap(), None);
}

#[tokio::test]
async fn release_for_tag_refuses_two_matches() {
    let (upstream, api, repo) = fixture().await;
    let fake = upstream.github_release();
    let _ = fake.add_release(&repo, "v1.2.3", true);
    let _ = fake.add_release(&repo, "v1.2.3", false);
    let client = connect(&api).await;
    assert_eq!(
        client.release_for_tag(&tag("v1.2.3")).await.unwrap_err(),
        GithubError::Unreadable
    );
}

#[tokio::test]
async fn release_for_tag_checks_only_the_assets_of_the_release_it_returns() {
    let (upstream, api, repo) = fixture().await;
    let fake = upstream.github_release();
    let odd = fake.add_release(&repo, "v1.2.2", false);
    fake.add_asset(&repo, odd, "name with spaces", b"x");
    let _ = fake.add_release(&repo, "v1.2.3", true);
    let client = connect(&api).await;
    assert!(
        client
            .release_for_tag(&tag("v1.2.3"))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client.release_for_tag(&tag("v1.2.2")).await.unwrap_err(),
        GithubError::Unreadable
    );
}

#[tokio::test]
async fn release_for_tag_refuses_assets_with_bad_names_or_digests() {
    let (upstream, api, _repo) = fixture().await;
    let client = connect(&api).await;
    let bad = [
        json!({"id": 1, "name": "../x", "digest": null}),
        json!({"id": 1, "name": "ok", "digest": "sha1:abc"}),
        json!({"id": 1, "name": "ok", "digest": format!("sha256:{}", "A".repeat(64))}),
        json!({"id": 1, "name": "ok", "digest": format!("sha256:{}", "a".repeat(63))}),
    ];
    for asset in bad {
        let list = json!([{"id": 7, "tag_name": "v1.2.3", "draft": true, "assets": [asset]}]);
        upstream
            .github_release()
            .answer_everything_with(Scripted::with_body(200, list.to_string()));
        assert_eq!(
            client.release_for_tag(&tag("v1.2.3")).await.unwrap_err(),
            GithubError::Unreadable,
            "{asset}"
        );
    }
    let digest = format!("sha256:{}", "a".repeat(64));
    let ok = json!([{"id": 7, "tag_name": "v1.2.3", "draft": true, "assets": [
        {"id": 1, "name": "warden-1.2.3.tar.gz", "digest": digest},
        {"id": 2, "name": "no-digest", "digest": null},
    ]}]);
    upstream
        .github_release()
        .answer_everything_with(Scripted::with_body(200, ok.to_string()));
    let release = client
        .release_for_tag(&tag("v1.2.3"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(release.assets[0].digest.as_deref(), Some(digest.as_str()));
    assert_eq!(release.assets[1].digest, None);
}

/// An API whose uploads host is under `/uploads` of the fake, which only that
/// path accepts uploads on.
fn api_with_uploads_apart(upstream: &HttpsUpstream) -> GithubApi {
    let origin: url::Url = upstream.origin().parse().unwrap();
    GithubApi::pinned(
        origin.clone(),
        origin.join("uploads").unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    )
}

#[tokio::test]
async fn upload_goes_to_uploads_host() {
    let (upstream, _api, repo) = fixture().await;
    let release = upstream.github_release().add_release(&repo, "v1.2.3", true);
    let api = api_with_uploads_apart(&upstream);
    let client = connect(&api).await;
    let asset = client
        .upload_asset(release, "warden-1.2.3-SHA256SUMS", b"the sums")
        .await
        .unwrap();
    assert_eq!(asset.name, "warden-1.2.3-SHA256SUMS");
    assert!(asset.digest.unwrap().starts_with("sha256:"));

    let calls = upstream.github_release().record();
    let upload = &calls[2];
    assert_eq!(upload.method, "POST");
    assert_eq!(
        upload.path_and_query,
        format!(
            "/uploads/repos/example-owner/example-repo/releases/{release}/assets?name=warden-1.2.3-SHA256SUMS"
        )
    );
    assert_eq!(upload.headers["content-type"], "application/octet-stream");
    assert_eq!(upload.body, b"the sums");
    assert_eq!(
        upstream
            .github_release()
            .release(&repo, release)
            .unwrap()
            .assets,
        [("warden-1.2.3-SHA256SUMS".to_owned(), b"the sums".to_vec())]
    );
}

#[tokio::test]
async fn upload_to_the_api_host_is_not_a_thing() {
    // The default `github()` API has one origin for both, so an upload lands on
    // the API's path, where GitHub has no such route.
    let (upstream, api, repo) = fixture().await;
    let release = upstream.github_release().add_release(&repo, "v1.2.3", true);
    let client = connect(&api).await;
    assert_eq!(
        client.upload_asset(release, "a", b"x").await.unwrap_err(),
        GithubError::NotFound
    );
}

#[tokio::test]
async fn an_asset_name_cannot_add_path_segments_or_query_parameters() {
    let (upstream, _api, repo) = fixture().await;
    let release = upstream.github_release().add_release(&repo, "v1.2.3", true);
    let api = api_with_uploads_apart(&upstream);
    let client = connect(&api).await;
    // The client refuses a name that is not a plain file name before sending.
    for name in ["a/../b&label=x", "name with spaces", "", ".", "..", "é"] {
        let err = client.upload_asset(release, name, b"x").await.unwrap_err();
        assert_eq!(err, GithubError::Unreadable, "{name}");
    }
    assert_eq!(requests(&upstream), Vec::<String>::new());
}

#[tokio::test]
async fn release_for_tag_reads_only_the_newest_releases() {
    let (upstream, api, repo) = fixture().await;
    let fake = upstream.github_release();
    let _old = fake.add_release(&repo, "v0.0.1", false);
    for n in 0..20 {
        let _ = fake.add_release(&repo, &format!("v1.0.{n}"), false);
    }
    let draft = fake.add_release(&repo, "v1.2.3", true);
    let client = connect(&api).await;
    assert_eq!(
        client
            .release_for_tag(&tag("v1.2.3"))
            .await
            .unwrap()
            .unwrap()
            .id,
        draft
    );
    // Past the newest 20 is not seen: fail closed by finding nothing.
    assert_eq!(client.release_for_tag(&tag("v0.0.1")).await.unwrap(), None);
}

#[tokio::test]
async fn delete_asset_removes_it() {
    let (upstream, api, repo) = fixture().await;
    let release = upstream.github_release().add_release(&repo, "v1.2.3", true);
    upstream
        .github_release()
        .add_asset(&repo, release, "keep", b"k");
    upstream
        .github_release()
        .add_asset(&repo, release, "drop", b"d");
    let client = connect(&api).await;
    let found = client
        .release_for_tag(&tag("v1.2.3"))
        .await
        .unwrap()
        .unwrap();
    let dropped = found.assets.iter().find(|a| a.name == "drop").unwrap().id;
    client.delete_asset(dropped).await.unwrap();
    assert_eq!(
        upstream
            .github_release()
            .release(&repo, release)
            .unwrap()
            .assets,
        [("keep".to_owned(), b"k".to_vec())]
    );
    assert_eq!(
        requests(&upstream)[1],
        format!("DELETE /repos/example-owner/example-repo/releases/assets/{dropped}")
    );
    assert_eq!(
        client.delete_asset(dropped).await.unwrap_err(),
        GithubError::NotFound
    );
}

#[tokio::test]
async fn publish_clears_the_draft_flag() {
    let (upstream, api, repo) = fixture().await;
    let release = upstream.github_release().add_release(&repo, "v1.2.3", true);
    let client = connect(&api).await;
    client.publish(release).await.unwrap();
    assert!(
        !upstream
            .github_release()
            .release(&repo, release)
            .unwrap()
            .draft
    );
    let calls = upstream.github_release().record();
    assert_eq!(calls[2].method, "PATCH");
    assert_eq!(
        calls[2].path_and_query,
        format!("/repos/example-owner/example-repo/releases/{release}")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&calls[2].body).unwrap(),
        json!({"draft": false})
    );
}

#[tokio::test]
async fn publish_refuses_answer_still_draft() {
    let (upstream, api, repo) = fixture().await;
    let release = upstream.github_release().add_release(&repo, "v1.2.3", true);
    let client = connect(&api).await;
    for body in [
        json!({"id": release, "draft": true}),
        json!({"id": release + 1, "draft": false}),
    ] {
        upstream
            .github_release()
            .answer_everything_with(Scripted::with_body(200, body.to_string()));
        assert_eq!(
            client.publish(release).await.unwrap_err(),
            GithubError::Unreadable,
            "{body}"
        );
    }
}
