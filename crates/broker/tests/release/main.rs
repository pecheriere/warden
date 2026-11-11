//! Phone-approved releases: requests, checked against a fake GitHub before the owner
//! is asked. Keys are generated for each test; time only moves through the broker's
//! manual clock.

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use warden_broker::github_app::GithubApi;
use warden_broker::policy::{ReleaseAppKey, ReleaseSigningKey};
use warden_broker::testkit::github_app::RSA2048_PKCS8;
use warden_broker::testkit::{HttpsUpstream, TestBroker};
use warden_broker_proto::release::RepoName;

mod request;

const REPO: &str = "example-owner/example-repo";
/// The head of the default branch.
const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";
/// The commit before it.
const PARENT: &str = "1111111111111111111111111111111111111111";
/// A commit that is not on the default branch.
const SIDE: &str = "2222222222222222222222222222222222222222";
/// 2026-11-08T12:00:00Z, when the fake GitHub's tokens are valid.
const NOW: i64 = 1_794_139_200;
const MANIFEST: (&str, &str) = ("warden-{version}-SHA256SUMS", "warden-release");

fn repo(name: &str) -> RepoName {
    name.to_owned().try_into().unwrap()
}

/// What a repository's release item asks the broker to do.
#[derive(Clone, Copy)]
enum Shape {
    /// Tag, sign a manifest and publish.
    Everything,
    /// Tag only.
    TagOnly,
}

/// A broker with the release App and a release key for [`REPO`], a fake GitHub
/// where the App is installed on it, an enrolled agent `build-agent`, and the
/// release key.
struct Harness {
    broker: TestBroker,
    upstream: HttpsUpstream,
    key: PrivateKey,
}

async fn harness(shape: Shape) -> Harness {
    let upstream = HttpsUpstream::start().await;
    let origin: url::Url = upstream.origin().parse().unwrap();
    let api = GithubApi::pinned(
        origin.clone(),
        origin,
        upstream.ca_pem().as_bytes().to_vec(),
    );
    let broker = TestBroker::with_github_api(api).await;
    broker.clock.set(NOW);
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let (manifest, publish) = match shape {
        Shape::Everything => (Some(MANIFEST), true),
        Shape::TagOnly => (None, false),
    };
    broker.backend.add_release_key(ReleaseSigningKey::for_tests(
        REPO,
        key.clone(),
        manifest,
        publish,
    ));
    broker.backend.set_release_app(Some(
        ReleaseAppKey::new(
            "987654".to_owned(),
            std::str::from_utf8(RSA2048_PKCS8).unwrap(),
        )
        .unwrap(),
    ));
    broker.add_agent("build-agent").await;

    let github = upstream.github_release();
    let repository = repo(REPO);
    github.install(&repository);
    github.add_commit(
        &repository,
        PARENT,
        "Start the project\n",
        "2026-11-01T09:00:00Z",
        &[],
    );
    github.add_commit(
        &repository,
        HEAD,
        "Add the release workflow\n\nMore detail.\n",
        "2026-11-07T10:30:00Z",
        &[PARENT],
    );
    github.add_commit(
        &repository,
        SIDE,
        "Work on another branch\n",
        "2026-11-06T10:30:00Z",
        &[PARENT],
    );
    github.set_default_branch(&repository, "main", HEAD);
    Harness {
        broker,
        upstream,
        key,
    }
}

impl Harness {
    /// Add the annotated tag `tag` whose object is `raw` to [`REPO`].
    fn annotate(&self, tag: &str, raw: &[u8]) {
        let _id = self
            .upstream
            .github_release()
            .add_annotated_tag(&repo(REPO), tag, raw);
    }
}
