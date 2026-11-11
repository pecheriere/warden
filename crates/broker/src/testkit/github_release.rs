//! A fake GitHub for the broker's release client, served by
//! [`super::upstream::HttpsUpstream`].
//!
//! It is a small in-memory GitHub: the repositories the release App is
//! installed on, every call it received, and an optional answer that replaces
//! the real one on any of its routes. Each installed repository holds commits
//! (with ancestry), a default branch, files, tags and releases with assets,
//! which tests fill in with the `add_*` methods and which the routes read and
//! write.
//!
//! Routes:
//! - `GET /repos/<owner>/<name>/installation`: `200` with
//!   [`INSTALLATION_ID`] for an installed repository, `404` for any other;
//! - `POST /app/installations/<INSTALLATION_ID>/access_tokens`: `201` with
//!   [`TOKEN`], limited to what the request asked for. Other installation ids
//!   belong to the plain token route of the upstream;
//! - on an installed repository `/repos/<owner>/<name>`: `GET` of the repository,
//!   `git/commits/<sha>`, `compare/<base>...<branch>`, `git/ref/tags/<tag>`,
//!   `git/tags/<sha>`, `contents/<path>?ref=<sha>`, `tags`, `releases`; `POST` of
//!   `git/tags` and `git/refs`; `PATCH` of `releases/<id>`; `DELETE` of
//!   `releases/assets/<id>`;
//! - `POST /uploads/repos/<owner>/<name>/releases/<id>/assets?name=<name>`: an
//!   asset upload, which only this path takes, as GitHub's uploads host has its
//!   own origin.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::response::Response;
use http::{HeaderMap, Method};
use serde_json::{Value, json};
use warden_broker_proto::release::RepoName;

use super::upstream::{Received, Scripted, answer_scripted};

mod repository;
mod signed_tag;

pub use repository::ReleaseView;
use repository::{Call, Repository};
pub use signed_tag::{signed_tag_object, unsigned_tag_object};

/// The installation id the fake gives every installed repository.
pub const INSTALLATION_ID: u64 = 424_242;

/// The token the fake mints.
pub const TOKEN: &str = "ghs_example_release_token";

/// When the fake's tokens expire: an hour after 2026-11-08T12:00:00Z, the
/// moment tests conventionally call at.
pub const TOKEN_EXPIRES_AT: &str = "2026-11-08T13:00:00Z";

#[derive(Default)]
struct State {
    /// Lowercase `owner/name` of each repository the release App is installed on.
    installed: Vec<String>,
    /// What each installed repository holds, by lowercase `owner/name`.
    repositories: HashMap<String, Repository>,
    /// Calls to the fake's routes, oldest first.
    calls: Vec<Received>,
    /// When set, every route answers this instead.
    answer_with: Option<Scripted>,
    /// Routes that answer something else, as `(path suffix, answer)`.
    path_answers: Vec<(String, Scripted)>,
}

/// The fake's state. Cloning shares it.
#[derive(Clone, Default)]
pub struct GithubReleaseFake(Arc<Mutex<State>>);

impl GithubReleaseFake {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().expect("github release fake poisoned")
    }

    /// Install the release App on `repo`.
    pub fn install(&self, repo: &RepoName) {
        self.state().installed.push(repo.to_string().to_lowercase());
    }

    fn with<T>(&self, repo: &RepoName, change: impl FnOnce(&mut Repository) -> T) -> T {
        let mut state = self.state();
        let held = state
            .repositories
            .entry(repo.to_string().to_lowercase())
            .or_default();
        change(held)
    }

    /// Name the default branch of `repo` and the commit at its head.
    pub fn set_default_branch(&self, repo: &RepoName, branch: &str, head: &str) {
        self.with(repo, |r| r.set_default_branch(branch, head));
    }

    /// Add commit `sha` to `repo`, with `parents` (ids) as its ancestry.
    pub fn add_commit(
        &self,
        repo: &RepoName,
        sha: &str,
        message: &str,
        date: &str,
        parents: &[&str],
    ) {
        self.with(repo, |r| r.add_commit(sha, message, date, parents));
    }

    /// Give `repo` a file at `path` as it is at `commit`.
    pub fn add_file(&self, repo: &RepoName, commit: &str, path: &str, bytes: &[u8]) {
        self.with(repo, |r| r.add_file(commit, path, bytes));
    }

    /// Add a lightweight tag: a ref straight to `commit`.
    pub fn add_lightweight_tag(&self, repo: &RepoName, tag: &str, commit: &str) {
        self.with(repo, |r| r.add_lightweight_tag(tag, commit));
    }

    /// Add the annotated tag `tag`, whose tag object is exactly `raw`, and
    /// return the object's id.
    ///
    /// # Panics
    /// If `raw` is not a tag object.
    #[must_use]
    pub fn add_annotated_tag(&self, repo: &RepoName, tag: &str, raw: &[u8]) -> String {
        self.with(repo, |r| {
            let sha = r.add_tag_object(raw);
            r.add_ref(tag, &sha);
            sha
        })
    }

    /// Add a release for `tag` and return its id.
    #[must_use]
    pub fn add_release(&self, repo: &RepoName, tag: &str, draft: bool) -> u64 {
        self.with(repo, |r| r.add_release(tag, draft))
    }

    /// Attach a file to `release`.
    ///
    /// # Panics
    /// If `release` is not one of `repo`'s.
    pub fn add_asset(&self, repo: &RepoName, release: u64, name: &str, bytes: &[u8]) {
        self.with(repo, |r| r.add_asset(release, name, bytes));
    }

    /// The id the ref `refs/tags/<tag>` points at.
    #[must_use]
    pub fn ref_target(&self, repo: &RepoName, tag: &str) -> Option<String> {
        self.with(repo, |r| r.ref_target(tag))
    }

    /// The bytes of the tag object `sha`.
    #[must_use]
    pub fn tag_object(&self, repo: &RepoName, sha: &str) -> Option<Vec<u8>> {
        self.with(repo, |r| r.tag_object(sha))
    }

    /// The release `id`, as the fake holds it now.
    #[must_use]
    pub fn release(&self, repo: &RepoName, id: u64) -> Option<ReleaseView> {
        self.with(repo, |r| r.release(id))
    }

    /// Every call the fake's routes have received, oldest first.
    #[must_use]
    pub fn record(&self) -> Vec<Received> {
        self.state().calls.clone()
    }

    /// Answer every route with `answer`, until [`Self::answer_normally`].
    pub fn answer_everything_with(&self, answer: Scripted) {
        self.state().answer_with = Some(answer);
    }

    /// Answer every call whose path (without the query) ends with `suffix` with
    /// `answer`, until [`Self::answer_normally`]. Other routes answer as GitHub would.
    pub fn answer_path_with(&self, suffix: &str, answer: Scripted) {
        self.state().path_answers.push((suffix.to_owned(), answer));
    }

    /// Go back to answering as GitHub would.
    pub fn answer_normally(&self) {
        let mut state = self.state();
        state.answer_with = None;
        state.path_answers.clear();
    }

    /// The answer to a call, or `None` when it is not one of the fake's routes.
    pub(super) async fn route(
        &self,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<Response> {
        let (path, query) = path_and_query
            .split_once('?')
            .unwrap_or((path_and_query, ""));
        let decoded: Vec<String> = path
            .trim_start_matches('/')
            .split('/')
            .map(|segment| {
                percent_encoding::percent_decode_str(segment)
                    .decode_utf8_lossy()
                    .into_owned()
            })
            .collect();
        let segments: Vec<&str> = decoded.iter().map(String::as_str).collect();
        let answer = match (method.as_str(), segments.as_slice()) {
            ("GET", ["repos", owner, name, "installation"]) => {
                Answer::Installation(format!("{owner}/{name}").to_lowercase())
            }
            ("POST", ["app", "installations", id, "access_tokens"])
                if id.parse() == Ok(INSTALLATION_ID) =>
            {
                Answer::Token
            }
            (_, ["repos", owner, name, rest @ ..]) => Answer::Repository {
                full: format!("{owner}/{name}").to_lowercase(),
                uploads: false,
                rest: rest.iter().map(|s| (*s).to_owned()).collect(),
            },
            (_, ["uploads", "repos", owner, name, rest @ ..]) => Answer::Repository {
                full: format!("{owner}/{name}").to_lowercase(),
                uploads: true,
                rest: rest.iter().map(|s| (*s).to_owned()).collect(),
            },
            _ => return None,
        };
        let scripted = {
            let mut state = self.state();
            state.calls.push(Received {
                method: method.to_string(),
                path_and_query: path_and_query.to_owned(),
                headers: headers.clone(),
                body: body.to_vec(),
            });
            let fixed = state.answer_with.clone().or_else(|| {
                state
                    .path_answers
                    .iter()
                    .find(|(suffix, _)| path.ends_with(suffix.as_str()))
                    .map(|(_, scripted)| scripted.clone())
            });
            match (&fixed, answer) {
                (Some(scripted), _) => scripted.clone(),
                (None, Answer::Installation(repo)) => {
                    if state.installed.contains(&repo) {
                        json_answer(200, &json!({"id": INSTALLATION_ID}))
                    } else {
                        json_answer(404, &json!({"message": "Not Found"}))
                    }
                }
                (None, Answer::Token) => token_answer(body, &state.installed),
                (
                    None,
                    Answer::Repository {
                        full,
                        uploads,
                        rest,
                    },
                ) => {
                    if state.installed.contains(&full) {
                        let call = Call {
                            method,
                            uploads,
                            rest,
                            query: url::form_urlencoded::parse(query.as_bytes())
                                .into_owned()
                                .collect(),
                            headers,
                            body,
                        };
                        state.repositories.entry(full).or_default().answer(&call)
                    } else {
                        json_answer(404, &json!({"message": "Not Found"}))
                    }
                }
            }
        };
        Some(answer_scripted(scripted).await)
    }
}

enum Answer {
    Installation(String),
    Token,
    Repository {
        full: String,
        uploads: bool,
        rest: Vec<String>,
    },
}

fn json_answer(status: u16, value: &Value) -> Scripted {
    Scripted::with_body(status, value.to_string()).header("content-type", "application/json")
}

/// A token limited to the repositories and permissions the request named, with
/// the repositories echoed as GitHub does: the ones among `installed` of those
/// names.
fn token_answer(body: &[u8], installed: &[String]) -> Scripted {
    let Ok(request) = serde_json::from_slice::<Value>(body) else {
        return json_answer(422, &json!({"message": "Invalid request"}));
    };
    let names = request["repositories"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let repositories: Vec<Value> = names
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|name| {
            let suffix = format!("/{}", name.to_lowercase());
            installed
                .iter()
                .find(|full| full.ends_with(&suffix))
                .map(|full| json!({"name": name, "full_name": full}))
        })
        .collect();
    json_answer(
        201,
        &json!({
            "token": TOKEN,
            "expires_at": TOKEN_EXPIRES_AT,
            "permissions": request["permissions"],
            "repository_selection": "selected",
            "repositories": repositories,
        }),
    )
}
