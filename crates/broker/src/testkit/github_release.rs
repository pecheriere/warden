//! A fake GitHub for the broker's release client, served by
//! [`super::upstream::HttpsUpstream`].
//!
//! It is a small in-memory GitHub: the repositories the release App is
//! installed on, every call it received, and an optional answer that replaces
//! the real one on any of its routes. Later routes (commits, tags, releases and
//! their assets) read and write the same state.
//!
//! Routes:
//! - `GET /repos/<owner>/<name>/installation`: `200` with
//!   [`INSTALLATION_ID`] for an installed repository, `404` for any other;
//! - `POST /app/installations/<INSTALLATION_ID>/access_tokens`: `201` with
//!   [`TOKEN`], limited to what the request asked for. Other installation ids
//!   belong to the plain token route of the upstream.

use std::sync::{Arc, Mutex};

use axum::response::Response;
use http::{HeaderMap, Method};
use serde_json::{Value, json};
use warden_broker_proto::release::RepoName;

use super::upstream::{Received, Scripted, answer_scripted};

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
    /// Calls to the fake's routes, oldest first.
    calls: Vec<Received>,
    /// When set, every route answers this instead.
    answer_with: Option<Scripted>,
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

    /// Every call the fake's routes have received, oldest first.
    #[must_use]
    pub fn record(&self) -> Vec<Received> {
        self.state().calls.clone()
    }

    /// Answer every route with `answer`, until [`Self::answer_normally`].
    pub fn answer_everything_with(&self, answer: Scripted) {
        self.state().answer_with = Some(answer);
    }

    /// Go back to answering as GitHub would.
    pub fn answer_normally(&self) {
        self.state().answer_with = None;
    }

    /// The answer to a call, or `None` when it is not one of the fake's routes.
    pub(super) async fn route(
        &self,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<Response> {
        let path = path_and_query.split('?').next().unwrap_or_default();
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let answer = match (method.as_str(), segments.as_slice()) {
            ("GET", ["repos", owner, name, "installation"]) => {
                Answer::Installation(format!("{owner}/{name}").to_lowercase())
            }
            ("POST", ["app", "installations", id, "access_tokens"])
                if id.parse() == Ok(INSTALLATION_ID) =>
            {
                Answer::Token
            }
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
            match (&state.answer_with, answer) {
                (Some(scripted), _) => scripted.clone(),
                (None, Answer::Installation(repo)) => {
                    if state.installed.contains(&repo) {
                        json_answer(200, &json!({"id": INSTALLATION_ID}))
                    } else {
                        json_answer(404, &json!({"message": "Not Found"}))
                    }
                }
                (None, Answer::Token) => token_answer(body),
            }
        };
        Some(answer_scripted(scripted).await)
    }
}

enum Answer {
    Installation(String),
    Token,
}

fn json_answer(status: u16, value: &Value) -> Scripted {
    Scripted::with_body(status, value.to_string()).header("content-type", "application/json")
}

/// A token limited to the repositories and permissions the request named.
fn token_answer(body: &[u8]) -> Scripted {
    let Ok(request) = serde_json::from_slice::<Value>(body) else {
        return json_answer(422, &json!({"message": "Invalid request"}));
    };
    json_answer(
        201,
        &json!({
            "token": TOKEN,
            "expires_at": TOKEN_EXPIRES_AT,
            "permissions": request["permissions"],
            "repository_selection": "selected",
        }),
    )
}
