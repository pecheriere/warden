//! GitHub token rows written straight into the database, as an earlier broker or the
//! approval flow of a later task would have written them.

use warden_broker_proto::github_token::{GrantRepository, GrantScope};
use warden_broker_proto::release::RepoName;
use warden_broker_proto::{
    Access, CreateRequest, GithubTokenAccess, GithubTokenGrant, Goal, GrantAccess, GrantView, Id,
    Window, fingerprint,
};

use super::TestBroker;
use crate::requests::Clock as _;

impl TestBroker {
    /// An active GitHub token grant for `agent` as 0.12.0 stored it: it names no
    /// repository. Returns the grant's id. The agent must exist.
    ///
    /// # Panics
    /// If the row cannot be written.
    pub async fn insert_legacy_github_grant(&self, agent: &str) -> Id {
        self.insert_github_grant(agent, GrantScope::Legacy).await
    }

    /// An active GitHub token grant for `agent` over `repositories`, `(name, id)`
    /// each, written as the approval of a scoped request would. Returns the grant's
    /// id. The agent must exist.
    ///
    /// # Panics
    /// If a name is not a valid repository, the list is not a valid scope, or the row
    /// cannot be written.
    pub async fn insert_scoped_github_grant(
        &self,
        agent: &str,
        repositories: &[(&str, u64)],
    ) -> Id {
        let list = repositories
            .iter()
            .map(|(name, id)| GrantRepository {
                name: RepoName::try_from((*name).to_owned()).expect("valid repository"),
                id: *id,
            })
            .collect();
        let scope = GrantScope::repositories(list).expect("a valid scope");
        self.insert_github_grant(agent, scope).await
    }

    async fn insert_github_grant(&self, agent: &str, scope: GrantScope) -> Id {
        let key = self
            .state
            .backend
            .github_app()
            .await
            .expect("the broker holds an App");
        let policy = key.policy(self.state.requests.github_token_max());
        let now = self.clock.now();
        let window = Window::D30;
        let grant_id = Id::random();
        let access = GithubTokenAccess::new(
            match &scope {
                GrantScope::Legacy => Vec::new(),
                GrantScope::Repositories(list) => list.iter().map(|r| r.name.clone()).collect(),
            },
            None,
        )
        .expect("valid repositories");
        let request_id = self
            .insert_github_request_row(agent, access, "approved")
            .await;
        let view = GrantView {
            grant_id: grant_id.clone(),
            not_before: now,
            not_after: now + i64::try_from(window.secs()).expect("a window fits"),
            access: GrantAccess::GithubToken(GithubTokenGrant {
                app_id: key.app_id().to_owned(),
                installation_id: key.installation_id(),
                digest: policy.destination_digest(),
                repositories: scope,
            }),
        };
        sqlx::query(
            "INSERT INTO grants (id, request_id, agent, window_secs, not_before, not_after, view) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(grant_id.as_str())
        .bind(request_id.as_str())
        .bind(agent)
        .bind(i64::try_from(window.secs()).expect("a window fits"))
        .bind(view.not_before)
        .bind(view.not_after)
        .bind(serde_json::to_string(&view).expect("a grant view serialises"))
        .execute(&self.state.pool)
        .await
        .expect("inserting a grant");
        grant_id
    }

    /// A pending GitHub token request from `agent` as 0.12.0 stored it: it names no
    /// repository. Returns its id. The agent must exist.
    ///
    /// # Panics
    /// If the row cannot be written.
    pub async fn insert_legacy_github_request(&self, agent: &str) -> Id {
        let access = GithubTokenAccess::new(Vec::new(), None).expect("valid access");
        self.insert_github_request_row(agent, access, "pending")
            .await
    }

    async fn insert_github_request_row(
        &self,
        agent: &str,
        access: GithubTokenAccess,
        status: &str,
    ) -> Id {
        let id = Id::random();
        let now = self.clock.now();
        let request = CreateRequest {
            goal: Goal::try_from("push the fix".to_owned()).expect("valid goal"),
            access: Access::GithubToken(access),
            window: Window::D30,
            session: None,
            link: None,
        };
        let fingerprint = fingerprint(&agent.parse().expect("a valid agent name"), &request);
        let body = serde_json::to_string(&request).expect("a request serialises");
        // What 0.12.0 wrote, and left unchanged when it approved the request.
        let dedupe = format!("{agent}|github_token");
        let decided_at = (status != "pending").then_some(now);
        sqlx::query(
            "INSERT INTO requests (id, agent, fingerprint, dedupe_key, body, \
             approval_token_hash, status, created_at, expires_at, decided_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(id.as_str())
        .bind(agent)
        .bind(fingerprint.as_str())
        .bind(dedupe)
        .bind(body)
        .bind(format!("{:0>64}", id.as_str()))
        .bind(status)
        .bind(now)
        .bind(now + 86_400)
        .bind(decided_at)
        .execute(&self.state.pool)
        .await
        .expect("inserting a request");
        id
    }
}
