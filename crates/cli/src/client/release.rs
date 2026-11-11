//! The calls of the release steps: `POST /v1/release/{tag,manifest,publish}`.

use reqwest::{Method, StatusCode};
use warden_broker_proto::release::{
    ManifestResponse, PublishResponse, ReleaseTag, ReleaseTarget, RepoName, SignManifestRequest,
    TagResponse,
};

use super::{CallError, Client, json, json_body};

impl Client {
    /// Have the broker create the tag under this agent's release grant.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn release_tag(
        &self,
        repository: &RepoName,
        tag: &ReleaseTag,
    ) -> Result<TagResponse, CallError> {
        self.release_step("v1/release/tag", &target(repository, tag))
            .await
    }

    /// Have the broker sign a manifest under this agent's release grant.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn release_manifest(
        &self,
        request: &SignManifestRequest,
    ) -> Result<ManifestResponse, CallError> {
        self.release_step("v1/release/manifest", request).await
    }

    /// Have the broker publish the draft under this agent's release grant.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn release_publish(
        &self,
        repository: &RepoName,
        tag: &ReleaseTag,
    ) -> Result<PublishResponse, CallError> {
        self.release_step("v1/release/publish", &target(repository, tag))
            .await
    }

    async fn release_step<B, R>(&self, path: &str, body: &B) -> Result<R, CallError>
    where
        B: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let url = self.url(path)?;
        let resp = self.call(Method::POST, url, Some(json_body(body)?)).await?;
        json(resp, StatusCode::OK).await
    }
}

fn target(repository: &RepoName, tag: &ReleaseTag) -> ReleaseTarget {
    ReleaseTarget {
        repository: repository.clone(),
        tag: tag.clone(),
    }
}
