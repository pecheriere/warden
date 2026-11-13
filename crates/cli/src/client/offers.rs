//! The calls of what the broker offers: `GET /v1/offers` and
//! `GET /v1/offers/repository/{owner}/{name}`.

use reqwest::{Method, StatusCode};
use warden_broker_proto::offers::{Offers, RepositoryOffer};
use warden_broker_proto::release::RepoName;

use super::{CallError, Client, json};

impl Client {
    /// What the broker offers this agent, or `None` from a broker without the
    /// route, which answers 404.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn offers(&self) -> Result<Option<Offers>, CallError> {
        let resp = self
            .call(Method::GET, self.url(Offers::path())?, None)
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        json(resp, StatusCode::OK).await.map(Some)
    }

    /// What the broker offers for `repo`, or `None` from a broker without the
    /// route, which answers 404.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn repository_offer(
        &self,
        repo: &RepoName,
    ) -> Result<Option<RepositoryOffer>, CallError> {
        let url = self.url(&RepositoryOffer::path(repo))?;
        let resp = self.call(Method::GET, url, None).await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        json(resp, StatusCode::OK).await.map(Some)
    }
}
