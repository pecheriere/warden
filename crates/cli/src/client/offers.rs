//! The calls of what the broker offers: `GET /v1/offers` and
//! `GET /v1/offers/repository/{owner}/{name}`.
//!
//! They return the body as the broker sent it, so `warden list --json` can
//! print it whole, newer fields included; [`read`] gives the typed view.

use std::fmt;

use reqwest::{Method, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::Value;
use warden_broker_proto::doctor::sanitize;
use warden_broker_proto::offers::{Offers, RepositoryOffer};
use warden_broker_proto::release::RepoName;

use super::{CallError, Client, failure, json};

/// Why an offers call gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OffersError {
    /// The broker answered with a server error (5xx): it is up, but cannot
    /// read its policy now.
    Broker(String),
    /// Any other failure, as for every other call.
    Call(CallError),
}

impl fmt::Display for OffersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Broker(m) => f.write_str(m),
            Self::Call(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for OffersError {}

impl From<CallError> for OffersError {
    fn from(e: CallError) -> Self {
        Self::Call(e)
    }
}

/// The typed view of an offers body.
///
/// # Errors
/// [`CallError::Refused`] if the body is not what this CLI reads.
pub fn read<T: DeserializeOwned>(body: &Value) -> Result<T, CallError> {
    T::deserialize(body).map_err(|e| {
        CallError::Refused(sanitize(&format!(
            "the broker sent an unexpected response: {e}"
        )))
    })
}

/// The body of an offers answer, or `None` from a broker without the route,
/// which answers 404.
async fn body(resp: Response) -> Result<Option<Value>, OffersError> {
    let status = resp.status();
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status.is_server_error() {
        return Err(OffersError::Broker(failure(resp).await.to_string()));
    }
    Ok(Some(json(resp, StatusCode::OK).await?))
}

impl Client {
    /// What the broker offers this agent, as it sent it, or `None` from a
    /// broker without the route.
    ///
    /// # Errors
    /// If the server is unreachable, refuses or fails.
    pub async fn offers(&self) -> Result<Option<Value>, OffersError> {
        let resp = self
            .call(Method::GET, self.url(Offers::path())?, None)
            .await?;
        body(resp).await
    }

    /// What the broker offers for `repo`, as it sent it, or `None` from a
    /// broker without the route.
    ///
    /// # Errors
    /// If the server is unreachable, refuses or fails.
    pub async fn repository_offer(&self, repo: &RepoName) -> Result<Option<Value>, OffersError> {
        let url = self.url(&RepositoryOffer::path(repo))?;
        let resp = self.call(Method::GET, url, None).await?;
        body(resp).await
    }
}
