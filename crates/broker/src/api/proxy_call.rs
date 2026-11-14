//! `POST /v1/grants/{id}/http`: a proxied call with an api grant, audited.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use url::Url;
use warden_broker_proto::{AgentName, ApiGrant, GrantAccess, Id, ProxyRequest, ProxyResponse};

use super::{ApiJson, Failure, POLICY_CHANGED, off_runtime, parse_id};
use crate::AppState;
use crate::audit::{AuditEvent, bounded_text};
use crate::identity::AuthedAgent;
use crate::policy::{ApiScope, PolicyError};
use crate::proxy::{self, CallEnd, CallInfo, CallSlot, GrantChecks, GrantState, Needles};
use crate::requests::{DailyUse, RequestError};

/// Longest method name recorded in the audit log as sent.
const MAX_AUDIT_METHOD: usize = 32;

/// Longest URL (origin and path) recorded in the audit log as sent.
const MAX_AUDIT_URL: usize = 512;

/// `POST /v1/grants/{id}/http`: make the call in the body with the grant's
/// API secret and return the redacted response.
///
/// The grant must be the agent's (404 otherwise), unrevoked, unexpired and
/// for API access (409 otherwise). Everything after that runs on its own
/// task and is audited as a `proxy_call` before the agent gets an answer,
/// so a disconnecting agent can neither stop a call halfway nor keep it out
/// of the audit log.
pub(super) async fn proxy_call(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<ProxyRequest>,
) -> Result<Json<ProxyResponse>, Failure> {
    let id = parse_id(&id)?;
    let grant = usable_api_grant(&state, &agent, &id).await?;
    tokio::spawn(audited_call(state, agent, id, grant, req))
        .await
        .map_err(|_| Failure::Request(RequestError::Internal("proxy call task failed")))?
        .map(Json)
}

/// Why a grant of the agent's cannot be used for a call now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unusable {
    Revoked,
    Expired,
    NotApi,
}

impl Unusable {
    const fn message(self) -> &'static str {
        match self {
            Self::Revoked => "grant revoked",
            Self::Expired => "grant expired",
            Self::NotApi => "grant is not for API access",
        }
    }
}

/// The approved details of grant `id` if `agent` may use it now, or why
/// not. The outer error is a failed lookup (404 for another agent's grant).
async fn api_grant_status(
    state: &AppState,
    agent: &AgentName,
    id: &Id,
) -> Result<Result<ApiGrant, Unusable>, Failure> {
    let (view, revoked) = state.requests.agent_grant(agent, id).await?;
    Ok(if revoked {
        Err(Unusable::Revoked)
    } else if state.clock.now() >= view.not_after {
        Err(Unusable::Expired)
    } else {
        match view.access {
            GrantAccess::Api(grant) => Ok(grant),
            GrantAccess::Ssh(_)
            | GrantAccess::Relay(_)
            | GrantAccess::CommitSigning(_)
            | GrantAccess::GithubToken(_)
            | GrantAccess::Release(_) => Err(Unusable::NotApi),
        }
    })
}

/// The approved details of grant `id` if `agent` may use it now; 409 if it
/// is revoked, expired or not for API access.
async fn usable_api_grant(
    state: &AppState,
    agent: &AgentName,
    id: &Id,
) -> Result<ApiGrant, Failure> {
    api_grant_status(state, agent, id)
        .await?
        .map_err(|why| Failure::Client(StatusCode::CONFLICT, why.message().to_owned()))
}

/// What a `proxy_call` audit entry records about a call.
struct CallRecord {
    method: String,
    url: String,
    /// The path of `url`, as the owner's live view lists the call: bounded
    /// with `url`, and `invalid` whenever `url` is.
    path: String,
    status: Option<u16>,
    response_bytes: u64,
    redactions: u32,
    /// Why the upstream call was stopped before it finished, if it was.
    aborted: Option<CallEnd>,
    /// Whether `proxy_call_started` was written: the result is then written whatever
    /// the allowance for refused calls says, so that a start always has its end.
    started: bool,
}

impl CallRecord {
    /// The method and URL as the agent sent them, reduced to what may be
    /// recorded: a method token, and the URL's origin and path (never the
    /// userinfo, or the query and fragment, which may carry the agent's own
    /// data). Unparsable or overlong values are recorded as `invalid`; the
    /// path is a suffix of the URL, so it is never longer than
    /// [`MAX_AUDIT_URL`] either.
    fn new(req: &ProxyRequest) -> Self {
        let method = http::Method::from_bytes(req.method.as_bytes())
            .ok()
            .filter(|m| m.as_str().len() <= MAX_AUDIT_METHOD)
            .map_or_else(|| "invalid".to_owned(), |m| m.as_str().to_owned());
        let (url, path) = Url::parse(&req.url)
            .ok()
            .map(|u| {
                let origin = u.origin().ascii_serialization();
                (format!("{origin}{}", u.path()), u.path().to_owned())
            })
            .filter(|(url, _)| url.len() <= MAX_AUDIT_URL)
            .unwrap_or_else(|| ("invalid".to_owned(), "invalid".to_owned()));
        Self {
            method,
            url,
            path,
            status: None,
            response_bytes: 0,
            redactions: 0,
            aborted: None,
            started: false,
        }
    }
}

/// Make the call and record its result. A call that finds the agent or the
/// broker at its limit of calls in flight is refused (429) before anything
/// is sent, and recorded like any other refused call. If the result entry cannot be
/// written, the agent gets an internal error instead of the response; the end of a
/// call that was stopped has no response to hold back, and waits for the log. A
/// call whose pre-flight entry could not be written was never sent and gets
/// no result entry either.
async fn audited_call(
    state: AppState,
    agent: AgentName,
    grant_id: Id,
    grant: ApiGrant,
    req: ProxyRequest,
) -> Result<ProxyResponse, Failure> {
    let mut record = CallRecord::new(&req);
    // The slot lives in this task, which runs to the end whether or not the
    // agent stays connected, and is released on every way out of it.
    // The call is listed with the method and path the audit records; a URL
    // that does not parse or is too long is listed as `invalid`, and one
    // that does not parse is refused by `call`.
    let info = CallInfo::new(
        grant_id.clone(),
        record.method.clone(),
        record.path.clone(),
        state.clock.now(),
    );
    let result = match state.requests.proxy_calls().try_acquire(&agent, info) {
        Ok(slot) => call(&state, &agent, &grant_id, &grant, &req, &slot, &mut record).await,
        Err(refused) => Err(Failure::Client(
            StatusCode::TOO_MANY_REQUESTS,
            refused.to_string(),
        )),
    };
    if let Err(Failure::Request(RequestError::Audit(_))) = &result {
        return result;
    }
    // A refusal can quote what the agent sent (a header name of up to 64 KiB), and
    // the agent gets the whole message; the log gets a bounded part of it.
    let outcome = bounded_text(match &result {
        Ok(_) => "ok".to_owned(),
        Err(failure) => failure.outcome(),
    });
    tracing::info!(agent = %agent, grant = %grant_id, url = %record.url, outcome = %outcome, "proxy call");
    let event = AuditEvent::ProxyCall {
        grant_id: grant_id.clone(),
        method: record.method,
        url: record.url,
        status: record.status,
        response_bytes: record.response_bytes,
        redactions: record.redactions,
        outcome,
        aborted: record.aborted,
    };
    if record.aborted.is_some() {
        state.requests.record_stopped_call(event).await;
        return result;
    }
    if !record.started {
        // Refused before it started: nothing was sent, and the count of such
        // entries is bounded, so a failure to write it changes nothing.
        state.requests.record_proxy_refusal(&agent, event).await;
        return result;
    }
    if let Err(e) = state.audit.append(event).await {
        tracing::error!(grant = %grant_id, error = %e, "could not audit a proxy call");
        return Err(Failure::Request(RequestError::Audit(e)));
    }
    result
}

/// Check `req` against the secret's current policy, which must still be
/// the approved one; record that the call starts (or refuse it if that
/// cannot be recorded); send it with the secret, stopping if the grant ends
/// while the call is out; and redact the answer, which is withheld if the grant
/// has ended by then. A stopped call drops what had arrived of the answer
/// unread: the agent gets only the fixed message.
async fn call(
    state: &AppState,
    agent: &AgentName,
    grant_id: &Id,
    grant: &ApiGrant,
    req: &ProxyRequest,
    slot: &CallSlot,
    record: &mut CallRecord,
) -> Result<ProxyResponse, Failure> {
    let (policy, secret) = state
        .backend
        .api_secret_with_value(&grant.secret)
        .await
        .map_err(policy_failure)?;
    if policy.destination_digest() != grant.digest {
        return Err(policy_changed());
    }
    // The grant's scope comes from the broker's own record; every rule of
    // the item then applies to the narrowed policy.
    let scope = ApiScope::try_from(grant).map_err(|e| {
        tracing::error!(grant = %grant_id, error = %e, "stored API grant is unusable");
        Failure::Request(RequestError::Internal("stored grant is unusable"))
    })?;
    let policy = policy.narrowed(&scope);
    let limits = state.config.proxy;
    let prepared = proxy::check(&policy, req, limits.max_request_bytes)
        .map_err(|refusal| Failure::Client(StatusCode::BAD_REQUEST, refusal.to_string()))?;
    let needles = Needles::new(secret.expose(), &policy.format.render(secret.expose()));
    // The budget is taken once the call is known to be sendable, so refused calls
    // leave it whole, and just before the start is recorded.
    let kind = DailyUse::ProxyCall {
        secret: grant.secret.clone(),
    };
    if !state.requests.take_daily_use(grant_id, &kind).await? {
        state
            .requests
            .daily_limit_reached(agent, grant_id, &kind)
            .await;
        return Err(Failure::Client(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "this grant made {} calls today, its limit; calls fail until 00:00 UTC, \
                 and the owner was told",
                state.requests.daily_limit(&kind)
            ),
        ));
    }
    let started = AuditEvent::ProxyCallStarted {
        grant_id: grant_id.clone(),
        method: record.method.clone(),
        url: record.url.clone(),
    };
    if let Err(e) = state.audit.append(started).await {
        tracing::error!(grant = %grant_id, error = %e, "could not audit a proxy call start; not sending it");
        return Err(Failure::Request(RequestError::Audit(e)));
    }
    record.started = true;
    // Writing the log can take long, and a revocation does not wait for it: the
    // grant may have ended meanwhile, and then nothing goes out.
    usable_api_grant(state, agent, grant_id).await?;
    // Whichever finishes first: the other is dropped, and dropping the call
    // closes its connection to the upstream. The end comes first so that a call
    // told to stop never goes on to use an answer that arrived at that moment.
    let forwarded = tokio::select! {
        biased;
        end = call_ended(state, agent, grant_id, slot) => Err(end),
        result = proxy::forward(&policy, &secret, prepared, &limits, slot.progress()) => Ok(result),
    };
    drop(secret);
    let upstream = match forwarded {
        Ok(result) => result.map_err(|e| Failure::Client(e.status(), e.to_string()))?,
        Err(end) => {
            tracing::warn!(grant = %grant_id, reason = end.message(), "proxied call stopped");
            record.status = slot.progress().status();
            record.response_bytes = slot.progress().bytes();
            record.aborted = Some(end);
            return Err(end.into());
        }
    };
    record.status = Some(upstream.status.as_u16());
    record.response_bytes = u64::try_from(upstream.body.len()).unwrap_or(u64::MAX);
    // Redaction scans every needle over up to 1 MiB, then the result is
    // base64 encoded: both run off the async workers. The needles are
    // moved in and wiped when the work ends.
    let response = off_runtime(move || proxy::redact_response(&upstream, &needles)).await?;
    // Checked last, redaction included: a grant that has ended gets nothing.
    if let Some(end) = grant_end(state, agent, grant_id).await? {
        return Err(end.into());
    }
    record.redactions = response.redactions;
    Ok(response)
}

/// Whether grant `id` has ended, for a call already under way on it. A grant
/// that is gone counts as revoked.
async fn grant_end(
    state: &AppState,
    agent: &AgentName,
    id: &Id,
) -> Result<Option<CallEnd>, Failure> {
    match api_grant_status(state, agent, id).await {
        Ok(Ok(_)) => Ok(None),
        Ok(Err(Unusable::Expired)) => Ok(Some(CallEnd::Expired)),
        Ok(Err(Unusable::Revoked | Unusable::NotApi))
        | Err(Failure::Request(RequestError::NotFound)) => Ok(Some(CallEnd::Revoked)),
        Err(other) => Err(other),
    }
}

/// Resolves once a call on the grant must stop: at once when this broker
/// revokes the grant or its agent, and otherwise when a periodic check finds the
/// grant ended (revoked by another process, or past its window) or unreadable.
async fn call_ended(
    state: &AppState,
    agent: &AgentName,
    grant_id: &Id,
    slot: &CallSlot,
) -> CallEnd {
    let checked = proxy::until_grant_ends(GrantChecks::default(), || async {
        match grant_end(state, agent, grant_id).await {
            Ok(None) => GrantState::Usable,
            Ok(Some(end)) => GrantState::Ended(end),
            Err(failure) => {
                tracing::warn!(grant = %grant_id, error = %failure.outcome(), "checking the grant of a call in flight failed");
                GrantState::Unreadable
            }
        }
    });
    tokio::select! {
        end = slot.ended() => end,
        end = checked => end,
    }
}

/// A failed policy or secret lookup at call time: an outage is a 503 with
/// the fixed message; a secret that is gone or no longer valid means the
/// approved policy no longer holds.
fn policy_failure(e: PolicyError) -> Failure {
    match e {
        PolicyError::Unavailable(detail) => Failure::Request(RequestError::Unavailable(detail)),
        other => {
            tracing::warn!(error = %other, "API secret unusable at call time");
            policy_changed()
        }
    }
}

fn policy_changed() -> Failure {
    Failure::Client(StatusCode::CONFLICT, POLICY_CHANGED.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(url: &str) -> CallRecord {
        CallRecord::new(&ProxyRequest {
            method: "GET".to_owned(),
            url: url.to_owned(),
            headers: Vec::new(),
            body_b64: None,
        })
    }

    #[test]
    fn records_origin_and_path_without_userinfo_query_or_fragment() {
        let r = record("https://u:p@api.example.com/v1/x?token=secret#frag");
        assert_eq!(r.url, "https://api.example.com/v1/x");
        assert_eq!(r.path, "/v1/x");
        let r = record("not a url");
        assert_eq!((r.url.as_str(), r.path.as_str()), ("invalid", "invalid"));
    }

    #[test]
    fn overlong_url_is_recorded_and_listed_as_invalid() {
        let origin = "https://api.example.com";
        let fits = format!("/{}", "a".repeat(MAX_AUDIT_URL - origin.len() - 1));
        let r = record(&format!("{origin}{fits}"));
        assert_eq!(r.url.len(), MAX_AUDIT_URL);
        assert_eq!(r.path, fits);
        let r = record(&format!("{origin}{fits}a"));
        assert_eq!((r.url.as_str(), r.path.as_str()), ("invalid", "invalid"));
    }
}
