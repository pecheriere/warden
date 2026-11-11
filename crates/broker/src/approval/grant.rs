//! The grant that approving a request gives: valid from the moment of approval for the
//! window the owner chose, and bound to the destination the owner was shown.

use axum::http::StatusCode;
use axum::response::Response;
use ssh_key::PublicKey;
use warden_broker_proto::{
    Access, CreateRequest, GrantAccess, GrantView, Id, RelayGrant, SshGrant, Window,
};

use super::{
    AppState, RELAY_NOT_CONFIGURED, api_scope, backend_unavailable, internal, json_error, release,
};
use crate::policy::{ApiSecretPolicy, CaKey, SshMode, SshTarget};
use crate::relay::RelayEndpoint;
use crate::requests::{Destination, PendingView};
use crate::ssh_ca::{self, IssueInput};

/// The grant that approving `view` with `window` at `now` gives, for the destination it
/// is bound to; the response that refuses the approval, if it cannot be built. The
/// response is boxed because it is large.
pub(super) async fn build_grant(
    state: &AppState,
    view: &PendingView,
    window: Window,
    now: i64,
) -> Result<GrantView, Box<Response>> {
    let relay = state.requests.relay();
    Ok(match &view.destination {
        Destination::Ssh(target) if target.mode == SshMode::Relay => {
            // `check_policy` already refused a relay target without a relay.
            let Some(relay) = relay else {
                return Err(Box::new(json_error(
                    StatusCode::CONFLICT,
                    RELAY_NOT_CONFIGURED,
                )));
            };
            match relay_grant(view, relay, window, now) {
                Ok(grant) => grant,
                Err((context, cause)) => return Err(Box::new(internal(context, &cause))),
            }
        }
        Destination::Ssh(target) => {
            let ca = match state.backend.ssh_ca().await {
                Ok(ca) => ca,
                Err(e) => return Err(Box::new(backend_unavailable(&e))),
            };
            match ssh_grant(view, target, &ca, window, now) {
                Ok(grant) => grant,
                Err((context, cause)) => return Err(Box::new(internal(context, &cause))),
            }
        }
        Destination::Api(policy) => match api_grant(&view.request, policy, window, now) {
            Ok(grant) => grant,
            Err((context, cause)) => return Err(Box::new(internal(context, &cause))),
        },
        Destination::CommitSigning(policy) => match validity(window, now) {
            Ok((not_before, not_after)) => GrantView {
                grant_id: Id::random(),
                not_before,
                not_after,
                access: GrantAccess::CommitSigning(policy.grant()),
            },
            Err((context, cause)) => return Err(Box::new(internal(context, &cause))),
        },
        Destination::GithubToken(policy) => match validity(window, now) {
            Ok((not_before, not_after)) => GrantView {
                grant_id: Id::random(),
                not_before,
                not_after,
                access: GrantAccess::GithubToken(policy.grant()),
            },
            Err((context, cause)) => return Err(Box::new(internal(context, &cause))),
        },
        Destination::Release(policy) => match release::grant(view, policy, window, now) {
            Ok(grant) => grant,
            Err((context, cause)) => return Err(Box::new(internal(context, &cause))),
        },
    })
}

/// A failed grant-building step and its cause.
pub(super) type GrantFailure = (&'static str, String);

/// Validity of a grant approved at `now` for `window`: `(now, now + window)`.
pub(super) fn validity(window: Window, now: i64) -> Result<(i64, i64), GrantFailure> {
    let length = i64::try_from(window.secs()).map_err(|e| ("window length", e.to_string()))?;
    let not_after = now
        .checked_add(length)
        .ok_or(("grant expiry", "time overflow".to_owned()))?;
    Ok((now, not_after))
}

/// The grant for approving `view` on SSH `target` with `window` at `now`:
/// valid from `now` for exactly the window, with a certificate signed by
/// `ca`. Errors name the failed step and its cause.
fn ssh_grant(
    view: &PendingView,
    target: &SshTarget,
    ca: &CaKey,
    window: Window,
    now: i64,
) -> Result<GrantView, GrantFailure> {
    let Access::Ssh {
        target: target_name,
        user,
        public_key,
    } = &view.request.access
    else {
        return Err(("access kind", "not an ssh request".to_owned()));
    };
    let public_key =
        PublicKey::from_openssh(public_key).map_err(|e| ("stored public key", e.to_string()))?;
    let (not_before, not_after) = validity(window, now)?;
    let grant_id = Id::random();
    let cert = ssh_ca::issue(
        ca,
        &IssueInput {
            agent: &view.agent,
            grant_id: &grant_id,
            target: target_name,
            user,
            public_key: &public_key,
            now,
            not_after,
        },
    )
    .map_err(|e| ("certificate issuance", e.to_string()))?;
    let certificate = cert
        .to_openssh()
        .map_err(|e| ("certificate encoding", e.to_string()))?;
    let host_keys = target
        .host_keys
        .iter()
        .map(PublicKey::to_openssh)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ("host key encoding", e.to_string()))?;
    Ok(GrantView {
        grant_id,
        not_before,
        not_after,
        access: GrantAccess::Ssh(SshGrant {
            certificate,
            host: target.host.clone(),
            port: target.port,
            user: user.clone(),
            host_keys,
        }),
    })
}

/// The grant for approving `view` on a relay target with `window` at `now`:
/// valid from `now` for exactly the window, naming where the agent reaches
/// `relay` and its host key, and carrying the digest of the approved
/// destination, which the relay checks at every session start. There is no
/// certificate: the relay admits the agent by the public key bound into the
/// approved request.
fn relay_grant(
    view: &PendingView,
    relay: &RelayEndpoint,
    window: Window,
    now: i64,
) -> Result<GrantView, GrantFailure> {
    let Access::Ssh { target, user, .. } = &view.request.access else {
        return Err(("access kind", "not an ssh request".to_owned()));
    };
    let (not_before, not_after) = validity(window, now)?;
    Ok(GrantView {
        grant_id: Id::random(),
        not_before,
        not_after,
        access: GrantAccess::Relay(RelayGrant {
            target: target.clone(),
            user: user.clone(),
            relay_host: relay.host.clone(),
            relay_port: relay.port,
            relay_host_key: relay.host_key.clone(),
            digest: view.destination.digest(),
        }),
    })
}

/// The grant for approving `request` for API secret `policy` with `window`
/// at `now`: valid from `now` for exactly the window, limited to the scope
/// the request asked for. It names where the broker will send the secret;
/// the secret itself is never part of it.
fn api_grant(
    request: &CreateRequest,
    policy: &ApiSecretPolicy,
    window: Window,
    now: i64,
) -> Result<GrantView, GrantFailure> {
    let scope = api_scope(request, policy).map_err(|e| ("API scope", e))?;
    let (not_before, not_after) = validity(window, now)?;
    Ok(GrantView {
        grant_id: Id::random(),
        not_before,
        not_after,
        access: GrantAccess::Api(policy.grant_for(&scope)),
    })
}
