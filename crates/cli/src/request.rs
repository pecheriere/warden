//! `warden request`: ask the owner for access, wait for the decision and
//! take the grant, or withdraw a pending request.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use warden_broker_proto::doctor::sanitize;
use warden_broker_proto::{
    Access, ApiGrant, CreateRequest, Goal, GrantAccess, GrantView, Id, RequestStatus, SecretName,
    SessionLabel, SessionLink, TargetName, UnixUser, Window, is_read_only, modifying_methods,
    under_prefix,
};

use crate::client::{CallError, Client, MAX_WAIT_SECS};
use crate::config::Config;
use crate::install::install_grant;
use crate::request_context::{self, Answered, RequestContext, compare};
use crate::{
    EXIT_CANCELLED, EXIT_DENIED, EXIT_ERROR, EXIT_EXPIRED, EXIT_INTERRUPTED, EXIT_REVOKED,
    EXIT_USAGE, Exit, client, guidance, http, local_time, unix_now,
};

/// How long Ctrl-C waits for the broker to confirm the cancellation of the
/// request being waited for.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `warden request` waits for a decision (pending requests expire
/// on the server after 10 minutes).
const DECISION_TIMEOUT: Duration = Duration::from_mins(11);

/// How long the broker keeps a request pending, in seconds.
pub(crate) const PENDING_EXPIRY_SECS: i64 = 600;

/// First pause before retrying an unavailable broker.
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Longest pause between retries.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(15);

/// The exit code for a request that reached `status`, or `None` while it is
/// still pending.
pub(crate) fn terminal_exit_code(status: &RequestStatus) -> Option<u8> {
    match status {
        RequestStatus::Pending => None,
        RequestStatus::Approved(_) => Some(0),
        RequestStatus::Denied => Some(EXIT_DENIED),
        RequestStatus::Expired => Some(EXIT_EXPIRED),
        RequestStatus::Cancelled => Some(EXIT_CANCELLED),
        RequestStatus::Revoked => Some(EXIT_REVOKED),
        RequestStatus::Error { .. } => Some(EXIT_ERROR),
    }
}

pub(crate) async fn cancel(id: &Id) -> Result<()> {
    let (_, client) = client()?;
    client.cancel(id).await?;
    println!("cancelled: request {id}");
    Ok(())
}

/// The label and link to send; wrong ones are a usage error, before anything
/// else happens.
fn resolve_context(context: RequestContext) -> Result<(Option<SessionLabel>, Option<SessionLink>)> {
    context
        .resolve(std::env::var_os(request_context::SESSION_ENV))
        .map_err(|message| Exit::new(EXIT_USAGE, message).into())
}

pub(crate) async fn request_ssh(
    target: TargetName,
    user: UnixUser,
    window: Window,
    goal: Goal,
    context: RequestContext,
) -> Result<()> {
    let (session, link) = resolve_context(context)?;
    let (config, client) = client()?;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| anyhow!("cannot generate a key: {e}"))?;
    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow!("cannot encode the public key: {e}"))?;
    let req = CreateRequest {
        goal,
        access: Access::Ssh {
            target: target.clone(),
            user: user.clone(),
            public_key,
        },
        window,
        session,
        link,
    };
    let grant = request_grant(&config, &client, &req, &format!("for {target}")).await?;
    install_grant(&target, &user, &key, &grant).await?;
    announce(&grant);
    Ok(())
}

pub(crate) async fn request_api(
    secret: SecretName,
    methods: Option<Vec<String>>,
    path: Option<String>,
    window: Window,
    goal: Goal,
    context: RequestContext,
) -> Result<()> {
    let (session, link) = resolve_context(context)?;
    let (config, client) = client()?;
    let methods: Option<Vec<String>> = methods.map(|m| {
        m.iter()
            .map(|method| method.trim().to_ascii_uppercase())
            .collect()
    });
    let req = CreateRequest {
        goal,
        access: Access::Api {
            secret: secret.clone(),
            methods: methods.clone(),
            path_prefix: path.clone(),
        },
        window,
        session,
        link,
    };
    let grant = request_grant(&config, &client, &req, &format!("for api secret {secret}")).await?;
    let GrantAccess::Api(api) = &grant.access else {
        bail!("the broker returned a non-api grant for an api request");
    };
    ensure!(
        api.secret == secret,
        "the grant is for secret {}, not {secret}",
        api.secret
    );
    ensure!(grant.not_after > unix_now(), "the grant has already ended");
    if let Err(problem) = check_scope_not_wider(api, methods.as_deref(), path.as_deref()) {
        bail!(
            "the broker granted a wider scope than requested ({problem}); upgrade the broker \
             to 0.4 or later. Grant {} was not recorded here; revoke it with `warden revoke {}`",
            grant.grant_id,
            grant.grant_id
        );
    }
    http::save(&http::ApiRecord::new(
        grant.grant_id.clone(),
        api,
        grant.not_after,
    ))?;
    announce(&grant);
    println!("{}", api_scope(api));
    Ok(())
}

pub(crate) async fn request_signing(
    window: Window,
    goal: Goal,
    context: RequestContext,
) -> Result<()> {
    let (session, link) = resolve_context(context)?;
    let (config, client) = client()?;
    let req = CreateRequest {
        goal,
        access: Access::CommitSigning {},
        window,
        session,
        link,
    };
    let grant = request_grant(&config, &client, &req, "for commit signing").await?;
    let GrantAccess::CommitSigning(signing) = &grant.access else {
        bail!("the broker returned another kind of grant for a commit signing request");
    };
    announce(&grant);
    println!(
        "commits are signed with key {} until then. Set git up with `warden setup git` if it \
         is not yet set up.",
        signing.key_fingerprint
    );
    Ok(())
}

/// Whether `api` is inside what was asked for. A broker older than 0.4
/// ignores `--methods` and `--path` and grants the whole item, so the CLI
/// must not record such a grant as if it were narrow. Without `methods` the
/// request means read-only; without `path` any prefix the broker picks is
/// its own to choose.
///
/// # Errors
/// What is wider, for the message.
fn check_scope_not_wider(
    api: &ApiGrant,
    methods: Option<&[String]>,
    path: Option<&str>,
) -> Result<(), String> {
    let extra: Vec<&str> = match methods {
        Some(requested) => api
            .methods
            .iter()
            .map(String::as_str)
            .filter(|m| !requested.iter().any(|r| r == m))
            .collect(),
        None if is_read_only(&api.methods) => Vec::new(),
        None => modifying_methods(&api.methods),
    };
    if !extra.is_empty() {
        return Err(format!("methods {}", extra.join(", ")));
    }
    if let Some(wanted) = path
        && !under_prefix(&api.path_prefix, wanted)
    {
        return Err(format!("path {} is not under {wanted}", api.path_prefix));
    }
    Ok(())
}

/// The scope of `api` for the owner-facing line after approval: whether it
/// can modify anything, the methods and where it applies. These come from the
/// broker as plain strings, so the line is made safe to print.
pub(crate) fn api_scope(api: &ApiGrant) -> String {
    let access = if is_read_only(&api.methods) {
        "read-only".to_owned()
    } else {
        format!("can modify: {}", modifying_methods(&api.methods).join(", "))
    };
    sanitize(&format!(
        "scope: {access}; methods {}; {}{}",
        api.methods.join(", "),
        api.origin,
        api.path_prefix
    ))
}

pub(crate) fn announce(grant: &GrantView) {
    println!(
        "approved: grant {} until {}",
        grant.grant_id,
        local_time(grant.not_after)
    );
}

/// Create `req`, wait for the owner's decision and return the approved
/// grant. `subject` completes "a request …" in messages. Denied, expired,
/// revoked, cancelled and failed requests end the process with their own exit
/// codes. Ctrl-C while waiting cancels the request (best effort, for at most
/// [`CANCEL_TIMEOUT`]) and exits 130; a second Ctrl-C during that, or a
/// Ctrl-C once the grant is returned (while the caller installs it), exits
/// 130 at once.
async fn request_grant(
    config: &Config,
    client: &Client,
    req: &CreateRequest,
    subject: &str,
) -> Result<GrantView> {
    // Registered before anything is sent, so Ctrl-C is never lost.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("cannot listen for Ctrl-C")?;
    let create = client.create(req);
    tokio::pin!(create);
    let created = tokio::select! {
        created = &mut create => Some(created?),
        _ = interrupt.recv() => None,
    };
    let Some(created) = created else {
        exit_on_interrupt(
            interrupt,
            "interrupted again; the request may have been made: check `warden status` and revoke any grant it shows"
                .to_owned(),
        );
        eprintln!("warden: interrupted; withdrawing the request (Ctrl-C again to stop at once)…");
        // The request may be made already: give the broker's answer a
        // moment, then withdraw what it made.
        let exit = match tokio::time::timeout(CANCEL_TIMEOUT, &mut create).await {
            Ok(Ok(created)) => withdraw_after_interrupt(client, &created.id).await,
            Ok(Err(_)) | Err(_) => Exit::new(
                EXIT_INTERRUPTED,
                "interrupted; the request may have been made; it expires unanswered on the broker",
            ),
        };
        return Err(exit.into());
    };
    match compare(&created.fingerprint, &config.agent, req) {
        Answered::Same => {}
        // The access is the same and only what this CLI added is missing. The
        // owner sees the request as its fingerprint says, so waiting on it is safe.
        Answered::WithoutContext => eprintln!("warden: {}", guidance::CONTEXT_NOT_SHOWN),
        // Approving it might not grant what was asked here.
        Answered::Other => bail!(guidance::already_pending(subject, &created)),
    }
    eprintln!(
        "request {}, fingerprint {} ({}) — waiting for approval…",
        created.id,
        created.fingerprint.words(),
        created.fingerprint
    );

    let created_at = unix_now();
    let deadline = Instant::now() + DECISION_TIMEOUT;
    let poll = || client.status(&created.id, MAX_WAIT_SECS);
    let waited = tokio::select! {
        waited = wait_for_decision(poll, deadline, FIRST_RETRY_DELAY) => Some(waited),
        _ = interrupt.recv() => None,
    };
    let Some(waited) = waited else {
        exit_on_interrupt(
            interrupt,
            format!(
                "interrupted again; request {} may still be pending or approved: check \
                 `warden status` and revoke any grant",
                created.id
            ),
        );
        eprintln!(
            "warden: interrupted; withdrawing request {} (Ctrl-C again to stop at once)…",
            created.id
        );
        return Err(withdraw_after_interrupt(client, &created.id).await.into());
    };
    let status = match waited {
        Ok(status) => status,
        Err(reason) => bail!(
            "{reason}; request {} may still be pending on the broker, where it expires \
             unanswered at about {}",
            created.id,
            local_time(created_at.saturating_add(PENDING_EXPIRY_SECS))
        ),
    };
    match status {
        RequestStatus::Approved(grant) => {
            exit_on_interrupt(
                interrupt,
                format!(
                    "interrupted while installing grant {0}; revoke it with `warden revoke {0}` \
                     if it is not wanted",
                    grant.grant_id
                ),
            );
            Ok(grant)
        }
        RequestStatus::Error { message } => {
            Err(Exit::new(EXIT_ERROR, format!("request failed: {message}")).into())
        }
        other => {
            let code = terminal_exit_code(&other).unwrap_or(EXIT_ERROR);
            Err(Exit::new(code, guidance::request_ended(&other)).into())
        }
    }
}

/// From now on, end the process at once on Ctrl-C: print `message` and exit
/// 130. Used once Ctrl-C has started a withdrawal (a second one skips the
/// wait) and once a grant is being installed (nothing is left to withdraw).
/// The exit skips destructors on purpose: it is the user's way out of a
/// wait, as the default Ctrl-C handling would be.
fn exit_on_interrupt(mut interrupt: tokio::signal::unix::Signal, message: String) {
    tokio::spawn(async move {
        if interrupt.recv().await.is_some() {
            eprintln!("warden: {message}");
            std::process::exit(i32::from(EXIT_INTERRUPTED));
        }
    });
}

/// Withdraw request `id` after Ctrl-C and say what came of it, within
/// [`CANCEL_TIMEOUT`]. The exit is the same either way; a request that could
/// not be cancelled is left to expire on its own, except one the owner
/// approved first, whose grant is revoked.
async fn withdraw_after_interrupt(client: &Client, id: &Id) -> Exit {
    let message = tokio::time::timeout(CANCEL_TIMEOUT, cancel_or_revoke(client, id))
        .await
        .unwrap_or_else(|_| {
            format!(
                "interrupted; withdrawing request {id} timed out; its outcome is unknown: check `warden status` and revoke any grant"
            )
        });
    Exit::new(EXIT_INTERRUPTED, message)
}

/// Cancel request `id`. If the broker refuses because it was decided in the
/// meantime, look at how: an approval has produced a grant nobody will use,
/// which is revoked.
async fn cancel_or_revoke(client: &Client, id: &Id) -> String {
    let refused = match client.cancel(id).await {
        Ok(()) => return format!("interrupted; request {id} cancelled"),
        Err(e @ CallError::Unavailable(_)) => {
            return format!(
                "interrupted; could not cancel request {id} ({e}); it expires unanswered on the broker"
            );
        }
        Err(e) => e,
    };
    match client.status(id, 0).await {
        Ok(RequestStatus::Approved(grant)) => match client.revoke(&grant.grant_id).await {
            Ok(()) => format!(
                "interrupted; request {id} was approved before it could be cancelled; grant {} revoked",
                grant.grant_id
            ),
            Err(e) => format!(
                "interrupted; request {id} was approved before it could be cancelled; could not revoke grant {} ({e})",
                grant.grant_id
            ),
        },
        Ok(other) => format!(
            "interrupted; request {id} was already {}; nothing to cancel",
            status_word(&other)
        ),
        Err(_) => format!(
            "interrupted; could not cancel request {id} ({refused}); it expires unanswered on the broker"
        ),
    }
}

/// The word for a terminal or pending `status` in messages.
pub(crate) const fn status_word(status: &RequestStatus) -> &'static str {
    match status {
        RequestStatus::Pending => "pending",
        RequestStatus::Approved(_) => "approved",
        RequestStatus::Denied => "denied",
        RequestStatus::Expired => "expired",
        RequestStatus::Cancelled => "cancelled",
        RequestStatus::Revoked => "revoked",
        RequestStatus::Error { .. } => "failed",
    }
}

/// Long-poll until the request reaches a terminal status. Transport errors
/// and 5xx answers are retried with exponential backoff (from `first_delay`,
/// doubling, at most [`MAX_RETRY_DELAY`]) until `deadline`, with one note on
/// stderr per failure. Returns why it gave up: a refusal (4xx) or the
/// deadline.
async fn wait_for_decision<F, Fut>(
    mut poll: F,
    deadline: Instant,
    first_delay: Duration,
) -> Result<RequestStatus, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<RequestStatus, CallError>>,
{
    let mut delay = first_delay;
    loop {
        let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return Err(format!(
                "no decision within {} minutes",
                DECISION_TIMEOUT.as_secs() / 60
            ));
        };
        match poll().await {
            Ok(status) if terminal_exit_code(&status).is_some() => return Ok(status),
            Ok(_) => delay = first_delay,
            Err(
                CallError::Refused(message)
                | CallError::Revoked(message)
                | CallError::Expired(message)
                | CallError::CallStopped(message),
            ) => return Err(message),
            Err(CallError::Unavailable(message)) => {
                let pause = delay.min(left);
                eprintln!("warden: {message}; retrying in {} ms", pause.as_millis());
                tokio::time::sleep(pause).await;
                delay = next_retry_delay(delay);
            }
        }
    }
}

/// The delay after `delay`: doubled, at most [`MAX_RETRY_DELAY`].
fn next_retry_delay(delay: Duration) -> Duration {
    delay.saturating_mul(2).min(MAX_RETRY_DELAY)
}

#[cfg(test)]
mod tests;
