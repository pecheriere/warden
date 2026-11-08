//! The commands that use what is set up here: `warden ssh`, `warden http`,
//! `warden status`, `warden revoke` and `warden setup git`.

use anyhow::{Context as _, Result};
use warden_broker_proto::{Id, SecretName, TargetName};

use crate::client::CallError;
use crate::{
    EXIT_CALL_STOPPED, EXIT_HTTP_FAIL, EXIT_NO_GRANT, EXIT_REVOKED, Exit, agent, client, guidance,
    http, local_time, recover, setup_git, ssh, unix_now,
};

pub(crate) async fn run_setup_git(local: bool) -> Result<()> {
    let (_, client) = client()?;
    let scope = if local {
        setup_git::Scope::Local
    } else {
        setup_git::Scope::Global
    };
    setup_git::run(&client, scope).await
}

pub(crate) fn run_ssh(target: &TargetName, command: &[String]) -> Result<()> {
    let grants = agent::grants_dir()?;
    let Some(grant) = ssh::active_grant(&grants, target, unix_now()) else {
        return Err(Exit::new(EXIT_NO_GRANT, guidance::no_ssh_grant(target)).into());
    };
    let args = ssh::ssh_args(&grant, command)?;
    Err(ssh::exec(&args)).context("cannot run ssh")
}

/// Everything `warden http` was asked to send.
pub(crate) struct HttpCall {
    pub(crate) secret: SecretName,
    pub(crate) method: String,
    pub(crate) url: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) data: Option<String>,
    pub(crate) data_file: Option<String>,
}

pub(crate) async fn run_http(call: HttpCall, include: bool, fail: bool) -> Result<()> {
    let secret = &call.secret;
    let active = http::active(secret, unix_now())?;
    if active.is_empty() {
        return Err(Exit::new(EXIT_NO_GRANT, guidance::no_api_grant(secret)).into());
    }
    let body = http::read_body(call.data.as_deref(), call.data_file.as_deref())?;
    let proxy = http::proxy_request(&call.method, &call.url, call.headers, body.as_deref())?;
    let path = url::Url::parse(&proxy.url)
        .context("the broker request holds an invalid URL")?
        .path()
        .to_owned();
    let Some(grant) = http::covering(&active, &proxy.method, &path) else {
        return Err(Exit::new(
            EXIT_NO_GRANT,
            http::no_covering_message(secret, &proxy.method, &path),
        )
        .into());
    };
    let (_, client) = client()?;
    let resp = match client.proxy(&grant.grant_id, &proxy).await {
        Ok(resp) => resp,
        Err(CallError::Revoked(message)) => {
            // The owner ended it elsewhere: the local record is dead weight.
            http::discard(&grant.grant_id)?;
            return Err(Exit::new(
                EXIT_REVOKED,
                guidance::api_grant_revoked(&grant.grant_id, secret, &message),
            )
            .into());
        }
        Err(CallError::Expired(message)) => {
            // The local clock thought it live: the record is dead weight.
            http::discard(&grant.grant_id)?;
            return Err(Exit::new(
                EXIT_NO_GRANT,
                guidance::api_grant_expired(&grant.grant_id, secret, &message),
            )
            .into());
        }
        Err(CallError::CallStopped(message)) => {
            // The grant may well still be good: its record stays.
            return Err(Exit::new(
                EXIT_CALL_STOPPED,
                guidance::api_call_stopped(&grant.grant_id, secret, &message),
            )
            .into());
        }
        Err(e) => return Err(e.into()),
    };
    let reply = http::decode(&resp)?;
    http::emit(
        &reply,
        include,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )?;
    if fail && reply.status >= 400 {
        return Err(Exit::new(
            EXIT_HTTP_FAIL,
            format!("the server answered with status {}", reply.status),
        )
        .into());
    }
    Ok(())
}

pub(crate) async fn status() -> Result<()> {
    let grants = agent::grants_dir()?;
    println!("local grants:");
    for (dir, record) in agent::load_grants(&grants) {
        match record {
            Ok(r) => println!(
                "  {}  {}  grant {}  until {}",
                r.target,
                local_subject(&r),
                r.grant_id,
                local_time(r.not_after)
            ),
            Err(e) => println!("  {}: {e:#}", dir.display()),
        }
    }
    println!("local api grants:");
    for (path, record) in http::load()? {
        match record {
            Ok(r) => println!("{}", recover::api_record_line(&r)),
            Err(e) => println!("  {}: {e:#}", path.display()),
        }
    }
    let local = recover::local_grant_ids()?;
    let (_, client) = client()?;
    println!("broker grants:");
    for g in client.grants().await? {
        println!("{}", recover::broker_grant_line(&g, &local));
    }
    recover::print_pending(&client).await
}

/// How `status` shows where a local grant connects.
fn local_subject(record: &agent::GrantRecord) -> String {
    let (user, host, port) = (&record.user, &record.host, record.port);
    match record.route {
        agent::Route::Direct => format!("{user}@{host}:{port}"),
        agent::Route::Relay => format!("{user} via relay {host}:{port}"),
    }
}

pub(crate) async fn revoke(grant: &Id) -> Result<()> {
    // Stop the local agent first: the grant is unusable here whatever the
    // broker answers.
    let local = agent::discard_grant(grant)? | http::discard(grant)?;
    let (_, client) = client()?;
    client.revoke(grant).await?;
    eprintln!(
        "revoked grant {grant}{}",
        if local {
            " and removed its local state"
        } else {
            ""
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use warden_broker_proto::Id;

    use super::local_subject;
    use crate::agent::{GrantRecord, Route};

    #[test]
    fn status_says_when_a_grant_goes_through_the_relay() {
        let mut record = GrantRecord {
            grant_id: Id::random(),
            target: "nas".parse().unwrap(),
            route: Route::Relay,
            host: "relay.example.com".to_owned(),
            port: 2222,
            user: "backup".parse().unwrap(),
            not_after: 1,
            socket: PathBuf::from("/tmp/s.sock"),
            pid: 1,
        };
        assert_eq!(
            local_subject(&record),
            "backup via relay relay.example.com:2222"
        );
        record.route = Route::Direct;
        assert_eq!(local_subject(&record), "backup@relay.example.com:2222");
    }
}
