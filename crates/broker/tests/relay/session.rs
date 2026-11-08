//! Sessions that work: shell and exec, window changes and signals, exit
//! status, refused forwarding and subsystems, and what is audited.

use std::process::Stdio;
use std::time::Duration;

use russh::Sig;
use serde_json::Value;
use warden_broker::testkit::sshd::current_user;

#[cfg(target_os = "linux")]
use super::password_target;
use super::{
    OpenSsh, TARGET, approved_agent, await_events, collect, key_target, login, reply,
    reply_keeping_stderr, sshd_connections, text,
};

#[tokio::test(flavor = "multi_thread")]
async fn relay_works_with_key_target() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);

    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ok\n");

    // stdin reaches the target and its EOF ends `cat`; stderr comes back.
    let out = ssh
        .run_as(TARGET, &[], &["cat; echo done >&2"], b"hello relay\n")
        .await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "hello relay\n");
    assert!(text(&out.stderr).contains("done"), "{}", text(&out.stderr));

    // An interactive shell on a pty.
    let out = ssh
        .run_as(TARGET, &["-tt"], &[], b"echo shell-$((40+2)); exit 3\n")
        .await;
    assert!(
        text(&out.stdout).contains("shell-42"),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(out.status.code(), Some(3), "stderr: {}", text(&out.stderr));

    // Only LANG, LC_* and TERM are passed on.
    let out = ssh
        .run_as(
            TARGET,
            &["-o", "SetEnv=LANG=C LC_TIME=C EVIL=1"],
            &["echo \"${LANG:-unset}/${LC_TIME:-unset}/${EVIL:-unset}\""],
            b"",
        )
        .await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "C/C/unset\n");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn relay_shell_and_exec_work_with_password_target() {
    let (broker, sshd, relay, _password) = password_target().await;
    let agent = approved_agent(&broker, "bot").await;
    let ssh = OpenSsh::new(&broker, relay, &agent.key);

    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ok\n");

    let out = ssh
        .run_as(TARGET, &["-tt"], &[], b"echo shell-$((40+2)); exit 4\n")
        .await;
    assert!(
        text(&out.stdout).contains("shell-42"),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(out.status.code(), Some(4), "stderr: {}", text(&out.stderr));
    assert!(sshd.log().contains("Accepted password"), "{}", sshd.log());
}

#[tokio::test(flavor = "multi_thread")]
async fn window_change_and_signals_are_forwarded() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;

    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(reply(&mut channel).await);
    channel.exec(true, "sleep 2; stty size").await.unwrap();
    assert!(reply(&mut channel).await);
    channel.window_change(132, 50, 0, 0).await.unwrap();
    let out = collect(&mut channel).await;
    assert!(
        text(&out.stdout).contains("50 132"),
        "{}",
        text(&out.stdout)
    );

    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel
        .exec(true, "trap 'echo got-term; exit 9' TERM; sleep 20 & wait")
        .await
        .unwrap();
    assert!(reply(&mut channel).await);
    tokio::time::sleep(Duration::from_millis(500)).await;
    channel.signal(Sig::TERM).await.unwrap();
    let out = collect(&mut channel).await;
    assert!(text(&out.stdout).contains("got-term"), "{out:?}");
    assert_eq!(out.exit_status, Some(9), "{out:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarding_and_subsystems_refused() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;

    // -R: remote port forwarding.
    assert!(c.handle.tcpip_forward("127.0.0.1", 0).await.is_err());
    // -L: a direct-tcpip channel, here aimed at the target itself.
    let direct = c
        .handle
        .channel_open_direct_tcpip("127.0.0.1", u32::from(s.sshd.port()), "127.0.0.1", 40000)
        .await;
    assert!(direct.is_err());

    let mut channel = c.handle.channel_open_session().await.unwrap();
    // One session channel per connection.
    assert!(c.handle.channel_open_session().await.is_err());
    // sftp and any other subsystem, X11 and agent forwarding.
    let mut stderr = Vec::new();
    channel.request_subsystem(true, "sftp").await.unwrap();
    assert!(!reply_keeping_stderr(&mut channel, &mut stderr).await);
    channel
        .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "00", 0)
        .await
        .unwrap();
    assert!(!reply_keeping_stderr(&mut channel, &mut stderr).await);
    channel.agent_forward(true).await.unwrap();
    assert!(!reply_keeping_stderr(&mut channel, &mut stderr).await);

    // The session itself is unaffected.
    channel.exec(true, "echo still-ok").await.unwrap();
    assert!(reply_keeping_stderr(&mut channel, &mut stderr).await);
    let out = collect(&mut channel).await;
    assert_eq!(text(&out.stdout), "still-ok\n");
    assert_eq!(out.exit_status, Some(0));
    stderr.extend_from_slice(&out.stderr);
    let stderr = text(&stderr);
    for notice in [
        "warden relay: port forwarding is not allowed",
        "warden relay: subsystems (such as sftp) are not allowed",
        "warden relay: X11 forwarding is not allowed",
        "warden relay: agent forwarding is not allowed",
    ] {
        assert!(stderr.contains(notice), "{notice}: {stderr}");
    }

    // The OpenSSH client reports a refused sftp subsystem.
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let mut cmd = ssh.command(TARGET, &["-s"], &["sftp"]);
    let out = cmd.stdin(Stdio::null()).output().await.unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("subsystem request failed"),
        "{}",
        text(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn exit_status_propagates() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["exit", "7"]).await;
    assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["exit_status"], 7);
    assert_eq!(ended[0]["reason"], "exited");

    // A command killed by a signal reports the signal.
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "kill -TERM $$").await.unwrap();
    assert!(reply(&mut channel).await);
    let out = collect(&mut channel).await;
    assert!(matches!(out.exit_signal, Some(Sig::TERM)), "{out:?}");
    assert_eq!(out.exit_status, None, "{out:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn session_audited_start_before_bytes_and_end() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);

    // The target reads the audit log itself: the start entry is already
    // there, durably, when the command runs; the end entry is not.
    let audit = s.broker.audit_path().display().to_string();
    let out = ssh
        .run_as(
            TARGET,
            &[],
            &[&format!("cat >/dev/null; cat '{audit}'")],
            b"12345",
        )
        .await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let seen = text(&out.stdout);
    let started: Vec<Value> = seen
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["event"].clone())
        .filter(|e| e["type"] == "relay_session_started")
        .collect();
    assert_eq!(started.len(), 1, "{seen}");
    assert_eq!(started[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(started[0]["target"], TARGET);
    assert_eq!(started[0]["user"], current_user());
    assert_eq!(
        started[0]["command"],
        format!("cat >/dev/null; cat '{audit}'")
    );
    assert!(!seen.contains("relay_session_ended"), "{seen}");

    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(ended[0]["reason"], "exited");
    assert_eq!(ended[0]["exit_status"], 0);
    assert_eq!(ended[0]["bytes_to_target"], 5);
    assert_eq!(
        ended[0]["bytes_from_target"],
        u64::try_from(out.stdout.len() + out.stderr.len()).unwrap()
    );

    // A shell session is audited without a command, and a long command is
    // cut to 200 characters.
    let out = ssh.run_as(TARGET, &["-tt"], &[], b"exit 0\n").await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let long = format!("true {}", "x".repeat(300));
    let out = ssh.run(&[&long]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let started = await_events(&s.broker, "relay_session_started", 3).await;
    assert!(started[1]["command"].is_null());
    let cut = started[2]["command"].as_str().unwrap();
    assert_eq!(cut.chars().count(), 201);
    assert!(cut.ends_with('…'));

    // If the start cannot be recorded, nothing reaches the target.
    let before = sshd_connections(&s.sshd);
    let holder = std::fs::File::open(s.broker.audit_path()).unwrap();
    holder.lock().unwrap();
    let out = ssh.run(&["echo", "unrecorded"]).await;
    holder.unlock().unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert_eq!(out.stdout, [] as [u8; 0]);
    assert!(
        text(&out.stderr).contains("warden relay: the session could not be recorded"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(sshd_connections(&s.sshd), before, "{}", s.sshd.log());
}
