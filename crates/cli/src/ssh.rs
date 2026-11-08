//! `warden ssh`: run OpenSSH through the longest-lived active grant for a target.

use std::ffi::OsString;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, ensure};
use warden_broker_proto::{TargetName, UnixUser};

use crate::agent::{GrantRecord, Route, is_safe_host, load_grants};

/// A grant this machine can use now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveGrant {
    /// The grant's directory.
    pub dir: PathBuf,
    /// Its record.
    pub record: GrantRecord,
}

/// The grant for `target` that is valid at `now`, stays valid longest and whose
/// agent socket exists.
#[must_use]
pub fn active_grant(grants: &Path, target: &TargetName, now: i64) -> Option<ActiveGrant> {
    load_grants(grants)
        .into_iter()
        .filter_map(|(dir, record)| {
            Some(ActiveGrant {
                dir,
                record: record.ok()?,
            })
        })
        .filter(|g| {
            &g.record.target == target && g.record.not_after > now && g.record.socket.exists()
        })
        .max_by_key(|g| g.record.not_after)
}

/// How ssh reaches a target through a grant, checked: what `warden ssh` passes
/// on the command line and `warden ssh-config` writes as a `Host` block, so the
/// two cannot drift apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// Host to connect to: the target's, or the relay's.
    pub host: String,
    /// Port to connect to.
    pub port: u16,
    /// Account to log in as: the grant's user, or the target's name through
    /// the relay.
    pub login: String,
    /// The grant agent's socket.
    pub socket: String,
    /// The grant's pinned `known_hosts`.
    pub known_hosts: String,
    /// Every other option, as `(keyword, value)` with the value already quoted
    /// for ssh. The same text works after `-o keyword=` and in a config file.
    pub options: Vec<(&'static str, String)>,
}

/// The [`Connection`] for `grant`. The grant's agent is the only identity
/// source: `IdentityFile none` keeps ssh from also offering `~/.ssh/id_*`, and
/// `ForwardAgent no` keeps the agent on this machine. Host, port and user come
/// from the server-signed grant and are validated again here. A relay grant
/// connects to the relay's address and logs in as the target's name (the relay
/// then logs in to the target as the user); every other option is the same.
///
/// # Errors
/// If the recorded host, user or target is not safe to pass to ssh, or a path
/// cannot be quoted for it.
pub fn connection(grant: &ActiveGrant) -> Result<Connection> {
    let rec = &grant.record;
    ensure!(
        is_safe_host(&rec.host),
        "grant host {:?} is not a valid host name",
        rec.host
    );
    // Re-validate: grant.json is a local file, not the server's word.
    let user = UnixUser::try_from(rec.user.as_str().to_owned()).context("grant user is invalid")?;
    let login = match rec.route {
        Route::Direct => user.to_string(),
        // A `TargetName` is `[a-z0-9-]` only, checked when grant.json is read.
        Route::Relay => rec.target.to_string(),
    };
    let known_hosts = grant.dir.join("known_hosts");
    let options = vec![
        ("IdentityAgent", quote_path("IdentityAgent", &rec.socket)?),
        ("IdentityFile", "none".to_owned()),
        ("IdentitiesOnly", "no".to_owned()),
        (
            "UserKnownHostsFile",
            quote_path("UserKnownHostsFile", &known_hosts)?,
        ),
        ("StrictHostKeyChecking", "yes".to_owned()),
        ("PasswordAuthentication", "no".to_owned()),
        ("KbdInteractiveAuthentication", "no".to_owned()),
        ("ForwardAgent", "no".to_owned()),
    ];
    Ok(Connection {
        host: rec.host.clone(),
        port: rec.port,
        login,
        socket: utf8("IdentityAgent", &rec.socket)?.to_owned(),
        known_hosts: utf8("UserKnownHostsFile", &known_hosts)?.to_owned(),
        options,
    })
}

/// The arguments for `ssh` (program name excluded): `-F /dev/null` so no
/// config file adds to them, the [`Connection`]'s options, and `--` to end
/// option parsing so the remote `command` can never be read as ssh options.
///
/// # Errors
/// As [`connection`].
pub fn ssh_args(grant: &ActiveGrant, command: &[String]) -> Result<Vec<OsString>> {
    let conn = connection(grant)?;
    let mut args: Vec<OsString> = vec!["-F".into(), "/dev/null".into()];
    for (key, value) in &conn.options {
        args.push("-o".into());
        args.push(format!("{key}={value}").into());
    }
    args.extend([
        "-p".into(),
        conn.port.to_string().into(),
        "--".into(),
        format!("{}@{}", conn.login, conn.host).into(),
    ]);
    args.extend(command.iter().map(OsString::from));
    Ok(args)
}

/// `path` as UTF-8, for the option `key`.
fn utf8<'a>(key: &str, path: &'a Path) -> Result<&'a str> {
    path.to_str()
        .with_context(|| format!("{key} path {} is not valid UTF-8", path.display()))
}

/// `"<path>"` for the ssh option `key`, after `-o key=` or in a config file.
/// ssh splits option values on whitespace, honours double quotes and
/// backslash escapes, and expands `%` tokens in both path options used here,
/// so the path is quoted with `%` doubled. Paths that quoting cannot carry
/// safely are refused.
///
/// # Errors
/// If the path is not UTF-8 or contains `"`, `\` or a control character.
fn quote_path(key: &str, path: &Path) -> Result<String> {
    let text = utf8(key, path)?;
    ensure!(
        !text
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control()),
        "{key} path \"{}\" contains a character ssh cannot take in an option",
        text.escape_debug()
    );
    Ok(format!("\"{}\"", text.replace('%', "%%")))
}

/// Replace this process with `ssh`. Returns only on failure.
#[must_use]
pub fn exec(args: &[OsString]) -> std::io::Error {
    Command::new("ssh").args(args).exec()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use warden_broker_proto::Id;

    use super::{ActiveGrant, active_grant, quote_path, ssh_args};
    use crate::agent::{GrantRecord, Route};

    fn grant(host: &str, port: u16) -> ActiveGrant {
        ActiveGrant {
            dir: PathBuf::from("/state/grants/g"),
            record: GrantRecord {
                grant_id: Id::random(),
                target: "pi".parse().unwrap(),
                route: Route::Direct,
                host: host.to_owned(),
                port,
                user: "alice".parse().unwrap(),
                not_after: 100,
                socket: PathBuf::from("/tmp/warden-501/abc.sock"),
                pid: 1,
            },
        }
    }

    fn strings(args: &[OsString]) -> Vec<&str> {
        args.iter().map(|a| a.to_str().unwrap()).collect()
    }

    #[test]
    fn ssh_args_pin_agent_known_hosts_and_end_options() {
        let args = ssh_args(
            &grant("127.0.0.1", 2222),
            &["echo".to_owned(), "-o".to_owned()],
        )
        .unwrap();
        assert_eq!(
            strings(&args),
            [
                "-F",
                "/dev/null",
                "-o",
                "IdentityAgent=\"/tmp/warden-501/abc.sock\"",
                "-o",
                "IdentityFile=none",
                "-o",
                "IdentitiesOnly=no",
                "-o",
                "UserKnownHostsFile=\"/state/grants/g/known_hosts\"",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "ForwardAgent=no",
                "-p",
                "2222",
                "--",
                "alice@127.0.0.1",
                "echo",
                "-o",
            ]
        );
    }

    fn relay_grant() -> ActiveGrant {
        let mut g = grant("relay.example.com", 2222);
        g.record.route = Route::Relay;
        g
    }

    /// Through the relay, ssh logs in to the relay as the target's name,
    /// with exactly the hardened options of a direct grant.
    #[test]
    fn relay_ssh_args_log_in_to_relay_as_target() {
        let args = ssh_args(&relay_grant(), &["echo".to_owned(), "ok".to_owned()]).unwrap();
        let direct = ssh_args(
            &grant("relay.example.com", 2222),
            &["echo".to_owned(), "ok".to_owned()],
        )
        .unwrap();
        let args = strings(&args);
        let direct = strings(&direct);
        let at = args.iter().position(|a| *a == "--").unwrap();
        assert_eq!(args[..at], direct[..at]);
        assert_eq!(args[at..], ["--", "pi@relay.example.com", "echo", "ok"]);
        assert_eq!(args[at - 2..at], ["-p", "2222"]);
    }

    #[test]
    fn relay_ssh_args_reject_option_like_relay_host() {
        let mut g = relay_grant();
        g.record.host = "-oProxyCommand=evil".to_owned();
        assert!(ssh_args(&g, &[]).is_err());
    }

    #[test]
    fn quote_path_quotes_spaces_and_doubles_percent() {
        let opt = quote_path(
            "UserKnownHostsFile",
            Path::new("/Users/u/Library/Application Support/warden/100%/known_hosts"),
        )
        .unwrap();
        assert_eq!(
            opt,
            "\"/Users/u/Library/Application Support/warden/100%%/known_hosts\""
        );
    }

    #[test]
    fn quote_path_rejects_quote_backslash_and_control_chars() {
        for bad in ["/a\"b", "/a\\b", "/a\nb", "/a\tb"] {
            assert!(
                quote_path("IdentityAgent", Path::new(bad)).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn ssh_args_reject_option_like_host() {
        assert!(ssh_args(&grant("-oProxyCommand=evil", 22), &[]).is_err());
        assert!(ssh_args(&grant("a b", 22), &[]).is_err());
    }

    fn write_grant(grants: &Path, rec: &GrantRecord) -> PathBuf {
        let dir = grants.join(rec.grant_id.as_str());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("grant.json"), serde_json::to_vec(rec).unwrap()).unwrap();
        dir
    }

    #[test]
    fn active_grant_is_longest_lived_one_for_target() {
        let root = tempfile::tempdir().unwrap();
        let grants = root.path().join("grants");
        let socket = root.path().join("live.sock");
        std::fs::write(&socket, b"").unwrap();
        let mut base = grant("h", 22).record;
        base.socket.clone_from(&socket);

        let older = GrantRecord {
            grant_id: Id::random(),
            not_after: 50,
            ..base.clone()
        };
        let newer = GrantRecord {
            grant_id: Id::random(),
            not_after: 80,
            ..base.clone()
        };
        let expired = GrantRecord {
            grant_id: Id::random(),
            not_after: 10,
            ..base.clone()
        };
        let other = GrantRecord {
            grant_id: Id::random(),
            target: "nas".parse().unwrap(),
            not_after: 90,
            ..base.clone()
        };
        let dead = GrantRecord {
            grant_id: Id::random(),
            not_after: 95,
            socket: root.path().join("gone.sock"),
            ..base.clone()
        };
        for rec in [&older, &newer, &expired, &other, &dead] {
            write_grant(&grants, rec);
        }
        std::fs::create_dir_all(grants.join("junk")).unwrap();

        let found = active_grant(&grants, &"pi".parse().unwrap(), 20).unwrap();
        assert_eq!(found.record, newer);
        assert_eq!(found.dir, grants.join(newer.grant_id.as_str()));
        assert!(active_grant(&grants, &"pi".parse().unwrap(), 80).is_none());
        assert!(active_grant(&grants, &"web".parse().unwrap(), 0).is_none());
    }
}
