//! `warden git-credential`: git's credential helper for `https://github.com`.
//!
//! `warden setup github` makes git run `<this program> git-credential <op>` through
//! the shell, with the credential git wants on stdin as `key=value` lines up to a
//! blank line (gitcredentials(7)). For `get` with exactly `protocol=https` and
//! `host=github.com`, this prints `username=x-access-token` and `password=<token>`,
//! a GitHub token from the broker. For anything else (another host, a port, `http`,
//! `store`, `erase`, input it cannot read) it prints nothing and exits 0, which
//! tells git this helper has nothing to say. The token is for the repository
//! git's `path` names (git sends it with `credential.useHttpPath`, which `warden
//! setup github` sets): with no `path`, the helper says so on stderr and prints
//! nothing, and with a `path` that is not exactly a repository, such as the
//! `/info/lfs` paths git-lfs sends, it prints nothing. Other keys, such as
//! `username` and `capability[]`, are ignored: the user name is fixed.

use std::ffi::OsString;
use std::io::{BufRead as _, Write as _};
use std::process::ExitCode;

use warden_broker_proto::release::RepoName;
use zeroize::Zeroizing;

use crate::github_repo;
use crate::github_token::{self, Caller};
use crate::{EXIT_ERROR, Exit};

/// The most input read from git, in bytes. Git sends a few short lines.
const MAX_INPUT_BYTES: u64 = 64 * 1024;

/// The only host this helper answers for.
const HOST: &str = "github.com";

/// The user name GitHub expects with an installation token.
const USERNAME: &str = "x-access-token";

/// Whether the command line is git's: `warden git-credential ...`.
pub fn is_program_call(args: &[OsString]) -> bool {
    args.first().is_some_and(|first| first == "git-credential")
}

/// What git asked about, as far as this helper cares.
#[derive(Debug, Default, PartialEq, Eq)]
struct Asked {
    protocol: Option<String>,
    host: Option<String>,
    path: Option<String>,
}

impl Asked {
    fn is_github(&self) -> bool {
        self.protocol.as_deref() == Some("https") && self.host.as_deref() == Some(HOST)
    }
}

/// Read git's description of a credential: `key=value` lines, up to a blank line or
/// the end. `None` for input git does not send: a line without `=`, the same
/// `protocol`, `host` or `path` twice, input that is not UTF-8 or longer than
/// [`MAX_INPUT_BYTES`].
fn read_asked(input: impl std::io::Read) -> Option<Asked> {
    let mut input = std::io::BufReader::new(input.take(MAX_INPUT_BYTES + 1));
    let mut asked = Asked::default();
    let mut total = 0_usize;
    let mut line = String::new();
    loop {
        line.clear();
        let read = input.read_line(&mut line).ok()?;
        total += read;
        if u64::try_from(total).ok()? > MAX_INPUT_BYTES {
            return None;
        }
        let Some(content) = line
            .strip_suffix('\n')
            .or((read > 0).then_some(line.as_str()))
        else {
            return Some(asked);
        };
        if content.is_empty() {
            return Some(asked);
        }
        let (key, value) = content.split_once('=')?;
        let slot = match key {
            "protocol" => &mut asked.protocol,
            "host" => &mut asked.host,
            "path" => &mut asked.path,
            _ => continue,
        };
        if slot.replace(value.to_owned()).is_some() {
            return None;
        }
    }
}

/// Whether to answer: only `get`, alone, for `https://github.com`.
fn wants_token(args: &[OsString], asked: Option<&Asked>) -> bool {
    matches!(args, [_, op] if op == "get") && asked.is_some_and(Asked::is_github)
}

/// What to do for a `get` that is for github.com.
#[derive(Debug)]
enum Answer {
    /// Print this token.
    Token(Zeroizing<String>),
    /// Print nothing: git sent a path that is not a repository.
    Nothing,
    /// Print nothing and say so: git sent no path.
    NoPath,
}

/// The answer for `asked`, with the token for its repository from `obtain`, which is
/// not called when there is no repository.
///
/// # Errors
/// What `obtain` fails with.
async fn answer<F, Fut>(asked: &Asked, obtain: F) -> anyhow::Result<Answer>
where
    F: FnOnce(RepoName) -> Fut,
    Fut: Future<Output = anyhow::Result<Zeroizing<String>>>,
{
    let Some(path) = asked.path.as_deref() else {
        return Ok(Answer::NoPath);
    };
    let Some(repository) = github_repo::from_helper_path(path) else {
        return Ok(Answer::Nothing);
    };
    obtain(repository).await.map(Answer::Token)
}

/// The lines git reads for `token`.
fn credentials(token: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(
        token.len() + USERNAME.len() + "username=\npassword=\n".len(),
    ));
    out.push_str("username=");
    out.push_str(USERNAME);
    out.push_str("\npassword=");
    out.push_str(token);
    out.push('\n');
    out
}

/// Do what git asked and give git its exit code. Failures go to stderr, which git
/// shows; stdout holds the credential or nothing.
pub async fn run(args: &[OsString]) -> ExitCode {
    // Read whatever the operation, so that git never writes to a closed pipe.
    let asked = read_asked(std::io::stdin().lock());
    if !wants_token(args, asked.as_ref()) {
        return ExitCode::SUCCESS;
    }
    let Some(asked) = asked else {
        return ExitCode::SUCCESS;
    };
    let obtain = |repository: RepoName| async move {
        github_token::obtain(Caller::CredentialHelper, &repository).await
    };
    let token = match answer(&asked, obtain).await {
        Ok(Answer::Token(token)) => token,
        Ok(Answer::Nothing) => return ExitCode::SUCCESS,
        Ok(Answer::NoPath) => {
            eprintln!(
                "warden: git sent no repository path; run `warden setup github`, which sets \
                 credential.https://github.com.useHttpPath"
            );
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            let code = e
                .downcast_ref::<Exit>()
                .map_or(EXIT_ERROR, |exit| exit.code);
            eprintln!("warden: {e:#}");
            return ExitCode::from(code);
        }
    };
    let mut out = std::io::stdout().lock();
    match out
        .write_all(credentials(&token).as_bytes())
        .and_then(|()| out.flush())
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("warden: cannot write the credential for git: {e}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{Answer, Asked, answer, credentials, is_program_call, read_asked, wants_token};

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn asked(input: &str) -> Option<Asked> {
        read_asked(input.as_bytes())
    }

    fn answers(op: &str, input: &str) -> bool {
        wants_token(&args(&["git-credential", op]), asked(input).as_ref())
    }

    #[test]
    fn only_git_credential_first_is_gits() {
        assert!(is_program_call(&args(&["git-credential", "get"])));
        assert!(!is_program_call(&args(&["github", "token"])));
        assert!(!is_program_call(&args(&["status", "git-credential"])));
        assert!(!is_program_call(&[]));
    }

    #[test]
    fn credential_get_github_prints_token() {
        // As git sends it, with the keys this helper ignores.
        let input = "capability[]=authtype\ncapability[]=state\nprotocol=https\n\
                     host=github.com\npath=owner/repo.git\nusername=someone\n\
                     wwwauth[]=Basic realm=\"GitHub\"\n\n";
        assert!(answers("get", input));
        assert!(answers("get", "protocol=https\nhost=github.com\n"));
        assert!(answers("get", "protocol=https\nhost=github.com"));
        assert_eq!(
            credentials("ghs_abc").as_str(),
            "username=x-access-token\npassword=ghs_abc\n"
        );
    }

    #[test]
    fn credential_other_host_prints_nothing() {
        for input in [
            "protocol=https\nhost=gitlab.com\n\n",
            "protocol=https\nhost=github.com:443\n\n",
            "protocol=https\nhost=GitHub.com\n\n",
            "protocol=https\nhost=api.github.com\n\n",
            "protocol=https\nhost=github.com.\n\n",
            "protocol=https\nhost=github.com\r\n\n",
            "protocol=https\nhost= github.com\n\n",
            "protocol=https\n\n",
            "",
        ] {
            assert!(!answers("get", input), "{input:?}");
        }
    }

    #[test]
    fn credential_http_scheme_prints_nothing() {
        for protocol in ["http", "ssh", "git", "HTTPS", "file", ""] {
            let input = format!("protocol={protocol}\nhost=github.com\n\n");
            assert!(!answers("get", &input), "{input:?}");
        }
    }

    #[test]
    fn credential_store_and_erase_are_silent() {
        let input = "protocol=https\nhost=github.com\nusername=x-access-token\npassword=x\n\n";
        for op in ["store", "erase", "fill", "Get", ""] {
            assert!(!answers(op, input), "{op}");
        }
        assert!(!wants_token(
            &args(&["git-credential", "get", "extra"]),
            asked(input).as_ref()
        ));
        assert!(!wants_token(
            &args(&["git-credential"]),
            asked(input).as_ref()
        ));
    }

    #[test]
    fn input_git_does_not_send_ends_with_nothing() {
        assert_eq!(
            asked("protocol=https\nno equals sign\nhost=github.com\n\n"),
            None
        );
        assert_eq!(
            asked("protocol=https\nhost=github.com\nhost=github.com\n\n"),
            None
        );
        assert_eq!(
            asked("protocol=https\nprotocol=https\nhost=github.com\n\n"),
            None
        );
        assert_eq!(
            read_asked(&b"protocol=https\nhost=github.com\xff\n\n"[..]),
            None
        );
        let long = format!(
            "protocol=https\nhost=github.com\npath={}\n\n",
            "a".repeat(70_000)
        );
        assert_eq!(asked(&long), None);
        // What follows the blank line is not read as part of the credential.
        let after = asked("protocol=https\nhost=github.com\n\nhost=gitlab.com\n").unwrap();
        assert!(after.is_github());
        // A value may hold `=`.
        let odd = asked("protocol=https\nhost=github.com\npath=a=b\n\n").unwrap();
        assert!(odd.is_github());
    }

    async fn answered(input: &str) -> (Option<String>, Option<String>) {
        let received = std::cell::RefCell::new(None);
        let outcome = answer(&asked(input).unwrap(), |repo| {
            *received.borrow_mut() = Some(repo.to_string());
            std::future::ready(Ok(zeroize::Zeroizing::new("ghs_t".to_owned())))
        })
        .await
        .unwrap();
        let token = match outcome {
            Answer::Token(t) => Some(t.to_string()),
            Answer::Nothing | Answer::NoPath => None,
        };
        (token, received.into_inner())
    }

    #[tokio::test]
    async fn get_with_path_answers_for_that_repository() {
        for path in [
            "example-owner/example-repo",
            "example-owner/example-repo.git",
        ] {
            let input = format!("protocol=https\nhost=github.com\npath={path}\n\n");
            let (token, repo) = answered(&input).await;
            assert_eq!(token.as_deref(), Some("ghs_t"), "{path}");
            assert_eq!(
                repo.as_deref(),
                Some("example-owner/example-repo"),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn get_without_path_answers_nothing() {
        let (token, repo) = answered("protocol=https\nhost=github.com\n\n").await;
        assert_eq!((token, repo), (None, None));
        let outcome = answer(
            &asked("protocol=https\nhost=github.com\n\n").unwrap(),
            |_| std::future::ready(Ok(zeroize::Zeroizing::new(String::new()))),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, Answer::NoPath));
    }

    #[tokio::test]
    async fn get_with_lfs_path_answers_nothing() {
        for path in [
            "example-owner/example-repo.git/info/lfs",
            "example-owner/example-repo/info/lfs/objects/batch",
            "example-owner",
        ] {
            let input = format!("protocol=https\nhost=github.com\npath={path}\n\n");
            let (token, repo) = answered(&input).await;
            assert_eq!((token, repo), (None, None), "{path}");
            let outcome = answer(&asked(&input).unwrap(), |_| {
                std::future::ready(Ok(zeroize::Zeroizing::new(String::new())))
            })
            .await
            .unwrap();
            assert!(matches!(outcome, Answer::Nothing), "{path}");
        }
    }

    #[test]
    fn repeated_path_is_unreadable() {
        assert_eq!(
            asked("protocol=https\nhost=github.com\npath=a/b\npath=a/b\n\n"),
            None
        );
    }
}
