//! Fix round 2a: secrets out of messages, wrappers, git and the owner's key,
//! and the smaller findings of review B.

use super::{check, context, signals};
use crate::detect::{OWNER_SSH_KEY_SUBJECTS, SECRET_STORE_SUBJECTS, TOKEN_READ_SUBJECTS};
use crate::settings::{Settings, Signal};

fn fires(command: &str, signal: Signal) {
    assert!(
        signals(command).contains(&signal),
        "{command}: {:?}",
        signals(command)
    );
}

fn silent(command: &str) {
    assert_eq!(signals(command), vec![], "{command}");
}

#[test]
fn a_misread_option_value_never_reaches_the_message() {
    for (command, secret) in [
        (
            "curl -H 'Authorization: Bearer x' --tlspassword s3cr3t.v4lue https://api.example.org/",
            "s3cr3t.v4lue",
        ),
        (
            "wget --header 'Authorization: Bearer x' --proxy-password s3c.r3t https://api.example.org/",
            "s3c.r3t",
        ),
        (
            "curl -u me https://api.example.org/ -d x=1 ghp_abc.def",
            "ghp_abc.def",
        ),
        (
            "curl -H 'Authorization: Bearer x' https://api.example.org/ eyJhbGciOi.eyJzdWIi.SflKxwRJSM",
            "eyJhbGciOi",
        ),
        ("curl -u me api.example.org s3cr3t.v4lue", "s3cr3t.v4lue"),
        (
            "curl --pass s3c.r3t -u me https://api.example.org/",
            "s3c.r3t",
        ),
        (
            "curl --oauth2-bearer t --proxy-header 'X: s3c.r3t' https://api.example.org/",
            "s3c.r3t",
        ),
        ("http -a me:pw https://api.example.org/ s3c.r3t", "s3c.r3t"),
    ] {
        let verdict = check(command, &context(true), &Settings::default());
        assert!(!verdict.message.contains(secret), "{command}");
        for found in &verdict.matches {
            assert!(!found.subject.contains(secret), "{command}: {found:?}");
        }
    }
}

#[test]
fn uncovered_host_needs_an_explicit_scheme_or_url_option() {
    silent("curl -u me api.example.org");
    silent("curl --max-filesize 10.5 https://example.com");
    fires("curl -u me --url api.example.org", Signal::UncoveredHost);
    fires("curl -u me https://api.example.org", Signal::UncoveredHost);
    fires(
        "curl -H 'Authorization: x' home-api.example.internal",
        Signal::CoveredApi,
    );
    assert_eq!(
        signals("curl --max-filesize 10.5 -u me https://api.example.org/"),
        vec![Signal::UncoveredHost]
    );
}

#[test]
fn more_http_credentials_count() {
    for command in [
        "curl --netrc https://api.example.org/",
        "curl -n https://api.example.org/",
        "curl --netrc-file /x/f https://api.example.org/",
        "curl -H 'X-API-Key: k' https://api.example.org/",
        "curl -H 'x-api-key: k' https://api.example.org/",
        "curl -H 'PRIVATE-TOKEN: k' https://api.example.org/",
        "curl -H 'Cookie: a=b' https://api.example.org/",
        "curl -H 'Proxy-Authorization: Basic k' https://api.example.org/",
        "wget --header 'X-API-Key: k' https://api.example.org/",
        "curl --tlsuser me --tlspassword p -H 'cookie: a=b' https://api.example.org/",
    ] {
        fires(command, Signal::UncoveredHost);
    }
    silent("curl -H 'Accept: text/html' https://api.example.org/");
}

#[test]
fn the_unspecified_address_is_the_machine_itself() {
    silent("curl -H 'Authorization: x' http://0.0.0.0:8080/");
    silent("curl -H 'Authorization: x' http://[::]:8080/");
    silent("ssh 0.0.0.0");
}

#[test]
fn wrappers_do_not_hide_the_command() {
    for command in [
        "timeout 10 ssh switch-01 uptime",
        "timeout -s KILL 10 ssh switch-01 uptime",
        "timeout --signal=KILL --foreground -k 5 10 ssh switch-01",
        "timeout -- 10 ssh switch-01",
        "xargs -I{} ssh switch-01 {}",
        "xargs -I R -n 1 -P 4 ssh switch-01 R",
        "xargs ssh switch-01",
        "nice ssh switch-01",
        "nice -n 5 ssh switch-01",
        "ionice -c 3 -n 7 ssh switch-01",
        "stdbuf -oL ssh switch-01",
        "stdbuf -o L -e0 ssh switch-01",
        "doas -u root ssh switch-01",
        "watch ssh switch-01 uptime",
        "watch -n 5 -d ssh switch-01 uptime",
        "watch -n5 'ssh switch-01 uptime'",
        "ssh-copy-id switch-01",
        "ssh-copy-id -i k.pub build-agent@switch-01",
        "autossh -M 0 switch-01",
        "autossh -M 20000 -f -N switch-01",
        "mosh switch-01",
        "mosh --ssh='ssh -p 22' build-agent@switch-01",
    ] {
        fires(command, Signal::CoveredSsh);
    }
    fires("timeout 10 op read op://v/i/f", Signal::SecretStore);
    fires("timeout 10 mosh other.example.org", Signal::UncoveredHost);
    fires(
        "ssh-copy-id -i ~/.ssh/k.pub other.example.org",
        Signal::OwnerSshKey,
    );
    fires("mosh --ssh='ssh -i ~/.ssh/k' host", Signal::OwnerSshKey);
    fires("autossh -M 0 -i ~/.ssh/k host", Signal::OwnerSshKey);
    for command in [
        "timeout 10 ls -la",
        "xargs -n 1 echo",
        "nice ls",
        "watch -n 5 df",
        "mosh",
    ] {
        silent(command);
    }
}

#[test]
fn git_and_the_owner_s_key() {
    for command in [
        "SSH_AUTH_SOCK=~/Library/agent.sock git push",
        "env SSH_AUTH_SOCK=/x/agent.sock git push",
        "GIT_SSH_COMMAND=\"ssh -i ~/.ssh/id_ed25519\" git push",
        "git -c core.sshCommand=\"ssh -i ~/.ssh/k\" push",
        "git -C repo -c core.sshCommand='ssh -o IdentityFile=~/k' fetch",
        "RSYNC_RSH='ssh -i ~/.ssh/k' rsync -a d build:/x",
        "rsync -e 'ssh -i ~/.ssh/k' -a d build:/x",
        "GIT_SSH_COMMAND='ssh -o IdentityAgent=/tmp/other.sock' git pull",
    ] {
        fires(command, Signal::OwnerSshKey);
    }
    let found = check(
        "SSH_AUTH_SOCK=/x/a.sock git push",
        &context(true),
        &Settings::default(),
    );
    assert_eq!(found.matches[0].subject, "git");
    for command in [
        "GIT_SSH_COMMAND=\"ssh -o IdentityAgent=/tmp/warden-501/a.sock\" git push",
        "SSH_AUTH_SOCK=/tmp/warden-501/a.sock git push",
        "GIT_SSH_COMMAND='ssh -o \"IdentityAgent /tmp/warden-501/a.sock\"' git clone git@switch-01.example.internal:r",
        "rsync -e 'ssh -o \"IdentityAgent /tmp/warden-501/a.sock\"' d switch-01:/x",
        "RSYNC_RSH='ssh -F /work/warden.conf' rsync d switch-01:/x",
        "git status",
    ] {
        silent(command);
    }
    fires(
        "GIT_SSH_COMMAND='ssh -J switch-01' git push",
        Signal::CoveredSsh,
    );
}

#[test]
fn git_commands_that_do_not_connect_are_silent() {
    for command in [
        "git remote add origin git@switch-01.example.internal:r.git",
        "git remote set-url origin ssh://git@switch-01.example.internal/r",
        "git config remote.origin.url git@switch-01.example.internal:r.git",
        "git -C d remote add o git@switch-01.example.internal:r.git",
        "SSH_AUTH_SOCK=/x/a.sock git remote add o git@other.example.org:r.git",
    ] {
        silent(command);
    }
    fires(
        "git clone git@switch-01.example.internal:r.git",
        Signal::CoveredSsh,
    );
    fires("git -C d fetch ssh://git@switch-01/r", Signal::CoveredSsh);
}

#[test]
fn jump_hosts_are_destinations() {
    for command in [
        "ssh -J switch-01 other.example.org",
        "ssh -J build-agent@switch-01:22,x.example.org other.example.org",
        "ssh -o ProxyJump=switch-01 other.example.org",
        "ssh -o 'ProxyJump switch-01' other.example.org",
        "scp -J switch-01 f other.example.org:/x",
        "sftp -J ssh://build-agent@switch-01:22 other.example.org",
        "rsync -e 'ssh -J switch-01' d other.example.org:/x",
    ] {
        fires(command, Signal::CoveredSsh);
    }
    fires("ssh -J jump.example.org switch-01", Signal::UncoveredHost);
    silent("ssh -J none localhost");
}

#[test]
fn document_files_named_env_are_not_credentials() {
    for command in [
        "cat docs/.env.md",
        "cat docs/.env.MD",
        "cat .env.txt",
        "cat .env.local.example",
        "cat .env.template",
        "cat .env.sample",
        "cat .env.dist",
    ] {
        silent(command);
    }
    fires("cat .env.production", Signal::TokenRead);
    fires("cat .env.local", Signal::TokenRead);
}

#[test]
fn secret_store_options_and_subcommands() {
    for command in [
        "op --cache read op://v/i/f",
        "op --format json item get x",
        "op --encoding utf-8 read x",
        "op --account a --session s --config c read x",
        "op document get x",
        "gopass env foo -- cmd",
        "pass grep foo",
        "pass generate web/x",
        "gopass generate web/x",
        "bw list items",
        "bw --session s list items",
    ] {
        fires(command, Signal::SecretStore);
    }
    for command in [
        "op --cache --version",
        "op --cache signin",
        "bw list folders",
        "pass ls",
    ] {
        silent(command);
    }
}

#[test]
fn the_message_lists_at_most_eight_matches() {
    let hosts: Vec<String> = (0..20).map(|n| format!("ssh h{n}.example.org")).collect();
    let verdict = check(&hosts.join("; "), &context(true), &Settings::default());
    assert_eq!(verdict.matches.len(), 20);
    assert_eq!(verdict.message.matches("uncovered-host:").count(), 8);
    assert!(verdict.message.contains("\u{2026} and 12 more.\n\n"));
    assert!(verdict.message.ends_with("Never look for another way in."));
    let few = check(
        "ssh a.example.org; ssh b.example.org",
        &context(true),
        &Settings::default(),
    );
    assert!(!few.message.contains("more."));
}

#[test]
fn subjects_belong_to_the_closed_sets() {
    let commands = [
        "ssh -i k h.example.org",
        "scp -i k f build:/x",
        "sftp -i k build:/x",
        "rsync -e 'ssh -i k' d build:/x",
        "SSH_AUTH_SOCK=/x git push",
        "ssh-copy-id -i k h",
        "autossh -M 0 -i k h",
        "mosh --ssh='ssh -i k' h",
        "op read x; security find-generic-password -w; pass show x; gopass show x; bw get x",
        "cat .netrc; cat .env; cat ~/.config/gh/hosts.yml; gh auth token",
        "curl -u me https://api.example.org/ s3cr3t.v4lue",
    ];
    for command in commands {
        for found in check(command, &context(true), &Settings::default()).matches {
            let set: &[&str] = match found.signal {
                Signal::OwnerSshKey => OWNER_SSH_KEY_SUBJECTS,
                Signal::SecretStore => SECRET_STORE_SUBJECTS,
                Signal::TokenRead => TOKEN_READ_SUBJECTS,
                _ => continue,
            };
            assert!(
                set.contains(&found.subject.as_str()),
                "{command}: {found:?}"
            );
        }
    }
}
