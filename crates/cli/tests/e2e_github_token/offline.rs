//! The CLI without a broker: the `gh` wrapper, git's credential helper and `warden
//! setup github`, which must work (or refuse) with no server configured.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

use super::{Machine, TOKEN, offline, text};

#[test]
fn the_gh_wrapper_refuses_without_a_repository_and_never_starts_the_real_gh() {
    let machine = offline();
    let set_up = machine.warden().args(["setup", "github"]).output().unwrap();
    assert_eq!(set_up.status.code(), Some(0), "{}", text(&set_up.stderr));

    // No `-R`, no `GH_REPO`, and a directory with no `origin`.
    let mut gh = Command::new("gh");
    machine.env(&mut gh);
    let out = gh
        .env_remove("GH_REPO")
        .args(["pr", "list"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let said = text(&out.stderr);
    assert!(
        said.contains("cannot tell which repository; pass -R owner/name"),
        "{said}"
    );
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    assert!(
        !machine.root.path().join("bin/gh-ran").exists(),
        "the real gh was started"
    );
}

#[test]
fn credential_for_anything_but_https_github_prints_nothing() {
    let machine = offline();
    for input in [
        "protocol=https\nhost=gitlab.com\n\n",
        "protocol=https\nhost=github.com.example.com\n\n",
        "protocol=https\nhost=github.com:443\n\n",
        "protocol=http\nhost=github.com\n\n",
        "protocol=ssh\nhost=github.com\n\n",
        "host=github.com\n\n",
        "protocol=https\n\n",
        "protocol=https\nnot a key value line\nhost=github.com\n\n",
        "protocol=https\nhost=github.com\nhost=gitlab.com\n\n",
        "",
    ] {
        let out = machine.credential("get", input);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{input:?}: {}",
            text(&out.stderr)
        );
        assert_eq!(text(&out.stdout), "", "{input:?}");
        assert_eq!(text(&out.stderr), "", "{input:?}");
    }
}

#[test]
fn credential_store_and_erase_are_silent() {
    let machine = offline();
    let stored =
        format!("protocol=https\nhost=github.com\nusername=x-access-token\npassword={TOKEN}\n\n");
    for op in ["store", "erase", "other"] {
        let out = machine.credential(op, &stored);
        assert_eq!(out.status.code(), Some(0), "{op}: {}", text(&out.stderr));
        assert_eq!(text(&out.stdout), "", "{op}");
        assert_eq!(text(&out.stderr), "", "{op}");
    }
    assert!(!machine.cache().exists());
}

fn global_helpers(machine: &Machine) -> Vec<String> {
    let out = machine.git(
        &[
            "config",
            "--global",
            "--get-all",
            "credential.https://github.com.helper",
        ],
        "",
    );
    text(&out.stdout).lines().map(ToOwned::to_owned).collect()
}

#[test]
fn setup_github_writes_helper_and_wrapper() {
    let machine = offline();
    let out = machine.warden().args(["setup", "github"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let exe = fs::canonicalize(env!("CARGO_BIN_EXE_warden")).unwrap();
    let exe = exe.to_str().unwrap();
    assert_eq!(
        global_helpers(&machine),
        [String::new(), format!("!'{exe}' git-credential")]
    );
    let wrapper = machine.home().join(".local/bin/gh");
    let mode = fs::metadata(&wrapper).unwrap().permissions().mode();
    assert_eq!(mode & 0o7777, 0o755);
    let script = fs::read_to_string(&wrapper).unwrap();
    let real = machine.root.path().join("bin/gh");
    assert!(
        script.contains(&format!("'{exe}' github token")),
        "{script}"
    );
    assert!(
        script.contains(&format!("exec '{}' \"$@\"", real.display())),
        "{script}"
    );
    let said = text(&out.stdout);
    assert!(
        said.contains("credential.https://github.com.helper"),
        "{said}"
    );
    assert!(said.contains(&wrapper.display().to_string()), "{said}");
    assert!(
        !text(&out.stderr).contains("warning"),
        "{}",
        text(&out.stderr)
    );

    // Again: the same values, and the wrapper it wrote is its own to replace.
    let again = machine.warden().args(["setup", "github"]).output().unwrap();
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
    assert_eq!(global_helpers(&machine).len(), 2);
    assert_eq!(fs::read_to_string(&wrapper).unwrap(), script);
}

#[test]
fn setup_github_warns_when_the_wrapper_is_not_first_on_path() {
    let machine = offline();
    let path = format!(
        "{}:{}:/usr/bin:/bin",
        machine.root.path().join("bin").display(),
        machine.home().join(".local/bin").display()
    );
    let out = machine
        .warden()
        .args(["setup", "github"])
        .env("PATH", path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let warned = text(&out.stderr);
    assert!(warned.contains("warning"), "{warned}");
    assert!(warned.contains("PATH"), "{warned}");
}

#[test]
fn setup_github_refuses_foreign_wrapper() {
    let machine = offline();
    let bin = machine.home().join(".local/bin");
    fs::create_dir_all(&bin).unwrap();
    let foreign = "#!/bin/sh\necho mine\n";
    fs::write(bin.join("gh"), foreign).unwrap();
    let out = machine.warden().args(["setup", "github"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("not written by warden"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(fs::read_to_string(bin.join("gh")).unwrap(), foreign);
    assert!(
        global_helpers(&machine).is_empty(),
        "git was left as it was"
    );
}
