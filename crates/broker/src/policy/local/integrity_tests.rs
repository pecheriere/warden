//! A policy file's digest: torn reads on real files, and sealing.

use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read, Write as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _, chown, symlink};
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use warden_broker_proto::SecretName;

use super::files::{MAX_POLICY_BYTES, read_limited, read_policy};
use super::seal::{Target, read_draft, replace, seal_as};
use super::{
    ACCESS_NOTE, END_MARKER, LocalBackend, LocalProbe, PolicyFile, SealError, SealedPolicy,
    Unverified, digest_line, parse_policy, seal_policy_file, seal_text,
};
use crate::config::LocalSettings;
use crate::policy::SecretBackend;

const CREDENTIAL: &str = "api-credential-do-not-leak";

/// Two versions, each harmless, line for line of the same length: `DELETE` on
/// public paths, then only reads on an admin path. Before the digest, the start of
/// the first with the end of the second loaded as `DELETE` on the admin path.
fn old_and_new() -> (String, String) {
    let version = |methods: &str, prefix: &str| {
        seal(&format!(
            "[api_secrets.home-api]\nwebsite = \"https://home.example.com\"\n\
             credential_file = \"home-api\"\nmax_window = \"30m\"\n\
             methods = {methods}\npath_prefix = \"{prefix}\"\n{END_MARKER}\n"
        ))
    };
    let old = version(r#"["GET", "DELETE"]"#, "/public/");
    let new = version(r#"["GET"]          "#, "/admin1/");
    assert_eq!(old.len(), new.len());
    (old, new)
}

fn seal_file(policy: &Path, draft: Option<&Path>) -> Result<SealedPolicy, SealError> {
    seal_policy_file(policy, draft, Unverified::Refuse)
}

fn seal(draft: &str) -> String {
    seal_text(draft).unwrap().to_string()
}

/// A private directory at its real path, with a policy file and a secret.
fn setup(policy: &str) -> (TempDir, PathBuf, LocalBackend) {
    let guard = tempfile::tempdir().unwrap();
    let root = guard.path().canonicalize().unwrap();
    fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
    let secrets = root.join("secrets");
    fs::create_dir(&secrets).unwrap();
    fs::set_permissions(&secrets, Permissions::from_mode(0o700)).unwrap();
    for (name, value) in [
        ("home-api", CREDENTIAL),
        ("new-api", "another-credential-value"),
    ] {
        let path = secrets.join(name);
        fs::write(&path, format!("{value}\n")).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    }
    let path = root.join("policy.toml");
    fs::write(&path, policy).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let backend = LocalBackend::unaudited(&LocalSettings {
        policy_file: path,
        secrets_dir: secrets,
    });
    (guard, root, backend)
}

/// Reads `first` bytes of a real file, lets `overwrite` change that file, and goes
/// on reading through the same open file: a torn read that needs no timing.
struct TornRead<F: FnMut()> {
    file: File,
    first: usize,
    overwrite: Option<F>,
}

impl<F: FnMut()> Read for TornRead<F> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.first == 0
            && let Some(mut overwrite) = self.overwrite.take()
        {
            overwrite();
        }
        let most = if self.overwrite.is_some() {
            buffer.len().min(self.first)
        } else {
            buffer.len()
        };
        let read = self.file.read(&mut buffer[..most])?;
        self.first -= read.min(self.first);
        Ok(read)
    }
}

/// What a real read of `path` returns when `other` is written over it, without
/// truncating, after `first` bytes.
fn read_torn(path: &Path, other: &str, first: usize) -> String {
    let writer = OpenOptions::new().write(true).open(path).unwrap();
    let torn = TornRead {
        file: File::open(path).unwrap(),
        first,
        overwrite: Some(|| writer.write_all_at(other.as_bytes(), 0).unwrap()),
    };
    read_limited(torn, MAX_POLICY_BYTES).unwrap().to_string()
}

/// The mix exists on a real read, would have been accepted without the digest, is
/// wider than both versions, and is refused.
#[test]
fn a_torn_read_wider_than_both_versions_is_refused() {
    let (old, new) = old_and_new();
    let (_guard, root, _backend) = setup(&old);
    let first = old.find("path_prefix").unwrap();
    let text = read_torn(&root.join("policy.toml"), &new, first);
    assert_eq!(text, format!("{}{}", &old[..first], &new[first..]));

    let without_digest_check: PolicyFile = toml::from_str(&text).unwrap();
    let entry = &without_digest_check.api_secrets["home-api"];
    assert_eq!(entry.methods.as_deref().unwrap(), ["GET", "DELETE"]);
    assert_eq!(entry.path_prefix.as_deref(), Some("/admin1/"));

    let refusal = parse_policy(&text).err().unwrap();
    assert!(refusal.contains("does not match the digest"), "{refusal}");
    assert!(refusal.contains("seal-policy"), "{refusal}");
}

/// Every point a read can tear at, each way round, on real files. A read that
/// happens to be all one version is that version, and is accepted.
#[test]
fn a_read_torn_at_any_byte_is_refused_or_is_one_whole_version() {
    let (old, new) = old_and_new();
    for (from, to) in [(&old, &new), (&new, &old)] {
        let (_guard, root, _backend) = setup(from);
        let path = root.join("policy.toml");
        for first in 0..=from.len() {
            fs::write(&path, from).unwrap();
            let text = read_torn(&path, to, first);
            let whole = text == *from || text == *to;
            assert_eq!(parse_policy(&text).is_ok(), whole, "torn after {first}");
        }
    }
}

/// A shorter version over a longer one, with nothing truncated, leaves the whole
/// new file, including its valid end, then the old tail with the old end.
#[test]
fn a_shorter_version_over_a_longer_one_is_refused() {
    let long = seal(&format!("# {}\n{END_MARKER}\n", "x".repeat(200)));
    let short = seal(&format!("{END_MARKER}\n"));
    let mix = format!("{short}{}", &long[short.len()..]);
    assert!(parse_policy(&short).is_ok() && parse_policy(&long).is_ok());
    assert!(parse_policy(&mix).is_err());
}

/// A writer that stopped part way: through the backend, for good, and with a new
/// credential that would have gone to the old destination under the same digest.
#[tokio::test]
async fn an_interrupted_overwrite_refuses_everything_through_the_backend() {
    let version = |credential: &str, website: &str| {
        seal(&format!(
            "[api_secrets.home-api]\ncredential_file = \"{credential}\"\n\
             website = \"https://{website}.example.com\"\nmax_window = \"30m\"\n{END_MARKER}\n"
        ))
    };
    let old = version("home-api", "old-host");
    let new = version("new-api", "new-host");
    let (_guard, root, backend) = setup(&old);
    let name = SecretName::try_from("home-api".to_owned()).unwrap();
    let digest_before = backend
        .api_secret(&name)
        .await
        .unwrap()
        .destination_digest();

    let first = new.find("website").unwrap();
    let path = root.join("policy.toml");
    let writer = OpenOptions::new().write(true).open(&path).unwrap();
    writer.write_all_at(&new.as_bytes()[..first], 0).unwrap();
    drop(writer);

    let mix = fs::read_to_string(&path).unwrap();
    let unchecked: PolicyFile = toml::from_str(&mix).unwrap();
    let entry = &unchecked.api_secrets["home-api"];
    assert_eq!(entry.credential_file.as_deref(), Some("new-api"));
    assert_eq!(
        entry.website.as_deref(),
        Some("https://old-host.example.com")
    );

    assert!(backend.api_secret_with_value(&name).await.is_err());
    assert!(backend.api_secret(&name).await.is_err());
    assert!(matches!(backend.probe().await, LocalProbe::Unreadable(_)));

    // Finishing the write is enough: nothing is remembered about the refusal.
    fs::write(&path, &old).unwrap();
    let digest_after = backend
        .api_secret(&name)
        .await
        .unwrap()
        .destination_digest();
    assert_eq!(digest_after, digest_before);
}

#[test]
fn only_the_exact_ending_is_accepted() {
    let draft = format!("# policy\n{END_MARKER}\n");
    let good = seal(&draft);
    assert!(parse_policy(&good).is_ok());
    assert!(parse_policy(good.trim_end()).is_ok());
    let digest = digest_line(&draft);
    for bad in [
        format!("{good}\n"),
        format!("{good} "),
        good.replace('\n', "\r\n"),
        format!(
            "{draft}{}\n",
            digest.to_uppercase().replace("SHA256", "sha256")
        ),
        format!("{draft}{digest} \n"),
        format!("{draft}{digest} # checked\n"),
        format!("{draft}sha256 = \"\"\n"),
        format!("{draft}sha256 = \"{}\"\n", "0".repeat(64)),
        format!("# changed\n{END_MARKER}\n{digest}\n"),
        draft.clone(),
    ] {
        assert!(parse_policy(&bad).is_err(), "{bad:?}");
    }
}

/// With a matching digest but something else in the section, the parser refuses.
#[test]
fn the_end_section_holds_the_digest_and_nothing_else() {
    let sealed = format!("{END_MARKER}\nother = 1\n{END_MARKER}\n");
    let text = format!("{sealed}{}\n", digest_line(&sealed));
    assert!(parse_policy(&text).is_err());
}

/// Refusals never quote the file, whatever was pasted into it.
#[test]
fn a_refusal_quotes_nothing() {
    let text = format!("credential = \"{CREDENTIAL}\"\n{END_MARKER}\nsha256 = \"{CREDENTIAL}\"\n");
    let refusal = parse_policy(&text).err().unwrap();
    assert!(!refusal.contains(CREDENTIAL), "{refusal}");
    let error = seal_text(&format!("{CREDENTIAL}\n")).unwrap_err();
    assert!(!error.to_string().contains(CREDENTIAL), "{error}");
}

#[test]
fn sealing_replaces_an_earlier_digest_and_changes_only_the_end() {
    let draft = format!("# a comment\n\n{END_MARKER}\n");
    let once = seal(&draft);
    assert!(once.starts_with(&draft));
    assert_eq!(seal(&once), once);
    let edited = once.replace("a comment", "another comment");
    let again = seal(&edited);
    assert!(parse_policy(&edited).is_err());
    assert!(parse_policy(&again).is_ok());
    assert_eq!(again.matches("sha256").count(), 1);
}

/// A draft cut short has lost the marker, so it cannot be sealed into something
/// wider than was written.
#[test]
fn sealing_refuses_a_draft_cut_short_at_any_byte() {
    let (old, _) = old_and_new();
    let body_end = old.find(END_MARKER).unwrap() + END_MARKER.len();
    for cut in 0..body_end {
        assert!(seal_text(&old[..cut]).is_err(), "cut at {cut}");
    }
}

fn entries(result: Result<SealedPolicy, SealError>) -> (usize, usize) {
    let sealed = result.unwrap();
    (sealed.targets, sealed.api_entries)
}

/// The hand edit from start to finish: refused until sealed, sealed only once the
/// person has seen what it allows, and the file a reader already has open stays
/// whole, because it is replaced and not written to.
#[tokio::test]
async fn a_hand_edit_is_sealed_only_after_being_shown_and_replaces_the_file() {
    let (old, _) = old_and_new();
    let (_guard, root, backend) = setup(&old);
    let path = root.join("policy.toml");
    let name = SecretName::try_from("home-api".to_owned()).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();

    let edited = old.replace("/public/", "/private/");
    fs::write(&path, &edited).unwrap();
    let refused = backend.api_secret(&name).await.unwrap_err().to_string();
    assert!(refused.contains("seal-policy --from"), "{refused}");

    let not_sealed = seal_file(&path, None).unwrap_err().to_string();
    assert!(not_sealed.contains("--accept-unverified"), "{not_sealed}");
    assert!(not_sealed.contains("/private/"), "{not_sealed}");
    assert_eq!(fs::read_to_string(&path).unwrap(), edited);

    let mut reader = File::open(&path).unwrap();
    let before = fs::metadata(&path).unwrap();
    let sealed = seal_policy_file(&path, None, Unverified::Accept).unwrap();
    assert!(
        sealed.access[0].contains("/private/"),
        "{:?}",
        sealed.access
    );
    let after = fs::metadata(&path).unwrap();
    assert_ne!(before.ino(), after.ino());
    assert_eq!(after.mode() & 0o777, 0o640);
    let mut seen = String::new();
    reader.read_to_string(&mut seen).unwrap();
    assert_eq!(seen, edited);

    let policy = backend.api_secret(&name).await.unwrap();
    assert_eq!(policy.path_prefix, "/private/");
    assert_eq!(names_in(&root), ["policy.toml", "secrets"]);
}

/// What the digest just caught is not blessed by default: the mix wider than both
/// versions stays refused, its access is shown, and nothing changes, including when
/// the file is named as its own draft. Only the explicit choice seals it.
#[test]
fn sealing_a_torn_file_in_place_needs_an_explicit_choice() {
    let (old, new) = old_and_new();
    let (_guard, root, _backend) = setup(&old);
    let path = root.join("policy.toml");
    let first = old.find("path_prefix").unwrap();
    let mix = read_torn(&path, &new, first);
    fs::write(&path, &mix).unwrap();

    for draft in [None, Some(path.as_path())] {
        let shown = seal_file(&path, draft).unwrap_err().to_string();
        for what in [
            "home-api",
            "GET, DELETE",
            "/admin1/",
            "--accept-unverified",
            "--from",
        ] {
            assert!(shown.contains(what), "{what}: {shown}");
        }
        assert_eq!(fs::read_to_string(&path).unwrap(), mix);
    }
    assert!(seal_policy_file(&path, None, Unverified::Accept).is_ok());
    assert!(parse_policy(&fs::read_to_string(&path).unwrap()).is_ok());
}

/// The usual ways in stay easy: no digest yet, a digest that matches, or a draft
/// copied from a sealed file and edited.
#[test]
fn a_first_seal_and_a_draft_need_no_extra_choice() {
    let (old, _) = old_and_new();
    let (_guard, root, _backend) = setup(&format!("# first\n{END_MARKER}\n"));
    let path = root.join("policy.toml");
    assert!(seal_file(&path, None).is_ok());
    assert!(seal_file(&path, None).is_ok());
    let draft = root.join("draft");
    fs::write(&draft, old.replace("/public/", "/private/")).unwrap();
    let sealed = seal_file(&path, Some(&draft)).unwrap();
    assert!(
        sealed.access[0].contains("/private/"),
        "{:?}",
        sealed.access
    );
}

fn names_in(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// A website is shown as its origin and a format only as present, so a credential
/// pasted into either does not reach a terminal. The note says what is shown.
#[test]
fn a_website_and_a_format_are_shown_only_in_outline() {
    let draft = format!(
        "[api_secrets.home-api]\nwebsite = \"https://user:{CREDENTIAL}@home.example.com/{CREDENTIAL}\"\n\
         credential_file = \"home-api\"\nmax_window = \"30m\"\nformat = \"{CREDENTIAL} {{{{secret}}}}\"\n\
         {END_MARKER}\n"
    );
    let (_guard, root, _backend) = setup(&seal(&draft).replace("30m", "20m"));
    let path = root.join("policy.toml");
    let shown = seal_file(&path, None).unwrap_err().to_string();
    assert!(shown.contains("https://home.example.com"), "{shown}");
    assert!(shown.contains("secret file home-api"), "{shown}");
    assert!(shown.contains(ACCESS_NOTE), "{shown}");
    assert!(!shown.contains(CREDENTIAL), "{shown}");
}

/// A setting naming a secret file, set to what is no valid name, may be the secret
/// itself: it never prints, in any of the three places such a setting exists.
#[test]
fn a_malformed_secret_file_setting_never_prints() {
    let pasted = "leaked+value/here==";
    let draft = format!(
        "[ca]\nprivate_key_file = \"{pasted}\"\n\
         [targets.web-01]\nprivate_key_file = \"{pasted}\"\npassword_file = \"{pasted}\"\n\
         [api_secrets.home-api]\ncredential_file = \"{pasted}\"\n{END_MARKER}\n"
    );
    let (_guard, root, _backend) = setup(&seal(&draft).replace("[ca]", "[ca] "));
    let path = root.join("policy.toml");
    let shown = seal_file(&path, None).unwrap_err().to_string();
    assert_eq!(
        shown.matches("not a valid file name, not shown").count(),
        4,
        "{shown}"
    );
    assert!(!shown.contains("leaked"), "{shown}");
}

/// Ordinary settings are shown whole: the difference a person is looking for can be
/// past any length, and anything a terminal could act on is escaped.
#[test]
fn settings_are_shown_whole_and_escaped() {
    let long = format!("/{}/end-of-the-prefix/", "a".repeat(300));
    let name = "x".repeat(32);
    let draft = format!(
        "[api_secrets.{name}]\nwebsite = \"https://home.example.com\"\ncredential_file = \"home-api\"\n\
         max_window = \"30m\"\npath_prefix = \"{long}\"\nheader = \"X-Long-\\u001b[31m{long}\"\n{END_MARKER}\n"
    );
    let (_guard, root, _backend) = setup(&seal(&draft).replace("30m", "20m"));
    let path = root.join("policy.toml");
    let shown = seal_file(&path, None).unwrap_err().to_string();
    assert!(shown.contains(&format!("path prefix {long}")), "{shown}");
    assert!(shown.contains(r"X-Long-\u{1b}[31m"), "{shown}");
    assert!(!shown.contains('\u{1b}'), "{shown}");
}

#[test]
fn sealing_from_a_draft_leaves_the_draft_and_can_make_the_file() {
    let (old, new) = old_and_new();
    let (_guard, root, _backend) = setup(&old);
    let draft = root.join("draft");
    fs::write(&draft, &new).unwrap();
    let path = root.join("policy.toml");
    assert_eq!(entries(seal_file(&path, Some(&draft))), (0, 1));
    assert_eq!(fs::read_to_string(&path).unwrap(), new);
    assert_eq!(fs::read_to_string(&draft).unwrap(), new);

    let created = root.join("created.toml");
    assert_eq!(entries(seal_file(&created, Some(&draft))), (0, 1));
    assert_eq!(fs::metadata(&created).unwrap().mode() & 0o777, 0o644);
    assert!(read_policy(&created, rustix::process::geteuid().as_raw()).is_ok());
}

/// Whatever is refused leaves the file as it was, and nothing beside it.
#[test]
fn sealing_refuses_what_warden_would_and_changes_nothing() {
    let (old, _) = old_and_new();
    let (_guard, root, _backend) = setup(&old);
    let path = root.join("policy.toml");
    let draft = root.join("draft");
    let oversize = format!("{}\n{END_MARKER}\n", "#".repeat(MAX_POLICY_BYTES));
    let unusable = [
        format!("# no end marker: {CREDENTIAL}\n"),
        format!("not toml: {CREDENTIAL}\n{END_MARKER}\n"),
        format!("credential = \"{CREDENTIAL}\"\n{END_MARKER}\n"),
        format!("{END_MARKER}\n{END_MARKER}\n"),
        oversize,
    ];
    for content in unusable {
        fs::write(&draft, content).unwrap();
        let error = seal_file(&path, Some(&draft)).unwrap_err();
        assert!(!error.to_string().contains(CREDENTIAL), "{error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), old);
    }
    fs::remove_file(&draft).unwrap();

    assert!(seal_file(&path, Some(&root.join("absent"))).is_err());
    assert!(seal_file(&root.join("absent"), None).is_err());

    let link = root.join("link");
    symlink(&path, &link).unwrap();
    assert!(seal_file(&link, Some(&path)).is_err());
    assert!(seal_file(&path, Some(&link)).is_err());
    fs::remove_file(&link).unwrap();

    let second_name = root.join("second-name");
    fs::hard_link(&path, &second_name).unwrap();
    assert!(seal_file(&path, None).is_err());
    fs::remove_file(&second_name).unwrap();

    fs::set_permissions(&path, Permissions::from_mode(0o660)).unwrap();
    assert!(seal_file(&path, None).is_err());
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();

    assert_eq!(fs::read_to_string(&path).unwrap(), old);
    assert_eq!(names_in(&root), ["policy.toml", "secrets"]);
}

/// The user to ask as, for whom `path` belongs to someone else. warden trusts root's
/// files whoever asks, so a test running as root has to give the file away; anyone
/// else cannot, and needs only to ask as another user.
fn owned_by_someone_else(path: &Path) -> u32 {
    let euid = rustix::process::geteuid().as_raw();
    if euid == 0 {
        chown(path, Some(12345), None).unwrap();
        12346
    } else {
        euid + 1
    }
}

/// A draft turns into access, so it is held to the policy file's own rules.
#[test]
fn a_draft_is_held_to_the_rules_of_the_policy_file() {
    let (old, new) = old_and_new();
    let (_guard, root, _backend) = setup(&old);
    let path = root.join("policy.toml");
    let draft = root.join("draft");
    fs::write(&draft, &new).unwrap();

    fs::set_permissions(&draft, Permissions::from_mode(0o666)).unwrap();
    let error = seal_file(&path, Some(&draft)).unwrap_err().to_string();
    assert!(error.contains("written by group or others"), "{error}");
    fs::set_permissions(&draft, Permissions::from_mode(0o600)).unwrap();

    let euid = rustix::process::geteuid().as_raw();
    assert!(read_draft(&draft, euid).is_ok());
    let other = owned_by_someone_else(&draft);
    let error = read_draft(&draft, other).err().unwrap().to_string();
    assert!(error.contains("another user"), "{error}");

    let real = root.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, Permissions::from_mode(0o700)).unwrap();
    fs::rename(&draft, real.join("draft")).unwrap();
    symlink(&real, root.join("linked")).unwrap();
    let error = seal_file(&path, Some(&root.join("linked/draft")))
        .unwrap_err()
        .to_string();
    assert!(error.contains("symbolic link"), "{error}");
    assert_eq!(fs::read_to_string(&path).unwrap(), old);
}

/// Refused over ownership, the error says what to do.
#[test]
fn a_refusal_over_ownership_says_how_to_run_it() {
    let (old, _) = old_and_new();
    let (_guard, root, _backend) = setup(&old);
    let path = root.join("policy.toml");
    let other = owned_by_someone_else(&path);
    let error = seal_as(&path, None, Unverified::Refuse, other)
        .unwrap_err()
        .to_string();
    assert!(error.contains("another user"), "{error}");
    assert!(error.contains("docker run --rm --user"), "{error}");
}

/// A file left by an earlier seal, under what used to be the predictable name, does
/// not stop this one, and is left alone.
#[test]
fn a_leftover_temporary_file_does_not_stop_a_seal() {
    let (old, _) = old_and_new();
    let (_guard, root, _backend) = setup(&old);
    let path = root.join("policy.toml");
    let leftover = root.join(format!(".policy.toml.seal-{}", std::process::id()));
    File::create(&leftover)
        .unwrap()
        .write_all(b"leftover")
        .unwrap();
    assert!(seal_file(&path, None).is_ok());
    assert_eq!(fs::read(&leftover).unwrap(), b"leftover");
}

fn target_in(directory: &File) -> Target<'_> {
    Target {
        directory,
        name: "policy.toml".as_ref(),
        ownership: None,
    }
}

/// A name taken every time: the error says writing failed, and which file is in the
/// way, and that file and the policy are left alone.
#[test]
fn a_temporary_name_taken_every_time_is_named_as_a_write_failure() {
    let (old, _) = old_and_new();
    let (_guard, root, _backend) = setup(&old);
    let taken = root.join(".policy.toml.seal-fixed");
    File::create(&taken)
        .unwrap()
        .write_all(b"someone else's")
        .unwrap();
    let directory = File::open(&root).unwrap();
    let error = replace(
        &target_in(&directory),
        "new",
        || Ok("fixed".to_owned()),
        File::sync_all,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains(".policy.toml.seal-fixed"), "{error}");
    assert!(error.contains("cannot be written"), "{error}");
    assert!(!error.contains("cannot be read"), "{error}");
    assert_eq!(fs::read(&taken).unwrap(), b"someone else's");
    assert_eq!(fs::read_to_string(root.join("policy.toml")).unwrap(), old);
}

/// A failure after the rename says the file was replaced, because it was.
#[test]
fn a_failed_directory_sync_says_the_file_was_replaced() {
    let (old, _) = old_and_new();
    let (_guard, root, _backend) = setup(&old);
    let directory = File::open(&root).unwrap();
    let error = replace(
        &target_in(&directory),
        "new",
        || Ok("once".to_owned()),
        |_| Err(io::Error::other("no sync today")),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("was replaced"), "{error}");
    assert!(error.contains("may not survive a crash"), "{error}");
    assert_eq!(fs::read_to_string(root.join("policy.toml")).unwrap(), "new");
    assert_eq!(names_in(&root), ["policy.toml", "secrets"]);
}
