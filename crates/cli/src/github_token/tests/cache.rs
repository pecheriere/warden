use std::cell::Cell;
use std::fs;
use std::future::ready;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use warden_broker_proto::Id;
use warden_broker_proto::github_permissions::{PermissionSet, known_names};

use super::super::cache::{AskedSet, Cache, Entry, MAX_CACHE_BYTES, MAX_ENTRIES};
use super::{
    CACHED, Dir, FRESH, NOW, OTHER_REPO, REPO, dir, entry, identity, loaded, repo, response, serve,
    serve_from, stored_token, write_one,
};

fn checks_read() -> AskedSet {
    AskedSet::Exactly(PermissionSet::parse("checks:read").unwrap())
}

/// An entry for `asked`, minted under `grant`.
fn asked_entry(token: &str, grant: &Id, asked: &AskedSet) -> Entry {
    let mut r = response(token, NOW + 3600, REPO, 1001);
    r.grant_id = grant.clone();
    Entry::new(r, asked)
}

/// As [`serve_as`], for `asked`, with `fresh`.
async fn serve_asked(path: &Path, asked: &AskedSet, fresh: bool) -> (String, bool) {
    let minted = Cell::new(false);
    let token = serve_from(path, NOW, &identity(), &repo(REPO), asked, fresh, || {
        minted.set(true);
        ready(Ok(response(FRESH, NOW + 3600, REPO, 1001)))
    })
    .await
    .unwrap();
    (token.to_string(), minted.get())
}

#[test]
fn cache_keys_by_repository_and_set() {
    let grant = Id::random();
    let mut cache = Cache::empty(identity());
    cache.put(asked_entry("ghs_default", &grant, &AskedSet::Default));
    assert!(
        cache.lookup(&repo(REPO), &checks_read(), NOW).is_none(),
        "a whole-set token does not answer a narrowed ask"
    );
    cache.put(asked_entry("ghs_narrow", &grant, &checks_read()));
    assert_eq!(cache.entries.len(), 2, "both coexist");
    let default = cache.lookup(&repo(REPO), &AskedSet::Default, NOW).unwrap();
    assert_eq!(default.token.as_str(), "ghs_default");
    let narrow = cache.lookup(&repo(REPO), &checks_read(), NOW).unwrap();
    assert_eq!(narrow.token.as_str(), "ghs_narrow");
    let other = AskedSet::Exactly(PermissionSet::parse("actions:read").unwrap());
    assert!(cache.lookup(&repo(REPO), &other, NOW).is_none());
    // The same key under the same grant replaces.
    cache.put(asked_entry("ghs_narrow2", &grant, &checks_read()));
    assert_eq!(cache.entries.len(), 2);
}

#[tokio::test]
async fn fresh_skips_and_replaces() {
    let d = dir();
    write_one(&d.cache, CACHED, NOW + 3600);
    assert_eq!(
        serve_asked(&d.cache, &AskedSet::Default, false).await,
        (CACHED.to_owned(), false)
    );
    assert_eq!(
        serve_asked(&d.cache, &AskedSet::Default, true).await,
        (FRESH.to_owned(), true)
    );
    assert_eq!(stored_token(&d.cache, REPO).as_deref(), Some(FRESH));
    assert_eq!(loaded(&d.cache).entries.len(), 1);
}

#[test]
fn put_keeps_entries_of_other_grants() {
    let (g1, g2) = (Id::random(), Id::random());
    let extra = AskedSet::Exactly(PermissionSet::parse("contents:write,workflows:write").unwrap());
    let mut cache = Cache::empty(identity());
    cache.put(asked_entry("ghs_old", &g1, &AskedSet::Default));
    cache.put(asked_entry("ghs_extra", &g2, &extra));
    cache.put(entry("ghs_other", NOW + 3600, OTHER_REPO, 1002));
    cache.put(asked_entry("ghs_new", &g1, &AskedSet::Default));
    let mut tokens: Vec<_> = cache.entries.iter().map(|e| e.token.to_string()).collect();
    tokens.sort();
    assert_eq!(tokens, ["ghs_extra", "ghs_new", "ghs_other"]);
}

#[tokio::test]
async fn version_3_file_is_ignored() {
    let d = dir();
    let v3 = format!(
        r#"{{"version":3,"agent":"build-agent","server":"https://warden.example.ts.net/","entries":[{{"repository":"{REPO}","repository_id":1001,"grant_id":"{}","token":"ghs_old","expires_at":{},"asked":"full"}}]}}"#,
        Id::random(),
        NOW + 3600
    );
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&d.cache)
        .unwrap();
    fs::write(&d.cache, v3).unwrap();
    assert!(Cache::load(&d.cache).is_none());
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
}

#[tokio::test]
async fn version_2_file_is_replaced() {
    let d = dir();
    let v2 = format!(
        r#"{{"version":2,"agent":"build-agent","server":"https://warden.example.ts.net/","entries":[{{"repository":"{REPO}","repository_id":1001,"grant_id":"{}","token":"ghs_old","expires_at":{}}}]}}"#,
        Id::random(),
        NOW + 3600
    );
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&d.cache)
        .unwrap();
    fs::write(&d.cache, v2).unwrap();
    assert!(Cache::load(&d.cache).is_none());
    assert_eq!(serve(&d.cache).await, (FRESH.to_owned(), true));
    assert_eq!(stored_token(&d.cache, REPO).as_deref(), Some(FRESH));
}

#[test]
fn bad_asked_key_makes_file_unreadable() {
    // `checks:read` alone is not canonical: it lacks the `metadata:read` the
    // canonical form always holds.
    for bad in [
        "",
        "Full",
        "full",
        "checks:read",
        "metadata:read,checks:read",
        "checks:admin,metadata:read",
        "nonsense",
    ] {
        let d = dir();
        let text = format!(
            r#"{{"version":4,"agent":"build-agent","server":"https://warden.example.ts.net/","entries":[{{"repository":"{REPO}","repository_id":1001,"grant_id":"{}","token":"ghs_a","expires_at":{},"asked":"{bad}"}}]}}"#,
            Id::random(),
            NOW + 3600
        );
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&d.cache)
            .unwrap();
        fs::write(&d.cache, text).unwrap();
        assert!(Cache::load(&d.cache).is_none(), "{bad}");
    }
    let d = dir();
    let mut cache = Cache::empty(identity());
    cache.put(asked_entry("ghs_a", &Id::random(), &checks_read()));
    cache.write(&d.cache).unwrap();
    assert_eq!(
        loaded(&d.cache).entries[0].asked,
        "checks:read,metadata:read"
    );
}

/// The longest `asked` there is: every permission name proto knows at `write`
/// (or `read` where the documented levels stop there), as long as
/// `PermissionSet` allows.
fn longest_set() -> AskedSet {
    let text = known_names()
        .filter(|n| *n != "metadata")
        .map(|n| {
            let write = format!("{n}:write");
            if PermissionSet::parse(&write).is_ok() {
                write
            } else {
                format!("{n}:read")
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    AskedSet::Exactly(PermissionSet::parse(&text).unwrap())
}

#[test]
fn full_cache_with_the_longest_asked_still_fits() {
    let asked = longest_set();
    let key = asked.key();
    let token = "a".repeat(64);
    let write_with = |count: u64, token: &str, d: &Dir| {
        let mut cache = Cache::empty(identity());
        let grant = Id::random();
        for i in 0..count {
            let mut r = response(
                token,
                NOW + 3600 + i64::try_from(i).unwrap(),
                &format!("o/r{i}"),
                i,
            );
            r.grant_id = grant.clone();
            cache.put(Entry::new(r, &asked));
        }
        cache.write(&d.cache).unwrap();
        cache
    };
    // How many entries the caps let in: what is left of the byte cap after the
    // file's own bytes, divided by one entry's bound, and at most the entry cap. A name added to proto's list only
    // moves this number.
    let d = dir();
    let one = write_with(1, &token, &d);
    let overhead = one.size_bound() - one.entries[0].size_bound();
    let per_entry = one.entries[0].size_bound();
    assert!(per_entry > key.len(), "the bound counts the key");
    let fit = ((MAX_CACHE_BYTES - overhead) / per_entry).min(MAX_ENTRIES);
    assert!(fit >= 1, "one entry with the longest key fits");

    // One more than fit: the cap evicts the soonest, the newest stays, and the
    // file is written within the cap and read back.
    let count = u64::try_from(fit).unwrap() + 1;
    let cache = write_with(count, &token, &d);
    assert_eq!(cache.entries.len(), fit, "the byte cap evicted");
    assert!(
        cache.entries.iter().any(|e| e.repository_id == count - 1),
        "the newest stays"
    );
    assert!(fs::metadata(&d.cache).unwrap().len() <= u64::try_from(MAX_CACHE_BYTES).unwrap());
    assert_eq!(loaded(&d.cache).entries.len(), fit);

    // As many as fit, whole.
    let d = dir();
    let cache = write_with(u64::try_from(fit).unwrap(), &token, &d);
    assert_eq!(cache.entries.len(), fit);
    assert_eq!(loaded(&d.cache).entries.len(), fit);
}
