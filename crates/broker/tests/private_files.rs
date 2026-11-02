//! warden's files are private to its user, whatever the directory's mode, with
//! the real `SQLite` creating its own files.

use std::fs::{self, Permissions};
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;

use warden_broker::audit::{self, AuditLog};
use warden_broker::private_files::{DirectoryState, tighten_data_directory};
use warden_broker::store;

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// A directory others can enter, in a process whose new files others can read
/// unless warden says otherwise, whatever umask the tests were started with.
fn open_directory() -> tempfile::TempDir {
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
    dir
}

/// Force a write, so `SQLite` has its WAL and SHM files in place.
async fn write(pool: &sqlx::SqlitePool) {
    sqlx::query("INSERT INTO agents (name, key_hash, created_at) VALUES ('bot', 'h', 1)")
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_new_database_and_the_files_sqlite_makes_are_private() {
    let dir = open_directory();
    let db = dir.path().join("warden.db");
    let pool = store::open(&db).await.unwrap();
    write(&pool).await;
    for name in ["warden.db", "warden.db-wal", "warden.db-shm"] {
        assert_eq!(mode(&dir.path().join(name)), 0o600, "{name}");
    }
    pool.close().await;
}

#[tokio::test]
async fn an_existing_loose_database_is_made_private_and_keeps_its_data() {
    let dir = open_directory();
    let db = dir.path().join("warden.db");
    let pool = store::open(&db).await.unwrap();
    write(&pool).await;
    pool.close().await;
    fs::set_permissions(&db, Permissions::from_mode(0o644)).unwrap();
    // Left behind by a process that stopped without closing the database.
    for name in ["warden.db-wal", "warden.db-shm"] {
        let path = dir.path().join(name);
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    }

    let pool = store::open(&db).await.unwrap();
    let agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(agents, 1);
    for name in ["warden.db", "warden.db-wal", "warden.db-shm"] {
        assert_eq!(mode(&dir.path().join(name)), 0o600, "{name}");
    }
    pool.close().await;
}

#[tokio::test]
async fn an_existing_loose_audit_log_is_made_private_and_still_verifies() {
    let dir = open_directory();
    let path = dir.path().join("audit.jsonl");
    let log = AuditLog::open(&path).await.unwrap();
    assert_eq!(mode(&path), 0o600);
    drop(log);
    fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    AuditLog::open(&path).await.unwrap();
    assert_eq!(mode(&path), 0o600);
    audit::verify(&path).unwrap();
}

#[tokio::test]
async fn a_symbolic_link_for_the_audit_log_is_refused_and_its_target_untouched() {
    let dir = open_directory();
    let target = dir.path().join("target");
    fs::write(&target, "").unwrap();
    fs::set_permissions(&target, Permissions::from_mode(0o644)).unwrap();
    let link = dir.path().join("audit.jsonl");
    symlink(&target, &link).unwrap();
    assert!(AuditLog::open(&link).await.is_err());
    assert_eq!(mode(&target), 0o644);
}

#[tokio::test]
async fn only_a_data_directory_that_is_clearly_warden_s_is_tightened() {
    let others = [Path::new("audit.jsonl"), Path::new("audience")];
    let dir = open_directory();
    let db = dir.path().join("warden.db");
    store::open(&db).await.unwrap().close().await;
    let first = tighten_data_directory(&db, &others).await.unwrap();
    if rustix::process::geteuid().is_root() {
        assert!(matches!(first, DirectoryState::Readable { .. }));
        assert_eq!(mode(dir.path()), 0o755);
    } else {
        assert_eq!(first, DirectoryState::Tightened);
        assert_eq!(mode(dir.path()), 0o700);
    }

    // The same, with something else in the directory: it is shared, like $HOME.
    let shared = open_directory();
    fs::write(shared.path().join(".profile"), "").unwrap();
    let db = shared.path().join("warden.db");
    let state = tighten_data_directory(&db, &others).await.unwrap();
    assert!(
        matches!(state, DirectoryState::Readable { .. }),
        "{state:?}"
    );
    assert_eq!(mode(shared.path()), 0o755);
}
