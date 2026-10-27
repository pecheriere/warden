//! `SQLite` pool setup and schema migrations.

use std::path::Path;

use anyhow::{Context, Result};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

/// Open (creating if missing) the database at `path` in WAL mode with foreign
/// keys enforced, and apply all pending migrations.
///
/// # Errors
///
/// Fails if the database cannot be opened or a migration cannot be applied.
pub async fn open(path: &Path) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .with_context(|| format!("opening database {}", path.display()))?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("applying database migrations")?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use sqlx::Row as _;

    use super::*;

    /// A database at the schema before migration 0003, holding requests and
    /// a grant, then migrated to the current one.
    async fn migrated_from_before_0003(dir: &tempfile::TempDir) -> SqlitePool {
        let options = SqliteConnectOptions::new()
            .filename(dir.path().join("warden.db"))
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .connect_with(options)
            .await
            .unwrap();

        let mut old = sqlx::migrate!("./migrations");
        old.migrations = Cow::Owned(
            old.migrations
                .iter()
                .filter(|m| m.version < 3)
                .cloned()
                .collect(),
        );
        old.run(&pool).await.unwrap();

        sqlx::query("INSERT INTO agents (name, key_hash, created_at) VALUES ('bot', 'h', 1)")
            .execute(&pool)
            .await
            .unwrap();
        // Explicit, non-consecutive rowids: the rebuild must keep them.
        for (rowid, id, status, dedupe) in [
            (7, "r1", "approved", "k1"),
            (3, "r2", "pending", "k2"),
            (11, "r3", "denied", "k2"),
        ] {
            sqlx::query(
                "INSERT INTO requests (rowid, id, agent, fingerprint, dedupe_key, body, \
                 approval_token_hash, status, error, created_at, expires_at, decided_at) \
                 VALUES (?4, ?1, 'bot', 'fp', ?3, '{}', 'tok-' || ?1, ?2, 'err-' || ?1, 10, 610, 20)",
            )
            .bind(id)
            .bind(status)
            .bind(dedupe)
            .bind(rowid)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO grants (rowid, id, request_id, agent, window_secs, not_before, \
             not_after, revoked_at, view) VALUES (5, 'g1', 'r1', 'bot', 900, 10, 910, 30, '{}')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    /// Migration 0003 rebuilds `requests` to widen its status CHECK; rows
    /// written under the old schema (with a grant pointing at one) survive
    /// with their rowids and columns, and the indexes and foreign keys still
    /// work.
    #[tokio::test]
    async fn request_cancelled_migration_keeps_rows_indexes_and_grants() {
        let dir = tempfile::tempdir().unwrap();
        let pool = migrated_from_before_0003(&dir).await;

        let rows = sqlx::query("SELECT rowid, id, status FROM requests ORDER BY rowid")
            .fetch_all(&pool)
            .await
            .unwrap();
        let rows: Vec<(i64, String, String)> = rows
            .iter()
            .map(|r| (r.get("rowid"), r.get("id"), r.get("status")))
            .collect();
        let row = |rowid, id: &str, status: &str| (rowid, id.to_owned(), status.to_owned());
        assert_eq!(
            rows,
            [
                row(3, "r2", "pending"),
                row(7, "r1", "approved"),
                row(11, "r3", "denied"),
            ]
        );
        let intact: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM requests WHERE error = 'err-' || id \
             AND created_at = 10 AND expires_at = 610 AND decided_at = 20",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(intact, 3);
        let grant = sqlx::query("SELECT rowid, request_id, revoked_at FROM grants")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(grant.get::<i64, _>("rowid"), 5);
        assert_eq!(grant.get::<String, _>("request_id"), "r1");
        assert_eq!(grant.get::<i64, _>("revoked_at"), 30);
        let violations = sqlx::query("PRAGMA foreign_key_check")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert!(violations.is_empty());

        let indexes: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'requests' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(indexes, ["one_pending", "requests_created_at"]);
        let grant_indexes: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'grants' \
             AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(grant_indexes, ["grants_not_after"]);
    }

    /// After migration 0003 the new status is accepted, the old ones still
    /// are, unknown ones are not, and one pending request per key holds.
    #[tokio::test]
    async fn request_cancelled_migration_widens_the_status_check() {
        let dir = tempfile::tempdir().unwrap();
        let pool = migrated_from_before_0003(&dir).await;
        // The pending uniqueness still holds, the new status is accepted, the
        // old statuses still are, and unknown ones are not.
        let insert = |id: &'static str, status: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO requests (id, agent, fingerprint, dedupe_key, body, \
                     approval_token_hash, status, created_at, expires_at) \
                     VALUES (?1, 'bot', 'fp', 'k2', '{}', 'tok-' || ?1, ?2, 10, 610)",
                )
                .bind(id)
                .bind(status)
                .execute(&pool)
                .await
            }
        };
        assert!(insert("r4", "pending").await.is_err());
        assert!(insert("r5", "cancelled").await.is_ok());
        assert!(insert("r6", "bogus").await.is_err());
    }

    /// Migration 0004 backfills `passkeys.counter` from the counter inside
    /// the stored credential; a credential without one starts at 0.
    #[tokio::test]
    async fn passkey_counter_migration_backfills_from_the_credential() {
        let dir = tempfile::tempdir().unwrap();
        let options = SqliteConnectOptions::new()
            .filename(dir.path().join("warden.db"))
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .connect_with(options)
            .await
            .unwrap();
        let mut old = sqlx::migrate!("./migrations");
        old.migrations = Cow::Owned(
            old.migrations
                .iter()
                .filter(|m| m.version < 4)
                .cloned()
                .collect(),
        );
        old.run(&pool).await.unwrap();
        for (id, credential) in [
            ("p1", r#"{"cred":{"cred_id":"x","counter":7}}"#),
            ("p2", r#"{"cred":{"cred_id":"x","counter":0}}"#),
            ("p3", r#"{"cred":{"cred_id":"x"}}"#),
        ] {
            sqlx::query(
                "INSERT INTO passkeys (id, label, credential, created_at) VALUES (?, 'l', ?, 1)",
            )
            .bind(id)
            .bind(credential)
            .execute(&pool)
            .await
            .unwrap();
        }

        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        let counters: Vec<(String, i64)> =
            sqlx::query("SELECT id, counter FROM passkeys ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap()
                .iter()
                .map(|r| (r.get("id"), r.get("counter")))
                .collect();
        assert_eq!(
            counters,
            [("p1".into(), 7), ("p2".into(), 0), ("p3".into(), 0)]
        );
    }

    /// A database at the schema before migration 0005, holding agents,
    /// requests and a grant, then migrated to the current one.
    async fn migrated_from_before_0005(dir: &tempfile::TempDir) -> SqlitePool {
        let options = SqliteConnectOptions::new()
            .filename(dir.path().join("warden.db"))
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .connect_with(options)
            .await
            .unwrap();
        let mut old = sqlx::migrate!("./migrations");
        old.migrations = Cow::Owned(
            old.migrations
                .iter()
                .filter(|m| m.version < 5)
                .cloned()
                .collect(),
        );
        old.run(&pool).await.unwrap();
        // Explicit, non-consecutive rowids: the rebuild must keep them.
        for (rowid, name, hash, revoked_at) in [
            (9, "alpha", "hash-a", None),
            (2, "beta", "hash-b", Some(77_i64)),
        ] {
            sqlx::query(
                "INSERT INTO agents (rowid, name, key_hash, created_at, revoked_at) \
                 VALUES (?, ?, ?, 5, ?)",
            )
            .bind(rowid)
            .bind(name)
            .bind(hash)
            .bind(revoked_at)
            .execute(&pool)
            .await
            .unwrap();
        }
        for (rowid, id, status, dedupe) in [(7, "r1", "approved", "k1"), (3, "r2", "pending", "k2")]
        {
            sqlx::query(
                "INSERT INTO requests (rowid, id, agent, fingerprint, dedupe_key, body, \
                 approval_token_hash, status, error, created_at, expires_at, decided_at) \
                 VALUES (?4, ?1, 'alpha', 'fp', ?3, '{}', 'tok-' || ?1, ?2, 'err-' || ?1, 10, 610, 20)",
            )
            .bind(id)
            .bind(status)
            .bind(dedupe)
            .bind(rowid)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO grants (rowid, id, request_id, agent, window_secs, not_before, \
             not_after, revoked_at, view) VALUES (5, 'g1', 'r1', 'alpha', 900, 10, 910, 30, '{}')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    /// Migration 0005 rebuilds `agents` (and, below it, `requests` and `grants`):
    /// rows written under the old schema keep their columns and rowids and
    /// become bearer agents, and the references and indexes still work.
    #[tokio::test]
    async fn agent_public_keys_migration_keeps_rows_and_references() {
        let dir = tempfile::tempdir().unwrap();
        let pool = migrated_from_before_0005(&dir).await;
        let agents: Vec<String> = sqlx::query(
            "SELECT rowid, name, key_hash, auth_kind, revoked_at, public_key, key_fingerprint \
             FROM agents ORDER BY rowid",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{}:{}:{}:{}:{:?}:{:?}:{:?}",
                r.get::<i64, _>("rowid"),
                r.get::<String, _>("name"),
                r.get::<String, _>("key_hash"),
                r.get::<String, _>("auth_kind"),
                r.get::<Option<i64>, _>("revoked_at"),
                r.get::<Option<String>, _>("public_key"),
                r.get::<Option<String>, _>("key_fingerprint"),
            )
        })
        .collect();
        assert_eq!(
            agents,
            [
                "2:beta:hash-b:bearer:Some(77):None:None",
                "9:alpha:hash-a:bearer:None:None:None"
            ]
        );
        let rowids: Vec<(i64, String)> =
            sqlx::query("SELECT rowid, id FROM requests ORDER BY rowid")
                .fetch_all(&pool)
                .await
                .unwrap()
                .iter()
                .map(|r| (r.get("rowid"), r.get("id")))
                .collect();
        assert_eq!(rowids, [(3, "r2".to_owned()), (7, "r1".to_owned())]);
        let grant = sqlx::query("SELECT rowid, request_id, revoked_at FROM grants")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(grant.get::<i64, _>("rowid"), 5);
        assert_eq!(grant.get::<String, _>("request_id"), "r1");
        assert_eq!(grant.get::<i64, _>("revoked_at"), 30);
        assert!(
            sqlx::query("PRAGMA foreign_key_check")
                .fetch_all(&pool)
                .await
                .unwrap()
                .is_empty()
        );
        // Requests still need an existing agent, and the indexes came back.
        assert!(
            sqlx::query(
                "INSERT INTO requests (id, agent, fingerprint, dedupe_key, body, \
                 approval_token_hash, status, created_at, expires_at) \
                 VALUES ('r9', 'nobody', 'fp', 'k9', '{}', 'tok-9', 'pending', 1, 2)",
            )
            .execute(&pool)
            .await
            .is_err()
        );
        let indexes: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            indexes,
            [
                "agent_nonces_expires_at",
                "agents_key_fingerprint",
                "grants_not_after",
                "one_pending",
                "requests_created_at",
            ]
        );
    }

    /// After migration 0005 bearer rows need a key hash and no key, key rows the
    /// reverse, and the kind is one of the two.
    #[tokio::test]
    async fn agent_public_keys_migration_adds_the_auth_checks() {
        let dir = tempfile::tempdir().unwrap();
        let pool = migrated_from_before_0005(&dir).await;
        // The checks: bearer rows need a key hash and no key; key rows the
        // reverse; the kind is one of the two.
        let insert = |name: &'static str,
                      kind: &'static str,
                      hash: Option<&'static str>,
                      key: Option<&'static str>| {
            let pool = pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO agents (name, auth_kind, key_hash, public_key, key_fingerprint, \
                     created_at) VALUES (?, ?, ?, ?, ?, 1)",
                )
                .bind(name)
                .bind(kind)
                .bind(hash)
                .bind(key)
                .bind(key.map(|_| format!("SHA256:{name}")))
                .execute(&pool)
                .await
            }
        };
        assert!(insert("c1", "bearer", Some("h1"), None).await.is_ok());
        assert!(
            insert("c2", "ssh-key", None, Some("ssh-ed25519 AAAA"))
                .await
                .is_ok()
        );
        assert!(insert("c3", "bearer", None, None).await.is_err());
        assert!(insert("c4", "bearer", Some("h4"), Some("k")).await.is_err());
        assert!(
            insert("c5", "ssh-key", Some("h5"), Some("k"))
                .await
                .is_err()
        );
        assert!(insert("c6", "ssh-key", None, None).await.is_err());
        assert!(insert("c7", "other", Some("h7"), None).await.is_err());
    }

    /// Migration 0005 creates the nonce table, unique per agent and nonce.
    #[tokio::test]
    async fn agent_nonces_are_unique_per_agent() {
        let dir = tempfile::tempdir().unwrap();
        let pool = migrated_from_before_0005(&dir).await;
        // The nonce table: unique per agent and nonce.
        let nonce = |agent: &'static str, nonce: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO agent_nonces (agent, nonce, expires_at) VALUES (?, ?, 100)",
                )
                .bind(agent)
                .bind(nonce)
                .execute(&pool)
                .await
            }
        };
        assert!(nonce("alpha", "n1").await.is_ok());
        assert!(nonce("alpha", "n1").await.is_err());
        assert!(nonce("beta", "n1").await.is_ok());
    }
}
