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

    /// Migration 0003 rebuilds `requests` to widen its status CHECK; rows
    /// written under the old schema (with a grant pointing at one) survive
    /// with their order, and the indexes and foreign keys still work.
    #[tokio::test]
    async fn request_cancelled_migration_keeps_rows_indexes_and_grants() {
        let dir = tempfile::tempdir().unwrap();
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
        for (id, status, dedupe) in [
            ("r1", "approved", "k1"),
            ("r2", "pending", "k2"),
            ("r3", "denied", "k2"),
        ] {
            sqlx::query(
                "INSERT INTO requests (id, agent, fingerprint, dedupe_key, body, \
                 approval_token_hash, status, created_at, expires_at) \
                 VALUES (?1, 'bot', 'fp', ?3, '{}', 'tok-' || ?1, ?2, 10, 610)",
            )
            .bind(id)
            .bind(status)
            .bind(dedupe)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO grants (id, request_id, agent, window_secs, not_before, not_after, view) \
             VALUES ('g1', 'r1', 'bot', 900, 10, 910, '{}')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        let rows = sqlx::query("SELECT id, status FROM requests ORDER BY rowid")
            .fetch_all(&pool)
            .await
            .unwrap();
        let rows: Vec<(String, String)> = rows
            .iter()
            .map(|r| (r.get("id"), r.get("status")))
            .collect();
        assert_eq!(
            rows,
            [
                ("r1".to_owned(), "approved".to_owned()),
                ("r2".to_owned(), "pending".to_owned()),
                ("r3".to_owned(), "denied".to_owned()),
            ]
        );
        let grant: String = sqlx::query_scalar("SELECT request_id FROM grants")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(grant, "r1");
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
}
