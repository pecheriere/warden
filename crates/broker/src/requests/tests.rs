//! Query plans and results of the request lifecycle's constant queries.

use super::create::LIVE_SSH_KEYS;
use super::grants::{ACTIVE_RELAY_GRANTS, ENDED_GRANTS};
use crate::store;
use sqlx::Row as _;

/// The query plan of `sql`, one step per line.
async fn plan(pool: &sqlx::SqlitePool, sql: &str) -> Vec<String> {
    // Test-only: `sql` is one of this module's constant queries.
    sqlx::query(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
        .bind(0_i64)
        .bind("x")
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<String, _>("detail"))
        .collect()
}

#[tokio::test]
async fn live_access_lookups_never_scan_whole_tables() {
    let dir = tempfile::tempdir().unwrap();
    let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
    let keys = plan(&pool, LIVE_SSH_KEYS).await;
    assert!(
        keys.iter()
            .any(|s| s.contains("USING INDEX requests_created_at")),
        "{keys:?}"
    );
    let grants = plan(&pool, ACTIVE_RELAY_GRANTS).await;
    for steps in [&keys, &grants] {
        assert!(
            steps
                .iter()
                .any(|s| s.contains("USING INDEX grants_not_after")),
            "{steps:?}"
        );
        // A bare SCAN reads every row of a table.
        assert!(
            !steps
                .iter()
                .any(|s| s.starts_with("SCAN ") && !s.contains("INDEX")),
            "{steps:?}"
        );
    }
    // The relay's check looks grants up by id.
    let ended = plan(&pool, ENDED_GRANTS).await;
    assert!(
        ended
            .iter()
            .any(|s| s.starts_with("SEARCH grants USING INDEX sqlite_autoindex_grants_1")),
        "{ended:?}"
    );
    assert!(
        !ended.iter().any(|s| s.starts_with("SCAN grants")),
        "{ended:?}"
    );
}

#[tokio::test]
async fn ended_grants_are_the_listed_revoked_or_expired_ones() {
    let dir = tempfile::tempdir().unwrap();
    let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    // Bare grant rows: their requests and agents do not matter here.
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    for (id, not_after, revoked_at) in [
        ("live", 1000, None),
        ("revoked", 1000, Some(500)),
        ("expired", 1000, None),
        ("both", 900, Some(800)),
        ("unlisted", 900, Some(800)),
    ] {
        let not_after = if id == "expired" { 999 } else { not_after };
        sqlx::query(
            "INSERT INTO grants (id, request_id, agent, window_secs, not_before, not_after, revoked_at, view) \
             VALUES (?, ?, 'a', 900, 0, ?, ?, '{}')",
        )
        .bind(id)
        .bind(format!("r-{id}"))
        .bind(not_after)
        .bind(revoked_at)
        .execute(&mut *conn)
        .await
        .unwrap();
    }
    let mut ended: Vec<(String, bool)> = sqlx::query(ENDED_GRANTS)
        .bind(999_i64)
        .bind(r#"["live","revoked","expired","both","missing"]"#)
        .fetch_all(&mut *conn)
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get("id"), row.get("revoked")))
        .collect();
    ended.sort();
    assert_eq!(
        ended,
        [
            ("both".to_owned(), true),
            ("expired".to_owned(), false),
            ("revoked".to_owned(), true),
        ]
    );
}
