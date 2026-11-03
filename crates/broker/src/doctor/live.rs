//! The real [`Environment`] of `warden-server doctor`.

use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tokio::net::TcpStream;
use warden_broker_proto::doctor::Report;

use super::{Environment, ListenerProbe, PasskeyProbe, PathFacts, examine, invalid_config_report};
use crate::approval::passkeys;
use crate::config::{BackendSettings, Config};
use crate::health::probe_target;
use crate::notify::{ChannelSettings, Doorbell, NotifyError};
use crate::policy::{
    CaProbe, CommitSigningProbe, LocalBackend, LocalProbe, OnePasswordConnect, VaultProbe,
};
use crate::requests::revocation::count_waiting_read_only;

/// How long a listener has to accept a connection.
const LISTENER_TIMEOUT: Duration = Duration::from_secs(3);

/// How long one channel has to accept the test notification, as for a real
/// notification.
const RING_TIMEOUT: Duration = Duration::from_secs(5);

/// Doctor's report for this process's environment.
pub async fn report(send_test_notification: bool) -> Report {
    // This reads secret files. The binary runs on the multi-thread runtime,
    // which `block_in_place` needs.
    match tokio::task::block_in_place(Config::from_env) {
        Err(e) => invalid_config_report(&e),
        Ok(config) => {
            let env = Live::new(&config);
            examine(&config, &env, send_test_notification).await
        }
    }
}

/// What [`examine`] would be told about a backend that is not the configured
/// one. It never asks, and the answer must not read as a working backend.
const NOT_CONFIGURED: &str = "this secret backend is not the configured one";

enum Live {
    OnePassword(OnePasswordConnect),
    Local(LocalBackend),
}

impl Live {
    fn new(config: &Config) -> Self {
        match &config.backend {
            BackendSettings::OnePassword(connect) => Self::OnePassword(OnePasswordConnect::new(
                connect.url.clone(),
                connect.token.clone(),
                connect.vault.clone(),
            )),
            BackendSettings::Local(settings) => Self::Local(LocalBackend::unaudited(settings)),
        }
    }
}

/// Open the database read-only, never creating or migrating it, and count its
/// passkeys. With no journal mode set, the connection leaves the file's as it
/// is. On a database in WAL mode, `SQLite` itself may create the `-shm` file
/// that readers share.
async fn count_passkeys(db: &Path) -> Result<usize, String> {
    let options = SqliteConnectOptions::new()
        .filename(db)
        .create_if_missing(false)
        .read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|e| e.to_string())?;
    let listed = passkeys::list(&pool).await.map_err(|e| e.to_string());
    pool.close().await;
    listed.map(|list| list.len())
}

#[async_trait]
impl Environment for Live {
    async fn vault(&self) -> VaultProbe {
        match self {
            Self::OnePassword(connect) => connect.probe_vault().await,
            Self::Local(_) => VaultProbe::Unhealthy(NOT_CONFIGURED.to_owned()),
        }
    }

    async fn ca(&self) -> CaProbe {
        match self {
            Self::OnePassword(connect) => connect.probe_ca().await,
            Self::Local(_) => CaProbe::Unknown(NOT_CONFIGURED.to_owned()),
        }
    }

    async fn commit_signing(&self) -> CommitSigningProbe {
        match self {
            Self::OnePassword(connect) => connect.probe_commit_signing().await,
            Self::Local(_) => CommitSigningProbe::Unknown(NOT_CONFIGURED.to_owned()),
        }
    }

    async fn local(&self) -> LocalProbe {
        match self {
            Self::OnePassword(_) => LocalProbe::Unreadable(NOT_CONFIGURED.to_owned()),
            Self::Local(backend) => backend.probe().await,
        }
    }

    async fn ring(
        &self,
        channel: &ChannelSettings,
        doorbell: &Doorbell,
    ) -> Result<(), NotifyError> {
        let notifier = channel.build()?;
        match tokio::time::timeout(RING_TIMEOUT, notifier.ring(doorbell)).await {
            Ok(rung) => rung.map(|_channel| ()),
            Err(_elapsed) => Err(NotifyError::Timeout {
                notifier: channel.kind().name(),
                after: RING_TIMEOUT,
            }),
        }
    }

    async fn passkeys(&self, db: &Path) -> PasskeyProbe {
        match tokio::fs::symlink_metadata(db).await {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return PasskeyProbe::NoDatabase,
            Err(e) => return PasskeyProbe::Unreadable(e.to_string()),
            Ok(_) => {}
        }
        match count_passkeys(db).await {
            Ok(count) => PasskeyProbe::Enrolled(count),
            Err(reason) => PasskeyProbe::Unreadable(reason),
        }
    }

    async fn waiting_entries(&self, db: &Path) -> Result<i64, String> {
        // With no database there is nothing waiting: the passkey check reports it.
        match tokio::fs::symlink_metadata(db).await {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
            _ => count_waiting_read_only(db).await,
        }
    }

    async fn listener(&self, addr: SocketAddr) -> ListenerProbe {
        let target = probe_target(addr);
        match tokio::time::timeout(LISTENER_TIMEOUT, TcpStream::connect(target)).await {
            Ok(Ok(_stream)) => ListenerProbe::Accepted,
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => ListenerProbe::Refused,
            Ok(Err(e)) => ListenerProbe::Inconclusive(e.to_string()),
            Err(_elapsed) => ListenerProbe::Inconclusive(format!(
                "no answer within {} s",
                LISTENER_TIMEOUT.as_secs()
            )),
        }
    }

    async fn path_facts(&self, path: &Path) -> io::Result<PathFacts> {
        let meta = tokio::fs::symlink_metadata(path).await?;
        Ok(PathFacts {
            is_dir: meta.is_dir(),
            is_file: meta.is_file(),
            uid: meta.uid(),
            mode: meta.permissions().mode(),
        })
    }

    fn euid(&self) -> u32 {
        rustix::process::geteuid().as_raw()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use secrecy::SecretString;
    use url::Url;

    use super::{Environment, ListenerProbe, Live, PasskeyProbe};
    use crate::store;

    fn live() -> Live {
        Live::OnePassword(crate::policy::OnePasswordConnect::new(
            Url::parse("http://connect.invalid").unwrap(),
            SecretString::from("unused"),
            "Warden".to_owned(),
        ))
    }

    #[tokio::test]
    async fn a_missing_database_is_reported_and_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("warden.db");
        assert_eq!(live().passkeys(&db).await, PasskeyProbe::NoDatabase);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn counting_passkeys_leaves_the_database_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("warden.db");
        let pool = store::open(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO passkeys (id, label, credential, created_at) VALUES ('a', 'l', 'c', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
        let before = fs::read(&db).unwrap();
        assert_eq!(live().passkeys(&db).await, PasskeyProbe::Enrolled(1));
        assert_eq!(fs::read(&db).unwrap(), before);
    }

    #[tokio::test]
    async fn a_file_that_is_no_database_is_unreadable_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("warden.db");
        fs::write(&db, "not a database, and long enough to be read as one").unwrap();
        let probe = live().passkeys(&db).await;
        assert!(matches!(probe, PasskeyProbe::Unreadable(_)), "{probe:?}");
        assert!(
            fs::read_to_string(&db)
                .unwrap()
                .starts_with("not a database")
        );
    }

    #[tokio::test]
    async fn a_database_without_the_table_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("warden.db");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&db)
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
        sqlx::query("CREATE TABLE other (x INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let probe = live().passkeys(&db).await;
        assert!(matches!(probe, PasskeyProbe::Unreadable(_)), "{probe:?}");
    }

    #[tokio::test]
    async fn listeners_accept_or_refuse() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert_eq!(live().listener(addr).await, ListenerProbe::Accepted);
        drop(listener);
        assert_eq!(live().listener(addr).await, ListenerProbe::Refused);
    }

    #[tokio::test]
    async fn path_facts_do_not_follow_links() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, "x").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let env = live();
        let facts = env.path_facts(&file).await.unwrap();
        assert!(facts.is_file);
        assert_eq!(facts.mode & 0o777, 0o640);
        assert_eq!(facts.uid, env.euid());
        let facts = env.path_facts(&link).await.unwrap();
        assert!(!facts.is_file && !facts.is_dir);
    }
}
