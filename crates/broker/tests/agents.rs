use sha2::{Digest as _, Sha256};
use sqlx::{Row as _, SqlitePool};
use warden_broker::agents::{self, AgentError};
use warden_broker::audit::{self, AuditLog};
use warden_broker::config::{Config, ConfigError};
use warden_broker::store;
use warden_broker_proto::AgentName;

async fn pool(dir: &tempfile::TempDir) -> SqlitePool {
    store::open(&dir.path().join("warden.db")).await.unwrap()
}

fn name(s: &str) -> AgentName {
    s.parse().unwrap()
}

fn env(var: &str) -> Option<String> {
    let value = match var {
        "WARDEN_DB_PATH" => "/tmp/w.db",
        "WARDEN_AUDIT_PATH" => "/tmp/w.audit",
        "WARDEN_PUBLIC_URL" => "https://warden.example.ts.net",
        "WARDEN_OWNER_LOGIN" => "owner@example.com",
        "WARDEN_OP_CONNECT_URL" => "http://connect:8080",
        "WARDEN_OP_CONNECT_TOKEN" => "connect-secret-token",
        "WARDEN_HA_WEBHOOK_URL" => "http://ha.local/api/webhook/secret-hook-id",
        _ => return None,
    };
    Some(value.to_owned())
}

#[tokio::test]
async fn add_returns_wdn_key_and_stores_only_hash() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool(&dir).await;
    let key = agents::add(&pool, &name("bot")).await.unwrap();
    let text = key.expose().to_owned();
    assert!(text.starts_with("wdn_"));
    assert_eq!(text.len(), 4 + 43);

    let stored: String = sqlx::query("SELECT key_hash FROM agents WHERE name = 'bot'")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("key_hash");
    assert_eq!(stored, hex::encode(Sha256::digest(text.as_bytes())));

    // Flush the WAL into the main file, then scan every database file.
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes.windows(text.len()).any(|w| w == text.as_bytes()));
    }
    assert!(!format!("{key:?}").contains(&text));
}

#[tokio::test]
async fn authenticate_ok_unknown_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool(&dir).await;
    let key = agents::add(&pool, &name("bot")).await.unwrap();
    assert_eq!(
        agents::authenticate(&pool, key.expose()).await.unwrap(),
        name("bot")
    );
    assert!(matches!(
        agents::authenticate(&pool, "wdn_nope").await,
        Err(AgentError::Unknown)
    ));
    agents::revoke(&pool, &name("bot"), 1_000).await.unwrap();
    assert!(matches!(
        agents::authenticate(&pool, key.expose()).await,
        Err(AgentError::Revoked)
    ));
    let listed = agents::list(&pool).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].revoked_at, Some(1_000));
    assert!(matches!(
        agents::revoke(&pool, &name("ghost"), 1).await,
        Err(AgentError::Unknown)
    ));
}

#[tokio::test]
async fn add_duplicate_name_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool(&dir).await;
    agents::add(&pool, &name("bot")).await.unwrap();
    assert!(matches!(
        agents::add(&pool, &name("bot")).await,
        Err(AgentError::AlreadyExists)
    ));
    agents::revoke(&pool, &name("bot"), 5).await.unwrap();
    assert!(matches!(
        agents::add(&pool, &name("bot")).await,
        Err(AgentError::AlreadyExists)
    ));
}

#[test]
fn config_from_env_names_missing_variable() {
    let err = Config::from_lookup(|v| env(v).filter(|_| v != "WARDEN_OWNER_LOGIN")).unwrap_err();
    assert!(err.to_string().contains("WARDEN_OWNER_LOGIN"), "{err}");
}

#[test]
fn config_rejects_http_public_url() {
    let err = Config::from_lookup(|v| {
        if v == "WARDEN_PUBLIC_URL" {
            Some("http://warden.example.ts.net".to_owned())
        } else {
            env(v)
        }
    })
    .unwrap_err();
    assert!(err.to_string().contains("WARDEN_PUBLIC_URL"), "{err}");
}

#[test]
fn public_url_must_be_a_bare_https_origin_with_a_domain() {
    use warden_broker::config::parse_public_url;
    assert!(parse_public_url("https://warden.example.ts.net").is_ok());
    assert!(parse_public_url("https://warden.example.ts.net:8443/").is_ok());
    for bad in [
        "http://warden.example.ts.net",
        "https://192.0.2.1",
        "https://warden.example.ts.net/warden",
        "https://warden.example.ts.net/?x=1",
        "https://warden.example.ts.net/#frag",
        "https://user:pw@warden.example.ts.net",
        "not a url",
    ] {
        let err = parse_public_url(bad).unwrap_err();
        assert!(
            err.to_string().contains("WARDEN_PUBLIC_URL"),
            "{bad}: {err}"
        );
    }
}

#[test]
fn config_defaults_requires_notifier_and_redacts_secrets() {
    let cfg = Config::from_lookup(env).unwrap();
    assert_eq!(cfg.api_listen.to_string(), "127.0.0.1:8080");
    assert_eq!(cfg.approval_listen.to_string(), "127.0.0.1:8081");
    assert_eq!(cfg.vault, "Warden");
    let shown = format!("{cfg:?}");
    assert!(!shown.contains("connect-secret-token"));
    assert!(!shown.contains("secret-hook-id"));

    let err = Config::from_lookup(|v| env(v).filter(|_| v != "WARDEN_HA_WEBHOOK_URL")).unwrap_err();
    assert_eq!(err, ConfigError::NoNotifier);
}

#[test]
fn config_rejects_ntfy_token_without_ntfy_url() {
    let with_token = |v: &str| {
        if v == "WARDEN_NTFY_TOKEN" {
            Some("tk_ntfy-secret".to_owned())
        } else {
            env(v)
        }
    };
    let err = Config::from_lookup(with_token).unwrap_err();
    let shown = err.to_string();
    assert!(shown.contains("WARDEN_NTFY_TOKEN"), "{shown}");
    assert!(shown.contains("WARDEN_NTFY_URL"), "{shown}");
    assert!(!shown.contains("tk_ntfy-secret"), "{shown}");

    let cfg = Config::from_lookup(|v| {
        if v == "WARDEN_NTFY_URL" {
            Some("https://ntfy.sh/warden".to_owned())
        } else {
            with_token(v)
        }
    })
    .unwrap();
    assert!(cfg.ntfy_token.is_some());
}

#[test]
fn config_proxy_response_limit_defaults_and_bounds() {
    let cfg = Config::from_lookup(env).unwrap();
    assert_eq!(cfg.proxy.max_response_bytes, 1_048_576);
    assert_eq!(cfg.proxy.max_request_bytes, 1_048_576);
    assert_eq!(cfg.proxy.timeout.as_secs(), 30);
    assert_eq!(cfg.proxy.connect_timeout.as_secs(), 10);

    let with = |value: &'static str| {
        move |v: &str| {
            if v == "WARDEN_PROXY_MAX_RESPONSE_BYTES" {
                Some(value.to_owned())
            } else {
                env(v)
            }
        }
    };
    let cfg = Config::from_lookup(with("4096")).unwrap();
    assert_eq!(cfg.proxy.max_response_bytes, 4096);
    for bad in ["0", "-1", "1MiB", "67108865"] {
        let err = Config::from_lookup(with(bad)).unwrap_err();
        assert!(
            err.to_string().contains("WARDEN_PROXY_MAX_RESPONSE_BYTES"),
            "{bad}: {err}"
        );
    }
}

#[test]
fn config_relay_defaults_and_public_address() {
    let cfg = Config::from_lookup(env).unwrap();
    assert_eq!(cfg.relay.listen.to_string(), "127.0.0.1:2222");
    assert_eq!(
        cfg.relay.host_key_path,
        std::path::Path::new("/data/relay_host_ed25519")
    );
    assert!(cfg.relay.public_addr.is_none());

    let with = |var: &'static str, value: &'static str| {
        move |v: &str| {
            if v == var {
                Some(value.to_owned())
            } else {
                env(v)
            }
        }
    };
    let cfg = Config::from_lookup(with(
        "WARDEN_RELAY_PUBLIC_ADDR",
        "warden.example.ts.net:2222",
    ))
    .unwrap();
    let addr = cfg.relay.public_addr.unwrap();
    assert_eq!(addr.host, "warden.example.ts.net");
    assert_eq!(addr.port, 2222);
    let cfg = Config::from_lookup(with("WARDEN_RELAY_PUBLIC_ADDR", "[2001:db8::1]:22")).unwrap();
    let addr = cfg.relay.public_addr.unwrap();
    assert_eq!((addr.host.as_str(), addr.port), ("2001:db8::1", 22));

    let cfg = Config::from_lookup(with("WARDEN_RELAY_LISTEN", "0.0.0.0:2200")).unwrap();
    assert_eq!(cfg.relay.listen.to_string(), "0.0.0.0:2200");
    let cfg = Config::from_lookup(with("WARDEN_RELAY_HOST_KEY_PATH", "/keys/relay")).unwrap();
    assert_eq!(cfg.relay.host_key_path, std::path::Path::new("/keys/relay"));

    for bad in [
        "warden.example.ts.net",
        "warden.example.ts.net:0",
        "warden.example.ts.net:65536",
        "warden example:22",
        ":22",
        "2001:db8::1:22",
        "-warden:22",
    ] {
        let err = Config::from_lookup(with("WARDEN_RELAY_PUBLIC_ADDR", bad)).unwrap_err();
        assert!(
            err.to_string().contains("WARDEN_RELAY_PUBLIC_ADDR"),
            "{bad}: {err}"
        );
    }
    let err = Config::from_lookup(with("WARDEN_RELAY_LISTEN", "nope")).unwrap_err();
    assert!(err.to_string().contains("WARDEN_RELAY_LISTEN"), "{err}");
}

#[test]
fn config_relay_max_sessions() {
    let with = |value: &'static str| {
        move |v: &str| {
            if v == "WARDEN_RELAY_MAX_SESSIONS" {
                Some(value.to_owned())
            } else {
                env(v)
            }
        }
    };
    assert_eq!(Config::from_lookup(env).unwrap().relay.max_sessions, 16);
    assert_eq!(
        Config::from_lookup(with("4")).unwrap().relay.max_sessions,
        4
    );
    assert_eq!(
        Config::from_lookup(with("1024"))
            .unwrap()
            .relay
            .max_sessions,
        1024
    );
    for bad in ["0", "1025", "-1", "many", "1.5"] {
        let err = Config::from_lookup(with(bad)).unwrap_err();
        assert!(
            err.to_string().contains("WARDEN_RELAY_MAX_SESSIONS"),
            "{bad}: {err}"
        );
    }
}

#[tokio::test]
async fn add_audited_records_agent_added() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool(&dir).await;
    let path = dir.path().join("audit.jsonl");
    let audit = AuditLog::open(&path).await.unwrap();
    let key = agents::add_audited(&pool, &audit, &name("bot"))
        .await
        .unwrap();
    assert_eq!(
        agents::authenticate(&pool, key.expose()).await.unwrap(),
        name("bot")
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains(r#""event":{"type":"agent_added","agent":"bot"}"#),
        "{text}"
    );
    assert_eq!(audit::verify(&path).unwrap(), 1);
}

#[tokio::test]
async fn add_audited_revokes_agent_when_audit_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool(&dir).await;
    let path = dir.path().join("audit.jsonl");
    let audit = AuditLog::open(&path).await.unwrap();
    // Another writer holds the audit lock, so the append times out.
    let holder = std::fs::File::open(&path).unwrap();
    holder.lock().unwrap();

    let err = agents::add_audited(&pool, &audit, &name("bot"))
        .await
        .unwrap_err();
    assert!(matches!(err, AgentError::Unaudited(_)), "{err:?}");
    let listed = agents::list(&pool).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(
        listed[0].revoked_at.is_some(),
        "unaudited agent left active"
    );
}
