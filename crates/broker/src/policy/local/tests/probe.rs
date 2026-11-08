//! The probe, and the audit of refused opens and requests.

use std::fs;
use std::sync::Arc;

use super::{API_ENTRY, Setup, ca_policy, cert_entry, chmod, ed25519_pem, secret};
use crate::audit::AuditLog;
use crate::policy::local::{LocalBackend, LocalProbe};
use crate::policy::{CaProbe, SecretBackend};

#[tokio::test]
async fn the_probe_passes_a_good_setup() {
    let setup = Setup::new(&(ca_policy() + API_ENTRY));
    setup.secret("ssh-ca", &ed25519_pem());
    let probe = setup.backend.probe().await;
    assert!(probe.problems().is_empty(), "{probe:?}");
    let LocalProbe::Read {
        targets,
        api_secrets,
        ca,
        ..
    } = probe
    else {
        panic!("expected Read");
    };
    assert_eq!((targets, api_secrets), (1, 1));
    assert!(matches!(ca, CaProbe::Loaded { .. }));
}

#[tokio::test]
async fn the_probe_lists_every_problem_and_never_a_secret() {
    let policy = format!(
        "{API_ENTRY}\n[api_secrets.Bad_Name]\ncredential_file = \"x\"\n\
         [targets.pi]\nmode = \"cert\"\n"
    );
    let setup = Setup::new(&policy);
    chmod(&setup.secret_path("home-api"), 0o644);
    let probe = setup.backend.probe().await;
    let problems = probe.problems();
    assert_eq!(problems.len(), 3, "{problems:?}");
    let shown = problems.join("\n");
    assert!(shown.contains("home-api"), "{shown}");
    assert!(shown.contains("Bad_Name"), "{shown}");
    assert!(shown.contains("\"pi\""), "{shown}");
    Setup::assert_no_secret(&shown);
}

#[tokio::test]
async fn the_probe_lists_a_target_with_an_unusable_name() {
    let setup = Setup::new("[targets.Bad_Name]\nmode = \"cert\"\n");
    let probe = setup.backend.probe().await;
    let problems = probe.problems();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("Bad_Name"), "{problems:?}");
    assert!(problems[0].contains("target name"), "{problems:?}");
}

#[tokio::test]
async fn the_probe_tells_a_needed_ca_from_an_unneeded_one() {
    let needed = Setup::new(&cert_entry()).backend.probe().await;
    let LocalProbe::Read { ca, .. } = &needed else {
        panic!("expected Read");
    };
    assert_eq!(*ca, CaProbe::Missing { cert_targets: 1 });
    assert_eq!(needed.problems().len(), 1);

    let unneeded = Setup::new(API_ENTRY).backend.probe().await;
    let LocalProbe::Read { ca, .. } = &unneeded else {
        panic!("expected Read");
    };
    assert_eq!(*ca, CaProbe::NotNeeded);
    assert_eq!(unneeded.problems(), Vec::<String>::new());
}

#[tokio::test]
async fn open_refuses_and_audits_anything_invalid_and_never_a_secret() {
    let setup = Setup::new(API_ENTRY);
    chmod(&setup.secret_path("home-api"), 0o644);
    let audit_path = setup.root.join("audit.jsonl");
    let audit = Arc::new(AuditLog::open(&audit_path).await.unwrap());
    let error = LocalBackend::open(&setup.settings, audit.clone())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("home-api"), "{error}");
    let log = fs::read_to_string(&audit_path).unwrap();
    assert!(log.contains("local secret backend"), "{log}");
    assert!(log.contains("home-api"), "{log}");
    Setup::assert_no_secret(&log);

    chmod(&setup.secret_path("home-api"), 0o600);
    assert!(LocalBackend::open(&setup.settings, audit).await.is_ok());
}

#[tokio::test]
async fn a_refused_request_is_audited_but_an_unknown_name_is_not() {
    let setup = Setup::new(API_ENTRY);
    let audit_path = setup.root.join("audit.jsonl");
    let audit = Arc::new(AuditLog::open(&audit_path).await.unwrap());
    let backend = LocalBackend::open(&setup.settings, audit).await.unwrap();

    assert!(backend.api_secret(&secret("absent")).await.is_err());
    assert_eq!(fs::read_to_string(&audit_path).unwrap(), "");

    chmod(&setup.secret_path("home-api"), 0o644);
    assert!(backend.api_secret(&secret("home-api")).await.is_err());
    let log = fs::read_to_string(&audit_path).unwrap();
    assert_eq!(log.lines().count(), 1, "{log}");
    assert!(log.contains("group or others"), "{log}");
    Setup::assert_no_secret(&log);
}
