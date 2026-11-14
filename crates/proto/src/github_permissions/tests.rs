use super::{Level, Permission, PermissionError, PermissionSet, under_ceiling};

fn set(text: &str) -> PermissionSet {
    PermissionSet::parse(text).unwrap()
}

fn permission(text: &str) -> Permission {
    text.parse().unwrap()
}

#[test]
fn parses_canonical_and_adds_metadata() {
    assert_eq!(
        set("checks:read, actions:read").to_string(),
        "actions:read,checks:read,metadata:read"
    );
}

#[test]
fn refuses_typos() {
    for text in [
        "Checks:read",
        "checks:read,",
        "",
        "checks",
        "checks:admin",
        "checks:read,checks:write",
        "metadata:write",
        "no_such:read",
    ] {
        assert!(PermissionSet::parse(text).is_err(), "{text:?}");
    }
    let err = PermissionSet::parse("no_such:read").unwrap_err();
    assert!(!err.to_string().contains("no_such"));
    assert_eq!(err, PermissionError::Unknown);
    assert_eq!(
        PermissionSet::parse("checks:admin").unwrap_err(),
        PermissionError::Admin("checks")
    );
}

#[test]
fn refuses_ceiling() {
    for text in [
        "workflows:write",
        "administration:read",
        "secrets:read",
        "environments:read",
        "organization_projects:read",
        "dependabot_secrets:read",
    ] {
        assert_eq!(
            PermissionSet::parse(text).unwrap_err(),
            PermissionError::Ceiling,
            "{text}"
        );
    }
    assert!(under_ceiling("organization_anything"));
    assert!(!under_ceiling("checks"));
    let err = PermissionSet::parse("organization_secret_thing:read").unwrap_err();
    assert!(!err.to_string().contains("secret_thing"));
}

#[test]
fn write_covers_read() {
    let have = set("checks:write,actions:read");
    assert!(have.covers(&permission("checks:read")));
    assert!(have.covers(&permission("checks:write")));
    assert!(have.covers(&permission("actions:read")));
    assert!(!have.covers(&permission("actions:write")));
    assert!(!have.covers(&permission("issues:read")));
    assert!(have.covers_all(&set("checks:read")));
    assert!(!set("checks:read").covers_all(&have));
    assert!(Level::Read < Level::Write);
}

#[test]
fn union_takes_higher_level() {
    let both = set("checks:read,actions:write").union(&set("checks:write,issues:read"));
    assert_eq!(
        both.to_string(),
        "actions:write,checks:write,issues:read,metadata:read"
    );
}

#[test]
fn missing_from_lists_uncovered() {
    let missing = set("checks:write,actions:read").missing_from(&set("checks:read,actions:read"));
    assert_eq!(missing, vec![permission("checks:write")]);
}

#[test]
fn extras_beyond_default_skips_covered_and_metadata() {
    let extras = set("contents:write,checks:read,issues:write,pull_requests:read")
        .extras_beyond(&PermissionSet::legacy());
    assert_eq!(extras.to_string(), "checks:read");
    assert!(
        set("contents:read")
            .extras_beyond(&PermissionSet::legacy())
            .iter()
            .next()
            .is_none()
    );
}

#[test]
fn only_metadata() {
    assert!(set("metadata:read").is_only_metadata());
    assert!(!set("checks:read").is_only_metadata());
}

#[test]
fn legacy_is_todays_four() {
    assert_eq!(
        PermissionSet::legacy().to_string(),
        "contents:write,issues:write,metadata:read,pull_requests:write"
    );
}

#[test]
fn serde_round_trips_as_string() {
    let value = set("checks:read");
    let json = serde_json::to_string(&value).unwrap();
    assert_eq!(json, "\"checks:read,metadata:read\"");
    assert_eq!(serde_json::from_str::<PermissionSet>(&json).unwrap(), value);
    assert!(serde_json::from_str::<PermissionSet>("\"checks\"").is_err());
}
