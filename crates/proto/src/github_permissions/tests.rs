use super::{
    GrantedPermissions, Level, MEANINGS, Permission, PermissionError, PermissionSet, SENSITIVE,
    is_sensitive, known_names, sensitive_meaning,
};

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
fn sensitive_names_parse() {
    for name in [
        "administration",
        "secrets",
        "environments",
        "dependabot_secrets",
        "repository_hooks",
        "variables",
        "organization_projects",
    ] {
        for level in ["read", "write"] {
            let permission: Permission = format!("{name}:{level}").parse().unwrap();
            assert!(permission.is_sensitive(), "{name}");
            assert_eq!(permission.name(), name);
        }
    }
    let parsed = set("workflows:write,contents:read,organization_hooks:read");
    let sensitive: Vec<_> = parsed.sensitive().map(|p| p.to_string()).collect();
    assert_eq!(sensitive, ["organization_hooks:read", "workflows:write"]);
    assert_eq!(set("checks:read").sensitive().count(), 0);
}

#[test]
fn variables_is_known_and_sensitive() {
    for level in ["read", "write"] {
        let permission = permission(&format!("variables:{level}"));
        assert_eq!(permission.name(), "variables");
        assert!(permission.is_sensitive());
    }
    assert!(is_sensitive("variables"));
    assert!(known_names().any(|name| name == "variables"));
    assert_eq!(
        set("variables:write, actions:write").to_string(),
        "actions:write,metadata:read,variables:write"
    );
    assert_eq!(set("variables:write").sensitive().count(), 1);
    assert!(set("variables:write").covers(&permission("variables:read")));
    assert_eq!(
        "variables:admin".parse::<Permission>(),
        Err(PermissionError::Admin("variables"))
    );
}

#[test]
fn every_sensitive_name_parses_and_is_flagged() {
    for (name, read, write) in MEANINGS {
        assert!(is_sensitive(name));
        for (level, documented) in [("read", read), ("write", write)] {
            assert_eq!(
                format!("{name}:{level}").parse::<Permission>().is_ok(),
                documented.is_some(),
                "{name}:{level}"
            );
        }
    }
    assert!(!is_sensitive("checks"));
    assert!(!is_sensitive("organization_anything"));
}

#[test]
fn levels_github_does_not_document_are_refused() {
    for (text, name, level) in [
        ("workflows:read", "workflows", Level::Read),
        (
            "organization_copilot_requests:write",
            "organization_copilot_requests",
            Level::Write,
        ),
        (
            "organization_events:write",
            "organization_events",
            Level::Write,
        ),
        ("organization_plan:write", "organization_plan", Level::Write),
    ] {
        let err = PermissionSet::parse(text).unwrap_err();
        assert_eq!(
            err,
            PermissionError::LevelNotDocumented(name, level),
            "{text}"
        );
        assert!(err.to_string().contains(name), "{text}");
        assert!(text.parse::<Permission>().is_err(), "{text}");
    }
    // The levels it does document still parse.
    for text in [
        "workflows:write",
        "organization_copilot_requests:read",
        "organization_events:read",
        "organization_plan:read",
    ] {
        assert!(text.parse::<Permission>().is_ok(), "{text}");
    }
}

#[test]
fn undocumented_organization_name_is_unknown() {
    let err = PermissionSet::parse("organization_secret_thing:read").unwrap_err();
    assert_eq!(err, PermissionError::Unknown);
    assert!(!err.to_string().contains("secret_thing"));
}

#[test]
fn admin_level_still_refused_on_sensitive() {
    assert_eq!(
        PermissionSet::parse("workflows:admin").unwrap_err(),
        PermissionError::Admin("workflows")
    );
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
fn intersection_takes_the_lower_level() {
    assert_eq!(
        set("contents:write").intersection(&set("contents:read")),
        set("contents:read")
    );
    assert_eq!(
        set("contents:read").intersection(&set("contents:write")),
        set("contents:read")
    );
    // A name in one set only is dropped; `metadata:read` is in both, so it stays.
    let both = set("contents:write,pull_requests:write")
        .intersection(&set("actions:write,contents:write,workflows:write"));
    assert_eq!(both.to_string(), "contents:write,metadata:read");
    assert_eq!(
        set("issues:write").intersection(&set("actions:write")),
        PermissionSet::metadata_only()
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

#[test]
fn granted_permissions_write_the_same_canonical_form() {
    for text in [
        "pull_requests:write, contents:write,issues:write",
        "checks:read",
        "metadata:read",
    ] {
        let strict = set(text);
        let lenient = GrantedPermissions::parse(text).unwrap();
        assert_eq!(lenient.as_str(), strict.to_string());
        assert_eq!(lenient, GrantedPermissions::from(&strict));
        assert_eq!(lenient.known().unwrap(), strict);
    }
    assert_eq!(
        GrantedPermissions::legacy().as_str(),
        PermissionSet::legacy().to_string()
    );
}

#[test]
fn granted_permissions_keep_unknown_names_but_act_on_none() {
    let set = GrantedPermissions::parse("zeta_9:read,contents:write").unwrap();
    assert_eq!(set.as_str(), "contents:write,metadata:read,zeta_9:read");
    assert_eq!(set.known(), Err(PermissionError::Unknown));
    let json = serde_json::to_string(&set).unwrap();
    assert_eq!(
        serde_json::from_str::<GrantedPermissions>(&json).unwrap(),
        set
    );
}

#[test]
fn granted_permissions_accepts_sensitive() {
    let held = GrantedPermissions::parse("workflows:write").unwrap();
    assert_eq!(
        held.known().unwrap().to_string(),
        "metadata:read,workflows:write"
    );
}

#[test]
fn granted_permissions_refuse_malformed_entries() {
    let long = format!("{}:read", "a".repeat(65));
    for text in [
        "",
        "contents",
        "contents:",
        ":read",
        "contents:admin",
        "contents:Write",
        "Contents:read",
        "con tents:read",
        "con-tents:read",
        "contents:read,,issues:read",
        "contents:read,contents:write",
        "metadata:write",
        long.as_str(),
    ] {
        assert_eq!(
            GrantedPermissions::parse(text),
            Err(PermissionError::Malformed),
            "{text:?}"
        );
    }
    assert!(GrantedPermissions::parse(&format!("{}:read", "a".repeat(64))).is_ok());
}

#[test]
fn every_sensitive_name_has_its_own_meaning() {
    let names: Vec<_> = MEANINGS.iter().map(|(name, _, _)| *name).collect();
    assert_eq!(names, SENSITIVE);
    let checks: Permission = "checks:read".parse().unwrap();
    for name in SENSITIVE {
        for level in ["read", "write"] {
            let Ok(permission) = format!("{name}:{level}").parse::<Permission>() else {
                continue;
            };
            let meaning = sensitive_meaning(&permission);
            assert!(!meaning.is_empty(), "{permission}");
            assert_ne!(meaning, sensitive_meaning(&checks), "{permission}");
        }
    }
    let workflows: Permission = "workflows:write".parse().unwrap();
    assert_eq!(
        sensitive_meaning(&workflows),
        "create and change GitHub Actions workflow files, which run with the repository's secrets"
    );
}

#[test]
fn meanings_follow_the_level() {
    let meaning = |text: &str| sensitive_meaning(&text.parse::<Permission>().unwrap());
    // Secret values are never readable through the API, so read only lists names.
    for name in ["secrets", "dependabot_secrets", "organization_secrets"] {
        let read = meaning(&format!("{name}:read"));
        let write = meaning(&format!("{name}:write"));
        assert!(read.starts_with("list the names of"), "{name}: {read}");
        assert!(
            write.starts_with("create, replace and delete"),
            "{name}: {write}"
        );
    }
    // A read never says more than reading.
    for (name, read, write) in MEANINGS {
        if let (Some(read), Some(write)) = (read, write) {
            for word in [
                "manage",
                "create",
                "delete",
                "publish",
                "approve",
                "block and",
            ] {
                assert!(!read.contains(word), "{name}: {read}");
            }
            assert!(!write.is_empty(), "{name}");
        }
    }
}

#[test]
fn written_form_without_metadata() {
    let parsed = GrantedPermissions::parse("workflows:write,checks:read").unwrap();
    assert_eq!(
        parsed.without_metadata().as_deref(),
        Some("checks:read,workflows:write")
    );
    let only = GrantedPermissions::parse("metadata:read").unwrap();
    assert_eq!(only.without_metadata(), None);
}
