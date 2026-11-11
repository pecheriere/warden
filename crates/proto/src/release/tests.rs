use super::{CommitId, ReleaseTag, RepoName};

fn repo(s: &str) -> Result<RepoName, crate::ParseError> {
    RepoName::try_from(s.to_owned())
}

#[test]
fn repo_name_accepts_owner_slash_name() {
    let name = repo("example-owner/example-repo.v2_x").unwrap();
    assert_eq!(name.owner(), "example-owner");
    assert_eq!(name.name(), "example-repo.v2_x");
    assert!(name.matches(&repo("Example-Owner/EXAMPLE-repo.v2_x").unwrap()));
    assert!(!name.matches(&repo("example-owner/other").unwrap()));
    assert!(repo("a/b").is_ok());
    assert!(repo(&format!("{}/x", "a".repeat(39))).is_ok());
    assert!(repo(&format!("o/{}", "n".repeat(100))).is_ok());
}

#[test]
fn repo_name_refuses() {
    let long_owner = format!("{}/x", "a".repeat(40));
    let long_name = format!("o/{}", "n".repeat(101));
    for bad in [
        "owner",
        "owner/",
        "/name",
        "a/b/c",
        "owner/..",
        "owner/.",
        "-owner/x",
        "owner/na me",
        "ow_ner/x",
        "",
        &long_owner,
        &long_name,
    ] {
        assert!(repo(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn release_tag_patterns() {
    let tag = |s: &str| ReleaseTag::try_from(s.to_owned());
    assert_eq!(tag("v1.2.3").unwrap().version(), "1.2.3");
    assert_eq!(tag("v0.1.0-rc.2").unwrap().version(), "0.1.0-rc.2");
    let long = format!("v1.2.3-{}", "a".repeat(57));
    assert_eq!(long.len(), 64);
    assert!(tag(&long).is_ok());
    let too_long = format!("v1.2.3-{}", "a".repeat(58));
    for bad in [
        "1.2.3",
        "v1.2",
        "v1.2.3.4",
        "v1.2.3+meta",
        "v1.2.3-",
        "v1..3",
        "v1.2.x",
        "V1.2.3",
        "v1.2.3-a b",
        "",
        &too_long,
    ] {
        assert!(tag(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn commit_id_is_40_lower_hex() {
    let id = |s: &str| CommitId::try_from(s.to_owned());
    assert!(id(&"0123456789abcdef".repeat(3)[..40]).is_ok());
    assert!(id(&"a".repeat(64)).is_err());
    assert!(id(&"A".repeat(40)).is_err());
    assert!(id(&"a".repeat(39)).is_err());
    assert!(id(&format!("{}g", "a".repeat(39))).is_err());
}

#[test]
fn deserializing_validates() {
    assert!(serde_json::from_str::<RepoName>("\"nope\"").is_err());
    assert!(serde_json::from_str::<ReleaseTag>("\"v1\"").is_err());
    assert!(serde_json::from_str::<CommitId>("\"abc\"").is_err());
}
