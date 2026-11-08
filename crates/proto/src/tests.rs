//! Unit tests of the wire types.

use crate::{
    Access, AgentName, ApiGrant, CreateRequest, Fingerprint, Goal, GrantAccess, GrantView, Id,
    InfoResponse, ProxyRequest, ProxyResponse, RelayGrant, RequestStatus, SecretName, SessionLabel,
    SessionLink, SshGrant, TargetName, UnixUser, Window, fingerprint, is_read_only,
    modifying_methods, signing, under_prefix,
};

fn sample_request() -> CreateRequest {
    CreateRequest {
        goal: Goal::try_from("deploy the thing".to_owned()).unwrap(),
        access: Access::Ssh {
            target: TargetName::try_from("pi".to_owned()).unwrap(),
            user: UnixUser::try_from("alice".to_owned()).unwrap(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample".to_owned(),
        },
        window: Window::M30,
        session: None,
        link: None,
    }
}

#[test]
fn agent_name_rejects_uppercase_and_long() {
    assert!(AgentName::try_from("bot-1".to_owned()).is_ok());
    assert!(AgentName::try_from("Bot".to_owned()).is_err());
    assert!(AgentName::try_from("-a".to_owned()).is_err());
    assert!(AgentName::try_from(String::new()).is_err());
    assert!(AgentName::try_from("a".repeat(32)).is_ok());
    assert!(AgentName::try_from("a".repeat(33)).is_err());
    assert!(serde_json::from_str::<AgentName>("\"BAD\"").is_err());
    assert!(TargetName::try_from("A".to_owned()).is_err());
}

#[test]
fn unix_user_rules() {
    assert!(UnixUser::try_from("_svc-1".to_owned()).is_ok());
    assert!(UnixUser::try_from("1abc".to_owned()).is_err());
    assert!(UnixUser::try_from("Root".to_owned()).is_err());
    assert!(serde_json::from_str::<UnixUser>("\"a b\"").is_err());
}

#[test]
fn goal_rejects_empty_and_501_chars() {
    assert!(Goal::try_from(String::new()).is_err());
    assert!(Goal::try_from("   ".to_owned()).is_err());
    assert!(Goal::try_from("x".repeat(500)).is_ok());
    assert!(Goal::try_from("x".repeat(501)).is_err());
    assert!(Goal::try_from("é".repeat(500)).is_ok());
    assert!(Goal::try_from("a\nb".to_owned()).is_err());
    assert!(Goal::try_from("a\u{0}b".to_owned()).is_err());
    assert_eq!(Goal::try_from("  hi  ".to_owned()).unwrap().as_str(), "hi");
    assert!(serde_json::from_str::<Goal>("\"\"").is_err());
}

#[test]
fn goal_rejects_bidi_overrides() {
    for c in [
        '\u{202A}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2069}',
    ] {
        assert!(
            Goal::try_from(format!("deploy {c}tset{c} now")).is_err(),
            "U+{:04X} accepted",
            u32::from(c)
        );
    }
}

#[test]
fn goal_rejects_zero_width_and_other_format_chars() {
    for c in [
        '\u{200B}',
        '\u{200C}',
        '\u{200D}',
        '\u{200E}',
        '\u{200F}',
        '\u{FEFF}',
        '\u{00AD}',
        '\u{2060}',
        '\u{E0001}',
    ] {
        assert!(
            Goal::try_from(format!("de{c}ploy")).is_err(),
            "U+{:04X} accepted",
            u32::from(c)
        );
    }
    // Ordinary non-ASCII text is still fine.
    assert!(Goal::try_from("redémarrer le job 🚀 日本".to_owned()).is_ok());
}

#[test]
fn goal_edge_format_chars_are_rejected_not_trimmed() {
    // Trimming removes only Unicode White_Space; a zero-width or BOM
    // character at either edge is not whitespace, so the goal is rejected
    // rather than silently trimmed.
    assert!(Goal::try_from("\u{200B}deploy".to_owned()).is_err());
    assert!(Goal::try_from("deploy\u{FEFF}".to_owned()).is_err());
    assert!(Goal::try_from(" \u{202E} deploy ".to_owned()).is_err());
    // Real whitespace at the edges is still trimmed.
    assert_eq!(
        Goal::try_from("\u{3000}deploy\u{00A0}".to_owned())
            .unwrap()
            .as_str(),
        "deploy"
    );
}

#[test]
fn window_roundtrip_and_secs() {
    let w: Window = serde_json::from_str("\"30m\"").unwrap();
    assert_eq!(w, Window::M30);
    assert_eq!(w.secs(), 1800);
    assert_eq!(serde_json::to_string(&w).unwrap(), "\"30m\"");
    assert_eq!("15m".parse::<Window>().unwrap().secs(), 900);
    assert_eq!("1h".parse::<Window>().unwrap().secs(), 3600);
    assert_eq!("4h".parse::<Window>().unwrap().secs(), 14400);
    assert!("2h".parse::<Window>().is_err());
    assert!(serde_json::from_str::<Window>("\"2h\"").is_err());
    assert!(Window::M15 < Window::M30 && Window::H1 < Window::H4);
}

#[test]
fn day_windows_are_for_commit_signing_only() {
    // Every policy's `max_window` is parsed with `FromStr`.
    for text in ["1d", "7d", "30d", "90d"] {
        assert!(text.parse::<Window>().is_err(), "{text}");
        let window = Window::commit_signing(text).unwrap();
        assert!(window.is_commit_signing());
        assert!(window > Window::H4, "a limit of 4h must refuse {text}");
        assert_eq!(
            serde_json::from_str::<Window>(&format!("\"{text}\"")).unwrap(),
            window
        );
    }
    assert!(Window::commit_signing("4h").is_err());
    assert!(!Window::H4.is_commit_signing());
    assert_eq!(Window::D30.secs(), 30 * 86_400);
}

#[test]
fn commit_signing_access_serde_shape() {
    let access = Access::CommitSigning {};
    let json = serde_json::to_string(&access).unwrap();
    assert_eq!(json, r#"{"kind":"commit_signing"}"#);
    assert_eq!(serde_json::from_str::<Access>(&json).unwrap(), access);
}

#[test]
fn id_validation_and_random() {
    let id = Id::random();
    assert_eq!(id.as_str().len(), 32);
    assert!(
        id.as_str()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_ne!(id, Id::random());
    assert!(Id::try_from("A".repeat(32)).is_err());
    assert!(Id::try_from("a".repeat(31)).is_err());
    assert!(serde_json::from_str::<Id>("\"zz\"").is_err());
}

#[test]
fn fingerprint_is_stable() {
    let agent = AgentName::try_from("bot".to_owned()).unwrap();
    let fp = fingerprint(&agent, &sample_request());
    assert_eq!(fp.as_str(), "b65b-9812-eb72");
    assert_eq!(fp, fingerprint(&agent, &sample_request()));
    let mut other = sample_request();
    other.window = Window::H1;
    assert_ne!(fp, fingerprint(&agent, &other));
    assert!(serde_json::from_str::<Fingerprint>("\"nope\"").is_err());
}

/// A request without a label or link hashes as it did before they existed,
/// so a request stored or made by an older CLI keeps its fingerprint.
#[test]
fn absent_session_and_link_leave_the_wire_form_and_fingerprint_alone() {
    let json = serde_json::to_string(&sample_request()).unwrap();
    assert!(!json.contains("session"), "{json}");
    assert!(!json.contains("link"), "{json}");
    let read: CreateRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(read, sample_request());
}

#[test]
fn session_and_link_are_part_of_the_fingerprint_and_come_last() {
    let agent = AgentName::try_from("bot".to_owned()).unwrap();
    let plain = fingerprint(&agent, &sample_request());
    let mut labelled = sample_request();
    labelled.session = Some(SessionLabel::try_from("one".to_owned()).unwrap());
    let one = fingerprint(&agent, &labelled);
    assert_ne!(plain, one);
    labelled.session = Some(SessionLabel::try_from("two".to_owned()).unwrap());
    assert_ne!(one, fingerprint(&agent, &labelled));
    let mut linked = sample_request();
    linked.link = Some(SessionLink::try_from("https://git.example.com/a".to_owned()).unwrap());
    let a = fingerprint(&agent, &linked);
    assert_ne!(plain, a);
    linked.link = Some(SessionLink::try_from("https://git.example.com/b".to_owned()).unwrap());
    assert_ne!(a, fingerprint(&agent, &linked));
    linked.session = labelled.session;
    let json = serde_json::to_string(&linked).unwrap();
    assert!(
        json.ends_with(r#""window":"30m","session":"two","link":"https://git.example.com/b"}"#),
        "{json}"
    );
    assert_eq!(
        serde_json::from_str::<CreateRequest>(&json).unwrap(),
        linked
    );
}

#[test]
fn a_bad_session_or_link_refuses_the_whole_request() {
    let json = serde_json::to_string(&sample_request()).unwrap();
    for extra in [
        r"'session':''",
        r"'session':'a\nb'",
        r"'link':'http://example.com/'",
        r"'link':'https://user:pw@example.com/'",
    ] {
        let extra = extra.replace('\'', "\"");
        let body = format!("{},{extra}}}", json.trim_end_matches('}'));
        assert!(
            serde_json::from_str::<CreateRequest>(&body).is_err(),
            "{body}"
        );
    }
}

#[test]
fn status_serde_shape() {
    assert_eq!(
        serde_json::to_string(&RequestStatus::Denied).unwrap(),
        r#"{"status":"denied"}"#
    );
    assert_eq!(
        serde_json::to_string(&RequestStatus::Pending).unwrap(),
        r#"{"status":"pending"}"#
    );
    assert_eq!(
        serde_json::to_string(&RequestStatus::Cancelled).unwrap(),
        r#"{"status":"cancelled"}"#
    );
    let e = RequestStatus::Error {
        message: "boom".to_owned(),
    };
    assert_eq!(
        serde_json::to_string(&e).unwrap(),
        r#"{"status":"error","message":"boom"}"#
    );
    let approved = RequestStatus::Approved(GrantView {
        grant_id: Id::random(),
        not_before: 1,
        not_after: 2,
        access: GrantAccess::Ssh(SshGrant {
            certificate: "cert".to_owned(),
            host: "pi".to_owned(),
            port: 22,
            user: UnixUser::try_from("alice".to_owned()).unwrap(),
            host_keys: vec!["k".to_owned()],
        }),
    });
    let json = serde_json::to_string(&approved).unwrap();
    assert!(json.starts_with(r#"{"status":"approved","grant_id":"#));
    assert_eq!(
        serde_json::from_str::<RequestStatus>(&json).unwrap(),
        approved
    );
}

#[test]
fn api_access_serde_shape() {
    let access = Access::Api {
        secret: SecretName::try_from("github".to_owned()).unwrap(),
        methods: None,
        path_prefix: None,
    };
    assert_eq!(
        serde_json::to_string(&access).unwrap(),
        r#"{"kind":"api","secret":"github"}"#
    );
    assert_eq!(
        serde_json::from_str::<Access>(r#"{"kind":"api","secret":"github"}"#).unwrap(),
        access
    );
    assert!(serde_json::from_str::<Access>(r#"{"kind":"api","secret":"Bad"}"#).is_err());
}

#[test]
fn api_request_serde_roundtrip_with_scope() {
    let access = Access::Api {
        secret: SecretName::try_from("github".to_owned()).unwrap(),
        methods: Some(vec!["GET".to_owned(), "POST".to_owned()]),
        path_prefix: Some("/v1/repos".to_owned()),
    };
    let json = serde_json::to_string(&access).unwrap();
    assert_eq!(
        json,
        r#"{"kind":"api","secret":"github","methods":["GET","POST"],"path_prefix":"/v1/repos"}"#
    );
    assert_eq!(serde_json::from_str::<Access>(&json).unwrap(), access);
}

#[test]
fn scope_fields_absent_keep_fingerprint() {
    // The request a 0.3 CLI sends (hash of its JSON checked by hand): the
    // new fields are absent from the encoding, so the fingerprint is the
    // one 0.3 computed.
    let agent = AgentName::try_from("bot".to_owned()).unwrap();
    let req = CreateRequest {
        goal: Goal::try_from("read the repos".to_owned()).unwrap(),
        access: serde_json::from_str(r#"{"kind":"api","secret":"github"}"#).unwrap(),
        window: Window::M15,
        session: None,
        link: None,
    };
    assert_eq!(
        serde_json::to_string(&req.access).unwrap(),
        r#"{"kind":"api","secret":"github"}"#
    );
    assert_eq!(fingerprint(&agent, &req).as_str(), "ae38-25c4-2428");
}

#[test]
fn read_only_methods() {
    let m = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert!(is_read_only(&m(&["GET"])));
    assert!(is_read_only(&m(&["HEAD", "GET"])));
    assert!(!is_read_only(&m(&["GET", "POST"])));
    assert!(!is_read_only(&m(&["OPTIONS"])));
    assert!(!is_read_only(&m(&[])));
}

#[test]
fn modifying_methods_names_what_is_not_read_only() {
    let m = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(modifying_methods(&m(&["GET", "HEAD"])), [] as [&str; 0]);
    assert_eq!(
        modifying_methods(&m(&["GET", "POST", "PUT"])),
        ["POST", "PUT"]
    );
    assert_eq!(modifying_methods(&m(&["OPTIONS"])), ["OPTIONS"]);
    assert_eq!(modifying_methods(&m(&[])), ["unverified scope"]);
}

#[test]
fn under_prefix_is_segment_aware() {
    assert!(under_prefix("/api", "/api"));
    assert!(under_prefix("/api/x", "/api"));
    assert!(!under_prefix("/apiary", "/api"));
    assert!(under_prefix("/api/", "/api/"));
    assert!(under_prefix("/api/x", "/api/"));
    assert!(!under_prefix("/api", "/api/"));
    assert!(under_prefix("/anything", "/"));
}

#[test]
fn grant_access_serde_tagged() {
    let api = GrantAccess::Api(ApiGrant {
        secret: SecretName::try_from("github".to_owned()).unwrap(),
        origin: "https://api.example.com".to_owned(),
        methods: vec!["GET".to_owned()],
        path_prefix: "/v1/".to_owned(),
        header: "Authorization".to_owned(),
        digest: "ab".repeat(32),
    });
    let json = serde_json::to_string(&api).unwrap();
    assert!(json.starts_with(r#"{"kind":"api","secret":"github""#));
    assert_eq!(serde_json::from_str::<GrantAccess>(&json).unwrap(), api);

    let ssh = GrantAccess::Ssh(SshGrant {
        certificate: "cert".to_owned(),
        host: "pi".to_owned(),
        port: 22,
        user: UnixUser::try_from("alice".to_owned()).unwrap(),
        host_keys: vec!["k".to_owned()],
    });
    let json = serde_json::to_string(&ssh).unwrap();
    assert!(json.starts_with(r#"{"kind":"ssh","certificate":"cert""#));
    assert_eq!(serde_json::from_str::<GrantAccess>(&json).unwrap(), ssh);

    let view = GrantView {
        grant_id: Id::random(),
        not_before: 1,
        not_after: 2,
        access: api,
    };
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains(r#""access":{"kind":"api""#));
    assert_eq!(serde_json::from_str::<GrantView>(&json).unwrap(), view);
}

#[test]
fn relay_grant_serde_tagged() {
    let relay = GrantAccess::Relay(RelayGrant {
        target: TargetName::try_from("nas".to_owned()).unwrap(),
        user: UnixUser::try_from("backup".to_owned()).unwrap(),
        relay_host: "warden.example.ts.net".to_owned(),
        relay_port: 2222,
        relay_host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample".to_owned(),
        digest: "cd".repeat(32),
    });
    let json = serde_json::to_string(&relay).unwrap();
    assert_eq!(
        json,
        format!(
            r#"{{"kind":"relay","target":"nas","user":"backup","relay_host":"warden.example.ts.net","relay_port":2222,"relay_host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample","digest":"{}"}}"#,
            "cd".repeat(32)
        )
    );
    assert_eq!(serde_json::from_str::<GrantAccess>(&json).unwrap(), relay);
    // Names are validated on the way in.
    let bad = json.replace(r#""target":"nas""#, r#""target":"Bad Name""#);
    assert!(serde_json::from_str::<GrantAccess>(&bad).is_err());

    let view = GrantView {
        grant_id: Id::random(),
        not_before: 1,
        not_after: 2,
        access: relay,
    };
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains(r#""access":{"kind":"relay","target":"nas""#));
    assert_eq!(serde_json::from_str::<GrantView>(&json).unwrap(), view);
}

#[test]
fn secret_name_rules() {
    assert!(SecretName::try_from("github".to_owned()).is_ok());
    assert!(SecretName::try_from("a".repeat(32)).is_ok());
    assert!(SecretName::try_from("a".repeat(33)).is_err());
    assert!(SecretName::try_from("Git".to_owned()).is_err());
    assert!(SecretName::try_from("-a".to_owned()).is_err());
    assert!(SecretName::try_from(String::new()).is_err());
    assert!(serde_json::from_str::<SecretName>("\"A B\"").is_err());
}

#[test]
fn ssh_fingerprint_unchanged() {
    let agent = AgentName::try_from("bot".to_owned()).unwrap();
    assert_eq!(
        fingerprint(&agent, &sample_request()).as_str(),
        "b65b-9812-eb72"
    );
    let json = serde_json::to_string(&sample_request().access).unwrap();
    assert_eq!(
        json,
        r#"{"kind":"ssh","target":"pi","user":"alice","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"}"#
    );
}

#[test]
fn proxy_request_roundtrip() {
    let req = ProxyRequest {
        method: "POST".to_owned(),
        url: "https://api.example.com/v1/x".to_owned(),
        headers: vec![("accept".to_owned(), "application/json".to_owned())],
        body_b64: Some("aGk=".to_owned()),
    };
    let json = serde_json::to_string(&req).unwrap();
    assert_eq!(serde_json::from_str::<ProxyRequest>(&json).unwrap(), req);
    let res = ProxyResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
        body_b64: "aGk=".to_owned(),
        redactions: 2,
    };
    let json = serde_json::to_string(&res).unwrap();
    assert_eq!(serde_json::from_str::<ProxyResponse>(&json).unwrap(), res);
}

#[test]
fn info_response_wire_shape() {
    let json =
        r#"{"protocols":["warden-request-v1"],"audience":"40ad20029e94984d193159667b296d8a"}"#;
    let info: InfoResponse = serde_json::from_str(json).unwrap();
    assert_eq!(info.protocols, [signing::PROTOCOL]);
    assert_eq!(serde_json::to_string(&info).unwrap(), json);
    assert!(serde_json::from_str::<InfoResponse>(r#"{"protocols":[],"audience":"nope"}"#).is_err());
}

#[test]
fn create_request_wire_shape() {
    let json = serde_json::to_string(&sample_request()).unwrap();
    assert!(json.contains(r#""access":{"kind":"ssh","target":"pi""#));
    assert_eq!(
        serde_json::from_str::<CreateRequest>(&json).unwrap(),
        sample_request()
    );
}
