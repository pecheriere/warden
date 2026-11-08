//! The approval page.

use warden_broker_proto::{Fingerprint, Window};

use super::super::approve;
use super::{
    NOW, agent, api_destination, api_request, goal, pending, ssh_destination, ssh_request,
};
use crate::policy::SshMode;
use crate::requests::LinkHosts;

#[test]
fn window_picker_offers_windows_up_to_the_max_with_the_request_checked() {
    let html = approve(
        &pending(
            agent("build-agent"),
            ssh_request(goal("Deploy the nightly build"), Window::M30),
            ssh_destination(SshMode::Cert),
        ),
        &LinkHosts::default(),
        NOW,
    )
    .into_string();
    assert!(
        html.contains(r#"<fieldset><legend class="label">Grant for</legend>"#),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<input id="window-30m" type="radio" name="window" value="30m" checked><label for="window-30m">30 min</label>"#
        ),
        "{html}"
    );
    assert!(html.contains(r#"value="4h">"#), "{html}");
    assert_eq!(html.matches(r#"name="window""#).count(), 4, "{html}");
    assert_eq!(html.matches(" checked").count(), 1, "{html}");

    // The requested 4h is above the secret's 1h max: capped and preselected.
    let mut request = api_request(goal("Read device status"), &["GET"]);
    request.window = Window::H4;
    let html = approve(
        &pending(agent("build-agent"), request, api_destination()),
        &LinkHosts::default(),
        NOW,
    )
    .into_string();
    assert!(html.contains(r#"value="1h" checked>"#), "{html}");
    assert!(!html.contains(r#"value="4h""#), "{html}");
    assert!(
        html.contains(
            r#"<p class="detail capped">Asked for 4 h; at most 1 h for this secret.</p>"#
        ),
        "{html}"
    );
}

/// The vectors the proto and CLI tests share, computed outside the Rust.
#[test]
fn approve_page_shows_both_forms_of_the_shared_vectors() {
    let raw = include_str!("../../../../../proto/tests/fixtures/fingerprint-words-v1.json");
    let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let hex = vector["hex"].as_str().unwrap();
        let mut view = pending(
            agent("build-agent"),
            ssh_request(goal("Deploy the nightly build"), Window::M30),
            ssh_destination(SshMode::Cert),
        );
        view.fingerprint = Fingerprint::try_from(hex.to_owned()).unwrap();
        let html = approve(&view, &LinkHosts::default(), NOW).into_string();
        let words = format!(
            r#"<code class="fingerprint">{}</code>"#,
            vector["words"].as_str().unwrap()
        );
        assert!(html.contains(&words), "{words}: {html}");
        let hex = format!("In hex <code>{hex}</code>");
        assert!(html.contains(&hex), "{hex}: {html}");
    }
}

#[test]
fn approve_page_keeps_the_script_hooks() {
    let html = approve(
        &pending(
            agent("build-agent"),
            ssh_request(goal("Deploy the nightly build"), Window::M30),
            ssh_destination(SshMode::Cert),
        ),
        &LinkHosts::default(),
        NOW,
    )
    .into_string();
    for hook in [
        r#"<main class="split" id="approval" data-target=""#,
        r#"<span>Pending · <span id="countdown" data-remaining="240">expires in 4 min</span></span>"#,
        r#"<code class="fingerprint">exquisite-nautically-cakewalk-oscillator-angelfish</code>"#,
        r#"<span class="fp-hex">In hex <code>ab01-cd01-ef01</code></span>"#,
        r#"<button class="btn approve" id="approve" type="button">"#,
        r#"<button class="btn deny" id="deny" type="button">Deny</button>"#,
        r#"<p class="result" id="result" role="status"></p>"#,
    ] {
        assert!(html.contains(hook), "{hook}: {html}");
    }
}
