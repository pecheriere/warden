//! Fixtures for the release pages, and the pages they make for the checks that
//! render every page and for the screenshots.

use maud::Markup;
use warden_broker_proto::release::{CommitId, ReleaseGrant, ReleaseTag, RepoName};
use warden_broker_proto::{Access, CreateRequest, GrantAccess, Window};

use super::{NOW, active, agent, approve, fingerprint, goal, grants, history, id, idle};
use crate::requests::{
    ActiveGrant, Destination, HistoryEntry, LinkHosts, PendingEntry, PendingView, ReleaseFacts,
    ReleasePolicy, ReleaseProgress,
};

pub(super) const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
pub(super) const KEY: &str = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8";

pub(super) fn release_request() -> CreateRequest {
    CreateRequest {
        goal: goal("Release 1.2.3 of the example project"),
        access: Access::Release {
            repository: RepoName::try_from("example-owner/example-repo".to_owned()).unwrap(),
            tag: ReleaseTag::try_from("v1.2.3".to_owned()).unwrap(),
            commit: CommitId::try_from(COMMIT.to_owned()).unwrap(),
        },
        window: Window::D1,
        session: None,
        link: None,
    }
}

pub(super) fn release_policy() -> ReleasePolicy {
    ReleasePolicy {
        repository: RepoName::try_from("example-owner/example-repo".to_owned()).unwrap(),
        key_fingerprint: KEY.to_owned(),
        manifest: Some("example-1.2.3-SHA256SUMS".to_owned()),
        publish: true,
        key_digest: "1".repeat(64),
        app_digest: "2".repeat(64),
    }
}

pub(super) fn release_facts(changelog: Option<&str>) -> ReleaseFacts {
    ReleaseFacts {
        commit_title: "Add the release workflow".to_owned(),
        commit_date: "2026-11-07T10:30:00Z".to_owned(),
        on_default_branch: true,
        changelog: changelog.map(str::to_owned),
        changelog_cut: false,
        tag_in_place: false,
        previous_tag: Some(ReleaseTag::try_from("v1.2.2".to_owned()).unwrap()),
    }
}

pub(super) const CHANGELOG: &str = "### Added\n\n- The release workflow.\n- A `--dry-run` flag.\n\n### Fixed\n\n- A crash when the manifest is empty.";

pub(super) fn release_view(facts: ReleaseFacts) -> PendingView {
    PendingView {
        id: id(1),
        agent: agent("build-agent"),
        fingerprint: fingerprint(1),
        request: release_request(),
        destination: Destination::Release(release_policy()),
        expires_at: NOW + 240,
        release: Some(facts),
        github: None,
    }
}

pub(super) fn release_grants(progress: ReleaseProgress) -> Vec<ActiveGrant> {
    let policy = release_policy();
    let mut grant = active(
        11,
        release_request(),
        GrantAccess::Release(ReleaseGrant {
            repository: policy.repository.clone(),
            tag: ReleaseTag::try_from("v1.2.3".to_owned()).unwrap(),
            commit: CommitId::try_from(COMMIT.to_owned()).unwrap(),
            key_fingerprint: policy.key_fingerprint.clone(),
            steps: policy.steps(false),
            digest: policy.digest(),
        }),
    );
    grant.not_after = NOW + 20 * 3600;
    grant.release = Some(progress);
    vec![grant]
}

pub(super) const HALFWAY: ReleaseProgress = ReleaseProgress {
    tag: true,
    manifest: false,
    publish: false,
};

fn pending_entry() -> PendingEntry {
    PendingEntry {
        id: id(11),
        agent: agent("build-agent"),
        fingerprint: fingerprint(11),
        request: release_request(),
        destination: Some(Destination::Release(release_policy())),
        expires_at: NOW + 240,
    }
}

/// The pages of a release request and grant.
pub(super) fn release_pages() -> Vec<(&'static str, Markup)> {
    let hosts = LinkHosts::default();
    let mut in_place = release_facts(Some(CHANGELOG));
    in_place.tag_in_place = true;
    let mut hostile = release_facts(Some(
        "<script>alert(1)</script> & \u{1b}[31mred\u{1b}[0m\n\u{202e}gnp.exe\n\u{2026}(cut)",
    ));
    hostile.changelog_cut = true;
    hostile.commit_title = "<b>Fix</b> \u{1b}[2J the build".to_owned();
    vec![
        (
            "approve-release",
            approve(&release_view(release_facts(Some(CHANGELOG))), &hosts, NOW),
        ),
        (
            "approve-release-tag-in-place",
            approve(&release_view(in_place), &hosts, NOW),
        ),
        (
            "approve-release-no-changelog",
            approve(&release_view(release_facts(None)), &hosts, NOW),
        ),
        (
            "approve-release-hostile",
            approve(&release_view(hostile), &hosts, NOW),
        ),
        (
            "pending-release",
            super::super::pending(&[pending_entry()], &hosts, NOW),
        ),
        (
            "grants-release",
            grants(
                &release_grants(HALFWAY),
                &idle(&release_grants(HALFWAY)),
                &hosts,
                NOW,
                0,
            ),
        ),
        (
            "history-release",
            history(
                &[HistoryEntry {
                    id: id(11),
                    agent: agent("build-agent"),
                    fingerprint: fingerprint(11),
                    request: release_request(),
                    status: "approved".to_owned(),
                    created_at: NOW - 600,
                    granted_secs: Some(86_400),
                }],
                &hosts,
            ),
        ),
    ]
}
