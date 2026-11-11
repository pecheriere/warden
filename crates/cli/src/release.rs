//! `warden request release`: what the request for a release says, and what the
//! owner's approval is reported as.

use anyhow::{Result, ensure};
use warden_broker_proto::release::{CommitId, ReleaseSteps, ReleaseTag, RepoName};
use warden_broker_proto::{
    Access, CreateRequest, Goal, GrantAccess, GrantView, SessionLabel, SessionLink, Window,
};

/// What `what` of a release request is for, to complete "a request …".
pub(crate) const SUBJECT: &str = "for a release";

/// The request for the release of `tag` at `commit` in `repository`. A release grant
/// lasts a day and is not renewable, so there is no window to choose.
pub(crate) fn release_request(
    repository: RepoName,
    tag: ReleaseTag,
    commit: CommitId,
    goal: Goal,
    session: Option<SessionLabel>,
    link: Option<SessionLink>,
) -> CreateRequest {
    CreateRequest {
        goal,
        access: Access::Release {
            repository,
            tag,
            commit,
        },
        window: Window::D1,
        session,
        link,
    }
}

/// Refuse a grant that is not a release grant.
pub(crate) fn check_release_grant(grant: &GrantView) -> Result<()> {
    ensure!(
        matches!(grant.access, GrantAccess::Release(_)),
        "the broker returned another kind of grant for a release request"
    );
    Ok(())
}

/// The steps the owner approved, in a line. The names come from the broker, so the
/// line is made safe to print.
pub(crate) fn steps_line(steps: &ReleaseSteps) -> String {
    let mut done = Vec::new();
    if steps.tag {
        done.push("create the tag".to_owned());
    }
    if let Some(name) = &steps.manifest {
        done.push(format!("sign the manifest {name}"));
    }
    if steps.publish {
        done.push("publish the release".to_owned());
    }
    warden_broker_proto::doctor::sanitize(&format!("approved steps: {}", done.join(", ")))
}
