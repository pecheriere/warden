//! `warden request release`: what the request for a release says, and what the
//! owner's approval is reported as.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result, anyhow, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use warden_broker_proto::doctor::sanitize;
use warden_broker_proto::release::{
    CommitId, MAX_MANIFEST_BYTES, NO_ACTIVE_GRANT, ReleaseSteps, ReleaseTag, RepoName,
    SignManifestRequest,
};
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

/// `warden release tag`: have the broker create the approved tag.
pub(crate) async fn run_tag(repository: RepoName, tag: ReleaseTag) -> Result<()> {
    let (_, client) = crate::client()?;
    let done = client
        .release_tag(&repository, &tag)
        .await
        .map_err(refusal)?;
    println!(
        "{}",
        sanitize(&format!("tag {} object {}", done.tag, done.object))
    );
    Ok(())
}

/// `warden release sign-manifest`: have the broker sign the manifest in `file`.
pub(crate) async fn run_sign_manifest(
    repository: RepoName,
    tag: ReleaseTag,
    file: &Path,
) -> Result<()> {
    // Read and checked before anything is sent or the credentials are touched.
    let request = manifest_request(repository, tag, file)?;
    let (_, client) = crate::client()?;
    let done = client.release_manifest(&request).await.map_err(refusal)?;
    println!(
        "{}",
        sanitize(&format!(
            "manifest {}\nsignature {}\nsha256 {}",
            done.name, done.signature_name, done.sha256
        ))
    );
    Ok(())
}

/// `warden release publish`: have the broker publish the draft.
pub(crate) async fn run_publish(repository: RepoName, tag: ReleaseTag) -> Result<()> {
    let (_, client) = crate::client()?;
    let done = client
        .release_publish(&repository, &tag)
        .await
        .map_err(refusal)?;
    println!("{}", sanitize(&format!("published {}", done.tag)));
    Ok(())
}

/// The broker's refusal, with how to get a grant when there is none.
fn refusal(error: crate::client::CallError) -> anyhow::Error {
    let message = error.to_string();
    if message.contains(NO_ACTIVE_GRANT) {
        anyhow!("{message}; ask the owner with `warden request release`")
    } else {
        error.into()
    }
}

/// The body of the manifest step for the manifest in `file`: its base name and
/// content. Refuses a file over [`MAX_MANIFEST_BYTES`] without sending it.
fn manifest_request(
    repository: RepoName,
    tag: ReleaseTag,
    file: &Path,
) -> Result<SignManifestRequest> {
    let name = file
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} has no usable file name", file.display()))?
        .to_owned();
    let mut content = Vec::new();
    std::fs::File::open(file)
        .and_then(|f| {
            // One byte more than the limit tells a file at the limit from one over it.
            f.take(MAX_MANIFEST_BYTES as u64 + 1)
                .read_to_end(&mut content)
        })
        .with_context(|| format!("cannot read {}", file.display()))?;
    ensure!(
        content.len() <= MAX_MANIFEST_BYTES,
        "{} is over the {MAX_MANIFEST_BYTES} bytes the broker signs",
        file.display()
    );
    Ok(SignManifestRequest {
        repository,
        tag,
        name,
        content_b64: STANDARD.encode(&content),
    })
}

#[cfg(test)]
mod tests;
