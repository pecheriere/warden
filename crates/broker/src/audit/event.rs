use serde::{Deserialize, Serialize};
use warden_broker_proto::release::{CommitId, ReleaseTag, RepoName};
use warden_broker_proto::{AgentName, Fingerprint, Id, TargetName, UnixUser};

use crate::proxy::CallEnd;

/// Something worth recording in the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditEvent {
    /// An agent asked for access.
    RequestCreated {
        /// Request id.
        id: Id,
        /// Requesting agent.
        agent: AgentName,
        /// Request fingerprint.
        fingerprint: Fingerprint,
        /// Free-text summary (never secrets).
        summary: String,
        /// The session label the agent stated, if any: its claim, not an
        /// identity. A string, not the validated type, so that a log stays
        /// readable whatever later releases accept.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
    },
    /// The owner was notified.
    Notified {
        /// Request id.
        id: Id,
        /// Name of the channel that delivered the notification.
        channel: String,
    },
    /// A notification channel failed.
    NotifyFailed {
        /// Request id.
        id: Id,
        /// Channel name.
        channel: String,
        /// Failure reason.
        reason: String,
    },
    /// The owner approved a request.
    Approved {
        /// Request id.
        id: Id,
        /// Grant id.
        grant_id: Id,
        /// Approved window in seconds.
        window_secs: u32,
        /// Passkey that signed the approval.
        passkey_id: String,
    },
    /// The owner denied a request.
    Denied {
        /// Request id.
        id: Id,
    },
    /// Requests of an agent were refused for being over its limits, since the
    /// previous such entry for it. Written for the first refusal, then at most
    /// once a minute, so that refused requests cannot fill the log.
    RequestLimited {
        /// The agent.
        agent: AgentName,
        /// Refused because too many of its requests were pending.
        pending: u64,
        /// Refused because it made too many new requests.
        rate: u64,
    },
    /// The owner was told that an agent is over its request limits.
    LimitNotified {
        /// The agent.
        agent: AgentName,
        /// Name of the channel that delivered the notification.
        channel: String,
    },
    /// An agent withdrew its own pending request.
    RequestCancelled {
        /// Request id.
        id: Id,
        /// The agent that made and cancelled it.
        agent: AgentName,
    },
    /// The owner opened a pending request from the pending screen: it has a new
    /// approval link, and the one before it stopped working. The token itself is
    /// never recorded.
    ApprovalLinkReplaced {
        /// Request id.
        id: Id,
    },
    /// A request timed out.
    Expired {
        /// Request id.
        id: Id,
    },
    /// A certificate was issued. Written with the approval, before anything
    /// is committed: the certificate is not given out if this entry cannot
    /// be written.
    CertIssued {
        /// Grant id.
        grant_id: Id,
        /// Certificate key id.
        key_id: String,
        /// Expiry, unix seconds.
        not_after: i64,
    },
    /// A grant was revoked.
    GrantRevoked {
        /// Grant id.
        grant_id: Id,
        /// Who revoked it.
        by: String,
    },
    /// A proxied HTTP call is about to be sent with an API secret. Written
    /// before anything leaves the broker; the call is not made if this
    /// entry cannot be written.
    ProxyCallStarted {
        /// Grant id.
        grant_id: Id,
        /// Request method.
        method: String,
        /// Origin and path of the URL (no query).
        url: String,
    },
    /// An agent asked the broker to make an HTTP call with an API secret.
    /// Recorded for every call on a usable grant, whether it was refused,
    /// failed or answered. Never holds the secret or the query string.
    ProxyCall {
        /// Grant id.
        grant_id: Id,
        /// Request method, or `invalid`.
        method: String,
        /// Origin and path of the URL (no query), or `invalid`.
        url: String,
        /// Upstream status, if a response arrived.
        status: Option<u16>,
        /// Upstream body length, before redaction.
        response_bytes: u64,
        /// Secret occurrences removed from the response.
        redactions: u32,
        /// `ok`, or the message the agent was given.
        outcome: String,
        /// Why the broker stopped the upstream call before it finished, if it
        /// did. Absent for a call that ran to its end, including one whose
        /// response was then withheld. `status` and `response_bytes` then say
        /// how far the answer had come, and the upstream may have acted on the
        /// call all the same.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        aborted: Option<CallEnd>,
    },
    /// A relayed SSH session is about to reach its target. Written before
    /// the relay opens any connection to the target; the session does not
    /// start if this entry cannot be written.
    RelaySessionStarted {
        /// Grant id.
        grant_id: Id,
        /// Target name.
        target: TargetName,
        /// Login user on the target.
        user: UnixUser,
        /// The command of an `exec` session (at most 200 characters, cut
        /// with `…`); `None` for a shell.
        command: Option<String>,
    },
    /// A relayed SSH session ended. Follows its `relay_session_started`.
    RelaySessionEnded {
        /// Grant id.
        grant_id: Id,
        /// Why it ended (a fixed phrase, never secrets).
        reason: String,
        /// Bytes the agent sent on to the target.
        bytes_to_target: u64,
        /// Bytes the target sent back (stdout and stderr).
        bytes_from_target: u64,
        /// The command's exit status, if the target reported one.
        exit_status: Option<u32>,
    },
    /// The relay refused to start a session on an authenticated
    /// connection: the grant or the target's policy changed since login.
    RelaySessionRefused {
        /// Grant id.
        grant_id: Id,
        /// Why (a fixed phrase, never secrets).
        reason: String,
    },
    /// A connection to the relay ended without logging in after trying to.
    /// Holds no key material.
    RelayLoginRefused {
        /// The user name asked for (the target), or `<invalid>` if it is
        /// not a valid target name.
        user: String,
        /// The peer's IP address.
        peer: String,
        /// Refused login attempts.
        attempts: u32,
    },
    /// The broker signed a commit for an agent. Written before the signature
    /// leaves the broker; it is not given out if this entry cannot be written. It
    /// means warden signed it for that agent, not that anyone reviewed the change.
    CommitSigned {
        /// Grant it was signed under.
        grant_id: Id,
        /// The agent.
        agent: AgentName,
        /// The id git gives the commit with this signature, as git lays it out. The
        /// signature stays valid under another layout, which makes another id: use
        /// `payload_sha256` to tell whether a commit is this one.
        commit: String,
        /// Lowercase hex SHA-256 of what was signed: the commit object without its
        /// signature header.
        payload_sha256: String,
        /// Parent ids, as the commit says.
        parents: Vec<String>,
        /// Tree id, as the commit says.
        tree: String,
        /// The author header, as the commit says: the agent's word, not checked.
        author: String,
        /// `SHA256:…` fingerprint of the key that signed.
        key_fingerprint: String,
    },
    /// The broker refused to sign something for an agent. Holds no payload, only
    /// its digest, since the agent chose those bytes.
    CommitSigningRefused {
        /// The agent.
        agent: AgentName,
        /// The active grant it had, if any.
        grant_id: Option<Id>,
        /// Why (a fixed phrase, never secrets).
        reason: String,
        /// Lowercase hex SHA-256 of the payload, if it could be read.
        payload_sha256: Option<String>,
    },
    /// Refusals to sign for an agent beyond those recorded one by one in a minute,
    /// counted so that refused calls, which an agent can make as fast as it likes,
    /// cannot fill the log.
    CommitSigningRefusalsHeld {
        /// The agent.
        agent: AgentName,
        /// How many.
        count: u64,
    },
    /// The broker minted a GitHub installation token for an agent. Written before
    /// the token leaves the broker; it is not given out if this entry cannot be
    /// written. The token itself is never recorded.
    GithubTokenMinted {
        /// Grant it was minted under.
        grant_id: Id,
        /// The agent.
        agent: AgentName,
        /// The installation the token is for.
        installation_id: u64,
        /// The permissions the token has, as `name:level`.
        permissions: Vec<String>,
        /// When GitHub ends the token, unix seconds.
        expires_at: i64,
        /// The repository the token is limited to, as the grant names it. Absent in
        /// the entries 0.12.0 wrote, which a log still holds; every new mint sets it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repository: Option<RepoName>,
        /// GitHub's id for that repository; absent in the same old entries.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repository_id: Option<u64>,
    },
    /// A GitHub token grant or pending request that named no repository was ended
    /// at upgrade, because GitHub grants are now scoped to repositories.
    GithubUnscopedEnded {
        /// The request: the grant's, or the pending one.
        request_id: Id,
        /// The grant that ended; `None` for a pending request.
        grant_id: Option<Id>,
    },
    /// Approving a GitHub token grant ended another of the agent's, because the two
    /// cover a repository in common.
    GithubTokenGrantReplaced {
        /// The grant that ended.
        grant_id: Id,
        /// The grant approved in its place.
        by_grant: Id,
        /// The ended grant's repositories (by its ids) that the new grant also covers
        /// by id or by name; empty when the ended grant named none.
        repository_ids: Vec<u64>,
    },
    /// The broker asked GitHub which repositories a GitHub token request names,
    /// when the owner opened its approval page, with a token that reads metadata
    /// and is dropped unused.
    GithubRepositoriesResolved {
        /// The request.
        request_id: Id,
        /// The ids GitHub gave, in the request's order; empty when it cannot reach
        /// every repository.
        repository_ids: Vec<u64>,
        /// Whether the App reaches every repository named.
        accessible: bool,
    },
    /// The broker refused to mint a GitHub token for an agent, or minted one it
    /// then did not give out because the grant had ended.
    GithubTokenRefused {
        /// The agent.
        agent: AgentName,
        /// The active grant it had, if any.
        grant_id: Option<Id>,
        /// Why (a fixed phrase, never secrets).
        reason: String,
    },
    /// Refusals to mint for an agent beyond those recorded one by one in a minute,
    /// counted so that refused calls cannot fill the log.
    GithubTokenRefusalsHeld {
        /// The agent.
        agent: AgentName,
        /// How many.
        count: u64,
    },
    /// The broker is about to act on GitHub for a step of a release, under a
    /// release grant whose step it has claimed. Written after the release key
    /// signed, if the step signs, and before anything signed leaves the broker or
    /// GitHub is changed: the step goes no further, and stays used, if this entry
    /// cannot be written.
    ReleaseStepStarted {
        /// The grant it is done under.
        grant_id: Id,
        /// The agent.
        agent: AgentName,
        /// The repository.
        repository: RepoName,
        /// The tag.
        tag: ReleaseTag,
        /// The step: `tag`, `manifest` or `publish`.
        step: String,
        /// What the release key signed for the step: the id of the tag object for
        /// `tag`, the lowercase hex SHA-256 of the manifest for `manifest`. Absent
        /// for `publish`, which signs nothing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed: Option<String>,
    },
    /// The broker created and pushed the signed tag of a release under a release
    /// grant. Written once the tag exists; the claim of the step and its
    /// `release_step_started` entry were made before.
    ReleaseTagCreated {
        /// The grant it was done under.
        grant_id: Id,
        /// The agent.
        agent: AgentName,
        /// The repository.
        repository: RepoName,
        /// The tag.
        tag: ReleaseTag,
        /// The commit the tag points at.
        commit: CommitId,
        /// The id of the tag object, which the broker computed before GitHub
        /// created it.
        object: String,
    },
    /// The broker signed the manifest of a release under a release grant and
    /// attached it, with its signature, to the draft release. Written once both
    /// files are uploaded; the claim of the step and its `release_step_started`
    /// entry were made before.
    ReleaseManifestSigned {
        /// The grant it was done under.
        grant_id: Id,
        /// The agent.
        agent: AgentName,
        /// The repository.
        repository: RepoName,
        /// The tag.
        tag: ReleaseTag,
        /// The manifest's file name.
        name: String,
        /// Lowercase hex SHA-256 of the manifest signed.
        sha256: String,
    },
    /// The broker published the draft release under a release grant. Written
    /// after GitHub confirmed the release is no longer a draft; the claim of the
    /// step and its `release_step_started` entry were made before.
    ReleasePublished {
        /// The grant it was done under.
        grant_id: Id,
        /// The agent.
        agent: AgentName,
        /// The repository.
        repository: RepoName,
        /// The tag of the release.
        tag: ReleaseTag,
    },
    /// The broker published a release, then found it is not what it checked just
    /// before: GitHub has no conditional publish, so a write can land in between.
    /// The owner is told.
    ReleasePublishedChanged {
        /// The grant it was done under.
        grant_id: Id,
        /// The agent.
        agent: AgentName,
        /// The repository.
        repository: RepoName,
        /// The tag of the release.
        tag: ReleaseTag,
        /// What differs (a fixed phrase, never anything GitHub said).
        reason: String,
    },
    /// The owner was told that a release was published unlike it was checked.
    ReleasePublishedChangedNotified {
        /// The grant.
        grant_id: Id,
        /// Name of the channel that delivered the notification.
        channel: String,
    },
    /// The broker refused a step of a release, or could not finish one it had
    /// claimed.
    ReleaseRefused {
        /// The agent.
        agent: AgentName,
        /// The active grant it had, if any.
        grant_id: Option<Id>,
        /// The step: `tag`, `manifest` or `publish`.
        step: String,
        /// Why (a fixed phrase, never secrets or anything GitHub said).
        reason: String,
    },
    /// Refusals of release steps for an agent beyond those recorded one by one in
    /// a minute, counted so that refused calls cannot fill the log.
    ReleaseRefusalsHeld {
        /// The agent.
        agent: AgentName,
        /// How many.
        count: u64,
    },
    /// The owner was told that a commit signing grant is about to end.
    CommitSigningRenewalNotified {
        /// The grant.
        grant_id: Id,
        /// Name of the channel that delivered the notification.
        channel: String,
    },
    /// The owner was told that a GitHub token grant is about to end.
    GithubTokenRenewalNotified {
        /// The grant.
        grant_id: Id,
        /// Name of the channel that delivered the notification.
        channel: String,
    },
    /// A commit signing grant reached its limit of signatures for the day. Written
    /// once a day per grant; the refusals themselves are recorded as usual.
    CommitSigningLimitReached {
        /// The grant.
        grant_id: Id,
        /// The agent.
        agent: AgentName,
        /// The limit.
        limit: u32,
    },
    /// The owner was told that a commit signing grant reached its daily limit.
    CommitSigningLimitNotified {
        /// The grant.
        grant_id: Id,
        /// Name of the channel that delivered the notification.
        channel: String,
    },
    /// An API grant reached its limit of proxied calls for the day. Written once a
    /// day per grant; the refusals themselves are recorded as usual.
    ProxyCallLimitReached {
        /// The grant.
        grant_id: Id,
        /// The agent.
        agent: AgentName,
        /// The limit.
        limit: u32,
    },
    /// The owner was told that an API grant reached its daily limit of calls.
    ProxyCallLimitNotified {
        /// The grant.
        grant_id: Id,
        /// Name of the channel that delivered the notification.
        channel: String,
    },
    /// Calls refused before they started (by policy, a changed secret, the
    /// calls in flight or the grant's daily limit, or a backend outage), counted
    /// for one agent over one minute instead of recorded one by one.
    ProxyCallsRefusedHeld {
        /// The agent.
        agent: AgentName,
        /// How many calls were refused.
        count: u64,
    },
    /// An agent was added.
    AgentAdded {
        /// Agent name.
        agent: AgentName,
    },
    /// An agent was switched to (or created with) request signing by this
    /// public key. The key itself is not recorded, only its fingerprint.
    AgentKeySet {
        /// Agent name.
        agent: AgentName,
        /// The key's `SHA256:…` fingerprint.
        fingerprint: String,
    },
    /// An agent was revoked.
    AgentRevoked {
        /// Agent name.
        agent: AgentName,
    },
    /// A one-time passkey enrollment code was made on the host. Neither the
    /// code nor its hash is recorded.
    EnrollmentCodeCreated {
        /// When the code stops working, unix seconds.
        expires_at: i64,
    },
    /// A passkey was enrolled.
    PasskeyEnrolled {
        /// Passkey id.
        passkey_id: String,
    },
    /// An approval was refused because the passkey's signature counter did
    /// not increase: a possible cloned authenticator.
    PasskeyCounterRegressed {
        /// Passkey id.
        passkey_id: String,
    },
    /// A passkey was removed.
    PasskeyRemoved {
        /// Passkey id.
        passkey_id: String,
    },
    /// Errors of the local secret backend beyond those recorded one by one in a
    /// minute, counted so that unusable files cannot fill the log.
    LocalBackendErrorsHeld {
        /// How many.
        count: u64,
    },
    /// An internal error worth recording.
    Error {
        /// Where it happened.
        context: String,
        /// What happened (never secrets).
        message: String,
    },
}
