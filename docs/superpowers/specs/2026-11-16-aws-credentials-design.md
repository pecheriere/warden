# Short-lived AWS credentials through warden

Status: approved by the owner, 2026-11-16.

Statements are tagged: (owner's decision) the owner decided it; **[call]** the
designer's call, open to the owner's veto; **[guess]** an assumption about how
AWS or the code behaves that the builder must check before relying on it.

## Why

Agents need AWS: today to start and stop a build box, later to bring up
machines on demand for a busy weekend and tear them down after. The only AWS
access on the agent's machine is a long session of a full-access role that the
owner opened in a browser and left in `~/.aws`, which every process of that
macOS user can use without asking anyone.

warden's API grants cannot cover AWS. Their proxy injects a static secret header
and filters by method and path prefix (design §8.3). AWS signs every request
(SigV4) over its method, path, headers and a hash of its body, so there is no
static header to inject, and many AWS APIs put the action in the body (EC2:
every call is `POST /`) or in a header (`X-Amz-Target`), so a path filter cannot
scope them.

AWS has its own answer to scoping: its token service (STS) mints temporary
credentials from a role, lasting 15 minutes to 12 hours, and a *session policy*
passed at mint time narrows what they can do. AWS enforces it, not warden. This
design has warden mint those credentials when the owner approves, the way it
mints GitHub installation tokens today.

## What success looks like

- An agent runs the `aws` CLI, an SDK or Terraform with no AWS secret on its
  machine. The tool asks warden for credentials; if no grant covers it, the
  owner gets a phone prompt; once approved, the tool works, and keeps working for
  the grant's window.
- Each request is either a set the owner wrote in 1Password and asked for by
  name, or a policy the agent wrote, shown to the owner in plain words. Either
  way AWS refuses anything outside it. (owner's decision: both)
- The owner can approve one short use, a few hours, or a long grant of days.
  (owner's decision)
- Every AWS call made with warden credentials shows, in CloudTrail, which warden
  grant and agent it came from.
- The full-access session no longer needs to live in `~/.aws` on the agent's
  machine.

## Goals

1. A new access kind, AWS credentials, for any AWS service, account and role
   the owner lists. warden does not know or care what the agent does with AWS.
   (owner's decision)
2. Two request forms on one target: the target's **preset** (the owner's own
   policy, or the role as it is), or a **custom** session policy the agent
   writes. (owner's decision)
3. Windows: **once** (a single credential of 15 minutes), **15m, 30m, 1h, 4h**,
   and **1d, 7d, 30d**, capped by the target. (owner's decision)
4. The broker holds one long-lived AWS credential: an IAM user's access key in
   1Password whose only permission is to assume the roles the owner marked for
   warden. (owner's decision, option A; certificates through IAM Roles Anywhere and
   OIDC federation were considered and set aside, see Approaches)
5. Credentials work with every AWS tool through `credential_process`, with no
   change to the tools.

## Non-goals

- Anything about how agents use AWS: cost limits, instance counts, which
  machines, autoscaling. A billing alarm or an AWS budget is the owner's to set
  up; warden documents the suggestion and nothing more. (owner's decision)
- A proxy for AWS calls. The agent talks to AWS directly with the credentials;
  warden never sees the calls.
- Revoking one minted credential early. AWS cannot; see Revocation.
- Managing IAM: warden creates no users, roles or policies. The owner sets them
  up once, following `docs/aws.md`.
- AWS console sign-in links (the federation endpoint). Possible later, not here.

## Anti-goals (a failure even if it works)

- A credential that can do more than the grant shows the owner, by any path:
  a custom policy wider than its target's role, an identity-service action in a
  custom policy, or a listed dangerous action shown without its red marking.
- A promise warden cannot keep: the docs and the approval page never say a
  custom policy is safe. warden refuses the identity services and flags the
  dangerous actions it knows; the owner reads the rest. (owner's decision)
- A grant whose credentials outlive it by more than one credential's lifetime.
- The broker's access key, a secret access key or a session token in a log, an
  audit entry, an error message, a crash or a file other than the CLI's 0600
  cache.
- Owner-run commands: once the owner has done the one-time AWS setup, nothing
  in day-to-day use asks the owner to type anything.
- A long grant ended or shortened because the agent asked for a different
  one on the same target (the bug `warden-rrq.7` records for GitHub). Grants
  with different policies live side by side.
- A change to the owner's own AWS setup: warden never edits `~/.aws/config`'s
  `default` profile or any profile it did not create.

## Approaches

**How the broker reaches AWS** (decided by the owner):

- **A. An IAM user's access key in 1Password (chosen).** The broker calls
  `sts:AssumeRole` with the key. The standard AWS route and the least code; the
  same shape as the GitHub App key. Its weakness, a key that never expires by
  itself, is answered by an IP condition where the owner's address is stable, a
  key-age check in doctor and documented rotation.
- **B. IAM Roles Anywhere.** The broker signs in with an X.509 certificate.
  Built-in expiry and revocation, but the private key still lives in 1Password,
  so a leak of that item is just as bad, and it costs much more code: X.509, a
  separate signing scheme and a second role hop, because Roles Anywhere's
  `CreateSession` takes no per-request session policy **[guess]**, which caps each
  credential at 1 hour by role chaining.
- **C. OIDC federation.** The broker issues signed tokens that AWS trusts. No
  secret at AWS, but AWS must fetch the broker's public keys from a public HTTPS
  address, and warden is tailnet-only.

**What a custom policy may contain** (decided by the owner, option 1): refuse the
identity services and flag a curated list of known-dangerous actions. Refusing
whole services was set aside because ordinary services (S3, EC2, SSM, Lambda)
hold actions that create lasting access while a ban on KMS breaks encrypted
disks; a full catalogue of AWS actions was set aside because it is a data source
warden would have to refresh and test for ever.

**How a request says what it wants** (decided by the owner): both a preset and
a custom policy. A preset alone forces the owner to predict every need in
1Password; a custom policy alone makes every approval a policy review on a
phone.

## Design

### AWS facts this design relies on

All **[guess]** until the builder checks them against AWS's documentation and
records the page and date in a code comment, as
`crates/proto/src/github_permissions.rs` does.

- `AssumeRole` takes `RoleArn`, `RoleSessionName` (2–64 characters of
  `[\w+=,.@-]`), `DurationSeconds` (900 to the role's maximum session duration,
  at most 43,200), `Policy` (inline JSON, at most 2,048 characters, and a packed
  size AWS reports as `PackedPolicySize`, which counts the session tags too, so a
  policy under 2,048 characters can still fail with `PackedPolicyTooLarge`),
  `PolicyArns` (up to 10 managed
  policies), `Tags` (up to 50 session tags) and `SourceIdentity`.
- The session's permissions are the intersection of the role's own policies with
  the session policies (inline and ARNs together). A session policy can only
  narrow; it never grants what the role lacks, with one exception: a resource
  policy that names the session's own ARN (`…:assumed-role/<role>/<session>`) is
  not limited by the session policy. The session name holds the grant id, so
  such a policy cannot exist before the grant does; the threat model notes it.
- An IAM user calling `AssumeRole` is not role chaining, so the 1-hour chaining
  cap does not apply.
- `SourceIdentity` cannot be changed by the session afterwards, including when it
  assumes another role, and it appears in CloudTrail.
- STS's Query API accepts `POST https://sts.<region>.amazonaws.com/` with a form
  body; it can answer in JSON with `Accept: application/json` (otherwise XML).
- `sts:GetCallerIdentity` needs no permission and returns the caller's ARN.
- `credential_process` expects `{"Version": 1, "AccessKeyId", "SecretAccessKey",
  "SessionToken", "Expiration"}` on stdout. botocore (the AWS CLI, boto3) starts
  refreshing 15 minutes before `Expiration` and must refresh within 10; it does
  not keep the output between invocations of the AWS CLI. aws-sdk-go-v2 (used by
  Terraform) kills the process after 1 minute by default.
- STS's answer names the session as
  `arn:aws:sts::<account>:assumed-role/<role name>/<session name>`: the `sts`
  namespace, without the role's path. Role names are unique per account,
  whatever the path.
- A trust policy has no condition on `DurationSeconds`: the role's maximum
  session duration is the only cap on what a holder of the broker's key can mint.

### 1Password items

All **[call]** for names and layout; see `docs/1password-items.md` for the
existing conventions.

- **`warden:aws`**, at most one, like `warden:github-app`:
  - `access_key_id`, `secret_access_key`: the IAM user's key.
  - `region`: the STS region the broker calls (regional endpoint).
  - Two items is a failure, as for the GitHub App. Missing means AWS is off.
- **`warden:aws-target`**, one per target. The title is the target name
  (`^[a-z0-9][a-z0-9-]{0,31}$`, as SSH targets):
  - `role_arn`: the role credentials are minted from. Must be an IAM role ARN
    (`arn:aws:iam::<12 digits>:role/<path/name>`), in the `aws` partition
    **[call]**: `aws-cn` and `aws-us-gov` are refused until someone needs them.
  - `max_window`: the longest window, from the set in Goal 3.
  - `policy` (optional): the preset's session policy JSON. Absent means the preset
    is the role as it is.
  - `custom` (optional): `allow` lets agents send a custom policy on this target;
    absent or anything else refuses one. Off by default, so a target meant only for
    its preset cannot be widened to its whole role. **[call]**
  - `sensitive` (optional): `yes` marks the preset as sensitive (see below). warden
    cannot see what the role's own policies allow without IAM read permissions it
    should not have, so the owner says. **[call]**
  - `list`: as for SSH targets (`full`, `name`, `hidden`).
  - `description` (optional): one line the approval page and `warden list` show.
- An item that cannot be used (bad ARN, a `policy` that does not parse or is too
  long, an unknown window) is a doctor failure naming the field, and the target
  is not offered. Other targets stay usable. **[call]**

### What the owner sets up in AWS once

`docs/aws.md` gives this as copy-paste policies, with generic account ids:

- An IAM user for the broker, with an access key and one inline policy allowing
  only `sts:AssumeRole`, `sts:TagSession` and `sts:SetSourceIdentity` on roles
  under a `/warden/` path, optionally conditioned on `aws:SourceIp`.
- Each target role under `/warden/`, trusting only that user, and requiring the
  session tags and source identity warden sets (conditions on
  `aws:RequestTag/warden-grant` and `sts:SourceIdentity`). The trust policy allows
  `sts:TagSession` and `sts:SetSourceIdentity` as actions next to `sts:AssumeRole`,
  or every mint is refused. Maximum session duration **exactly 1 hour**, the most
  the broker ever asks for.
- What this protects, said plainly in `docs/aws.md` and the threat model: the
  conditions only require the tags to be present, so a thief holding the key sets
  any values. The real limits on a leaked key are the roles it may assume, their
  1-hour maximum, and the IP condition where the owner can set one. Rotation and
  CloudTrail are how a leak is found and ended.
- Roles in other accounts work the same way: their trust names the user's ARN.
- A suggestion, not a requirement: an AWS budget alarm.

### Requests and grants

- **Wire:** `Access::Aws { target: TargetName, policy: Option<String> }` with
  `deny_unknown_fields`. `policy` absent is the preset; present is a custom policy,
  sent as the agent wrote it. **[call]**
- **At creation** the broker checks, without calling AWS: the target exists and is
  offered; the window is allowed and within `max_window`; a custom policy is
  allowed on the target and passes the custom-policy rules below. A refusal is a
  `400` naming the rule, before the owner is asked.
- **Identity of a grant:** agent, target and *policy digest* (SHA-256 of the
  canonical form of the custom policy, or a fixed marker for the preset). At most
  one active grant per identity. Grants with other identities, including a long
  preset grant and a short custom one on the same target, live side by side.
  (owner's anti-goal; the rules here are **[call]**)
- **A new request never shortens a live grant.** When the agent already holds a
  grant with the same identity that ends later than the request would, creation
  answers with that grant and asks no one. When the request would end later, it
  goes to the owner, and approving it replaces the old grant ("renewed"). A
  `once` request with a live grant of the same identity is answered with the live
  grant. This is a new rule next to `renewal.rs`'s `OneAtATime`, which covers only
  commit signing and GitHub tokens.
- **Ending-soon notices and renewal** from the grants page apply to AWS grants of
  1 day or more, as for GitHub; shorter ones get neither.
- **Pending:** one pending request per identity; a duplicate gets the existing
  one back, as for other kinds.
- **The preset's policy is read at approval** and stored on the grant, inside the
  digest the passkey ceremony binds (`approval/mod.rs`), so an owner who edits the
  item later does not change what an approved grant mints. **[call]**
- **Windows:** `once` is a grant that allows exactly one mint and lasts 15 minutes.
  `Window` (`crates/proto/src/window.rs`) is shared by every kind and has no
  `once`: add it as a variant only AWS accepts (every other kind refuses it at
  creation), and add a per-grant mint count, which has no precedent (migration
  0011 counts mints per hour). Grants are stored as `GrantAccess`, separate from
  `Access`, which needs an AWS variant too.
  The other windows are ordinary grants. With a sensitive preset, or a custom
  policy that is sensitive (see Custom-policy rules), only `once`, `15m`, `30m`
  and `1h` are offered. Either way the request defaults to `1h`.
  **[call]**: GitHub defaults to 30 days because git asks automatically; AWS
  requests are explicit, so the default is short.

### Custom-policy rules

All **[call]**; each is checked at creation and again at approval.

- Valid JSON, an IAM policy document (`Version` `2012-10-17`, `Statement` a list or
  one object), at most 1,800 characters after warden's canonical re-encoding (below
  AWS's 2,048 to leave room for the session tags in the packed size; a
  `PackedPolicyTooLarge` at mint is still reported plainly and audited),
  which is what the broker sends to AWS (so the owner approves exactly what AWS
  receives).
- Only `Effect`, `Action`, `Resource`, `Condition` and `Sid` in a statement.
  `NotAction`, `NotResource` and `Principal` are refused: they make "what this
  allows" hard to show and easy to get wrong.
- Every action names its service literally: `ec2:RunInstances` and `ec2:Describe*`
  are fine, `*`, `*:*` and `e*:Run*` are refused.
- **Identity services are refused in `Allow` statements:** `iam`, `sts`,
  `organizations`, `account`, `cloudtrail`, `sso`, `sso-directory`,
  `identitystore`. These create users, keys and roles that outlive the grant,
  escape its limits (assuming other roles, passing a role to a service), or blind
  the audit trail. A task that needs one uses a preset the owner wrote and marked
  sensitive. `kms` is allowed: launching an instance with a disk encrypted under a
  customer key needs `kms:CreateGrant` and `kms:GenerateDataKey*`. (owner's
  decision, option 1 of 3)
- **Known-dangerous actions make a custom policy sensitive**, in red on the
    approval page with only the short windows. warden keeps a short, curated list in
    code, each entry with the reason it is there, starting with: **[call: list to
    review]**
    - access that outlives the grant through resource policies:
      `s3:PutBucketPolicy`, `s3:PutBucketAcl`, `s3:PutObjectAcl`,
      `lambda:AddPermission`, `ecr:SetRepositoryPolicy`,
      `secretsmanager:PutResourcePolicy`, `sqs:SetQueueAttributes`,
      `sqs:AddPermission`, `sns:SetTopicAttributes`, `sns:AddPermission`,
      `kms:CreateGrant`, `kms:PutKeyPolicy`, every `ram` action;
    - a way into machines that outlives the grant: `ec2:ImportKeyPair`,
      `ec2:CreateKeyPair`, `ec2:ModifyInstanceAttribute` (user data);
    - borrowing an instance's role: `ssm:SendCommand`, `ssm:StartSession`,
      every `ec2-instance-connect` action;
    - weakening the audit trail: `logs:DeleteLogGroup`, `logs:PutRetentionPolicy`.

    An action pattern with a wildcard is matched against the list (`ec2:*`,
    `s3:Put*` and `ssm:Send*` all match), so a wildcard that covers a listed action
    is sensitive too. The page names the listed actions the policy reaches and why
    each is there. `Deny` statements may name anything: they only narrow.

- **The docs say the list is not complete.** `docs/aws.md` and the threat model
  state that a custom policy can reach dangerous actions warden does not list, and
  that the owner's reading of the page is the control for them.

- The approval page shows each statement as a line: allow or deny, the actions
  grouped by service, the resources, and conditions as key, operator and values.
  The raw JSON sits below, folded.

### Broker: minting

- `POST /v1/aws/credentials` with `{target, policy_digest}`, signed like every
  agent request. The broker finds the agent's active grant with that identity, or
  answers `NO_ACTIVE_GRANT`.
- It calls `AssumeRole` with:
  - `RoleArn` from the grant (stored at approval, so a later edit of the item does
    not move the grant to another role **[call]**).
  - `DurationSeconds`: the grant's remaining time, clamped to 15 minutes at least
    and 1 hour at most. A grant ending in 5 minutes yields a 15-minute credential.
  - `Policy`: the grant's stored policy (custom, or the preset's), canonical form.
    None when the preset is the role as it is.
  - `RoleSessionName`: `warden-<grant id>` (truncated to fit).
  - `SourceIdentity`: `warden-<agent>` (AWS needs at least 2 characters; agent
    names may have 1).
  - `Tags`: `warden-grant`, `warden-agent`, `warden-target`.
- It returns the four `credential_process` fields. The secret access key and
  session token are held in `secrecy` types from the HTTP body to the response
  and never formatted into errors; AWS error bodies are redacted the way
  `proxy/redact.rs` redacts upstream answers before any of their text reaches a
  log or the agent. **[call]**
- The broker refuses an STS answer whose `Expiration` is later than requested
  plus a minute, or whose `AssumedRoleUser` ARN does not name the grant's account,
  role name and session name, and audits the refusal.
- A rate limit per agent, as GitHub mints have (migration 0009 and its
  successor). **[call]**: the same numbers.
- Audit: each mint records grant, target, role ARN, session name, the returned
  `AccessKeyId` (an identifier, not a secret, and what CloudTrail shows), and the
  expiry. Never the secret key or session token.
- **Signing STS calls:** SigV4 over one `POST` with a form body. The workspace
  already has `aws-lc-rs` (HMAC, SHA-256) and `sha2`. **[call]** Hand-roll it in a
  small module tested against AWS's published SigV4 test suite, unless the
  `aws-sigv4` crate passes `cargo deny` and crate age with a dependency tree the
  builder judges small; say which and why in the PR.
- **Egress:** the broker needs HTTPS to `sts.<region>.amazonaws.com`.
  `docs/deployment.md`'s "Lock warden's egress" gains the rule, and the Pi's
  firewall needs it too.

### Revocation

Revoking a grant stops new mints at once. A credential already minted keeps
working until it expires: at most 1 hour, and 15 minutes for `once`. AWS cannot
end one session early; the only lever is a deny on the whole role for sessions
issued before a time (IAM "revoke active sessions"), which needs IAM write
permissions warden must not hold. `docs/aws.md` tells the owner how to do it by
hand in an emergency, and the threat model states the residual. (Same shape as
GitHub's one-hour residual.)

### CLI

- `warden request aws <target> [--policy <file>] [--for <window>] --goal "…"`.
- `warden aws credentials <target> [--policy <file>]`: prints the
  `credential_process` JSON. **It never files a request.** Without a grant it
  exits non-zero at once, with a message telling the agent to run
  `warden request aws`. Waiting is wrong here: SDKs kill the process after a
  minute, the AWS tools re-run it near every expiry, and a phone prompt in the
  middle of a run (after a `once` credential, or after a grant ended) is not
  something the owner asked for. **[call]**
- `warden aws exec <target> [--policy <file>] -- <command>`: runs one command with
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` set, for tools
  that ignore profiles. Like `credentials`, it never files a request. The
  credentials are fixed for the command's life (no refresh), so it suits commands
  shorter than one credential. **[call]**
- `warden setup aws <target> [--policy <file>]`: adds a profile named
  `warden-<target>` (or `warden-<target>-<short digest>` with a policy) to
  `~/.aws/config` with `credential_process`, and touches nothing else in the file.
  It refuses to overwrite a profile it did not write. **[call]**
- **Cache:** the CLI keeps minted credentials in a 0600 file, one entry per grant
  identity, so every `aws` invocation does not mint. It mints a new credential
  once the cached one has less than 15 minutes left, so botocore's refresh window
  does not turn into a mint per call; near the grant's end, where only a
  15-minute credential is possible, it serves the last one to its expiry rather
  than mint again. The builder checks what botocore does with a credential that
  is still inside its 10-minute window after a refresh **[guess]**. Same ownership, mode and size checks as the GitHub
  token cache; a version bump discards an old file. **[call]**
- `warden list` shows targets (name, description, longest window, whether custom
  policies are allowed, sensitive marker), as its `list` field allows.
  `warden status` shows AWS grants with target and policy kind.
- `/v1/info` gains `aws_credentials: true`; the CLI refuses to request or mint
  against a broker without it, before anything reaches the owner.

### Approval page

Follows `docs/design-language.md`; screenshots at the template's sizes, light and
dark.

- Headline: the target name and its description, then the window, then the goal.
- Preset: "the preset of <target>", with the role ARN and the preset's policy
  rendered as for a custom one, or "the role as it is" when there is none.
- Custom: a highlighted notice "The agent wrote this policy", then the statements
  as described under Custom-policy rules.
- Sensitive: red, with what the target's description says, and only the short
  windows.
- `once`: shown as "one credential, 15 minutes".
- The grants page lists AWS grants with target, kind, window and mints so far.

### Doctor

- `warden-server doctor`: the `warden:aws` item loads; `GetCallerIdentity` with
  the key succeeds and returns an IAM **user** ARN, never the account root
  (`:root`), which is a failure; each target item is valid; the key's item has not
  been changed in over 90 days is a warning to rotate **[guess: whether Connect
  reports an item's last change]**.
- `warden doctor` (client): the broker offers AWS; any profiles `setup aws` wrote
  point at this `warden` binary.

### Docs

New `docs/aws.md` (setup, policies, rotation, emergency revocation, what warden
does not do). Update in the same pull requests: README, `docs/1password-items.md`,
`docs/configuration.md`, `docs/agent-usage.md`, `docs/agent-protocol.md`,
`docs/agent-instructions.md`, `docs/interfaces.md`, `docs/deployment.md` (egress),
`docs/threat-model.md` (new asset: the access key; residual: one credential
lifetime after revoke; the owner's trust in role policies warden cannot see),
`docs/assurance-case.md`, `docs/security-assessment.md` and its date,
`docs/design.md` (a new access mode section), `site/index.html` if it lists what
warden covers, `CHANGELOG.md`. The owner's dotfiles `rules/warden.md` gains the
AWS usage line after release.

## Constraints

- Everything in `AGENTS.md`: fail closed, secrets in `secrecy`/`zeroize` types
  and never logged, no silenced lints, files under about 800 lines (split
  `api.rs`, `cli/src/agent.rs` or others the change pushes over), a new migration
  file for new tables or columns, never an edited one.
- Public repository: examples use documentation account ids (`111122223333`)
  and generic names only.
- Tests do not depend on timing; STS is faked at the HTTP level, as the GitHub
  App tests fake GitHub. The SigV4 code is tested against AWS's published
  vectors.
- No test or CI step calls real AWS. The first pull request that mints records
  in its description a manual test against a real throwaway role, with what it
  showed (preset, custom, a refused sensitive action, expiry).

## Left to the builder

- Splitting into pull requests. Suggested: (1) proto, items, policy loading and
  doctor; (2) STS client and SigV4, minting, audit, rate limit; (3) custom-policy
  rules and the approval page; (4) CLI (`request`, `credentials`, `exec`,
  `setup`, cache, `list`, `status`); (5) docs.
- Exact wire shapes, table layout, error wording, the cache file layout.
- Whether to ask STS for JSON or parse its XML (if XML, without a new
  dependency if practical).
