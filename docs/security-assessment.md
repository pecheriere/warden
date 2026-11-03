# Security assessment

**Date: 2026-11-02. Covers release 0.9.0, reviewed at `main` commit `699b99b`. The
review for this release checked the ranked risks and findings against the changes
since 0.8.1; it did not repeat the full reading of the documents against the code.**

**This is the project's own assessment. It is not an independent review, audit
or penetration test.** warden has not had one. The people and tools that wrote
warden also wrote this, so read it as a statement of what the project knows, not
as proof that nothing else is wrong.

**How it was done.** A coding agent, working for the maintainer, read the
documents against the source and looked at the project's alerts. Nothing was run
against a live deployment, the dependencies were read only where this page says
so, and no attack was attempted.

**When it is updated.** When a change moves a risk below (see
[`AGENTS.md`](../AGENTS.md)), and at the latest with each minor release. Change
the date at the top and say what the new version covers.

The [threat model](threat-model.md) says what warden protects and which risks are
accepted, and the [assurance case](assurance-case.md) gives the reasoning and the
code. To report a problem, see [`SECURITY.md`](../SECURITY.md).

## Ranked risks

Most important first, by how likely each one looks and how much damage it would
do. The ratings are judgement, not measurement. warden is young, with few users
and no incident history to learn from.

| # | Problem | Likelihood | Damage | What limits it | What you can do |
|---|---|---|---|---|---|
| 1 | **The owner approves something they should not**: a persuasive goal from a prompt-injected agent, or a reflex tap after many requests. | High | High: whatever the grant allows, for up to 4 hours | The scope is shown, read-only is the default, and the window is capped by the item. warden cannot judge a goal. | Read the scope. Keep items narrow, with short maximum windows and least-privileged accounts. Deny what you did not expect. |
| 2 | **A compromised agent machine uses a live grant**, for another task or for an attacker ([#49](https://github.com/pecheriere/warden/issues/49)). | High, if agents read untrusted content | Medium to high: bounded by the grant | Short windows, scope, audit. Secrets and credentials stay on the broker in proxy and relay modes. | One request per task. Revoke when done. Separate OS users and keys for work that must not share grants. |
| 3 | **A deployment mistake removes a control**: an approval port an agent machine can reach, a listener another process can reach, or Funnel left on. | Medium: the setup has many steps, and warden cannot see the tailnet policy | High: the header can be forged. With it, an attacker can read the history and pending requests, deny and revoke, replace a request's approval link so that the owner's page fails, and show an agent's approval prompt to the owner on the wrong device. It still takes a passkey to approve. | `doctor` checks what it can, and [says what it cannot](configuration.md#checking-a-setup). The agent API and the approval listener refuse Funnel. | Follow [Deployment](deployment.md). Do the by-hand checks `doctor` lists. Test the tailnet policy. |
| 4 | **A certificate target accepts more than it should**: it trusts the CA for any principal. | Medium: a per-host setting that is easy to get wrong | High: an approval for one target works on others | Principals name the target. | [Set targets up](ssh-targets.md) for their own principal only, and test that another target's certificate is refused. |
| 5 | **Certificate access outlives its revocation, and its window** ([#35](https://github.com/pecheriere/warden/issues/35)). New logins work until the certificate expires. A login already open is not ended by revoking, by expiry, or by removing the CA. | Medium | Medium to high: new logins for at most 4 hours, but an open session, or a process it left running, has no time limit | Short windows limit new logins; the ephemeral key exists only in memory. Nothing in warden reaches an open session. Relay mode ends sessions. | Use relay mode where a session must be ended. In an emergency, [remove the CA and end the sessions on each target](assurance-case.md#the-ssh-ca-key). |
| 6 | **A vulnerability in a dependency that handles untrusted input**: `russh` on the relay (before login too), `axum` and `hyper`, `webauthn-rs` and OpenSSL. `rsa` is a pre-release through `russh`. | Medium | High, up to the broker: the broker can read the whole vault | Tailnet policy in front of every port. `cargo deny` nightly, Dependabot, memory-safe code. A check of the pinned OpenSSL release against its end of support and the newest release of its line, nightly and at each release. The relay can be left off. | Keep up with releases. Narrow who reaches each port. Leave the relay off if you can. |
| 7 | **A bug in warden's own parsing or policy checks**: proxy rules, redaction, signature checks, the framing around P-256 verification, the CLI's `ssh-agent` client. Fuzzing is young and covers only part of this ([#91](https://github.com/pecheriere/warden/issues/91)), and coverage says which lines ran, not that their results were checked ([#97](https://github.com/pecheriere/warden/issues/97)). | Medium | Medium to high | Unit and integration tests, a scheduled fuzz job, Rust's memory safety, typed input. | Report what you find. |
| 8 | **The API origin handles the secret badly**, or a response leaks it in a form redaction does not catch. | Medium, depending on the API | Medium | Redaction, no compressed responses, exact origin. [The real control is the destination rule](threat-model.md#proxy-mode-residual-risks). | Give secrets the least scope the service offers. |
| 9 | **An agent's key is copied**: a bearer key, or a signing key kept in a file. It can use the agent's live API grants, within their scope and with the answers: writes too, if a live grant allows them. It can also list and revoke the agent's grants, cancel its requests, and ask for more. It cannot approve anything, or use a live SSH grant without that grant's ephemeral key. | Low to medium: a bearer key is on the machine, or in its environment | Medium to high: bounded by what is live or later approved, up to 4 hours per grant, and the owner sees nothing new unless it asks for something | A bearer key works only with the owner's login. A signing key has no such check, only the tailnet policy. A key in hardware cannot be copied. Calls are audited under the agent's name. | Use a hardware key where the machine has one. Keep API grants short and read-only. `warden-server agent revoke` as soon as you suspect a copy. |
| 10 | **The warden host is compromised.** | Low to medium, depending on what else runs there | Critical: every secret in the vault, and the ability to issue grants. With the [local backend](local-backend.md), the secrets are on the host itself, with no read-only token boundary | Non-root, distroless, no capabilities, restricted egress, and private files. | Treat the host like your most sensitive target, and run nothing else untrusted on it. |
| 11 | **The vault or the Connect token leaks**, or Connect's traffic is read on a network that is not private. | Low | Critical: the same secrets | A token limited to one vault; isolated network. warden [refuses plain `http`](configuration.md#plain-http) to a host that is not clearly local or private, unless the owner opts in. | A read-only token for one vault. Connect on its own network, or over the tailnet or TLS. |
| 12 | **The release pipeline or a maintainer account is compromised.** warden has one maintainer. | Low | Critical for those who upgrade | Signed commits, protected branch, pinned actions, attestations, and from 0.9.0 a manifest the maintainer signs off GitHub. Nothing enforces that signing step. | Pin the image by digest and [verify the release](verifying-releases.md). |
| 13 | **An enrolled agent floods the owner**: many requests, notifications and disk use. See F3 below. | Low: needs an enrolled key | Low: bounded at 60 notifications an hour per agent by default, which still makes risk 1 somewhat more likely | Dedupe per target or scope, and [per-agent limits](configuration.md#request-limits). Revoking the agent stops it. | `warden-server agent revoke`. Lower the limits if you see this. |
| 14 | **The audit log is rewritten** by someone who controls the host. | Low | Medium: loss of evidence | The hash chain catches partial edits, but [not a whole rewrite or a removed last entry](threat-model.md#deployment-assumptions). | Ship the log somewhere the server cannot modify. |

## Findings of this review

What reading the documents against the code turned up. As far as reading the code
could show, none of these is a way in, but that is not proof: F6, for one, rested
on Tailscale behaviour that was not tested. Documents that were wrong are corrected
in the same change that added this page. The others need a code change or a
decision by the maintainer, and stay open until then.

| # | Finding | State |
|---|---|---|
| F1 | **The design overstated the approval binding.** It said the passkey signs a hash of the request and window. It signs a random challenge from `webauthn-rs`, and the binding is state on the server ([`approval/passkeys.rs`](../crates/broker/src/approval/passkeys.rs)). The threat model already said so. A broker that is trusted loses nothing, but the signature alone does not prove what was approved, so the audit trail cannot be checked that way either. | Document corrected. A signature over the request was [considered and not planned](design/passkey-binding.md). |
| F2 | **The design said a CA rotation procedure was documented. It was not.** | [Added](assurance-case.md#the-ssh-ca-key). Not yet run against a live deployment. |
| F3 | **Nothing limits how many requests an agent makes.** Dedupe is per target, and per secret and scope for API requests, so an agent can vary the path prefix, or cancel and ask again, and each new request notifies the owner. The `requests` table and audit log also grow without limit. No document mentioned it. | Fixed in [#113](https://github.com/pecheriere/warden/issues/113): [per-agent limits](configuration.md#request-limits), with what remains in the [threat model](threat-model.md#accepted-residual-risks). |
| F4 | **A certificate's `cert_issued` entry can be missing.** The approval is committed and audited first, then the issue entry is written; if that write fails, it is logged and the grant stands (`approve_finish` in [`approval/mod.rs`](../crates/broker/src/approval/mod.rs)). The design says each issue is audited. The `approved` entry names the grant, so the loss is small. | Fixed in [#114](https://github.com/pecheriere/warden/issues/114): the entry is written with the approval, and the certificate is not given out if it cannot be. |
| F5 | **Making an enrollment code is not audited**, though enrolling a passkey with one is. Only someone on the host can make one. | Fixed in [#114](https://github.com/pecheriere/warden/issues/114): `enrollment_code_created`, and no code without it. |
| F4a | **Ending access depended on the audit log.** Found while fixing F4. A revocation needed its entry written first, and writing the log could hold up other changes. | Changed on purpose: stopping access matters more than recording it. The entry waits in the database and reaches the log once it works, and the owner is warned until then. See [the threat model](threat-model.md#what-the-audit-log-can-miss). |
| F4b | **A proxied call or relay session did not check its grant again after recording its start.** A grant that ended during that write could still be used. | Fixed: both check again before anything goes out. |
| F6 | **The approval listener has no Funnel check.** Unlike the agent API, it relies on Funnel requests not carrying `Tailscale-User-Login`, as Tailscale documents. That was not tested here. Adding `refuse_funnel` to that router would make this independent of Tailscale's behaviour. | Fixed in [#115](https://github.com/pecheriere/warden/issues/115): the approval router refuses Funnel requests as the agent API does. |
| F7 | **`WARDEN_OP_CONNECT_URL` and the notifier URLs accept plain `http`.** This is deliberate for Connect on an isolated network, and for a local Home Assistant, but it was not written down as a choice. The approval link in a notification is useless without the owner's identity and a passkey. | Fixed in [#115](https://github.com/pecheriere/warden/issues/115): plain `http` is [refused](configuration.md#plain-http) unless the URL shows a local or private host or the owner opts in for that variable. |
| F8 | **The threat model said the broker holds the CA key in memory.** It reads the key at each approval and drops it after signing. Still true: anyone in control of the process can fetch it with the token. | Document corrected. |
| F9 | **The protocol said the owner may approve a *shorter* window.** The page offers any window up to the item's maximum, including one longer than asked. This is the owner's choice and is limited by the item, but an agent should not assume `not_after` is no later than it asked. | Document corrected. |
| F10 | **Open alerts at this date.** Five Scorecard alerts about project practices (CII badge, code review, maintained, vulnerabilities and branch protection), tracked under [#93](https://github.com/pecheriere/warden/issues/93). No CodeQL or Dependabot alert is open. | Open under #93. |
| F11 | **The reason on `deny.toml`'s `RUSTSEC-2026-0387` exemption is out of date.** It says "only Ed25519 is used", but P-256 signatures are verified through that code. Verification handles no secret, so the exemption still seems right. | Resolved by [#118](https://github.com/pecheriere/warden/pull/118), which removed `crypto-bigint` 0.5 and that exemption. |
| F12 | **`subtle` is listed in `[workspace.dependencies]`, and no crate uses it directly.** | Harmless. For a code change. |
| F13 | **The documents said a copied bearer key can only create requests.** `proxy_call`, `list_grants` and `revoke_grant` in [`api.rs`](../crates/broker/src/api.rs) take the same `AuthedAgent` as creating a request, so any copied agent key can use the agent's live API grants and manage its grants. | Documents corrected, and the risk re-rated (risk 9). The code does what it should: a key is the agent. |
| F14 | **The documents treated a certificate's expiry as the end of access.** `sshd` checks a certificate when it authenticates, and not afterwards. On a throwaway OpenSSH 10.3 server on 2026-11-01, a session outlived its certificate's expiry, and outlived removing the CA with a reload, while new logins were refused in both cases. On OpenSSH 9.2 in a Debian 12 container, `usermod --expiredate 1` refused new logins and did not end an open session, and with `UsePAM yes`, `passwd -l` and `usermod -L` did not stop certificate logins at all. warden sees none of it. | Documents corrected, and risk 5 re-rated. [#35](https://github.com/pecheriere/warden/issues/35) covers what to do about it. |
| F15 | **Certificate logins are not in the audit log.** They go straight to the target, so warden records the issue and not the use. The target's `sshd` logs each login with the certificate's key id, `warden:<agent>:<grant id>`. Interactive input to a relay session is not recorded either. | Documents corrected. Ship the targets' logs if you need this trail. |
| F16 | **warden does not check the length of a pinned RSA host key.** An earlier draft of the [assurance case](assurance-case.md#key-lengths) said `ssh-key` refuses one under 2048 bits. That check exists only in a conversion this path does not use. It affects only keys the owner pins. | Documented. Refusing one at parse time would need a code change. |
| F17 | **The Pending page lets the owner's login do more without a passkey.** Found in review of [#145](https://github.com/pecheriere/warden/pull/145). With that login alone, someone can see pending requests, deny them, and keep replacing a request's approval link, so every page the owner opens fails before the passkey finishes. Where an agent has browser tools next to a usable passkey, the login can also raise a real prompt, and only the owner's attention stops it. | [Documented in the threat model](threat-model.md). It still takes a passkey to approve, and passkey prompts are limited per request. See risk 3. Not tested on a real phone. |

## What this assessment did not do

- Test a live deployment (the OpenSSH behaviour above was tried on throwaway
  servers only), including the [systemd service](deployment-systemd.md),
  which is itself not yet tested on a clean host, or the procedures for
  [replacing credentials](assurance-case.md#7-replacing-credentials).
- Review the dependencies, beyond the algorithm lists quoted in the
  [assurance case](assurance-case.md#6-cryptography).
- Review Tailscale, 1Password Connect, or how browsers and authenticators
  implement passkeys. warden relies on all of them.
- Check what dependencies log above the default level.
- Check every line of the relay's flow control and teardown against the design.
  The claims there were spot-checked, and rest on the relay's tests.
