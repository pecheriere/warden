# Security assessment

**Date: 2026-11-01. Covers release 0.8.1 and `main` at commit `a3b9b1e`.**

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
| 3 | **A deployment mistake removes a control**: an approval port an agent machine can reach, a listener another process can reach, or Funnel left on. | Medium: the setup has many steps, and warden cannot see the tailnet policy | High: the header can be forged. With it, an attacker can read the history, deny and revoke, and show an agent's approval prompt to the owner on the wrong device. It still takes a passkey to approve. | `doctor` checks what it can, and [says what it cannot](configuration.md#checking-a-setup). The agent API refuses Funnel. | Follow [Deployment](deployment.md). Do the by-hand checks `doctor` lists. Test the tailnet policy. |
| 4 | **A certificate target accepts more than it should**: it trusts the CA for any principal. | Medium: a per-host setting that is easy to get wrong | High: an approval for one target works on others | Principals name the target. | [Set targets up](ssh-targets.md) for their own principal only, and test that another target's certificate is refused. |
| 5 | **An issued certificate outlives its revocation** ([#35](https://github.com/pecheriere/warden/issues/35)). | Medium | Medium: at most the window, 4 hours | Short windows; a key that exists only in memory. | Prefer short windows. In an emergency, [remove the CA from the targets](assurance-case.md#the-ssh-ca-key). |
| 6 | **A vulnerability in a dependency that handles untrusted input**: `russh` on the relay (before login too), `axum` and `hyper`, `webauthn-rs` and OpenSSL. `rsa` is a pre-release through `russh`. | Medium | High, up to the broker: the broker can read the whole vault | Tailnet policy in front of every port. `cargo deny` nightly, Dependabot, memory-safe code. The relay can be left off. | Keep up with releases. Narrow who reaches each port. Leave the relay off if you can. |
| 7 | **A bug in warden's own parsing or policy checks**: proxy rules, redaction, signature checks. No fuzzing yet ([#91](https://github.com/pecheriere/warden/issues/91)), and coverage is not measured ([#97](https://github.com/pecheriere/warden/issues/97)). | Medium | Medium to high | Unit and integration tests, Rust's memory safety, typed input. | Report what you find. |
| 8 | **The API origin handles the secret badly**, or a response leaks it in a form redaction does not catch. | Medium, depending on the API | Medium | Redaction, no compressed responses, exact origin. [The real control is the destination rule](threat-model.md#proxy-mode-residual-risks). | Give secrets the least scope the service offers. |
| 9 | **The warden host is compromised.** | Low to medium, depending on what else runs there | Critical: every secret in the vault, and the ability to issue grants | Non-root, distroless, no capabilities, restricted egress. | Treat the host like your most sensitive target, and run nothing else untrusted on it. |
| 10 | **The vault or the Connect token leaks**, or Connect's traffic is read on a network that is not private. | Low | Critical: the same secrets | A token limited to one vault; isolated network. warden does not require `https` for Connect. | A read-only token for one vault. Connect on its own network, or over the tailnet or TLS. |
| 11 | **The release pipeline or a maintainer account is compromised.** warden has one maintainer. | Low | Critical for those who upgrade | Signed commits, protected branch, pinned actions, attestations. | Pin the image by digest and [verify the attestation](deployment.md). |
| 12 | **An enrolled agent floods the owner**: many requests, notifications and disk use. See F3 below. | Low: needs an enrolled key | Low to medium: makes risk 1 more likely, and can fill the disk | Dedupe per target or scope. Revoking the agent stops it. | `warden-server agent revoke`. Watch the data volume. |
| 13 | **A bearer key is copied.** | Low: only legacy agents | Low: it can only create requests, from the owner's devices | Each request still takes a passkey. | Move to signing keys (`agent set-key`). |
| 14 | **The audit log is rewritten** by someone who controls the host. | Low | Medium: loss of evidence | The hash chain catches partial edits, but [not a whole rewrite or a removed last entry](threat-model.md#deployment-assumptions). | Ship the log somewhere the server cannot modify. |

## Findings of this review

What reading the documents against the code turned up. None of these is a way
in. Documents that were wrong are corrected in the same change that added this
page. The others need a code change or a decision by the maintainer, and stay
open until then.

| # | Finding | State |
|---|---|---|
| F1 | **The design overstated the approval binding.** It said the passkey signs a hash of the request and window. It signs a random challenge from `webauthn-rs`, and the binding is state on the server ([`approval/passkeys.rs`](../crates/broker/src/approval/passkeys.rs)). The threat model already said so. A broker that is trusted loses nothing, but the signature alone does not prove what was approved, so the audit trail cannot be checked that way either. | Document corrected. A signature over the request would need another WebAuthn design. |
| F2 | **The design said a CA rotation procedure was documented. It was not.** | [Added](assurance-case.md#the-ssh-ca-key). Not yet run against a live deployment. |
| F3 | **Nothing limits how many requests an agent makes.** Dedupe is per target, and per secret and scope for API requests, so an agent can vary the path prefix, or cancel and ask again, and each new request notifies the owner. The `requests` table and audit log also grow without limit. No document mentioned it. | Recorded in the [threat model](threat-model.md#accepted-residual-risks). A limit needs a code change. |
| F4 | **A certificate's `cert_issued` entry can be missing.** The approval is committed and audited first, then the issue entry is written; if that write fails, it is logged and the grant stands (`approve_finish` in [`approval/mod.rs`](../crates/broker/src/approval/mod.rs)). The design says each issue is audited. The `approved` entry names the grant, so the loss is small. | Document says so now. The code is unchanged. |
| F5 | **Making an enrollment code is not audited**, though enrolling a passkey with one is. Only someone on the host can make one. | Documented in [Configuration](configuration.md#checking-a-setup). The code is unchanged. |
| F6 | **The approval listener has no Funnel check.** Unlike the agent API, it relies on Funnel requests not carrying `Tailscale-User-Login`, as Tailscale documents. That was not tested here. Adding `refuse_funnel` to that router would make this independent of Tailscale's behaviour. | Open. The threat model states the dependence. |
| F7 | **`WARDEN_OP_CONNECT_URL` and the notifier URLs accept plain `http`.** This is deliberate for Connect on an isolated network, and for a local Home Assistant, but it was not written down as a choice. The approval link in a notification is useless without the owner's identity and a passkey. | Documented. Enforcing `https` would need a decision about those setups. |
| F8 | **The threat model said the broker holds the CA key in memory.** It reads the key at each approval and drops it after signing. Still true: anyone in control of the process can fetch it with the token. | Document corrected. |
| F9 | **The protocol said the owner may approve a *shorter* window.** The page offers any window up to the item's maximum, including one longer than asked. This is the owner's choice and is limited by the item, but an agent should not assume `not_after` is no later than it asked. | Document corrected. |
| F10 | **Open alerts at this date.** CodeQL `rust/cleartext-logging` at `crates/broker/src/main.rs`: `agent add` prints a new bearer key once, on stdout, which is its purpose. Seven Scorecard alerts about project practices (for example, fuzzing and CII badge), tracked under [#93](https://github.com/pecheriere/warden/issues/93). | The CodeQL alert is for the maintainer to resolve. |
| F11 | **The reason on `deny.toml`'s `RUSTSEC-2026-0387` exemption is out of date.** It says "only Ed25519 is used", but P-256 signatures are verified through that code. Verification handles no secret, so the exemption still seems right. | [#99](https://github.com/pecheriere/warden/issues/99) re-checks the exemptions. |
| F12 | **`subtle` is listed in `[workspace.dependencies]`, and no crate uses it directly.** | Harmless. For a code change. |

## What this assessment did not do

- Test a live deployment, including the [systemd service](deployment-systemd.md),
  which is itself not yet tested on a clean host, or the procedures for
  [replacing credentials](assurance-case.md#7-replacing-credentials).
- Review the dependencies, beyond the algorithm lists quoted in the
  [assurance case](assurance-case.md#6-cryptography).
- Review Tailscale, 1Password Connect, or how browsers and authenticators
  implement passkeys. warden relies on all of them.
- Check what dependencies log above the default level.
- Check every line of the relay's flow control and teardown against the design.
  The claims there were spot-checked, and rest on the relay's tests.
