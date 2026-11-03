# Security assurance case

This page argues why warden meets its security requirements, and points at the
code that does the work so that you can check. It does not repeat the
[threat model](threat-model.md), which says what warden protects, who it trusts
and which risks are accepted, or the [design](design.md), which says how it
works. The [security assessment](security-assessment.md) ranks what is most
likely to go wrong and lists what this review found.

This is the project's own argument. Nobody independent has reviewed it, and a
page like this one can be wrong. Each pointer below was checked against the code
of the `main` branch on 2026-11-01. Links go to files, and name the function or
constant to look for, because line numbers go stale.

Contents:

1. [Security requirements](#1-security-requirements)
2. [Trust boundaries](#2-trust-boundaries)
3. [Secure design principles](#3-secure-design-principles)
4. [Input validation](#4-input-validation)
5. [Common weaknesses](#5-common-weaknesses)
6. [Cryptography](#6-cryptography)
7. [Replacing credentials](#7-replacing-credentials)
8. [How the project keeps this true](#8-how-the-project-keeps-this-true)

This case describes the recommended 1Password backend. The weaker [local backend](local-backend.md) gives up the vault's separation from the host: [the threat model](threat-model.md#the-local-secret-backend) says what changes.

## 1. Security requirements

What warden is meant to do, for anyone deciding whether to rely on it. What it
does *not* do is at the top of the [threat model](threat-model.md#in-short), and
its guarantees hold only under the
[deployment assumptions](threat-model.md#deployment-assumptions).

| # | Requirement | Where it is enforced |
|---|---|---|
| R1 | No access without the owner's passkey. An agent can only ask. | [`approve_finish`](../crates/broker/src/approval/mod.rs) issues a grant only after [`finish_approval`](../crates/broker/src/approval/passkeys.rs) verifies the assertion, with user verification required. |
| R2 | An approval applies to the one request and window the owner saw. | [`ApprovalBinding`](../crates/broker/src/approval/passkeys.rs), checked again in `approve_finish`. See [how it binds](threat-model.md#approval-binding), and its limit below. |
| R3 | Access is bounded in time and scope, and the agent cannot widen it. On a certificate target the time bound applies to new logins only: [an open login outlives the certificate](threat-model.md#accepted-residual-risks). | `check_policy` in [`approval/mod.rs`](../crates/broker/src/approval/mod.rs); [`ssh_ca::issue`](../crates/broker/src/ssh_ca.rs); [`proxy/rules.rs`](../crates/broker/src/proxy/rules.rs); `scope` in [`policy/mod.rs`](../crates/broker/src/policy/mod.rs). |
| R4 | The agent never receives a reusable secret: no CA key, API secret or relay credential. It keeps only its own identity key, which can ask and use active grants, and [can be copied](security-assessment.md#ranked-risks) unless held in hardware. | Grant types in [`proto/src/lib.rs`](../crates/proto/src/lib.rs) carry no secret field. [`proxy/client.rs`](../crates/broker/src/proxy/client.rs) adds the secret itself and [`proxy/redact.rs`](../crates/broker/src/proxy/redact.rs) redacts answers. |
| R5 | A secret reaches only the place the owner configured. | Exact origin match in `check_url` ([`proxy/rules.rs`](../crates/broker/src/proxy/rules.rs)); no redirects and no proxy in `client_for` ([`proxy/client.rs`](../crates/broker/src/proxy/client.rs)); pinned host keys in `check_server_key` ([`relay/onward.rs`](../crates/broker/src/relay/onward.rs)). |
| R6 | Secrets are not logged, audited, sent to notifiers or put in errors. | `Debug` of secret types prints `<redacted>` ([`policy/mod.rs`](../crates/broker/src/policy/mod.rs), [`agents.rs`](../crates/broker/src/agents.rs), [`config.rs`](../crates/broker/src/config.rs)); fixed upstream errors in `ProxyError` ([`proxy/client.rs`](../crates/broker/src/proxy/client.rs)); the `Scrubber` in [`doctor/mod.rs`](../crates/broker/src/doctor/mod.rs). |
| R7 | Every request, decision and grant is recorded, and every use that passes through warden: relay sessions and proxied calls. A change to the record can be detected unless the whole file is rewritten. **warden does not see certificate logins** (B9 below): it records the issue, and only the target's `sshd` logs the login. | [`audit.rs`](../crates/broker/src/audit.rs) (hash chain), `record` in [`requests/transition.rs`](../crates/broker/src/requests/transition.rs). Exceptions: finding [F15](security-assessment.md#findings-of-this-review), and revocation, which [does not wait for the log](threat-model.md#what-the-audit-log-can-miss) ([`requests/revocation.rs`](../crates/broker/src/requests/revocation.rs)). |
| R8 | When state cannot be read, warden refuses. | Fail-closed paths are listed under [Fail-safe defaults](#3-secure-design-principles). |
| R9 | An agent always gets an explicit outcome. | `RequestStatus` in [`proto/src/lib.rs`](../crates/proto/src/lib.rs). |
| R10 | The demo cannot reach a real deployment. | [`scripts/check-demo-not-shipped.sh`](../scripts/check-demo-not-shipped.sh), run in CI, also against the built image. |

**The limit of R2.** The passkey signs a random challenge chosen by the WebAuthn
library, not a hash of the request. The tie between the signature and the request
is state kept on the server, so whoever controls the broker can apply an approval
to something else. That is consistent with the threat model, where the broker is
trusted, but it is weaker than a signature over the request itself.

## 2. Trust boundaries

```text
                         tailnet policy (outer control)
                 ┌───────────────────────────────────────────┐
 agent machine ──┼─B1─▶ Tailscale Serve ──▶ agent API ─┐     │
 agent machine ──┼─B2─▶ Serve TCP forward ─▶ SSH relay ─┤    │
 owner's phone ──┼─B3─▶ Tailscale Serve ──▶ approval UI ┤    │
                 └───────────────────────────────────────│───┘
                                                         ▼
                 operator on the host ──B4──▶  warden-server
                                                 │  │  │  │
          1Password Connect ◀──B5────────────────┘  │  │  │
          notifiers (Home Assistant, ntfy) ◀──B6────┘  │  │
          API origins ◀──B7────────────────────────────┘  │
          relay targets ◀──B8─────────────────────────────┘
 agent machine ──B9 (OpenSSH, certificate)──▶ certificate targets
```

| Boundary | What crosses | Untrusted side | Controls | Code |
|---|---|---|---|---|
| **B1** Agent to API | Signed or bearer requests; grants, redacted answers | The agent, and anything that reaches the port | `refuse_funnel`; the signature, or a bearer key plus the owner's login; body size and time limits; typed input | [`signed.rs`](../crates/broker/src/signed.rs), [`identity.rs`](../crates/broker/src/identity.rs), [`api.rs`](../crates/broker/src/api.rs) |
| **B2** Agent to relay | An SSH session | The agent, and anything that reaches the port | Public-key login only, with the approved key; limits before login; one session channel; no forwarding or subsystems | [`relay/server.rs`](../crates/broker/src/relay/server.rs), [`relay/session.rs`](../crates/broker/src/relay/session.rs), [`relay/read_ahead.rs`](../crates/broker/src/relay/read_ahead.rs) |
| **B3** Browser to approval UI | Pages; WebAuthn ceremonies; deny and revoke | The browser, and anything that reaches the listener | `require_owner`; `require_same_origin_json`; a strict CSP; server-rendered pages that show agent text as text; a passkey to approve | [`approval/mod.rs`](../crates/broker/src/approval/mod.rs), [`approval/pages.rs`](../crates/broker/src/approval/pages.rs), [`approval/warden.js`](../crates/broker/src/approval/warden.js) |
| **B4** Operator to broker | Settings, `warden-server` commands | None: the host is inside the trust boundary | Validated settings that are never echoed; secret-file checks; changes to agents and passkeys audited | [`config.rs`](../crates/broker/src/config.rs), [`main.rs`](../crates/broker/src/main.rs) |
| **B5** Broker to Connect | The token out; policy, secrets and the CA key back | Connect is trusted, but its answers are still validated | Fields are parsed and refused when invalid; redirects off; secrets held in wiped memory. TLS only if the URL says so: see [Cleartext](#5-common-weaknesses) | [`policy/onepassword.rs`](../crates/broker/src/policy/onepassword.rs) |
| **B6** Broker to notifiers | The agent, the access, a stated session label, a shortened goal, a link | The notifier and its push provider | A link alone approves nothing; redirects off; errors drop the URL | [`notify/mod.rs`](../crates/broker/src/notify/mod.rs) |
| **B7** Broker to API origin | The real secret, the agent's call; the answer | The origin's answer, the agent's call | Rules checked before sending; verified TLS; compressed answers refused; size and time limits; redaction | [`proxy/`](../crates/broker/src/proxy/mod.rs) |
| **B8** Broker to relay target | The onward login | The target, until its pinned key is proven | Host key checked before the credential is sent; only pinned algorithms; channels opened by the target are refused | [`relay/onward.rs`](../crates/broker/src/relay/onward.rs) |
| **B9** Agent to certificate target | A certificate limited to one principal | warden is not on this path | The target's `sshd` decides, using the [principal mapping](threat-model.md#deployment-assumptions); warden sees no logins and cannot end one | [`ssh_ca.rs`](../crates/broker/src/ssh_ca.rs), [`cli/src/ssh.rs`](../crates/cli/src/ssh.rs) |

Two more lines matter:

- **The tailnet policy decides who reaches which port.** warden cannot see it.
  In particular, the rule that an agent machine cannot reach the approval UI is
  a policy rule, not something warden enforces.
- **Inside the broker's process there is no boundary.** A flaw there can reach
  the Connect token, and through it everything in the vault.

## 3. Secure design principles

The Saltzer and Schroeder principles, with how each applies, and where warden
falls short.

- **Economy of mechanism.** One process, one SQLite file, one append-only log, no
  plugin system. The approval UI is server-rendered with one script. A separate
  question is size: the relay and its dependencies are the largest part of the
  attack surface, and it can be left off (`WARDEN_RELAY_PUBLIC_ADDR` unset).
- **Fail-safe defaults.** Access is denied unless a grant says otherwise, and:
  - a request without `methods` is read-only (`scope` in
    [`policy/mod.rs`](../crates/broker/src/policy/mod.rs));
  - listeners default to loopback ([`config.rs`](../crates/broker/src/config.rs));
  - an item with a missing or invalid field is unusable
    ([`policy/onepassword.rs`](../crates/broker/src/policy/onepassword.rs));
  - if the grant state cannot be read for 10 s, relay sessions end
    (`FAIL_CLOSED_AFTER` in [`relay/server.rs`](../crates/broker/src/relay/server.rs));
  - if `proxy_call_started` or `relay_session_started` cannot be written, nothing
    is sent ([`api.rs`](../crates/broker/src/api.rs), `relay/server.rs`);
  - a route that lacks the signature middleware still refuses `Warden-*` headers
    (`AuthedAgent` in [`identity.rs`](../crates/broker/src/identity.rs));
  - `doctor` never counts a check that could not run as passed
    ([`proto/src/doctor.rs`](../crates/proto/src/doctor.rs)).
- **Complete mediation.** Every API call is authenticated by an extractor the
  handler cannot run without. Policy is read from 1Password again at request, at
  approval, and at each call or session start; only the vault id is cached. The
  relay checks live grants every second.
- **Open design.** All of this is public. The only secrets are keys and tokens,
  all of which [can be replaced](#7-replacing-credentials).
- **Separation of privilege.** Approving takes the owner's Tailscale identity
  and a passkey with user verification, on an approval token. Asking and approving
  are on separate listeners, which the tailnet policy gives to separate devices.
  Where it falls short: the identity alone can get a new token from the pending
  screen, and deny and revoke take only the identity, which anything
  that reaches a listener directly can forge, as the
  [deployment assumptions](threat-model.md#deployment-assumptions) say.
- **Least privilege.** Certificates carry one principal and only `permit-pty`
  ([`ssh_ca.rs`](../crates/broker/src/ssh_ca.rs)). The image runs as a non-root
  user in a distroless base ([`Dockerfile`](../Dockerfile)), and the
  [systemd unit](../deploy/systemd/warden.service) has its own sandbox. The
  Connect token should be read-only, which warden
  [cannot check](configuration.md#checking-a-setup). Where it falls short: one
  token reads the whole vault, because every secret passes through one process.
- **Least common mechanism.** A fresh HTTP client per proxied call, so no trust
  decision is shared between secrets (`client_for`). One `ssh-agent` per grant
  on the agent's machine ([`cli/src/agent.rs`](../crates/cli/src/agent.rs)).
  Where it falls short: grants of one agent are not separated by task
  ([#49](https://github.com/pecheriere/warden/issues/49)).
- **Psychological acceptability.** The page and the notification say **Read-only**
  or **Can modify:** ([`approval/pages.rs`](../crates/broker/src/approval/pages.rs)).
  `doctor` says what to fix. Where it falls short: approving is one tap and a
  passkey, so a tired owner can approve a persuasive goal. This is the first risk
  in the [assessment](security-assessment.md#ranked-risks).

Also:

- **Limited attack surface.** Two HTTP listeners and an optional SSH one, meant
  to be reachable only through Tailscale. No listener handles TLS, because Serve
  terminates it, so warden trusts Serve's headers and depends on nothing else
  reaching the listeners.
- **Defence in depth.** Redaction backs up the destination rules, and passkey
  approval backs up the tailnet policy. Neither is treated as enough on its own.
- **Audit before action.** For proxied calls, relay sessions and changes that give
  access, the entry is written first, before any database write (`record` in
  [`requests/transition.rs`](../crates/broker/src/requests/transition.rs)). A change
  that ends access [does not wait for the log](threat-model.md#what-the-audit-log-can-miss):
  its entry is stored with it and written after
  ([`requests/revocation.rs`](../crates/broker/src/requests/revocation.rs)).

## 4. Input validation

Input from outside is checked against what is allowed, not against what is known
to be bad, and parsed into a type before it is used. An invalid value cannot be
constructed, so code holding the type does not check again.

| Input | Allowed | Code |
|---|---|---|
| Agent, target and secret names | `^[a-z0-9][a-z0-9-]{0,31}$` | `AgentName`, `TargetName`, `SecretName` in [`proto/src/lib.rs`](../crates/proto/src/lib.rs) |
| Unix user | `^[a-z_][a-z0-9_-]{0,31}$` | `UnixUser`, same file |
| Goal | 1 to 500 characters, no control or Unicode format characters | `Goal`, same file |
| Ids | 32 lowercase hex characters | `Id`, same file |
| Window | `15m`, `30m`, `1h`, `4h` | `Window`, same file |
| SSH public key in a request | One OpenSSH `ssh-ed25519` key | `check_ed25519` in [`requests.rs`](../crates/broker/src/requests.rs) |
| Agent signing key | `ssh-ed25519` or `ecdsa-sha2-nistp256`; not `sk-*`, not a certificate, not a published test key | `SigningPublicKey` in [`proto/src/signing.rs`](../crates/proto/src/signing.rs) |
| Signature headers | Exactly four, each once; visible ASCII; timestamp digits only; nonce 32 hex; signature at most 4096 characters | `SignatureHeaders::parse` in [`signed.rs`](../crates/broker/src/signed.rs) |
| Request bodies | 16 KiB, or 2 MiB for a proxied call, on the agent API; 64 KiB on the approval UI; JSON into typed structures | `BODY_LIMIT`, `PROXY_BODY_LIMIT` in [`api.rs`](../crates/broker/src/api.rs); `BODY_LIMIT` in [`approval/mod.rs`](../crates/broker/src/approval/mod.rs) |
| Proxied URL, method, headers, body | The rules in [the design](design.md#83-http-proxy-mode-secret-injection), inspected as sent | `check` in [`proxy/rules.rs`](../crates/broker/src/proxy/rules.rs) |
| Relay session requests | `pty-req`, `env` (`LANG`, `LC_*`, `TERM`), `window-change`, `signal`, `shell`, `exec`; limits before start | [`relay/server.rs`](../crates/broker/src/relay/server.rs) |
| 1Password items | Every field parsed, an item with an invalid field refused | [`policy/onepassword.rs`](../crates/broker/src/policy/onepassword.rs) |
| Local policy and secret files | The same validators as 1Password items, plus owner, mode, link, single-file mount and content digest checks on what was opened, each read. A problem refuses the start or the request. | [`policy/local.rs`](../crates/broker/src/policy/local.rs), [`policy/local/files.rs`](../crates/broker/src/policy/local/files.rs), [`policy/local/seal.rs`](../crates/broker/src/policy/local/seal.rs) |
| Answers from the broker, in the CLI | Control characters removed from messages; hosts checked by `is_safe_host`; host keys parsed and written again | `sanitize` in [`proto/src/doctor.rs`](../crates/proto/src/doctor.rs); [`cli/src/agent.rs`](../crates/cli/src/agent.rs) |
| `warden-server agent add --server` | `https` (or `http` on loopback), a root URL, a plain host name, because the printed command is pasted in a shell | `parse_agent_api_url` in [`enrollment.rs`](../crates/broker/src/enrollment.rs) |
| Secret files | Regular file, no access for others, one line, at most 32 KiB | `read_secret_file` in [`config.rs`](../crates/broker/src/config.rs) |

Two inputs are deliberately not restricted: the query string and the body of a
proxied call belong to the agent, and the commands of a relay session or
certificate login are not inspected. The
[threat model](threat-model.md#proxy-mode-residual-risks) records both.

## 5. Common weaknesses

Using [CWE](https://cwe.mitre.org/) names. "Not applicable" means the code has no
such path, which was searched for on the date above.

| Weakness | How it is countered | Limit |
|---|---|---|
| Memory corruption (CWE-787 and others) | Rust with `unsafe_code = "forbid"` in every crate of the workspace ([`Cargo.toml`](../Cargo.toml)). | Dependencies contain `unsafe`, and `webauthn-rs` links OpenSSL. |
| SQL injection (CWE-89) | Every query is a constant string with bound parameters (`sqlx`); no query is built with `format!`. | |
| Cross-site scripting (CWE-79) | `maud` escapes by default and `PreEscaped` is not used. The CSP allows only same-origin scripts and styles. [`warden.js`](../crates/broker/src/approval/warden.js) builds DOM text nodes. `every_page_renders_self_contained` fails on inline styles, external origins or other scripts. | |
| Cross-site request forgery (CWE-352) | `require_same_origin_json`: every state-changing request needs the exact `Origin` and a JSON content type. | |
| Clickjacking (CWE-1021) | `frame-ancestors 'none'`. | |
| Missing authentication or authorization (CWE-306, CWE-862) | The extractors `Owner` and `AuthedAgent`; middleware on the whole approval router; another agent's request or grant is a 404. | The owner's identity is a header: anything that reaches a listener directly [can forge it](threat-model.md#deployment-assumptions). |
| Replay (CWE-294) | Single-use nonce, ±60 s, audience, signed method, target and body ([`signed.rs`](../crates/broker/src/signed.rs)). A ceremony is used once and an approval token is valid only while its request is pending and until a newer one replaces it. | Bearer keys can be replayed by design. |
| Cleartext transmission (CWE-319) | Serve terminates TLS on the listeners. The proxy is `https_only`. `WARDEN_PUBLIC_URL` must be https. The CLI refuses a remote `http` server. | **`WARDEN_OP_CONNECT_URL` and the notifier URLs may be plain `http`** to a host the URL shows to be [local or private](configuration.md#plain-http), or to any host when the owner lists the variable in `WARDEN_ALLOW_PLAIN_HTTP`. The Connect token and the secrets then cross that network in clear, which is why Connect must be on [its own network](threat-model.md#deployment-assumptions) or reached over the tailnet or TLS. warden resolves no name and cannot see who shares the network. |
| Improper certificate validation (CWE-295) | See [`crypto_certificate_verification`](#certificate-verification). | |
| Weak cryptography (CWE-327, CWE-326) | See [Cryptography](#6-cryptography). | |
| Weak randomness (CWE-330) | Tokens, keys, nonces and ids come from the OS (`getrandom`, `OsRng`). Failure is an error or a panic, never a fallback. | |
| Hard-coded credentials (CWE-798) | None. The only keys in the repository are throwaway test keys, and the published test key is [refused at enrollment](../crates/proto/src/signing.rs). | |
| Secrets in logs or errors (CWE-532, CWE-209) | See R6. Errors from `reqwest` use `without_url()`. Parse errors from Connect's answers are not passed on, because they can quote a value. | With `RUST_LOG` above `info`, dependencies log too, and their output was not reviewed. Keep the default. The goal and `exec` commands are logged as sent, so an agent that puts a secret there has it recorded. |
| Secrets left in memory (CWE-316) | `secrecy` and `zeroize` types, and the CA key is dropped after each signature. | Best effort: see [the accepted risks](threat-model.md#accepted-residual-risks). |
| OS command injection (CWE-78) | The CLI runs `ssh` and `ssh-agent` without a shell, with options before `--` and a checked host ([`cli/src/ssh.rs`](../crates/cli/src/ssh.rs)). `warden-server` runs no programs. | |
| Path traversal (CWE-22) | No path comes from a request. On the proxy, the rules refuse dot segments and encoded separators (`check_url`), and the URL is sent as checked. | |
| Server-side request forgery (CWE-918) | The origin comes from the vault and must match exactly; redirects are not followed. | The origin's DNS is trusted, within what TLS verifies. |
| Header injection (CWE-113) | CR, LF and NUL refused; reserved headers refused (`check_headers`). | |
| Log and terminal injection (CWE-117, CWE-150) | Goals have no control characters. The CLI removes them from what it prints. Logs are structured fields. | |
| Unsafe deserialization (CWE-502) | `serde` into typed structures; no code or type names in data. | |
| Resource exhaustion (CWE-400, CWE-770) | Size and time limits on bodies, proxied calls and relay sessions, with counts per agent and overall; pre-login limits; a nonce is stored only after its signature verifies. | **No limit on how many requests an agent makes or on how many notifications they cause, and the database and audit log grow without bound.** See [the assessment](security-assessment.md#findings-of-this-review). |
| Time-of-check to time-of-use (CWE-367) | One item read gives both policy and secret. The destination digest is checked at approval and at use. Approval is one conditional `UPDATE`. A public key's binding is checked inside the write transaction. | |
| Hash truncation (CWE-328) | The 48-bit fingerprint is for people to compare and is not a security check: the approval is tied by token hash and ceremony. | An agent can find two requests with the same fingerprint, so a match proves little if the agent is the attacker. |
| Timing leaks on secrets (CWE-208) | Bearer keys and approval tokens are looked up by SHA-256 hash, so no secret is compared byte by byte. | Agent names [can be probed](threat-model.md#authentication-of-callers), which is accepted. |

## 6. Cryptography

warden implements no cryptographic primitive itself. It calls published
libraries through published protocols. It does assemble some of the framing: for a
P-256 request signature, the broker parses the SSHSIG's signature blob and passes
the signed data to `p256`, and the CLI has its own small `ssh-agent` client
([`cli/src/ssh_agent.rs`](../crates/cli/src/ssh_agent.rs)).

| Use | Algorithm | Strength | Library | Code |
|---|---|---|---|---|
| SSH CA and certificates | Ed25519, refused otherwise | about 128 bits | `ssh-key` | `CaKey::new` in [`policy/mod.rs`](../crates/broker/src/policy/mod.rs) |
| Ephemeral agent keys | Ed25519, refused otherwise | about 128 bits | `ssh-key` | `check_ed25519` in [`requests.rs`](../crates/broker/src/requests.rs) |
| Agent request signatures | SSHSIG with Ed25519 or ECDSA P-256; hash SHA-512 or SHA-256 | about 128 bits | `ssh-key` for Ed25519, `p256` for P-256 | `check_signature` and `sshsig_verifies` in [`signed.rs`](../crates/broker/src/signed.rs) |
| Relay host key | Ed25519 | about 128 bits | `ssh-key`, `russh` | [`relay/host_key.rs`](../crates/broker/src/relay/host_key.rs) |
| Relay target login key | Ed25519, refused otherwise | about 128 bits | `ssh-key`, `russh` | `RelayCredential` in [`policy/mod.rs`](../crates/broker/src/policy/mod.rs) |
| Pinned target host keys | Ed25519, ECDSA P-256, P-384 or P-521, or RSA; verified only | at least 128 bits for the elliptic curves; for RSA, what the operator pinned ([below](#key-lengths)) | `russh`, `ssh-key` | `host_key_algorithms` in [`relay/onward.rs`](../crates/broker/src/relay/onward.rs) |
| SSH transport (relay, both sides) | `mlkem768x25519-sha256`, `curve25519-sha256`, then Diffie-Hellman with SHA-2: group exchange (at least 3072 bits as a client), groups 14 to 18. ChaCha20-Poly1305, AES-GCM, AES-CTR. HMAC with SHA-2. No compression. | at least 112 bits | `russh` defaults, with `aws-lc-rs` | `SAFE_KEX_ORDER`, `CIPHER_ORDER` and `SAFE_HMAC_ORDER` in `russh` 0.65.0 `negotiation.rs` |
| Passkeys | ES256 or RS256; user verification required; origin and RP id checked | about 128 bits for ES256 | `webauthn-rs` (OpenSSL) | `COSEAlgorithm::secure_algs` in `webauthn-rs-proto` 0.5.5 |
| TLS out of the broker and CLI | TLS through `rustls`, certificates verified | as `rustls` configures | `reqwest` with `rustls` | `client_for` in [`proxy/client.rs`](../crates/broker/src/proxy/client.rs) |
| Approval tokens | 256 random bits; stored as SHA-256 | 256 bits | `getrandom`, `sha2` | `approval_token` in [`requests.rs`](../crates/broker/src/requests.rs) |
| Bearer keys | 256 random bits; stored as SHA-256 | 256 bits | `getrandom`, `sha2` | `AgentKey::generate` in [`agents.rs`](../crates/broker/src/agents.rs) |
| Enrollment codes | 60 random bits; stored as SHA-256; single use, 10 minutes | 60 bits, online only | `getrandom`, `sha2` | `create_enrollment_code` in [`approval/passkeys.rs`](../crates/broker/src/approval/passkeys.rs) |
| Ids, nonces, audience | 128 random bits | 128 bits | `getrandom` | `Id::random` in [`proto/src/lib.rs`](../crates/proto/src/lib.rs); [`audience.rs`](../crates/broker/src/audience.rs) |
| Audit chain, destination digest | SHA-256, unkeyed | detects changes only | `sha2` | `compute_hash` in [`audit.rs`](../crates/broker/src/audit.rs) |

Plain SHA-256 is right for tokens and keys here because they are long and random,
so a salt or a slow hash would add nothing. No password is stored or checked by
warden: the only password it handles is a relay target's, read from 1Password
and sent to that target.

TLS on the listeners is outside warden: Tailscale Serve terminates it with the
node's `ts.net` certificate.

### No algorithm with a known serious weakness

`crypto_weaknesses`. By default warden uses none of MD4, MD5, single DES, RC4 or
SHA-1, for signing or otherwise, and the `russh` lists above have no CBC mode,
no 3DES, no SHA-1 MAC and no SHA-1 key exchange. Evidence: the table above; the
relay's own algorithms come from `host_key_algorithms` in
[`relay/onward.rs`](../crates/broker/src/relay/onward.rs), with tests in the
same file.

Exceptions you should know about:

- **SHA-1 on a pinned RSA host key.** warden asks a target for `rsa-sha2-512` or
  `rsa-sha2-256`, never `ssh-rsa`. But `russh` 0.65 does not check that the
  signature uses the negotiated hash, so the holder of the pinned private key
  could sign with SHA-1. That holder is already the target, so this gives them
  nothing they did not have. It is recorded in [`Cargo.toml`](../Cargo.toml).
- **The `russh` default list for the relay's own host key names `ssh-rsa`.** The
  relay holds only an Ed25519 host key and accepts only Ed25519 logins, so it is
  never used.
- **A known advisory in the dependency tree.** `deny.toml` carries one exemption:
  RUSTSEC-2023-0071, a timing attack on RSA private-key operations, in the `rsa`
  pre-release that `russh` pins. warden holds no RSA private key, and that code
  runs only in the broker, to verify the pinned host keys of targets.
- **Certificate targets.** The login between the agent's `ssh` and the target is
  OpenSSH on both sides, and their settings decide its algorithms.

### Key lengths

`crypto_keylength`. Every key warden generates or requires by default meets the
NIST minimum through 2030 (112 bits of security): see "Strength" above. The keys
warden holds are Ed25519, and other types are refused rather than warned about.
RSA keys appear only as pinned host keys of targets. **warden does not check their
length**, and we found no such check in the libraries it reads with: `ssh-key` 0.6
parses the item's key without one, and the conversion in `ssh-key` 0.7.0-rc.11, used
for verifying, has none. So the operator can pin an RSA key that is too short, and must not: pin
one of at least 2048 bits, or a better type. The operator can weaken only what the
operator supplies from outside: a target's host key, or a pinned `ca_pem`, whose
key sizes warden does not inspect beyond what `rustls` accepts.

### Certificate verification

`crypto_certificate_verification`. No code in the repository turns verification
off: nothing calls `danger_accept_invalid_certs`, `danger_accept_invalid_hostnames`
or anything like them, which a search of `crates/` confirms.

| Client | Verification | Code |
|---|---|---|
| Proxied API calls | Hostname always checked. System roots, or only the item's `ca_pem`. `https_only`. Redirects not followed. | `client_for` in [`proxy/client.rs`](../crates/broker/src/proxy/client.rs); `untrusted_cert_refused_without_ca_pem` and `redirect_is_returned_not_followed` in [`tests/proxy.rs`](../crates/broker/tests/proxy.rs) |
| CLI to broker | `reqwest` defaults, which verify. `http` only to loopback. Redirects not followed. | `http_client` in [`cli/src/client.rs`](../crates/cli/src/client.rs) |
| Notifiers | `reqwest` defaults. Redirects not followed. | `http_client` in [`notify/mod.rs`](../crates/broker/src/notify/mod.rs) |
| Connect | `reqwest` defaults, when the URL is `https`. Redirects not followed. | `OnePasswordConnect::new` in [`policy/onepassword.rs`](../crates/broker/src/policy/onepassword.rs) |

The health check talks plain `http` to its own listener on loopback
([`health.rs`](../crates/broker/src/health.rs)), and the demo serves plain HTTP on
loopback.

SSH has the same idea with pinned keys. There is no trust on first use: the
target's host keys come from the vault, the relay checks them before sending a
credential, and the CLI writes them to a per-grant `known_hosts` with
`StrictHostKeyChecking=yes` ([`cli/src/ssh.rs`](../crates/cli/src/ssh.rs)).

### Replacing credentials without recompiling

`crypto_credential_agility`. No credential is in the code or the image. See
[the next section](#7-replacing-credentials). Changing which *algorithms* warden
accepts does take a new release, which is deliberate: the
[signing protocol](agent-protocol.md) has a name and a version
(`warden-request-v1`) so that it can change, and `/v1/info` lists what a broker
accepts.

## 7. Replacing credentials

Credentials and private keys are stored apart from the code and from the
configuration that is not secret. All of them can be replaced by the operator,
without recompiling. The procedures below follow from what the code does; apart
from the operations that tests cover, **they have not been run as a whole against
a live deployment**. Try one before you need it.

| Credential | Where it lives | How to replace it | What happens to what exists |
|---|---|---|---|
| **SSH CA key** | 1Password item tagged `warden:ssh-ca` | [Below](#the-ssh-ca-key) | Read at each approval, so no restart. |
| **API secret** | Its 1Password item | Change the value in the item. | The next call uses it: the value is not part of the destination digest. Changing the origin, prefix, methods, header, format or CA invalidates the grants. |
| **Relay target's key or password** | Its 1Password item | Change it on the target and in the item. | The next session uses it. Open sessions are unaffected. |
| **Target host keys** | Its 1Password item | Change `host_keys`. | Part of the destination digest: open grants stop working and the agent asks again. |
| **Connect token** | Environment, or the file `WARDEN_OP_CONNECT_TOKEN_FILE` names | `op connect token create`, replace it, restart `warden-server`, then revoke the old one. | Grants survive a restart. Relay sessions and calls in flight end. |
| **Notifier URL or token** | Environment, or a `_FILE` | Replace it and restart. | As above. |
| **Key-signed agent's key** | The agent's machine; the broker holds the public half | Make a new key, then `warden-server agent set-key <name> '<line>'`. | The old key stops at once, even with the server running: the key is read for every request. Grants stay. Keys already enrolled by any agent, revoked or not, are refused. |
| **Bearer agent key** | The agent's machine; the broker holds a hash | There is no command to replace it. Better: move to a signing key with `agent set-key`. Otherwise `agent revoke <name>` and `agent add` under a **new** name, as a revoked name stays taken. | `set-key` deletes the bearer key at once. `revoke` also ends the agent's requests and grants. |
| **Ephemeral key, certificate** | The agent's per-grant `ssh-agent` | Nothing to do: a new one for each request. | No new login after the window. A login already open continues. |
| **Relay host key** | The file at `WARDEN_RELAY_HOST_KEY_PATH` | Stop warden, move the file away, start warden: it makes a new one. | Each relay grant stores the old public key, so its logins are refused by the agent's `ssh` until it asks again. Revoke those grants first. |
| **Passkey** | The owner's authenticator; the broker holds the public key | `warden-server enroll` to add the new one, `warden-server passkey remove <id>` to remove the old one. | Takes effect at once. |
| **Passkey's relying party** | `WARDEN_PUBLIC_URL` | Changing the host invalidates every passkey: enroll again. | |
| **Audience** | The file at `WARDEN_AUDIENCE_PATH` | Not a credential, and it is not meant to change. Replacing it makes every key-signed agent log in again. | |

### The SSH CA key

warden uses whichever key the item holds when an approval happens, so the
transition is on the targets. `TrustedUserCAKeys` and `authorized_keys` can each
hold several CA keys.

1. Generate a new unencrypted Ed25519 key.
2. On every certificate target, **add** the new public key, keeping the old one.
3. Replace the private key in the item tagged `warden:ssh-ca`. Keep exactly one
   item with that tag: two is an error, and refused until fixed.
4. Run `warden-server doctor`: the `ssh-ca` check loads the key. Make one request
   to confirm that a target accepts the new certificate.
5. Wait for the old certificates to end. Four hours after step 3 is enough, as
   that is the longest window.
6. Remove the old public key from every target, and reload `sshd` if the key was
   in a `TrustedUserCAKeys` file.

**If the old key may be compromised**, or you must cut certificate access off now,
do step 6 straight away. That refuses new logins with any certificate that key
signed, and it is the one way warden's setup offers to
[revoke certificates](threat-model.md#accepted-residual-risks) today. Agents with a
live grant have to ask again.

**It does not end sessions that are already open**, and neither does a certificate
expiring: `sshd` checks a certificate when it authenticates, and not afterwards.
We confirmed this on a throwaway OpenSSH 10.3 server: a session kept running after
its certificate expired and after the CA was removed and `sshd` reloaded, while new
logins were refused. So on each target, also:

7. See what the account is running: `ps -u <user>`. `who` is not enough, as it
   misses sessions without a terminal.
8. If the account is [used by warden alone](ssh-targets.md#the-recommended-setup-one-user-per-agent),
   end all of it, **as root**: `pkill -KILL -u <user>`. Run from another account it
   only fails. That also ends what a session left running in the background. Then
   check with `ps -u <user>`, and repeat until nothing is left: a process that keeps
   forking can slip past one pass. If it cannot be cleared, restart the host. On an
   account that does other work too, `pkill -u` would stop that as well, so kill the
   processes you identified instead.
9. Look for what would outlast this: cron jobs, added `authorized_keys` lines,
   services, and anything started under another account through `sudo`, which
   `pkill -u` does not match. warden cannot see any of it. Anyone holding the old
   key could also have signed any principal, so read each target's `sshd` log for
   the period: it names each certificate's key id and CA.

We ran steps 7 and 8 in a Debian 12 container with OpenSSH 9.2: `pkill` as root
ended a live session, and a process that kept replacing itself took a second pass.
They have not been run on a real target. Check that they work on yours, in
particular on an appliance whose tools differ.

To refuse one certificate and not the whole CA, `sshd`'s `RevokedKeys` setting takes
a list of keys ([`sshd_config(5)`](https://man.openbsd.org/sshd_config#RevokedKeys)).
It too applies to new logins only.

## 8. How the project keeps this true

- **Every change** passes `cargo fmt`, clippy with `all` and `pedantic` denied,
  all tests and `cargo doc` with warnings denied. See the list in
  [`AGENTS.md`](../AGENTS.md) and [`ci.yml`](../.github/workflows/ci.yml).
- **The tests** cover forgery and replay ([`signed.rs`](../crates/broker/tests/signed.rs)),
  approval binding ([`approval.rs`](../crates/broker/tests/approval.rs)), proxy
  rules and redaction ([`proxy.rs`](../crates/broker/tests/proxy.rs)), and the
  relay against a real OpenSSH server ([`relay.rs`](../crates/broker/tests/relay.rs)).
  This document's claims are not themselves tested, but the
  [protocol's test vectors and worked client](agent-protocol.md#4-test-vectors) are.
- **Dependencies**: `cargo deny` for advisories, licences and sources, nightly
  too ([`advisories.yml`](../.github/workflows/advisories.yml)); a 7-day minimum
  age for new crate versions
  ([`crate_age.py`](../.github/scripts/crate_age.py)); dependency review on pull
  requests.
- **CI itself**: actions pinned to full commit hashes, checked by `zizmor`.
- **Static analysis**: GitHub CodeQL, and OpenSSF Scorecard
  ([`scorecard.yml`](../.github/workflows/scorecard.yml)).
- **The `main` branch** takes pull requests only, with signed commits, linear
  history and required checks.
- **Releases**: the image and the CLI, server and demo binaries have build-provenance attestations
  ([`release.yml`](../.github/workflows/release.yml)).
- **Fuzzing and coverage**: a scheduled job fuzzes part of the code that parses
  untrusted input ([#91](https://github.com/pecheriere/warden/issues/91)), and CI
  measures coverage and fails below 80% of lines
  ([#97](https://github.com/pecheriere/warden/issues/97)).
- **Not yet in place**: an independent review.

When behaviour changes, [`AGENTS.md`](../AGENTS.md) requires the documents to
change in the same pull request. That includes this page and, for anything that
moves a risk, [the assessment](security-assessment.md).
