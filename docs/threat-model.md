# Threat model

This describes what warden protects, who it trusts, what it must never allow,
and the risks that are accepted. It covers the SSH certificate mode, the SSH
relay mode (sessions the broker relays to targets that cannot trust a CA) and
the HTTP proxy mode (brokered API calls that use a stored secret). The design
rationale is in [design.md](design.md), and how to deploy warden so that the
assumptions at the end of this page hold is in [deployment.md](deployment.md).
The [assurance case](assurance-case.md) argues how the code meets all this, and
the dated [security assessment](security-assessment.md) ranks what is most likely
to go wrong. Both are the project's own, not an independent review.

## In short

warden protects against an agent that holds standing credentials, against
an agent that approves its own access, and against secrets leaking to the
agent or to notification services. Every grant needs the owner's passkey on
the owner's phone, is bounded in time and scope, and is audited.

warden does **not** protect against:

- **Whoever controls the warden host.** Root on that host (or on the
  container runtime) can read the CA key, the Connect token and relay
  credentials from memory, rewrite the database and the audit log, and
  issue grants. The host is the root of trust: keep it as locked down as
  the most sensitive target warden reaches.
- **Whoever controls the 1Password vault**, who decides what warden may hand
  out and where secrets may go.
- **A compromised agent machine, within its approvals.** Code running as the
  agent's OS user can make requests and use that agent's grants while they
  last. Each request still needs the owner's approval.
- **Use of a grant for another task by the same agent.** Grants are not tied
  to a task: everything that runs as the agent's OS user can use any of the
  agent's active grants (issue
  [#49](https://github.com/pecheriere/warden/issues/49)).
- **The owner approving a misleading goal.** warden shows the goal, the
  scope and a fingerprint; it cannot judge whether the goal is honest.
- **What happens on the target or API during the window.** An approved
  shell or API scope can do anything it permits until the grant ends. On a
  certificate target warden does not see the logins at all, and a login already
  open does not end with the grant.
- **Instant revocation everywhere.** An issued certificate stays valid on
  its target until it expires, and an open login to a certificate target continues
  even after that (issue
  [#35](https://github.com/pecheriere/warden/issues/35)). A proxied API
  call already in flight runs to completion (issue
  [#44](https://github.com/pecheriere/warden/issues/44)).

This page is about a real deployment. The [local demo](demo.md) is a separate
binary that is not secure for real use: on it, everyone on the machine counts as
the owner. It is not in `warden-server` or the image, and a CI guard keeps it
out.

## Actors and trust

| Actor | Trust |
|---|---|
| Owner (phone, workstation) | Root of trust. Holds the passkey. Edits the 1Password vault. |
| The warden host (its root, its container runtime) | Root of trust. Can read everything warden holds and act as warden. |
| Agent (for example an AI coding agent on the owner's workstation) | Semi-trusted: well-intentioned but may be prompt-injected. Bounded by its stated goal, the approved window, and the targets and users the vault allows. It can request access and use what was granted, never approve it. |
| warden server | Trusted. Holds a read-only 1Password Connect token in memory, and for short times what it reads with it: the SSH CA private key, from the read at an approval until the certificate is signed, API secrets during a call, and relay login credentials (see below). Compromise of the server is compromise of everything it brokers, so it is hardened accordingly. |
| 1Password Connect | Trusted secret backend. Reachable only from warden, on its own network, and unable to reach warden's listeners. |
| Notifiers (Home Assistant Companion, ntfy, push providers) | Untrusted doorbells. They receive the goal text, agent, target and a link, and nothing else. They cannot approve anything. Which channels are used is fixed at startup from a compile-time set (`WARDEN_NOTIFY`); agents cannot influence it. |
| Tailscale | Transport and network-level identity. The tailnet policy is the outer access control. |

## Anti-goals

These are failures even if everything else "works". Each lists how warden
defends against it.

- **An approval is forged, replayed, widened or applied to a different request
  than the one displayed.** Approval needs a WebAuthn assertion from an
  enrolled passkey. The approval token is at least 128 bits of randomness,
  stored only as a SHA-256 hash, single use, tied to one request and expiring
  with it. The window cannot exceed what the target allows. An approval is
  valid only on the approved target: the certificate's single principal is
  `warden:<target>:<user>`, which only that target's host maps to the account
  (see "Targets trust the CA, per target" below). See "Approval binding"
  below.
- **A notification channel sees secrets or can approve.** Notifications carry
  the agent, target, user, a goal truncated to 200 characters, and a link.
  The link opens a page that only the owner's phone can reach and that still
  requires a passkey.
- **Private keys are written to disk on the workstation.** The CLI keeps the
  ephemeral Ed25519 key in memory and hands it to a dedicated per-grant
  `ssh-agent`. For a key-signed agent the CLI stores no secret at all: it signs
  through an `ssh-agent`, and whether that key sits in hardware or in a file is
  the operator's choice. A bearer key lives in the macOS Keychain (or in
  `WARDEN_AGENT_KEY`). Otherwise the CLI
  stores only its configuration (server URL, agent name, the signing key's
  public half, the `ssh-agent` socket and the pinned audience), grant
  records, sockets and `known_hosts` files, in 0700 directories with 0600
  files.
- **warden becomes the easiest way into the network.** It runs as a non-root
  user in a distroless image with no shell, listens only where Tailscale
  Serve can reach it (on a network of its own behind a host whose Serve
  publishes it as Tailscale Services, or on loopback in the network
  namespace of its Tailscale sidecar), and is exposed only through that
  Serve. It holds a read-only Connect token. Run as a systemd service instead,
  it has no image of its own: see "systemd service" under "Deployment
  assumptions".
- **Silent failure.** The CLI always receives an explicit terminal state:
  `approved`, `denied`, `expired`, `cancelled`, `revoked` or `error` with a
  message.
- **An API secret reaches the agent.** In proxy mode the broker reads the
  secret from 1Password only when a call is made, in the same single read of
  the item as the policy it is checked against, builds the header from the
  policy, sends the call itself and redacts the answer. The agent supplies no
  placeholder and no part of the header. The destination is the item's origin
  (exact match), a path prefix on a segment boundary, and an allowed method
  list; changing any of them, the header, its format or the pinned CA between
  approval and use invalidates the grant (409).

## Approval binding

The design called for a WebAuthn challenge derived from the hash of the exact
request plus the chosen window. webauthn-rs generates and verifies the
challenge itself, so warden binds the approval differently, with an equivalent
guarantee because the server is the trusted party. The passkey's signature does
not itself cover the request: it covers a random challenge, and the link between
the two is state on the server. So the signature alone cannot prove afterwards
what was approved, and a compromised broker could misapply it.

- The server starts the passkey ceremony for one specific request and window.
  The ceremony state, including the challenge, is kept server-side and keyed
  to that request, the chosen window and the approval token. It is consumed by
  the first completion attempt.
- The assertion is verified against that stored state, so it cannot be used
  for another request or another window, and a replay finds no state.
- The approval page and the CLI both show a short fingerprint of the request
  (a hash of the agent name and the whole request: target, user, requested
  window, goal and public key). It is 48 bits, for people to compare, so an agent
  could craft two requests that share one: it detects a mix-up, not an attacker
  who controls both. If the owner is talking to the person or agent
  that made the request, they can compare the two before approving. A mismatch
  means the owner is looking at a different request and should deny it.
- The destination the page shows (host, port and the target's host keys; for
  an API secret its origin, path prefix, methods, header, value format and
  whether a CA is pinned) is bound too. The page embeds a digest of it, the
  ceremony begins only if the target or secret still has that digest, and the
  approval completes only if the item re-read at that moment still matches.
  If the 1Password item changed in between, the owner is asked to reload and
  review.
- The certificate is signed for the exact ephemeral public key in the request.
  One certificate is issued per grant. The grant id is not a bearer credential
  and cannot mint further certificates.

## Authentication of callers

- Every endpoint on both listeners requires the `Tailscale-User-Login` header
  to equal `WARDEN_OWNER_LOGIN`, with these exceptions on the agent API:
  `GET /healthz` (unauthenticated for the container health check, a static
  body revealing nothing), `GET /v1/info` (the public signing protocols and
  audience, which a client reads before it can sign), and signed requests of
  key-signed agents (below). The header is set by Tailscale Serve after it
  authenticates the peer. The CLI never sets it.
- **No exemption reaches the internet.** Every route of the agent API,
  `GET /healthz` and `GET /v1/info` included, refuses with
  `401 {"error":"unauthorized"}` a request carrying the
  `Tailscale-Funnel-Request` header, which Serve sets on requests that came
  through Tailscale Funnel, whatever credentials (signature or bearer key)
  it carries; a signed one's body is not read. The exemptions above assume
  a tailnet peer: published through Funnel by mistake, the API would let
  anyone on the internet read the audience and try signed requests. The
  approval UI needs the owner's login, which Funnel requests never carry; it
  has no Funnel check of its own, so it relies on Serve for this.
- Agent endpoints also require the agent to authenticate, in one of two ways.
  A request with any `Warden-*` header is authenticated by its signature or
  refused; it is never treated as a bearer request.
  - **Signed requests** (`warden-request-v1`, see
    [agent-protocol.md](agent-protocol.md)). The broker checks, in order and
    stopping at the first failure: the four `Warden-*` headers are present
    once each and well formed, `Warden-Signature` is at most 4096
    characters (refused before decoding), and no `Authorization` header
    comes with them; the agent exists, is not revoked and has a registered
    key; the timestamp is within 60 s of the broker's clock; the body fits
    the route's limit (413 otherwise, before any signature work); the
    SSHSIG verifies in namespace `warden-request-v1`, with hash `sha512` or
    `sha256`, by exactly the registered key (the key embedded in the
    signature must equal it), over the canonical message rebuilt from the
    request as received (audience, agent, method, path and query, timestamp,
    nonce, body SHA-256); and the `(agent, nonce)` pair is new. Every other
    failure is a 401 with a fixed body (a database failure is a 500); the reason
    is logged without key material or signature bytes. A captured request cannot be replayed (the nonce is
    single use and remembered for 10 minutes, longer than the ±60 s window),
    sent to another broker (the audience), or altered (method, target and
    body are signed). The nonce is recorded only after the signature
    verified, so callers who cannot sign cannot fill the nonce table, and
    expired nonces are swept. Other `Warden-*` header names are reserved
    and refused.
  - Before a signed request is verified, its body is read capped in size
    (the route's limit, 16 KiB or 2 MiB for proxied calls; 413) and in time
    (the larger of 10 s and the limit at 128 KiB/s: 10 s, or 16 s for
    proxied calls; 408), so a caller naming a known agent cannot hold a
    connection or memory beyond that without a valid signature.
  - **Agent names are not secret.** An unauthenticated peer that can reach
    the API can learn whether a name belongs to an enrolled, unrevoked
    key-signed agent: such a name gets a 413 or 408 for an oversized or slow
    body, any other name a 401. This is accepted: agent names appear in
    notifications and logs, and knowing one gives no way to sign.
  - Each refused signed request is logged at warn level with its reason
    (and the agent name once it parsed). A caller can therefore add log
    lines at the rate it can send requests; this is bounded by who the
    tailnet policy lets reach the API port, and accepted.
  - **Bearer keys** (legacy): `wdn_` followed by 256 random bits, shown once
    and stored only as a SHA-256 hash, accepted only with the owner's
    `Tailscale-User-Login`.
- **Key-signed agents need no owner login (deliberate).** A key-signed agent
  may run on a tagged device (an agent host), which has no Tailscale user
  login, so the broker does not require `Tailscale-User-Login` for signed
  requests and ignores whatever login Serve reports for them. The signature
  is the authentication; who may reach the API port at all is decided by the
  tailnet policy (and, if you run one, a gateway's app capability). The
  consequence:
  any tailnet device the policy lets reach the API can send signed requests,
  and only possession of an enrolled signing key separates it from an
  agent. Keep the API port's grant as narrow as the agents that need it.
  Bearer-key agents keep requiring the owner's login.
- Grants are bound to the agent that requested them. Revoking an agent
  disables its key at once, ends its pending requests and grants, and wakes
  its waiting CLI calls.
- The approval endpoints are meant to be reachable from the owner's phone and
  not from a machine an agent runs on (see "Deployment assumptions").

## Accepted residual risks

These were recorded during implementation and are accepted for this release.

- **The CA key is copied into HTTP client buffers.** The CA private key PEM is
  read from 1Password Connect over HTTP. Parts of it can sit in reqwest and
  hyper buffers that warden does not control and cannot zeroize. The parsed
  key warden holds is zeroized on drop. The mitigation is the hardening
  described under "Deployment assumptions": an unprivileged process, no
  capabilities and, in a container, no other container on its network.
- **Signing protects the key, not the machine.** A key-signed agent's
  signature stops credential theft on the wire (nothing reusable is sent), and at
  rest when the key is in hardware (a key in the Secure Enclave, a TPM or a PIV
  token cannot be copied off the machine; a key file can), replay (single-use nonce, 60 s window) and reuse against another
  broker (the audience) or another endpoint or body (all signed). It does not
  stop code running as the agent's operating-system user: whatever can reach
  the agent's `ssh-agent` socket can ask it to sign, for as long as it runs
  there. That is the same position as a prompt-injected agent, and the
  defences are the same: every request still needs the owner's passkey
  approval on the phone, grants are short and scoped, and revoking the agent
  ends all use of its key, hardware-backed or not. Hardware-backed keys are
  recommended because they leave the attacker only that access while they
  are on the machine, with nothing to take away; a plain key file can be
  copied and used from anywhere that can reach the API. Because key-signed
  agents are exempt from the owner-login check (above), the tailnet policy
  (and a gateway's app capability, if you run one) is the only network gate
  besides the signature.
- **Bearer agent keys are bearer credentials.** Anyone who obtains a bearer
  agent key can replay it from a host that can reach the API with the
  owner's login (key-signed agents do not have this problem; switch an agent
  with `warden-server agent set-key`). The key is the agent, so whoever holds it
  can use the agent's live API grants within their scope, read the answers, list
  and revoke its grants, and cancel its requests. A signing key copied from a file
  gives the same, without needing the owner's login. Neither can approve anything:
  each new request still needs a passkey approval that shows the agent name and
  goal. Neither can use a live SSH grant, which needs that grant's ephemeral key. A
  leaked key is revoked with `warden-server agent revoke`, which ends all of this.
- **Certificates cannot be revoked before they expire, and open logins outlive
  them.** Revoking a grant stops new issuance and the CLI's use of it, but a
  certificate already issued stays valid on target hosts until it expires. The
  windows are short (at most four hours) and each certificate is bound to a key
  that exists only in the agent's memory, which limits new logins. It does not
  limit a login already open: `sshd` checks a certificate when it authenticates,
  so a session, and whatever it left running, continues after the window and after
  a revocation, until something on the target ends it. warden cannot see or end it.
  Use relay mode where sessions must end on time.
  [Ending them by hand](assurance-case.md#the-ssh-ca-key) is possible. Distributing
  a revocation list to targets is out of scope.
- **Revocation from the server CLI is not instant for waiting clients.** A
  `warden-server agent revoke` run from the command line changes the database,
  but the running server only re-reads it when a long poll wakes, so a waiting
  client can take up to 30 seconds to see the terminal state.
- **Cloned authenticators are detected, not prevented.** The broker keeps
  each passkey's signature counter in its own column and raises it with a
  single conditional update, so concurrent approvals can never store an older
  value. An assertion whose counter is not above the stored one (a non-zero
  authenticator that goes backwards or repeats) is refused with a fixed
  message, no grant is issued, and `passkey_counter_regressed` is audited.
  Two signatures from the same authenticator that arrive out of order are
  refused the same way; the owner simply approves again. An approval of a
  request that was already decided is refused as such before the passkey is
  checked, but two approvals of the same request finishing at the same moment
  can still be refused as a counter regression (and audited); exactly one of
  them is approved. Passkeys that always
  report a counter of 0 (most platform passkeys) cannot be checked this way: a
  cloned one of those is not detected.
- **Grants are not tied to a task** (issue
  [#49](https://github.com/pecheriere/warden/issues/49)). `warden ssh` and
  `warden http` use any active grant of the agent for the target or secret
  (the one that stays valid longest), and the broker accepts any grant of
  the calling agent. Two sessions of one agent, or one session across
  tasks, can therefore use a grant whose goal the owner approved for
  something else. The audit log still names the grant and the agent. The
  mitigations today: one request per task, revoking each grant when its task
  ends, and separate agents (separate OS users and keys) for work that must
  not share grants.
- **An agent can still send the owner some notifications.** A flood of requests
  makes a careless approval more likely and can hide one that matters, so each
  agent may have 5 requests pending and make 10 new ones per 10 minutes by
  default ([configuration](configuration.md#request-limits)). The counts come
  from the database, in the transaction that would store the request: creates
  cannot race past them, a restart does not reset them, and a database that
  cannot be read refuses the request. Every stored request counts, so cancelling
  and asking again gains nothing, but a duplicate of a pending request does not,
  as it stores nothing and rings nobody. Within the limits an agent can still
  cause up to 60 notifications an hour. An owner who sees that should revoke the
  agent. Requests that end in `error` because no notification channel worked
  count too, so an outage of the channels can use up an agent's allowance for
  one window.
  - **The limits cannot block anyone else for long.** The counts are per agent,
    and there is no shared limit, so one agent cannot use up another's allowance
    or stop the owner from deciding. An agent that uses up its own waits at most
    the window (an hour at the highest setting) for a new request, or 10 minutes
    for a pending slot. A key that is stolen can only block its own agent.
  - **A clock set back is not a long block.** Requests dated ahead of the clock
    do not count towards the window, so a step back gives an agent one fresh
    allowance rather than holding the limit until the clock catches up. Pending
    requests dated ahead of it do count, as they really are pending until they
    expire: `Retry-After` then gives that longer wait, and the agent can cancel
    one to free a slot at once. After a small step back, `Retry-After` for the rate
    limit can be too short, as requests dated ahead start to count again when the
    clock reaches them; the next refusal gives the new wait. An agent cannot move
    the broker's clock.
  - **Refusals cannot fill the audit log.** An agent can send refused requests as
    fast as it can sign them. The first is audited as `request_limited` and the
    rest are counted and written at most once a minute; the count is written by
    the periodic sweep and at shutdown even if the agent stops. A crash can lose
    the count of up to a minute of repeats, never the fact of the first refusal.
    If an entry cannot be written, the request is still refused and the count is
    tried again a minute later, so an audit outage does not flood the server log. The owner gets one notice per agent per hour at most, with the
    agent's name and no text the agent chose. A notice that cannot be delivered
    is audited and not retried until that hour has passed.
  - **Refused requests are not free.** The request is checked against the policy
    first, so each refused request still reads the item from 1Password Connect
    and, for a signed request, verifies a signature and stores a nonce. This is
    bounded by who the tailnet policy lets reach the API, as for other refused
    requests. A flooding agent can affect others in two ways: by slowing 1Password
    Connect, which they also read, and through the shared database, whose write
    lock each refused request takes. The server log has one warning per agent per
    minute at most.
- **Certificate logins are not audited.** They go straight to the target. warden
  records the approval and the certificate, and the target's `sshd` logs the login
  with the certificate's key id. Ship those logs if you need that trail.
- **A certificate's `cert_issued` entry can be missing.** The approval is committed
  and audited first. If writing the entry for the certificate then fails, this is
  logged and the grant stands. The `approved` entry still names the grant.
- **Connect and notifiers can be configured over plain HTTP.** warden does not
  require `https` for `WARDEN_OP_CONNECT_URL` or the notifier URLs, because Connect
  on its own network and a local Home Assistant commonly use `http`. On a network
  that is not private, that exposes the Connect token and everything it reads.
- **Secrets in the environment.** Unless given through a `_FILE` variable (see
  [Configuration](configuration.md#secrets-in-files)), the Connect token and the
  notifier secrets are in the process environment, readable by root and the same
  user. A `_FILE` keeps them out, and may allow group access. It is read once at
  startup.
- **Goals are free text.** The goal is a single line of at most 500 characters
  without control characters or invisible format characters (bidi overrides,
  zero-width characters). The owner decides on the goal alone, and a
  prompt-injected agent can write a misleading goal. The fingerprint check,
  the narrow user and the short window limit the damage.

## Proxy mode residual risks

- **The destination sees the secret, by design.** The approved origin gets
  the real credential in every call. The owner must trust that origin and the
  path prefix. A secret whose origin can act on the agent's behalf beyond the
  stated goal (a broad token on a general-purpose API) is only as safe as that
  origin and the window allow. Keep the website, `path_prefix` and `methods`
  as narrow as the use needs, and use a token with the least scope the service
  offers.
- **Redaction is defence in depth, not a guarantee.** It removes the secret
  and the injected header value from responses in the raw, base64,
  percent-encoded, JSON and HTML forms listed in the design, so a service that
  echoes its input does not hand the secret to the agent. A response header
  whose name carries the secret is dropped, matched regardless of letter case.
  It cannot catch
  every transformation (encryption, hashing, other encodings, a secret split
  across calls) and, inside a larger base64 blob, at most 4 bits of the secret
  per side can remain at the boundary. Compressed responses are refused
  because they cannot be inspected. The real control is the destination rule.
- **Revoking does not stop a call in flight** (issue
  [#44](https://github.com/pecheriere/warden/issues/44)). A revoke refuses
  new calls and withholds the response of a call already sent (409), but the
  upstream request runs to completion (at most 30 s), so a state-changing
  call sent just before the revoke still takes effect.
- **Within the window, the agent can make any allowed call.** Approval is
  bound to an origin, prefix, method set and window, not to individual
  requests. A prompt-injected agent can issue any call the grant permits
  until it expires or is revoked, including state-changing calls if the owner
  approved `POST`, `PUT` or `DELETE`. Choose methods and window accordingly,
  and revoke when done.
- **The agent cannot widen a request.** The 1Password item is the ceiling. A
  request without `--methods` is read-only; requested methods or a path
  prefix outside the item's (including `CONNECT`, `TRACE`, `/apiary` for
  `/api`, dot segments and encoded separators) are refused when the request
  is made, and nothing is notified. The broker stores the approved scope and
  checks it on every call; the agent never supplies it again, so a call
  outside the grant is refused even if the item allows it. Editing the item
  after approval invalidates the grant through the destination digest.
- **The owner decides, and can misjudge.** The approval page shows
  **Read-only** or **Can modify:** with the methods; the notification says
  `(read-only)` or `(CAN MODIFY: …)` with them. A pending read-only request
  never absorbs a write request. A phone owner who approves a "Can modify"
  request without reading it, or on a persuasive goal, grants write access for
  the window. Residual: warden shows the scope; it does not decide whether the
  goal justifies it. Prefer short write windows and a separate read-only grant
  for the rest.
- **The query string and body are the agent's.** They are not restricted by
  the policy, and the query is not written to the audit log.
- **Redirects and other origins.** Redirects are never followed, so the secret
  cannot be carried to another origin by a 3xx. The 3xx is returned to the
  agent, which cannot reuse the secret elsewhere.
- **The server holds the secret briefly in memory.** It is fetched per call,
  wiped after use, and never logged or audited. Parts of it may sit in HTTP
  client buffers that warden cannot zeroize, as for the CA key above.

## Relay mode residual risks

- **The broker holds target credentials.** A relay target's private key or
  password is read from 1Password and validated whenever the target item is
  read (at request, at approval and at session start), and used only at
  session start, where it is held zeroized and dropped right after the onward
  login. A compromise of the running broker can therefore expose the
  credentials of relay targets it reads, in the same way it exposes the CA
  key. The relay is for targets that cannot trust a CA; prefer certificate
  mode where it is possible. The credential never reaches the agent, the
  notifiers or the audit log. Give each relay item a credential that is valid
  only for that target and account.
- **Parts of a password are copied beyond warden's reach.** The SSH library
  takes a password as a `String`, which warden cannot zeroize, and the
  credential also passes through HTTP client buffers (as the CA key does). A
  password therefore may remain in freed memory after use; a private key does
  not have this copy, which is why relay keys are limited to Ed25519 and
  passwords are the alternative for everything else.
- **Approval binds to the key, and the key to one access.** The relay accepts
  an agent only by the ephemeral public key bound into the approved request. A
  public key can be bound to one live request or grant at a time across all
  agents, so one agent cannot use another's approval. The ephemeral private
  key exists only in the agent's `ssh-agent`, as in certificate mode.
- **Pinned host keys are required.** There is no trust on first use. Key
  exchange negotiates only the algorithms of the pinned keys. RSA and ECDSA
  host keys are accepted (verification only); SHA-1 signatures are never
  negotiated, but a holder of the pinned private key could still sign with
  one. An attacker who holds a target's host key can impersonate it to the
  broker.
- **Everything inside the window passes through the target.** Once logged in,
  the agent has the approved account's shell for the window. The relay forbids
  port, agent and X11 forwarding and subsystems such as sftp, and filters the
  environment, but it does not inspect commands. The audit log records
  `exec` commands (first 200 characters) and byte counts, not interactive
  input.
- **Bounded, not instant, teardown.** Revocation, expiry, the 15 minute idle
  limit and failures end a session; once it is told to end, it has at most
  1 s to close before both connections are cut hard. Revoking through the
  broker acts at once and expiry is checked every second, so such a session
  is gone within about 2 s. A revoke made by another process (the server CLI)
  is found by a check every second, each query bounded to 1.5 s: about 5 to
  6 s in the worst case with a healthy database. With a database that cannot
  be read, the relay fails closed (below) within about 10 to 11 s.
- **Flow control is watchdog-based.** The SSH library has no reader-driven
  back-pressure, so each direction of a session has a byte-bounded queue
  (2 MiB towards the target, 8 MiB towards the agent) and a session whose
  receiver does not read is ended: after 60 s of held, undelivered data in one
  direction (reason `flow control: output to the agent not drained` or
  `flow control: input to the target not drained`), or 2 s when both
  directions are held up at once (`flow control: both directions held up`).
  A target that stops reading its input is a target
  failure, and the session ends. An agent that disconnects meanwhile is
  still seen, through a read-ahead on its connection, and its session ends
  about 2 s later (`client closed`); its input still held is dropped. The
  read-ahead is bounded: the bytes it counts are capped at 64 KiB before
  login (640 KiB across 10 unauthenticated connections) and 4 MiB per
  session after; heap use stays within a small constant factor of that
  (each chunk counts for at least 128 bytes), plus a 16 KiB read buffer and
  at most one partly read 16 KiB chunk per connection. With the session's
  queues (2 MiB towards the target, 8 MiB towards the agent) a session
  counts for at most 14 MiB, so the total scales with
  `WARDEN_RELAY_MAX_SESSIONS`: 224 MiB at the default of 16 sessions, 64 MiB
  of it read-ahead. An agent
  that keeps its connection open and sends past its window, or in many tiny
  packets (no client does), only fills the read-ahead; its session ends by
  the 60 s stall rule.
- **The per-address pre-login limit is global behind Tailscale Serve.** The
  relay allows 5 connections per source address and 10 overall that have not
  logged in. Serve forwards every TCP stream from one address (the node's
  loopback in the sidecar layout), so every peer has the same address and the
  per-address limit acts as a global one: a peer that can reach the relay port
  can fill the login slots for a few seconds at a time (10 s login timeout, 3
  attempts). It does not let anyone in. The tailnet policy decides who can
  reach the port; grant it to the agent machines only.
- **Fail closed when state cannot be read.** The relay checks the grants of
  its live sessions every second, each check bounded to 1.5 s. If none
  succeeds for 10 s, every relayed session ends (reason
  `grant state unavailable`) and no session starts until a check succeeds. A
  database outage longer than 10 s therefore ends relay sessions, by design.
- **A session start is recorded first.** `relay_session_started` is written
  before the first byte reaches the target; if it cannot be written, the
  session does not start.

## Deployment assumptions

warden's guarantees depend on its environment being set up as follows.

- **Publishing through Tailscale.** One of the two Docker deployments below or,
  with less isolation, the systemd service after them.
  In every case, only Tailscale Serve (or a reverse proxy that Serve targets)
  may reach the listeners: anything that can reach a listener directly can
  forge `Tailscale-User-Login`. (Signed agent requests do not rely on the
  header, but the approval UI and bearer-key agents do.)
- **Tailscale Services (recommended).** The host, which must carry a tag
  identity, publishes the approval UI and the agent API as separate Services
  (`tailscale serve --service=svc:<name>`); each has its own MagicDNS name,
  so the relying party is the approval Service's name and is not shared.
  The listeners are bound to warden's address on a network that holds
  warden alone (and its reverse proxy, if any), never to `0.0.0.0`, and no
  port is published. Unlike the sidecar, every process on the host and
  every container with host networking can connect to the listeners and
  forge the header, so the whole host is inside the trust boundary: it runs
  nothing untrusted and no host-network container, and local access to the
  listeners can be limited to tailscaled (see
  [deployment.md](deployment.md#who-can-reach-the-listeners)). The Docker
  Engine is 28 or later, which stops other LAN machines from routing to
  unpublished container ports. Network access is a grant
  with `dst: svc:<name>`; an application capability reaches warden (or a
  gateway in front of it) only when its grant targets the host (`tag:` or IP
  alias), because `app` capabilities on a `svc:` destination are not
  forwarded. Serve strips a client-supplied `Tailscale-App-Capabilities`. A
  device without a grant cannot resolve a Service name, so the agent's
  machine cannot see the approval Service. Publishing the SSH relay as a
  Service has not been tested.
- **Tailscale sidecar (alternative).** warden runs in the network namespace
  of a dedicated Tailscale node (`--network container:<sidecar>`) with both
  listeners on loopback (the defaults), and the node exposes the API and
  approval UI through Tailscale Serve and, for relay targets, the SSH relay
  port as a Serve TCP forward (granted to the agent machines only). No other
  container can reach warden. Binding a listener to `0.0.0.0` or running
  warden on a shared bridge network breaks this. The WebAuthn relying party
  is the node's name, so it is not shared with other services. Nothing is
  published on the LAN.
- **systemd service (no container for warden; not the recommended setup, and
  not yet tested on a clean host).** warden runs on the host under a dedicated
  user, with the sandbox of `deploy/systemd/warden.service`, and the host's
  Tailscale Services publish its listeners from loopback. As in the Services
  layout, every process on the host can connect to the listeners and forge the
  header, so the whole host is inside the trust boundary. Further:
  - Other machines cannot reach loopback as long as `route_localnet` stays 0
    on every interface; this replaces the Docker Engine 28 requirement. A local
    process can also bind a listener's port while warden is stopped, and receive
    what Serve forwards; in a container, it cannot bind warden's address.
  - warden shares the host's filesystem (read-only) and network stack. Code
    running in warden can read world-readable files on the host and connect to
    other services on its loopback, which the image and its network do not
    allow. `NoExecPaths` limits the programs it can start, and it can open no
    Unix socket.
  - The Connect token is readable by root and the `warden` user, not by the
    `docker` group, and is not in the process environment
    (`LoadCredential`).
  - Egress is limited by address but not by port (`IPAddressAllow`), and only
    if the kernel supports the filter; the service starts without it otherwise.
    The filter also covers tailnet addresses.
  - There is no build attestation to verify until binaries are published. The
    operator builds from a release tag and trusts that build.
  - 1Password publishes Connect only as a container, so it still runs in one, on
    this host or another. Either way it cannot reach this host's loopback.
    Connect on another host must be reached over the tailnet or TLS.
  - SSH relay targets are not supported.

  [deployment-systemd.md](deployment-systemd.md) compares each guarantee.
- **Operator commands run as the broker's user, with its secrets.**
  `warden-server doctor` reads the vault with the Connect token, loads the CA key
  and drops it, and prints no secret; with `--send-test-notification` it sends a
  fixed text that holds no request data and no approval link. `warden-server agent
  add` prints a bearer key once, alone on stdout, and sends the instructions for
  the agent's machine to stderr, so that a pipe takes the key and a log of the
  instructions does not. Shell history, terminal scrollback and logs on that host
  are the operator's to protect.
- **Phone-only approval port.** The tailnet policy grants the approval UI port
  to the owner's phone only, never to a machine an agent runs on. An
  agent that is prompt-injected must not be able to put an approval prompt in
  front of the owner on the machine it controls. warden checks only that the
  caller is the owner; this separation is enforced by the tailnet policy, and
  the policy should have tests that assert it.
- **Connect read-only and isolated.** The Connect server serves only the
  `Warden` vault, which holds only warden's items, and the token is
  read-only. Connect runs on a network of its own that warden joins, so
  warden can reach Connect but Connect cannot reach warden's listeners (a
  compromised Connect could otherwise forge `Tailscale-User-Login`). Its
  egress is limited to the account's 1Password servers.
- **Hardened container.** Run as the image's non-root user, with all
  capabilities dropped, a read-only root filesystem and a writable `/data`
  volume for the database and audit log. No port is published. Egress is
  limited to what warden needs: Connect, the notifiers, the origins of the
  API secrets (proxy mode) and the addresses of the relay targets (relay
  mode). The image is pinned by a digest whose build attestation was
  verified. The systemd service has its own equivalents, listed above.
- **Targets trust the CA, per target.** Each target host must trust the SSH
  CA only for its own target name. With OpenSSH: `TrustedUserCAKeys
  /etc/ssh/warden_ca.pub` and `AuthorizedPrincipalsFile
  /etc/ssh/auth_principals/%u`, the file holding one line
  `warden:<target>:<user>` per allowed user. A host that only reads
  `authorized_keys` (for example the Home Assistant SSH add-on) uses
  `cert-authority,principals="warden:<target>:<user>" ssh-ed25519 AAAA…`.
  The property "an approval is valid only on the approved target" depends on
  this configuration: a host that accepted any principal from the CA, or
  listed another target's principal, would accept certificates approved for
  other targets. A target that cannot be set up this way is outside this
  release.
- **Backups.** The SQLite database, the audit log, the audience and the relay
  host key live on `/data` (`/var/lib/warden` for the systemd service). Losing the database loses requests, grants,
  enrolled passkeys and agents, which are all enrolled again; losing the
  audience makes key-signed agents log in again. Migrations are one-way, so
  `/data` is backed up (with warden stopped) before every upgrade. The audit
  log is a hash chain; `warden-server audit verify` detects an edited,
  reordered or removed entry before the last one, but whoever can rewrite the
  whole file can rewrite the chain, so ship the log somewhere the server
  cannot modify.
