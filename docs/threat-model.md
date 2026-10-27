# Threat model

This describes what warden protects, who it trusts, what it must never allow,
and the risks that are accepted. It covers the SSH certificate mode, the SSH
relay mode (sessions the broker relays to targets that cannot trust a CA) and
the HTTP proxy mode (brokered API calls that use a stored secret). The design
rationale is in
[design.md](design.md).

## Actors and trust

| Actor | Trust |
|---|---|
| Owner (phone, workstation) | Root of trust. Holds the passkey. Edits the 1Password vault. |
| Agent (for example an AI coding agent on the owner's workstation) | Semi-trusted: well-intentioned but may be prompt-injected. Bounded by its stated goal, the approved window, and the targets and users the vault allows. It can only request access, never approve it. |
| warden server | Trusted. Holds the SSH CA private key and a read-only 1Password Connect token in memory, and relay login credentials briefly (see below). Compromise of the server is compromise of everything it brokers, so it is hardened accordingly. |
| 1Password Connect | Trusted secret backend. Reachable only from warden. |
| Notifiers (Home Assistant Companion, ntfy, push providers) | Untrusted doorbells. They receive the goal text, agent, target and a link, and nothing else. They cannot approve anything. |
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
  `ssh-agent`. The agent key lives in the macOS Keychain. The CLI stores only
  the server URL, agent name, socket and pid files and `known_hosts` files, in
  0700 directories with 0600 files.
- **warden becomes the easiest way into the network.** It runs as a non-root
  user in a distroless image with no shell, listens on the loopback interface
  of the network namespace it shares with its Tailscale sidecar, and is
  exposed only through that sidecar's Tailscale Serve. It holds a read-only
  Connect token.
- **Silent failure.** The CLI always receives an explicit terminal state:
  `approved`, `denied`, `expired`, `cancelled` or `error` with a message.
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
guarantee because the server is the trusted party:

- The server starts the passkey ceremony for one specific request and window.
  The ceremony state, including the challenge, is kept server-side and keyed to
  that request, the chosen window and the approval token. It is consumed by the
  first completion attempt.
- The assertion is verified against that stored state, so it cannot be used for
  another request or another window, and a replay finds no state.
- The approval page and the CLI both show a short fingerprint of the request
  (a hash of the agent name and the whole request: target, user, requested window, goal and public key). If the owner is talking to
  the person or agent that made the request, they can compare the two before
  approving. A mismatch means the owner is looking at a different request and
  should deny it.
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
  to equal `WARDEN_OWNER_LOGIN`, except `GET /healthz` on the agent API, which
  is unauthenticated for the container health check and returns a static body
  revealing nothing. The header is set by Tailscale Serve after it
  authenticates the peer. The CLI never sets it.
- Agent endpoints also require an agent key. Keys are `wdn_` followed by 256
  random bits, shown once and stored only as a SHA-256 hash. Grants are bound
  to the agent that requested them. Revoking an agent disables its key at
  once, ends its pending requests and grants, and wakes its waiting CLI calls.
- The approval endpoints are meant to be reachable from the owner's phone and
  not from the workstation the agent runs on (see "Deployment assumptions").

## Accepted residual risks

These were recorded during implementation and are accepted for this release.

- **The CA key is copied into HTTP client buffers.** The CA private key PEM is
  read from 1Password Connect over HTTP. Parts of it can sit in reqwest and
  hyper buffers that warden does not control and cannot zeroize. The parsed
  key warden holds is zeroized on drop. The mitigation is the
  container hardening described under "Deployment assumptions": an unprivileged
  process, no capabilities and no other container on its network.
- **Agent keys are bearer credentials.** Anyone who obtains an agent key can
  replay it from a host that can reach the API. The impact is bounded: a key
  can only create requests, and every request still needs a passkey approval
  that shows the agent name and goal. A leaked key is revoked with
  `warden-server agent revoke`.
- **Certificates cannot be revoked before they expire.** Revoking a grant
  stops new issuance and the CLI's use of it, but a certificate already issued
  stays valid on target hosts until it expires. The windows are short (at most
  four hours) and each certificate is bound to a key that exists only in the
  agent's memory. Distributing a revocation list to targets is out of scope.
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
  refused the same way; the owner simply approves again. Passkeys that always
  report a counter of 0 (most platform passkeys) cannot be checked this way: a
  cloned one of those is not detected.
- **Goals are free text.** The goal is a single line of at most 500 characters
  without control characters or invisible format characters (bidi
  overrides, zero-width characters). The owner decides on the goal alone, and a
  prompt-injected agent can write a misleading goal. The fingerprint check, the
  narrow user and the short window limit the damage.

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
  credentials of relay targets it reads, in the same way it exposes the CA key.
  The relay is for targets that cannot trust a CA; prefer certificate mode where
  it is possible. The credential never reaches the agent, the notifiers or the
  audit log. Give each relay item a credential that is valid only for that
  target and account.
- **Parts of a password are copied beyond warden's reach.** The SSH library
  takes a password as a `String`, which warden cannot zeroize, and the
  credential also passes through HTTP client buffers (as the CA key does). A
  password therefore may remain in freed memory after use; a private key does
  not have this copy, which is why relay keys are limited to Ed25519 and
  passwords are the alternative for everything else.
- **Approval binds to the key, and the key to one access.** The relay accepts
  an agent only by the ephemeral public key bound into the approved request. A
  public key can be bound to one live request or grant at a time across all
  agents, so one agent cannot use another's approval. The ephemeral private key
  exists only in the agent's `ssh-agent`, as in certificate mode.
- **Pinned host keys are required.** There is no trust on first use. Key
  exchange negotiates only the algorithms of the pinned keys. RSA and ECDSA
  host keys are accepted (verification only); SHA-1 signatures are never
  negotiated, but a holder of the pinned private key could still sign with one.
  An attacker who holds a target's host key can impersonate it to the broker.
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
  read-ahead holds at most 64 KiB before login (so 10 unauthenticated
  connections hold at most 640 KiB) and 4 MiB after (64 MiB at 16
  sessions), plus a 16 KiB read buffer per connection. An agent that keeps
  its connection open and sends past its window (no client does) fills
  only the read-ahead; its session ends by the 60 s stall rule.
- **The per-address pre-login limit is global behind Tailscale Serve.** The
  relay allows 5 connections per source address and 10 overall that have not
  logged in. Serve forwards the TCP stream from `127.0.0.1`, so every peer has
  the same address and the per-address limit acts as a global one: a peer that
  can reach the relay port can fill the login slots for a few seconds at a
  time (10 s login timeout, 3 attempts). It does not let anyone in. The tailnet
  policy decides who can reach the port; grant it to the workstation only.
- **Fail closed when state cannot be read.** The relay checks the grants of
  its live sessions every second, each check bounded to 1.5 s. If none succeeds
  for 10 s, every relayed session ends (reason `grant state unavailable`) and no
  session starts until a check succeeds. A database outage longer than 10 s
  therefore ends relay sessions, by design.
- **A session start is recorded first.** `relay_session_started` is written
  before the first byte reaches the target; if it cannot be written, the
  session does not start.

## Deployment assumptions

warden's guarantees depend on its environment being set up as follows.

- **Tailscale sidecar.** warden runs in the network namespace of a dedicated
  Tailscale node (`--network container:<sidecar>`) with both listeners on
  loopback (the defaults), and the node exposes the API and approval UI through
  Tailscale Serve and, for relay targets, the SSH relay port as a Serve TCP
  forward (granted to the workstation only). No other container can reach
  warden, so none can forge `Tailscale-User-Login`. Binding a listener to
  `0.0.0.0` or running warden on a shared bridge network breaks this: anything
  that can reach the listener directly can forge the header. The WebAuthn
  relying party is the node's name, so it is not shared with other services.
  Nothing is published on the LAN.
- **Phone-only approval port.** The tailnet policy grants the approval UI port
  to the owner's phone only, never to the workstation the agent runs on. An
  agent that is prompt-injected must not be able to put an approval prompt in
  front of the owner on the machine it controls. warden checks only that the
  caller is the owner; this separation is enforced by the tailnet policy, and
  the policy should have tests that assert it.
- **Connect read-only and internal.** The Connect token can read only the
  `Warden` vault and is read-only. The Connect server is reachable from warden
  alone, on an internal network.
- **Hardened container.** Run as the image's non-root user, with all
  capabilities dropped, a read-only root filesystem and a writable `/data`
  volume for the database and audit log. Egress is limited to what warden
  needs: Connect, the notifiers, Tailscale and, for proxy mode, the origins
  of the API secrets.
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
- **Backups.** The SQLite database and the audit log live on `/data`. Losing
  the database loses only in-flight requests and enrolled passkeys, which are
  enrolled again. The audit log is a hash chain; `warden-server audit verify`
  detects an edited, reordered or removed entry before the last one, but
  whoever can rewrite the whole file can rewrite the chain, so ship the log somewhere
  the server cannot modify.
