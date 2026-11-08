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
  out and where secrets may go. With the [local backend](#the-local-secret-backend)
  there is no vault: whoever can write its files decides that, and a compromised
  host gets every secret at rest.
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
- **What an agent commits while it may sign.** A signature means warden signed the
  commit for that agent, not that anyone reviewed the change. See
  [Commit signing](#commit-signing).
- **Instant revocation everywhere.** An issued certificate stays valid on
  its target until it expires, and an open login to a certificate target continues
  even after that (issue
  [#35](https://github.com/pecheriere/warden/issues/35)). Stopping a proxied
  API call already in flight does not undo what the API has done with it.

This page is about a real deployment. The [local demo](demo.md) is a separate
binary that is not secure for real use: on it, everyone on the machine counts as
the owner. It is not in `warden-server` or the image, and a CI guard keeps it
out. A release attaches it as a separate archive named as a demo, so a person
would have to choose to run it, and its attestation and signature say where it came
from, not that it is safe for real use.

## Actors and trust

| Actor | Trust |
|---|---|
| Owner (phone, workstation) | Root of trust. Holds the passkey. Edits the 1Password vault. |
| The warden host (its root, its container runtime) | Root of trust. Can read everything warden holds and act as warden. |
| Agent (for example an AI coding agent on the owner's workstation) | Semi-trusted: well-intentioned but may be prompt-injected. Bounded by its stated goal, the approved window, and the targets and users the vault allows. It can request access and use what was granted, never approve it. |
| warden server | Trusted. Holds a read-only 1Password Connect token in memory, and for short times what it reads with it: the SSH CA private key, from the read at an approval until the certificate is signed, the commit signing key while it signs, API secrets during a call, and relay login credentials (see below). Compromise of the server is compromise of everything it brokers, so it is hardened accordingly. |
| 1Password Connect | Trusted secret backend. Reachable only from warden, on its own network, and unable to reach warden's listeners. |
| Notifiers (Home Assistant Companion, ntfy, push providers) | Untrusted doorbells. They receive the goal text, the session label the agent stated, agent, target and a link to the approval page, and nothing else. They cannot approve anything. Which channels are used is fixed at startup from a compile-time set (`WARDEN_NOTIFY`); agents cannot influence it. |
| Tailscale | Transport and network-level identity. The tailnet policy is the outer access control. |

## Anti-goals

These are failures even if everything else "works". Each lists how warden
defends against it.

- **An approval is forged, replayed, widened or applied to a different request
  than the one displayed.** Approval needs a WebAuthn assertion from an
  enrolled passkey. The approval token is at least 128 bits of randomness,
  stored only as a SHA-256 hash, single use, tied to one request and expiring
  with it. A request has one valid token at a time. The window cannot exceed what the target allows. An approval is
  valid only on the approved target: the certificate's single principal is
  `warden:<target>:<user>`, which only that target's host maps to the account
  (see "Targets trust the CA, per target" below). See "Approval binding"
  below.
- **A notification channel sees secrets or can approve.** Notifications carry
  the agent, target, user, the session label the agent stated, a goal truncated to
  200 characters, and a link. A link stated in the request goes to no notifier: one
  could preview it, which fetches a page the agent chose.
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
  files. The cost is that an SSH request cannot outlive the `warden request ssh`
  that made it: if that run dies, the owner can still approve the request, and the
  resulting grant is unusable, as nothing holds its key. See "A client dies with a
  request pending" below.
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
what was approved, and a compromised broker could misapply it. This is deliberate: the
signature is not evidence of what the owner approved, because a compromised broker
could show one thing and have the passkey sign another, and needs no signature to act.
[The design](design/passkey-binding.md) explains the decision.

- The server starts the passkey ceremony for one specific request and window.
  The ceremony state, including the challenge, is kept server-side and keyed
  to that request, the chosen window and the approval token. It is consumed by
  the first completion attempt.
- The assertion is verified against that stored state, so it cannot be used
  for another request or another window, and a replay finds no state.
- The approval page and the CLI both show a short fingerprint of the request
  (a hash of the agent name and the whole request: target, user, requested
  window, goal, public key, and any session label and link). It is 48 bits, for people to compare, so an agent
  could craft two requests that share one: it detects a mix-up, not an attacker
  who controls both. Both show it as five words from a fixed list, the EFF Short
  Wordlist 2.0, a reversible way of writing the same 48 bits, with the hex beside
  them. Any two words of that list differ by at least 3 edits, so one misread letter
  does not make another word. The words make it easier to compare, not harder to
  forge, and a person who compares only some of the words checks fewer bits. The API,
  the database and the audit log hold the hex. If the
  owner is talking to the person or agent
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
- **The pending screen goes through all of the above.** `GET /pending` lists the
  pending requests. Approve… there is `POST /pending/{id}/open`, which gives the
  request a new token, stores its hash in place of the old one, and returns the
  link: the same approval page, the same passkey ceremony, bound in the same way.
  It approves nothing, and no route of the screen does. The old token stops working
  in that statement. A page open on it ends in the not-pending outcome, a ceremony
  bound to it is refused before the assertion is checked and does not carry over
  to the new token, and an approval already past those checks either finishes first
  or fails on the token in its own update. A request that is no longer pending
  (decided, cancelled, expired, even before a sweep) gets no new token.
  `approval_link_replaced` is written before the change, or the change does not
  happen, and it holds the request id and no token or hash.

## What the audit log can miss

The audit log is the evidence warden leaves, so an action that gives access
must not happen without its entry. An action that ends access is the exception:
stopping access matters more than recording it. Either way, the log is never
written while a database write is open, so writing it cannot hold up another
change.

- **Written first, or the action does not happen.** Creating a request, approving
  one, adding an agent or changing its key, enrolling or removing a passkey and
  making an enrollment code write their entries before they touch the database. A
  proxied call and a relay session write theirs before anything reaches the target,
  and then check the grant again. If the entry cannot be written, the action does
  not happen and the caller gets an error. A bearer agent's row is written first and
  revoked if its entry cannot be written; its key is shown only after that entry, so
  the row cannot be used.
- **Ending access does not wait for the log (deliberate).** A failing log must not
  leave an owner unable to end access they have decided to end, and a compromise is
  when both are most likely to matter. So revoking, denying, cancelling and expiring
  store their entries in the database, in the transaction that makes the change, and
  only then write them to the log, waiting 2 s at most. The end of a proxied call
  stopped because its grant ended goes the same way, just after.
  - Access stops as usual. A revoked grant or agent is revoked in the database,
    pending requests of a revoked agent end, relay sessions close, and proxied calls
    and the agent's key are refused. A call or session waiting to record its start
    checks the grant again once it has, and does not go out. One already sent is
    stopped, and a certificate already issued stays valid until it expires, as for
    any revocation.
  - The entry is not lost. It waits in the database, and every sweep (each 15 s, and
    at start) tries again, so it reaches the log once the log works, with a note
    holding the entry if it is over a minute late, because its own time is when it was
    written. Until then
    it has no hash chain, and whoever controls the host could remove it. Writers
    claim an entry first, so two processes do not both write it, though entries
    can then reach the log out of order. A crash just after writing one can write it
    twice, and its claim holds it back for up to 5 minutes.
  - The owner sees it. The grants page warns for as long as any entry is waiting,
    whatever the page reloads for. A revocation also sends a notification, with the
    grant id or agent name, because an agent can revoke its own grant with no owner
    there. The server log has an error with the entries at each attempt.
    `warden-server agent revoke` has no server log, so it prints the entries and exits
    with an error, after revoking. `warden-server doctor` fails while entries wait,
    and `warden-server audit verify` warns.
  - What can still stop a revocation is the database: if it cannot commit, the
    revocation did not happen and the caller gets an error. Other writers hold it only
    briefly, as none of them writes the log meanwhile; a revocation queues behind them,
    for 5 s at most. The relay ends its sessions by itself if it cannot read the
    database for 10 s (see "Fail closed when state cannot be read").
  - Entries of these changes are written just after the commit, so a session or
    call that a revocation ends can log its end before the revocation's entry.
- **`cert_issued` fails closed.** A certificate cannot be revoked before it
  expires, so one with no entry would be access with no evidence and no way to
  take it back. `cert_issued` is therefore written with `approved`, before the
  database changes. The certificate is signed in memory and reaches the agent only through
  the grant that commit stores, so if either entry cannot be written, it is
  dropped without having left the broker. The owner, who is looking at the
  approval page, sees that nothing changed and no access was given, and can
  approve again, which signs a new certificate. The agent is not told: its
  request is still `pending`, which is true, and ends in a decision or `expired`
  as usual, also if the log is still failing by then.
- **Entries written first can overstate, not understate.** A change that then fails,
  or finds that its agent was revoked meanwhile, leaves an entry for something that
  did not happen; an `error` entry then says so. A crash at that moment, or a failure
  to write the `error` entry too, leaves none: an `approved` with no matching grant in
  the database means the approval did not take effect, and no certificate left the
  broker.
- **Written after the fact, and only logged if that fails.** `request_limited`,
  `limit_notified`, `notified`,
  `relay_session_ended`, `relay_session_refused` and `relay_login_refused`
  record something that already happened and gave no new access, so nothing can
  be refused any more. The server log has an error when one is lost. A session's
  end is also missing after a crash; its `relay_session_started` is still there.
- **Not recorded at all.** Attempts that change nothing are not in the audit log:
  a failed passkey assertion (a counter regression is recorded), a wrong
  enrollment code, a call on a grant that is revoked or expired, a signed request
  that fails verification. They come from callers who passed the checks in front
  of those endpoints, and some are in the server log. An enrollment code that is
  spent but never finishes enrolling is not recorded either; only `passkey_enrolled`
  shows that it was used. An `enrollment_code_created` entry holds neither the
  code nor its hash, so it cannot be matched to one enrollment.
- **A log that cannot be written stops what gives access.** With a full disk, or
  after a failed write (which needs a restart to repair), no request can be created
  or approved, and relay sessions and proxied calls cannot start. A log that stalls
  holds those up until it answers. Ending access goes on as above. Watch
  the disk that holds the log.

## Authentication of callers

- Every endpoint on both listeners requires the `Tailscale-User-Login` header
  to equal `WARDEN_OWNER_LOGIN`, with these exceptions on the agent API:
  `GET /healthz` (unauthenticated for the container health check, a static
  body revealing nothing), `GET /v1/info` (the public signing protocols and
  audience, which a client reads before it can sign), and signed requests of
  key-signed agents (below). The header is set by Tailscale Serve after it
  authenticates the peer. The CLI never sets it.
- **No exemption reaches the internet.** Every route of both listeners,
  `GET /healthz` and `GET /v1/info` included, refuses with
  `401 {"error":"unauthorized"}` a request carrying the
  `Tailscale-Funnel-Request` header, which Serve sets on requests that came
  through Tailscale Funnel, whatever credentials (signature or bearer key)
  it carries; a signed one's body is not read. The exemptions above assume
  a tailnet peer: published through Funnel by mistake, the API would let
  anyone on the internet read the audience and try signed requests. The
  approval UI also needs the owner's login, which Funnel requests never carry.
  Both refusals rely on Serve to set its headers, so neither protects a
  listener reached without Serve.
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
- **`warden ssh-config` lets another tool use a grant's agent.** It prints an
  `ssh_config` block that points at the grant's `ssh-agent` socket and pinned
  `known_hosts`, with the options `warden ssh` passes. It writes no key or
  certificate, and gives nothing the agent's operating-system user could not
  already reach: the socket is that user's. Expiry and revocation work as for
  `warden ssh` (the agent drops the key at `not_after`, and revoking removes the
  socket), but a connection already logged in, including a `ControlMaster`
  master kept by `ControlPersist`, lives until it closes, like any open login
  above. The block sets `ForwardAgent no`. A caller that adds the socket to
  `SSH_AUTH_SOCK` or to a normal `~/.ssh/config` would offer the grant's key to
  any host it connects to; the [agent usage](agent-usage.md#tools-that-run-ssh-themselves)
  says not to, and warden cannot stop it.
- **Revocation from the server CLI is not instant for waiting clients.** A
  `warden-server agent revoke` run from the command line changes the database,
  but the running server only re-reads it when a long poll wakes, so a waiting
  client can take up to 30 seconds to see the terminal state.
- **The approval token is not a second factor against the owner's login.** Since
  the pending screen can issue a new token, holding the owner's login is enough to
  get one, so only the passkey separates the login from an approval. Whoever has the
  login, or can [forge it](#deployment-assumptions), still cannot approve anything.
  They can deny any pending request without learning a link, and replace links.
  Replacing kills the link in a notification, and also any page the owner has open:
  by repeating `POST /pending/{id}/open`, they can kill every page the owner opens
  before the passkey finishes, for the whole life of the request, with an audit entry
  each time, at the rate they can send requests. They could read the same requests on
  `/history` already. All of it is on the record.

  Stopping access is not the limit of it. Anyone with browser tools on a machine that
  holds both the login and a passkey the owner can use, such as a synced passkey, can
  now get a link from `/pending` and put a real passkey prompt in front of the owner,
  where before they had to learn a link from a notification first. The prompt is for
  warden's real origin, so an owner who taps it has approved. No credential is forged,
  so the broker cannot tell this from the owner. The passkey's user verification is
  what remains, and it does not help a tired owner. This is why the tailnet policy
  should give the approval listener only to the owner's phone, and why the owner's
  passkey and sessions should stay off machines that run agents: a device logged in
  as the owner that the policy lets through, a workstation running an agent for
  example, has everything above. See [the owner identity design](design/owner-identity.md).
  Without that network layer, nothing but the owner's attention stands between an
  agent with those browser tools and an approval.
- **Passkey prompts in progress cannot crowd each other out.** A request keeps its
  4 newest ceremonies, and beginning another drops its oldest, so one request cannot
  fill the table, and replacing a link drops those of the old one. Enrollment has its
  own room for 8, each costing a code from the server's command line. Whoever holds
  the owner's login can still keep cancelling the prompts of a request they keep
  beginning, as they can by replacing its link, but not those of another request.
  Approval ceremonies as a whole stop at 1024, with a 429, to bound memory. A request
  that has ended keeps its ceremonies until they expire, after 120 s, so ended requests
  count too. With the default limits, reaching this takes the owner's login and about
  26 agents each spending its 10 new requests within 2 minutes, and fewer agents where
  the [request limits](configuration.md#request-limits) are raised. It would refuse new
  approvals for up to 120 s, not enrollment. An agent's own limits are spent doing it.
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
- **An agent can list its own pending requests, and learns nothing else from it.**
  `GET /v1/requests` is signed like every agent route and filters on the
  authenticated agent, so another agent's request is absent, as it is `404` by ID. It
  returns what the agent sent, with the ID, the fingerprint and the times. It reads
  neither the approval link, which only the owner is sent, nor its token's hash. It
  only reads: no notification, no audit entry and no use of the request limits, so
  polling it cannot pester the owner or fill the log.
- **A client dies with a request pending.** The request stays approvable until it
  expires, 10 minutes after it was made. The broker has no way to tell a dead client
  from a slow one, and ending requests when polling stops would make a network blip
  cost the owner's decision. An owner can therefore approve a request nobody is waiting
  on. The harm is limited: the grant goes only to the same agent, within the window the
  owner chose, and shows on the owner's Grants page like any other, where it can be
  revoked.
  - **An api grant can be collected later**, with `warden request collect`. This gives
    the agent nothing new, as the grant answers to its login from any machine anyway,
    and the broker checks every call. The CLI only records it, and has no scope it
    asked for to compare with, so it prints the scope it found.
  - **A commit signing grant has nothing to collect.** The broker signs under it for
    the agent's login, so it works whether or not the run that asked is alive, and
    `warden request collect` says so and writes nothing.
  - **An SSH or relay grant of a dead `warden request ssh` is unusable.** The private key
    was only in that run's memory, so the certificate, which the agent can still read,
    gives no login, and the relay admits no one. Writing the key to disk so that a later
    run could finish the request would give up "Private keys are written to disk on the
    workstation" above, for little: a new request costs the owner one more tap. The
    certificate still cannot be revoked before it expires, but with no key that does not
    matter. A client of the API that keeps its own key takes on protecting it, and it can
    complete the request.
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
  with the certificate's key id. Ship those logs if you need that trail. The
  Active grants page shows when the certificate was issued and when it expires,
  never whether it was used.
- **Connect and notifiers can be configured over plain HTTP.** warden accepts
  `http` for `WARDEN_OP_CONNECT_URL` and the notifier URLs when the URL shows a
  local or private host, because Connect on its own network and a local Home
  Assistant commonly use it, and refuses any other host unless the variable is
  listed in `WARDEN_ALLOW_PLAIN_HTTP` ([rules](configuration.md#plain-http)).
  Anyone else on that network can read the Connect token and everything it reads.
  The check reads the URL and resolves no name, so a local-looking name that
  resolves elsewhere is not caught, and it cannot see who shares a private network
  or whether a `100.64.0.0/10` address, which is also carrier NAT, is on your tailnet.
  With the opt-in, warden logs a warning at startup and doctor does not pass it.
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

- **A session label is a claim.** It has the rules of a goal, at most 64 characters
  on one line, and the same limit: nothing checks it. Sessions of one agent run as
  one OS user with one key, so any of them can state any label, and a prompt-injected
  one can state another's. The pages say the agent stated it and that it is not
  verified. It is free text in the notification and the audit log, like the goal, so
  it can look like a link there. It does not stop one session from using another's
  grant ([#49](https://github.com/pecheriere/warden/issues/49)).
- **A link in a request is the agent's too.** It is off unless the owner lists hosts
  (`WARDEN_REQUEST_LINK_HOSTS`), matched exactly, and a request linking anywhere else
  is refused, with nothing stored or notified.
  - **The host shown is the host it goes to.** A link is reduced to `https`, a plain
    host name and a path, and anything that could read differently is refused rather
    than cleaned up: other schemes, a user or password, a port, percent-encoding in
    the name, non-ASCII (an international name is matched and shown as `xn--…`), IP
    addresses in any spelling, backslashes, whitespace and control characters that a
    URL parser would drop. A query and a fragment are refused too, as the usual places
    for a token and for a redirect's destination. At most 256 bytes.
  - **On the page.** A link is an escaped `https` address in a new tab with
    `rel="noopener noreferrer"`, under the details, apart from Approve and Deny, with
    the host as its text. It is a link only while its host is on the list at that
    moment. Errors never quote it, and it is not in the audit log.
  - **What is not stopped.** A listed host can still redirect, or let anyone publish on
    it, so list hosts accordingly. A secret in a link's path cannot be told from any
    other path: it would be stored, and shown to the owner. The page behind a link is
    written or chosen by the agent, so a compromised agent controls that context as
    well: it must not read as evidence, and the page says so. Opening a link tells
    that host the owner's address, and acts as the owner if they are signed in there,
    as any link does.

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
- **Revoking stops a call in flight, but cannot undo it.** A revoke refuses new
  calls and stops those already out: the connection to the upstream closes and the
  agent gets a 409, including while a response is still arriving. A revocation does
  not wait for any of this. It commits, tells the calls and moves on, whatever the
  upstream or the audit log is doing. Limits:
  - **The upstream may have acted already.** Closing the connection tells it nothing
    useful: a state-changing call it has received may take effect, in part or in
    full. The call's `proxy_call` entry has `aborted` with the reason, and the
    status and bytes received so far, which show how far the answer came, not what
    the upstream did. Check there when the call could have changed something. The
    agent is told the same: the outcome is unknown, and `warden http` says to find
    out before repeating the call.
  - **The log does not hold this up.** A stopped call's `proxy_call` entry is treated
    like the revocation's (see "Ending access does not wait for the log"): stored in
    the database, then written to the log, waiting 2 s at most, and a stalled log does
    not hold up the agent's answer. With every database connection busy, the call is
    still stopped, but the answer waits for a free connection. The entry is lost only in a crash before it is stored, or if neither
    the database nor the log can take it, which is what the server log's error then
    holds; `proxy_call_started` is still there. The entry of a call that ran to its
    end is different: if it cannot be written, the agent gets an error and no response,
    and only `proxy_call_started` remains.
  - **How fast.** Through this broker it is at once. A revoke made by another process
    (the server CLI) and the end of the window are found by a check every second, so
    about 1 s, or about 2.5 s if the check is slow. If the grant's state cannot be
    read for 10 s, the call fails closed with a 503. The longest a call can run on
    without any of these is still the 30 s limit.
  - **A complete answer can still be delivered.** The grant is checked once more after
    redaction. A revoke after that, while the answer waits for its `proxy_call` entry
    or is on its way, does not hold it back.
  - **Nothing partial leaves the broker.** The whole response is read before it is
    redacted and returned, so a response that is cut part-way, which may quote the
    secret, is dropped unread. The agent gets the fixed message, and the audit entry
    holds only the counts.
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
  The stall clock only catches a reader that has stopped: each message
  delivered restarts it, so an agent that keeps reading, however slowly, is
  not stalled. Its session keeps its place in the session limits and its
  queues until the idle timeout, its grant's end or a revocation. The idle
  timeout counts bytes the relay reads from either side, not bytes it delivers:
  a slow reader working through output already queued, with nothing new read
  either way, is ended after 15 minutes though it is still reading, while one
  whose target keeps producing makes room for more, so only the grant's end or
  a revocation ends its session.
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

## Commit signing

A branch that requires signed commits means a signing key wherever commits are made. The
broker can hold that key instead. The goal is modest, and this must not be read for more:
**a signature means warden signed the commit for that agent, not that the owner reviewed
the change.** What it gives is that the key cannot be copied off the agent's machine, that
every signature is recorded, and that one agent can be cut off. An on-disk key on an agent's
machine can then be deleted.

**Why this is the one grant that can outlast 4 hours.** Other grants are short because the
access is broad and has effects outside warden. A signature only says who made a commit,
one rebase can need dozens, and a grant of 4 hours would mean a prompt every few hours for
something the owner cannot judge anyway: the phone cannot show a trustworthy diff, because
the agent would supply it. An approval per commit would be habit, not review, so it would
add nothing. So a grant lasts 30 days by default, up to `WARDEN_COMMIT_SIGNING_MAX_WINDOW`.
The windows in days are a separate set: a policy's `max_window` cannot name one, so a target
or secret stays at 4 hours or less whatever the setting.

What an attacker gets, and what stops it:

- **During a grant, an agent gets anything it commits signed**, for as long as the grant
  lasts, with no prompt. A prompt-injected agent gets its commits signed too. They show as
  verified under the account the key is registered on, so a signature is not a reason to
  skip review. Keep code review as the check on what lands.
- **The fields in the audit log are the commit's own.** Author, parents and tree are what
  the agent's commit says, recorded as such. An agent that never stores the commit leaves an
  entry with no commit behind it, and one that lays the signature out differently gets another
  commit id: see [what the log can and cannot show](#rotating-the-commit-signing-key).
- **A signature can be moved to another repository**, since a commit names no repository.
  warden cannot limit signing to a repository, branch or pull request, and does not ask, as
  anything an agent said about that could not be checked. Repository limits belong to
  pushing.
- **Revoking stops new signatures at once**, including one being recorded when the
  revocation lands, and does not undo the ones already made.
- **A compromised warden host can sign anything with this key**, as with everything else it
  holds. That is one reason release signing must not use this key: see below.

What holds:

- **The key signs in one namespace, and only commits.** Only the `git` SSHSIG namespace, so
  the key signs for no other purpose, and only a payload that parses strictly as a commit,
  so not a tag object, a push certificate or anything else.
  [The rules](agent-protocol.md#commit-signing-grants-kindcommit_signing) refuse whatever git
  would not have written or another reader could take differently.
- **One agent's grant does not help another.** Signing looks up the calling agent's own
  grant, for each signature.
- **It fails closed.** A database that cannot be read, a key that cannot be read, or an
  entry that cannot be written all mean no signature. The signature leaves the broker only
  after its entry is written.
- **Every refusal is recorded.** Beyond 30 a minute per agent they are counted, so refused
  calls cannot fill the log. A body over the route's 2 MiB limit is refused before the
  caller is known, and is not recorded, as on every route.
- **An agent cannot approve it, and nothing renews by itself.** A grant takes the passkey,
  and so does renewing it. warden notifies the owner a few days before a grant ends, and the
  notification names only the agent.
- **The key is handled like the CA key**: `ssh-ed25519` only, read for each use, in types
  that wipe it and print nothing, with the same residual copies in HTTP client buffers
  ([accepted residual risks](#accepted-residual-risks)). It is read for each approval page,
  each signature and each request for its public half, so it spends little time in memory
  but more often than the CA key. The owner causes the first; an agent causes the others only
  with an active grant, and a signature only within its daily limit. An agent with no grant
  cannot make the broker read it: asking for a grant only checks that a key is configured.
- **It must not be the SSH CA key.** warden compares the public keys and refuses to approve a
  grant while they are the same, or while a configured CA cannot be read to tell: several
  items, a malformed key or an outage. Only a broker with no CA at all has nothing to compare. Doctor fails on it, and
  with the local backend so does the server's start. With 1Password nothing is read at
  start, so this is caught at approval and by doctor. A grant is bound to the key it was
  approved for, so it cannot come to use the CA key later.
- **A grant has a daily limit of signatures**, 5000 per UTC day by default
  (`WARDEN_COMMIT_SIGNING_MAX_PER_DAY`), far more than rebases need. Without it an agent with a
  grant could loop for the life of the grant, writing an entry of a few KB for each signature
  until the disk holding the audit log filled. It is counted in the database, so a restart does
  not reset it. At the limit, signing is refused and so the commit fails, the refusal is
  recorded, and warden tries once that day per grant to notify the owner. Other agents and
  their grants are not affected. It bounds the log, and does not limit what a grant can sign:
  the limit is high enough that a compromised agent can sign all it wants within it.

**When signing is not available, the commit fails.** With no grant, or with the broker out
of reach, git's signing program fails, so `git commit` fails, saying why and how to ask.
Nothing retries unsigned, wraps git or turns signing off. An agent on its own machine can
still change its own git configuration, which warden cannot prevent: bypassing takes
deliberate effort, and an unsigned commit is then visible, and refused by a branch that
requires signatures. GitHub's documentation says that unsigned commits on a pull request's
branch can block a squash merge into such a branch, even though GitHub signs the commit that
lands, so an unsigned commit is not a harmless way around.

**Tags are kept apart for later.** A release verifier should trust a separate key: commits
and tags share the `git` namespace, and a signature shows only which key made it. With one
key, a mistake in this payload check could let a commit grant sign a release. So tag objects
are refused here, and this key must not be listed in `docs/release-signers`.

### Rotating the commit signing key

Replace the key in the backend (the item tagged `warden:commit-signing`, or the file
`[commit_signing]` names). Every grant made for the old key stops working at once, since a
grant is bound to the key the owner approved, so agents ask again and each machine runs
`warden setup git`. Register the new public key on the account.

Signatures made with the old key remain valid for whoever still trusts that key. GitHub's
documentation says that a commit verified when it was pushed keeps its verified status when
the key is later rotated or revoked. A commit first pushed after that is checked against the
keys on the account at that time.

**If the key leaks**, remove it from the account on GitHub at once (revoke it, if the account
offers that) and replace it as above. By the same documentation, commits already verified
stay verified, including any an attacker pushed before the removal, so check those by hand.
Check them against the audit log as below.

**What the log can and cannot show.** Each `commit_signed` entry holds the SHA-256 of what was
signed: the commit object without its signature header. Its commit id is only the id git gives
that signature as git lays it out: the signature's lines can be wrapped differently, which
makes another commit id that still verifies, with the same content. So look a commit up by
that digest, not by its id. A commit whose digest is in the log was signed through warden. One
whose digest is not there, but which verifies with this key, was signed some other way, or
under an entry the log no longer has: someone with control of the warden host can rewrite the
log. The log does not show whether a commit was stored or pushed, where it went, or whether its
author line is true.

## The local secret backend

`WARDEN_SECRET_BACKEND=local` reads targets, API secrets and the SSH CA key from
files on warden's host ([guide](local-backend.md)). It exists for setups without
1Password, and **1Password stays the recommended backend**. The rest of this page
describes 1Password; this section says what changes.

What is lost, and cannot be regained by any setting:

- **The vault's separation from the host. A compromised host gets the secrets.**
  With 1Password, the secrets rest elsewhere, and a compromise of the host reaches
  them through a token that can be revoked. With local files, they rest on the host:
  an attacker with root, or with warden's user, reads every credential warden holds,
  all at once, whether or not any agent ever asked for it. The only recovery is to
  rotate each one on its service.
- **Backups and disks hold the secrets**, unless they are encrypted some other way.
- **There is no read-only token boundary.** warden's Connect token cannot change the
  policy; nothing comparable stands in front of the policy file. Owning it by root
  and mounting it and the secrets read-only stops a compromised warden *process*
  from changing what it hands out or where secrets go, but not a compromised host,
  and warden cannot verify that it was done beyond the file's owner and mode.
- **No record of edits.** 1Password keeps item history and usage reports. warden
  audits its own refusals, not who changed a file.
- **Policy and secret are two reads.** With 1Password both come from one read of one
  item. Here, a change touching both files is two steps, and a call can fall between
  them: an old credential could go to a new destination. Writing a new secret under
  a new file name, then replacing the policy atomically, avoids it
  ([how](local-backend.md#rotating-a-secret)).
- **A file can be read while it is being written.** A 1Password item is read whole.
  A policy file ends with `[end_of_policy]` and a SHA-256 of the bytes before the
  digest line, checked on the bytes read, so a read cut short or mixing two versions
  is refused and audited, and can never yield a wider policy. That fails closed for as
  long as the file stays so: replacing it by a rename
  ([`warden-server seal-policy`](local-backend.md#editing-the-file)) avoids the
  refusals. The digest is an integrity check against accidents, with no key: **anyone
  who can write the file can seal it**. Sealing a mix would make it valid, so the
  command will not seal a file in place whose digest does not match until a person
  has been shown what it allows and passes `--accept-unverified`. That guards against
  a mistake and is no boundary: deleting the digest line, or copying the file and
  sealing with `--from`, skips it. Sealing is a person's decision, and the digest
  detects torn writes, not tampering. The file's owner and mode are what stand against an
  attacker. A secret file has no digest: one cut short is sent as what it is, to the
  destination its entry allows.
- **Single-file mounts go stale, so they are refused.** A file mounted alone stays on
  the old inode after a rename on the host, which would ignore a revocation. Moving
  the old file aside first leaves it with one name, so nothing about the file shows
  it. warden therefore refuses, at every read, a policy or secret file that is the
  root of a mount, as the kernel reports through `statx` (Linux 5.8 or later; where
  the kernel or a sandbox cannot say, every file is refused and the backend does not
  work). A file with no name left, or a second name, is refused
  as well. What this does not see is a mount of the directory that is itself out of
  date, or a copy made at start, as below.
- **Secrets from systemd credentials are copied at start**, so rotating or removing
  one takes a restart. Removing the entry from the policy still applies at once.

What holds, because the same code runs:

- **Validation is as strict as for 1Password items**, through the same validators,
  and stricter in places: an optional setting set blank is refused, where a 1Password
  field takes its default. At startup the whole policy and every secret it names are
  checked, and the server refuses to start on any problem, which 1Password items are
  not.
- **Fresh reads.** Nothing is cached: a policy edit, a removed entry or a removed
  secret applies at the next request. Destination digests work as before, so an edit
  invalidates a grant it no longer matches, but does not stop a proxied call already
  in flight. A certificate already issued behaves as described above.
- **Fail closed, and audited.** A file that is invalid, unreadable, ambiguous or too
  open refuses the request and writes an `error` event to the audit log, without
  quoting any value. If the audit log cannot be written, the request is still refused.
- **No following of links, no gap between check and use.** Each read walks from `/`
  with `O_NOFOLLOW`, one component at a time, and checks owner and mode on what it
  opened. A secret must be a private regular file with one name, in a private
  directory, so a file reachable under wider permissions is refused. An entry names
  only a file in the secrets directory, so a policy edit cannot point a credential at
  another file on the host. Permissions are the file system's: anyone who passes them
  (root, warden's user) reads the secret. ACLs are not examined; if the file system
  has them, keep them off this directory. A read of a file that a process with those
  rights is changing at that moment may see part of it, which fails validation or is
  sent as is, so write secrets by creating a new file.
- **Secrets stay in wiped memory** and out of logs, errors, the audit log and doctor's
  output, as far as for 1Password. The same limits apply: a password passed to the SSH
  library is a copy warden cannot wipe, and the kernel's page cache and the host's swap
  are outside warden's control. Systemd credentials do not swap.

warden does not generate the SSH CA key with this backend. It would need write access
to the directory holding the secrets, and a volume that failed to mount would silently
yield a new CA. `ssh-keygen` does it in one command.

## warden's files on disk

warden keeps its files private to its user. The database and its `-wal`, `-shm` and
`-journal` files, the audit log, the audience and the relay's host key are mode 0600.
warden creates them that way, corrects a loose file when it opens it, and refuses to
start if it cannot, or if a symbolic link is in the file's place. The relay's host key
is refused rather than corrected. warden also refuses to start if others can write to
the data directory and warden cannot call it its own, as they could replace the files
in it. [The data directory](configuration.md#the-data-directory) has the rules.

This does not cover:

- **Anyone with warden's uid or with root.** That includes root on the host, and any
  other container running as uid 65532 with the same volume mounted. The default user
  of many distroless images has that uid, so do not share the volume.
- **Encryption.** The files are in clear on disk. Protecting a stolen disk or backup
  is the host's job.
- **Copies.** A backup is as private as where it is put and how it is made.
- **Changes while warden runs.** Modes are corrected when a file is opened, at start
  and by server commands that change data. `warden-server doctor` and `audit verify`
  only read, and change no mode. A file loosened afterwards stays so until the next
  start; `warden-server doctor` reports it.
- **Names and sizes in a directory warden leaves alone.** If others can read the data
  directory, warden warns and starts: they can see the files' names, sizes and times,
  not their contents.
- **A file system that misreports modes.** warden relies on the mode the file system
  reports. A network or shared file system that reports one mode and enforces another
  is outside what warden can see.

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
  - Releases after v0.9.0 attach an attested, signed static binary for the operator
    to verify, in place of the image's digest. It links musl where the image's links
    glibc. An operator who builds from a release tag instead has no attestation, and
    trusts that build.
  - 1Password publishes Connect only as a container, so it still runs in one, on
    this host or another. Either way it cannot reach this host's loopback.
    Connect on another host must be reached over the tailnet or TLS.
  - SSH relay targets are not supported.

  [deployment-systemd.md](deployment-systemd.md) compares each guarantee.
- **The CLI's `.deb` and `.rpm` are checked like its archives.** From v0.10.0 a release
  attaches them, holding the same binary as the CLI's archive, attested and listed in
  the signed manifest. They are not signed with a package key and come from no
  repository, so the package manager checks nothing about where they came from: the
  [release checks](verifying-releases.md) are what cover them, and nothing updates them.
  They are made and checked in one job, which
  [Verifying a release](verifying-releases.md#not-covered-yet) lists as not covered yet.
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
  verified. Build attestations do not protect against a compromise of GitHub
  or of an account that can change the repository, because those can produce
  a new one. From the release after v0.8.1 a manifest signed off GitHub covers
  that case ([Verifying a release](verifying-releases.md)), if the operator
  kept a copy of the maintainer's public key from before the compromise. The systemd service has its own equivalents, listed above.
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
