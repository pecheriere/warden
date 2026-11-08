# Approving without Tailscale: owner identity and listener exposure

**Status: proposed. Nothing here is implemented.** warden today requires
Tailscale, and [the threat model](../threat-model.md), [the deployment
guide](../deployment.md) and [the configuration
reference](../configuration.md) describe that behaviour correctly. They change
only when the code does. Tracking issue:
[#75](https://github.com/pecheriere/warden/issues/75).

## Recommendation

1. **Add one identity source: a passkey login session (`passkey-session`).**
   warden verifies the owner itself, with the passkeys it already holds, and
   trusts nothing the network says about who is calling. A session lets the
   owner see and refuse things. It never approves: each approval still needs
   its own passkey assertion.
2. **Do not ship a plain trusted header.** warden cannot check its one
   assumption, and a mistake is silent. Someone who wants Cloudflare Access or
   Authelia can put it in front of `passkey-session` as an outer gate, and
   warden ignores what it says.
3. **Support private networks only.** The reference layout is WireGuard with a
   per-peer firewall rule, which replaces the tailnet policy. Internet exposure
   is unsupported, but the design makes sure an accidental exposure costs
   availability and not approvals.
4. **Tailscale stays the recommended setup.** It remains the only option that
   gives warden a per-device network policy with tests, and no certificate or
   proxy to run.

## What warden assumes today

Everything in this section was checked by reading the code at the commit this
document was written on.

| Assumption | Where | What depends on it |
|---|---|---|
| The owner is whoever `Tailscale-User-Login` names. | `TailscaleServeIdentity` and `Owner` in [`identity.rs`](../../crates/broker/src/identity.rs) | Every approval UI route, through `require_owner` in [`approval/mod.rs`](../../crates/broker/src/approval/mod.rs), and bearer agent keys, through `AuthedAgent`. |
| `WARDEN_OWNER_LOGIN` is set. | `Config::from_lookup` in [`config.rs`](../../crates/broker/src/config.rs) | Startup: it is required. The value is a Tailscale login, and a session has no equivalent. |
| A `Tailscale-Funnel-Request` header marks internet traffic. | `refuse_funnel` in `identity.rs`, layered in [`api.rs`](../../crates/broker/src/api.rs) and the approval router | "No exemption reaches the internet" in the threat model. |
| Who can reach each port is decided by tailnet policy. | Not in the code; see "Phone-only approval port" in the threat model | Keeping agents off the approval UI. Limiting who can try signed requests, and the log lines and connections they can cost. |
| TLS is someone else's job. | `parse_public_url` requires https, while `axum::serve` in [`main.rs`](../../crates/broker/src/main.rs) serves plain HTTP. `check_server_url` in the [CLI](../../crates/cli/src/config.rs) refuses plain HTTP except to loopback. | Every option here still needs a TLS terminator. |

Three limits matter once Tailscale is gone:

- **The relay's pre-login limit is the only per-source limit warden has.**
  `PreAuthLimiter` in
  [`relay/session/limits.rs`](../../crates/broker/src/relay/session/limits.rs) allows 5
  connections per address and 10 overall. Behind any TCP forwarder all peers
  share one address, so it acts as a global limit, as the threat model already
  says for Serve.
- **The HTTP listeners have no per-source limit, and no limit on connections.**
  `axum::serve` is called without connection info, so a handler cannot see the
  peer address at all. Only signed requests have a body-read timer
  (`BodyReadTimeout` in [`signed.rs`](../../crates/broker/src/signed.rs)). The
  approval listener has a 64 KiB body limit and no timer.
- **The passkey ceremony table is bounded per request and per kind.** Ceremonies
  live 120 s. A request keeps its 4 newest, enrollment has 8 slots of its own, and
  approvals as a whole stop at 1024, counting requests that ended in the last 120 s
  (`PasskeyError::Busy` in
  [`passkeys.rs`](../../crates/broker/src/approval/passkeys.rs)). Today only the
  owner can reach it. An unauthenticated login route would need limits of its own:
  nothing here ties a ceremony to a request for it to be bounded by.

`IdentitySource::caller` takes only the headers and is synchronous, so it can
read a cookie but cannot query the database. `Owner` compares its answer with
`owner_login`. The trait marks the right place to change, but its current shape
fits neither a session nor a peer check, and it will have to change.

## What stays true under every option

These come from the passkey layer, which has nothing to do with Tailscale:

- **Nobody approves without an assertion from an enrolled passkey**, with user
  verification required (`finish_approval`). The ceremony state is on the
  server, single use, and bound to the request, window, fingerprint and
  destination digest. A forged owner identity does not change this: deployment
  documentation already says a forged login "cannot approve anything".
- **The WebAuthn relying party is the `WARDEN_PUBLIC_URL` host**, with that one
  origin accepted (`Passkeys::new`). A look-alike site cannot get a usable
  assertion.
- **Nobody enrolls a passkey without a code** printed by `warden-server enroll`
  on the server: 12 base32 characters (60 bits), single use, 10 minutes, stored
  hashed.
- **The agent never receives the approval token.** `CreatedResponse` has only
  the id and fingerprint; the link goes to the notifier.

What the identity layer protects is everything else on the approval UI: reading
`/grants` and `/history` (every goal, agent and target), reading a pending
request through its link, denying, revoking, and acting as the second factor of
enrollment.

### One limit that is easy to miss: the TLS terminator can swap an approval

A WebAuthn assertion proves the owner's device answered warden's challenge for
warden's origin. It does not sign what the page displayed. So whatever
terminates TLS can show the owner request A while running the ceremony for
request B, and warden sees a valid assertion for B. The fingerprint does not
help, because the terminator also controls the page that shows it.

Today that position is held by tailscaled on a host that is already the root of
trust. A reverse proxy on the same host adds little. **A third party that
terminates TLS, such as a CDN or a hosted access proxy, can obtain approvals the
owner did not mean to give.** It also sees session cookies and approval links.
Any support for such a service has to say so plainly.

## Options

### A. Tailscale Serve (today, stays recommended)

- **Trusts:** the Tailscale control plane and tailscaled, and that only Serve
  can reach the listeners.
- **Fails:** a process or container that reaches a listener directly can forge
  the login, and warden cannot tell. The sidecar layout rules this out; the
  Services layout puts the whole host in the trust boundary.

### B. Passkey login session (recommended addition)

The owner signs in with a passkey at `WARDEN_PUBLIC_URL` and gets a session
cookie. warden ignores `Tailscale-*` identity headers and all proxy headers when
deciding who is calling.

- **Trusts:** the enrolled passkeys, the server's own session table, and the TLS
  terminator (for confidentiality and approval integrity, as above, but not for
  identity).
- **Fails:** a stolen cookie gives its holder the session's powers until it
  expires, and still no approvals. A reachable login route can be flooded, which
  locks the owner out of logging in. If the database cannot be read, every owner
  request is refused.

### C. Plain trusted header from a configured proxy

The proxy (for example Authelia behind a forward-auth rule, which passes
`Remote-User`) authenticates the owner and warden believes a header.

- **Trusts:** the proxy's authentication, its rule set on every route, its
  removal of any client-supplied copy of the header, and that nothing else can
  connect to the listener.
- **Fails:** silently. Each of these looks like a working deployment: a route
  that skips the auth rule, a proxy that forwards a client's header, a second
  service on the same Docker network. warden can narrow this but not close it.
  A peer address check needs connection info warden does not collect today, and
  does nothing against a same-host process when the proxy is also on loopback. A
  shared secret or a Unix socket with `0660` permissions (axum supports
  `UnixListener`) proves the request came from the proxy, not that the proxy
  checked anything. Authelia's own documentation tells backends to pin the
  proxy's address, and warns that trusting a whole Docker network lets a
  compromised container bypass authentication.

The issue asks that a misconfiguration fail closed where possible. Here the
dangerous misconfigurations are the ones warden cannot see.

### D. Signed assertion from an identity-aware proxy or OIDC provider

warden verifies a signed token rather than believing a name. Cloudflare Access,
for example, sends `Cf-Access-Jwt-Assertion`, with keys published at a team
endpoint and rotated about every six weeks.

- **Trusts:** the issuer's signing keys and its policy, plus warden's own
  verification of signature, issuer, audience and expiry. With a hosted proxy,
  also the party terminating TLS.
- **Fails:** closed when the listener is reached directly, because a forged
  token does not verify. This is a real improvement over C. If the issuer is
  compromised or its policy is wrong, the attacker is the owner except for
  approvals.
- **Costs:** JWT verification, a key fetch path, a new egress destination, and
  key rotation failures that lock the owner out. The result still needs passkey
  approval, so it adds an external dependency without adding what the session
  gives.

### Also considered

- **No identity on the approval page, token and passkey only.** Rejected: it
  breaks the rule that no mode accepts a caller with no identity. It would also
  let every notifier, which holds the link, read the destination details and
  deny the request. Today the threat model limits notifiers to the goal, agent,
  target and link.
- **Client certificates.** warden has no TLS listener, so this cannot be an
  identity source without adding one. A client certificate checked at the proxy
  is useful as an exposure control; see below.

### What each attacker can do

The columns describe an attacker with no credentials and no enrollment code. In
every cell, they cannot approve a request. "Forge" means sending the header or
token that names the owner, which gives read access to `/pending`, `/grants`,
`/history` and any pending request's approval page, since `/pending` hands out a new
link for it, plus revoke, deny and replacing approval links.

| Option | Attacker on the LAN | Agent on the same host (unprivileged, another OS user) | Internet attacker |
|---|---|---|---|
| **A. Tailscale** | Nothing, unless a listener is bound to the LAN against the documented rules; then forge. | Services layout: forge, and use a stolen bearer key. Sidecar layout: nothing. | Nothing with Funnel off. With Funnel on: 401 from both listeners. |
| **B. Passkey session** | Can reach the endpoint if the firewall allows: gets the login page, `/static`, credential ids, `/healthz`, `/v1/info`. While no passkey is enrolled, can guess enrollment codes (below). Can flood login. Cannot forge. | The same, and it can connect to a TCP listener directly. Cannot forge. If warden is down it could bind the port first and receive the proxy's traffic, gaining the swap position above; a Unix socket or a private network namespace prevents this. | Unsupported. If exposed by accident, the same as the LAN column, with easier flooding. |
| **C. Plain header** | Authenticates at the proxy, or forges if any route skips the rule or the listener is reachable. | Forges unless a Unix socket or shared secret keeps it out; a peer address check does not, on loopback. | Depends on the proxy having no mistakes. A direct hit on the origin, or one unprotected route, is a forge. |
| **D. Signed assertion** | Cannot forge. Reaches at most a refusal. | Cannot forge. Could replay a token it captured until it expires, which needs root on this host. | Best of the set: a hosted proxy can stop traffic before warden, and direct hits fail verification. The proxy can swap approvals. |

The guess risk for B: at 10,000 guesses per second for the 600 s life of a code,
an attacker has about a 5 × 10⁻¹² chance per code. warden does not rate-limit
these guesses, and that figure is why it does not have to on a private network.
Guessing is possible only before the first passkey is enrolled, because enrollment
needs a session afterwards, and a code exists only after the owner runs
`warden-server enroll`.

## Why B

The issue's concern with a header is that warden cannot verify that nothing else
reaches the listener. B removes that assumption rather than managing it: reaching
the listener gives nothing. It also improves on Tailscale's own weak spot, since
a local process on the host can no longer forge the owner. It uses code warden
already has (`webauthn-rs`, ceremonies, the counter check) and adds no external
service. Owners keep the option of a proxy gate in front, without warden having
to trust it.

What B costs is a new unauthenticated surface: login routes that anyone who can
reach the port can call. The next sections are mostly about containing that.

## Design of `passkey-session`

### Configuration

A new required variable, `WARDEN_IDENTITY`, set to `tailscale` or
`passkey-session`. warden refuses to start when:

| Condition | Why |
|---|---|
| `WARDEN_IDENTITY` is unset, empty or unknown | Missing configuration refuses to start. This breaks existing deployments until they add one line; see the open questions. |
| `tailscale` without `WARDEN_OWNER_LOGIN` | As today. |
| `passkey-session` with `WARDEN_OWNER_LOGIN` set | Ambiguous: the owner seems to expect a login to matter. |
| `passkey-session` with a wildcard address (`0.0.0.0`, `::`) on any listener | A wildcard is never right here. `Config` accepts one today in every mode. |
| `passkey-session` with an unrevoked bearer agent | Bearer keys are only accepted with the owner's login, and agents have no session. They would all fail with 403; this reports it at startup instead. |

The startup log names the source and what it trusts, for example
`identity=passkey-session trusts="enrolled passkeys; TLS terminator for
confidentiality and approval integrity; network exposure is not checked"`.

The configuration type should carry this as an enum holding `owner_login` only
in the Tailscale variant, so that the invalid combination cannot be represented.

### Routes

`require_owner` stays on the whole approval router, with an explicit short list
of exceptions. Everything else, the fallback included, needs a session.

| Route | Without a session |
|---|---|
| `POST /login/begin`, `POST /login/finish` | Allowed. They start and finish authentication and return nothing about requests. |
| `GET /static/warden.js`, `GET /static/warden.css` | Allowed. Public code. |
| `GET /enroll`, `POST /enroll/begin`, `POST /enroll/finish` | Allowed only while **no passkey is enrolled**, with the code. Once one exists, enrollment needs a session and a code, the same two factors as today. |
| Any other `GET` | Renders the login page at the same URL with status 401, without saying whether a token is valid. After login the page reloads, so there is no redirect parameter to abuse. |
| Any other method | 401 with a fixed JSON body. |

`require_same_origin_json` keeps applying to every state-changing route,
including login and logout. If the owner loses every passkey, recovery is
`warden-server passkey remove` and a new code, which needs access to the host,
which is already the root of trust.

### Sessions

- **The token** is 256 random bits, stored only as a SHA-256 hash, like approval
  tokens. It is created at login and never before.
- **The cookie** is `__Host-warden_session`, with `Secure`, `HttpOnly`,
  `SameSite=Strict` and `Path=/`. The prefix stops a sibling subdomain from
  setting it. The CSP already forbids inline script.
- **Storage is a SQLite table in a new migration**, with the passkey that opened
  it. `warden-server passkey remove` runs in another process and must end that
  passkey's sessions, which an in-memory table cannot do. The check therefore
  queries the database, so it belongs in the async `Owner` extractor. A database
  error refuses with `AuthRejection::Internal`.
- **Lifetime is absolute**, proposed at 12 hours, and not extended by use. The
  grants page polls every 5 s, so sliding expiry would keep an open tab signed
  in forever.
- **`POST /logout`** ends the session. Sessions past expiry are swept with the
  existing sweeper.

### Login ceremonies

- **A new ceremony kind, in its own table.** `take_approval` already refuses the
  wrong kind, so a login assertion cannot complete an approval or the reverse. A
  login flood must not be able to fill the approval table.
- **The login table evicts its oldest entry rather than refusing**, with a 60 s
  lifetime. A flood then has to outrun the owner's own tap: with 64 entries and
  10 s to finish a prompt, about 6 requests per second. That is still low, and
  it is the main reason internet exposure is not supported.
- **Reuse the counter check** (`store_counter`), with its audit event.
- **No limit based on `X-Forwarded-For`.** warden has no trustworthy way to know
  it came from a proxy, and this design exists to avoid that kind of trust. Per
  source limits belong on the proxy, and nothing in warden relies on them.
- **Add a body-read timer** on routes reachable without a session, reusing
  `BodyReadTimeout`.

`start_passkey_registration` does not require a resident key, so existing
passkeys may not be discoverable. Login therefore uses
`start_passkey_authentication`, which puts credential ids in the options
returned to an unauthenticated caller. WebAuthn does not treat them as secret,
and they give no way to sign, so this is accepted and recorded in the threat
model.

### Audit and notification

- **Audit** successful logins, logouts and session ends. **Do not audit failed
  assertions**: anyone who can reach the route could then grow the hash-chained
  log without limit. Log them at warn level, like refused signed requests.
- **Ring the doorbell** for each login and each enrollment. A login the owner did
  not make, or a new passkey, is the event they most need to hear about. The
  notification carries no link.

### Two changes that apply to every mode

- **`refuse_funnel` on the approval router**, now in place. Without it, Funnel
  traffic would fail on the approval UI only for lack of a login, and
  `passkey-session` behind Serve with Funnel on would put the login page on the
  internet. Absence of the header proves nothing outside Serve, so this protects
  only that one setup.
- **Refuse a request with more than one value of an identity header.**
  `TailscaleServeIdentity` reads the first value. Serve removes client copies, so
  this is hardening rather than a bug.

## Exposing the listeners

warden cannot see its network, so these are documented requirements, with checks
for `warden-server doctor` ([#77](https://github.com/pecheriere/warden/issues/77))
where a check is possible.

**What is lost if an agent can reach the approval page.** The threat model counts
two layers: the network keeps agents away, and the passkey protects approval.
Without the first:

- With no browser access to the owner's session or passkey, an agent gets the
  login page and nothing else. It does not have the approval token either.
- With browser tools on a machine holding a synced passkey or a signed-in
  session, which is the case the design calls out, the agent can read history,
  revoke grants and deny requests. It can also get a link for any pending request
  from `/pending`, with no notifier client needed, and put a real passkey prompt in
  front of the owner, on the machine it controls. A tired owner who taps it has
  approved. This is the anti-goal "phone-only approval" exists to prevent, and a
  session does not replace it.

So a replacement for the network layer stays a requirement, not a suggestion.
What replaces the tailnet policy, strongest first:

| Control | Binds access to | Limits |
|---|---|---|
| **WireGuard, per-peer firewall rule** (reference layout) | The peer's key: WireGuard ties a tunnel source address to the peer's key. | Policy tests are the operator's to write. Equivalent in structure to the tailnet policy: approval port to the phone's peer, API port to the agents' peers. |
| **Client certificate checked by the proxy, installed on the phone only** | A key on the phone. | Works on any network. Mobile setup is awkward, and the proxy is now trusted for this check. |
| **Separate VLAN with firewall rules by address** | An address. | Spoofable by a machine with enough access on the same segment. Acceptable if agents are on a different segment. |
| **Nothing: approval UI reachable from agent machines** | Nothing. | Only the passkey protects approval. It should be documented as a weaker setup rather than forbidden, because warden cannot detect it. Keep the owner's passkey and sessions off agent machines. |

**TLS.** A passkey needs a domain name and a certificate the phone trusts, and
`parse_public_url` rejects IP addresses. On a private network this means a real
name with a certificate obtained by DNS challenge, or a private CA installed on
the phone and the agent machines. The proxy (Caddy, nginx or similar) listens only
on the private interface, and uses separate names for the UI and the API, as the
Services layout does, so the relying party is not shared. Traffic between the
proxy and warden is plain HTTP and should stay on loopback, a Unix socket or a
network holding only those two.

**Reference layout (not yet tested):**

```
owner-phone ──── WireGuard ──▶ warden.example.com     (443) ─┐
                                                             │  reverse proxy,
agent-machine ── WireGuard ──▶ warden-api.example.com (443) ─┤  private interface only
                                                             ▼
                                warden  :8081 approval UI    :8080 agent API
```

The firewall allows the phone's peer to the approval name's address and the
agent's peer to the API name's address, and drops the rest. Connect's isolation,
container hardening, egress rules and backups stay as they are.

**The agent API needs no identity change.** A signed request is authenticated by
its signature, not by the network. What the tailnet policy did for it was limit
who can try. A peer that can reach it can learn `/v1/info` and which agent names
exist, add a log line per refused request, and hold a connection for up to 16 s
with up to 2 MiB per request when it names a known agent. All of these are
accepted in the threat model *because* the tailnet bounds them. They need the
firewall rule above for the same reason. Bearer keys are refused in this mode.

**The relay** authenticates agents by key and pins host keys through the grant,
so identity needs no change. Its 5-per-address limit means something only when it
sees real peer addresses; through a TCP forwarder it acts as a global limit of 10,
and a peer that can reach the port can hold up logins for a few seconds at a time.
Same answer: restrict the port to agent peers.

**A proxy adds logs.** `/approve/<token>` will appear in its access log. The link
needs a session and a passkey to use, and the token expires in 10 minutes, so
this is tolerable, but the documentation should mention it.

## The internet

**Unsupported, and warden cannot enforce that.** `refuse_funnel` only sees Serve's
header, and nothing else tells warden where a connection came from. So the design
asks what happens when someone does it anyway:

| What they face | Result under `passkey-session` |
|---|---|
| Approval tokens | Not testable: every route needs a session first, and the login page looks the same for any URL. Knowing one gives nothing without a passkey. |
| Enrollment | Needs a code, and a session once a passkey exists. The guessing figure above holds, though a flood could raise the rate. |
| Login | No password to guess. The realistic harm is flooding that locks the owner out. |
| Agent API | Signatures hold. Names can be enumerated, logs grown, and connections held with no overall limit. A real flood could exhaust memory. |
| Relay | Keys hold. Logins can be blocked. |

No approval is lost, and no secret is exposed. The owner can lose the ability to
log in and approve while under attack, and warden's logs can be flooded. This is
why a public listener needs work (connection limits, global rate limits, log
limits) that this design does not include. An identity-aware proxy in front would
address availability, at the cost of the swap risk for a hosted service, so it is
an open question below rather than a supported layout.

## Threat model changes this would need

These go in with the implementation, not before.

- **In short:** add whoever terminates TLS to the list of what warden does not
  protect against, with the swap described above.
- **Actors and trust:** make the Tailscale row conditional on the mode. Add rows
  for the reverse proxy or TLS terminator and for the private network.
- **Anti-goals:**
  - "A notification channel sees secrets or can approve": "only the owner's phone
    can reach" becomes a statement about the network layer, plus the session.
  - "warden becomes the easiest way into the network": it says warden listens only
    where Serve can reach it. Add the `passkey-session` equivalent.
- **Approval binding:** state that an assertion binds the ceremony, not what was
  displayed, and that the fingerprint cannot defend against the terminator.
- **Authentication of callers:**
  - State the first bullet per mode, and list the routes open without a session.
  - "No exemption reaches the internet" holds only behind Serve. Say what replaces
    it in `passkey-session`: the firewall, unchecked.
  - Replace "tailnet policy" with the network layer where it bounds signed
    requests, log lines and agent-name probing.
  - State that bearer keys exist only in `tailscale` mode.
- **Accepted residual risks:** add session theft (what it allows, how long),
  login flooding, published credential ids, and approval links in proxy logs.
- **Relay mode residual risks:** generalize "the per-address pre-login limit is
  global behind Tailscale Serve" to any TCP forwarder.
- **Deployment assumptions:**
  - Add the third way to publish, and state that agents on the same host are
    outside the supported layouts.
  - Restate "Phone-only approval port" with the controls in the table above,
    including the weaker case.
  - Note that "anything that can reach a listener can forge the login" applies
    only to `tailscale`.

The same change updates `deployment.md` ("Tailscale is a hard requirement"),
`design.md` §13 (the same decision, stated for v1), `configuration.md`
(`WARDEN_OWNER_LOGIN`, `WARDEN_IDENTITY`, the endpoint table), the README, and
the Tailscale wording in `agent-protocol.md`, `agent-usage.md` and the doc
comments in `identity.rs`, `api.rs`, `approval/mod.rs` and the CLI's
`config.rs`.

## What is certain, and what is not

**Verified by reading the code:** everything in "What warden assumes today" and
"What stays true under every option", and that credential ids are returned by
`start_passkey_authentication`'s path and registration does not require a resident
key (`webauthn-rs` 0.5.5 source).

**Reasoned from the code and from how WebAuthn works, not run:** the attacker
table, the swap by a TLS terminator, the flooding rates.

**Taken from vendor documentation, not tested:** the Cloudflare Access and Authelia
behaviour described in options C and D.

**Not tested or not checked at all, and to settle before or during implementation:**

- **Notification links on real phones.** Today identity comes from the network,
  so it does not matter which browser opens a link. With a cookie it does. A link
  opened in a notifier's in-app browser may not share cookies with the main
  browser, may not support passkeys, or may lose a `Strict` cookie. If `Strict`
  loses the session on these links, `Lax` is safe here because `GET` routes have
  no side effects and every other method passes the origin check.
- **Prompt count.** With no live session, approving takes two passkey prompts:
  login, then approval. How annoying that is depends on the previous point and the
  session lifetime.
- **The reference layout**, including which root certificates the CLI trusts for a
  private CA.
- **hyper's defaults** for slow request headers on these listeners. If it does not
  limit them, the login routes need that too.

## Open questions for the owner

1. **Is breaking existing deployments acceptable?** The rule "missing
   configuration refuses to start" means every Tailscale deployment must add
   `WARDEN_IDENTITY=tailscale` on upgrade. The recommendation is to accept this, with a
   changelog note and a startup error that says what to set. The alternative,
   defaulting to `tailscale` when `WARDEN_OWNER_LOGIN` is set, is friendlier but
   implicit, and the issue asks for an explicit setting.
2. **Does an enrollment code count as an identity for the first passkey?** With no
   passkey there can be no session, so the code alone has to be enough. It is
   minted on the host, which is the root of trust, so this design treats it as
   satisfying "no caller with no identity". It is the one place where this design is arguably
   weaker than today, which requires a login too.
3. **Should an identity-aware proxy in front be documented as a supported way onto
   the internet?** The recommendation is no for now: private networks only. A self-hosted
   proxy would be defensible; a hosted one means the swap risk. The answer decides
   whether connection and log limits become part of this work.
4. **Should `passkey-session` refuse synced passkeys?** Refusing backup-eligible
   credentials would enforce that the passkey is not on the agent's machine. It
   would probably also exclude most phones' built-in passkeys, leaving security
   keys; this has not been tested across devices. The recommendation is to allow
   them, document the risk and rely on the login notification.
5. **Is 12 hours the right session lifetime?** Shorter means more double prompts.
   Longer means a stolen cookie lasts longer, though it cannot approve.
6. **Is option D wanted later?** It is the one defensible way to use an external
   identity. It should become its own issue only if someone asks.
7. **Should sessions eventually apply in `tailscale` mode too?** That would close
   the same-host forgery in the Services layout. It is out of scope for #75, and it
   would add a login step to the recommended setup.

Related: [#73](https://github.com/pecheriere/warden/issues/73) (the local demo)
needs its own answer for localhost and must not use this mode's settings to weaken
a real deployment. [#74](https://github.com/pecheriere/warden/issues/74) (no
Docker) should treat the same-host findings above as input.
