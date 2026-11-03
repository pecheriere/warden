# Approving from an Apple Watch and a native app

**Status: a plan. Nothing here is implemented, and nothing will be built yet:** the
maintainer has decided not to create the repository or a test app for now. Today
every grant needs a passkey, and [the threat model](../threat-model.md) says so
correctly. It changes only when the code does. Tracking issue:
[#149](https://github.com/pecheriere/warden/issues/149), with the maintainer's
decisions in its comments.

## Where this ends up

**Decided:**

- **One native app** for iPhone and iPad, including folding sizes, wanted in its own
  right, with notification buttons. A Watch app comes with it.
- **warden stays on the tailnet.** No public listener for now. The Watch reaches
  warden through the iPhone.
- **A separate repository**, with CI building the apps.
- **A cellular Watch**, which adds nothing under this plan: see below.

**What that gives:**

- **Each device has its own Secure Enclave key.** The device signs a hash of what it
  displayed, and the broker checks that hash against what it sent.
- **The new routes sit on the existing approval listener,** behind Tailscale Serve
  and the owner's login. That layer stays, so there is no new internet surface.

**What it does not give:**

- **A Watch cannot approve or deny without its iPhone nearby.** A Watch [cannot join a
  tailnet](#what-apple-allows), so the cellular radio can bring in a push and nothing
  more. Pushes still arrive with the phone left behind; the Watch then says it cannot
  reach warden. warden's own timeout ends the request.
- **An iPad cannot relay for a Watch,** although that was the wish. [Session objects
  exist only on Apple Watch and iPhones that can pair with
  one](https://developer.apple.com/documentation/watchconnectivity/wcsession/issupported()).
  An iPad runs the app for itself.
- **Silent approval from a notification, with Face ID, probably cannot work.** See
  [notification buttons](#notification-buttons).
- **The reflex tap.** It is [the top risk](../security-assessment.md). The plan raises
  the effort and limits the damage. It cannot make the owner read.

## What Apple allows

Checked on 2026-11-02 against Apple's documentation and the iOS and watchOS 27.2 SDKs.
**Nothing has run on a device.** "Typechecked" means a throwaway Swift file was checked
with `swiftc -typecheck` against the watchOS SDK, which proves an API is offered, not
how it behaves. **[Not confirmed]** marks what the sources do not settle.

### Confirming on a Watch

- **Side button double-click: no API found.** The SDK mentions it only for the [Apple
  Pay sheet](https://developer.apple.com/documentation/passkit/pkpaymentauthorizationcontroller)
  and a deprecated Mac policy. Apple states no ban; this is absence from a search.
- **Companion authentication** (`deviceOwnerAuthenticationWithCompanion` and
  `SecAccessControlCreateFlags.companion`; SDK headers, iOS 18). An iPhone app may be
  able to hold a key that a nearby device must confirm. With the relay already needing
  the iPhone, this is a real candidate rather than a curiosity: it could give a
  system prompt, perhaps the side button. **[Not confirmed]**: whether an iPhone's
  companion can be a Watch, what the Watch shows, and whether it works in the
  background. The text would come from the iPhone app, so it gives no independent
  display. It belongs in the first test.
- **Double tap.** An app can make a button [the scene's primary
  action](https://developer.apple.com/documentation/watchos-apps/enabling-double-tap).
  On a notification, the system ["invokes the first nondestructive
  action"](https://developer.apple.com/documentation/watchos-apps/adding-actions-to-notifications-on-watchos),
  so a pinch runs whichever button is first.
- **App Intents** exist on watchOS, with [a policy that requires
  unlocking](https://developer.apple.com/documentation/appintents/intentauthenticationpolicy).
  A widget shows stale content and approves in one gesture, so they are not used.

### Keys and the wrist

- **Passkeys on a Watch: no.** The [platform
  provider](https://developer.apple.com/documentation/authenticationservices/asauthorizationplatformpublickeycredentialprovider)
  is unavailable on watchOS (typechecked: refused).
- **Secure Enclave keys: yes.**
  [`SecureEnclave.P256.Signing.PrivateKey`](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
  is on iOS and watchOS, with access control and an `LAContext` from watchOS 9
  (typechecked).
- **Wrist detection: yes, with a contradiction.** There is no biometry on a Watch.
  [`deviceOwnerAuthenticationWithWristDetection`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithwristdetection)
  fails, says its page, if the Watch came off. The header `LAContext.h` says
  authentication is by passcode and "will also succeed" if it stayed on the wrist.
  **[Not confirmed]**: which is right, and whether a key's signing is held to this. An
  [unanswered 2018 post](https://developer.apple.com/forums/thread/111970) reports
  `userPresence` not protecting an item with Wrist Detection off.
- **Removing the passcode** [deletes items in
  `WhenPasscodeSetThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly).
  They never migrate to another device.

### Notifications

- **A tap can run code.** [By default the app launches in the
  background](https://developer.apple.com/documentation/watchos-apps/adding-actions-to-notifications-on-watchos).
- **Where it runs:** foreground actions on the device where they were selected,
  background actions "on the device that was the notification's target". A push to the
  iPhone that is forwarded to a Watch runs its background action on the iPhone.
- **Forwarding:** [a push to the iPhone goes to the phone if it is unlocked with the
  screen on, otherwise to a Watch on the wrist and unlocked, otherwise to the
  phone](https://developer.apple.com/documentation/watchos-apps/taking-advantage-of-notification-forwarding).
  Direct pushes to a Watch appear only there. For a watchOS app with an iOS companion, Apple says
  that if you send to [both iPhone and Watch](https://developer.apple.com/documentation/watchos-apps/enabling-and-receiving-notifications),
  the system ensures one notification at the best destination. It says nothing about an iPad.
- **Unlocking is not a key prompt.**
  [`authenticationRequired`](https://developer.apple.com/documentation/usernotifications/unnotificationactionoptions/authenticationrequired)
  asks the user to unlock, then notifies the app. On a phone already unlocked it asks
  for nothing.
- **A prompt in the background is the open question.** A key operation that would need
  UI fails with `errSecInteractionNotAllowed`, and an evaluation with `LAErrorNotInteractive`,
  [when interaction is forbidden](https://developer.apple.com/documentation/localauthentication/lacontext/interactionnotallowed)
  (SDK headers `LAContext.h`, `LAError.h`). **[Not confirmed]**: whether iOS treats a
  background action this way or shows Face ID anyway. The plan assumes it cannot prompt.
- **Time is short.** [About 30
  seconds](https://developer.apple.com/documentation/usernotifications/modifying-content-in-newly-delivered-notifications)
  for a service extension. **[Not confirmed]**: the time a background action gets.

### Reaching warden

- **A Watch cannot run a VPN.** `NEVPNManager`, `NETunnelProviderManager` and
  `NEPacketTunnelProvider` are unavailable on watchOS (typechecked: refused), and
  [low-level networking is blocked and BSD sockets never
  work](https://developer.apple.com/documentation/technotes/tn3135-low-level-networking-on-watchos).
- **Watch routes:** [the iPhone first, then known Wi-Fi, then
  cellular](https://developer.apple.com/documentation/watchos-apps/keeping-your-watchos-app-s-content-up-to-date).
  **[Not confirmed]**: whether Watch traffic through the iPhone enters its Tailscale
  tunnel. If it does, the relay below shrinks to nothing when the phone is near.
- **WatchConnectivity:** the Watch app, while running, can message the iPhone app, and
  iOS launches it if needed (SDK header `WCSession.h`). The phone must have been unlocked
  once since boot. **[Not confirmed]**: how long that launch can run.
- **The Tailscale app on iPhone:** an app's HTTPS follows the tunnel when it is up.
  [VPN On Demand](https://tailscale.com/docs/features/client/ios-vpn-on-demand) can
  start it for `*.ts.net` names, only under its "Do Nothing" rule. **[Not confirmed]**:
  whether it fires for a background app's request.

### TailscaleKit

[`TailscaleKit`](https://github.com/tailscale/libtailscale/tree/main/swift), in
`tailscale/libtailscale` (BSD-3-Clause), embeds a Tailscale node in an app, with a
`URLSession` extension for reaching tailnet nodes. Its README builds for macOS, iOS and
the iOS simulator, and calls the device framework suitable for App Store submission.

- **What it might solve:** the app reaches warden by itself, with no Tailscale app, VPN
  profile or On Demand rule, and no competition for the phone's one VPN slot.
- **Background time: not solved.** The README does not discuss it. The node must come up
  inside the window of a notification action or a Watch request. It may not fit.
- **Owner identity: not solved by default.** warden trusts the login Serve reports. A
  node with a tagged auth key has none, and storing an auth key in an app is its own
  risk. The README also describes interactive login through `browseToURL`. **[Not
  confirmed]**: that such a node presents the owner's login through Serve.
- **watchOS: no build listed,** and TN3135's rules make one unlikely. Even so, it is a
  question rather than a closed door: a Watch that could run this would need no relay,
  and the cellular Watch would become useful.
- **New costs:** one more device in the tailnet with its own access rules, and node
  state in the app's storage, which a stolen phone holds.

**The plan:** use the Tailscale app first, as it needs no new code or identity. Move to
TailscaleKit only if the first test shows the tunnel is not there when woken.

### Pushes and distribution

- **APNs from the broker** needs [HTTP/2 to `api.push.apple.com`, on 443 or 2197, and a
  JWT from a `.p8` key](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns),
  [refreshed every 20 to 60
  minutes](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns).
  A topic-specific key limits it to named apps. A rule by address means [Apple's whole
  `17.0.0.0/8`](https://support.apple.com/en-us/102266). APNs is best effort.
- **Precedents:** [ntfy](https://docs.ntfy.sh/config/) and [Home
  Assistant](https://contributors.home-assistant.io/companion/mobile-app-api/notifications/)
  ship one app with one key, so users go through a relay. ntfy's relay sees only a
  message ID and a topic hash.
- **Each owner builds their own app.** A paid membership ([push is not in the free
  tier](https://developer.apple.com/help/account/reference/supported-capabilities-ios)),
  an App ID, a `.p8`, and [a new TestFlight build every 90
  days](https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview).
  A shared App Store app would need [a demo backend for
  review](https://developer.apple.com/app-store/review/guidelines/) and a relay someone
  runs forever. Its publisher could also ship an update that signs silently.
  It can come later: the push carries nothing that blocks it.

## The plan

```text
agent ──request──▶ warden ──"a request is waiting"──▶ APNs ──▶ iPhone, iPad, Watch
                     ▲
                     │  Tailscale Serve, owner's login, signed routes
                     │
              iPhone or iPad app ◀──WatchConnectivity── Watch (iPhone only)
```

| | iPhone or iPad | Watch |
|---|---|---|
| **Key** | Secure Enclave, `.biometryCurrentSet`: Face ID or Touch ID for each signature, and a changed enrollment voids it | Secure Enclave, passcode class, wrist policy |
| **Screen** | The full request, in an adaptive layout | The broker's shortened display |
| **Network** | Itself, over the tailnet | Through the iPhone, which passes `/device/v1/` calls and nothing else |
| **Also** | Lists requests; can fall back to the passkey page | |

The layout uses size classes rather than fixed sizes, and is checked at the sizes in the
pull request template, folding sizes included.

**`.biometryCurrentSet` and no passcode fallback** because a thief who knows the passcode
could otherwise sign. If Face ID fails, the passkey page is still there.

### How each way of approving differs

| | Passkey | iPhone or iPad key | Watch key |
|---|---|---|---|
| **Check for each approval** | Biometry or PIN | Biometry only | **None:** a passcode once, then the wrist |
| **Key** | May sync | One device | One device |
| **What it signs** | A random challenge; the link to the request is [state on the broker](../threat-model.md#approval-binding) | The display, the request and a challenge | The same |
| **Who controls what is shown** | warden's page, in a browser | The app, and whoever can ship it | The same |
| **Phishing** | The browser binds it to warden's origin | No browser check: the app talks to the URL it enrolled with, and the signature names it | The same |
| **Clone check** | Counter | None; the key cannot be exported | The same |
| **Can enroll a device** | Yes | **No** | **No** |

So a native key is **about as strong as a passkey for each approval, with a better record
of what was approved, and less protection against a bad app**. That last point is why
shipping the app counts as a release of something that can approve.

### Enrollment

The iPhone carries everything between a Watch and the broker, so a compromised iPhone OS
could enroll its own key instead. That key would live off the phone, with no Face ID, until
someone revoked it. Two things have to stop this.

**The code must be compared on screens the phone does not draw.** A page rendered on the
same iPhone catches only a malicious app, as a compromised OS can draw any code on it.

**The phone must not be able to pick values that make the codes match.** A plain hash of the
two public keys fails: the phone chooses both its own key and the receipt key it hands the
Watch, so it can search both sides for a collision, about 2^30 work for a 60-bit code. So each
side commits before it sees the other's random value, as Bluetooth numeric comparison does:

1. In the app, **Add this device**. For a Watch, the iPhone asks over WatchConnectivity. The
   device creates its key `K` and a random `Nd`, and posts only `SHA-256(K, Nd)` to
   `POST /devices/pending`. This is on the approval listener, needs the owner's login, holds at
   most four entries for 10 minutes, and has no power at all.
2. The broker stores that, and returns its receipt key `R` and a fresh random `Nb`.
3. Only after receiving those, the device sends `K` and `Nd`. The broker checks them against the
   commitment.
4. The device and the broker each compute a **check code**: 40 bits of SHA-256 over `K`, `R`, `Nd`
   and `Nb`, such as `ABCD-EFGH`.
5. The owner confirms **on the warden host or a second device**: `warden-server device confirm
   <code>`, typing the code the device shows. That needs only the host, already the root of trust,
   like `warden-server enroll` today. Or the passkey-protected `/devices` page on another device,
   where the [phone-only approval port](../threat-model.md#deployment-assumptions) allows one. A
   code that matches two pending entries is refused.

**Why that is enough.** A phone in the middle must commit its key to the broker, and give the Watch
its `R` and `Nb`, all before the Watch reveals `Nd`. It then has nothing left to choose, so each run
has about one chance in 2^40 for each entry it holds, and no offline search helps. Each failed run
needs the owner to start again. A longer code without the commitment would also work, but 128 bits
is not something a person compares on a Watch.

**Where it stays weak, which is worth saying plainly:**

- **The phone's or iPad's own key: no protection against a compromised OS, on any path.** That
  device draws its own half of the comparison, so it can show whatever the host shows. An OS
  compromised at enrollment can enroll an off-device key, which outlives cleaning the phone. The
  code still catches a malicious app or a mix-up. The defences are the audit log, the notification
  and the Devices list.
- **A Watch confirmed on its own iPhone: the same,** as the phone draws the page. warden cannot tell
  which screen was used, so this is allowed, and the page says what it gives up.
- **A phone compromised at enrollment can still lie later,** as a relay. This stops the durable key
  for a Watch, not the rest.

The push token is not part of this. The first signed call sets it, so it needs no check code.

Passkey ceremonies get a new kind, so an enrollment assertion cannot complete an approval.
`device_enrolled` is audited and rings the existing notifiers.

### What is signed

A P-256 ECDSA signature over SHA-256, from the Secure Enclave:

```text
warden-device-decision-v1
audience: https://warden.example.ts.net
device: <device id>
decision: approve | deny
request: <request id>
fingerprint: <full request fingerprint>
destination: <destination digest>
window: 15m | 30m | 1h | 4h | none
display: <SHA-256 of the exact bytes received for display>
challenge: <256 random bits from the broker>
signed-at: <Unix seconds>
```

- **The broker sends** a display and a challenge, and keeps both, with the request and
  device, in memory for 120 s. A challenge is single use, and is consumed before
  verification, as ceremonies are.
- **The body carries only** the challenge ID, decision, `signed-at` and signature. The
  broker rebuilds the message from its own state, so a forged display fails. It refuses a
  `signed-at` older than 30 s, which limits how long a relay can hold a signature.
- **Other calls** (inbox, token) are signed as `warden-device-request-v1` with a timestamp
  and nonce, by the agent protocol's replay rules.
- **Then every check `approve_finish` makes:** still pending, fingerprint, destination
  digest, and policy read fresh. The signed message and signature go in the audit log.

**The hash covers bytes received, not pixels.** So:

- **The broker does the shortening,** for each device kind. A Watch's display cuts the goal
  to about 140 characters and says "shortened; full text on your phone" in the signed
  bytes. It also removes control and bidirectional characters.
- **The app must render every byte, verbatim and unclipped:** `Text(verbatim:)`, no line
  limit, in a scroll view. A test at the smallest Watch size checks this. If the app clips,
  the signature says the owner saw what they did not, and no one can detect it.
- **The fingerprint covers the full request,** so the record still ties a shortened display
  to the whole goal.

### Notification buttons

**What can sign from a notification:**

| Option | How | Cost |
|---|---|---|
| **A. Foreground (recommended)** | `Approve…` opens the app on the full request and starts Face ID. | The app opens. Expected to work, since it is ordinary UI. |
| **B. Background, same key** | Sign from the action, with Face ID. | Expected to fail: see [the open question](#notifications). Test it. |
| **C. Background, a second weaker key** | A key with no biometric constraint, in an unlocked-only class, after `authenticationRequired`. | **One tap approves on an unlocked phone,** with a second key to steal. What was shown must also be what was signed, so a service extension must fetch the display over the tailnet in about 30 s, or the details go through Apple. |

**The recommendation for the phone is A.** The maintainer's idea, an Approve on the
notification only for low-risk requests, then opens the full request for the rest. With A it
needs no such split, because every Approve reaches the full request and Face ID. **If C is
ever wanted,** limit it to read-only API items and a small budget, with the maintainer's
explicit choice, since it is the first way to approve without a check.

**Buttons on the phone, in this order:** `Review`, `Approve…`, `Deny`. Review comes first
because a phone's push can be forwarded to a Watch, where a pinch runs the first
nondestructive action. Deny is destructive and needs an unlocked phone. It needs no key:
it uses the existing `POST /pending/{id}/deny`, which takes the push's request ID, the owner's
login through Serve, and the same-origin JSON check, and no approval token.
`POST /approve/{token}/deny` does need the token, which a push does not carry.

**On a Watch, Approve stays rejected as a button.** It has no check for each approval, so a
button would be a single motion with nothing behind it. Its buttons are `Review` and `Deny`.

**The push:**

```json
{"aps": {"alert": {"title": "warden", "body": "A request is waiting"},
         "category": "WARDEN_REQUEST", "sound": "default"},
 "request": "<random request id>"}
```

No name, target or goal. The ID is random, so Deny knows its request. Apple learns when
requests happen and for which devices. The push is sent to each enrolled device, and APNs
rings alongside the existing notifiers rather than as a fallback, since APNs accepting a
push says nothing about arrival. Nothing trusts a push: the app fetches.

### On the Watch

1. **Scope and window, from warden:** `GET HEAD`, `home-api /status/`, `15 min`. This comes
   first because warden knows it for certain.
2. **Agent name.** warden has no session label. Goals may start with one, by convention,
   and that is the agent's own text.
3. **"The agent says:"** and the shortened goal, labelled as untrusted.
4. **Short fingerprint.**
5. **Deny**, then **Hold to approve**, below the fold, for two seconds, with no
   `handGestureShortcut`, so double tap can only scroll.

The broker also refuses a decision within 3 s of its challenge, and by default allows three
Watch approvals per rolling hour, then Deny only. If the relay is out of reach, the Watch
says so and sends nothing.

**Confirming the outcome.** The relay can lie, so the broker returns a signed receipt:

```text
warden-device-outcome-v1
challenge: <challenge>
outcome: approved | denied | refused
```

It is signed with a broker Ed25519 key that the check code covers. The Watch says "Denied"
or "Approved" only on a valid receipt. Otherwise: "Not confirmed. Check your phone. A
signed Approve may still apply for 30 seconds." The app does the same.

### What the Watch may approve

**Open.** The maintainer asks to consider modes, or a mode per session, rather than one rule.
**Until that is decided, a Watch approves only read-only API requests, for at most 15
minutes,** and denies anything. Phone keys follow the passkey's limits.

| Option | Gives | Loses |
|---|---|---|
| **Read-only API only** | Something warden can prove ([`is_read_only`](../../crates/proto/src/lib.rs)). | **Most of the value.** [Most of what stops an agent](advance-approval.md) is a push or a shell command. |
| **Opt-in per item** (`watch_max_window` in the vault item) | The owner marks an SSH account as narrow enough, read fresh at each decision. | Upkeep for each item, and a judgement warden cannot check. |
| **A mode the owner sets** (for example "away, 2 hours", on the passkey page, with an expiry) | Wider approval only when the owner chose it, for a limited time. | One more state to get wrong and forget. It must not be something an agent can set. |
| **A mode per session** | A wider rule for work the owner is watching. | **warden has no session.** The `[session]` prefix is agent-written, so a prompt-injected agent can claim any name, and [grants are not tied to a task](https://github.com/pecheriere/warden/issues/49). It needs a real, broker-issued session first. |
| **No limit** | Everything. | The margin: a reflex or a thief with the passcode gets a 4 hour shell, behind no check for each approval. |

### If something is compromised or stolen

| Who | What they can do | What they cannot |
|---|---|---|
| **The iPhone, as a relay** | **Read every request detail** passing through, which it can already see on the page. **Hide requests** from the Watch's inbox. **Drop a Deny and report success,** which the receipt exposes. **Hold a signed Approve** for up to 30 s, or 120 s without `signed-at`, then deliver or drop it. **Refuse to relay** anything. | **Get a signature for another request.** The Watch signs a hash of what it received, and the broker compares. **Approve with no signature.** **Forge a receipt,** unless it fooled enrollment. |
| **The iPhone's OS** | All of the above, and everything with its own key and passkey by misleading the owner at the prompt, as with a passkey today. If it is compromised at enrollment, it can [enroll a key of its own](#enrollment) in place of its own device's key, or of a Watch's confirmed on that phone. | Use a biometric key without a real match. |
| **Tailscale or the TLS terminator** | What it can today, such as seeing details. | The [swap in the #75 design](owner-identity.md#one-limit-that-is-easy-to-miss-the-tls-terminator-can-swap-an-approval), for native and Watch approvals: a changed display fails at the broker. |
| **The broker** | Everything, [as today](../threat-model.md#in-short). It can issue grants with no signature, and get a real signature over false text. | Forge a device's signature. If public keys are off the host and the log is shipped, a claimed approval can be checked, within the limits of [the passkey binding design](passkey-binding.md). |
| **APNs or the push key** | Spam a device, to train a reflex. Withhold pushes. | Approve, or learn details. Revoke a stolen key at Apple. |
| **Whoever ships the app** | Sign silently on a Watch; show false text before Face ID. **CI that can upload is in this group.** | Go beyond the limits the broker enforces. |

| Stolen | What the thief gets |
|---|---|
| **Watch, locked or off the wrist** | Nothing, if the wrist test passes. |
| **Watch, passcode known, iPhone nearby or also stolen** | Reads pending requests, approves what the limits allow, denies anything. **No access itself:** a grant goes to the agent that asked, and no credential reaches a device. |
| **Watch alone** | No relay, so nothing beyond any cached display. Nothing is cached after the screen closes. |
| **iPhone or iPad, locked** | Nothing new. Each signature needs biometry. |
| **iPhone or iPad, unlocked or passcode known** | Today's powers through the tailnet: read, deny, revoke. No signature, since a new face voids the key. A passkey that accepts the passcode is still today's risk. With TailscaleKit, also the node's state. |

**Revoking:** a **Devices** page, with the owner's login and no passkey, and `warden-server
device revoke <id>`. Each check reads the database, and a failure refuses. Grants already made
stay until revoked on the grants page. Find My's erase is not a revocation warden can see.

### Changes to the broker

| Area | Change |
|---|---|
| **New `device` module** | Store, routes, signatures, challenges, receipts. `POST /device/v1/inbox`, `/review`, `/decide`, `/token` on the approval router, so `require_owner`, `refuse_funnel` and the same-origin JSON check apply as they do to every route there, with the app sending the matching `Origin` and a JSON body. |
| **Approval pages** | `/devices`, confirm and revoke, following `docs/design-language.md`. |
| **Shared approval path** | Move grant-building out of `approve_finish`, and mark a request approved by ID and device, without rotating the approval token. |
| **Database** | A new migration: devices (kind, public key, push token, label, dates, revoked). |
| **Receipt key** | Generated on first use. It is at rest on the host, which is already the root of trust. |
| **Audit** | `device_enrolled`, `device_revoked`, and `approved` with the device, message and signature. |
| **Push** | `notify/apns.rs`, using the `p256` in the tree. APNs needs HTTP/2, and the workspace's `reqwest` entry does not list it, so add it and keep the no-decompression guard green. |
| **Deployment** | The tailnet policy's [phone-only approval port](../threat-model.md#deployment-assumptions) gains the iPad and any embedded node. |

## Hard parts

| Part | Rating | Why |
|---|---|---|
| **Reaching warden from the background** | **Hard: unknown** | The relay stacks WatchConnectivity, a background launch and a tunnel that may be down. If it is slow, the Watch is not worth having. |
| **The wrist check on a real key** | **Hard: unknown** | Apple's sources disagree, and the theft answer rests on it. |
| **The reflex tap** | **Medium: not solvable** | Only the owner can read. |
| **Two apps' upkeep and CI** | **Medium: ongoing** | Yearly OS changes, 90-day builds, and a trusted upload job. |
| **Enrollment** | **Medium** | Three devices, and a second screen. |
| **Signature, receipts, APNs, screens** | Easy | Familiar shapes. |

## The code, and its size

**A separate public repository** (not created), with macOS CI. Every pull request builds and
tests with no secrets. Uploading to TestFlight is a separate job in an environment with a
required reviewer, like any publish job, since [it can ship something that
approves](#if-something-is-compromised-or-stolen). Each owner signs their own, and the team and
bundle ID come from one config file.

**This repository keeps** the broker and `docs/device-protocol.md`, with test vectors checked
in `crates/proto`. The Swift repository tests against those at a pinned commit.

Rough estimates, not measurements:

| Phase | What | Size |
|---|---|---|
| **0. First test** | A throwaway app on real devices, answering the list below. Nothing else until it passes. | Days, with the devices |
| **1. Threat model and protocol** | A labelled "planned" section in the threat model, the protocol document, test vectors. | 300 lines of docs |
| **2. Broker** | Routes, store, enrollment, receipts, audit, docs. | 1,000 to 1,500 lines of Rust with tests |
| **3. iPhone and iPad app** | Enroll, list, review, sign, notifications, adaptive layout. | 800 to 1,200 lines of Swift |
| **4. Push** | APNs sender and deployment docs. | 300 lines of Rust |
| **5. Watch app and relay** | Only if phase 0 says the relay is fast enough. | 500 to 800 lines of Swift |

**The threat model must gain, in phase 1:** an exception to "every grant needs the owner's
passkey"; rows for the app, Watch, APNs and the upload job; the signed message under approval
binding; the device routes under authentication of callers; and as accepted risks, no check for
each Watch approval, a stolen Watch with its passcode, a lying relay, and enrollment confirmed on
one phone.

## The first test

Only real devices can answer these. The first two can change the plan.

1. **Background reach.** With the phone locked in a pocket, how long does a Watch request or a
   notification action take to reach warden? Through the Tailscale app, with On Demand, and with
   TailscaleKit? Does Serve report the owner's login for an embedded node?
2. **Keys.** On a Watch: does a passcode-class key with a wrist-policy `LAContext` sign on the
   wrist, and fail once off it? With Wrist Detection off? Is it gone without a passcode?
3. **Notification signing.** Does a background action on iPhone sign with a biometric key, or
   fail with `errSecInteractionNotAllowed`? Can a background Deny on a Watch use its key?
4. **Watch through the phone.** Does `URLSession` reach a tailnet name? If so, the relay is not
   needed when near.
5. **Companion authentication.** On an iPhone: can a Watch confirm, what does it show, and how?
6. **Pushes.** Direct to the Watch and to both: how quickly, and do they really arrive once?
7. **A pinch on the long look,** on a Series 9 or Ultra 2.
8. **Fit and feel,** on a small Watch and at folding sizes.

## Alternatives rejected

- **Side button double-click, and passkeys on a Watch.** No API. Dressing an approval as an Apple
  Pay payment would mislead.
- **A Watch without its own key, only forwarding to the iPhone.** Simple, and the iPhone is nearby
  anyway, but the phone would sign text the Watch cannot vouch for. Companion authentication is the
  one form of this still being tested.
- **Approve inside a notification's long look, or in a widget.** The reflex tap, with stale content.
- **A mailbox relay,** where the broker polls a store the Watch posts to. It would need a second
  public service.

## A later option: a public listener

The plan does not include this, and the maintainer decided against it for now. It is the only known
way, short of TailscaleKit on a Watch, for a Watch to work with the phone left behind, which is when
a cellular Watch would matter. It would be a separate listener accepting only device-signed requests,
through a separate ingress node, since [warden's listeners are never to use
Funnel](../deployment.md). It would lose the tailnet layer for these routes, and need [the limits the
#75 design lists](owner-identity.md#the-internet). The signed message would not change.

## Decisions still open

1. **What may a Watch approve?** Read-only API until decided.
2. **Option C on notifications?** The recommendation is no.
3. **Is an iPhone-only relay acceptable?** An iPad cannot relay for a Watch.
4. **Must a device be confirmed on a second screen?** The recommendation is to make that the
   documented path, with same-phone confirmation allowed and labelled.
