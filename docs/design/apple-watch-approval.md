# Approving from an Apple Watch

**Status: proposed. Nothing here is implemented.** Today every grant needs a
passkey, on a page only the tailnet can reach, and
[the threat model](../threat-model.md) says so correctly. It changes only when
the code does. Tracking issue:
[#149](https://github.com/pecheriere/warden/issues/149).

## Where this ends up

**It can work, with a real cost.** A Watch app can hold a key in its Secure
Enclave, show a request, sign exactly what it showed, and send that to warden.
Apple's APIs allow all of it, and the signature is better than a passkey's at
proving what was approved.

**The hard problem is reaching warden, and it decides the design.** A Watch
cannot join a tailnet: the VPN APIs are [unavailable on
watchOS](#reaching-warden). So a tailnet-only design cannot work when the owner
is out with only a Watch. There are two honest choices:

1. **A new, small, public listener that accepts only signed requests** from
   enrolled devices. It works with the phone nearby, on a cellular Watch and on
   known Wi-Fi. It is the recommendation, and it is new attack surface.
2. **Tailnet only, relayed through the iPhone.** Nothing new is public, but the
   iPhone must be nearby with its tunnel up, and it stacks several behaviours
   nobody has tested. It answers "don't reach for my phone", not "I left my
   phone behind".

**No design works on a GPS-only Watch that is away from its phone and off known
Wi-Fi.** It has no network at all, so no push arrives either.

**What is not possible:** the side button double-click, and passkeys on the
Watch. A confirmation inside the app replaces both.

**What it does not fix:** it makes approving easier, and that is the point and
the risk. The reflex tap is [the top risk](../security-assessment.md). The
design below makes a reflex take three deliberate motions and limits what a Watch
can approve at all, but it cannot make the owner read.

**Worth saying plainly:** if the owner wants neither the public listener nor the
relay, the thing to do is nothing new. The existing ntfy and Home Assistant
doorbells already reach a Watch, and approving stays on the phone.

## What Apple allows

Checked on 2026-11-02 against Apple's documentation and the watchOS 27.2 SDK in
Xcode 27.2. Nothing here has run on a Watch.
**[Not confirmed]** marks what the sources do not settle.

"Typechecked" means a throwaway Swift file, outside this repository, was checked
with `swiftc -typecheck -target arm64-apple-watchos11.0`. That proves an API is
offered, not how it behaves.

### The side button and other confirmations

| Option | Answer | Source |
|---|---|---|
| Side button double-click | **No API found for a third-party Watch app.** The SDK mentions it in only two places: the Apple Pay sheet, and a deprecated Mac policy that asks the Watch to confirm. Apple does not state a ban; this is absence, from searching the SDK. | [PassKit](https://developer.apple.com/documentation/passkit/pkpaymentauthorizationcontroller), SDK headers `PKPaymentAuthorizationController.h`, `LAContext.h` |
| Companion authentication | An iPhone or Mac app can ask a "companion device" to authenticate (`deviceOwnerAuthenticationWithCompanion`, iOS 18, macOS 15). Unavailable on watchOS. It authenticates the iPhone or Mac app, so the key would not be on the Watch. **[Not confirmed]**: whether an iPhone's companion can be a Watch, or uses the side button. | SDK header `LAContext.h` |
| Double tap | **Yes, but it is dangerous here.** An app can make a button the scene's primary action. On a notification, the system "invokes the first nondestructive action". | [Enabling double tap](https://developer.apple.com/documentation/watchos-apps/enabling-double-tap), [actions on watchOS](https://developer.apple.com/documentation/watchos-apps/adding-actions-to-notifications-on-watchos) |
| Notification actions | **Yes.** Buttons on the long look. See below. | Same |
| App Intents | Available on watchOS 9 and later, with a policy that requires unlocking. Double tap also reaches widgets in the Smart Stack. A widget shows stale content and approves with one gesture, so it is not used. | [IntentAuthenticationPolicy](https://developer.apple.com/documentation/appintents/intentauthenticationpolicy), [double tap](https://developer.apple.com/documentation/watchos-apps/enabling-double-tap) |
| Confirmation in the app | **Yes.** Ordinary SwiftUI. This is what the design uses. | |

### Passkeys, the Secure Enclave and the wrist

- **Passkeys: no.** `ASAuthorizationPlatformPublicKeyCredentialProvider` and the
  security key provider list no watchOS. The platform provider is [explicitly
  unavailable](https://developer.apple.com/documentation/authenticationservices/asauthorizationplatformpublickeycredentialprovider)
  (typechecked: refused). So the Watch cannot be a WebAuthn authenticator.
- **Secure Enclave keys: yes.** CryptoKit's
  [`SecureEnclave.P256.Signing.PrivateKey`](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
  has been on watchOS since 6.0, and the form with access control and an
  `LAContext` since 9.0 (typechecked).
- **Wrist detection: yes.**
  [`deviceOwnerAuthenticationWithWristDetection`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithwristdetection)
  exists on watchOS 9 and later. There is no biometry on a Watch: the only
  factor is "the passcode was entered and it has stayed on the wrist".
- **Removing the passcode:** Apple says [items in the
  `WhenPasscodeSetThisDeviceOnly` class are
  deleted](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly),
  and never migrate to another device.
- **[Not confirmed]: the sources disagree on the wrist policy.** The SDK header
  `LAContext.h` says authentication is by passcode and "will also succeed" if the
  Watch has stayed on the wrist. The documentation page says evaluation fails if
  the Watch came off. Also unknown is whether signing with a key is held to this
  policy.
  An [unanswered 2018 forum post](https://developer.apple.com/forums/thread/111970)
  reports that `userPresence` did not protect a keychain item with Wrist
  Detection off. Test this first; it is the core of the theft answer.

### Notification actions

- **A tap can run code that signs and sends.** [By default the system launches
  the app in the
  background](https://developer.apple.com/documentation/watchos-apps/adding-actions-to-notifications-on-watchos)
  and calls its delegate.
- **Where it runs is the catch.** Foreground actions run on the device where they
  were selected. Background actions run "on the device that was the notification's
  target". So a push sent to the iPhone and forwarded to the Watch runs its
  background action **on the iPhone**, which has no key.
- **So the push must go straight to the Watch.** Direct pushes need watchOS 6 and
  a token from the Watch app, and ["only appear on Apple
  Watch"](https://developer.apple.com/documentation/watchos-apps/taking-advantage-of-notification-forwarding).
- **Forwarding has its own rules.** A push sent to the iPhone goes to the phone
  if it is unlocked with the screen on, otherwise to the Watch if on the wrist and
  unlocked, otherwise to the phone.
- **Time in the background is short.** Apple documents "[a few
  seconds](https://developer.apple.com/documentation/watchkit/background-execution)"
  for refresh tasks and [30
  seconds](https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app)
  for background notifications, and says [background URL sessions may be
  deferred](https://developer.apple.com/documentation/watchos-apps/making-background-requests).
  **[Not confirmed]**: the time a background action gets, and whether it can use
  a wrist-protected key. Apple warns only that [actions can arrive with the device
  locked](https://developer.apple.com/documentation/usernotifications/declaring-your-actionable-notification-types).
- **Result:** Approve always runs in the foreground, where the Watch can show the
  scope. Only Deny may try the background.

### Getting a push there

- **APNs from the broker works.** It needs [HTTP/2 to `api.push.apple.com` on 443
  or 2197, and a JWT signed with a `.p8`
  key](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns),
  [refreshed every 20 to 60
  minutes](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns).
- **Keys can be narrow.** A team-scoped key reaches every topic in the team. A
  topic-specific key is limited to named topics and one environment. Use that.
- **Egress:** a rule by address means [Apple's whole
  `17.0.0.0/8`](https://support.apple.com/en-us/102266). Port 2197 exists so that
  a firewall can allow APNs without allowing other HTTPS there.
- **Payload:** at most 4 KB. APNs is [best effort, may reorder, and stores one
  notification per bundle ID](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns).
- **Not on Apple's servers.** A push needs almost nothing in it. A [service
  extension](https://developer.apple.com/documentation/usernotifications/modifying-content-in-newly-delivered-notifications)
  could fetch or decrypt details on arrival. Its class lists watchOS 6, but the
  guide talks only about iOS. **[Not confirmed]** that it works on a Watch, and
  this design does not need it.

**Precedents.** Both projects shipped one app with one Apple key, so their users
go through a relay.

| Project | How it works | What the relay sees |
|---|---|---|
| [ntfy](https://docs.ntfy.sh/config/) | A self-hosted server sends a poll request to `upstream-base-url` (ntfy.sh). The phone wakes and fetches the message from the owner's server. Without it, delivery can take hours. | A message ID and a hash of the topic. Not the content. |
| [Home Assistant](https://contributors.home-assistant.io/companion/mobile-app-api/notifications/) | Posts to a `push_url`. The official apps use the project's own push service, at 500 notifications per device per day. An app can ask for a local WebSocket first. | The notification. |

### Reaching warden

| Question | Answer | Source |
|---|---|---|
| Can a Watch run a VPN? | **No.** `NEVPNManager`, `NETunnelProviderManager` and `NEPacketTunnelProvider` are marked unavailable on watchOS (typechecked: refused). | [NETunnelProviderManager](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager), SDK headers |
| Could an app embed Tailscale? | **No.** watchOS [blocks low-level networking](https://developer.apple.com/documentation/technotes/tn3135-low-level-networking-on-watchos) for ordinary apps, and BSD sockets never work. Only `URLSession`. | TN3135 |
| Is there a Tailscale client for Watch? | None found. **[Not confirmed]**: absence from a search. | |
| What routes does a Watch use? | [It tries the iPhone first, then known Wi-Fi, then cellular](https://developer.apple.com/documentation/watchos-apps/keeping-your-watchos-app-s-content-up-to-date). | Apple |
| With the phone nearby, does Watch traffic enter the phone's Tailscale tunnel? | **[Not confirmed]**. Apple does not say; the only sources are VPN vendors' blogs and forum posts that disagree. One test on real hardware settles it. | |
| Can the iPhone reach the tailnet from the background? | Probably. An ordinary app's HTTPS follows the system's routes when the tunnel is up. Tailscale's [VPN On Demand](https://tailscale.com/docs/features/client/ios-vpn-on-demand) can start it for `*.ts.net` names, only under its "Do Nothing" rule. **[Not confirmed]**: that this fires for a background app's request. | Tailscale |
| WatchConnectivity? | The Watch can message the iPhone app, and [iOS launches it if it isn't running](https://developer.apple.com/documentation/watchconnectivity/wcsession) (SDK header `WCSession.h`). Reachability needs the phone to have been unlocked once since boot. Apple calls it [an opportunistic optimization, not a primary path](https://developer.apple.com/documentation/watchos-apps/keeping-your-watchos-app-s-content-up-to-date). | Apple |

**What that means, assuming the push and network behave as documented:**

| Where the owner is | Public listener | Tailnet, relayed by iPhone |
|---|---|---|
| Phone in a pocket, online | Works | Works if the tunnel is up and the app wakes in time |
| Phone left behind, Watch on cellular | Works | **No** |
| Phone left behind, Watch on known Wi-Fi | Works | **No** |
| Phone left behind, GPS-only Watch, no known Wi-Fi | **No** (no network) | **No** |
| Phone nearby with Bluetooth but no internet | [Not confirmed]: failing over to the Watch's own network | **No** |

### Distribution

| Route | What it takes | Limits |
|---|---|---|
| Install from Xcode or an exported `.ipa` | A paid membership: [push is not in the free tier](https://developer.apple.com/help/account/reference/supported-capabilities-ios). [Registered devices and Developer Mode](https://developer.apple.com/documentation/xcode/distributing-your-app-to-registered-devices). | Limited devices per year. **[Not confirmed]**: profile lifetime. Uses the sandbox APNs. |
| TestFlight, internal | [Up to 100 App Store Connect users](https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview). | **Builds stop working after 90 days.** The page implies no review for internal testers but does not say so. **[Not confirmed]**: which APNs environment it uses. |
| App Store | [A working demo account with the backend live for review](https://developer.apple.com/app-store/review/guidelines/), so a demo broker. | One bundle means one push key, so **someone has to run a relay**. Nothing in the part of the guidelines read here addresses apps that need the user's own server; **[not confirmed]** whether review accepts one. |

**Why one shared App Store app is the wrong start.** A push key can send to every
user of its topic, so it cannot be handed to every broker. A relay is a service
that someone keeps running forever. And whoever publishes the app can ship an
update that signs without showing anything, because a key on a wrist needs no
prompt. For a security tool, each owner building their own app is the honest
trust model.

**What "each owner has their own" means:** a paid Apple Developer membership, an
App ID for the iPhone and Watch apps with push on, a topic-specific `.p8`, and a
new TestFlight build every 90 days. The repository takes the team and bundle ID
from one config file. That suits people who already have Xcode, and only them. If
others ask for it, an App Store app and a relay can follow, and the design does
not block that, since the push carries nothing.

## The design

```text
agent ──request──▶ warden ──"a request is waiting"──▶ APNs ──▶ Watch
                     ▲                                          │ owner taps Review
                     │        signed requests over HTTPS        │
                     └──── device listener ◀── public ingress ◀─┘

iPhone: only enrolls the Watch, through the existing passkey page.
```

- **The Watch app** holds the key, shows the request and signs the decision.
- **The iPhone app** is one screen, "Add this Watch", and one button, "Open
  warden". It has no key, no token and no network identity of its own. A request
  too large for the Watch is read on the existing approval page, which the existing
  notifiers already link to.
- **warden** stores the public key and the push token.

### Enrollment

No code and no public route. The owner's passkey page is the only thing that
writes a device.

1. In the iPhone app, the owner taps **Add this Watch**. Over WatchConnectivity,
   the Watch creates a key (`.privateKeyUsage` and a passcode constraint, in the
   `WhenPasscodeSetThisDeviceOnly` class), registers for push, and returns the
   public key and push token. It shows a **check code**: 60 bits of the key's
   SHA-256, such as `ABCD-EFGH-JKLM`.
2. The iPhone app opens Safari at
   `https://warden.example.ts.net/devices/add#key=…&token=…`. A fragment is not
   sent to any server, so only the page's script reads it.
3. That page sits behind Tailscale and the owner's login, like every approval
   page. It shows the check code. The owner compares it with the Watch and taps
   **Add Watch**, which runs a passkey ceremony bound to the hash of that key.
4. warden stores the device, audits `device_enrolled`, and rings the existing
   notifiers: "A Watch was added". The page links back to the app with the device
   ID and the device listener's URL, which the iPhone passes to the Watch.

**Why the check code:** a compromised iPhone could substitute its own key. The
Watch shows the code for the key it really made, and the page shows the code for
the key it was given. Passkey ceremonies get a new kind, so a device enrollment
assertion cannot complete an approval, or the reverse.

### What the Watch signs

A P-256 ECDSA signature over SHA-256, from the Secure Enclave:

```text
warden-device-decision-v1
audience: https://warden-device.example.ts.net
device: <device id>
decision: approve | deny
request: <request id>
fingerprint: <full request fingerprint>
destination: <destination digest>
window: 15m | 30m | none
display: <SHA-256 of the exact bytes the Watch displayed>
challenge: <256 random bits from the broker>
```

- **The broker sends** the display (UTF-8 text, rendered verbatim, never as
  Markdown) and a challenge. It keeps, in memory and for 120 s, the challenge with
  the request, device, display digest, fingerprint, destination digest and window.
- **The Watch hashes what it was given** and signs this message.
- **The body carries only** the challenge ID, the decision and the signature. The
  broker rebuilds the message from its own state, so a different display fails
  verification.
- **No replay.** A challenge is single use, consumed before verification as
  ceremonies are today, and it dies with its request. Deny and approve use the same
  message.
- **Separate names.** Other calls (fetching the inbox, updating the push token) are
  signed as `warden-device-request-v1` with a timestamp and a nonce, using the
  agent protocol's replay rules. A signature for one cannot serve as the other.

The broker then repeats every check `approve_finish` makes: still pending,
fingerprint, destination digest and policy read fresh. It adds the Watch limits
below, and audits the signed message and signature with the device ID.

### How this differs from a passkey

| | Passkey | Watch |
|---|---|---|
| **Who can reach it** | The tailnet and the owner's login | The public internet, up to the signature check |
| **Authentication** | Biometry or PIN for each approval | The passcode, once, then staying on the wrist. **Weaker: no check per approval** |
| **Key** | May sync across the owner's devices | Stays in one Secure Enclave. **Stronger** |
| **What it signs** | A random challenge; the link to the request is [state on the broker](../threat-model.md#approval-binding) | The exact text shown, and the request. **Stronger** |
| **Can approve** | Any request, for any allowed window | Only what the limits below allow |
| **Prompt** | The page, then the system's prompt | Three deliberate steps |
| **Clone check** | Signature counter | None; the key cannot be exported |

The passkey stays required for enrolling a device. Revoking a device or a grant
stays possible without one, as revoking a grant is today. **A Watch can never
enroll another device or a passkey.**

### What a stolen device can do

| Device and state | What the thief gets |
|---|---|
| Watch, locked or taken off the wrist | Nothing, as long as the wrist test in phase 0 passes. The push text says nothing. |
| Watch, with the passcode known | Can read pending requests, approve those the limits allow, and deny anything, until revoked. **Gets no access itself:** a grant goes to the agent that asked, and no credential ever reaches the Watch. To gain anything, the thief also needs an agent asking for something useful at that moment. |
| Watch with Wrist Detection off | Apple says it [stops locking on removal](https://support.apple.com/en-bh/guide/security/secc7d85209d/web). warden cannot tell. The app refuses to enroll if the policy cannot be evaluated, but behaviour afterwards is a phase 0 question. |
| iPhone, in this design | No key and no token, so nothing new. What it already holds is the passkey, a risk that exists today. |

**Revoking.** A **Devices** page lists each device with its last use, and has a
Revoke button that needs the owner's identity and no passkey. `warden-server
device revoke <id>` does it from the host. Because revoking may come from another
process, each check reads the database, and if that fails, the request is refused.
A revoke drops the device's challenges at the next check, and is audited and
announced. Grants already made stay until they end: revoke them on the grants page,
as the page tells the owner.

**Find My's erase is not a revocation** warden can see. Revoke as well.

### The screen, and the reflex tap

**Order on the Watch:**

1. **Scope and window, from warden:** `GET HEAD`, `home-api /status/`, `15 min`, or
   `ssh deploy@build-agent`, `15 min`. This uses what warden knows.
2. **Agent name:** `build-agent`. Requests have no session label today, and v1 does
   not add one.
3. **"The agent says:"** and the goal, cut to about 140 characters with "more on
   your phone". It comes last, and it is labelled as untrusted.
4. **Fingerprint**, short, for comparing if someone is at the workstation.
5. **Deny**, then **Hold to approve**.

**What stands between a reflex and an approval:**

- **No Approve on the notification.** Its buttons are **Review** (foreground) and
  **Deny** (destructive). Apple's double tap runs the first nondestructive action,
  so if Approve were first, a pinch would approve. Here it opens the review screen.
- **The approve control is below the fold,** so the owner scrolls past the scope.
  The app sets no `handGestureShortcut`, so double tap can only scroll.
- **Hold for two seconds.** A press, not a tap.
- **The broker refuses a decision within 3 s of the challenge.** A check on the
  server, not only the app's goodwill.
- **A budget:** by default, three Watch approvals per rolling hour, after which the
  Watch offers Deny only. Rapid approving is the pattern risk 1 describes, and
  [risk 13](../security-assessment.md) makes floods possible.

The push carries no name and no goal, so the owner cannot decide from the short
look. That loses a glance at the wrist telling them whether it matters. It is
deliberate, and it also keeps the details off Apple's servers.

### Should a Watch approve only low-risk requests?

The owner has not settled this. There is a real trade.

| Option | What it allows | What is lost |
|---|---|---|
| **Read-only API only** (the issue's starting point) | `GET` and `HEAD` API grants, short windows | **Most of the value.** warden can prove "read-only" only for API methods ([`is_read_only`](../../crates/proto/src/lib.rs)). An SSH account is a shell, whatever its name. [As the advance-approval design notes](advance-approval.md), most of what stops a coding agent is a push or a shell command, and those would still need the phone. |
| **No limit** | Everything the passkey can | **The safety margin.** A reflex or a thief with the passcode gets a 4 hour shell or write access, behind a weaker check than a passkey's. |
| **Opt-in per item (recommended)** | Items that name a Watch window | **Some simplicity, and a judgement call.** The owner must mark each item, and each SSH item is a bet that the account is narrow. |

**The recommendation:** a new optional item field, `watch_max_window`, with `15m`
or `30m`. Absent means phone only.

- A read-only API request on such an item can be approved.
- An SSH request on such an item can be approved. The owner is saying "this account
  is narrow enough". warden cannot check that, and the docs must say so.
- **An API request with writing methods is phone-only in v1**, whatever the item
  says. warden can see that one for certain.
- **Deny always works**, for any request.
- A Watch approval uses the lesser of the requested window and `watch_max_window`,
  and the screen shows the result.

Keeping it in the vault item means it sits with `max_window`, is read fresh at each
decision, and is changed by whoever can already change scope. A switch on the server
would be coarser, and could not separate two SSH accounts. For anything else, the
Watch says "open on your phone".

### Changes to the broker

| Area | Change |
|---|---|
| **New `device` module** | `crates/broker/src/device/`: store, API, signature and challenge handling. `approval/mod.rs` is large, so this goes in its own module. |
| **Device listener** | `WARDEN_DEVICE_ADDR`, off unless set. Routes: `POST /device/v1/inbox`, `/review`, `/decide`, `/token`. It serves nothing else, ignores every identity header, and never shares a router with the other two listeners. |
| **Limits on that listener** | The work [the #75 design](owner-identity.md#the-internet) says a public listener needs: a connection limit, a small concurrency limit on signature checks, 4 KB bodies, read timeouts, and a look-up of the device ID before any signature work. No per-request logging: counters and an occasional summary. Audit only decisions and device changes. |
| **Approval page** | `/devices`, `/devices/add`, enroll and revoke, following `docs/design-language.md`, with a new ceremony kind. |
| **Sharing the approval path** | Move grant-building out of `approve_finish`, so that both paths run the same checks and make the same grant. Add a way to mark a request approved by ID and device. It must not rotate the approval token, as `/pending/{id}/open` does, or it would break a link open on the phone. |
| **Database** | A new migration: devices (public key, push token, label, created, last used, revoked). Never edit a released one. |
| **Audit** | `device_enrolled`, `device_revoked`, and `approved` with the device ID, signed message and signature. |
| **Push** | `notify/apns.rs`: ES256 JWT with the `p256` already in the tree, plus `WARDEN_APNS_KEY_FILE`, `_KEY_ID`, `_TEAM_ID`, `_TOPIC`, `_ENVIRONMENT`. APNs needs HTTP/2, and the workspace's `reqwest` entry does not list that feature today, so add it, keeping the no-decompression guard green. |
| **Not in the notifier chain** | APNs rings alongside the others, not as a fallback. The chain stops at the first success, and APNs accepting a push says nothing about arrival. The existing doorbell stays the safety net. |
| **`warden-server doctor`** | Report the listener, enrolled devices and an unusable APNs key. |

**The push:**

```json
{"aps": {"alert": {"title": "warden", "body": "A request is waiting"},
         "category": "WARDEN_REQUEST", "sound": "default"}}
```

No request ID, name or goal. Priority 10, with `apns-expiration` set to the
request's expiry. Opening the app fetches the inbox over the signed channel. **Apple
learns when requests happen, and which device and app they are for.** It learns
nothing else.

**Exposing the listener.** [`docs/deployment.md`](../deployment.md) says never to
publish warden's listeners with Funnel, and that rule stays: the warden host keeps
no `funnel` attribute. The suggested layout is **a separate small Tailscale node**,
an extra container, that runs Funnel and can reach only warden's device port under
the tailnet policy. [The Funnel relay cannot read
traffic](https://tailscale.com/docs/features/tailscale-funnel), and TLS ends on that
node, which the owner runs. Funnel is in beta and has fixed bandwidth limits, which
this traffic will not notice. Any HTTPS reverse proxy works too, since warden trusts
nothing it adds. **[Not confirmed]**: this layout has not been run.

### If something is compromised

| Who | What they can do | What they cannot |
|---|---|---|
| **iPhone** | Withhold enrollment. Substitute a key at enrollment, which the check code catches. Its OS carries the Watch's traffic when nearby. If its passkey is compromised, that is today's risk. | **Show the Watch one request and get a signature for another.** The Watch signs a hash of what it displayed, and the broker compares it with what it sent. A forged display fails. |
| **The proxy or ingress** | See request details if it ends TLS. Block traffic. Tell the Watch "approved" when nothing happened. | The same swap. This closes, for Watch approvals, the [TLS-terminator swap](owner-identity.md#one-limit-that-is-easy-to-miss-the-tls-terminator-can-swap-an-approval) that the #75 design warns of for passkeys. |
| **The broker** | Everything, as [today](../threat-model.md#in-short): it can issue grants with no signature at all. It can show false text on the Watch and get a real signature over that false text. Push noise, to train a reflex. | Forge a signature. If public keys are kept off the host and the audit log is shipped, a claimed Watch approval can be checked independently. |
| **APNs or the push key** | Spam the Watch, to train a reflex. Withhold pushes. | Approve anything or learn details. The app never trusts a push: it fetches. Revoke a stolen key at Apple. |
| **Anyone on the internet** | Reach the listener and burn a slice of CPU. Learn that something is listening, since the name is in public DNS. | Read a request, or approve. A flood costs Watch approval. The passkey path is on another listener, and survives unless the host itself is overwhelmed. |
| **The app's publisher** | Ship an update that signs silently, within the limits. This is why each owner builds their own. | Go beyond the limits, which the broker enforces. |

**Related to [#117](https://github.com/pecheriere/warden/issues/117):** [the proposed
design for that issue](https://github.com/pecheriere/warden/pull/148) found that a
passkey challenge can be derived from the request, but that the browser and page
still decide what the owner sees. Here warden writes both ends, so the Watch signs a
hash of what it displayed, with no WebAuthn constraints. A compromised broker can
still show false text, so the evidence is limited as that design says: it is useful
only with the keys off the host.

## Hard parts

| Part | Rating | Why |
|---|---|---|
| **The public listener** | **Hard: a decision and a security review** | New internet-facing code in a security broker, and a change to a standing rule. The code is small. The argument is what matters. |
| **The wrist check on a real key** | **Hard: unknown** | Apple's sources disagree. If a key cannot be held to it, the theft answer changes. |
| **Reliability** | **Medium: unknown** | Push and `URLSession` across three routes, on one device, with the only evidence being Apple's description. The phone stays the fallback, so a failure costs time, not safety. |
| **The reflex tap** | **Medium: cannot be fully solved** | The measures make it harder. Only the owner can read. |
| **Maintaining a second app** | **Medium: ongoing** | Xcode and watchOS move every year, and builds expire every 90 days. It is a real cost for a small project. |
| **APNs sender** | Easy | One HTTP/2 POST, a JWT and an error table. |
| **Enrollment** | Easy to medium | Passes through three devices, but uses a pattern warden already has. |
| **Signature and challenge** | Easy | The same shape as passkey ceremonies, and simpler. |
| **Screen and hold button** | Easy | SwiftUI. |

## Where the code lives, and how big it is

**A separate public repository for the Swift code**, such as
`pecheriere/warden-apple`, with its own macOS CI. Swift has a different toolchain and
release pace, and macOS runners shouldn't slow the broker's CI. CI holds no signing
keys and uploads nothing, since each owner signs their own build.

**This repository keeps** the broker code and `docs/device-protocol.md`, with test
vectors for the signed messages checked in `crates/proto`, as the agent protocol's
are. The Swift repository copies those vectors at a pinned commit and tests its
signing against them. warden advertises `warden-device-v1`, so a mismatch fails
plainly.

Sizes are rough estimates, not measurements:

| Phase | What | Size |
|---|---|---|
| **0. Hardware spike** | A throwaway app on a real Watch answers the list below. **Do nothing else until this passes.** | 1 to 2 days, with the Watch |
| **1. Threat model and protocol** | `docs/threat-model.md` gains a labelled "planned" section (below), plus the protocol document and test vectors. | 300 lines of docs |
| **2. Broker** | Device store, enrollment page, listener and limits, decisions and audit, doctor, docs. | 1,500 to 2,000 lines of Rust with tests |
| **3. Apps** | Watch app, then iPhone app. | 600 to 900 and 150 to 250 lines of Swift |
| **4. Push** | APNs sender and deployment docs. | 300 lines of Rust |
| **5. Use it** | TestFlight, for a month. Read the audit log: if the owner never denies from the Watch, the reflex problem is real. Decide then whether the limits move. | Time |

### What the threat model must gain

The issue requires this before anything is built, so it is phase 1. This pull request
leaves the file alone, as it describes what exists.

- **In short:** "every grant needs the owner's passkey" gains an exception, for items
  marked for Watch approval, with the Watch's weaker check.
- **Actors and trust:** add rows for the Watch, the iPhone app, APNs, and the public
  ingress.
- **Anti-goals:** "an approval is forged, replayed…" gains the signed message. "warden
  becomes the easiest way into the network" gains the device listener, and "listens
  only where Serve can reach it" no longer covers everything.
- **Approval binding:** a section on what the signature covers, and what the broker
  rebuilds.
- **Authentication of callers:** the device listener's routes and limits.
- **Accepted residual risks:** a stolen Watch with its passcode, no per-approval check,
  flooding, and the opt-in on SSH items being a judgement warden cannot check.
- **Deployment assumptions:** the ingress node, and that the warden host still has no
  Funnel.

## What could not be settled without hardware

Only phase 0 can answer these. A failure in the first two changes the design.

1. **Wrist and key.** On a real Watch: does signing with a passcode-constrained key
   and a wrist-policy `LAContext` go through on the wrist, and fail after taking it
   off? With Wrist Detection off? With the passcode removed, is the key gone? Which
   access control flag is right?
2. **Network.** Does `URLSession` reach a public HTTPS host with the phone locked in a
   pocket, phone left behind on Wi-Fi, and on cellular? With the phone on Bluetooth but
   offline?
3. **The relay option.** Does Watch traffic through the phone reach a tailnet name? If
   it does, tailnet-only needs no WatchConnectivity relay when the phone is near, which
   makes option 2 much cheaper.
4. **Direct push.** Does it arrive in the same situations, how quickly, and on which
   models? Does the Watch app need to be installed independently of the iPhone app?
5. **Background Deny.** Can a background action use the key and finish its request? If
   not, Deny opens the app, which is still fine.
6. **Fit and feel.** Does it fit a small Watch? Does the hold feel deliberate, or
   annoying enough to go unused?
7. **Double tap on the long look**, on a Series 9 or Ultra 2: does it really open
   Review?

Which Watch the owner has also matters: only a cellular model is independent once away
from known Wi-Fi.

## Alternatives rejected

- **Side button double-click.** No API. The Apple Pay sheet is for payments, and
  dressing an approval up as one would mislead the person reading it.
- **Passkeys on the Watch.** The APIs are unavailable.
- **A passkey on the iPhone, confirmed on the Watch.** The companion policy, or a
  forwarded notification with a background action. The key stays on the phone, which
  must be nearby, and a compromised phone signs anything it likes. It is a nicer phone
  prompt, not Watch approval.
- **Approve as a notification button, or inside the long look.** The most convenient
  and exactly the reflex tap. A pinch could approve, and nothing would have fetched a
  fresh challenge.
- **A Smart Stack widget or App Intent.** The same problem, with stale content.
- **A mailbox relay, with no inbound port.** The broker polls a store that the Watch
  posts signed decisions to, ntfy included. Elegant, and the broker stays closed. But
  someone has to run a second public service, with request details encrypted to the
  Watch, and a broker that must poll. Worth revisiting if the owner refuses the
  listener but wants to leave the phone behind.
- **The full approval listener on the internet.** [#75's design](owner-identity.md#the-internet)
  already declines this. This design exposes four signed routes instead.
- **Tailscale inside the iPhone app.** It would run only while the app runs, and would
  add a second tailnet identity for no gain over the Tailscale app.
- **Watch-only, no iPhone app.** Apple allows it, and it would be simpler to ship. But
  typing a URL on a Watch is painful, and the passkey ceremony needs the phone anyway.

## Decisions for the owner

1. **The public listener, or tailnet relayed through the iPhone?** This is the main one.
   The recommendation is the public listener behind a separate ingress node, because it
   is one code path and it does what the issue asks. It relaxes a rule warden has held
   so far: nothing public. If that is not acceptable, the relay gives up "phone left
   behind". If neither is, keep approving on the phone.
2. **Which Watch?** A GPS-only Watch needs the phone or known Wi-Fi in any design, and
   then option 1's main benefit is smaller.
3. **What may a Watch approve?** The recommendation is opt-in per item as above,
   including SSH on items the owner marks. The stricter choice is read-only API only.
4. **A separate repository?** The recommendation is yes. Creating it, and its settings,
   is yours.
5. **Accepting the upkeep?** A second app, a push key, and rebuilding every 90 days. If
   that is too much for how often the Watch would be used, this is the point to stop.
