# Notifications

When an agent asks for access, warden tells the owner with a link to the
approval page. The channels to use are chosen at startup with `WARDEN_NOTIFY`,
a comma-separated list in priority order. warden tries the first channel; if
it errors, answers non-2xx, or does not answer within 5 seconds, it tries the
next one, and so on. The first channel that accepts wins. If every channel
fails, the request ends in `error`. The worst-case delay before the owner is
notified (or the request fails) is 5 s times the number of channels. The audit
log's `notified` entry names the channel that delivered the notification.

A notification contains the agent, the target and user, the goal (truncated to
200 characters, with `…` appended when cut) and the approval link. It never
contains secrets. The approval link opens the passkey approval page, which is
only reachable over the tailnet.

## Configuration

| Variable | Meaning |
|----------|---------|
| `WARDEN_NOTIFY` | Required. Enabled channels in priority order, for example `homeassistant,ntfy`. |
| `WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL` | Required when `homeassistant` is listed. |
| `WARDEN_NOTIFY_NTFY_URL` | Required when `ntfy` is listed. |
| `WARDEN_NOTIFY_NTFY_TOKEN` | Optional bearer token for ntfy. |

Home Assistant first, ntfy as the fallback:

```sh
WARDEN_NOTIFY=homeassistant,ntfy
WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL=https://ha.example.com/api/webhook/<webhook_id>
WARDEN_NOTIFY_NTFY_URL=https://ntfy.example.com/warden-<random>
```

Any single channel works on its own (`WARDEN_NOTIFY=ntfy`), and the order is
yours to choose (`ntfy,homeassistant`).

Startup refuses, with a message naming the variable:

- an unset or empty `WARDEN_NOTIFY`, an empty entry, an unknown channel name,
  a name with upper-case letters (channel names are lowercase) or a channel
  listed twice;
- a listed channel with a missing or invalid setting;
- a setting for a channel that is not listed (most likely a forgotten list
  entry);
- the variables of the earlier fixed wiring, `WARDEN_HA_WEBHOOK_URL`,
  `WARDEN_NTFY_URL` and `WARDEN_NTFY_TOKEN`. They are removed, not deprecated;
  the error names the replacement.

## Home Assistant

Name the channel `homeassistant` and set
`WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL` to the webhook URL, for example
`http://homeassistant.local:8123/api/webhook/<webhook_id>`. The webhook id is a
secret: warden redacts the URL in logs and errors and does not follow
redirects.

warden POSTs JSON `{"title": "...", "message": "...", "url": "..."}`. Create
an automation that triggers on the webhook and forwards it to the phone:

```yaml
alias: Warden approval request
mode: queued
triggers:
  - trigger: webhook
    webhook_id: "<webhook_id>"
    allowed_methods:
      - POST
    # false when warden reaches Home Assistant over the tailnet (see below).
    local_only: false
actions:
  - action: notify.mobile_app_<phone>
    data:
      title: "{{ trigger.json.title }}"
      message: "{{ trigger.json.message }}"
      data:
        # iOS: tapping the notification opens the approval page.
        url: "{{ trigger.json.url }}"
        # Android: same, via clickAction.
        clickAction: "{{ trigger.json.url }}"
        push:
          interruption-level: time-sensitive
```

Replace `<phone>` with your device name as shown under `notify.` in
Developer Tools, and `<webhook_id>` with a long random value (for example
`openssl rand -hex 24`).

**`local_only`.** With `local_only: true`, Home Assistant accepts the webhook
only from addresses it considers local (its LAN). A tailnet address is not
one of them, so if warden reaches Home Assistant over Tailscale, Home
Assistant refuses the call and the owner is never notified. Use
`local_only: true` only when warden reaches Home Assistant on its local
network; otherwise set it to `false`. Either way, anyone who can reach Home
Assistant and knows the webhook id can trigger the automation (to send a
fake notification, never to approve anything), so keep the id long, random
and secret, and keep Home Assistant off the internet.

Test the automation once, from the warden host and with the URL warden will
use, before relying on it. Home Assistant answers a webhook it refuses (or
does not know) as if it had accepted it, and only logs a warning in its own
log. warden then records the notification as delivered and does not try the
next channel: the owner simply never hears of the request.

## ntfy

Name the channel `ntfy` and set `WARDEN_NOTIFY_NTFY_URL` to the topic URL, for
example `https://ntfy.example.com/warden-<random>`, and optionally
`WARDEN_NOTIFY_NTFY_TOKEN` for an access token (sent as
`Authorization: Bearer ...`). The token is redacted in logs and debug output.

warden POSTs the message as the body with the headers `Title`, `Click` (the
approval link), `Priority: high` and `Tags: lock`. A title containing
non-ASCII characters is sent as an RFC 2047 encoded word (`=?UTF-8?B?...?=`),
which ntfy decodes. The message body is UTF-8 and needs no encoding.

Use a hard-to-guess topic name, or a server with access control and a token
that can only publish to the topic. Subscribe to the topic in the ntfy app on
your phone.

## Adding a channel

Channels are a compile-time registry (no plugins are loaded at runtime). A new
channel is one module plus its registration, in `crates/broker/src/notify/`:

1. Implement `Notifier` (`name()` and `ring()`) in its own module. `name()` is
   the channel's `ChannelKind` name, used in errors, logs and the audit log;
   `ring()` returns it on success.
2. Write a settings parser with validation. Settings come from
   `WARDEN_NOTIFY_<KIND>_*` variables: a missing required one is
   `ConfigError::Missing`, a bad value `ConfigError::Invalid` (never echo the
   value). Wrap anything secret in a redacting type (`SecretUrl`,
   `SecretString`) so `Debug` cannot leak it.
3. Register it in `channels.rs`: add a `ChannelKind` variant (name, variables)
   and a `ChannelSettings` variant (parse, build), and add the kind to
   `ChannelKind::ALL` (a unit test fails if you forget). The compiler lists
   every `match` that needs the new arm.
4. Keep secrets out of the payload: the doorbell carries the title, the
   truncated goal and the approval link only.
5. Use the shared HTTP client (`http_client()`): fixed connect and request
   timeouts, no redirects. Never add a configurable timeout; the chain also
   enforces 5 s per channel.
6. Never put a URL or response body in a `NotifyError`; use
   `NotifyError::request` and `check_status`. Error text reaches the audit log
   and must not leak webhook ids, and it is never echoed to agents.
7. Test it against a fake endpoint (wiremock) in
   `crates/broker/tests/notify.rs`, plus config parsing tests in
   `crates/broker/tests/agents.rs`, and document the channel on this page.
