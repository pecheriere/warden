# Notifications

When an agent asks for access, warden tells the owner with a link to the
approval page. It tries Home Assistant first and falls back to ntfy when
Home Assistant errors, answers non-2xx, or does not answer within 5 seconds.
If both fail, the request ends in `error`.

A notification contains the agent, the target and user, the goal (truncated to
200 characters, with `…` appended when cut) and the approval link. It never
contains secrets. The approval link opens the passkey approval page, which is
only reachable over the tailnet.

## Home Assistant

Set `WARDEN_HA_WEBHOOK_URL` to the webhook URL, for example
`http://homeassistant.local:8123/api/webhook/<webhook_id>`. The webhook id is a
secret: warden redacts the URL in logs and errors and does not follow
redirects.

Warden POSTs JSON `{"title": "...", "message": "...", "url": "..."}`. Create an
automation that triggers on the webhook and forwards it to the phone:

```yaml
alias: Warden approval request
mode: queued
triggers:
  - trigger: webhook
    webhook_id: "<webhook_id>"
    allowed_methods:
      - POST
    local_only: true
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

`local_only: true` restricts the webhook to requests from the local network, so
the warden host must reach Home Assistant directly. Replace `<phone>` with your
device name as shown under `notify.` in Developer Tools, and `<webhook_id>` with
a long random value (for example `openssl rand -hex 24`).

## ntfy

Set `WARDEN_NTFY_URL` to the topic URL, for example
`https://ntfy.example.com/warden-<random>`, and optionally `WARDEN_NTFY_TOKEN`
for an access token (sent as `Authorization: Bearer ...`). Setting the
token without the URL is a configuration error.

Warden POSTs the message as the body with the headers `Title`, `Click` (the
approval link), `Priority: high` and `Tags: lock`. A title containing
non-ASCII characters is sent as an RFC 2047 encoded word
(`=?UTF-8?B?...?=`), which ntfy decodes. The message body is UTF-8 and needs no
encoding.

Use a hard-to-guess topic name, or a server with access control and a token
that can only publish to the topic. Subscribe to the topic in the ntfy app on
your phone.
