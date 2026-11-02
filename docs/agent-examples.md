# Examples

Two common uses, end to end: what the owner sets up, then what the agent runs.
Both use the agent `build-agent`, already enrolled and logged in
([Agent usage](agent-usage.md#one-time-setup)). All names are examples.

Contents:

- [An SSH deployment](#an-ssh-deployment)
- [An API call](#an-api-call)

## An SSH deployment

The agent deploys a release to `web-01`. It can run one deploy script as root
and nothing else that needs root.

### What the owner sets up

1. **The account, the CA and sshd on `web-01`**, as in
   [the recommended setup](ssh-targets.md#the-recommended-setup-one-user-per-agent):
   an account `build-agent` that logs in only with a warden certificate for the
   principal `warden:web-01:build-agent`.

2. **Only what the deployment needs.** Install `/usr/local/bin/deploy-app`,
   owned by root and writable only by root, and allow that one command in
   `/etc/sudoers.d/build-agent`:

   ```
   build-agent ALL=(root) NOPASSWD: /usr/local/bin/deploy-app
   ```

3. **The target's item** in the `Warden` vault (category Server, tag
   `warden:ssh-target`, title `web-01`, see
   [the fields](1password-items.md#ssh-target)):

   ```
   address     web-01.example.com
   mode        cert
   users       build-agent
   max_window  30m
   host_keys   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... root@web-01
   ```

A `max_window` of `30m` means a request for longer is refused, whatever the
goal says.

### What the agent runs

Request access right before the deployment:

```sh
warden request ssh web-01 --user build-agent --for 15m \
  --goal "deploy release v1.4.2 to web-01 for issue #128: run deploy-app, check the service"
```

While it waits, it prints this on stderr. The agent tells the owner the
fingerprint, and the approval page shows the same one:

```
request 0b8f4c1e…, fingerprint b65b-9812-eb72 — waiting for approval…
```

The owner approves on their phone with a passkey, and the agent gets this on
stdout:

```
approved: grant 0f3a…e1 until 2026-11-01 21:15:00 CET
```

It deploys, then checks the result. `warden ssh` exits with ssh's own code:

```sh
warden ssh web-01 -- sudo /usr/local/bin/deploy-app v1.4.2
warden ssh web-01 -- systemctl is-active app
```

Then it revokes the grant at once, also if the deployment failed:

```sh
warden revoke <grant-id>
```

The certificate it already holds stays valid on the host until the window ends
([why](ssh-targets.md#revocation-and-certificates)), which is why the window
should be short. A session already open keeps running even after that, so end it
when the work is done.

## An API call

The agent reads a thermostat's state from a home automation API, and then sets
it back. It never sees the API's token: warden adds it to each call.

### What the owner sets up

The secret's item in the `Warden` vault (category API Credential, tag
`warden:api-secret`, title `home-api`, see
[the fields](1password-items.md#api-secret)):

```
website      https://home.example.com
credential   ••••••••••••••••
max_window   30m
methods      GET, POST
path_prefix  /api/
```

warden sends the secret only to that website, under `/api/`, as
`Authorization: Bearer <credential>`. Each request can only narrow this.

### What the agent runs: reading

A request without `--methods` is read-only, so ask for that first, under the
narrowest path that covers the question:

```sh
warden request api home-api --path /api/states/ --for 15m \
  --goal "read the thermostat state to find why automation 12 did not fire (issue #57)"
```

After the owner approves, stdout shows the grant and its scope:

```
approved: grant 7c21…9a until 2026-11-01 21:15:00 CET
scope: read-only; methods GET; https://home.example.com/api/states/
```

The call goes through the broker. `--fail` makes an upstream status of 400 or
more exit 22, with the body still written to stdout:

```sh
warden http home-api GET https://home.example.com/api/states/climate.living_room --fail
```

If the upstream's response echoes the secret, warden replaces it with
`[REDACTED]`. When the agent has its answer, it revokes the grant:

```sh
warden revoke <grant-id>
```

### What the agent runs: changing something

If the task then needs a change, the agent asks for that separately, naming
only the method it will use, and says in the goal what it will change. The
owner sees **Can modify: POST** on the approval page:

```sh
warden request api home-api --methods POST --path /api/services/climate/ --for 15m \
  --goal "set the living room thermostat back to 19 °C after the automation 12 fix (issue #57)"
```

```sh
warden http home-api POST https://home.example.com/api/services/climate/set_temperature \
  -H 'Content-Type: application/json' \
  -d '{"entity_id":"climate.living_room","temperature":19}' --fail
```

Then it revokes that grant too, with the id `warden request` printed:

```sh
warden revoke <grant-id>
```

### If something else happens

While it holds the read-only grant, a call that the grant does not cover stops
before it reaches the broker, and exits 5:

```sh
warden http home-api DELETE https://home.example.com/api/states/climate.living_room
```

```
warden: no active grant for home-api allows DELETE /api/states/climate.living_room. If the task needs it, ask the owner with: warden request api home-api --methods DELETE --for <window> --goal <goal> (window: the shortest of 15m, 30m, 1h or 4h that covers the work; goal: what you will do and why)
```

Here the task does not need it, so the agent stops there. The broker would
refuse that request anyway, since the item does not list `DELETE`. If the owner
denies a request, `warden request` exits 2 and the agent asks them what to
change; [the exit codes](agent-usage.md#exit-codes) cover the rest.
