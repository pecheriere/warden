# Local demo

`warden-demo` runs a throwaway warden on one machine, so you can see the idea
work before you set up a deployment: an agent asks for access, you approve with
a passkey in a browser, the agent uses the grant, and the audit log shows it.

**It is not secure for real use.** Everyone on the machine counts as the owner,
and it serves plain HTTP on loopback. Do not put real secrets near it. A real
deployment is described in [deployment.md](deployment.md).

## Get it

You need a browser that can create a passkey, and one of these two ways to get
the binaries. There is no Docker version: reaching a container from the browser
means listening on something other than loopback inside it, which the demo
refuses.

### With the release binaries

Releases after v0.9.0 attach `warden-demo-<version>-<platform>.tar.gz` for macOS
arm64, Linux amd64 and Linux arm64, next to the `warden` CLI. Pick a release that
lists them on the [releases page](https://github.com/pecheriere/warden/releases).
The name, a `NOT-FOR-REAL-USE.txt` in the archive and the program's own output
all say that it is a demo. It is attested and signed like the other files, so you
can [verify where it came from](verifying-releases.md), which says nothing about
whether it is safe for real use: it is not.

Checking the attestation needs a logged-in [`gh`](https://cli.github.com/). In a
first terminal:

```sh
version=x.y.z         # the release you picked
platform=linux-amd64  # or linux-arm64, macos-arm64
base="https://github.com/pecheriere/warden/releases/download/v$version"
mkdir warden-try && cd warden-try
for name in warden-demo warden; do
  file="$name-$version-$platform.tar.gz"
  curl -fLO "$base/$file"
  gh attestation verify "$file" --repo pecheriere/warden \
    --signer-workflow pecheriere/warden/.github/workflows/release.yml \
    --source-ref "refs/tags/v$version"
  tar -xzf "$file" --strip-components=1
done
./warden-demo
```

On macOS, download with `curl` as above rather than a browser: the binaries are
not notarized, and macOS may block one that a browser downloaded. On a minimal
Linux system, install the `ca-certificates` package: the `warden` CLI refuses to
start without the system's CA certificates.

### From source

- Rust, through [rustup](https://rustup.rs): the repository pins its version,
  and rustup installs that for you.
- A C toolchain and the OpenSSL headers, because the broker links OpenSSL. On
  Debian or Ubuntu: `sudo apt install build-essential pkg-config libssl-dev`.
  Without the headers, add `--features warden-broker/vendored-openssl` to the
  build command, which also needs `perl` and `make`.
- The first build takes a few minutes.

In a first terminal:

```sh
git clone https://github.com/pecheriere/warden && cd warden
cargo build --locked -p warden-demo -p warden-broker-cli
target/debug/warden-demo
```

## Run it

The demo prints these steps with the real ports, paths and enrollment code. The
ports change on every run, and it names the `warden` beside it, or the one on your
`PATH` if there is none beside it. Use what it prints where these steps say
`warden`.

1. **Enroll a passkey.** Open the printed `http://localhost:<port>/enroll`,
   enter the printed code and any name. Use `localhost`, as printed: `WebAuthn`
   does not work on an IP address.

2. **Be the agent.** In a second terminal:

   ```sh
   source '<the printed path>/agent.env'
   warden request api demo-api --for 15m --goal "try the warden demo"
   ```

   It waits for your decision, and the first terminal prints an approval link
   where a real server would notify your phone. `agent.env` points the CLI at
   the temporary directory, so a real warden configuration on this machine is
   neither used nor changed, and the Keychain is not touched. Close this
   terminal when you are done, because those settings stay in its environment.

3. **Approve.** Open the link, check the goal and the fingerprint against what
   the agent printed, and approve with your passkey. Then, as the agent:

   ```sh
   warden http demo-api GET https://localhost:<port>/v1/hello
   ```

   The answer shows `"authorization_received": "[REDACTED]"`. The demo API
   really received the token and echoed it, and the broker removed it before
   the agent could see it. Calling before the approval, or with `POST`, is
   refused.

4. **Read the audit log.**

   ```sh
   cat "$WARDEN_DEMO_DIR/audit.jsonl"
   ```

   The approval UI's `/history` and `/grants` pages show the same request.

5. **Stop it** with Ctrl-C in the first terminal. It verifies the audit log's
   hash chain and deletes the temporary directory.

The passkey stays with your authenticator, listed under `localhost`, and is
useless afterwards: delete it from your password manager. To avoid creating one,
use a virtual authenticator from Chrome's DevTools (More tools, WebAuthn). If
the enrollment code expires after its 10 minutes, restart the demo.

## What is real and what is not

The routers, approval pages, passkey ceremonies, request lifecycle, proxy,
redaction and audit log are the broker's own code, and the agent is the real
`warden` CLI. No check is switched off. Three things a deployment gets from its
environment are replaced, in the `warden-demo` crate only:

| In a deployment | In the demo |
|---|---|
| Tailscale Serve says who is calling. | A request addressed to the demo's own `localhost:<port>` or `127.0.0.1:<port>` is the owner. Any other `Host` has no identity, which keeps out web pages using DNS rebinding. |
| `WARDEN_PUBLIC_URL` is https, on a real name. | `http://localhost:<port>/`, which browsers treat as a secure context. |
| 1Password holds the policy and the secrets. | One API secret in memory, generated at startup, for a local HTTPS API with a throwaway pinned CA. |

Notifications are printed in the terminal instead of sent.

## What it does not show

- **SSH.** There are no SSH targets, certificates or relay sessions, only proxy
  mode.
- **The separation that makes warden safe.** In a deployment, the approval page
  is reachable only from your phone, so a prompt-injected agent cannot put an
  approval in front of you on the machine it controls. Here everything is on one
  machine, and the agent could open the page itself. It would still need your
  passkey.
- **Tailscale identity, 1Password, notification channels, key-signed agents**
  (the demo uses a bearer key), hardened containers, restarts and backups.

## Why it cannot weaken a real deployment

`warden-server` gains no setting, flag or code path for this. The crate depends
on the broker, never the reverse, and passes its stand-ins through the broker's
existing `IdentitySource`, `SecretBackend` and `Notifier` traits. The real
server still refuses `http://localhost` as `WARDEN_PUBLIC_URL`, and always uses
Tailscale Serve's identity.

`warden-demo` takes no options and reads no `WARDEN_*` variable, so it cannot be
pointed at another address. `scripts/check-demo-not-shipped.sh` runs in CI and
fails if `warden-server` or `warden` links the demo or the testkit, if the demo
enables the testkit, if the broker mentions the demo or gains another identity
source, if the Dockerfile builds or copies anything more, if the release workflow
builds the demo other than through `scripts/package-binary.sh`, or if the crate
becomes publishable to a registry. `.dockerignore` keeps the demo's sources out of
the image build, and the CI image job checks the built image for it.

A release attaches the demo only as its own archive, built on its own runner by
that script, which refuses a binary whose startup banner does not match the
archive it is going into. Downloading the demo gives you the demo: it adds nothing
to a `warden-server` or a `warden` you already have.
