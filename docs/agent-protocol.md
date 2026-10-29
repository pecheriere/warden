# warden agent protocol

**Protocol version warden-request-v1**

This document is the complete client side of the warden agent API: enough
to write a client in any language, on any machine, without reading warden's
code. The `warden` CLI is one such client; everything it does is described
here.

An *agent* is a program (or a person at a terminal) that asks the owner for
short-lived access and then uses it. The *broker* (`warden-server`) receives
the request, notifies the owner, who approves or denies it on their phone with
a passkey, and then issues the access: an SSH certificate, a session through
its SSH relay, or HTTPS calls it makes on the agent's behalf with a secret
the agent never sees.

Agents authenticate every API call by **signing it with an SSH key** whose
public half the owner enrolled on the broker (the *signing key*). The key
can live in hardware (Secure Enclave, TPM, YubiKey) behind an `ssh-agent`, so
no reusable secret is stored on the agent's machine and a captured request
cannot be replayed. Older agents authenticate with a bearer key instead (see
[Bearer keys](#bearer-keys-legacy)); a new client should sign.

Contents:

1. [Prerequisites](#1-prerequisites)
2. [Enrollment](#2-enrollment)
3. [Signing requests](#3-signing-requests)
4. [Test vectors](#4-test-vectors)
5. [API conventions](#5-api-conventions)
6. [Endpoints](#6-endpoints)
7. [Using a grant](#7-using-a-grant)
8. [A worked client in POSIX shell](#8-a-worked-client-in-posix-shell)
9. [Where to keep the signing key](#9-where-to-keep-the-signing-key)
10. [Security notes](#10-security-notes)

## 1. Prerequisites

The broker is reachable only over a Tailscale tailnet. An agent machine
needs:

- **Tailnet membership.** The machine runs Tailscale and is a node of the
  owner's tailnet. It may be a user's device or a tagged device (for example
  a server tagged as an agent host); signed requests work from both.
- **Access to the broker's API.** The broker's API is published with
  Tailscale Serve over HTTPS on the broker node's tailnet name, for example
  `https://warden.example.ts.net`, at the root of that origin. The tailnet
  policy must allow the agent machine to reach that port. When the deployment
  puts a gateway in front of the broker that admits callers by a Tailscale
  application capability, the tailnet policy must also grant that capability
  to the agent machine (or its tag). The owner sets both up; ask them.
- **Access to the relay**, only if some targets are reached through the
  broker's SSH relay: the relay's TCP port (a Tailscale Serve TCP forward on
  the same node, announced in each relay grant) must be allowed for the agent
  machine too.
- **Never the approval UI.** The approval pages live on another port that
  the tailnet policy grants to the owner's phone only. An agent machine must
  not be able to reach it, so that a compromised agent can never put an
  approval prompt in front of the owner.
- **A clock within 60 seconds of the broker's** (use NTP), because signed
  requests carry a timestamp.
- **OpenSSH 8.9 or later** for `ssh-keygen -Y sign` and for using grants,
  or an SSHSIG implementation in your language.

Use the broker's URL exactly as given, with nothing after the host: the API
paths below are at the root. No proxy between the agent and the broker may
rewrite the path or query, since both are signed.

Never set the `Tailscale-User-Login` header (or any `Tailscale-*` header)
yourself. Tailscale Serve sets it, for user devices only, after
authenticating the machine.

Never expose the API through Tailscale Funnel: it is for tailnet peers only.
Serve marks requests that came through Funnel with the
`Tailscale-Funnel-Request` header, and the broker refuses every such request,
on every path (`/healthz` and `/v1/info` included), with
`401 {"error":"unauthorized"}`, whatever credentials it carries.

## 2. Enrollment

### Key types

The signing key must be one of:

| Key type | Typical source |
|----------|----------------|
| `ssh-ed25519` | a key file, or an `ssh-agent` holding one |
| `ecdsa-sha2-nistp256` | Secure Enclave (Secretive), TPM (`ssh-tpm-agent`), YubiKey PIV |

The broker refuses at enrollment RSA keys, ECDSA keys on other curves,
security keys (`sk-ssh-ed25519@openssh.com`,
`sk-ecdsa-sha2-nistp256@openssh.com`: they need a touch for every signature,
and every API call is signed) and certificates. See
[section 9](#9-where-to-keep-the-signing-key) for how to create a key.

### Registering the key

Give the owner the public key line (the content of the `.pub` file, for
example `ecdsa-sha2-nistp256 AAAAE2VjZHNh… build-bot@host`) and an agent
name of 1 to 32 characters matching `^[a-z0-9][a-z0-9-]{0,31}$`. The owner
runs, on the broker:

```sh
warden-server agent add <name> --public-key '<public key line>'
```

This creates a key-signed agent; no bearer key is printed, and nothing
secret changes hands. An existing bearer-key agent is switched with
`warden-server agent set-key <name> '<public key line>'`: its bearer key stops
working at once. `warden-server agent list` shows each agent's kind of
authentication and its key's fingerprint
(`SHA256:…`, the same as `ssh-keygen -lf <key>.pub`); compare it with yours.
`warden-server agent revoke <name>` disables the agent, cancels its pending
requests, ends its grants and kills its relay sessions.

A key belongs to one agent: enrolling a key that another agent has is
refused, and a revoked agent keeps its key, so a revoked agent's key can
never be enrolled again, under any name. After a revocation, make a new key.

### Pinning the audience

Every broker has an **audience**: a random identifier of 32 lowercase hex
characters, created once and never changed. Signatures name it, so a request
signed for one broker is refused by every other broker, even one where the
same key is enrolled. Fetch it once, when you set the client up:

```sh
curl -sS https://warden.example.ts.net/v1/info
# {"protocols":["warden-request-v1"],"audience":"40ad20029e94984d193159667b296d8a"}
```

Store the audience in the client's configuration with the broker URL, the
agent name and the public key (none of these is secret), and use the stored
value from then on. Check that `protocols` contains `warden-request-v1`.
If `/v1/info` later reports another audience, stop and ask the owner: you are
talking to another broker, or the broker's data was reset. Then make one
signed call, such as `GET /v1/grants`, to confirm the enrollment works.

## 3. Signing requests

Every call to the API except `GET /healthz` and `GET /v1/info` is signed.

### Headers

| Header | Value |
|--------|-------|
| `Warden-Agent` | The agent name. |
| `Warden-Timestamp` | The current time in Unix seconds, plain decimal: digits only, no sign, no leading zero, no fraction. |
| `Warden-Nonce` | 16 fresh random bytes as 32 lowercase hex characters, from a cryptographic random source. New for every request. |
| `Warden-Signature` | The SSHSIG signature of the canonical message (below), as standard base64 (with `=` padding) of the binary signature blob, on one line. This is the armored output of `ssh-keygen -Y sign` without the `-----BEGIN SSH SIGNATURE-----` and `-----END SSH SIGNATURE-----` lines, its lines joined with no separator. |

Send each of the four headers exactly once, with one value. Do not send an
`Authorization` header with them. See [Rules](#rules) for what is refused.

### The canonical message

The signature covers this text, UTF-8, exactly eight lines, each ended by a
single `\n` (LF, also after the last line), with no other whitespace, no
spaces around the colons and no trailing spaces:

```text
warden-request-v1
audience:<audience>
agent:<agent name>
method:<METHOD>
target:<path and query exactly as sent on the request line>
timestamp:<Warden-Timestamp>
nonce:<Warden-Nonce>
body-sha256:<lowercase hex SHA-256 of the exact body bytes; of the empty string when there is no body>
```

- `audience` is the pinned audience; `agent`, `timestamp` and `nonce` are the
  header values, character for character.
- `method` is the HTTP method as sent, uppercase for every endpoint here
  (`GET`, `POST`).
- `target` is the request target in origin form: the path, and `?` and the
  query if there is one, byte for byte as on the HTTP request line. It is
  what you put after the host in the URL, for example `/v1/grants` or
  `/v1/requests/0b8f4c1e9d2a47f3a5c6e7d8f9a0b1c2?wait=30`. It starts with `/`,
  is visible ASCII (no spaces, no non-ASCII: percent-encode them), has no
  `#` fragment and is at most 8192 bytes. The broker rebuilds the message
  from the request-target it receives, so sign exactly what you send, and
  do not let the HTTP library normalise the path or re-encode the query after
  you signed it. Send targets in a form no intermediary has a reason to
  change: no empty query (a bare trailing `?`), no percent-encoding of
  characters that need none (`%41` for `A`, `%2D` for `-`), and uppercase hex
  digits in the percent-encodings you do need (`%2F`, not `%2f`). An
  intermediary that normalises the target would make the signature fail.
- `body-sha256` is the SHA-256 of the bytes of the request body exactly as
  sent (after any encoding, before any transfer framing). A request without a
  body (every `GET`, and the bodiless `POST`s) uses the hash of the empty
  string, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

### Making the signature

Sign the canonical message as an SSHSIG ([OpenSSH
`PROTOCOL.sshsig`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig))
with:

- namespace **`warden-request-v1`**;
- hash algorithm **`sha512`** (the `ssh-keygen` default; the broker also
  accepts `sha256`);
- the enrolled key.

With OpenSSH and a key in an `ssh-agent`:

```sh
ssh-keygen -Y sign -n warden-request-v1 -f signing-key.pub < message > message.sig
```

Given the public key file with `-f`, `ssh-keygen` asks the agent at
`SSH_AUTH_SOCK` to sign; given the private key file, it signs itself.
If the agent does not hold the key, `ssh-keygen` silently falls back to a
private key file of the same name without `.pub` next to it, if one exists.
For a key that must never be on disk, keep no private key file beside the
`.pub`, and check that `ssh-add -L` lists the key before relying on the agent.
With no file argument it reads the message from standard input and writes
the armored signature to standard output. Turn the armored signature into
the header value with `sed '1d;$d' message.sig | tr -d '\n'`.

### The SSHSIG format

For a client that implements SSHSIG itself, or talks to an `ssh-agent`
socket directly, here is the layout from `PROTOCOL.sshsig`. `string` is a
`uint32` big-endian length followed by that many bytes, as everywhere in the
SSH protocol ([RFC 4251](https://www.rfc-editor.org/rfc/rfc4251#section-5)).

The key signs this preimage, not the message itself:

```text
byte[6]   "SSHSIG"
string    namespace          "warden-request-v1"
string    reserved           empty
string    hash_algorithm     "sha512" (or "sha256")
string    H(message)         the raw 64-byte SHA-512 (or 32-byte SHA-256)
                             digest of the canonical message, not hex
```

The signature blob, which `Warden-Signature` carries in base64, is:

```text
byte[6]   "SSHSIG"
uint32    version            1
string    publickey          the signing key in SSH wire format (the
                             base64 field of the .pub line, decoded)
string    namespace          "warden-request-v1"
string    reserved           empty
string    hash_algorithm     "sha512" (or "sha256")
string    signature          the SSH signature of the preimage: string
                             algorithm name, then string signature data
                             (Ed25519: the 64-byte signature; ECDSA P-256:
                             mpint r and mpint s, signed over SHA-256 of the
                             preimage as ecdsa-sha2-nistp256 specifies)
```

Through an `ssh-agent`, send `SSH_AGENTC_SIGN_REQUEST` (message 13) with the
key blob, the preimage as the data and flags 0; the
`SSH_AGENT_SIGN_RESPONSE` (message 14) carries the `signature` field above,
ready to put in the blob.

### Rules

- **One request, one nonce.** Every HTTP request gets a fresh nonce and a
  fresh timestamp, and is signed anew. This includes each long poll and each
  retry: a request is never resent with an old signature, since the broker
  refuses a nonce it has already seen.
- **Clock skew.** The broker refuses a timestamp more than 60 seconds away
  from its own clock, in either direction.
- **Header form.** Each `Warden-*` header appears once, with one value.
  A request is refused with 401 if:
  - any `Warden-*` header comes together with an `Authorization` header;
  - a `Warden-*` header is repeated or carries several values;
  - `Warden-Signature` is longer than 4096 characters (it is refused before
    it is decoded; real signatures are under 400);
  - it carries any other `Warden-*` header: other `Warden-*` header names
    are reserved and refused.
- **Errors.** An authentication failure is a 401. Branch on the status
  only. The body is `{"error":"unauthorized"}` for a signature failure,
  but it may say something else for other failures (for example
  `{"error":"agent revoked"}`). The precise reason is in the broker's log.
  Check your clock, your audience and the bytes you signed against what you
  sent.

### What the broker checks

In this order, stopping at the first failure. Every failure is a 401,
except an oversized body (413) and a body too slow to arrive (408):

1. The four `Warden-*` headers are present, each once, and well formed;
   `Warden-Signature` is at most 4096 characters; no other `Warden-*` header
   and no `Authorization` header is present.
2. The agent exists, is not revoked and has a registered signing key.
3. The timestamp is within 60 seconds of the broker's clock.
4. The body is read, within the endpoint's size limit and within the time
   allowed for that limit ([section 5](#5-api-conventions): 10 seconds, or
   16 for `POST /v1/grants/{id}/http`). A larger body is refused with 413,
   and a body still incomplete when the time is up with 408, at this step,
   before the signature is checked.
5. The signature verifies: namespace `warden-request-v1`, hash `sha512` or
   `sha256`, made by exactly the agent's registered key, over the canonical
   message rebuilt from the request as received.
6. The pair (agent, nonce) has not been seen before. It is remembered for 10
   minutes, which covers the whole 60-second window on either side. Only a
   request whose signature verified is remembered.

Signed agents do not need the owner's `Tailscale-User-Login`: tagged devices
have none. Who may reach the broker at all is decided by the tailnet policy
(section 1).

### Bearer keys (legacy)

Agents enrolled with `warden-server agent add <name>` (no `--public-key`)
authenticate with `Authorization: Bearer wdn_…` instead of the `Warden-*`
headers. Such calls must also come from a device of the owner (Serve's
`Tailscale-User-Login` must be the owner's login), or they are refused with
`403 {"error":"forbidden"}`; a missing, unknown or revoked key is
`401 {"error":"unauthorized"}`. A bearer key can be replayed by whoever
copies it, so new clients should sign.

## 4. Test vectors

These vectors are generated with the throwaway Ed25519 key in
[`crates/proto/tests/fixtures/throwaway-test-only-signing-ed25519.key`](../crates/proto/tests/fixtures/throwaway-test-only-signing-ed25519.key)
(a test key that protects nothing; never enroll it), whose public key is:

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFtEYSaZPFM5lYU6qb0mU18GImVC77EbHBHD9eXvkSjX warden throwaway test vector key, not a secret
```

The same values are in
[`crates/proto/tests/fixtures/signing-v1.json`](../crates/proto/tests/fixtures/signing-v1.json),
and warden's tests check that this document, that file and the code agree.
Ed25519 signatures are deterministic, so signing a vector's message with
that key (namespace `warden-request-v1`, hash `sha512`) must reproduce its
signature exactly. ECDSA signatures are randomised, so the
[P-256 vector](#vector-3-ecdsa-p-256-verify-only) can only be verified, and
for ECDSA you check that your signatures verify.

### Vector 1: create a request (`POST` with a body)

Inputs:

| Field | Value |
|-------|-------|
| audience | `40ad20029e94984d193159667b296d8a` |
| `Warden-Agent` | `build-bot` |
| method | `POST` |
| target | `/v1/requests` |
| `Warden-Timestamp` | `1793091600` |
| `Warden-Nonce` | `ee517b64804ef8916b8386eeaa436de0` |

Body (no trailing newline):

```json
{"goal":"list open pull requests to triage issue 42","access":{"kind":"api","secret":"github"},"window":"15m"}
```

SHA-256 of the body:
`7b4d5ced01700c9d1f327ea0468eb7f7415f721be9174d9b1787fac19f97e3bc`

Canonical message (every line ends with `\n`):

```text
warden-request-v1
audience:40ad20029e94984d193159667b296d8a
agent:build-bot
method:POST
target:/v1/requests
timestamp:1793091600
nonce:ee517b64804ef8916b8386eeaa436de0
body-sha256:7b4d5ced01700c9d1f327ea0468eb7f7415f721be9174d9b1787fac19f97e3bc
```

SHA-256 of the canonical message (all 8 lines, final `\n` included):
`4ae35bb0a07a66df1cb95810a28ef919bdba8c7eefe55f8ec8080a8576944620`

`Warden-Signature`:

```text
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgW0RhJpk8UzmVhTqpvSZTXwYiZULvsRscEcP15e+RKNcAAAARd2FyZGVuLXJlcXVlc3QtdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAlPvk/zRidR1rxdes/qGezl9WbfbZEwmU+4JPvdcjBCat/6nB0FMHMxOYHx6pi/cl/inmt+L63OYj+2lDb5wGDg==
```

### Vector 2: long-poll a request (`GET` with a query, no body)

Inputs:

| Field | Value |
|-------|-------|
| audience | `40ad20029e94984d193159667b296d8a` |
| `Warden-Agent` | `build-bot` |
| method | `GET` |
| target | `/v1/requests/0b8f4c1e9d2a47f3a5c6e7d8f9a0b1c2?wait=30` |
| `Warden-Timestamp` | `1793091600` |
| `Warden-Nonce` | `4a445d4dbb87ff887c7ee560e015dadb` |

No body. SHA-256 of the (empty) body:
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

Canonical message:

```text
warden-request-v1
audience:40ad20029e94984d193159667b296d8a
agent:build-bot
method:GET
target:/v1/requests/0b8f4c1e9d2a47f3a5c6e7d8f9a0b1c2?wait=30
timestamp:1793091600
nonce:4a445d4dbb87ff887c7ee560e015dadb
body-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

SHA-256 of the canonical message:
`2303c5f701c4085cc29ed3c7e0978bc5a4b20c71152bdd69eecb1151c50a2568`

`Warden-Signature`:

```text
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgW0RhJpk8UzmVhTqpvSZTXwYiZULvsRscEcP15e+RKNcAAAARd2FyZGVuLXJlcXVlc3QtdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABA9sQPlnSUAsLdic8E6k3x17XCbv3vxLsAG+ogblqBwrMwBZElIqCAqPO2vVopQyofr2hakmLDYOGHFNMbg9mzCw==
```

### Vector 3: ECDSA P-256 (verify only)

A signature over the canonical message of vector 1, made with a throwaway
P-256 key (namespace `warden-request-v1`, hash `sha512`). The private key was
discarded: this vector checks that a verifier handles
`ecdsa-sha2-nistp256` signatures, as Secure Enclave, TPM and PIV keys
produce.

Public key:

```text
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC+QqOP9eVCRD+mZKR9M9swQ1UATTw3+lcxT1Yj8H0huXEBHMc58PIqZfCWeiPzLR8jnMD8GKW77zKgpJ5a91W0= warden throwaway P-256 test vector key, not a secret
```

`Warden-Signature`:

```text
U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEL5Co4/15UJEP6ZkpH0z2zBDVQBNPDf6VzFPViPwfSG5cQEcxznw8ipl8JZ6I/MtHyOcwPwYpbvvMqCknlr3VbQAAABF3YXJkZW4tcmVxdWVzdC12MQAAAAAAAAAGc2hhNTEyAAAAYwAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAASAAAACBwZSOEMIbCLLtADjA5B/WhOpW48NiXwO6oh9ebjlOQUgAAACBRM0a5nkMa/v6ei0rMK6xbkRVE96JqAYC5i/XAXhwj9Q==
```

### Checking an implementation with OpenSSH

```sh
printf 'warden-request-v1\naudience:40ad20029e94984d193159667b296d8a\nagent:build-bot\nmethod:GET\ntarget:/v1/requests/0b8f4c1e9d2a47f3a5c6e7d8f9a0b1c2?wait=30\ntimestamp:1793091600\nnonce:4a445d4dbb87ff887c7ee560e015dadb\nbody-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n' > message
openssl dgst -sha256 -r message      # 2303c5f7…50a2568 *message

# Re-armor a Warden-Signature value ($SIG) and verify it against the key.
{ echo '-----BEGIN SSH SIGNATURE-----'; printf '%s' "$SIG" | fold -w 70; echo
  echo '-----END SSH SIGNATURE-----'; } > message.sig
echo 'build-bot ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFtEYSaZPFM5lYU6qb0mU18GImVC77EbHBHD9eXvkSjX' > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I build-bot -n warden-request-v1 -s message.sig < message
```

For vector 3, write vector 1's message to `message` the same way and put
the P-256 public key in `allowed_signers`.

An SSHSIG blob carries the signer's public key, so a verifier must check
that it is the expected key, as `-Y verify` with an allowed-signers file does
(`-Y check-novalidate` does not).

## 5. API conventions

- **Base URL.** All paths are relative to the broker's root, for example
  `https://warden.example.ts.net/v1/grants`. HTTPS only (Tailscale Serve
  terminates TLS with the node's `ts.net` certificate).
- **JSON.** Request and response bodies are JSON (UTF-8). Send
  `Content-Type: application/json` with every JSON body; without it the
  broker answers 415. Unknown fields in a request body are ignored.
- **Size limits.** A request body is at most 16 KiB, except
  `POST /v1/grants/{id}/http` which accepts 2 MiB. Over the limit is 413
  `{"error":"request body rejected"}`. This is checked before the signature,
  so an oversized signed request gets a 413, not a 401.
- **Time limit.** The body of a signed request must arrive within a time
  that scales with the endpoint's size limit: the larger of 10 seconds and
  the limit at 128 KiB per second, counted from when the broker starts
  reading it. That is 10 seconds for the 16 KiB endpoints and 16 seconds for
  `POST /v1/grants/{id}/http` (2 MiB). A body still incomplete then is
  `408 {"error":"request body timed out"}`, also before the signature is
  checked. Send the body at once: sign it buffered, not streamed slowly.
- **Identifiers.** Request and grant ids are 32 lowercase hex characters.
  A malformed id in a path is `400 {"error":"invalid id"}`.
- **Times** are Unix seconds (integers).
- **Errors** have the body `{"error":"<message>"}`. Messages are for people
  and for logs; branch on the status code, except where a message is given
  below as fixed. Treat a message as untrusted text: strip control
  characters before printing it.
- **Common statuses** for every signed endpoint: 401 (authentication
  failed, or the agent is revoked; branch on the status, as the body varies,
  see [Rules](#rules)), 408 (body too slow), 413 (body over the limit), 500 `{"error":"internal error"}`, 503 (the broker's secret
  backend is unavailable: `{"error":"secret backend unavailable"}`; or a
  short contention, `{"error":"request slot contended; retry"}`). An unknown
  path is `404 {"error":"not found"}`.
- **Retrying.** 5xx statuses and transport errors may be retried with
  backoff (the CLI starts at 1 s and doubles up to 15 s), each attempt signed
  anew. A 4xx is final: do not retry it unchanged.
- Responses carry `Cache-Control: no-store`. Redirects are never used; do
  not follow one.

## 6. Endpoints

| Method and path | Purpose |
|-----------------|---------|
| `GET /healthz` | Liveness, unauthenticated. |
| `GET /v1/info` | Protocols and audience, unauthenticated. |
| `POST /v1/requests` | Ask for access. |
| `GET /v1/requests/{id}[?wait=N]` | A request's state; long poll. |
| `POST /v1/requests/{id}/cancel` | Withdraw a pending request. |
| `GET /v1/grants` | The agent's live grants. |
| `POST /v1/grants/{id}/revoke` | End a grant. |
| `POST /v1/grants/{id}/http` | Make an HTTPS call with an `api` grant. |

### `GET /healthz`

Not signed. `200` with the plain-text body `ok`.

### `GET /v1/info`

Not signed (the tailnet policy still decides who can reach it). `200`:

```json
{"protocols":["warden-request-v1"],"audience":"40ad20029e94984d193159667b296d8a"}
```

`protocols` lists the signing protocols the broker accepts; `audience` is
the value to pin (section 2).

### `POST /v1/requests`

Ask the owner for access. Signed; JSON body:

| Field | Type | Meaning |
|-------|------|---------|
| `goal` | string | Why access is needed: what you will do and why, naming the change, issue or error. 1 to 500 characters after trimming whitespace, one line: no control characters and no invisible format characters (Unicode category Cf: bidi controls, zero-width characters, BOM, soft hyphen…). The owner decides on it alone; the notification shows the first 200 characters. |
| `access` | object | What is asked for; see below. |
| `window` | string | How long the access should last: `15m`, `30m`, `1h` or `4h`. The target's or secret's policy caps it, and the owner may approve a shorter one. |

`access` for SSH (a certificate, or a session through the relay; the
target's policy decides which, and the agent does not need to know):

```json
{"kind":"ssh","target":"pi","user":"deploy","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… "}
```

- `target`: the target's name, `^[a-z0-9][a-z0-9-]{0,31}$`.
- `user`: the Unix account to log in as, `^[a-z_][a-z0-9_-]{0,31}$`. Ask
  for the least privileged account that can do the job.
- `public_key`: an OpenSSH `ssh-ed25519` public key line. Make a **new
  key pair for every request** and keep its private half in memory or in a
  dedicated `ssh-agent` (section 7); never reuse the signing key. The owner's
  approval is bound to this exact key, and one key can back only one live
  request or grant at a time (`409`, see below).

`access` for an HTTPS API (calls the broker makes with a stored secret):

```json
{"kind":"api","secret":"github","methods":["POST"],"path_prefix":"/repos/alice/widgets/"}
```

- `secret`: the secret's name, `^[a-z0-9][a-z0-9-]{0,31}$`.
- `methods` (optional): 1 to 8 uppercase method names, no duplicates,
  never `CONNECT` or `TRACE`, each allowed by the secret's policy. Absent
  means **read-only**: the policy's methods among `GET` and `HEAD`.
- `path_prefix` (optional): a path prefix under the policy's, matched on a
  segment boundary. Absent means the policy's prefix.

Example:

```json
{"goal":"list open pull requests to triage issue 42","access":{"kind":"api","secret":"github"},"window":"15m"}
```

Responses:

- `201`: `{"id":"0b8f4c1e9d2a47f3a5c6e7d8f9a0b1c2","fingerprint":"42d5-403c-c2f0"}`.
  The owner is notified. Show the id and fingerprint to whoever supervises
  the agent: the approval page shows the same fingerprint.
- `400`: the body is not valid JSON or a field is invalid (the message says
  which), or the policy refuses the request (the user, window, method or
  path is not allowed; the message names the rule). Not retried, not
  notified.
- `404`: `unknown target <name>` or `unknown API secret <name>`.
- `409`: `{"error":"this public key is already bound to another request or grant"}`.
- `401`, `413`, `415`, `500`, `503`: see section 5.

**Only one pending request per agent and target (or secret and scope).**
If one is already pending, the broker answers `201` with *that* request's
id and fingerprint instead of making a new one. To tell, compute the
fingerprint of your own request and compare: it is the first 6 bytes of
the SHA-256 of the JSON array `[<agent name>, <request body>]`, as lowercase
hex in groups of four (`xxxx-xxxx-xxxx`). The broker hashes its own compact
JSON encoding of the request: the fields in the order `goal`, `access`,
`window`; inside `access`, `kind` first, then the other fields in the order
listed above, absent optional fields left out; the goal trimmed; no
whitespace between tokens; only `"`, `\` and control characters escaped,
other characters as raw UTF-8. Send the body in exactly that form and you
can hash what you sent:

```sh
printf '["build-bot",%s]' "$(cat body.json)" | openssl dgst -sha256 -r | cut -c1-12
# 42d5403cc2f0  ->  fingerprint 42d5-403c-c2f0
```

On a mismatch, do not wait on the other request: it is not yours to use.

### `GET /v1/requests/{id}` (long poll)

The state of one of the agent's own requests. Signed; no body.

Query parameter `wait` (optional, default `0`): a whole number of seconds
from 0 to 30. With `wait=0` the answer is immediate. Otherwise, while the
request is pending, the broker holds the call until the state changes or
`wait` seconds pass, then answers with the current state, which may still
be `pending`. Poll in a loop with `wait=30` and a fresh signature each time,
with an HTTP timeout above 30 seconds (the CLI uses 50). A pending request
expires 10 minutes after it was made, so a loop of about 11 minutes always
sees the outcome.

`200`, one of:

```json
{"status":"pending"}
{"status":"denied"}
{"status":"expired"}
{"status":"cancelled"}
{"status":"revoked"}
{"status":"error","message":"could not notify the owner: …"}
{"status":"approved","grant_id":"…","not_before":1793091612,"not_after":1793092512,"access":{"kind":"ssh",…}}
```

- `pending`: no decision yet.
- `approved`: the grant is inline (`grant_id`, `not_before`, `not_after` and
  `access`, described in section 7). `not_after` reflects the window the
  owner approved, which may be shorter than the one asked for.
- `denied`: do not retry the same request; ask the owner what to change.
- `expired`: nobody decided within 10 minutes. Retry later, not in a loop.
- `cancelled`: the agent withdrew it.
- `revoked`: it was approved, then the grant was revoked.
- `error`: it failed, for example no notification could be delivered;
  `message` says why.

Errors: `400` for a malformed id or `wait` (`wait must be a whole number of
seconds from 0 to 30`, `wait must be at most 30 seconds`), `404`
`{"error":"not found"}` for an unknown id or another agent's request, and
section 5.

### `POST /v1/requests/{id}/cancel`

Withdraw one of the agent's own pending requests, for example when the work
no longer needs it. Signed; no body (sign the empty body). The owner's
approval link then shows "Cancelled by the agent." and cannot be approved.

- `204`: cancelled; no body.
- `404` `{"error":"not found"}`: unknown id, or another agent's request.
- `409` `{"error":"request already decided"}`: no longer pending (decided,
  cancelled or expired). If it was approved in the meantime, read its state
  and revoke the grant you no longer want.
- `400`, and section 5.

### `GET /v1/grants`

The agent's live grants (neither revoked nor expired), soonest expiry
first. Signed; no body. `200` with a JSON array of grants, each
`{"grant_id","not_before","not_after","access"}` as in section 7:

```json
[{"grant_id":"5e1c…","not_before":1793091612,"not_after":1793092512,"access":{"kind":"api","secret":"github","origin":"https://api.github.com","methods":["GET","HEAD"],"path_prefix":"/","header":"Authorization","digest":"…"}}]
```

### `POST /v1/grants/{id}/revoke`

End one of the agent's grants as soon as the work is done. Signed; no
body. Relay sessions on the grant are killed and `api` calls refused.
Certificates already issued stay valid on the target until they expire,
which is why windows are short.

- `204`: revoked (also if it already was); no body.
- `404` `{"error":"not found"}`: unknown id, or another agent's grant.
- `400`, and section 5.

### `POST /v1/grants/{id}/http`

Have the broker make one HTTPS call with an `api` grant's secret; see
[section 7](#api-grants) for the body and the rules.

## 7. Using a grant

A grant is:

| Field | Type | Meaning |
|-------|------|---------|
| `grant_id` | string | Grant id (32 hex). |
| `not_before`, `not_after` | integer | Validity, Unix seconds. |
| `access` | object | What the grant allows, tagged by `kind`: `ssh`, `relay` or `api`. |

Keep a record of each grant (id, kind, `not_after`) so you can use and
revoke it. Drop it when it expires; `GET /v1/grants` is the broker's view.

### SSH certificate grants (`"kind":"ssh"`)

```json
{"kind":"ssh","certificate":"ssh-ed25519-cert-v01@openssh.com AAAA…","host":"pi.example.ts.net","port":22,"user":"deploy","host_keys":["ssh-ed25519 AAAA…"]}
```

The broker's SSH CA signed the request's `public_key` into `certificate`
(principal `warden:<target>:<user>`, valid for the approved window, key id
the grant id). To use it:

1. Check that `user` is the account you asked for and that `host` is a
   plain host name (letters, digits, `.`, `-`; not starting with `-`).
2. Load the request's private key **with the certificate** into an
   `ssh-agent`, ideally one started for this grant alone, with a lifetime of
   `not_after` minus now: write the certificate next to the key as
   `<key>-cert.pub` and run `SSH_AUTH_SOCK=<grant agent> ssh-add -t <secs>
   <key>` (it loads both), then delete the private key file. Keep the files in
   a 0700 directory, on a RAM-backed file system if you can.
3. Pin the host keys: write a `known_hosts` file with one line per entry of
   `host_keys`, `<host> <key>` for port 22 and `[<host>]:<port> <key>`
   otherwise. Drop any comment from the key, and refuse entries that are not
   a single OpenSSH public key.
4. Connect with only that agent and those keys:

   ```sh
   ssh -F /dev/null -o IdentityAgent=<grant agent socket> -o IdentityFile=none \
     -o UserKnownHostsFile=<grant dir>/known_hosts -o StrictHostKeyChecking=yes \
     -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
     -p <port> -- <user>@<host> [command]
   ```

   Pass the remote command after `--` and the destination, never as ssh
   options.

### Relay grants (`"kind":"relay"`)

```json
{"kind":"relay","target":"nas","user":"backup","relay_host":"warden.example.ts.net","relay_port":2222,"relay_host_key":"ssh-ed25519 AAAA…","digest":"…"}
```

No certificate: the broker's SSH relay accepts the request's own
`public_key`, and it opens the session to the target itself with a
credential that never leaves the broker. To use it:

1. Load the request's private key (alone, no certificate) into a grant
   `ssh-agent` as above.
2. Pin `relay_host_key` for `[relay_host]:relay_port` (or `relay_host` on
   port 22) in the grant's `known_hosts`.
3. Log in to the relay **as the target name** (not the Unix user; the relay
   logs in to the target as `user`):

   ```sh
   ssh -F /dev/null -o IdentityAgent=<grant agent socket> -o IdentityFile=none \
     -o UserKnownHostsFile=<grant dir>/known_hosts -o StrictHostKeyChecking=yes \
     -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
     -p <relay_port> -- <target>@<relay_host> [command]
   ```

A shell or one command per session; port forwarding, agent forwarding, X11
and subsystems (`sftp`, so also `scp` in its default mode) are refused: move
files through stdin and stdout. A session that the relay ends or refuses
exits 255 with a message starting `warden relay:` on stderr. `digest` is the
approved destination; a client only passes it through.

### API grants (`"kind":"api"`)

```json
{"kind":"api","secret":"github","origin":"https://api.github.com","methods":["GET","HEAD"],"path_prefix":"/","header":"Authorization","digest":"…"}
```

The agent never sees the secret. It sends each call to the broker, which
checks it against the grant and the secret's current policy, adds the
`header` carrying the secret, makes the call and returns the answer with the
secret redacted. `origin`, `methods` and `path_prefix` say which calls the
grant covers; pick the grant whose scope covers the call.

`POST /v1/grants/{id}/http`, signed, with the JSON body:

| Field | Type | Meaning |
|-------|------|---------|
| `method` | string | HTTP method, one of the grant's `methods`. |
| `url` | string | Absolute URL: `https`, exactly the grant's `origin`, a path under `path_prefix` on a segment boundary. Printable ASCII, no spaces, no user info, no fragment; the path has no `.` or `..` segments, `//`, `;`, `\` or encoded separators (`%2e`, `%2f`, `%5c`, `%3b`, `%25`, `%c0`, `%c1`, `%u`, any case). The query is free. |
| `headers` | array | Request headers, as `[name, value]` pairs: `[["Content-Type","application/json"]]`. Not allowed: `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Proxy-*`, the grant's `header`, `Accept-Encoding`, `Range`, `If-Range`, method and URL override headers, forwarding and host-override headers (`Forwarded`, `Via`, `X-Forwarded-*`, `X-Real-IP`, `X-Host`, `X-Original-Host`), and any name or value with CR, LF or NUL. |
| `body_b64` | string or null | The request body, **standard base64** (RFC 4648 alphabet with `+` and `/`, `=` padding, no line breaks, no whitespace), at most 1 MiB once decoded. Absent or `null` for no body. |

```json
{"method":"POST","url":"https://api.github.com/repos/alice/widgets/issues","headers":[["Content-Type","application/json"]],"body_b64":"eyJ0aXRsZSI6InN0YWxlIGZvcmsifQ=="}
```

The signature covers this JSON body (its SHA-256 is the `body-sha256`),
not the upstream call inside it.

`200` with the upstream answer, whatever its status:

```json
{"status":200,"headers":[["content-type","application/json"]],"body_b64":"W3sibnVtYmVyIjo0Mn1d","redactions":0}
```

- `status`: the upstream status code. Redirects are not followed: a 3xx comes
  back as is.
- `headers`: the response headers as `[name, value]` pairs, names lowercase,
  hop-by-hop headers and `Content-Length` removed.
- `body_b64`: the response body, standard base64 with padding (decode it
  strictly).
- `redactions`: how many occurrences of the secret were replaced with
  `[REDACTED]`.

Errors:

- `400`: the call breaks a rule of the grant or policy; the message names the
  rule (`URL refused: …`, `header refused: …`, `body refused: …`, `method is
  not allowed for this secret`, …).
- `404` `{"error":"not found"}`: unknown id, or another agent's grant.
- `409`: the grant cannot be used: `grant revoked`, `grant expired`,
  `grant is not for API access`, `policy changed; request access again` (the
  owner changed the secret's policy after approval), or, when this happens
  while the call is out, `grant revoked during the call` / `grant expired
  during the call` (the response is withheld). Request access again.
- `413`: the JSON body is over 2 MiB.
- `429` `too many concurrent calls`: at most 4 calls per agent (16 overall)
  may be in flight; wait for one to finish.
- `502`, `504`: the upstream failed, timed out (30 s per call), sent a
  compressed or oversized (over 1 MiB by default) response; the message is
  fixed and never quotes the upstream.
- `500`, `503`, and section 5.

Every call is recorded in the broker's audit log (method, origin and path,
never the query; status, size, redactions).

## 8. A worked client in POSIX shell

`warden-call` signs and sends one request. It needs `curl`, `openssl`,
`ssh-keygen` (OpenSSH 8.9+) and an `ssh-agent` at `SSH_AUTH_SOCK` holding the
enrolled key. `sha256sum` works in place of `openssl dgst -sha256 -r`.

```sh
#!/bin/sh
# warden-call METHOD TARGET [BODY_FILE]
# Send one signed request to a warden broker and print the response body.
# The HTTP status goes to stderr. Configuration (none of it secret):
#   WARDEN_URL       broker URL, e.g. https://warden.example.ts.net
#   WARDEN_AGENT     agent name
#   WARDEN_PUBKEY    path to the enrolled public key (.pub); the private key
#                    is used through the ssh-agent at SSH_AUTH_SOCK
#   WARDEN_AUDIENCE  the audience pinned at setup (GET /v1/info)
set -eu
: "${WARDEN_URL:?}" "${WARDEN_AGENT:?}" "${WARDEN_PUBKEY:?}" "${WARDEN_AUDIENCE:?}" "${SSH_AUTH_SOCK:?}"
[ $# -ge 2 ] || { echo "usage: warden-call METHOD TARGET [BODY_FILE]" >&2; exit 2; }
method=$1 target=$2 body=${3:-}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# The exact bytes that will be sent, and their hash (empty file: no body).
if [ -n "$body" ]; then cp -- "$body" "$tmp/body"; else : > "$tmp/body"; fi
body_sha256=$(openssl dgst -sha256 -r "$tmp/body" | cut -d' ' -f1)

timestamp=$(date +%s)
nonce=$(openssl rand -hex 16)

printf 'warden-request-v1\naudience:%s\nagent:%s\nmethod:%s\ntarget:%s\ntimestamp:%s\nnonce:%s\nbody-sha256:%s\n' \
  "$WARDEN_AUDIENCE" "$WARDEN_AGENT" "$method" "$target" "$timestamp" "$nonce" "$body_sha256" \
  > "$tmp/message"

# Sign through the ssh-agent; drop the armor lines and join the base64.
ssh-keygen -q -Y sign -n warden-request-v1 -f "$WARDEN_PUBKEY" < "$tmp/message" > "$tmp/message.sig"
signature=$(sed '1d;$d' "$tmp/message.sig" | tr -d '\n')

set -- --silent --show-error --path-as-is --globoff --max-time 60 \
  --request "$method" \
  --header "Warden-Agent: $WARDEN_AGENT" \
  --header "Warden-Timestamp: $timestamp" \
  --header "Warden-Nonce: $nonce" \
  --header "Warden-Signature: $signature" \
  --write-out '%{stderr}HTTP %{http_code}\n'
if [ -n "$body" ]; then
  set -- "$@" --header 'Content-Type: application/json' --data-binary "@$tmp/body"
fi
curl "$@" "$WARDEN_URL$target"
```

`--data-binary` sends the file byte for byte (`-d` would strip newlines and
change the hash), `--path-as-is` stops curl from normalising the path, and
`--globoff` keeps `[]{}` literal. warden's tests run this script, exactly as
shown here, against a broker with Ed25519 and P-256 keys in an `ssh-agent`.

A session with it (`jq` only for reading the answers):

```sh
export WARDEN_URL=https://warden.example.ts.net WARDEN_AGENT=build-bot
export WARDEN_PUBKEY="$HOME/.ssh/warden-build-bot.pub"
# Once, at setup; store it and check it is unchanged from then on:
export WARDEN_AUDIENCE=$(curl -sS "$WARDEN_URL/v1/info" | jq -r .audience)

warden-call GET /v1/grants                  # confirms enrollment: []

printf '%s' '{"goal":"list open pull requests to triage issue 42","access":{"kind":"api","secret":"github"},"window":"15m"}' > req.json
id=$(warden-call POST /v1/requests req.json | jq -r .id)

# Long-poll until decided (each call is signed anew).
while :; do
  state=$(warden-call GET "/v1/requests/$id?wait=30")
  [ "$(printf '%s' "$state" | jq -r .status)" = pending ] || break
done
grant=$(printf '%s' "$state" | jq -r .grant_id)

# One API call through the grant.
printf '%s' '{"method":"GET","url":"https://api.github.com/repos/alice/widgets/pulls","headers":[["Accept","application/vnd.github+json"]],"body_b64":null}' > call.json
warden-call POST "/v1/grants/$grant/http" call.json | jq -r .body_b64 | openssl base64 -d -A

warden-call POST "/v1/grants/$grant/revoke"  # done: end the grant
```

A real client also handles `denied`, `expired`, `cancelled` and `error`
(stop), retries 5xx and transport errors with backoff, and cancels the
request (`POST /v1/requests/$id/cancel`) if it stops waiting.

## 9. Where to keep the signing key

Pick the strongest option the machine has. The key must be usable without a
person present (every call is signed, long polls included), so choose
settings that need no touch or biometric prompt per signature. A hardware
key cannot be copied off the machine, which is the point: an attacker who
gets in can use it only while they are in, and revoking the agent ends that.

- **macOS: Secure Enclave via [Secretive](https://github.com/maxgoedjen/secretive).**
  Create a key with authentication set to none (no Touch ID per signature).
  It is an `ecdsa-sha2-nistp256` key that never leaves the Secure Enclave.
  Point `SSH_AUTH_SOCK` at Secretive's agent socket
  (`~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh`)
  and use the public key file Secretive exports as `WARDEN_PUBKEY`.
- **Linux: TPM via [ssh-tpm-agent](https://github.com/Foxboron/ssh-tpm-agent).**
  Create a P-256 key sealed to the machine's TPM with `ssh-tpm-keygen`
  (without a PIN, or with one the agent can unlock unattended), run
  `ssh-tpm-agent`, and point `SSH_AUTH_SOCK` at its socket. The private key
  file it writes is only usable with that TPM.
- **YubiKey PIV.** Generate an ECC P-256 key in a PIV slot with PIN policy
  `never` (or once per session) and touch policy `never`, for example with
  `ykman piv keys generate --algorithm ECCP256 --pin-policy NEVER
  --touch-policy NEVER`, and expose it to an `ssh-agent` through PKCS#11
  (`ssh-add -s <path to libykcs11>`).
- **Plain key file** (weakest: anyone who copies the file can sign). Create a
  dedicated key, `ssh-keygen -t ed25519 -f ~/.ssh/warden-<agent>`, mode 0600,
  used for nothing else, preferably loaded into an `ssh-agent` (or pass the
  private key file to `ssh-keygen -Y sign -f` directly).

**Why not FIDO security keys (`sk-*`).** An `sk-ssh-ed25519@openssh.com` or
`sk-ecdsa-sha2-nistp256@openssh.com` key requires a physical touch for every
signature, and an agent signs every call, including every 30-second long
poll; an unattended agent cannot do that. Such keys are refused at
enrollment. Use a PIV, TPM or Secure Enclave key instead: they are equally
non-exportable and need no touch.

Never use the signing key for anything else, and never use it as the
`public_key` of an SSH request: those keys are fresh per request.

## 10. Security notes

What signing protects:

- **No reusable secret on the wire or at rest.** A request is useless to
  whoever captures it: the nonce is single-use, the timestamp limits it to 60
  seconds, the audience to one broker, and the signature covers the method,
  path, query and body, so it cannot be redirected to another endpoint, grant
  or body.
- **The key cannot leak if it is in hardware.** Unlike a bearer key, a
  Secure Enclave, TPM or PIV key cannot be copied off the machine; revoking
  the agent ends all use of it.
- **Unauthenticated callers cannot fill the broker's nonce store**: a nonce
  is stored only after its signature verifies.

What it does not protect:

- **A compromised agent machine** can sign whatever it wants while it can
  reach the key's `ssh-agent`. Every request still needs the owner's
  approval on their phone, with a goal and fingerprint the owner reads;
  grants are short, scoped and revocable. Limit who can use the
  `SSH_AUTH_SOCK` socket (it is the key).
- **Responses are not signed.** Their integrity and confidentiality rely on
  TLS, which Tailscale Serve terminates with the broker node's certificate.
  Do not disable certificate verification.
- **Headers other than the four `Warden-*` ones are not signed.** The
  broker does not act on them (`Content-Type` only gates JSON parsing).
- **Network access.** Signed agents do not need the owner's Tailscale
  identity, so who can reach the broker's API is decided by the tailnet
  policy (and the gateway's application capability, where there is one).
  Grant it only to agent machines, and never grant the approval UI to them.
- **Content is not hidden from the broker.** The broker sees every request
  and call it makes on the agent's behalf, and records them in its audit log.
- **Clock.** A machine whose clock is off by more than 60 seconds cannot
  call the broker; fix the clock rather than retrying.
