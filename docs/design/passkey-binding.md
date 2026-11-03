# Binding the passkey signature to the request it approves

**Status: decided, not planned.** Nothing here is implemented. The maintainer accepted
the recommendation below, and [#117](https://github.com/pecheriere/warden/issues/117)
is closed. [The threat model](../threat-model.md#approval-binding) describes what warden
does.

## Recommendation

**Don't do this now.** It can be built, with no fork and no migration, but it buys
little:

- A valid signature would not show that the owner saw the request. The broker
  serves the page and picks the challenge, so a compromised broker can show one
  thing and have the passkey sign another.
- A compromised broker needs no signature to act. It holds the CA key and the
  secrets, and can issue a certificate with no log entry at all.
- What it does catch is a forged approval record, and only if the owner keeps the
  passkeys' public keys off the host, ships the log off the host and runs a new
  verifier. A patient attacker gets past even that with one real tap.

It would also tempt readers to treat a signature as proof of what the owner approved.
[The assessment](../security-assessment.md) (F1) has already had to correct that claim once.

Revisit it if a third party ever has to audit a broker, or if the owner gets a way
to see the request that does not come from the broker, such as a phone app of its own.
A `webauthn-rs` API for the challenge would lower the cost, not raise the value.

## Can the challenge be derived?

Yes, as long as a random nonce goes in with the hash:

```text
challenge = SHA-256("warden-approval-v1" ‖ nonce ‖ statement)
```

- **The nonce keeps it fresh.** Without one, the same request and window give the
  same challenge, so a captured assertion could be replayed on a later ceremony of
  that request. With 32 random bytes per ceremony, the challenge cannot be guessed
  and never repeats. Ceremonies stay as they are: kept on the server, single use, 120 s.
- **The specification.** [WebAuthn §13.4.3](https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges)
  says a challenge MUST be "randomly generated" in an environment the relying party
  trusts, must match what was generated, and SHOULD be stored until the operation is
  complete. A hash over a random nonce has the entropy and meets the rest, but is not
  literally that wording. No browser or authenticator can tell the difference.
- **The statement** is the relying party id, request id, agent, the whole
  `CreateRequest` (goal, access, requested window), the chosen window, the destination
  and the request's expiry, in a length-prefixed encoding with test vectors, as
  `warden-request-v1` has. It needs the full hash: the 48-bit fingerprint can be
  collided by an agent, as the threat model says.

### What `webauthn-rs` 0.5.5 offers

Read from the source of `webauthn-rs`, `webauthn-rs-core` and `webauthn-rs-proto`
0.5.5. **There is no API for supplying a challenge.**

| Route | Finding |
|---|---|
| `start_passkey_authentication` | Takes only the passkeys. |
| `WebauthnCore::generate_challenge_authenticate` | Public, and calls the private `generate_challenge`, which always draws random bytes. Its builder has no challenge field. |
| `AuthenticationState.challenge` | `pub(crate)`, with no setter. |
| `danger-allow-state-serialisation` feature | Adds serde to `PasskeyAuthentication`. warden can serialize the state to JSON, replace `ast.challenge`, read it back, and set the public `options.public_key.challenge`. **This works, but rests on private field names**, not on an API. |
| A fork | A few lines, but `deny.toml` refuses unknown git sources, and warden would have to carry the security fixes of the library that checks approvals. No. |
| warden's own assertion check | No. That library exists so that warden does not write this. |

**Tested once, outside the repository**, with a throwaway program on 0.5.5 and the
software authenticator warden's tests use: with the swapped state the assertion
verifies, and with the original state it fails with `MismatchedChallenge`, so a swap
that goes wrong fails closed. Not tested: a real phone or a real browser. `warden.js`
just passes the challenge on, so it should not need a change. In the source of 0.6.2
([#120](https://github.com/pecheriere/warden/issues/120)) the type behind the field
changed but its name and base64url form did not; that was read, not run. Upstream
has not been asked for an API.

## What independent verification would need

| What | Where | Why |
|---|---|---|
| The statement's bytes and the nonce | Audit log | A digest alone does not say what was claimed, so the destination goes in whole, not only its digest. It holds no secret. |
| `authenticatorData`, `clientDataJSON`, signature, credential id | Audit log | The exact bytes, since the signature covers them. 280 bytes raw in the test. They cannot be replayed, as the challenge is used up. |
| Each passkey's public key | `passkey_enrolled`, and **a copy off the host** | The row is deleted when a passkey is removed. And the broker can enroll a key of its own, so a key read from the broker proves nothing. |
| The log itself | Off the host | Whoever controls the host can rewrite the whole chain. |

Attestation does not help: `start_passkey_registration` asks for none, so nothing
ties a public key to a real authenticator. The copy of the key is the only anchor,
and it is good only if the broker was clean when the key was enrolled.

The verifier, run away from the broker, recomputes the challenge from the statement
and checks that it equals the one in `clientDataJSON`, then the type, origin,
`rpIdHash` and the user present and verified flags, then the signature over
`authenticatorData ‖ SHA-256(clientDataJSON)` with a key from the kept copy, and that
no nonce repeats. Enrollment allows ES256 and RS256, so it needs both. The same
throwaway program checked an ES256 assertion this way with only the `p256` crate.

## The Pending page's replaced link

The statement must hold **no token and no token hash**. The owner approves a
request, not a link, and the request id survives a replacement.
`approval_link_replaced` deliberately holds neither, and this log should not start
to. The token stays bound in server state, as now, and nothing changes in the flow:
replacing drops the request's ceremonies, a ceremony on the old token is refused
before its assertion is checked, and an approval already past those checks finishes
first or fails on the token in its own update.

Three consequences for what a signature means:

- **A signature is not an approval that took effect.** A passkey signs before the
  broker sees the result, so a tap on a replaced link yields a valid signature over
  a real statement. An honest broker drops it; a compromised one can keep it.
- **Evidence written first can overstate.** It would go in with `approved`, before the
  final token check, so an approval that then loses to a replacement leaves valid
  evidence and an `error` entry. Whether access was given comes from the log's other
  entries, as today.
- **It does not separate the owner from a stolen prompt.** Someone with the owner's
  login and browser tools can
  [get a link and put a real prompt in front of them](../threat-model.md#accepted-residual-risks).
  A tap there signs a perfectly valid statement.

## What this protects against

This holds only with the kept keys, the shipped log and someone running the verifier.

- An approval record made up without a tap has no valid signature.
- A record changed afterwards (window, target, goal) no longer matches its signature.
- One tap cannot be claimed for a different approval.

A missing or bad signature is good evidence of tampering. A good one shows only that
the passkey signed, for warden's origin, a challenge the broker supplied.

## What it does not protect against

- **A compromised broker showing one thing and signing another.** The authenticator
  shows the relying party and signs opaque bytes. WebAuthn has no way to display the
  transaction: the current specification has no `txAuth` extension. The evidence would
  then look like proof against an owner who never saw that statement.
- **A broker that acts without logging.** A record is checked only if it exists.
  Catching a silent certificate takes the target's `sshd` logs.
- **A patient attacker.** Wait for one real approval, swap the statement, and also
  grant what the owner asked for, so the owner sees nothing odd at the time. That is valid evidence for
  the attacker's request, at the cost of one tap.
- **When it happened, and on which device.** The time in the entry is the broker's, and
  the broker picks the nonce, so freshness cannot be checked later. A synced passkey
  does not say which device signed, and a counter stuck at 0 does not reveal a clone.
- **A misleading goal,** or an owner who taps without reading.

## What it would cost

- **Migration: none.** The issue expected one, but ceremonies stay in memory and the
  evidence lives in the log. Passkeys that already exist need a command to print
  their public keys for the owner to copy.
- **Audit format: one new event**, written in the same `record` call as `approved`,
  and new fields on `passkey_enrolled` that are left out when empty, because lines
  must stay canonical. Old lines still verify. An older binary's `audit verify`
  refuses the new ones (`deny_unknown_fields`), as for any new event, so it needs a
  line in the upgrade notes. Each approval adds a few KB, more with a pinned CA. The
  verifier needs a pinned point where the evidence starts, or removing it passes as
  an old log.
- **Dependency: no fork**, but a `danger-` feature, a swap that depends on private
  names, a test that fails when they change, and a fresh look at each `webauthn-rs`
  upgrade.
- **Code:** the statement encoding and its test vectors, the swap, and the verifier
  with its parsing and two signature types. A few hundred lines (an estimate), in the
  approval path of a security broker.
- **The owner's time, for good:** copy each new public key off the host at enrollment
  and run the verifier. Without this, the rest proves nothing. Nothing changes on the
  approval page, so the owner sees no benefit there either.

## What to do instead

Ship the audit log and the targets' `sshd` logs off their hosts, as the [threat
model](../threat-model.md) already advises, and compare the key ids in the `sshd` logs
(`warden:<agent>:<grant id>`) with the `cert_issued` entries. It takes no new code, and
it catches the silent certificate that a signature cannot. It leaves one gap: a broker
that also writes a matching fake `approved` entry. That gap is what this design
would narrow.

## The decision

Accepted: not planned, with a sentence in the threat model saying that the signature
is deliberately not evidence, and why. To build it later, start by asking upstream for
an API, and use the JSON swap if they decline. It would make sense only for someone who
will keep the public keys off the host and run the verifier.
