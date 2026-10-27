//! Signed agent requests, protocol `warden-request-v1`.
//!
//! An agent signs every API request with its SSH key (an SSHSIG over the
//! [`canonical_message`] of the request, namespace [`NAMESPACE`]) and sends
//! the signature and its inputs in the `Warden-*` headers. The complete
//! client protocol is in `docs/agent-protocol.md`; the test vectors it
//! embeds are checked here.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{AgentName, ParseError, is_lower_hex, random_hex16};

/// Identifier of the signing protocol, as listed by `GET /v1/info` and as
/// the first line of every canonical message.
pub const PROTOCOL: &str = "warden-request-v1";

/// SSHSIG namespace of request signatures (`ssh-keygen -Y sign -n`).
pub const NAMESPACE: &str = PROTOCOL;

/// Header naming the agent that signed the request.
pub const AGENT_HEADER: &str = "Warden-Agent";

/// Header with the signing time: Unix seconds, plain decimal.
pub const TIMESTAMP_HEADER: &str = "Warden-Timestamp";

/// Header with the request's single-use nonce: 32 lowercase hex characters.
pub const NONCE_HEADER: &str = "Warden-Nonce";

/// Header with the signature: standard base64 of the binary SSHSIG blob.
pub const SIGNATURE_HEADER: &str = "Warden-Signature";

/// Largest accepted difference between the broker's clock and
/// `Warden-Timestamp`, in seconds, either way.
pub const MAX_CLOCK_SKEW_SECS: i64 = 60;

/// Longest accepted request target (path and query), in bytes.
pub const MAX_TARGET_LEN: usize = 8192;

/// Single-use request nonce: 32 lowercase hex characters (16 random bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Nonce(String);

impl Nonce {
    /// A fresh nonce from 16 bytes of OS randomness.
    ///
    /// # Panics
    ///
    /// Panics if the operating system cannot provide randomness, which leaves
    /// no safe way to continue.
    #[must_use]
    pub fn random() -> Self {
        Self(random_hex16())
    }
}

impl TryFrom<String> for Nonce {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_lower_hex(&value, 32) {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "nonce",
                "must be 32 lowercase hex characters",
            ))
        }
    }
}
string_newtype!(Nonce);

/// Audience of signed requests: a broker's own random identifier, 32
/// lowercase hex characters, published at `GET /v1/info`. A signature names
/// it, so a request signed for one broker is refused by any other.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Audience(String);

impl Audience {
    /// A fresh audience from 16 bytes of OS randomness.
    ///
    /// # Panics
    ///
    /// Panics if the operating system cannot provide randomness, which leaves
    /// no safe way to continue.
    #[must_use]
    pub fn random() -> Self {
        Self(random_hex16())
    }
}

impl TryFrom<String> for Audience {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_lower_hex(&value, 32) {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "audience",
                "must be 32 lowercase hex characters",
            ))
        }
    }
}
string_newtype!(Audience);

/// Parse a `Warden-Timestamp` value: Unix seconds as plain decimal digits,
/// no sign, no leading zero (except `0` itself), within `i64`. Any other
/// spelling is refused, so the value signed is the value parsed.
///
/// # Errors
/// If `value` is not in that form.
pub fn parse_timestamp(value: &str) -> Result<i64, ParseError> {
    let err = || {
        ParseError::new(
            "timestamp",
            "must be Unix seconds in plain decimal, without sign or leading zero",
        )
    };
    let canonical = !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'));
    if !canonical {
        return Err(err());
    }
    value.parse().map_err(|_| err())
}

/// The inputs of a signed request's canonical message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedRequestParts<'a> {
    /// The broker's audience.
    pub audience: &'a Audience,
    /// The agent signing, as in `Warden-Agent`.
    pub agent: &'a AgentName,
    /// HTTP method exactly as on the request line, for example `GET`.
    pub method: &'a str,
    /// Path and query exactly as on the request line, for example
    /// `/v1/requests/<id>?wait=30`.
    pub target: &'a str,
    /// Unix seconds, as in `Warden-Timestamp`.
    pub timestamp: i64,
    /// The request's nonce, as in `Warden-Nonce`.
    pub nonce: &'a Nonce,
    /// SHA-256 of the exact body bytes; of the empty string when there is
    /// no body.
    pub body_sha256: [u8; 32],
}

/// An RFC 9110 token character, as allowed in a method name.
const fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// The message an agent signs for a request: eight lines, each ended by
/// `\n`, with no other whitespace:
///
/// ```text
/// warden-request-v1
/// audience:<audience>
/// agent:<agent name>
/// method:<METHOD>
/// target:<path and query>
/// timestamp:<Unix seconds>
/// nonce:<nonce>
/// body-sha256:<lowercase hex SHA-256 of the body>
/// ```
///
/// # Errors
/// If the method is not an HTTP token, the target is not an origin-form
/// request target (it must start with `/`, be at most [`MAX_TARGET_LEN`]
/// bytes of visible ASCII and carry no fragment), or the timestamp is
/// negative. Such a field could not appear on a request line, and a
/// newline in it could forge another line of the message.
pub fn canonical_message(parts: &SignedRequestParts<'_>) -> Result<String, ParseError> {
    if parts.method.is_empty() || !parts.method.bytes().all(is_tchar) {
        return Err(ParseError::new("method", "must be an HTTP token"));
    }
    let target_ok = parts.target.starts_with('/')
        && parts.target.len() <= MAX_TARGET_LEN
        && parts
            .target
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'#');
    if !target_ok {
        return Err(ParseError::new(
            "target",
            "must be a path and query of visible ASCII starting with /",
        ));
    }
    if parts.timestamp < 0 {
        return Err(ParseError::new("timestamp", "must not be negative"));
    }
    let message = format!(
        "{PROTOCOL}\naudience:{}\nagent:{}\nmethod:{}\ntarget:{}\ntimestamp:{}\nnonce:{}\nbody-sha256:{}\n",
        parts.audience,
        parts.agent,
        parts.method,
        parts.target,
        parts.timestamp,
        parts.nonce,
        hex::encode(parts.body_sha256),
    );
    Ok(message)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

    use super::{
        Audience, MAX_TARGET_LEN, Nonce, PROTOCOL, SignedRequestParts, canonical_message,
        parse_timestamp,
    };
    use crate::{AgentName, CreateRequest, fingerprint};

    /// The shared test vectors; `docs/agent-protocol.md` embeds the same.
    const FIXTURE: &str = include_str!("../tests/fixtures/signing-v1.json");
    const DOC: &str = include_str!("../../../docs/agent-protocol.md");
    const TEST_KEY: &str =
        include_str!("../tests/fixtures/throwaway-test-only-signing-ed25519.key");

    #[derive(Deserialize)]
    struct Fixture {
        protocol: String,
        public_key: String,
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        audience: String,
        agent: String,
        method: String,
        target: String,
        timestamp: String,
        nonce: String,
        body: String,
        body_sha256: String,
        message: String,
        message_sha256: String,
        signature: String,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(FIXTURE).unwrap()
    }

    /// A `Warden-Signature` value as the armored form `ssh-keygen` reads.
    fn armor(header: &str) -> String {
        let lines: Vec<&str> = header
            .as_bytes()
            .chunks(70)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
            lines.join("\n")
        )
    }

    /// The armored signature as a `Warden-Signature` value.
    fn unarmor(pem: &str) -> String {
        pem.lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>()
    }

    fn sample() -> (Audience, AgentName, Nonce) {
        (
            Audience::try_from("40ad20029e94984d193159667b296d8a".to_owned()).unwrap(),
            AgentName::try_from("build-bot".to_owned()).unwrap(),
            Nonce::try_from("ee517b64804ef8916b8386eeaa436de0".to_owned()).unwrap(),
        )
    }

    fn parts<'a>(
        (audience, agent, nonce): &'a (Audience, AgentName, Nonce),
        method: &'a str,
        target: &'a str,
    ) -> SignedRequestParts<'a> {
        SignedRequestParts {
            audience,
            agent,
            method,
            target,
            timestamp: 1_793_091_600,
            nonce,
            body_sha256: Sha256::digest(b"").into(),
        }
    }

    #[test]
    fn canonical_message_matches_doc_vector() {
        let fixture = fixture();
        assert_eq!(fixture.protocol, PROTOCOL);
        let public = PublicKey::from_openssh(&fixture.public_key).unwrap();
        let private = PrivateKey::from_openssh(TEST_KEY).unwrap();
        assert_eq!(private.public_key().key_data(), public.key_data());
        assert_eq!(fixture.vectors.len(), 2);
        for v in &fixture.vectors {
            let audience = Audience::try_from(v.audience.clone()).unwrap();
            let agent = AgentName::try_from(v.agent.clone()).unwrap();
            let nonce = Nonce::try_from(v.nonce.clone()).unwrap();
            let body_sha256: [u8; 32] = Sha256::digest(v.body.as_bytes()).into();
            assert_eq!(hex::encode(body_sha256), v.body_sha256, "{}", v.name);
            let message = canonical_message(&SignedRequestParts {
                audience: &audience,
                agent: &agent,
                method: &v.method,
                target: &v.target,
                timestamp: parse_timestamp(&v.timestamp).unwrap(),
                nonce: &nonce,
                body_sha256,
            })
            .unwrap();
            assert_eq!(message, v.message, "{}", v.name);
            assert_eq!(
                hex::encode(Sha256::digest(message.as_bytes())),
                v.message_sha256,
                "{}",
                v.name
            );

            // The recorded signature (made by `ssh-keygen -Y sign`) verifies,
            // and Ed25519 being deterministic, signing again reproduces it.
            let recorded = SshSig::from_pem(armor(&v.signature)).unwrap();
            assert_eq!(recorded.hash_alg(), HashAlg::Sha512, "{}", v.name);
            public
                .verify(PROTOCOL, message.as_bytes(), &recorded)
                .unwrap();
            let fresh = private
                .sign(PROTOCOL, HashAlg::Sha512, message.as_bytes())
                .unwrap();
            assert_eq!(
                unarmor(&fresh.to_pem(LineEnding::LF).unwrap()),
                v.signature,
                "{}",
                v.name
            );
            // The signature is bound to the namespace and to every byte.
            assert!(
                public
                    .verify("file", message.as_bytes(), &recorded)
                    .is_err()
            );
            let tampered = message.replace("timestamp:1793091600", "timestamp:1793091601");
            assert!(
                public
                    .verify(PROTOCOL, tampered.as_bytes(), &recorded)
                    .is_err()
            );
        }
    }

    #[test]
    fn doc_embeds_the_fixture_vectors() {
        let fixture = fixture();
        assert!(DOC.contains("Protocol version warden-request-v1"));
        assert!(DOC.contains(&fixture.public_key));
        for v in &fixture.vectors {
            for value in [
                &v.message,
                &v.message_sha256,
                &v.body_sha256,
                &v.signature,
                &v.body,
            ] {
                assert!(
                    DOC.contains(value.as_str()),
                    "{}: doc lacks {value}",
                    v.name
                );
            }
        }
        // The fingerprint the doc shows for the first vector's request.
        let first = &fixture.vectors[0];
        let agent = AgentName::try_from(first.agent.clone()).unwrap();
        let request: CreateRequest = serde_json::from_str(&first.body).unwrap();
        assert_eq!(serde_json::to_string(&request).unwrap(), first.body);
        let shown = format!(r#""fingerprint":"{}""#, fingerprint(&agent, &request));
        assert!(DOC.contains(&shown), "doc lacks {shown}");
    }

    #[test]
    fn canonical_message_rejects_newlines_in_fields() {
        let ids = sample();
        assert!(canonical_message(&parts(&ids, "GET", "/v1/grants")).is_ok());
        for (method, target) in [
            ("GET\n", "/v1/grants"),
            ("GET", "/v1/grants\nnonce:00"),
            ("GET", "/v1/grants\r"),
            ("G\rET", "/v1/grants"),
            ("GET", "/v1/grants?x=\u{0}"),
        ] {
            assert!(
                canonical_message(&parts(&ids, method, target)).is_err(),
                "{method:?} {target:?} accepted"
            );
        }
        // The identifiers cannot carry a newline either.
        assert!(Audience::try_from(format!("{}\n", "a".repeat(31))).is_err());
        assert!(Nonce::try_from(format!("{}\n", "a".repeat(31))).is_err());
        assert!(AgentName::try_from("bot\n".to_owned()).is_err());
    }

    #[test]
    fn canonical_message_rejects_malformed_method_and_target() {
        let ids = sample();
        for (method, target) in [
            ("", "/v1/grants"),
            ("GET POST", "/v1/grants"),
            ("GET:", "/v1/grants"),
            ("GET", ""),
            ("GET", "v1/grants"),
            ("GET", "https://warden.example/v1/grants"),
            ("GET", "/v1/grants with space"),
            ("GET", "/v1/grants#frag"),
            ("GET", "/v1/gr\u{e9}nts"),
            ("GET", "/v1/grants\t"),
        ] {
            assert!(
                canonical_message(&parts(&ids, method, target)).is_err(),
                "{method:?} {target:?} accepted"
            );
        }
        let long = format!("/{}", "a".repeat(MAX_TARGET_LEN - 1));
        assert!(canonical_message(&parts(&ids, "GET", &long)).is_ok());
        let longer = format!("{long}a");
        assert!(canonical_message(&parts(&ids, "GET", &longer)).is_err());
        let mut negative = parts(&ids, "GET", "/v1/grants");
        negative.timestamp = -1;
        assert!(canonical_message(&negative).is_err());
    }

    #[test]
    fn canonical_message_keeps_target_and_method_as_sent() {
        let ids = sample();
        let message =
            canonical_message(&parts(&ids, "PATCH", "/v1/a%2Fb/?q=%20x&y=&wait=30")).unwrap();
        assert!(message.contains("\nmethod:PATCH\n"));
        assert!(message.contains("\ntarget:/v1/a%2Fb/?q=%20x&y=&wait=30\n"));
        assert!(message.starts_with("warden-request-v1\naudience:"));
        assert!(message.ends_with(
            "\nbody-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        ));
        assert_eq!(message.lines().count(), 8);
    }

    #[test]
    fn nonce_and_audience_are_32_lowercase_hex() {
        for ok in ["0".repeat(32), "abcdef0123456789".repeat(2)] {
            assert!(Nonce::try_from(ok.clone()).is_ok());
            assert!(Audience::try_from(ok).is_ok());
        }
        for bad in [
            String::new(),
            "a".repeat(31),
            "a".repeat(33),
            "A".repeat(32),
            "g".repeat(32),
            format!(" {}", "a".repeat(31)),
        ] {
            assert!(Nonce::try_from(bad.clone()).is_err(), "{bad:?}");
            assert!(Audience::try_from(bad).is_err());
        }
        assert!(serde_json::from_str::<Audience>("\"zz\"").is_err());
        let (a, b) = (Nonce::random(), Nonce::random());
        assert_ne!(a, b);
        assert!(Nonce::try_from(a.as_str().to_owned()).is_ok());
        let audience = Audience::random();
        assert!(Audience::try_from(audience.as_str().to_owned()).is_ok());
        assert_ne!(audience, Audience::random());
    }

    #[test]
    fn timestamp_is_plain_decimal_seconds() {
        assert_eq!(parse_timestamp("1793091600").unwrap(), 1_793_091_600);
        assert_eq!(parse_timestamp("0").unwrap(), 0);
        assert_eq!(parse_timestamp("9223372036854775807").unwrap(), i64::MAX);
        for bad in [
            "",
            "-1",
            "+1",
            "01793091600",
            "1793091600.0",
            " 1793091600",
            "1793091600\n",
            "1e9",
            "9223372036854775808",
            "１",
        ] {
            assert!(parse_timestamp(bad).is_err(), "{bad:?} accepted");
        }
    }
}
