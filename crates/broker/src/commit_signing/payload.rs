//! The strict parser of what the broker agrees to sign: a git commit object as
//! git itself writes one, and nothing else.
//!
//! A verifier and a parser that disagree on a byte are how a signature comes to
//! cover something other than what was checked, so anything git would not have
//! written, or that another reader could take differently, is refused rather than
//! tidied up: a NUL anywhere, a header out of order or repeated, an unknown header,
//! a signature header already in the payload.

/// Longest `author` or `committer` value kept, in bytes: they go into the audit log.
const MAX_IDENT_BYTES: usize = 1024;

/// Most parents of a commit: their ids go into the audit log.
const MAX_PARENTS: usize = 64;

/// Longest value of the `encoding` header.
const MAX_ENCODING_BYTES: usize = 64;

/// Why a payload is not signed. The texts are fixed: nothing from the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayloadRefusal {
    /// A tag object: commit signing grants never sign tags.
    #[error("this is a tag object, and a commit signing grant signs commits only")]
    TagObject,
    /// Not the start of a commit object.
    #[error("not a git commit: it must start with a tree header")]
    NotACommit,
    /// Something a commit written by git never contains.
    #[error("not a well-formed git commit: {0}")]
    Malformed(&'static str),
    /// Larger than the broker signs.
    #[error("the commit is too large to sign")]
    TooLarge,
}

/// Which object format the commit belongs to, from the length of its ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    /// 40 hex digits.
    Sha1,
    /// 64 hex digits.
    Sha256,
}

impl ObjectFormat {
    const fn hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    /// The header git keeps the signature in.
    pub(super) const fn signature_header(self) -> &'static str {
        match self {
            Self::Sha1 => "gpgsig",
            Self::Sha256 => "gpgsig-sha256",
        }
    }
}

/// What a payload that parsed says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommit {
    /// Object format of the repository the commit belongs to.
    pub format: ObjectFormat,
    /// Tree id.
    pub tree: String,
    /// Parent ids, in order.
    pub parents: Vec<String>,
    /// The `author` header's value.
    pub author: String,
    /// Offset of the blank line that ends the headers. The signature header goes
    /// right there.
    pub(super) end_of_headers: usize,
}

fn is_object_id(text: &str, format: ObjectFormat) -> bool {
    text.len() == format.hex_len()
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `value` is `Name <email> seconds +hhmm`, as git writes an identity.
fn is_ident(value: &str) -> bool {
    if value.len() > MAX_IDENT_BYTES || value.chars().any(char::is_control) {
        return false;
    }
    let Some((who, when)) = value.rsplit_once("> ") else {
        return false;
    };
    let Some((name, email)) = who.split_once(" <") else {
        return false;
    };
    let plain = |part: &str| !part.contains(['<', '>']);
    if name.is_empty() || !plain(name) || !plain(email) {
        return false;
    }
    let Some((seconds, zone)) = when.split_once(' ') else {
        return false;
    };
    let all_digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let no_padding = seconds == "0" || !seconds.starts_with('0');
    let zone_ok = zone.len() == 5
        && (zone.starts_with('+') || zone.starts_with('-'))
        && zone.get(1..).is_some_and(all_digits);
    all_digits(seconds) && seconds.len() <= 20 && no_padding && zone_ok
}

/// The next `\n`-terminated line of `text` from `at`, without its newline, and
/// where the line after it starts.
fn line_at(text: &[u8], at: usize) -> Result<(&[u8], usize), PayloadRefusal> {
    let rest = text.get(at..).unwrap_or_default();
    let end = rest
        .iter()
        .position(|b| *b == b'\n')
        .ok_or(PayloadRefusal::Malformed("the headers do not end"))?;
    Ok((&rest[..end], at + end + 1))
}

/// A header line as text: headers are UTF-8 even when the message is not.
fn header_text(line: &[u8]) -> Result<&str, PayloadRefusal> {
    std::str::from_utf8(line).map_err(|_| PayloadRefusal::Malformed("a header is not UTF-8"))
}

/// Parse `payload` as a git commit, or say why it is not signed.
///
/// # Errors
/// [`PayloadRefusal`], for anything but a commit as git writes one.
pub fn parse(payload: &[u8]) -> Result<ParsedCommit, PayloadRefusal> {
    if payload.len() > warden_broker_proto::commit_signing::MAX_PAYLOAD_BYTES {
        return Err(PayloadRefusal::TooLarge);
    }
    if payload.starts_with(b"object ") {
        return Err(PayloadRefusal::TagObject);
    }
    if !payload.starts_with(b"tree ") {
        return Err(PayloadRefusal::NotACommit);
    }
    // Git's own readers stop at a NUL, so what follows one would be signed unseen.
    if payload.contains(&0) {
        return Err(PayloadRefusal::Malformed("it contains a NUL byte"));
    }
    let (line, mut at) = line_at(payload, 0)?;
    let tree = header_text(line)?
        .strip_prefix("tree ")
        .ok_or(PayloadRefusal::NotACommit)?;
    let format = match tree.len() {
        40 => ObjectFormat::Sha1,
        64 => ObjectFormat::Sha256,
        _ => {
            return Err(PayloadRefusal::Malformed(
                "the tree id has the wrong length",
            ));
        }
    };
    if !is_object_id(tree, format) {
        return Err(PayloadRefusal::Malformed(
            "the tree id is not lowercase hex",
        ));
    }
    let tree = tree.to_owned();

    let mut parents = Vec::new();
    let mut line;
    loop {
        (line, at) = line_at(payload, at)?;
        let Some(parent) = header_text(line)?.strip_prefix("parent ") else {
            break;
        };
        if !is_object_id(parent, format) {
            return Err(PayloadRefusal::Malformed("a parent id is not valid"));
        }
        parents.push(parent.to_owned());
        if parents.len() > MAX_PARENTS {
            return Err(PayloadRefusal::Malformed("it has too many parents"));
        }
    }

    let author = header_text(line)?
        .strip_prefix("author ")
        .filter(|value| is_ident(value))
        .ok_or(PayloadRefusal::Malformed("the author header is not valid"))?
        .to_owned();
    (line, at) = line_at(payload, at)?;
    header_text(line)?
        .strip_prefix("committer ")
        .filter(|value| is_ident(value))
        .ok_or(PayloadRefusal::Malformed(
            "the committer header is not valid",
        ))?;

    let end_of_headers = extra_headers(payload, at, format)?;
    Ok(ParsedCommit {
        format,
        tree,
        parents,
        author,
        end_of_headers,
    })
}

/// Check what may follow the committer, in the order git writes it: at most one
/// `encoding`, then `mergetag` blocks, then the blank line, whose offset this
/// returns. A signature header here would be left out by whoever verifies, so
/// the signature would not cover what it seems to.
fn extra_headers(
    payload: &[u8],
    from: usize,
    format: ObjectFormat,
) -> Result<usize, PayloadRefusal> {
    let mut at = from;
    let (mut line, mut next) = line_at(payload, at)?;
    if let Some(value) = line.strip_prefix(b"encoding ") {
        let plain = value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
        if value.is_empty() || value.len() > MAX_ENCODING_BYTES || !plain {
            return Err(PayloadRefusal::Malformed(
                "the encoding header is not valid",
            ));
        }
        at = next;
        (line, next) = line_at(payload, at)?;
    }
    while let Some(value) = line.strip_prefix(b"mergetag ") {
        let object = header_text(value)?
            .strip_prefix("object ")
            .filter(|id| is_object_id(id, format));
        if object.is_none() {
            return Err(PayloadRefusal::Malformed(
                "the mergetag header is not valid",
            ));
        }
        at = next;
        (line, next) = line_at(payload, at)?;
        // A multi-line header's lines start with a space.
        while line.first() == Some(&b' ') {
            at = next;
            (line, next) = line_at(payload, at)?;
        }
    }
    if line.is_empty() {
        Ok(at)
    } else {
        Err(PayloadRefusal::Malformed("it has an unexpected header"))
    }
}

#[cfg(test)]
mod tests {
    use super::{ObjectFormat, PayloadRefusal, parse};

    const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    const PARENT: &str = "1111111111111111111111111111111111111111";
    const AUTHOR: &str = "build-agent <build-agent@example.com> 1800000000 +0000";

    fn commit(headers_after_committer: &str, message: &str) -> Vec<u8> {
        format!(
            "tree {TREE}\nparent {PARENT}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\
             {headers_after_committer}\n{message}"
        )
        .into_bytes()
    }

    fn malformed(payload: &[u8]) {
        assert!(
            matches!(parse(payload), Err(PayloadRefusal::Malformed(_))),
            "{:?}: {:?}",
            String::from_utf8_lossy(payload),
            parse(payload)
        );
    }

    #[test]
    fn a_plain_commit_says_what_it_is() {
        let payload = commit("", "Fix the thing\n");
        let parsed = parse(&payload).unwrap();
        assert_eq!(parsed.format, ObjectFormat::Sha1);
        assert_eq!(parsed.tree, TREE);
        assert_eq!(parsed.parents, [PARENT]);
        assert_eq!(parsed.author, AUTHOR);
        assert_eq!(&payload[parsed.end_of_headers..][..1], b"\n");
    }

    #[test]
    fn a_root_merge_and_empty_message_are_commits() {
        let root = format!("tree {TREE}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\n");
        assert_eq!(parse(root.as_bytes()).unwrap().parents, [] as [String; 0]);
        let merge = format!(
            "tree {TREE}\nparent {PARENT}\nparent {PARENT}\nauthor {AUTHOR}\n\
             committer {AUTHOR}\n\nmerge\n"
        );
        assert_eq!(parse(merge.as_bytes()).unwrap().parents.len(), 2);
    }

    #[test]
    fn a_sha256_commit_is_a_commit_but_ids_cannot_mix() {
        let tree = "a".repeat(64);
        let good = format!("tree {tree}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\nm\n");
        assert_eq!(parse(good.as_bytes()).unwrap().format, ObjectFormat::Sha256);
        malformed(
            format!("tree {tree}\nparent {PARENT}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\nm\n")
                .as_bytes(),
        );
    }

    #[test]
    fn the_message_may_be_any_bytes_but_nul() {
        let mut payload = commit("encoding ISO-8859-1\n", "");
        payload.extend_from_slice(b"caf\xe9\r\n");
        assert!(parse(&payload).is_ok());
        payload.extend_from_slice(b"\0hidden");
        malformed(&payload);
    }

    #[test]
    fn a_tag_object_is_named_and_refused() {
        let tag = format!("object {PARENT}\ntype commit\ntag v1.0.0\ntagger {AUTHOR}\n\nrelease\n");
        assert_eq!(parse(tag.as_bytes()), Err(PayloadRefusal::TagObject));
    }

    #[test]
    fn anything_else_is_not_a_commit() {
        for payload in [
            &b""[..],
            b"certificate version 0.1\npusher x\n\n",
            b" tree abc",
            b"TREE abc\n",
            b"hello",
            b"\xff\xfe",
        ] {
            assert_eq!(parse(payload), Err(PayloadRefusal::NotACommit));
        }
    }

    #[test]
    fn headers_out_of_order_or_repeated_are_refused() {
        for payload in [
            format!("tree {TREE}\ncommitter {AUTHOR}\nauthor {AUTHOR}\n\nm\n"),
            format!("tree {TREE}\nauthor {AUTHOR}\nparent {PARENT}\ncommitter {AUTHOR}\n\nm\n"),
            format!("tree {TREE}\nauthor {AUTHOR}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\nm\n"),
            format!("tree {TREE}\ntree {TREE}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\nm\n"),
            format!("tree {TREE}\nauthor {AUTHOR}\ncommitter {AUTHOR}\ncommitter {AUTHOR}\n\nm\n"),
            format!("tree {TREE}\nauthor {AUTHOR}\n\nm\n"),
            format!("tree {TREE}\n\nm\n"),
        ] {
            malformed(payload.as_bytes());
        }
    }

    #[test]
    fn a_signature_already_in_the_payload_is_refused() {
        // A verifier drops these headers before checking, so a signature over them
        // would cover something the verifier never looks at.
        malformed(&commit(
            "gpgsig -----BEGIN SSH SIGNATURE-----\n abc\n",
            "m\n",
        ));
        malformed(&commit("gpgsig-sha256 x\n", "m\n"));
    }

    #[test]
    fn unknown_or_misplaced_extra_headers_are_refused() {
        malformed(&commit("change-id abc\n", "m\n"));
        malformed(&commit(" continuation\n", "m\n"));
        malformed(&commit("encoding UTF-8\nencoding UTF-8\n", "m\n"));
        malformed(&commit(
            &format!("mergetag object {PARENT}\n type commit\nencoding UTF-8\n"),
            "m\n",
        ));
        malformed(&commit("encoding bad value\n", "m\n"));
        malformed(&commit("encoding \n", "m\n"));
        malformed(&commit("mergetag type commit\n", "m\n"));
    }

    #[test]
    fn a_mergetag_is_part_of_a_merge() {
        let block = format!(
            "encoding UTF-8\nmergetag object {PARENT}\n type commit\n tag v1\n tagger {AUTHOR}\n \n msg\n"
        );
        assert!(parse(&commit(&block, "merge\n")).is_ok());
    }

    #[test]
    fn identities_must_look_like_git_wrote_them() {
        for ident in [
            "",
            "no email 1 +0000",
            "<a@b> 1 +0000",
            "Name <a@b>",
            "Name <a@b> 1",
            "Name <a@b> x +0000",
            "Name <a@b> 01 +0000",
            "Name <a@b> 1 0000",
            "Name <a@b> 1 +00",
            "Name <a@b> 1 +abcd",
            "Na<me <a@b> 1 +0000",
            "Name <a<b@c> 1 +0000",
            "Name <a@b> 1 +0000 extra",
            "Na\rme <a@b> 1 +0000",
            "Na\u{7f}me <a@b> 1 +0000",
        ] {
            malformed(format!("tree {TREE}\nauthor {ident}\ncommitter {AUTHOR}\n\nm\n").as_bytes());
        }
        let long = format!("{} <a@b> 1 +0000", "n".repeat(1024));
        malformed(format!("tree {TREE}\nauthor {long}\ncommitter {AUTHOR}\n\nm\n").as_bytes());
        // An empty email and the epoch are what git can write.
        assert!(
            parse(format!("tree {TREE}\nauthor N <> 0 -0130\ncommitter {AUTHOR}\n\n").as_bytes())
                .is_ok()
        );
    }

    #[test]
    fn a_header_that_is_not_utf8_is_refused() {
        let mut payload = format!("tree {TREE}\nauthor ").into_bytes();
        payload.extend_from_slice(b"caf\xe9 <a@b> 1 +0000\n");
        payload.extend_from_slice(format!("committer {AUTHOR}\n\nm\n").as_bytes());
        malformed(&payload);
    }

    #[test]
    fn ids_must_be_lowercase_hex_of_the_right_length() {
        let upper = TREE.to_uppercase();
        for bad in [upper.as_str(), "abc", &"g".repeat(40), &"a".repeat(41)] {
            malformed(format!("tree {bad}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\nm\n").as_bytes());
        }
        malformed(
            format!("tree {TREE}\nparent abc\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\nm\n")
                .as_bytes(),
        );
    }

    #[test]
    fn headers_that_never_end_are_refused() {
        malformed(format!("tree {TREE}").as_bytes());
        malformed(format!("tree {TREE}\nauthor {AUTHOR}\ncommitter {AUTHOR}").as_bytes());
        malformed(format!("tree {TREE}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n").as_bytes());
    }

    #[test]
    fn too_many_parents_or_too_many_bytes_are_refused() {
        let parents = format!("parent {PARENT}\n").repeat(65);
        malformed(
            format!("tree {TREE}\n{parents}author {AUTHOR}\ncommitter {AUTHOR}\n\nm\n").as_bytes(),
        );
        let mut huge = commit("", "");
        huge.resize(
            warden_broker_proto::commit_signing::MAX_PAYLOAD_BYTES + 1,
            b'x',
        );
        assert_eq!(parse(&huge), Err(PayloadRefusal::TooLarge));
    }
}
