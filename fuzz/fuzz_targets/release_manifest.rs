//! The manifest the broker signs for a release: what it accepts must be exactly
//! what its rules allow, whatever the agent sends.
//!
//! Input: the manifest, as sent. The release is fixed to version `1.2.3` and the
//! manifest to the name `warden-1.2.3-SHA256SUMS`, which the seed matches.
//! Properties: `check` never panics; an input it accepts is at most 64 KiB, ends
//! with a line feed, has no carriage return, and each of its lines is 64 lowercase
//! hex digits, two spaces and a name that is unique, a plain file name or an image
//! reference tagged `1.2.3`; and the same bytes under another name are refused.

#![no_main]

use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use warden_broker::signed::fuzzing::manifest_accepted;

const VERSION: &str = "1.2.3";
const NAME: &str = "warden-1.2.3-SHA256SUMS";

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-')
}

fn is_file_name(name: &str) -> bool {
    !matches!(name, "" | "." | "..") && name.bytes().all(is_name_byte)
}

fn is_image(name: &str) -> bool {
    let Some((path, tag)) = name.rsplit_once(':') else {
        return false;
    };
    let segments: Vec<&str> = path.split('/').collect();
    tag == VERSION
        && segments.len() >= 2
        && segments.iter().all(|s| {
            !matches!(*s, "" | "." | "..")
                && s.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                })
        })
}

fuzz_target!(|data: &[u8]| {
    let accepted = manifest_accepted(NAME, VERSION, NAME, data);
    assert!(!manifest_accepted(NAME, VERSION, "other-SHA256SUMS", data));
    if !accepted {
        return;
    }
    assert!(data.len() <= 65_536);
    let text = std::str::from_utf8(data).expect("accepted text is UTF-8");
    assert!(!text.contains('\r'));
    let lines = text
        .strip_suffix('\n')
        .expect("accepted text ends with a line feed");
    let mut names = HashSet::new();
    for line in lines.split('\n') {
        let (digest, rest) = line.split_at(64);
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let name = rest
            .strip_prefix("  ")
            .expect("two spaces follow the digest");
        assert!(is_file_name(name) || is_image(name));
        assert!(names.insert(name), "a name appears once");
    }
    assert!(!names.is_empty());
});
