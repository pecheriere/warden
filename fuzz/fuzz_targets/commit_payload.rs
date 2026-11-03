//! What the broker agrees to sign: the strict parser of a git commit. A payload it
//! accepts must never hold what would make a verifier read it differently.

#![no_main]

use libfuzzer_sys::fuzz_target;
use warden_broker::commit_signing::payload::parse;

fuzz_target!(|data: &[u8]| {
    if let Ok(commit) = parse(data) {
        assert!(data.starts_with(b"tree "));
        assert!(!data.contains(&0));
        assert_ne!(commit.tree, "");
        let headers = data
            .split(|b| *b == b'\n')
            .take_while(|line| !line.is_empty());
        for line in headers {
            assert!(!line.starts_with(b"gpgsig"));
        }
    }
});
