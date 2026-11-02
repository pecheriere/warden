//! `Cargo.lock` stays free of the crate versions RUSTSEC-2023-0071 and
//! RUSTSEC-2026-0387 were cleared of.
//!
//! `cargo deny` cannot check this: it follows the features actually enabled.
//! `ssh-key` 0.6's `std` feature locks these crates through its weak features
//! (`rsa?/std`, `p256?/std`) without compiling them, which `cargo deny` accepts
//! while scanners that read the lockfile, like Scorecard, report them.

/// Crate versions that must not be in the lockfile, and what brings them in.
const BANNED: [(&str, &str, &str); 3] = [
    (
        "crypto-bigint",
        "0.5.",
        "ssh-key 0.6's std or p256 feature, or a crate turning them on",
    ),
    (
        "rsa",
        "0.9.",
        "ssh-key 0.6's std or rsa feature, or a crate turning them on",
    ),
    (
        "ssh-agent-lib",
        "",
        "ssh-agent-lib itself: see ssh_agent.rs",
    ),
];

#[test]
fn lockfile_has_no_cleared_crate_versions() {
    let lock = include_str!("../../../Cargo.lock");
    // `name = "x"` is always followed by `version = "y"`.
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        let Some(name) = line
            .strip_prefix("name = \"")
            .and_then(|rest| rest.strip_suffix('"'))
        else {
            continue;
        };
        let version = lines
            .next()
            .and_then(|l| l.strip_prefix("version = \""))
            .unwrap_or_else(|| panic!("no version after {line}"));
        for (banned, prefix, why) in BANNED {
            assert!(
                name != banned || !version.starts_with(prefix),
                "Cargo.lock has {name} {version}, brought in by {why}"
            );
        }
    }
}

/// The check itself sees packages: its names are spelled as the lockfile does.
#[test]
fn lockfile_lists_packages_the_way_the_check_reads_them() {
    let lock = include_str!("../../../Cargo.lock");
    assert!(lock.contains("name = \"crypto-bigint\"\nversion = \""));
    assert!(lock.contains("name = \"rsa\"\nversion = \""));
}
