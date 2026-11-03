//! Rebuild when migrations change, since `sqlx::migrate!` embeds them.
//!
//! With `WARDEN_OPENSSL_PINNED` set, as every build that ships sets it, fail on any
//! OpenSSL but the release in `scripts/openssl-pin.env`. A build pointed nowhere would
//! otherwise link whatever the system has, and work.

use std::{env, fs};

const PIN_FILE: &str = "../../scripts/openssl-pin.env";

fn main() {
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-env-changed=WARDEN_OPENSSL_PINNED");
    if env::var_os("WARDEN_OPENSSL_PINNED").is_some() {
        println!("cargo:rerun-if-changed={PIN_FILE}");
        if let Err(message) = check_pinned_openssl() {
            panic!("{message}");
        }
    }
}

fn check_pinned_openssl() -> Result<(), String> {
    let pin = fs::read_to_string(PIN_FILE).map_err(|error| format!("{PIN_FILE}: {error}"))?;
    let version = pin
        .lines()
        .find_map(|line| line.strip_prefix("WARDEN_OPENSSL_VERSION="))
        .ok_or_else(|| format!("{PIN_FILE} names no version"))?;
    let expected = version_number(version)?;
    // From `openssl-sys`, which reads it from the headers of the OpenSSL it found.
    let found = env::var("DEP_OPENSSL_VERSION_NUMBER")
        .map_err(|error| format!("openssl-sys reported no version: {error}"))?;
    let found = u64::from_str_radix(&found, 16)
        .map_err(|error| format!("openssl-sys reported version {found}: {error}"))?;
    if found == expected {
        Ok(())
    } else {
        Err(format!(
            "this build links OpenSSL {found:#x}, and the pinned {version} is {expected:#x}: \
             build it with scripts/build-openssl.sh and set OPENSSL_DIR and OPENSSL_STATIC"
        ))
    }
}

/// OpenSSL's `OPENSSL_VERSION_NUMBER` for a release: `MNN00PP0` in hexadecimal.
fn version_number(version: &str) -> Result<u64, String> {
    let parts = version
        .split('.')
        .map(str::parse)
        .collect::<Result<Vec<u64>, _>>()
        .map_err(|error| format!("version {version}: {error}"))?;
    match parts[..] {
        [major, minor, patch] => Ok((major << 28) | (minor << 20) | (patch << 4)),
        _ => Err(format!("version {version} is not major.minor.patch")),
    }
}
