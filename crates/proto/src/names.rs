//! Validated names and the goal text: agent, target, secret and Unix user
//! names, and the purpose of a request.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{ParseError, check_free_text};

fn is_name(s: &str, first: impl Fn(u8) -> bool, rest: impl Fn(u8) -> bool) -> bool {
    let bytes = s.as_bytes();
    match bytes.split_first() {
        Some((&head, tail)) => bytes.len() <= 32 && first(head) && tail.iter().all(|&b| rest(b)),
        None => false,
    }
}

/// Name of an agent: `^[a-z0-9][a-z0-9-]{0,31}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AgentName(String);

impl TryFrom<String> for AgentName {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if is_name(&value, alnum, |b| alnum(b) || b == b'-') {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "agent name",
                "must match ^[a-z0-9][a-z0-9-]{0,31}$",
            ))
        }
    }
}
string_newtype!(AgentName);

/// Name of a target: `^[a-z0-9][a-z0-9-]{0,31}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TargetName(String);

impl TryFrom<String> for TargetName {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if is_name(&value, alnum, |b| alnum(b) || b == b'-') {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "target name",
                "must match ^[a-z0-9][a-z0-9-]{0,31}$",
            ))
        }
    }
}
string_newtype!(TargetName);

/// Name of an API secret: `^[a-z0-9][a-z0-9-]{0,31}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretName(String);

impl TryFrom<String> for SecretName {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if is_name(&value, alnum, |b| alnum(b) || b == b'-') {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "secret name",
                "must match ^[a-z0-9][a-z0-9-]{0,31}$",
            ))
        }
    }
}
string_newtype!(SecretName);

/// Unix account name: `^[a-z_][a-z0-9_-]{0,31}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UnixUser(String);

impl TryFrom<String> for UnixUser {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let head = |b: u8| b.is_ascii_lowercase() || b == b'_';
        let tail = |b: u8| head(b) || b.is_ascii_digit() || b == b'-';
        if is_name(&value, head, tail) {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "unix user",
                "must match ^[a-z_][a-z0-9_-]{0,31}$",
            ))
        }
    }
}
string_newtype!(UnixUser);

/// Human-readable purpose of a request: 1 to 500 characters after trimming
/// Unicode whitespace, single line (no control characters), and free of
/// invisible format characters (general category Cf: bidi overrides and
/// isolates, zero-width characters, BOM, soft hyphen, tags, ...), which could
/// make the text the owner reads differ from what was sent. The stored value
/// is trimmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Goal(String);

impl TryFrom<String> for Goal {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let trimmed = value.trim();
        let chars = trimmed.chars().count();
        if chars == 0 || chars > 500 {
            return Err(ParseError::new("goal", "must be 1 to 500 characters"));
        }
        check_free_text("goal", trimmed)?;
        Ok(Self(trimmed.to_owned()))
    }
}
string_newtype!(Goal);
