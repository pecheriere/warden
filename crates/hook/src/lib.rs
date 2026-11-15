//! Pure detection logic for the warden agent plugin's `warden hook check`.
//!
//! No I/O and no panics on any input: the callers feed it text an agent wrote.
//!
//! # Limits
//!
//! The shell tokenizer is best effort and is not a security boundary: it
//! flags the usual ways of going around warden, not every way a shell can
//! build a command. It does not see:
//!
//! - `$'…'` quoting;
//! - a command that follows an expansion word (`$(true) ssh pi`,
//!   `$EMPTY ssh pi`);
//! - nesting deeper than one `bash -c` or `eval` level, or more than four
//!   levels of `$(…)` and backticks;
//! - the inside of `$((…))` arithmetic (so `$((ssh pi) )` is skipped);
//! - parentheses of a `case` pattern inside `$(…)`.

pub mod context;
pub mod settings;
pub mod shell;
