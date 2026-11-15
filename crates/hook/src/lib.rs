//! Pure detection logic for the warden agent plugin's `warden hook check`.
//!
//! No I/O and no panics on any input: the callers feed it text an agent wrote.

pub mod shell;
