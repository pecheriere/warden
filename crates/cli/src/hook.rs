//! The agent hook behind `warden hook check` and `warden hook session-start`:
//! the `[hook]` settings, the offers cache, the small-file reader and the
//! command's checks, Claude Code adapter and session-start output.

pub mod cache;
pub mod check;
pub mod claude;
pub mod files;
pub mod include;
pub mod session_start;
pub mod settings;

#[cfg(test)]
mod tests;
