//! The agent hook: `[hook]` settings now, the checks and adapters in later
//! modules.

pub mod cache;
pub mod check;
pub mod claude;
pub mod files;
pub mod include;
pub mod session_start;
pub mod settings;

#[cfg(test)]
mod tests;
