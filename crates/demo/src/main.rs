//! `warden-demo`: one command that runs a throwaway warden on this machine.

use anyhow::{Context as _, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;
use warden_demo::Demo;

/// A throwaway warden on this machine, to try the approval flow.
///
/// NOT SECURE FOR REAL USE. It takes no options and reads no `WARDEN_*`
/// setting: it always listens on loopback, on free ports, with throwaway keys
/// and data in a temporary directory.
#[derive(Parser)]
#[command(version)]
struct Cli {}

/// Resolves on SIGTERM or Ctrl-C.
async fn termination() -> Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing the SIGTERM handler")?;
    tokio::select! {
        _ = term.recv() => {}
        result = tokio::signal::ctrl_c() => result.context("installing the Ctrl-C handler")?,
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("warn"))
        .with_writer(std::io::stderr)
        .init();

    let mut demo = Demo::start().await?;
    println!("{}", demo.banner());

    let stop = termination();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            result = &mut stop => {
                result?;
                break;
            }
            bell = demo.next_doorbell() => {
                let bell = bell?;
                println!("\n>>> {}: {}\n>>> Open: {}\n", bell.title, bell.message, bell.url);
            }
        }
    }
    let entries = demo.finish().await?;
    println!("\nAudit log verified: {entries} entries, hash chain intact. Everything is deleted.");
    Ok(())
}
