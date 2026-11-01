//! `warden-demo`: one command that runs a throwaway warden on this machine.

use anyhow::{Context as _, Result};
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;
use warden_demo::Prepared;

/// A throwaway warden on this machine, to try the approval flow.
///
/// NOT SECURE FOR REAL USE. It takes no options and reads no `WARDEN_*`
/// setting: it always listens on loopback, on free ports, with throwaway keys
/// and data in a temporary directory.
#[derive(Parser)]
#[command(version)]
struct Cli {}

/// Installs the handlers for SIGTERM and Ctrl-C at once, so a signal from now
/// on deletes the data instead of killing the process, and returns a future
/// that resolves on either.
fn termination() -> Result<impl Future<Output = ()>> {
    let mut term = signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("installing the Ctrl-C handler")?;
    Ok(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = interrupt.recv() => {}
        }
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("warn"))
        .with_writer(std::io::stderr)
        .init();

    let stop = termination()?;
    tokio::pin!(stop);
    let prepared = Prepared::new().await?;
    println!("{}", prepared.banner());
    let mut demo = prepared.serve().await?;

    loop {
        tokio::select! {
            () = &mut stop => break,
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
