use anyhow::Result;
use clap::{Parser, Subcommand};
use federated_server::runtime::{Config, Host};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "JLUCraft central Minecraft game host")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Run the operations executor independently of managed game services.
    Supervise {
        #[arg(long)]
        config: PathBuf,
    },
    /// Start configured game services.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Read and validate local host configuration.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
}
async fn stopping() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! { _ = terminate.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Args::parse().command {
        Command::Supervise { config } => {
            let supervisor = federated_server::operations::Supervisor::start(
                federated_server::operations::Config::load(&config)?,
            )
            .await?;
            tracing::info!(address = %supervisor.address()?, "operations supervisor listening");
            supervisor.run(stopping()).await?;
        }
        Command::Check { config } => {
            Config::load(&config)?;
        }
        Command::Run { config } => {
            let host = Host::start(Config::load(&config)?).await?;
            println!("{}", serde_json::to_string(&host.status())?);
            let result = tokio::select! { result = host.run() => result, _ = stopping() => Ok(()) };
            host.close().await?;
            result?;
        }
    }
    Ok(())
}
