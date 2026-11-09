use anyhow::{Context, Result, anyhow};
use authority::{journal::SignedCommand, protocol};
use clap::{Parser, Subcommand};
use identity::{Identity, trust};
use league::application::Application;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    fs::File,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[command(name = "jlucraft-agent", about = "Sign locally with an agent identity")]
struct Cli {
    #[arg(long, global = true, default_value_t = node::protocol::Namespace::builtin().organization)]
    organization: String,
    #[arg(long, global = true, default_value_t = node::protocol::Namespace::builtin().wire_version)]
    protocol_version: u32,
    #[command(subcommand)]
    command: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Create an Ed25519 identity without overwriting an existing file.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Show the peer ID and standard padded base64 public key.
    Public {
        #[arg(long)]
        key: PathBuf,
    },
    /// Sign a TrustedCommand for the federated application.
    SignCommand {
        #[arg(long)]
        key: PathBuf,
        /// JSON file path, inline JSON object, or '-' for stdin.
        #[arg(long, value_name = "JSON|-")]
        input: String,
    },
    /// Add this identity's signature to a TrustRecord.
    SignRecord {
        #[arg(long)]
        key: PathBuf,
        /// JSON file path, inline JSON object, or '-' for stdin.
        #[arg(long, value_name = "JSON|-")]
        input: String,
    },
}

#[derive(Serialize)]
struct PublicIdentity {
    peer: String,
    #[serde(with = "protocol::base64_pad")]
    public_key: Vec<u8>,
}

fn public(identity: &Identity) -> PublicIdentity {
    PublicIdentity {
        peer: identity.peer_id().to_string(),
        public_key: identity.public_key().encode_protobuf(),
    }
}

// Match application_submit's encoding while leaving the journal type unchanged.
#[derive(Serialize)]
struct CommandOutput {
    #[serde(with = "protocol::base64_pad")]
    payload: Vec<u8>,
    #[serde(with = "protocol::base64_pad")]
    public_key: Vec<u8>,
    #[serde(with = "protocol::base64_pad")]
    signature: Vec<u8>,
}

fn read_json<T: DeserializeOwned>(input: &str, kind: &str) -> Result<T> {
    let parsed = if input == "-" {
        serde_json::from_reader(io::stdin().lock())
    } else if input.trim_start().starts_with(['{', '[']) {
        serde_json::from_str(input)
    } else {
        let file = File::open(input).context("cannot open JSON input file")?;
        serde_json::from_reader(file)
    };
    // Do not echo input values, which might accidentally contain secret material.
    parsed.map_err(|error| {
        anyhow!(
            "invalid {kind} JSON at line {}, column {} ({:?})",
            error.line(),
            error.column(),
            error.classify()
        )
    })
}

#[cfg(test)]
fn run(command: Operation) -> Result<Value> {
    run_with_namespace(command, &node::protocol::Namespace::builtin())
}

fn run_with_namespace(command: Operation, namespace: &node::protocol::Namespace) -> Result<Value> {
    match command {
        Operation::Keygen { out } => {
            let identity = Identity::generate();
            identity
                .save_new(out)
                .context("cannot create identity key; an existing file will not be overwritten")?;
            Ok(serde_json::to_value(public(&identity))?)
        }
        Operation::Public { key } => {
            let identity = Identity::load(key).context("cannot load identity key")?;
            Ok(serde_json::to_value(public(&identity))?)
        }
        Operation::SignCommand { key, input } => {
            let identity = Identity::load(key).context("cannot load identity key")?;
            let command = read_json::<authority::journal::TrustedCommand<Application>>(
                &input,
                "TrustedCommand",
            )?;
            let signed = SignedCommand::sign_with_namespace(&identity, command, namespace)?;
            Ok(serde_json::to_value(CommandOutput {
                payload: signed.payload,
                public_key: signed.public_key,
                signature: signed.signature,
            })?)
        }
        Operation::SignRecord { key, input } => {
            let identity = Identity::load(key).context("cannot load identity key")?;
            let mut record = read_json::<trust::TrustRecord>(&input, "TrustRecord")?;
            trust::sign_with_namespace(&mut record, &identity, namespace)
                .context("cannot sign TrustRecord")?;
            Ok(serde_json::to_value(record)?)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = node::protocol::Namespace::new(cli.organization, cli.protocol_version)
        .map_err(anyhow::Error::from)
        .and_then(|namespace| run_with_namespace(cli.command, &namespace))
        .and_then(|value| {
            let mut stdout = io::stdout().lock();
            serde_json::to_writer(&mut stdout, &value).context("cannot write JSON output")?;
            writeln!(stdout).context("cannot write JSON output")
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
