//! `csca-registry` entry point.
//!
//! ```text
//! csca-registry build sources/ -o registry.json
//! csca-registry verify --registry registry.json
//! csca-registry prove key --registry registry.json --key <id|key_hash> --at <unix>
//! csca-registry prove not-revoked --registry registry.json --issuer-key <id> --serial <hex>
//! ```

use clap::Parser;
use tracing_subscriber::EnvFilter;

use csca_registry::commands::{build, prove};
use csca_registry::{Cli, Commands, ProveCommands};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Commands::Build {
            sources,
            output,
            carry_revocations,
        } => build::handle_build(&sources, &output, carry_revocations.as_deref()).map(drop),
        Commands::Verify { registry } => prove::handle_verify(&registry).map(drop),
        Commands::Prove { action } => match action {
            ProveCommands::Key {
                registry,
                key,
                at,
                output,
            } => {
                let reg = prove::handle_verify(&registry)?;
                prove::write_json(&prove::prove_key(&reg, &key, at)?, output.as_deref())
            }
            ProveCommands::NotRevoked {
                registry,
                issuer_key,
                serial,
                output,
            } => {
                let reg = prove::handle_verify(&registry)?;
                let proof = prove::prove_not_revoked(&reg, &issuer_key, &serial)?;
                prove::write_json(&proof, output.as_deref())
            }
        },
    }
}
