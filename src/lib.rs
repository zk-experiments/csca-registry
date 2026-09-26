//! Combined, signature-checked registry of eMRTD CSCA certificates (ICAO PKD
//! and national master lists) with validity periods per key, per-country
//! signature profiles, and a Poseidon2 Merkle commitment over keys and
//! revocations for in-circuit verification.
//!
//! The binary entry point is in `main.rs`; argument types live here so the
//! integration tests can drive the command handlers directly.

pub mod cert;
pub mod commands;
pub mod commitment;
pub mod crypto;
pub mod der;
pub mod ldif;
pub mod masterlist;
pub mod output;
pub mod registry;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Build and prove against the combined CSCA registry.
#[derive(Debug, Parser)]
#[command(name = "csca-registry", version, about, propagate_version = true)]
pub struct Cli {
    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Build registry.json from master lists, ICAO LDIFs, CRLs and certificates
    Build {
        /// Source files or directories (searched recursively)
        #[arg(required = true)]
        sources: Vec<PathBuf>,

        /// Output JSON path
        #[arg(short, long, default_value = "registry.json")]
        output: PathBuf,
    },
    /// Rebuild the Merkle trees from a registry's leaves and check its roots
    Verify {
        /// Registry JSON (from `build`)
        #[arg(short, long, default_value = "registry.json")]
        registry: PathBuf,
    },
    /// Produce Merkle proofs against a registry's commitment
    Prove {
        /// Proof subcommand to execute.
        #[command(subcommand)]
        action: ProveCommands,
    },
}

/// Proof subcommands.
#[derive(Debug, Subcommand)]
pub enum ProveCommands {
    /// Inclusion proof for the leaf of a CSCA key whose period covers `--at`
    Key {
        /// Registry JSON (from `build`)
        #[arg(short, long, default_value = "registry.json")]
        registry: PathBuf,

        /// Key id (sha256 of the key material) or Poseidon2 key hash
        #[arg(short, long)]
        key: String,

        /// Date the key must be valid at, unix seconds
        #[arg(long)]
        at: i64,

        /// Output JSON path (stdout when omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Exclusion proof that a serial is not revoked under an issuer key
    NotRevoked {
        /// Registry JSON (from `build`)
        #[arg(short, long, default_value = "registry.json")]
        registry: PathBuf,

        /// Issuer key id (sha256 of the key material) or Poseidon2 key hash
        #[arg(short, long)]
        issuer_key: String,

        /// Certificate serial number, hex
        #[arg(short, long)]
        serial: String,

        /// Output JSON path (stdout when omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}
