//! `build`: sources -> registry.json.

use crate::output::Registry;
use crate::registry::Builder;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Builds the registry from `sources` and writes it to `output`, keeping the
/// revocations of the registry at `carry` (a previous release) that no CRL
/// lists any more.
pub fn handle_build(sources: &[PathBuf], output: &Path, carry: Option<&Path>) -> Result<Registry> {
    let mut builder = Builder::default();
    for s in sources {
        builder.add_path(s)?;
    }
    if let Some(p) = carry {
        let prev: Registry = serde_json::from_slice(
            &std::fs::read(p).with_context(|| format!("read {}", p.display()))?,
        )
        .with_context(|| format!("parse {}", p.display()))?;
        builder.carry_revocations(&prev);
    }
    let registry = builder.finish()?;
    let mut json = serde_json::to_string_pretty(&registry)?;
    json.push('\n');
    std::fs::write(output, json).with_context(|| format!("write {}", output.display()))?;
    tracing::info!(
        output = %output.display(),
        root = %registry.commitment.root,
        countries = registry.countries.len(),
        certificates = registry.certificates.len(),
        keys = registry.keys.len(),
        revocations = registry.revocations.len(),
        "registry written"
    );
    Ok(registry)
}
