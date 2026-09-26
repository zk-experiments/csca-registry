//! `build`: sources -> registry.json.

use crate::output::Registry;
use crate::registry::Builder;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Builds the registry from `sources` and writes it to `output`.
pub fn handle_build(sources: &[PathBuf], output: &Path) -> Result<Registry> {
    let mut builder = Builder::default();
    for s in sources {
        builder.add_path(s)?;
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
