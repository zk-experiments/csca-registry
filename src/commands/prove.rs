//! `verify`, `prove key` and `prove not-revoked`.

use crate::commitment::{self, Exclusion, KeyHeader, MerkleProof};
use crate::output::{Key, Registry};
use crate::registry;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

/// Inclusion proof for a key leaf, with everything a circuit needs to
/// recompute the leaf.
#[derive(Debug, Clone, Serialize)]
pub struct KeyProof {
    /// Registry root.
    pub root: String,
    /// Key tree root.
    pub keys_root: String,
    /// Revocation tree root (for recomputing `root`).
    pub revocations_root: String,
    /// Key material, hex (RSA modulus or EC `x || y`).
    pub public_key: String,
    /// Poseidon2 key hash.
    pub key_hash: String,
    /// Country, alpha-2.
    pub country: String,
    /// ICAO three-letter code committed in the leaf.
    pub country_code: String,
    /// 1 = RSA, 2 = EC.
    pub key_type: u8,
    /// Curve id.
    pub curve: u8,
    /// Key size.
    pub bits: u16,
    /// RSA exponent.
    pub exponent: u32,
    /// Period start.
    pub open: i64,
    /// Period end.
    pub close: i64,
    /// Packed leaf header.
    pub header: String,
    /// Inclusion proof.
    pub proof: ProofJson,
}

/// Exclusion proof for a (issuer key, serial) pair.
#[derive(Debug, Clone, Serialize)]
pub struct NotRevokedProof {
    /// Registry root.
    pub root: String,
    /// Key tree root (for recomputing `root`).
    pub keys_root: String,
    /// Revocation tree root.
    pub revocations_root: String,
    /// Issuer Poseidon2 key hash.
    pub issuer_key_hash: String,
    /// Serial, hex.
    pub serial: String,
    /// Revocation leaf that is absent.
    pub target: String,
    /// Largest leaf below the target, if any.
    pub lower: Option<ProofJson>,
    /// Next slot above the target (zero leaf past the end).
    pub upper: ProofJson,
}

/// A Merkle path.
#[derive(Debug, Clone, Serialize)]
pub struct ProofJson {
    /// Leaf slot.
    pub index: usize,
    /// Leaf value.
    pub leaf: String,
    /// Siblings from the leaves up.
    pub siblings: Vec<String>,
}

impl From<&MerkleProof> for ProofJson {
    fn from(p: &MerkleProof) -> Self {
        Self {
            index: p.index,
            leaf: commitment::to_hex(&p.leaf),
            siblings: p.siblings.iter().map(commitment::to_hex).collect(),
        }
    }
}

/// Loads a registry and checks its commitment against its own leaves.
pub fn handle_verify(path: &Path) -> Result<Registry> {
    let json = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let reg: Registry = serde_json::from_str(&json).context("parse registry")?;
    let (keys, revs) = registry::trees(&reg)?;
    let root = commitment::state_root(keys.root(), revs.root());
    let got = [keys.root(), revs.root(), root].map(|f| commitment::to_hex(&f));
    let want = [
        &reg.commitment.keys_root,
        &reg.commitment.revocations_root,
        &reg.commitment.root,
    ];
    if got.iter().zip(want).any(|(g, w)| g != w) {
        bail!("registry leaves do not reproduce its commitment: got {got:?}");
    }
    for k in &reg.keys {
        let key_hash = commitment::from_hex(&k.key_hash)?;
        let material = hex::decode(&k.public_key).context("public_key hex")?;
        if commitment::key_hash(&material) != key_hash {
            bail!("key {} public_key does not reproduce its key_hash", k.id);
        }
        for p in &k.periods {
            let leaf = commitment::key_leaf(&header(k, p.open, p.close)?, key_hash);
            if commitment::to_hex(&leaf) != p.leaf {
                bail!(
                    "key {} period {}..{} does not reproduce its leaf",
                    k.id,
                    p.open,
                    p.close
                );
            }
        }
    }
    tracing::info!(root = %reg.commitment.root, "commitment verified");
    Ok(reg)
}

/// Builds a [`KeyProof`] for `key` valid at `at`.
pub fn prove_key(reg: &Registry, key: &str, at: i64) -> Result<KeyProof> {
    let k = find_key(reg, key)?;
    let p = k
        .periods
        .iter()
        .find(|p| p.open <= at && at <= p.close)
        .with_context(|| format!("key {} has no period covering {at}", k.id))?;
    let (tree, revs) = registry::trees(reg)?;
    let proof = tree.proof(p.index);
    if commitment::to_hex(&proof.leaf) != p.leaf || proof.root() != tree.root() {
        bail!("registry leaf index is stale; rebuild the registry");
    }
    let h = header(k, p.open, p.close)?;
    Ok(KeyProof {
        root: commitment::to_hex(&commitment::state_root(tree.root(), revs.root())),
        keys_root: commitment::to_hex(&tree.root()),
        revocations_root: commitment::to_hex(&revs.root()),
        public_key: k.public_key.clone(),
        key_hash: k.key_hash.clone(),
        country: k.country.clone(),
        country_code: k.country_code.clone(),
        key_type: k.key_type,
        curve: k.curve,
        bits: k.bits,
        exponent: k.exponent,
        open: p.open,
        close: p.close,
        header: commitment::to_hex(&h.field()),
        proof: (&proof).into(),
    })
}

/// Builds a [`NotRevokedProof`]; fails if the serial is revoked.
pub fn prove_not_revoked(
    reg: &Registry,
    issuer_key: &str,
    serial: &str,
) -> Result<NotRevokedProof> {
    let k = find_key(reg, issuer_key)?;
    let serial_bytes = hex::decode(normalize_hex(serial)).context("serial hex")?;
    let serial_bytes = crate::der::uint(&serial_bytes).to_vec();
    let key_hash = commitment::from_hex(&k.key_hash)?;
    let target = commitment::revocation_leaf(key_hash, &serial_bytes);
    let (keys, tree) = registry::trees(reg)?;
    let Some(Exclusion { lower, upper, .. }) = tree.exclusion(target) else {
        bail!("serial {serial} is revoked under key {}", k.id);
    };
    Ok(NotRevokedProof {
        root: commitment::to_hex(&commitment::state_root(keys.root(), tree.root())),
        keys_root: commitment::to_hex(&keys.root()),
        revocations_root: commitment::to_hex(&tree.root()),
        issuer_key_hash: k.key_hash.clone(),
        serial: hex::encode(&serial_bytes),
        target: commitment::to_hex(&target),
        lower: lower.as_ref().map(Into::into),
        upper: (&upper).into(),
    })
}

/// Writes `value` as JSON to `output`, or stdout.
pub fn write_json<T: Serialize>(value: &T, output: Option<&Path>) -> Result<()> {
    let mut json = serde_json::to_string_pretty(value)?;
    json.push('\n');
    match output {
        Some(p) => std::fs::write(p, json).with_context(|| format!("write {}", p.display())),
        None => std::io::stdout()
            .write_all(json.as_bytes())
            .context("write stdout"),
    }
}

fn find_key<'a>(reg: &'a Registry, key: &str) -> Result<&'a Key> {
    let key = normalize_hex(key);
    reg.keys
        .iter()
        .find(|k| k.id == key || normalize_hex(&k.key_hash) == key)
        .with_context(|| format!("no key {key} in the registry"))
}

fn normalize_hex(s: &str) -> String {
    s.trim().trim_start_matches("0x").to_lowercase()
}

fn header(k: &Key, open: i64, close: i64) -> Result<KeyHeader> {
    let [c0, c1, c2] = k.country_code.as_bytes() else {
        bail!(
            "key {} country code {} is not three letters",
            k.id,
            k.country_code
        );
    };
    Ok(KeyHeader {
        country: [*c0, *c1, *c2],
        key_type: k.key_type,
        curve: k.curve,
        bits: k.bits,
        exponent: k.exponent,
        open: u64::try_from(open).unwrap_or(0),
        close: u64::try_from(close).unwrap_or(0),
    })
}
