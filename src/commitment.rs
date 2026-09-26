//! Poseidon2 (BN254, noir-compatible) commitment to the registry.
//!
//! Layout follows zkpassport's certificate registry (ordered binary Merkle
//! trees, zero leaf `0`, leaves sorted ascending, `packBeBytesIntoFields`
//! packing) with a leaf that also commits the key's validity period, so a
//! circuit can prove "signed by a CSCA key that was valid on date D":
//!
//! ```text
//! key_hash   = H(pack(key material))                  RSA modulus | EC x||y
//! key leaf   = H(header, key_hash)                    one per (key, period)
//! header     = be(version:1 | type=1:1 | country:2 | key_type:1 | curve:1
//!                 | bits:2 | exponent:4 | open:8 | close:8)       28 bytes
//! revocation = H(issuer key_hash, H(pack(serial)))
//! root       = H(version, keys_root, revocations_root)
//! ```
//!
//! `H` is `std::hash::poseidon2` (sponge, iv = len << 64); `pack` splits
//! big-endian bytes into 31-byte chunks, least significant chunk first.

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use pso_poseidon::{Poseidon2, PoseidonHasher};

/// Leaf/root format version.
pub const LEAF_VERSION: u8 = 1;
/// Certificate type committed in key leaves (zkpassport's `CERT_TYPE_CSCA`).
pub const CERT_TYPE_CSCA: u8 = 1;
/// Key tree height (65 536 leaves).
pub const KEY_TREE_HEIGHT: usize = 16;
/// Revocation tree height (16 384 leaves).
pub const REVOCATION_TREE_HEIGHT: usize = 14;

/// Poseidon2 sponge over BN254, bit-identical to noir's `poseidon2::hash`.
pub fn poseidon2(inputs: &[Fr]) -> Fr {
    Poseidon2::<Fr>::new()
        .hash(inputs)
        .expect("the Poseidon2 sponge is infallible")
}

/// zkpassport `packBeBytesIntoFields(bytes, 31)`: 31-byte big-endian chunks,
/// the short chunk taken from the front, least significant chunk at index 0.
pub fn pack_be(bytes: &[u8]) -> Vec<Fr> {
    let first = match bytes.len() % 31 {
        0 => 31,
        r => r,
    };
    let mut chunks = vec![Fr::from_be_bytes_mod_order(
        &bytes[..first.min(bytes.len())],
    )];
    chunks.extend(
        bytes[first.min(bytes.len())..]
            .chunks(31)
            .map(Fr::from_be_bytes_mod_order),
    );
    if bytes.is_empty() {
        return vec![];
    }
    chunks.reverse();
    chunks
}

/// Poseidon2 hash of key material (RSA modulus or EC `x || y`).
pub fn key_hash(material: &[u8]) -> Fr {
    poseidon2(&pack_be(material))
}

/// Fields of a key leaf besides the key itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHeader {
    /// Upper-case alpha-2 country.
    pub country: [u8; 2],
    /// 1 = RSA, 2 = EC.
    pub key_type: u8,
    /// Curve id (`crypto::Curve::id`), 0 for RSA.
    pub curve: u8,
    /// Modulus or field size in bits.
    pub bits: u16,
    /// RSA public exponent, 0 for EC.
    pub exponent: u32,
    /// Period start, unix seconds.
    pub open: u64,
    /// Period end, unix seconds.
    pub close: u64,
}

impl KeyHeader {
    /// Header packed into one field element.
    pub fn field(&self) -> Fr {
        let mut b = vec![
            LEAF_VERSION,
            CERT_TYPE_CSCA,
            self.country[0],
            self.country[1],
            self.key_type,
            self.curve,
        ];
        b.extend(self.bits.to_be_bytes());
        b.extend(self.exponent.to_be_bytes());
        b.extend(self.open.to_be_bytes());
        b.extend(self.close.to_be_bytes());
        Fr::from_be_bytes_mod_order(&b)
    }
}

/// Key leaf: `H(header, key_hash)`.
pub fn key_leaf(header: &KeyHeader, key_hash: Fr) -> Fr {
    poseidon2(&[header.field(), key_hash])
}

/// Revocation leaf: `H(issuer key_hash, H(pack(serial)))`.
pub fn revocation_leaf(issuer_key_hash: Fr, serial: &[u8]) -> Fr {
    poseidon2(&[issuer_key_hash, poseidon2(&pack_be(serial))])
}

/// Registry root: `H(version, keys_root, revocations_root)`.
pub fn state_root(keys_root: Fr, revocations_root: Fr) -> Fr {
    poseidon2(&[
        Fr::from(u64::from(LEAF_VERSION)),
        keys_root,
        revocations_root,
    ])
}

/// Ordered binary Poseidon2 Merkle tree with zero-padding.
#[derive(Debug, Clone)]
pub struct Tree {
    levels: Vec<Vec<Fr>>,
    zeros: Vec<Fr>,
}

impl Tree {
    /// Builds a tree of `height` over `leaves`, which must be strictly ascending
    /// and non-zero (the canonical ordering exclusion proofs rely on).
    pub fn new(leaves: Vec<Fr>, height: usize) -> Result<Self> {
        if leaves.len() > 1 << height {
            bail!(
                "{} leaves do not fit a tree of height {height}",
                leaves.len()
            );
        }
        if leaves.windows(2).any(|w| w[0] >= w[1]) || leaves.contains(&Fr::from(0u64)) {
            bail!("leaves must be non-zero and strictly ascending");
        }
        let mut zeros = vec![Fr::from(0u64)];
        for l in 0..height {
            zeros.push(poseidon2(&[zeros[l], zeros[l]]));
        }
        let mut levels = vec![leaves];
        for l in 0..height {
            let prev = &levels[l];
            let next = (0..prev.len().div_ceil(2))
                .map(|i| {
                    let left = prev[2 * i];
                    let right = prev.get(2 * i + 1).copied().unwrap_or(zeros[l]);
                    poseidon2(&[left, right])
                })
                .collect();
            levels.push(next);
        }
        Ok(Self { levels, zeros })
    }

    /// Tree height.
    pub fn height(&self) -> usize {
        self.levels.len() - 1
    }

    /// Root.
    pub fn root(&self) -> Fr {
        self.node(self.height(), 0)
    }

    /// Committed leaves.
    pub fn leaves(&self) -> &[Fr] {
        &self.levels[0]
    }

    fn node(&self, level: usize, index: usize) -> Fr {
        self.levels[level]
            .get(index)
            .copied()
            .unwrap_or(self.zeros[level])
    }

    /// Inclusion proof for slot `index` (also valid for a zero slot past the end).
    pub fn proof(&self, index: usize) -> MerkleProof {
        let siblings = (0..self.height())
            .map(|l| self.node(l, (index >> l) ^ 1))
            .collect();
        MerkleProof {
            index,
            leaf: self.node(0, index),
            siblings,
        }
    }

    /// Exclusion proof for `target`, or `None` if it is a member.
    /// Brackets it between adjacent slots: `lower.leaf < target < upper.leaf`,
    /// with `upper.leaf == 0` meaning "past the last leaf" and `lower == None`
    /// meaning "before the first".
    pub fn exclusion(&self, target: Fr) -> Option<Exclusion> {
        let leaves = self.leaves();
        match leaves.binary_search(&target) {
            Ok(_) => None,
            Err(0) => Some(Exclusion {
                target,
                lower: None,
                upper: self.proof(0),
            }),
            Err(i) => Some(Exclusion {
                target,
                lower: Some(self.proof(i - 1)),
                upper: self.proof(i),
            }),
        }
    }
}

/// Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// Leaf slot.
    pub index: usize,
    /// Leaf value.
    pub leaf: Fr,
    /// Siblings from the leaf level up.
    pub siblings: Vec<Fr>,
}

impl MerkleProof {
    /// Root this proof commits to.
    pub fn root(&self) -> Fr {
        self.siblings
            .iter()
            .enumerate()
            .fold(self.leaf, |acc, (l, s)| {
                if (self.index >> l) & 1 == 0 {
                    poseidon2(&[acc, *s])
                } else {
                    poseidon2(&[*s, acc])
                }
            })
    }
}

/// Ordered-tree non-membership proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    /// Leaf asserted absent.
    pub target: Fr,
    /// Largest leaf below `target`, if any.
    pub lower: Option<MerkleProof>,
    /// Next slot: smallest leaf above `target`, or the zero slot after the end.
    pub upper: MerkleProof,
}

impl Exclusion {
    /// Checks the bracket against `root` (zkpassport's verification rules).
    pub fn verify(&self, root: Fr) -> bool {
        let zero = Fr::from(0u64);
        if self.upper.root() != root {
            return false;
        }
        match &self.lower {
            None => {
                self.upper.index == 0 && self.upper.leaf != zero && self.target < self.upper.leaf
            }
            Some(lower) => {
                lower.root() == root
                    && lower.leaf != zero
                    && lower.leaf < self.target
                    && self.upper.index == lower.index + 1
                    && (self.upper.leaf == zero || self.target < self.upper.leaf)
            }
        }
    }
}

/// `0x`-prefixed 32-byte big-endian hex.
pub fn to_hex(f: &Fr) -> String {
    format!("0x{}", hex::encode(f.into_bigint().to_bytes_be()))
}

/// Parses [`to_hex`] output (rejects non-canonical values).
pub fn from_hex(s: &str) -> Result<Fr> {
    let bytes = hex::decode(s.trim_start_matches("0x")).context("field element hex")?;
    let f = Fr::from_be_bytes_mod_order(&bytes);
    if to_hex(&f) != format!("0x{}", s.trim_start_matches("0x").to_lowercase()) {
        bail!("{s} is not a canonical 32-byte BN254 field element");
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::MontFp;

    #[test]
    fn poseidon2_matches_noir() {
        // Same known answer pso-poseidon locks against `nargo execute`.
        let h: Fr = MontFp!("0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383");
        assert_eq!(poseidon2(&[Fr::from(1u64), Fr::from(2u64)]), h);
    }

    #[test]
    fn pack_matches_zkpassport() {
        // 33 bytes: front 2-byte chunk is the most significant field (index 1).
        let bytes: Vec<u8> = (1..=33).collect();
        let f = pack_be(&bytes);
        assert_eq!(f.len(), 2);
        assert_eq!(f[1], Fr::from(0x0102u64));
        assert_eq!(f[0], Fr::from_be_bytes_mod_order(&bytes[2..]));
        assert_eq!(pack_be(&bytes[..31]).len(), 1);
        assert!(pack_be(&[]).is_empty());
    }

    #[test]
    fn inclusion_and_exclusion() {
        let mut leaves: Vec<Fr> = (1..=5u64).map(|i| Fr::from(i * 10)).collect();
        leaves.sort();
        let tree = Tree::new(leaves.clone(), 4).unwrap();
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let p = tree.proof(i);
            assert_eq!((p.leaf, p.root()), (*leaf, root));
        }
        assert!(tree.exclusion(Fr::from(30u64)).is_none());
        for t in [5u64, 25, 55] {
            let ex = tree.exclusion(Fr::from(t)).unwrap();
            assert!(ex.verify(root), "target {t}");
            let mut forged = ex.clone();
            forged.target = Fr::from(30u64);
            assert!(!forged.verify(root), "member must not be excludable ({t})");
        }
        assert!(Tree::new(vec![Fr::from(2u64), Fr::from(1u64)], 4).is_err());
        assert!(Tree::new(vec![Fr::from(1u64); 1], 0).is_ok());
    }

    #[test]
    fn empty_tree_root_is_zero_chain() {
        let t = Tree::new(vec![], 2).unwrap();
        let z1 = poseidon2(&[Fr::from(0u64), Fr::from(0u64)]);
        assert_eq!(t.root(), poseidon2(&[z1, z1]));
        assert_eq!(from_hex(&to_hex(&t.root())).unwrap(), t.root());
    }
}
