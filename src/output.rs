//! `registry.json` schema.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Current `registry.json` format version.
pub const FORMAT_VERSION: u32 = 2;

/// The combined registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    /// Format version ([`FORMAT_VERSION`]).
    pub version: u32,
    /// Poseidon2 commitment over `keys` and `revocations`.
    pub commitment: Commitment,
    /// Every input and what became of it.
    pub sources: Vec<Source>,
    /// Per-country key and signature algorithm profile.
    pub countries: BTreeMap<String, Country>,
    /// Every unique certificate.
    pub certificates: Vec<Certificate>,
    /// Unique public keys with their merged validity periods (the key tree leaves).
    pub keys: Vec<Key>,
    /// Revoked serials per issuing key (the revocation tree leaves).
    pub revocations: Vec<Revocation>,
}

/// Roots and tree shapes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    /// `H(version, keys_root, revocations_root)`.
    pub root: String,
    /// Key tree root.
    pub keys_root: String,
    /// Revocation tree root.
    pub revocations_root: String,
    /// Leaf layout version.
    pub leaf_version: u8,
    /// Key tree height.
    pub key_tree_height: usize,
    /// Revocation tree height.
    pub revocation_tree_height: usize,
}

/// One input file (or LDIF entry).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Source {
    /// Path, or `path#dn` for LDIF entries.
    pub name: String,
    /// `masterlist`, `crl`, `certificate` or `ldif`.
    pub kind: String,
    /// sha256 of the bytes.
    pub sha256: String,
    /// `trusted`, `rejected`, `manual`, `parsed` or `error`.
    pub status: String,
    /// Publisher country (master lists).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Fingerprint of the CSCA the ML signer chains to, or of the CRL issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    /// Signature scheme of the ML signer / CRL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
    /// Certificates contributed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<usize>,
    /// Entries that failed to parse.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unparsable: Vec<String>,
    /// CRL entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<usize>,
    /// CRL thisUpdate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_update: Option<i64>,
    /// DSCs counted for the country profile (LDIF).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsc: Option<usize>,
    /// Why it was rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What a country's PKI uses. `csca_*` comes from the CSCAs (their key types,
/// and the schemes they sign certificates with — i.e. how DSCs are signed).
/// `dsc_*` comes from DSCs in ICAO PKD LDIFs, when given: the DSC key signs
/// the document's SOD, so these are the schemes found in issued documents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Country {
    /// Unique CSCA certificates.
    pub cscas: usize,
    /// Unique CSCA keys.
    pub keys: usize,
    /// CSCA key types, e.g. `RSA-4096`, `EC-brainpoolP512r1`.
    pub csca_keys: BTreeMap<String, usize>,
    /// Schemes CSCAs sign with, e.g. `ecdsa-sha512`.
    pub csca_signature_schemes: BTreeMap<String, usize>,
    /// DSC key types (= SOD signature key).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dsc_keys: BTreeMap<String, usize>,
    /// Schemes the CSCA used on DSCs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dsc_signature_schemes: BTreeMap<String, usize>,
}

/// A certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// sha256(DER).
    pub fingerprint: String,
    /// Alpha-2.
    pub country: String,
    /// `root`, `link` or `orphan`.
    pub kind: String,
    /// `verified`, `issuer-missing`, `invalid` or `unsupported`.
    pub chain: String,
    /// Detail for non-verified chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_detail: Option<String>,
    /// Issuer certificate that verified this one.
    pub issuer_fingerprint: Option<String>,
    /// Subject DN.
    pub subject: String,
    /// Issuer DN.
    pub issuer: String,
    /// Serial, hex.
    pub serial: String,
    /// Scheme the issuer used, or the unsupported algorithm.
    pub signature_scheme: String,
    /// Public key.
    pub key: KeyInfo,
    /// Validity start.
    pub not_before: i64,
    /// Validity end.
    pub not_after: i64,
    /// PrivateKeyUsagePeriod (when the CSCA may issue DSCs).
    pub private_key_usage_period: Option<[Option<i64>; 2]>,
    /// Earliest revocation from a verified CRL.
    pub revoked_at: Option<i64>,
    /// Sources that listed it.
    pub sources: BTreeSet<String>,
}

/// Public key summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// sha256 of the key material; groups certificates sharing a key.
    pub id: Option<String>,
    /// e.g. `RSA-4096`, `EC-brainpoolP384r1`, or the parse error.
    pub description: String,
}

/// A key and the periods it was valid in: one tree leaf per period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    /// sha256 of the key material.
    pub id: String,
    /// Alpha-2, as in the certificate.
    pub country: String,
    /// ICAO three-letter code committed in the leaf.
    pub country_code: String,
    /// e.g. `EC-brainpoolP512r1`.
    pub description: String,
    /// Key material the leaf commits to, hex: RSA modulus, or EC `x || y`.
    pub public_key: String,
    /// Poseidon2 key hash.
    pub key_hash: String,
    /// 1 = RSA, 2 = EC.
    pub key_type: u8,
    /// Curve id, 0 for RSA.
    pub curve: u8,
    /// Key size.
    pub bits: u16,
    /// RSA exponent, 0 for EC.
    pub exponent: u32,
    /// Disjoint `[open, close]` periods with their leaves.
    pub periods: Vec<Period>,
    /// Certificates carrying the key.
    pub certificates: Vec<String>,
}

/// A validity period and its leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Period {
    /// Unix seconds.
    pub open: i64,
    /// Unix seconds (cut at revocation).
    pub close: i64,
    /// Leaf value.
    pub leaf: String,
    /// Leaf slot in the key tree.
    pub index: usize,
}

/// A revoked serial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    /// Key id of the issuer.
    pub issuer_key: String,
    /// Poseidon2 key hash of the issuer.
    pub issuer_key_hash: String,
    /// A certificate carrying the issuer key.
    pub issuer_fingerprint: String,
    /// Serial, hex.
    pub serial: String,
    /// Revocation time.
    pub revoked_at: i64,
    /// CRL it came from.
    pub source: String,
    /// Leaf value.
    pub leaf: String,
    /// Leaf slot in the revocation tree.
    pub index: usize,
}
