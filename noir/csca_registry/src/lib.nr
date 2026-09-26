//! In-circuit verification against the csca-registry commitment (leaf format v2).
//!
//! This library is the only place circuits compute registry leaves, Merkle
//! paths, validity windows and revocation non-membership. It mirrors
//! `src/commitment.rs` of the csca-registry crate bit for bit; `src/vectors.nr`
//! is generated from that crate (tests/noir_vectors.rs) and `nargo test`
//! checks both sides agree. See README.md for the specification.

mod tests;
mod vectors;

use poseidon::poseidon2::Poseidon2;

/// Leaf layout version (`commitment::LEAF_VERSION`).
pub global LEAF_VERSION: u8 = 2;
/// Certificate type committed in key leaves (CSCA).
pub global CERT_TYPE_CSCA: u8 = 1;
/// Key tree height (65 536 leaves).
pub global KEY_TREE_HEIGHT: u32 = 16;
/// Revocation tree height (16 384 leaves).
pub global REVOCATION_TREE_HEIGHT: u32 = 14;
/// `key_type` for RSA keys (key material = modulus).
pub global KEY_TYPE_RSA: u8 = 1;
/// `key_type` for EC keys (key material = `x || y`).
pub global KEY_TYPE_EC: u8 = 2;

/// Germany writes its issuing state as `D<<` in the MRZ.
global MRZ_GERMANY: [u8; 3] = [0x44, 0x3c, 0x3c];
global ISO_GERMANY: [u8; 3] = [0x44, 0x45, 0x55];

/// Everything a key leaf commits to except the key itself.
pub struct KeyHeader {
    /// ICAO three-letter country code (ISO alpha-3 or ICAO issuer code).
    pub country: [u8; 3],
    /// `KEY_TYPE_RSA` or `KEY_TYPE_EC`.
    pub key_type: u8,
    /// Curve id (csca-registry curve table row + 1), 0 for RSA.
    pub curve: u8,
    /// Modulus or field size in bits.
    pub bits: u16,
    /// RSA public exponent, 0 for EC.
    pub exponent: u32,
    /// Validity period start, unix seconds.
    pub open: u64,
    /// Validity period end, unix seconds (cut at revocation).
    pub close: u64,
}

/// A Merkle inclusion witness.
pub struct MerklePath<let H: u32> {
    /// Leaf slot; only the low `H` bits are used and the rest must be zero.
    pub index: Field,
    /// Siblings from the leaf level up.
    pub siblings: [Field; H],
}

/// Witness that a leaf is absent from the ordered revocation tree: the two
/// adjacent committed slots that bracket it.
pub struct Exclusion<let H: u32> {
    /// False when the target sorts before every committed leaf.
    pub has_lower: bool,
    /// Largest committed leaf below the target (ignored when `has_lower` is false).
    pub lower_leaf: Field,
    /// Path of `lower_leaf`.
    pub lower: MerklePath<H>,
    /// Leaf in the next slot: the smallest leaf above the target, or 0 past the end.
    pub upper_leaf: Field,
    /// Path of `upper_leaf`.
    pub upper: MerklePath<H>,
}

/// Poseidon2 sponge over all of `inputs` (noir's `poseidon2::hash`, iv = len << 64).
pub fn hash<let L: u32>(inputs: [Field; L]) -> Field {
    Poseidon2::hash(inputs, L)
}

/// zkpassport `packBeBytesIntoFields(bytes, 31)`: big-endian 31-byte chunks,
/// the short chunk taken from the front, least significant chunk at index 0.
/// `M` must be `(N + 30) / 31`.
pub fn pack_be<let N: u32, let M: u32>(bytes: [u8; N]) -> [Field; M] {
    assert_eq(M, (N + 30) / 31, "pack_be: M must be ceil(N / 31)");
    let mut pow: [Field; 31] = [1; 31];
    for i in 1..31 {
        pow[i] = pow[i - 1] * 256;
    }
    let mut out: [Field; M] = [0; M];
    for k in 0..N {
        let from_end = N - 1 - k;
        out[from_end / 31] += bytes[k] as Field * pow[from_end % 31];
    }
    out
}

/// `key_hash = H(pack_be(key material))`. RSA: the modulus, big-endian, no
/// leading zero bytes. EC: `x || y`, each padded to the field size.
pub fn key_hash<let N: u32, let M: u32>(public_key: [u8; N]) -> Field {
    hash(pack_be::<N, M>(public_key))
}

/// The 29-byte header packed big-endian into one field:
/// `version | type | country[3] | key_type | curve | bits[2] | exponent[4] | open[8] | close[8]`.
pub fn header_field(h: KeyHeader) -> Field {
    let mut acc: Field = LEAF_VERSION as Field;
    acc = acc * 256 + CERT_TYPE_CSCA as Field;
    for i in 0..3 {
        acc = acc * 256 + h.country[i] as Field;
    }
    acc = acc * 256 + h.key_type as Field;
    acc = acc * 256 + h.curve as Field;
    acc = acc * 65536 + h.bits as Field;
    acc = acc * 4294967296 + h.exponent as Field;
    acc = acc * 18446744073709551616 + h.open as Field;
    acc * 18446744073709551616 + h.close as Field
}

/// `leaf = H(header_field, key_hash)`.
pub fn key_leaf(h: KeyHeader, key_hash: Field) -> Field {
    hash([header_field(h), key_hash])
}

/// `revocation leaf = H(issuer_key_hash, H(serial))`. `serial` is the DSC
/// serial number as a big-endian unsigned integer (at most 20 bytes per
/// RFC 5280, so it always packs into one field; leading zeros do not matter).
pub fn revocation_leaf(issuer_key_hash: Field, serial: [u8; 20]) -> Field {
    let packed: [Field; 1] = pack_be(serial);
    hash([issuer_key_hash, hash(packed)])
}

/// Root of the binary Poseidon2 tree containing `leaf` at `path.index`.
pub fn merkle_root<let H: u32>(leaf: Field, path: MerklePath<H>) -> Field {
    // to_le_bits constrains `index < 2^H`.
    let bits: [bool; H] = path.index.to_le_bits();
    let mut node = leaf;
    for l in 0..H {
        node = if !bits[l] {
            hash([node, path.siblings[l]])
        } else {
            hash([path.siblings[l], node])
        };
    }
    node
}

/// `root = H(LEAF_VERSION, keys_root, revocations_root)`.
pub fn state_root(keys_root: Field, revocations_root: Field) -> Field {
    hash([LEAF_VERSION as Field, keys_root, revocations_root])
}

/// Asserts that `public_key` with `header` is a key leaf under `root` and that
/// its period covers `at`; returns the key hash (to bind revocations to).
///
/// `root` must come from the caller's public inputs (the published registry
/// root). `revocations_root` is a private witness bound by `root`.
pub fn verify_key<let N: u32, let M: u32>(
    root: Field,
    revocations_root: Field,
    header: KeyHeader,
    public_key: [u8; N],
    path: MerklePath<KEY_TREE_HEIGHT>,
    at: u64,
) -> Field {
    assert(header.open <= at, "CSCA key period has not opened at the given date");
    assert(at <= header.close, "CSCA key period has closed at the given date");
    let kh = key_hash::<N, M>(public_key);
    let keys_root = merkle_root(key_leaf(header, kh), path);
    assert_eq(state_root(keys_root, revocations_root), root, "registry root mismatch");
    kh
}

/// Asserts that no revocation of `serial` under `issuer_key_hash` is in the
/// ordered revocation tree with root `revocations_root`.
///
/// Soundness relies on the tree being canonical (strictly ascending non-zero
/// leaves packed from slot 0, zero-padded), which csca-registry guarantees
/// and `verify` re-checks.
pub fn verify_not_revoked<let H: u32>(
    revocations_root: Field,
    issuer_key_hash: Field,
    serial: [u8; 20],
    w: Exclusion<H>,
) {
    let target = revocation_leaf(issuer_key_hash, serial);
    assert_eq(merkle_root(w.upper_leaf, w.upper), revocations_root, "upper path mismatch");
    if w.has_lower {
        assert_eq(merkle_root(w.lower_leaf, w.lower), revocations_root, "lower path mismatch");
        assert(w.lower_leaf != 0, "lower bound must be a committed leaf");
        assert(w.lower_leaf.lt(target), "lower bound must be below the target");
        assert_eq(w.upper.index, w.lower.index + 1, "bounds must be adjacent");
        assert(
            (w.upper_leaf == 0) | target.lt(w.upper_leaf),
            "upper bound must be above the target",
        );
    } else {
        assert_eq(w.upper.index, 0, "without a lower bound the upper bound must be slot 0");
        assert(w.upper_leaf != 0, "empty revocation tree needs no exclusion witness");
        assert(target.lt(w.upper_leaf), "upper bound must be above the target");
    }
}

/// Issuing state from the MRZ as the three-letter code leaves commit to
/// (`D<<` becomes `DEU`).
pub fn country_from_mrz(issuing_state: [u8; 3]) -> [u8; 3] {
    if issuing_state == MRZ_GERMANY {
        ISO_GERMANY
    } else {
        issuing_state
    }
}
