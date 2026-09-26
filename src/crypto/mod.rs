//! Signature verification for the algorithms eMRTD PKIs use, on RustCrypto:
//! `rsa` (PKCS#1 v1.5, PSS), `p256`/`p384`/`p521`/`bp256`/`bp384` (ECDSA) and a
//! local brainpoolP512r1 ([`bp512`]) assembled from RustCrypto's generic
//! `primefield`/`primeorder` code. Keys with explicit EC domain parameters are
//! resolved to the named curve they spell out.

pub mod bp512;
mod curves;

use crate::der;
use ecdsa::signature::hazmat::PrehashVerifier;
use elliptic_curve::array::typenum::Unsigned;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

/// Why a signature did not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Algorithm, curve or parameter combination this crate cannot check.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Well-formed input whose signature is wrong.
    #[error("signature does not verify")]
    Invalid,
}

/// Digest algorithms. `id` matches zkpassport's canonical hash identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Hash {
    /// SHA-1
    Sha1,
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl Hash {
    /// Maps a digest algorithm OID.
    pub fn from_oid(oid: &str) -> Option<Self> {
        Some(match oid {
            "1.3.14.3.2.26" => Self::Sha1,
            "2.16.840.1.101.3.4.2.4" => Self::Sha224,
            "2.16.840.1.101.3.4.2.1" => Self::Sha256,
            "2.16.840.1.101.3.4.2.2" => Self::Sha384,
            "2.16.840.1.101.3.4.2.3" => Self::Sha512,
            _ => return None,
        })
    }

    /// Lowercase name, e.g. `sha256`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// Digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha224 => Sha224::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// A signature scheme with its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scheme {
    /// RSASSA-PKCS1-v1_5.
    RsaPkcs1(Hash),
    /// RSASSA-PSS with MGF1.
    RsaPss {
        /// Message digest.
        hash: Hash,
        /// MGF1 digest.
        mgf: Hash,
        /// Salt length in bytes.
        salt: usize,
    },
    /// ECDSA, DER `SEQUENCE { r, s }` (X9.62) or plain `r || s` (BSI TR-03111).
    Ecdsa {
        /// Message digest.
        hash: Hash,
        /// BSI plain encoding.
        plain: bool,
    },
}

impl Scheme {
    /// Maps a signature AlgorithmIdentifier. `digest` is the SignerInfo digest
    /// algorithm, needed when CMS names only the key algorithm.
    pub fn from_algorithm(
        oid: &str,
        params: Option<&[u8]>,
        digest: Option<Hash>,
    ) -> Result<Self, VerifyError> {
        let hash_or = |h: Option<Hash>| h.ok_or_else(|| VerifyError::Unsupported(oid.into()));
        Ok(match oid {
            "1.2.840.113549.1.1.1" => Self::RsaPkcs1(hash_or(digest)?),
            "1.2.840.113549.1.1.5" => Self::RsaPkcs1(Hash::Sha1),
            "1.2.840.113549.1.1.14" => Self::RsaPkcs1(Hash::Sha224),
            "1.2.840.113549.1.1.11" => Self::RsaPkcs1(Hash::Sha256),
            "1.2.840.113549.1.1.12" => Self::RsaPkcs1(Hash::Sha384),
            "1.2.840.113549.1.1.13" => Self::RsaPkcs1(Hash::Sha512),
            "1.2.840.113549.1.1.10" => pss_params(params)?,
            "1.2.840.10045.2.1" => Self::Ecdsa {
                hash: hash_or(digest)?,
                plain: false,
            },
            "1.2.840.10045.4.1" => Self::Ecdsa {
                hash: Hash::Sha1,
                plain: false,
            },
            "1.2.840.10045.4.3.1" => Self::Ecdsa {
                hash: Hash::Sha224,
                plain: false,
            },
            "1.2.840.10045.4.3.2" => Self::Ecdsa {
                hash: Hash::Sha256,
                plain: false,
            },
            "1.2.840.10045.4.3.3" => Self::Ecdsa {
                hash: Hash::Sha384,
                plain: false,
            },
            "1.2.840.10045.4.3.4" => Self::Ecdsa {
                hash: Hash::Sha512,
                plain: false,
            },
            "0.4.0.127.0.7.1.1.4.1.1" => Self::Ecdsa {
                hash: Hash::Sha1,
                plain: true,
            },
            "0.4.0.127.0.7.1.1.4.1.2" => Self::Ecdsa {
                hash: Hash::Sha224,
                plain: true,
            },
            "0.4.0.127.0.7.1.1.4.1.3" => Self::Ecdsa {
                hash: Hash::Sha256,
                plain: true,
            },
            "0.4.0.127.0.7.1.1.4.1.4" => Self::Ecdsa {
                hash: Hash::Sha384,
                plain: true,
            },
            "0.4.0.127.0.7.1.1.4.1.5" => Self::Ecdsa {
                hash: Hash::Sha512,
                plain: true,
            },
            _ => {
                return Err(VerifyError::Unsupported(format!(
                    "signature algorithm {oid}"
                )))
            }
        })
    }

    /// Stable name, e.g. `rsa-pss-sha256-mgf1-sha256-salt32` or `ecdsa-sha384`.
    pub fn name(&self) -> String {
        match self {
            Self::RsaPkcs1(h) => format!("rsa-pkcs1v15-{}", h.name()),
            Self::RsaPss { hash, mgf, salt } => {
                format!("rsa-pss-{}-mgf1-{}-salt{salt}", hash.name(), mgf.name())
            }
            Self::Ecdsa { hash, plain: false } => format!("ecdsa-{}", hash.name()),
            Self::Ecdsa { hash, plain: true } => format!("ecdsa-plain-{}", hash.name()),
        }
    }

    fn hash(&self) -> Hash {
        match self {
            Self::RsaPkcs1(h) | Self::RsaPss { hash: h, .. } | Self::Ecdsa { hash: h, .. } => *h,
        }
    }
}

/// `RSASSA-PSS-params ::= SEQUENCE { [0] hash, [1] mgf, [2] saltLength, [3] trailer }`
/// with RFC 4055 defaults (SHA-1, MGF1-SHA-1, 20).
fn pss_params(params: Option<&[u8]>) -> Result<Scheme, VerifyError> {
    let bad = || VerifyError::Unsupported("malformed RSASSA-PSS parameters".into());
    let (mut hash, mut mgf, mut salt) = (Hash::Sha1, Hash::Sha1, 20usize);
    if let Some(p) = params {
        let (seq, _) = der::expect(p, 0x30).ok_or_else(bad)?;
        for field in der::children(seq.content).ok_or_else(bad)? {
            let (inner, _) = der::read(field.content).ok_or_else(bad)?;
            match field.tag {
                0xa0 => {
                    let (oid, _) = der::algorithm(inner.content).ok_or_else(bad)?;
                    hash = Hash::from_oid(&oid).ok_or_else(bad)?;
                }
                0xa1 => {
                    let (oid, mgf_params) = der::algorithm(inner.content).ok_or_else(bad)?;
                    let (alg, _) =
                        der::expect(mgf_params.ok_or_else(bad)?, 0x30).ok_or_else(bad)?;
                    let (mgf_hash, _) = der::algorithm(alg.content).ok_or_else(bad)?;
                    if oid != "1.2.840.113549.1.1.8" {
                        return Err(VerifyError::Unsupported(format!("PSS mask function {oid}")));
                    }
                    mgf = Hash::from_oid(&mgf_hash).ok_or_else(bad)?;
                }
                0xa2 => {
                    salt = der::uint(inner.content)
                        .iter()
                        .fold(0usize, |acc, &b| acc << 8 | usize::from(b));
                }
                _ => {}
            }
        }
    }
    Ok(Scheme::RsaPss { hash, mgf, salt })
}

/// A named curve this crate knows the domain parameters of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Curve {
    /// Row index in the curve table; stable, used as the leaf's curve id.
    pub index: usize,
}

impl Curve {
    /// Resolves a named-curve OID.
    pub fn from_oid(oid: &str) -> Option<Self> {
        curves::NAMED
            .iter()
            .position(|row| row.1 == oid)
            .map(|index| Self { index })
    }

    /// Resolves explicit `SpecifiedECDomain` parameters (content of the SEQUENCE)
    /// by comparing p, a, b and n with the named curves.
    pub fn from_explicit(content: &[u8]) -> Option<Self> {
        let parts = der::children(content)?;
        let field = der::children(parts.get(1)?.content)?;
        let curve = der::children(parts.get(2)?.content)?;
        let norm = |b: &[u8]| hex::encode(der::uint(b));
        let (p, a, b, n) = (
            norm(field.get(1)?.content),
            norm(curve.first()?.content),
            norm(curve.get(1)?.content),
            norm(parts.get(4)?.content),
        );
        let trim = |s: &str| s.trim_start_matches('0').to_string();
        curves::NAMED
            .iter()
            .position(|row| {
                (trim(row.2), trim(row.3), trim(row.4), trim(row.7))
                    == (trim(&p), trim(&a), trim(&b), trim(&n))
            })
            .map(|index| Self { index })
    }

    /// Curve name, e.g. `brainpoolP384r1`.
    pub fn name(self) -> &'static str {
        curves::NAMED[self.index].0
    }

    /// Canonical id committed in registry leaves (table index + 1; 0 = not EC).
    pub fn id(self) -> u8 {
        u8::try_from(self.index + 1).unwrap_or(u8::MAX)
    }
}

/// A subject public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// RSA modulus and exponent, big-endian without leading zeros.
    Rsa {
        /// Modulus.
        n: Vec<u8>,
        /// Public exponent.
        e: Vec<u8>,
    },
    /// EC point (SEC1). `curve` is `None` for explicit parameters that match no
    /// known curve.
    Ec {
        /// Resolved curve.
        curve: Option<Curve>,
        /// SEC1-encoded point.
        point: Vec<u8>,
    },
}

impl PublicKey {
    /// Parses a DER SubjectPublicKeyInfo.
    pub fn from_spki(spki: &[u8]) -> Result<Self, VerifyError> {
        let bad = |what: &str| VerifyError::Unsupported(format!("public key: {what}"));
        let (seq, _) = der::expect(spki, 0x30).ok_or_else(|| bad("not a SEQUENCE"))?;
        let (alg, rest) = der::expect(seq.content, 0x30).ok_or_else(|| bad("algorithm"))?;
        let (bits, _) = der::expect(rest, 0x03).ok_or_else(|| bad("key bits"))?;
        let key = bits.content.get(1..).ok_or_else(|| bad("key bits"))?;
        let (oid, params) = der::algorithm(alg.content).ok_or_else(|| bad("algorithm"))?;
        match oid.as_str() {
            "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
                let (rsa, _) = der::expect(key, 0x30).ok_or_else(|| bad("RSA key"))?;
                let parts = der::children(rsa.content).ok_or_else(|| bad("RSA key"))?;
                let [n, e] = parts.as_slice() else {
                    return Err(bad("RSA key"));
                };
                Ok(Self::Rsa {
                    n: der::uint(n.content).to_vec(),
                    e: der::uint(e.content).to_vec(),
                })
            }
            "1.2.840.10045.2.1" => {
                let (p, _) = der::read(params.ok_or_else(|| bad("EC parameters"))?)
                    .ok_or_else(|| bad("EC parameters"))?;
                let curve = match p.tag {
                    0x06 => der::oid(p.content).and_then(|o| Curve::from_oid(&o)),
                    0x30 => Curve::from_explicit(p.content),
                    _ => None,
                };
                Ok(Self::Ec {
                    curve,
                    point: key.to_vec(),
                })
            }
            other => Err(bad(other)),
        }
    }

    /// Bytes committed for the key: RSA modulus, or EC `x || y`.
    pub fn material(&self) -> &[u8] {
        match self {
            Self::Rsa { n, .. } => n,
            Self::Ec { point, .. } => point.get(1..).unwrap_or_default(),
        }
    }

    /// Size in bits (modulus or field).
    pub fn bits(&self) -> usize {
        match self {
            Self::Rsa { n, .. } => n
                .first()
                .map_or(0, |b| (n.len() - 1) * 8 + (8 - b.leading_zeros() as usize)),
            Self::Ec { curve: Some(c), .. } => match c.name() {
                "P-521" => 521,
                name => name.trim_start_matches(|ch: char| !ch.is_ascii_digit())[..3]
                    .parse()
                    .unwrap_or(0),
            },
            Self::Ec { point, .. } => point.len().saturating_sub(1) / 2 * 8,
        }
    }

    /// Short description, e.g. `RSA-4096` or `EC-brainpoolP512r1`.
    pub fn describe(&self) -> String {
        match self {
            Self::Rsa { .. } => format!("RSA-{}", self.bits()),
            Self::Ec { curve: Some(c), .. } => format!("EC-{}", c.name()),
            Self::Ec { .. } => "EC-explicit-unknown".into(),
        }
    }
}

/// Verifies `sig` over `msg` under `key` with `scheme`.
pub fn verify(scheme: &Scheme, key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
    let hashed = scheme.hash().digest(msg);
    match (scheme, key) {
        (Scheme::RsaPkcs1(_) | Scheme::RsaPss { .. }, PublicKey::Rsa { n, e }) => {
            verify_rsa(scheme, n, e, &hashed, sig)
        }
        (Scheme::Ecdsa { plain, .. }, PublicKey::Ec { curve, point }) => {
            let curve =
                curve.ok_or_else(|| VerifyError::Unsupported("unknown explicit curve".into()))?;
            let (r, s) = ecdsa_rs(sig, *plain).ok_or(VerifyError::Invalid)?;
            verify_ecdsa(curve, point, &hashed, r, s)
        }
        _ => Err(VerifyError::Unsupported(format!(
            "{} with {}",
            scheme.name(),
            key.describe()
        ))),
    }
}

fn verify_rsa(
    scheme: &Scheme,
    n: &[u8],
    e: &[u8],
    hashed: &[u8],
    sig: &[u8],
) -> Result<(), VerifyError> {
    use rsa::{BigUint, Pkcs1v15Sign, Pss, RsaPublicKey};
    let key = RsaPublicKey::new_with_max_size(
        BigUint::from_bytes_be(n),
        BigUint::from_bytes_be(e),
        16384,
    )
    .map_err(|err| VerifyError::Unsupported(format!("RSA key: {err}")))?;
    // Some encoders drop leading zero bytes of the signature.
    let mut padded = vec![0u8; n.len().saturating_sub(sig.len())];
    padded.extend_from_slice(sig);
    let result = match *scheme {
        Scheme::RsaPkcs1(h) => {
            let padding = match h {
                Hash::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
                Hash::Sha224 => Pkcs1v15Sign::new::<Sha224>(),
                Hash::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
                Hash::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
                Hash::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
            };
            key.verify(padding, hashed, &padded)
        }
        Scheme::RsaPss { hash, mgf, salt } => {
            if hash != mgf {
                return Err(VerifyError::Unsupported(format!(
                    "PSS with MGF1-{}",
                    mgf.name()
                )));
            }
            let padding = match hash {
                Hash::Sha1 => Pss::new_with_salt::<Sha1>(salt),
                Hash::Sha224 => Pss::new_with_salt::<Sha224>(salt),
                Hash::Sha256 => Pss::new_with_salt::<Sha256>(salt),
                Hash::Sha384 => Pss::new_with_salt::<Sha384>(salt),
                Hash::Sha512 => Pss::new_with_salt::<Sha512>(salt),
            };
            key.verify(padding, hashed, &padded)
        }
        Scheme::Ecdsa { .. } => return Err(VerifyError::Invalid),
    };
    result.map_err(|_| VerifyError::Invalid)
}

/// `(r, s)` from a DER `SEQUENCE { INTEGER, INTEGER }` or plain `r || s`.
fn ecdsa_rs(sig: &[u8], plain: bool) -> Option<(&[u8], &[u8])> {
    if plain {
        return sig
            .len()
            .is_multiple_of(2)
            .then(|| sig.split_at(sig.len() / 2));
    }
    let (seq, _) = der::expect(sig, 0x30)?;
    let parts = der::children(seq.content)?;
    let [r, s] = parts.as_slice() else {
        return None;
    };
    Some((der::uint(r.content), der::uint(s.content)))
}

macro_rules! verify_on {
    ($curve:ty, $point:expr, $hashed:expr, $r:expr, $s:expr) => {{
        let size = <<$curve as elliptic_curve::Curve>::FieldBytesSize as Unsigned>::USIZE;
        let key = ecdsa::VerifyingKey::<$curve>::from_sec1_bytes($point)
            .map_err(|_| VerifyError::Invalid)?;
        let rs = [left_pad($r, size)?, left_pad($s, size)?].concat();
        let sig = ecdsa::Signature::<$curve>::from_slice(&rs).map_err(|_| VerifyError::Invalid)?;
        // RustCrypto requires a prehash of at least half the field size; left
        // zero-padding up to that keeps the integer value (it stays below n's
        // bit length), so a SHA-1 signature on a 384-bit curve still checks.
        let prehash = left_pad($hashed, $hashed.len().max(size.div_ceil(2)))?;
        key.verify_prehash(&prehash, &sig)
            .map_err(|_| VerifyError::Invalid)
    }};
}

fn verify_ecdsa(
    curve: Curve,
    point: &[u8],
    hashed: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<(), VerifyError> {
    match curve.name() {
        "P-256" => verify_on!(p256::NistP256, point, hashed, r, s),
        "P-384" => verify_on!(p384::NistP384, point, hashed, r, s),
        "P-521" => verify_on!(p521::NistP521, point, hashed, r, s),
        "brainpoolP256r1" => verify_on!(bp256::BrainpoolP256r1, point, hashed, r, s),
        "brainpoolP384r1" => verify_on!(bp384::BrainpoolP384r1, point, hashed, r, s),
        "brainpoolP512r1" => verify_on!(bp512::BrainpoolP512r1, point, hashed, r, s),
        other => Err(VerifyError::Unsupported(format!("ECDSA on {other}"))),
    }
}

fn left_pad(b: &[u8], size: usize) -> Result<Vec<u8>, VerifyError> {
    let b = der::uint(b);
    if b.len() > size {
        return Err(VerifyError::Invalid);
    }
    let mut out = vec![0u8; size - b.len()];
    out.extend_from_slice(b);
    Ok(out)
}
