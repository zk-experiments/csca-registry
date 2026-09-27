//! Certificate and CRL model: the fields the registry needs, extracted once.

use crate::crypto::{self, PublicKey, Scheme, VerifyError};
use crate::der;
use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};
use x509_parser::revocation_list::CertificateRevocationList;

/// A parsed certificate.
#[derive(Debug, Clone)]
pub struct Cert {
    /// Full DER.
    pub der: Vec<u8>,
    /// sha256(DER), hex.
    pub fingerprint: String,
    /// Subject, RFC 4514-ish.
    pub subject: String,
    /// Issuer, RFC 4514-ish.
    pub issuer: String,
    /// Canonical subject used to find issuers.
    pub subject_key: String,
    /// Canonical issuer used to find issuers.
    pub issuer_key: String,
    /// Subject (else issuer) country, upper-case alpha-2.
    pub country: String,
    /// Serial, big-endian without leading zeros.
    pub serial: Vec<u8>,
    /// Validity start, unix seconds.
    pub not_before: i64,
    /// Validity end, unix seconds.
    pub not_after: i64,
    /// PrivateKeyUsagePeriod, unix seconds.
    pub private_key_usage: Option<(Option<i64>, Option<i64>)>,
    /// Subject key identifier.
    pub ski: Option<Vec<u8>>,
    /// Authority key identifier.
    pub aki: Option<Vec<u8>>,
    /// Subject public key.
    pub key: Result<PublicKey, VerifyError>,
    /// Scheme the issuer signed this certificate with.
    pub scheme: Result<Scheme, VerifyError>,
    /// Signature algorithm OID as written.
    pub signature_oid: String,
    tbs: Vec<u8>,
    signature: Vec<u8>,
}

impl Cert {
    /// Parses a DER certificate.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (_, x) = X509Certificate::from_der(der).map_err(|e| anyhow!("x509: {e}"))?;
        let (tbs, oid, params, signature) =
            der::signed_parts(der).context("certificate outer structure")?;
        let ext = |oid: &str| {
            x.extensions()
                .iter()
                .find(|e| e.oid.to_id_string() == oid)
                .map(|e| e.value)
        };
        let country = country(x.subject())
            .or_else(|| country(x.issuer()))
            .unwrap_or_default();
        Ok(Self {
            der: der.to_vec(),
            fingerprint: hex::encode(Sha256::digest(der)),
            subject: x.subject().to_string(),
            issuer: x.issuer().to_string(),
            subject_key: name_key(x.subject()),
            issuer_key: name_key(x.issuer()),
            country,
            serial: der::uint(x.raw_serial()).to_vec(),
            not_before: x.validity().not_before.timestamp(),
            not_after: x.validity().not_after.timestamp(),
            private_key_usage: ext("2.5.29.16").and_then(pkup),
            ski: ext("2.5.29.14").and_then(|v| Some(der::expect(v, 0x04)?.0.content.to_vec())),
            aki: ext("2.5.29.35").and_then(aki),
            key: PublicKey::from_spki(x.public_key().raw),
            scheme: Scheme::from_algorithm(&oid, params, None),
            signature_oid: oid,
            tbs: tbs.to_vec(),
            signature: signature.to_vec(),
        })
    }

    /// Whether `issuer`'s key verifies this certificate's signature.
    pub fn verify_with(&self, issuer: &PublicKey) -> Result<(), VerifyError> {
        let scheme = self.scheme.clone()?;
        crypto::verify(&scheme, issuer, &self.tbs, &self.signature)
    }
}

/// A parsed CRL.
#[derive(Debug, Clone)]
pub struct Crl {
    /// Full DER.
    pub der: Vec<u8>,
    /// Canonical issuer.
    pub issuer_key: String,
    /// thisUpdate, unix seconds.
    pub this_update: i64,
    /// (serial without leading zeros, revocation time).
    pub revoked: Vec<(Vec<u8>, i64)>,
    scheme: Result<Scheme, VerifyError>,
    tbs: Vec<u8>,
    signature: Vec<u8>,
}

impl Crl {
    /// Parses a DER CRL.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (_, crl) = CertificateRevocationList::from_der(der).map_err(|e| anyhow!("crl: {e}"))?;
        let (tbs, oid, params, signature) =
            der::signed_parts(der).context("CRL outer structure")?;
        Ok(Self {
            der: der.to_vec(),
            issuer_key: name_key(crl.issuer()),
            this_update: crl.last_update().timestamp(),
            revoked: crl
                .iter_revoked_certificates()
                .map(|r| {
                    (
                        der::uint(r.raw_serial()).to_vec(),
                        r.revocation_date.timestamp(),
                    )
                })
                .collect(),
            scheme: Scheme::from_algorithm(&oid, params, None),
            tbs: tbs.to_vec(),
            signature: signature.to_vec(),
        })
    }

    /// Whether `issuer`'s key verifies this CRL.
    pub fn verify_with(&self, issuer: &PublicKey) -> Result<(), VerifyError> {
        let scheme = self.scheme.clone()?;
        crypto::verify(&scheme, issuer, &self.tbs, &self.signature)
    }
}

fn country(name: &X509Name<'_>) -> Option<String> {
    let c = name
        .iter_country()
        .next()
        .and_then(|c| c.as_str().ok())
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())?;
    // The United Nations' first CSCA (2012-2022, in the ICAO Master List)
    // wrote the user-assigned `ZZ`; its laissez-passers carry UNO like the
    // current `C=UN` CSCA's. Any other `ZZ` stays an unknown issuer.
    let united_nations = name.iter_organization().any(|o| {
        o.as_str()
            .is_ok_and(|o| o.trim().eq_ignore_ascii_case("United Nations"))
    });
    Some(if c == "ZZ" && united_nations {
        "UN".into()
    } else {
        c
    })
}

/// Case- and whitespace-insensitive name: countries mix PrintableString and
/// UTF8String (and letter case) for the same DN across a CSCA and its links.
fn name_key(name: &X509Name<'_>) -> String {
    name.iter_attributes()
        .map(|a| {
            let value = a.as_str().map_or_else(
                |_| hex::encode(a.attr_value().data),
                |s| {
                    s.split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .to_lowercase()
                },
            );
            format!("{}={value}", a.attr_type().to_id_string())
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// `AuthorityKeyIdentifier ::= SEQUENCE { [0] keyIdentifier OPTIONAL, ... }`
fn aki(value: &[u8]) -> Option<Vec<u8>> {
    let (seq, _) = der::expect(value, 0x30)?;
    der::children(seq.content)?
        .into_iter()
        .find(|t| t.tag == 0x80)
        .map(|t| t.content.to_vec())
}

/// `PrivateKeyUsagePeriod ::= SEQUENCE { [0] GeneralizedTime OPTIONAL, [1] GeneralizedTime OPTIONAL }`
fn pkup(value: &[u8]) -> Option<(Option<i64>, Option<i64>)> {
    let (seq, _) = der::expect(value, 0x30)?;
    let (mut from, mut to) = (None, None);
    for t in der::children(seq.content)? {
        let at = generalized_time(t.content);
        match t.tag {
            0x80 => from = at,
            0x81 => to = at,
            _ => {}
        }
    }
    Some((from, to))
}

/// `YYYYMMDDHHMMSS[.f]Z` to unix seconds.
fn generalized_time(b: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(b).ok()?;
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (hh, mm, ss) = (num(8..10)?, num(10..12)?, num(12..14)?);
    // days_from_civil (H. Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::generalized_time;

    /// The United Nations' first CSCA writes `C=ZZ`; it's still the UN
    /// (committed as UNO), so documents it vouched for can be proven.
    #[test]
    fn united_nations_zz_csca_is_un() {
        let c =
            super::Cert::from_der(include_bytes!("../tests/fixtures/un-csca-2012.der")).unwrap();
        assert_eq!(c.country, "UN");
        assert_eq!(crate::country::alpha3(&c.country), Some("UNO"));
    }

    #[test]
    fn generalized_time_to_unix() {
        assert_eq!(generalized_time(b"19700101000000Z"), Some(0));
        assert_eq!(generalized_time(b"20240229123456Z"), Some(1_709_210_096));
        assert_eq!(generalized_time(b"2024"), None);
    }
}
