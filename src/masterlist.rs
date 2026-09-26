//! ICAO CSCA master lists (Doc 9303-12 §9): CMS SignedData whose eContent is
//! `CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF Certificate }`.

use crate::cert::Cert;
use crate::crypto::{self, Hash, Scheme};
use crate::der;
use anyhow::{bail, Context, Result};

const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const ID_ICAO_CSCA_MASTER_LIST: &str = "2.23.136.1.1.2";
const ID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const ID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

/// A verified master list.
#[derive(Debug)]
pub struct MasterList {
    /// Certificates in the list that parsed.
    pub certs: Vec<Cert>,
    /// Entries in the list that did not parse, with the reason.
    pub unparsable: Vec<String>,
    /// The ML signer certificate.
    pub signer: Cert,
    /// Fingerprint of the in-list `country` CSCA whose key signed `signer`.
    pub anchor: String,
}

/// Parses and verifies a master list published by `country`:
/// 1. the CMS signature (over signed attributes, whose messageDigest must match
///    the eContent) verifies under one of the embedded certificates, and
/// 2. that signer certificate is signed by a `country` CSCA contained in the list.
pub fn load(der: &[u8], country: &str) -> Result<MasterList> {
    let sd = signed_data(der).context("malformed CMS SignedData")?;
    if sd.content_type != ID_ICAO_CSCA_MASTER_LIST {
        bail!(
            "eContentType {} is not id-icao-cscaMasterList",
            sd.content_type
        );
    }
    let (certs, unparsable) = parse_content(sd.content).context("malformed CscaMasterList")?;

    let signed = match sd.signed_attrs {
        Some(attrs) => {
            check_signed_attrs(attrs, sd.digest, sd.content)?;
            // Signature covers the attributes re-tagged as a SET (RFC 5652 §5.4).
            let mut buf = attrs.to_vec();
            buf[0] = 0x31;
            buf
        }
        None => sd.content.to_vec(),
    };
    let scheme = Scheme::from_algorithm(&sd.sig_oid, sd.sig_params, Some(sd.digest))
        .map_err(|e| anyhow::anyhow!("signer algorithm: {e}"))?;
    let signer = sd
        .certificates
        .iter()
        .filter_map(|c| Cert::from_der(c).ok())
        .find(|c| {
            c.key
                .as_ref()
                .is_ok_and(|k| crypto::verify(&scheme, k, &signed, sd.signature).is_ok())
        })
        .context("CMS signature does not verify under any embedded certificate")?;

    let own: Vec<&Cert> = certs.iter().filter(|c| c.country == country).collect();
    let anchor = own
        .iter()
        .find(|a| a.key.as_ref().is_ok_and(|k| signer.verify_with(k).is_ok()))
        .map(|a| a.fingerprint.clone())
        .with_context(|| {
            format!(
                "signer {} is not signed by any of the {} {country} CSCAs in the list",
                signer.subject,
                own.len()
            )
        })?;
    Ok(MasterList {
        certs,
        unparsable,
        signer,
        anchor,
    })
}

struct SignedData<'a> {
    content_type: String,
    content: &'a [u8],
    certificates: Vec<&'a [u8]>,
    digest: Hash,
    signed_attrs: Option<&'a [u8]>,
    sig_oid: String,
    sig_params: Option<&'a [u8]>,
    signature: &'a [u8],
}

fn signed_data(der: &[u8]) -> Option<SignedData<'_>> {
    let (ci, _) = der::expect(der, 0x30)?;
    let (oid, rest) = der::expect(ci.content, 0x06)?;
    if der::oid(oid.content)? != ID_SIGNED_DATA {
        return None;
    }
    let (explicit, _) = der::expect(rest, 0xa0)?;
    let (sd, _) = der::expect(explicit.content, 0x30)?;
    let fields = der::children(sd.content)?;
    // version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
    let encap = der::children(fields.get(2)?.content)?;
    let content_type = der::oid(encap.first()?.content)?;
    let (octets, _) = der::expect(encap.get(1)?.content, 0x04)?;
    let certificates = fields
        .iter()
        .find(|f| f.tag == 0xa0)
        .and_then(|f| der::children(f.content))
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.raw)
        .collect();
    let signer_infos = der::children(fields.last()?.content)?;
    // Master lists carry exactly one SignerInfo.
    let [si] = signer_infos.as_slice() else {
        return None;
    };
    let si = der::children(si.content)?;
    // version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature
    let (digest_oid, _) = der::algorithm(si.get(2)?.content)?;
    let attrs = si.get(3).filter(|t| t.tag == 0xa0);
    let rest = &si[if attrs.is_some() { 4 } else { 3 }..];
    let (sig_oid, sig_params) = der::algorithm(rest.first()?.content)?;
    Some(SignedData {
        content_type,
        content: octets.content,
        certificates,
        digest: Hash::from_oid(&digest_oid)?,
        signed_attrs: attrs.map(|a| a.raw),
        sig_oid,
        sig_params,
        signature: rest.get(1)?.content,
    })
}

fn check_signed_attrs(attrs: &[u8], digest: Hash, content: &[u8]) -> Result<()> {
    let (set, _) = der::read(attrs).context("signedAttrs")?;
    let mut digest_ok = false;
    for attr in der::children(set.content).context("signedAttrs")? {
        let parts = der::children(attr.content).context("attribute")?;
        let (Some(oid), Some(values)) = (parts.first(), parts.get(1)) else {
            bail!("malformed attribute");
        };
        let value = der::read(values.content).context("attribute value")?.0;
        match der::oid(oid.content).as_deref() {
            Some(ID_MESSAGE_DIGEST) => digest_ok = value.content == digest.digest(content),
            Some(ID_CONTENT_TYPE) => {
                if der::oid(value.content).as_deref() != Some(ID_ICAO_CSCA_MASTER_LIST) {
                    bail!("signed contentType attribute mismatch");
                }
            }
            _ => {}
        }
    }
    if !digest_ok {
        bail!("messageDigest attribute missing or does not match the content");
    }
    Ok(())
}

type Parsed = (Vec<Cert>, Vec<String>);

fn parse_content(b: &[u8]) -> Option<Parsed> {
    let (seq, _) = der::expect(b, 0x30)?;
    let (_, rest) = der::expect(seq.content, 0x02)?;
    let (set, _) = der::expect(rest, 0x31)?;
    let mut certs = vec![];
    let mut errors = vec![];
    for t in der::children(set.content)? {
        match Cert::from_der(t.raw) {
            Ok(c) => certs.push(c),
            Err(e) => errors.push(format!("{e:#}")),
        }
    }
    Some((certs, errors))
}
