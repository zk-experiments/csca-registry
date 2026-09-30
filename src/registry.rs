//! Builds the combined registry from source files.

use crate::cert::{Cert, Crl};
use crate::commitment::{self, KeyHeader, Tree, KEY_TREE_HEIGHT, REVOCATION_TREE_HEIGHT};
use crate::crypto::{PublicKey, VerifyError};
use crate::ldif::{self, Object};
use crate::masterlist;
use crate::output::{
    self, Certificate, Commitment, Country, Key, KeyInfo, Period, Revocation, Source,
};
use anyhow::{Context, Result};
use ark_bn254::Fr;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

/// Accumulates sources, then [`Builder::finish`]es into a [`output::Registry`].
#[derive(Debug, Default)]
pub struct Builder {
    certs: BTreeMap<String, (Cert, BTreeSet<String>)>,
    crls: Vec<(String, Crl)>,
    dscs: Vec<Cert>,
    sources: Vec<Source>,
    carried: Vec<(String, Revocation)>,
}

impl Builder {
    /// Adds a file, or every file under a directory (sorted, recursive).
    /// Standalone master lists must be named `<publisher alpha-2>_*.ml`.
    pub fn add_path(&mut self, path: &Path) -> Result<()> {
        if path.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(path)
                .with_context(|| format!("read {}", path.display()))?
                .map(|e| e.map(|e| e.path()))
                .collect::<std::io::Result<_>>()?;
            entries.sort();
            return entries.iter().try_for_each(|e| self.add_path(e));
        }
        let name = path.to_string_lossy().to_string();
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if !matches!(
            ext.as_str(),
            "ml" | "ldif" | "crl" | "cer" | "crt" | "der" | "pem"
        ) {
            return Ok(());
        }
        let bytes = std::fs::read(path).with_context(|| format!("read {name}"))?;
        let file_name = path
            .file_name()
            .map(|f| f.to_string_lossy())
            .unwrap_or_default();
        match ext.as_str() {
            "ml" => {
                let country: String = file_name.chars().take(2).collect::<String>().to_uppercase();
                self.add_masterlist(&name, &bytes, &country);
            }
            "ldif" => self.add_ldif(&name, &String::from_utf8_lossy(&bytes)),
            "crl" => self.add_crl(&name, &bytes),
            _ => self.add_certificates(&name, &bytes),
        }
        Ok(())
    }

    /// Adds a CMS master list published by `country`; its certificates count
    /// only if it verifies (see [`masterlist::load`]).
    pub fn add_masterlist(&mut self, name: &str, der: &[u8], country: &str) {
        let mut src = source(name, "masterlist", der);
        src.country = Some(country.into());
        match masterlist::load(der, country) {
            Ok(ml) => {
                src.status = "trusted".into();
                src.anchor = Some(ml.anchor);
                src.signature_scheme = ml.signer.scheme.as_ref().map(|s| s.name()).ok();
                src.certificates = Some(ml.certs.len());
                src.unparsable = ml.unparsable;
                for c in ml.certs {
                    self.add_cert(c, name);
                }
            }
            Err(e) => {
                src.status = "rejected".into();
                src.error = Some(format!("{e:#}"));
            }
        }
        self.push_source(src);
    }

    /// Adds loose certificates (DER or PEM bundle), trusted as operator-provided.
    pub fn add_certificates(&mut self, name: &str, bytes: &[u8]) {
        let mut src = source(name, "certificate", bytes);
        let ders = if bytes.starts_with(b"-----") {
            pem_blocks(bytes)
        } else {
            vec![bytes.to_vec()]
        };
        let parsed: Result<Vec<Cert>> = ders.iter().map(|d| Cert::from_der(d)).collect();
        match parsed {
            Ok(certs) => {
                src.status = "manual".into();
                src.certificates = Some(certs.len());
                certs.into_iter().for_each(|c| self.add_cert(c, name));
            }
            Err(e) => {
                src.status = "error".into();
                src.error = Some(format!("{e:#}"));
            }
        }
        self.push_source(src);
    }

    /// Keeps `prev`'s revocations: a revoked certificate stays revoked when a
    /// later CRL no longer lists it (or can't be fetched). Applied in
    /// [`Builder::finish`] for issuer keys still in the registry.
    pub fn carry_revocations(&mut self, prev: &output::Registry) {
        let from = prev.commitment.root.clone();
        self.carried
            .extend(prev.revocations.iter().map(|r| (from.clone(), r.clone())));
    }

    /// Adds a CRL; applied in [`Builder::finish`] if a registry key verifies it.
    pub fn add_crl(&mut self, name: &str, der: &[u8]) {
        match Crl::from_der(der) {
            Ok(crl) => self.crls.push((name.into(), crl)),
            Err(e) => {
                let mut src = source(name, "crl", der);
                src.status = "error".into();
                src.error = Some(format!("{e:#}"));
                self.push_source(src);
            }
        }
    }

    /// Adds an ICAO PKD LDIF: master lists, CRLs, and DSCs (country profile only).
    pub fn add_ldif(&mut self, name: &str, text: &str) {
        let mut dsc = 0;
        for e in ldif::entries(text) {
            let entry_name = format!("{name}#{}", e.dn);
            match e.kind {
                Object::MasterList => self.add_masterlist(&entry_name, &e.der, &e.country),
                Object::Crl => self.add_crl(&entry_name, &e.der),
                Object::Dsc => {
                    if let Ok(c) = Cert::from_der(&e.der) {
                        self.dscs.push(c);
                        dsc += 1;
                    }
                }
            }
        }
        let mut src = source(name, "ldif", text.as_bytes());
        src.status = "parsed".into();
        src.dsc = Some(dsc);
        self.push_source(src);
    }

    fn add_cert(&mut self, c: Cert, source: &str) {
        self.certs
            .entry(c.fingerprint.clone())
            .or_insert_with(|| (c, BTreeSet::new()))
            .1
            .insert(source.into());
    }

    fn push_source(&mut self, src: Source) {
        tracing::info!(
            name = %src.name,
            kind = %src.kind,
            status = %src.status,
            certificates = ?src.certificates,
            error = ?src.error,
            "source"
        );
        self.sources.push(src);
    }

    /// Resolves chains, applies CRLs, groups keys and builds the commitment.
    pub fn finish(mut self) -> Result<output::Registry> {
        let mut by_name: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut by_ski: HashMap<&[u8], Vec<&str>> = HashMap::new();
        for (fp, (c, _)) in &self.certs {
            by_name.entry(&c.subject_key).or_default().push(fp);
            if let Some(ski) = &c.ski {
                by_ski.entry(ski).or_default().push(fp);
            }
        }

        let chains: BTreeMap<String, Chain> = self
            .certs
            .iter()
            .map(|(fp, (c, _))| {
                (
                    fp.clone(),
                    resolve_chain(c, fp, &self.certs, &by_name, &by_ski),
                )
            })
            .collect();

        // Revocations are keyed by the issuing *key*: a CSCA's root and link
        // certificates share it, and the circuit only sees the key.
        let mut revoked: BTreeMap<(String, Vec<u8>), (i64, String, String)> = BTreeMap::new();
        let mut crl_sources = vec![];
        for (name, crl) in std::mem::take(&mut self.crls) {
            let mut src = source(&name, "crl", &crl.der);
            let issuer = by_name.get(crl.issuer_key.as_str()).and_then(|cands| {
                cands.iter().find(|fp| {
                    self.certs[**fp]
                        .0
                        .key
                        .as_ref()
                        .is_ok_and(|k| crl.verify_with(k).is_ok())
                })
            });
            if let Some(fp) = issuer {
                let issuer = &self.certs[*fp].0;
                let key_id = key_id(issuer.key.as_ref().ok());
                src.status = "trusted".into();
                src.anchor = Some((*fp).to_string());
                src.revoked = Some(crl.revoked.len());
                src.this_update = Some(crl.this_update);
                for (serial, at) in &crl.revoked {
                    let e = revoked
                        .entry((key_id.clone().unwrap_or_default(), serial.clone()))
                        .or_insert((*at, name.clone(), (*fp).to_string()));
                    e.0 = e.0.min(*at);
                }
            } else {
                src.status = "rejected".into();
                src.error = Some("no certificate in the registry verifies this CRL".into());
            }
            crl_sources.push(src);
        }
        crl_sources.into_iter().for_each(|s| self.push_source(s));
        for (from, r) in std::mem::take(&mut self.carried) {
            let Ok(serial) = hex::decode(&r.serial) else {
                continue;
            };
            let entry = (r.issuer_key.clone(), serial);
            if revoked.contains_key(&entry) {
                continue;
            }
            let issuer = std::iter::once(&r.issuer_fingerprint)
                .chain(self.certs.keys())
                .find(|fp| {
                    self.certs.get(*fp).is_some_and(|(c, _)| {
                        key_id(c.key.as_ref().ok()).as_deref() == Some(r.issuer_key.as_str())
                    })
                });
            let Some(fp) = issuer else {
                tracing::warn!(issuer = %r.issuer_key, serial = %r.serial, "carried revocation's issuer key isn't in the registry; dropped");
                continue;
            };
            let source = match r.source.split_once(" (carried from ") {
                Some((s, _)) => s.to_string(),
                None => r.source.clone(),
            };
            revoked.insert(
                entry,
                (
                    r.revoked_at,
                    format!("{source} (carried from {from})"),
                    fp.clone(),
                ),
            );
        }

        let mut certificates = vec![];
        let mut countries: BTreeMap<String, Country> = BTreeMap::new();
        let mut grouped: BTreeMap<String, KeyGroup<'_>> = BTreeMap::new();
        for (fp, (c, sources)) in &self.certs {
            let chain = &chains[fp];
            let kid = key_id(c.key.as_ref().ok());
            let revoked_at = chain
                .issuer
                .as_ref()
                .and_then(|i| key_id(self.certs[i].0.key.as_ref().ok()))
                .and_then(|ik| revoked.get(&(ik, c.serial.clone())))
                .map(|r| r.0);
            let country = countries.entry(c.country.clone()).or_default();
            country.cscas += 1;
            *country.csca_keys.entry(describe(&c.key)).or_default() += 1;
            *country
                .csca_signature_schemes
                .entry(scheme_name(c))
                .or_default() += 1;
            if let Some(id) = &kid {
                let g = grouped
                    .entry(id.clone())
                    .or_insert_with(|| (c, vec![], vec![]));
                g.1.push((
                    c.not_before,
                    revoked_at.map_or(c.not_after, |r| r.min(c.not_after)),
                ));
                g.2.push(fp.clone());
            }
            certificates.push(Certificate {
                fingerprint: fp.clone(),
                country: c.country.clone(),
                kind: match chain.issuer.as_deref() {
                    Some(i) if i == fp => "root",
                    Some(_) => "link",
                    None => "orphan",
                }
                .into(),
                chain: chain.status.into(),
                chain_detail: chain.detail.clone(),
                issuer_fingerprint: chain.issuer.clone(),
                subject: c.subject.clone(),
                issuer: c.issuer.clone(),
                serial: hex::encode(&c.serial),
                signature_scheme: scheme_name(c),
                key: KeyInfo {
                    id: kid,
                    description: describe(&c.key),
                },
                not_before: c.not_before,
                not_after: c.not_after,
                private_key_usage_period: c.private_key_usage.map(|(a, b)| [a, b]),
                revoked_at,
                sources: sources.clone(),
            });
        }
        certificates.sort_by(|a, b| {
            (&a.country, a.not_before, &a.fingerprint).cmp(&(
                &b.country,
                b.not_before,
                &b.fingerprint,
            ))
        });
        for dsc in &self.dscs {
            let country = countries.entry(dsc.country.clone()).or_default();
            *country.dsc_keys.entry(describe(&dsc.key)).or_default() += 1;
            *country
                .dsc_signature_schemes
                .entry(scheme_name(dsc))
                .or_default() += 1;
        }

        let mut keys = vec![];
        for (id, (cert, periods, fps)) in grouped {
            let Ok(key) = &cert.key else { continue };
            let Some(header) = header_base(&cert.country, key) else {
                tracing::warn!(key = %id, country = %cert.country, "key has no leaf encoding; left out of the commitment");
                continue;
            };
            countries.entry(cert.country.clone()).or_default().keys += 1;
            let key_hash = commitment::key_hash(key.material());
            let periods = merge_periods(periods)
                .into_iter()
                .map(|(open, close)| {
                    let h = KeyHeader {
                        open: u64::try_from(open).unwrap_or(0),
                        close: u64::try_from(close).unwrap_or(0),
                        ..header
                    };
                    let leaf = commitment::key_leaf(&h, key_hash);
                    Period {
                        open,
                        close,
                        leaf: commitment::to_hex(&leaf),
                        index: 0,
                    }
                })
                .collect();
            keys.push(Key {
                id,
                country: cert.country.clone(),
                country_code: String::from_utf8_lossy(&header.country).into_owned(),
                description: key.describe(),
                public_key: hex::encode(key.material()),
                key_hash: commitment::to_hex(&key_hash),
                key_type: header.key_type,
                curve: header.curve,
                bits: header.bits,
                exponent: header.exponent,
                periods,
                certificates: fps,
            });
        }
        keys.sort_by(|a, b| {
            (&a.country, a.periods[0].open, &a.id).cmp(&(&b.country, b.periods[0].open, &b.id))
        });

        let mut revocations: Vec<Revocation> = revoked
            .into_iter()
            .filter_map(|((issuer_key, serial), (revoked_at, source, issuer_fp))| {
                let key = self.certs[&issuer_fp].0.key.as_ref().ok()?;
                let issuer_key_hash = commitment::key_hash(key.material());
                let leaf = commitment::revocation_leaf(issuer_key_hash, &serial);
                Some(Revocation {
                    issuer_key,
                    issuer_key_hash: commitment::to_hex(&issuer_key_hash),
                    issuer_fingerprint: issuer_fp,
                    serial: hex::encode(serial),
                    revoked_at,
                    source,
                    leaf: commitment::to_hex(&leaf),
                    index: 0,
                })
            })
            .collect();

        let key_tree = index_leaves(
            keys.iter_mut()
                .flat_map(|k| k.periods.iter_mut())
                .map(|p| (&p.leaf, &mut p.index)),
            KEY_TREE_HEIGHT,
        )?;
        let revocation_tree = index_leaves(
            revocations.iter_mut().map(|r| (&r.leaf, &mut r.index)),
            REVOCATION_TREE_HEIGHT,
        )?;
        let root = commitment::state_root(key_tree.root(), revocation_tree.root());

        Ok(output::Registry {
            version: output::FORMAT_VERSION,
            commitment: Commitment {
                root: commitment::to_hex(&root),
                keys_root: commitment::to_hex(&key_tree.root()),
                revocations_root: commitment::to_hex(&revocation_tree.root()),
                leaf_version: commitment::LEAF_VERSION,
                key_tree_height: KEY_TREE_HEIGHT,
                revocation_tree_height: REVOCATION_TREE_HEIGHT,
            },
            sources: self.sources,
            countries,
            certificates,
            keys,
            revocations,
        })
    }
}

/// Rebuilds the key and revocation trees from a registry's leaves.
pub fn trees(reg: &output::Registry) -> Result<(Tree, Tree)> {
    let collect = |leaves: Vec<&String>| -> Result<Vec<Fr>> {
        let mut v = leaves
            .into_iter()
            .map(|l| commitment::from_hex(l))
            .collect::<Result<Vec<_>>>()?;
        v.sort();
        v.dedup();
        Ok(v)
    };
    let keys = collect(
        reg.keys
            .iter()
            .flat_map(|k| &k.periods)
            .map(|p| &p.leaf)
            .collect(),
    )?;
    let revs = collect(reg.revocations.iter().map(|r| &r.leaf).collect())?;
    Ok((
        Tree::new(keys, reg.commitment.key_tree_height)?,
        Tree::new(revs, reg.commitment.revocation_tree_height)?,
    ))
}

/// Sorts the leaves, builds the tree and writes each leaf's slot back.
fn index_leaves<'a>(
    items: impl Iterator<Item = (&'a String, &'a mut usize)>,
    height: usize,
) -> Result<Tree> {
    let mut items: Vec<(Fr, &mut usize)> = items
        .map(|(leaf, index)| Ok((commitment::from_hex(leaf)?, index)))
        .collect::<Result<_>>()?;
    items.sort_by_key(|(leaf, _)| *leaf);
    let mut leaves: Vec<Fr> = items.iter().map(|(l, _)| *l).collect();
    leaves.dedup();
    let tree = Tree::new(leaves, height)?;
    for (leaf, index) in items {
        *index = tree.leaves().binary_search(&leaf).unwrap_or_default();
    }
    Ok(tree)
}

/// First certificate seen with a key, its validity windows, and all carriers.
type KeyGroup<'a> = (&'a Cert, Vec<(i64, i64)>, Vec<String>);

#[derive(Debug)]
struct Chain {
    issuer: Option<String>,
    status: &'static str,
    detail: Option<String>,
}

/// Finds the certificate whose key signed `c`: itself first (roots), then any
/// same-DN certificate, then any certificate whose SKI matches `c`'s AKI.
fn resolve_chain(
    c: &Cert,
    fp: &str,
    certs: &BTreeMap<String, (Cert, BTreeSet<String>)>,
    by_name: &HashMap<&str, Vec<&str>>,
    by_ski: &HashMap<&[u8], Vec<&str>>,
) -> Chain {
    let mut candidates: Vec<&str> = vec![];
    if c.subject_key == c.issuer_key {
        candidates.push(fp);
    }
    let named = by_name.get(c.issuer_key.as_str()).into_iter().flatten();
    let by_aki = c
        .aki
        .as_deref()
        .and_then(|a| by_ski.get(a))
        .into_iter()
        .flatten();
    for f in named.chain(by_aki) {
        if !candidates.contains(f) {
            candidates.push(f);
        }
    }
    // Only a failure against the certificate's *own* issuer means something:
    // the AKI-matched key, or its own key when it claims to be self-signed.
    // Same-DN certificates of other key generations failing is expected.
    let claims_self_signed = c.subject_key == c.issuer_key && (c.aki.is_none() || c.aki == c.ski);
    let mut failure: Option<(&'static str, String)> = None;
    for f in &candidates {
        let cand = &certs[*f].0;
        let Ok(key) = &cand.key else { continue };
        let own_issuer = (*f == fp && claims_self_signed) || (c.aki.is_some() && cand.ski == c.aki);
        match c.verify_with(key) {
            Ok(()) => {
                return Chain {
                    issuer: Some((*f).to_string()),
                    status: "verified",
                    detail: None,
                }
            }
            Err(e) if own_issuer && failure.is_none() => {
                let status = match e {
                    VerifyError::Unsupported(_) => "unsupported",
                    VerifyError::Invalid => "invalid",
                };
                failure = Some((status, format!("{e} (issuer {f})")));
            }
            Err(_) => {}
        }
    }
    if let Some((status, detail)) = failure {
        return Chain {
            issuer: None,
            status,
            detail: Some(detail),
        };
    }
    Chain {
        issuer: None,
        status: "issuer-missing",
        detail: Some(format!(
            "none of {} same-name/AKI certificate(s) signed it; typically a link certificate from a retired CSCA key",
            candidates.len()
        )),
    }
}

fn source(name: &str, kind: &str, bytes: &[u8]) -> Source {
    Source {
        name: name.into(),
        kind: kind.into(),
        sha256: hex::encode(Sha256::digest(bytes)),
        ..Source::default()
    }
}

fn key_id(key: Option<&PublicKey>) -> Option<String> {
    key.map(|k| hex::encode(Sha256::digest(k.material())))
}

fn describe(key: &Result<PublicKey, VerifyError>) -> String {
    key.as_ref()
        .map_or_else(|e| e.to_string(), PublicKey::describe)
}

fn scheme_name(c: &Cert) -> String {
    c.scheme
        .as_ref()
        .map_or_else(|_| c.signature_oid.clone(), |s| s.name())
}

/// Leaf header without the period; `None` for keys a leaf cannot encode.
fn header_base(country: &str, key: &PublicKey) -> Option<KeyHeader> {
    let [c0, c1, c2] = crate::country::leaf_code(country)?;
    let (key_type, curve, exponent) = match key {
        PublicKey::Rsa { e, .. } => {
            if e.len() > 4 {
                return None;
            }
            (1, 0, e.iter().fold(0u32, |acc, b| acc << 8 | u32::from(*b)))
        }
        PublicKey::Ec {
            curve: Some(curve), ..
        } => (2, curve.id(), 0),
        PublicKey::Ec { curve: None, .. } => return None,
    };
    Some(KeyHeader {
        country: [c0, c1, c2],
        key_type,
        curve,
        bits: u16::try_from(key.bits()).ok()?,
        exponent,
        open: 0,
        close: 0,
    })
}

/// Unions overlapping validity windows into disjoint `[open, close]` periods.
pub fn merge_periods(mut ps: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    ps.sort_unstable();
    let mut out: Vec<(i64, i64)> = vec![];
    for (a, b) in ps {
        match out.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

fn pem_blocks(bytes: &[u8]) -> Vec<Vec<u8>> {
    use base64::Engine;
    let text = String::from_utf8_lossy(bytes);
    text.split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .filter_map(|block| {
            let body: String = block.split("-----END").next()?.split_whitespace().collect();
            base64::engine::general_purpose::STANDARD.decode(body).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::merge_periods;

    #[test]
    fn merges_overlapping_periods() {
        assert_eq!(
            merge_periods(vec![(5, 9), (1, 3), (2, 6), (20, 30)]),
            vec![(1, 9), (20, 30)]
        );
        assert_eq!(merge_periods(vec![]), vec![]);
    }
}
