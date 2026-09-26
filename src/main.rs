//! Builds a combined CSCA registry from ICAO PKD LDIF files, national CSCA master lists,
//! CRLs and loose certificates. See README.md for the trust model and output format.

use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::base64::decode_block;
use openssl::bn::BigNumContext;
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::ec::{EcGroup, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::Id;
use openssl::sha::sha256;
use openssl::stack::Stack;
use openssl::x509::{X509, X509Crl, X509NameRef, X509Ref};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out, dirs) = match args.iter().position(|a| a == "-o") {
        Some(i) if i + 1 < args.len() => {
            let mut dirs = args.clone();
            let out = dirs.remove(i + 1);
            dirs.remove(i);
            (out, dirs)
        }
        _ => ("registry.json".into(), args),
    };
    if dirs.is_empty() {
        eprintln!("usage: csca-registry <sources-dir>... [-o registry.json]");
        std::process::exit(2);
    }
    let mut reg = Registry::default();
    for d in &dirs {
        reg.add_path(Path::new(d));
    }
    let json = reg.finish();
    std::fs::write(&out, serde_json::to_string_pretty(&json).unwrap() + "\n").unwrap();
    eprintln!(
        "wrote {out}: {} certificates, {} keys, {} revocations",
        json["certificates"].as_array().unwrap().len(),
        json["keys"].as_array().unwrap().len(),
        json["revocations"].as_array().unwrap().len()
    );
}

type Certs = BTreeMap<String, (X509, BTreeSet<String>)>;

#[derive(Default)]
struct Registry {
    /// sha256(DER) hex -> (cert, source names)
    certs: Certs,
    crls: Vec<(String, X509Crl)>,
    sources: Vec<Value>,
}

impl Registry {
    fn add_path(&mut self, p: &Path) {
        if p.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(p).unwrap().flatten().map(|e| e.path()).collect();
            entries.sort();
            entries.iter().for_each(|e| self.add_path(e));
            return;
        }
        let name = p.to_string_lossy().to_string();
        let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        // Standalone master lists are named <publisher alpha-2>_*.ml (DE_ML_..., IT_MasterListCSCA...).
        let file_country: String = p.file_name().unwrap().to_string_lossy().chars().take(2).collect::<String>().to_uppercase();
        match ext.as_str() {
            "ml" => self.add_ml(&name, &std::fs::read(p).unwrap(), &file_country),
            "ldif" => self.add_ldif(&name, &String::from_utf8_lossy(&std::fs::read(p).unwrap())),
            "crl" => self.add_crl(&name, &std::fs::read(p).unwrap()),
            "cer" | "crt" | "der" | "pem" => {
                let bytes = std::fs::read(p).unwrap();
                match X509::from_der(&bytes).map(|c| vec![c]).or_else(|_| X509::stack_from_pem(&bytes)) {
                    Ok(certs) => {
                        self.source(&name, &bytes, "certificate", json!({"status": "manual", "certificates": certs.len()}));
                        certs.into_iter().for_each(|c| self.add_cert(c, &name));
                    }
                    Err(e) => self.source(&name, &bytes, "certificate", json!({"status": "error", "error": e.to_string()})),
                }
            }
            _ => {}
        }
    }

    fn source(&mut self, name: &str, bytes: &[u8], kind: &str, extra: Value) {
        let mut v = json!({"name": name, "kind": kind, "sha256": hex(&sha256(bytes))});
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        eprintln!("{v}");
        self.sources.push(v);
    }

    fn add_cert(&mut self, c: X509, source: &str) {
        let fp = hex(&sha256(&c.to_der().unwrap()));
        self.certs.entry(fp).or_insert_with(|| (c, BTreeSet::new())).1.insert(source.into());
    }

    fn add_ml(&mut self, name: &str, der: &[u8], country: &str) {
        match load_ml(der, country) {
            Ok((certs, anchor)) => {
                self.source(name, der, "masterlist", json!({"status": "trusted", "country": country, "anchor": anchor, "certificates": certs.len()}));
                certs.into_iter().for_each(|c| self.add_cert(c, name));
            }
            Err(e) => self.source(name, der, "masterlist", json!({"status": "rejected", "country": country, "error": e})),
        }
    }

    fn add_crl(&mut self, name: &str, der: &[u8]) {
        match X509Crl::from_der(der).or_else(|_| X509Crl::from_pem(der)) {
            Ok(crl) => self.crls.push((name.into(), crl)),
            Err(e) => self.source(name, der, "crl", json!({"status": "error", "error": e.to_string()})),
        }
    }

    fn add_ldif(&mut self, name: &str, text: &str) {
        let mut skipped_dsc = 0;
        for entry in ldif_entries(text) {
            let dn = entry.iter().find(|(k, _)| k == "dn").map(|(_, v)| String::from_utf8_lossy(v).to_string()).unwrap_or_default();
            let country = dn_country(&dn);
            for (attr, val) in &entry {
                let src = format!("{name}#{dn}");
                if attr.starts_with("pkdmasterlistcontent") || attr.starts_with("cscamasterlistdata") {
                    self.add_ml(&src, val, &country);
                } else if attr.starts_with("certificaterevocationlist") {
                    self.add_crl(&src, val);
                } else if attr.starts_with("usercertificate") {
                    // ponytail: DSCs ship inside the document SOD, not needed in a CSCA registry; add when DSC allow-listing is wanted
                    skipped_dsc += 1;
                }
            }
        }
        self.source(name, text.as_bytes(), "ldif", json!({"status": "parsed", "skipped_dsc": skipped_dsc}));
    }

    fn finish(mut self) -> Value {
        // Canonical (X509_NAME_hash) rather than DER: countries mix PrintableString/UTF8String for the same DN.
        let mut by_subject: HashMap<u32, Vec<String>> = HashMap::new();
        for (fp, (c, _)) in &self.certs {
            by_subject.entry(c.subject_name_hash()).or_default().push(fp.clone());
        }
        // Self first: link certs often reuse the root's DN, so a name match alone proves nothing.
        let find_issuer = |c: &X509Ref, fp: &str, certs: &Certs| -> Option<String> {
            let mut cands = by_subject.get(&c.issuer_name_hash())?.clone();
            cands.sort_by_key(|f| f != fp);
            cands.into_iter().find(|f| c.verify(&certs[f].0.public_key().unwrap()).unwrap_or(false))
        };

        let mut revocations: BTreeMap<(String, String), (i64, String)> = BTreeMap::new();
        for (src, crl) in std::mem::take(&mut self.crls) {
            let issuer = self.certs.iter().find(|(_, (c, _))| {
                c.subject_name().try_cmp(crl.issuer_name()).is_ok_and(|o| o.is_eq()) && crl.verify(&c.public_key().unwrap()).unwrap_or(false)
            });
            let issuer = issuer.map(|(fp, _)| fp.clone());
            let der = crl.to_der().unwrap();
            let Some(issuer) = issuer else {
                self.source(&src, &der, "crl", json!({"status": "rejected", "error": "no CSCA in registry verifies this CRL"}));
                continue;
            };
            let revoked = crl.get_revoked().map(|s| s.iter().collect::<Vec<_>>()).unwrap_or_default();
            self.source(&src, &der, "crl", json!({"status": "trusted", "issuer": issuer, "this_update": unix(crl.last_update()), "revoked": revoked.len()}));
            for r in revoked {
                let at = unix(r.revocation_date());
                let e = revocations.entry((issuer.clone(), serial(r.serial_number()))).or_insert((at, src.clone()));
                e.0 = e.0.min(at);
            }
        }

        let mut certificates = vec![];
        let mut keys: BTreeMap<String, (String, Vec<(i64, i64)>, Vec<String>)> = BTreeMap::new();
        for (fp, (c, sources)) in &self.certs {
            let issuer_fp = find_issuer(c, fp, &self.certs);
            let kind = match &issuer_fp {
                Some(i) if i == fp => "root",
                Some(_) => "link",
                // Trust comes from the signed source that listed it; "orphan" only means its
                // issuer (typically a retired CSCA behind a link cert) is not in the registry.
                None => "orphan",
            };
            let (key_type, bits, curve, key_id) = key_info(c);
            let country = name_country(c.subject_name()).or_else(|| name_country(c.issuer_name())).unwrap_or_default();
            let (nb, na) = (unix(c.not_before()), unix(c.not_after()));
            let revoked_at = issuer_fp.as_ref().and_then(|i| revocations.get(&(i.clone(), serial(c.serial_number())))).map(|r| r.0);
            let k = keys.entry(key_id.clone()).or_insert_with(|| (country.clone(), vec![], vec![]));
            k.1.push((nb, revoked_at.map_or(na, |r| r.min(na))));
            k.2.push(fp.clone());
            certificates.push(json!({
                "fingerprint": fp,
                "country": country,
                "kind": kind,
                "issuer_fingerprint": issuer_fp,
                "subject": name_str(c.subject_name()),
                "issuer": name_str(c.issuer_name()),
                "serial": serial(c.serial_number()),
                "signature_algorithm": c.signature_algorithm().object().to_string(),
                "key": {"id": key_id, "type": key_type, "bits": bits, "curve": curve},
                "not_before": nb,
                "not_after": na,
                "private_key_usage_period": pkup(&c.to_der().unwrap()).map(|(a, b)| json!({"not_before": a, "not_after": b})),
                "revoked_at": revoked_at,
                "sources": sources,
            }));
        }
        certificates.sort_by(|a, b| (a["country"].as_str(), a["not_before"].as_i64()).cmp(&(b["country"].as_str(), b["not_before"].as_i64())));

        let mut keys: Vec<Value> = keys
            .into_iter()
            .map(|(id, (country, periods, certs))| json!({"id": id, "country": country, "periods": merge_periods(periods), "certificates": certs}))
            .collect();
        keys.sort_by(|a, b| (a["country"].as_str(), a["periods"][0][0].as_i64()).cmp(&(b["country"].as_str(), b["periods"][0][0].as_i64())));

        let revocations: Vec<Value> = revocations
            .into_iter()
            .map(|((issuer, serial), (at, src))| json!({"issuer_fingerprint": issuer, "serial": serial, "revoked_at": at, "source": src}))
            .collect();
        json!({"version": 1, "sources": self.sources, "certificates": certificates, "keys": keys, "revocations": revocations})
    }
}

/// Verifies a CSCA master list (CMS SignedData) and returns its certificates plus the
/// fingerprint of the `country` CSCA inside the list whose key signed the ML signer cert.
fn load_ml(der: &[u8], country: &str) -> Result<(Vec<X509>, String), String> {
    let mut cms = CmsContentInfo::from_der(der).map_err(|e| format!("cms parse: {e}"))?;
    let mut content = vec![];
    cms.verify(None, None, None, Some(&mut content), CMSOptions::BINARY | CMSOptions::NO_SIGNER_CERT_VERIFY)
        .map_err(|e| format!("cms signature: {e}"))?;
    let certs = parse_masterlist_content(&content).ok_or("malformed CscaMasterList content")?;

    // Chain building is done by hand: OpenSSL 3 refuses keys with explicit EC params
    // (X509_V_ERR_EC_KEY_EXPLICIT_PARAMS), which many CSCAs and ML signers use.
    let signer = signed_data_certs(der)
        .ok_or("malformed SignedData certificates")?
        .into_iter()
        .find(|c| {
            let mut only = Stack::new().unwrap();
            only.push(c.clone()).unwrap();
            let flags = CMSOptions::BINARY | CMSOptions::NOINTERN | CMSOptions::NO_SIGNER_CERT_VERIFY;
            cms.verify(Some(&only), None, None, None, flags).is_ok()
        })
        .ok_or("signer certificate not embedded")?;
    let own: Vec<&X509> = certs.iter().filter(|c| name_country(c.subject_name()).as_deref() == Some(country)).collect();
    let anchor = own.iter().find(|a| signer.verify(&a.public_key().unwrap()).unwrap_or(false)).map(|a| hex(&sha256(&a.to_der().unwrap())));
    let n = own.len();
    anchor.map(|a| (certs, a)).ok_or_else(|| format!("signer {} is not signed by any of the {n} {country} CSCAs in the list", name_str(signer.subject_name())))
}

/// ContentInfo { oid, [0] SignedData { version, digestAlgs, encap, [0] IMPLICIT certificates, ... } }
fn signed_data_certs(der: &[u8]) -> Option<Vec<X509>> {
    let (0x30, ci, _) = tlv(der)? else { return None };
    let (0x06, _, rest) = tlv(ci)? else { return None };
    let (0xa0, explicit, _) = tlv(rest)? else { return None };
    let (0x30, sd, _) = tlv(explicit)? else { return None };
    let mut rest = sd;
    for _ in 0..3 {
        rest = tlv(rest)?.2;
    }
    let (0xa0, mut set, _) = tlv(rest)? else { return Some(vec![]) };
    let mut out = vec![];
    while !set.is_empty() {
        let (_, _, next) = tlv(set)?;
        out.extend(X509::from_der(&set[..set.len() - next.len()]).ok());
        set = next;
    }
    Some(out)
}

/// CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF Certificate }
fn parse_masterlist_content(b: &[u8]) -> Option<Vec<X509>> {
    let (0x30, seq, _) = tlv(b)? else { return None };
    let (0x02, _, rest) = tlv(seq)? else { return None };
    let (0x31, mut set, _) = tlv(rest)? else { return None };
    let mut out = vec![];
    while !set.is_empty() {
        let (_, _, rest) = tlv(set)?;
        match X509::from_der(&set[..set.len() - rest.len()]) {
            Ok(c) => out.push(c),
            Err(e) => eprintln!("skipping unparsable certificate in master list: {e}"),
        }
        set = rest;
    }
    Some(out)
}

/// Minimal DER TLV reader: (tag, content, rest).
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)? as usize;
    let (len, hl) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        (b.get(2..2 + n)?.iter().fold(0usize, |acc, &x| acc << 8 | x as usize), 2 + n)
    };
    let end = hl.checked_add(len)?;
    Some((tag, b.get(hl..end)?, &b[end..]))
}

/// PrivateKeyUsagePeriod (2.5.29.16): the window in which the CSCA may sign DSCs.
fn pkup(cert_der: &[u8]) -> Option<(Option<i64>, Option<i64>)> {
    // ponytail: byte-scans for the extension OID instead of walking TBSCertificate; fine for X.509 DER
    const OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x10];
    let at = cert_der.windows(OID.len()).position(|w| w == OID)? + OID.len();
    let mut rest = &cert_der[at..];
    if rest.first() == Some(&0x01) {
        rest = tlv(rest)?.2;
    }
    let (0x04, octets, _) = tlv(rest)? else { return None };
    let (0x30, mut seq, _) = tlv(octets)? else { return None };
    let (mut nb, mut na) = (None, None);
    while !seq.is_empty() {
        let (tag, t, rest) = tlv(seq)?;
        let t = Asn1Time::from_str(std::str::from_utf8(t).ok()?).ok().map(|t| unix(&t));
        match tag {
            0x80 => nb = t,
            0x81 => na = t,
            _ => {}
        }
        seq = rest;
    }
    Some((nb, na))
}

/// Returns (type, bits, curve, id). `id` hashes the raw key material so the same key in
/// differently-encoded certs (named vs explicit curve params) groups together.
fn key_info(c: &X509Ref) -> (String, u32, Option<String>, String) {
    let pk = c.public_key().unwrap();
    match pk.id() {
        Id::RSA => ("RSA".into(), pk.bits(), None, hex(&sha256(&pk.rsa().unwrap().n().to_vec()))),
        Id::EC => {
            let ec = pk.ec_key().unwrap();
            let point = ec.public_key().to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut BigNumContext::new().unwrap()).unwrap();
            ("EC".into(), pk.bits(), Some(curve_name(ec.group())), hex(&sha256(&point)))
        }
        _ => (format!("{:?}", pk.id()), pk.bits(), None, hex(&sha256(&pk.public_key_to_der().unwrap()))),
    }
}

/// Resolves explicit-parameter curves (common in CSCAs) to their named equivalent.
fn curve_name(g: &openssl::ec::EcGroupRef) -> String {
    if let Some(n) = g.curve_name() {
        return n.short_name().unwrap_or("?").into();
    }
    let params = |g: &openssl::ec::EcGroupRef| {
        let mut ctx = BigNumContext::new().unwrap();
        let mut v: [openssl::bn::BigNum; 4] = std::array::from_fn(|_| openssl::bn::BigNum::new().unwrap());
        let [p, a, b, n] = &mut v;
        g.components_gfp(p, a, b, &mut ctx).unwrap();
        g.order(n, &mut ctx).unwrap();
        v.map(|x| x.to_vec())
    };
    let mine = params(g);
    // secp/prime + brainpool {160..512} r1/t1 (raw NIDs 921..934 per obj_mac.h)
    [409, 713, 415, 715, 716].into_iter().chain(921..=934).map(Nid::from_raw)
        .find(|nid| EcGroup::from_curve_name(*nid).is_ok_and(|ng| params(&ng) == mine))
        .map(|nid| nid.short_name().unwrap_or("?").into())
        .unwrap_or_else(|| "explicit-unknown".into())
}

/// Unions overlapping validity windows into disjoint [open, close] periods.
fn merge_periods(mut ps: Vec<(i64, i64)>) -> Vec<[i64; 2]> {
    ps.sort();
    let mut out: Vec<[i64; 2]> = vec![];
    for (a, b) in ps {
        match out.last_mut() {
            Some(last) if a <= last[1] => last[1] = last[1].max(b),
            _ => out.push([a, b]),
        }
    }
    out
}

/// Unfolds LDIF and returns entries as (lowercased attr, decoded value) pairs.
fn ldif_entries(text: &str) -> Vec<Vec<(String, Vec<u8>)>> {
    let mut entries = vec![];
    let mut lines: Vec<String> = vec![];
    for raw in text.lines().chain(std::iter::once("")) {
        if let Some(cont) = raw.strip_prefix(' ') {
            if let Some(l) = lines.last_mut() {
                l.push_str(cont);
            }
        } else if raw.trim().is_empty() {
            let entry: Vec<_> = lines
                .drain(..)
                .filter_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    let val = match v.strip_prefix(':') {
                        Some(b64) => decode_block(b64.trim()).ok()?,
                        None => v.trim().as_bytes().to_vec(),
                    };
                    Some((k.trim().to_lowercase(), val))
                })
                .collect();
            if !entry.is_empty() {
                entries.push(entry);
            }
        } else if !raw.starts_with('#') {
            lines.push(raw.to_string());
        }
    }
    entries
}

fn dn_country(dn: &str) -> String {
    dn.split(',').filter_map(|p| p.trim().split_once('=')).find(|(k, _)| k.eq_ignore_ascii_case("c")).map(|(_, v)| v.to_uppercase()).unwrap_or_default()
}

fn name_country(n: &X509NameRef) -> Option<String> {
    n.entries_by_nid(Nid::COUNTRYNAME).next().and_then(|e| e.data().to_string().ok()).map(|s| s.to_uppercase())
}

fn name_str(n: &X509NameRef) -> String {
    n.entries()
        .map(|e| {
            let k = e.object().nid().short_name().map(str::to_string).unwrap_or_else(|_| e.object().to_string());
            let v = e.data().to_string().unwrap_or_else(|_| hex(e.data().as_slice()));
            format!("{k}={v}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn serial(s: &openssl::asn1::Asn1IntegerRef) -> String {
    s.to_bn().unwrap().to_hex_str().unwrap().to_lowercase()
}

fn unix(t: &Asn1TimeRef) -> i64 {
    let d = Asn1Time::from_unix(0).unwrap().diff(t).unwrap();
    d.days as i64 * 86400 + d.secs as i64
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Integer;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::X509NameBuilder;
    use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage};

    fn key() -> PKey<Private> {
        PKey::from_ec_key(openssl::ec::EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap()).unwrap()
    }

    fn cert(c: &str, cn: &str, k: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>, ca: bool, sn: u32) -> X509 {
        let mut n = X509NameBuilder::new().unwrap();
        n.append_entry_by_text("C", c).unwrap();
        n.append_entry_by_text("CN", cn).unwrap();
        let n = n.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(sn).unwrap()).unwrap()).unwrap();
        b.set_subject_name(&n).unwrap();
        b.set_issuer_name(issuer.map_or(&n, |(i, _)| i.subject_name())).unwrap();
        b.set_pubkey(k).unwrap();
        b.set_not_before(&Asn1Time::from_unix(1_600_000_000).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::from_unix(1_900_000_000).unwrap()).unwrap();
        if ca {
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
        } else {
            b.append_extension(ExtendedKeyUsage::new().other("2.23.136.1.1.3").build().unwrap()).unwrap();
        }
        b.sign(issuer.map_or(k, |(_, ik)| ik), MessageDigest::sha256()).unwrap();
        b.build()
    }

    fn ml(certs: &[&X509], signer: &X509, signer_key: &PKey<Private>) -> Vec<u8> {
        let wrap = |tag: u8, b: &[u8]| -> Vec<u8> {
            let l = b.len();
            [&[tag, 0x83, (l >> 16) as u8, (l >> 8) as u8, l as u8][..], b].concat()
        };
        let body: Vec<u8> = certs.iter().flat_map(|c| c.to_der().unwrap()).collect();
        let content = wrap(0x30, &[&[0x02, 0x01, 0x00][..], &wrap(0x31, &body)].concat());
        CmsContentInfo::sign(Some(signer), Some(signer_key), None, Some(&content), CMSOptions::BINARY).unwrap().to_der().unwrap()
    }

    #[test]
    fn masterlist_trust_links_and_periods() {
        let (ka, ka2, kb, ks, kx) = (key(), key(), key(), key(), key());
        let root_a = cert("XA", "CSCA A", &ka, None, true, 1);
        // link cert: new key, same DN, signed by the old root
        let link_a = cert("XA", "CSCA A", &ka2, Some((&root_a, &ka)), true, 2);
        let root_b = cert("XB", "CSCA B", &kb, None, true, 3);
        let signer = cert("XA", "ML Signer", &ks, Some((&root_a, &ka)), false, 4);
        let good = ml(&[&root_a, &link_a, &root_b], &signer, &ks);

        let (certs, anchor) = load_ml(&good, "XA").unwrap();
        assert_eq!(certs.len(), 3);
        assert_eq!(anchor, hex(&sha256(&root_a.to_der().unwrap())));

        // A list claiming to be XA but signed under XB is rejected.
        let signer_b = cert("XB", "ML Signer", &ks, Some((&root_b, &kb)), false, 5);
        assert!(load_ml(&ml(&[&root_a, &root_b], &signer_b, &ks), "XA").is_err());
        // Tampered bytes fail the CMS signature.
        let mut bad = good.clone();
        let i = bad.len() / 2;
        bad[i] ^= 1;
        assert!(load_ml(&bad, "XA").is_err());

        let mut reg = Registry::default();
        reg.add_ml("good.ml", &good, "XA");
        reg.add_cert(cert("XC", "Orphan", &kx, Some((&root_b, &ka)), true, 7), "loose.cer"); // issuer key mismatch
        let out = reg.finish();
        let certs = out["certificates"].as_array().unwrap();
        let kinds: BTreeSet<_> = certs.iter().map(|c| (c["country"].as_str().unwrap(), c["kind"].as_str().unwrap())).collect();
        assert_eq!(kinds, BTreeSet::from([("XA", "link"), ("XA", "root"), ("XB", "root"), ("XC", "orphan")]));
        assert_eq!(out["keys"].as_array().unwrap().len(), 4);
        assert_eq!(out["keys"][0]["periods"], json!([[1_600_000_000, 1_900_000_000]]));
    }

    #[test]
    fn merge_and_ldif() {
        assert_eq!(merge_periods(vec![(5, 9), (1, 3), (2, 6), (20, 30)]), vec![[1, 9], [20, 30]]);
        let e = ldif_entries("dn: cn=x,o=ml,c=DE,dc=data\npkdMasterListContent:: AQ\n I=\n\ndn: y\n");
        assert_eq!(e[0][1], ("pkdmasterlistcontent".into(), vec![1, 2]));
        assert_eq!(dn_country(&String::from_utf8_lossy(&e[0][0].1)), "DE");
    }
}
