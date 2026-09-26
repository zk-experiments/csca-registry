//! ICAO PKD LDIF exports (`icaopkd-00{1,2}-*.ldif`).

use base64::Engine;

/// What an LDIF entry carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    /// A CSCA master list (CMS), published by `country`.
    MasterList,
    /// A CRL.
    Crl,
    /// A document signer certificate.
    Dsc,
}

/// One PKD object with the country from its DN (`c=XX`).
#[derive(Debug, Clone)]
pub struct Entry {
    /// Entry DN.
    pub dn: String,
    /// Upper-case alpha-2 from the DN.
    pub country: String,
    /// Object kind.
    pub kind: Object,
    /// Decoded DER.
    pub der: Vec<u8>,
}

/// Unfolds the LDIF and returns every master list, CRL and DSC it holds.
pub fn entries(text: &str) -> Vec<Entry> {
    let mut out = vec![];
    let mut lines: Vec<String> = vec![];
    for raw in text.lines().chain(std::iter::once("")) {
        if let Some(cont) = raw.strip_prefix(' ') {
            if let Some(last) = lines.last_mut() {
                last.push_str(cont);
            }
        } else if raw.trim().is_empty() {
            flush(&mut lines, &mut out);
        } else if !raw.starts_with('#') {
            lines.push(raw.to_string());
        }
    }
    out
}

fn flush(lines: &mut Vec<String>, out: &mut Vec<Entry>) {
    let attrs: Vec<(String, Vec<u8>)> = lines
        .drain(..)
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let value = match v.strip_prefix(':') {
                Some(b64) => base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .ok()?,
                None => v.trim().as_bytes().to_vec(),
            };
            Some((k.trim().to_lowercase(), value))
        })
        .collect();
    let dn = attrs
        .iter()
        .find(|(k, _)| k == "dn")
        .map(|(_, v)| String::from_utf8_lossy(v).to_string())
        .unwrap_or_default();
    let country = dn
        .split(',')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| k.eq_ignore_ascii_case("c"))
        .map(|(_, v)| v.to_uppercase())
        .unwrap_or_default();
    for (attr, der) in attrs {
        let kind =
            if attr.starts_with("pkdmasterlistcontent") || attr.starts_with("cscamasterlistdata") {
                Object::MasterList
            } else if attr.starts_with("certificaterevocationlist") {
                Object::Crl
            } else if attr.starts_with("usercertificate") {
                Object::Dsc
            } else {
                continue;
            };
        out.push(Entry {
            dn: dn.clone(),
            country: country.clone(),
            kind,
            der,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfolds_and_classifies() {
        let text = "dn: cn=x,o=ml,c=DE,dc=data\npkdMasterListContent:: AQ\n I=\n\n# c\ndn: cn=y,o=crl,c=it\ncertificateRevocationList;binary:: Aw==\n";
        let e = entries(text);
        assert_eq!(e.len(), 2);
        assert_eq!(
            (e[0].kind.clone(), e[0].country.as_str(), e[0].der.clone()),
            (Object::MasterList, "DE", vec![1, 2])
        );
        assert_eq!(
            (e[1].kind.clone(), e[1].country.as_str()),
            (Object::Crl, "IT")
        );
    }
}
