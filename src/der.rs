//! Minimal DER reader for the structures x509-parser does not model: CMS
//! SignedData, explicit EC domain parameters, ECDSA/PSS signature fields and
//! the PrivateKeyUsagePeriod extension. Definite lengths and single-byte tags
//! only, which is all DER (and every master list seen so far) uses.

/// One decoded TLV.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    /// Identifier octet.
    pub tag: u8,
    /// Content octets.
    pub content: &'a [u8],
    /// The whole encoding (tag + length + content).
    pub raw: &'a [u8],
}

/// Reads one TLV from the front of `b`, returning it and the remainder.
pub fn read(b: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *b.first()?;
    let l0 = usize::from(*b.get(1)?);
    let (len, header) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let len = b
            .get(2..2 + n)?
            .iter()
            .fold(0usize, |acc, &x| acc << 8 | usize::from(x));
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    let tlv = Tlv {
        tag,
        content: b.get(header..end)?,
        raw: &b[..end],
    };
    Some((tlv, &b[end..]))
}

/// Reads one TLV and requires its tag.
pub fn expect(b: &[u8], tag: u8) -> Option<(Tlv<'_>, &[u8])> {
    read(b).filter(|(t, _)| t.tag == tag)
}

/// Splits `content` into its child TLVs.
pub fn children(mut content: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = vec![];
    while !content.is_empty() {
        let (t, rest) = read(content)?;
        out.push(t);
        content = rest;
    }
    Some(out)
}

/// Decodes an OBJECT IDENTIFIER's content octets to dotted form.
pub fn oid(content: &[u8]) -> Option<String> {
    let mut arcs: Vec<u64> = vec![];
    let mut acc: u64 = 0;
    for &b in content {
        acc = acc.checked_mul(128)? | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            arcs.push(acc);
            acc = 0;
        }
    }
    let first = *arcs.first()?;
    let (a, b) = match first {
        0..=39 => (0, first),
        40..=79 => (1, first - 40),
        _ => (2, first - 80),
    };
    let mut s = format!("{a}.{b}");
    for arc in &arcs[1..] {
        s.push_str(&format!(".{arc}"));
    }
    Some(s)
}

/// INTEGER content as unsigned big-endian bytes without leading zeros.
pub fn uint(content: &[u8]) -> &[u8] {
    let skip = content.iter().take_while(|&&b| b == 0).count();
    &content[skip..]
}

/// `(tbs, signature algorithm oid, parameters, signature)`.
pub type SignedParts<'a> = (&'a [u8], String, Option<&'a [u8]>, &'a [u8]);

/// `(tbs, signature algorithm oid, algorithm parameters, signature)` of a
/// `SEQUENCE { tbs, AlgorithmIdentifier, BIT STRING }` (certificates and CRLs).
pub fn signed_parts(der: &[u8]) -> Option<SignedParts<'_>> {
    let (outer, _) = expect(der, 0x30)?;
    let parts = children(outer.content)?;
    let [tbs, alg, sig] = parts.as_slice() else {
        return None;
    };
    let (oid_tlv, params) = algorithm(alg.content)?;
    let sig = sig
        .content
        .split_first()
        .filter(|(unused, _)| **unused == 0)?
        .1;
    Some((tbs.raw, oid_tlv, params, sig))
}

/// Splits AlgorithmIdentifier content into (oid, raw parameters TLV if any and not NULL).
pub fn algorithm(content: &[u8]) -> Option<(String, Option<&[u8]>)> {
    let (o, rest) = expect(content, 0x06)?;
    let params = read(rest)
        .filter(|(t, _)| t.tag != 0x05)
        .map(|(t, _)| t.raw);
    Some((oid(o.content)?, params))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_long_lengths_and_oids() {
        let mut b = vec![0x04, 0x81, 0x80];
        b.extend([7u8; 0x80]);
        b.push(0xff);
        let (t, rest) = read(&b).unwrap();
        assert_eq!((t.tag, t.content.len(), rest), (0x04, 0x80, &[0xff][..]));
        assert!(read(&[0x04, 0x85, 1, 1, 1, 1, 1]).is_none());
        // 1.2.840.113549.1.1.10 (RSASSA-PSS)
        let pss = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
        assert_eq!(oid(&pss).unwrap(), "1.2.840.113549.1.1.10");
        assert_eq!(uint(&[0, 0, 1, 0]), &[1, 0]);
    }
}
