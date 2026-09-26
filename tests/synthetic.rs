//! End-to-end over the synthetic PKI in tests/fixtures/synthetic (see gen.py):
//! LDIF master list + CRL + DSCs, a forged master list, RSA-PSS, an explicit-
//! parameter brainpoolP512r1 root and its brainpoolP384r1 link certificate.

use csca_registry::commands::{build::handle_build, prove};
use csca_registry::masterlist;
use csca_registry::output::Registry;
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic")
}

fn build() -> (tempfile::TempDir, PathBuf, Registry) {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let out = dir.path().join("registry.json");
    let reg = handle_build(&[fixtures()], &out).expect("build");
    (dir, out, reg)
}

fn cert<'a>(
    reg: &'a Registry,
    country: &str,
    kind: &str,
) -> &'a csca_registry::output::Certificate {
    reg.certificates
        .iter()
        .find(|c| c.country == country && c.kind == kind)
        .unwrap_or_else(|| panic!("{country} {kind}"))
}

#[test]
fn trusts_the_ldif_masterlist_and_rejects_the_forged_one() {
    let (_d, _p, reg) = build();
    let ml = reg
        .sources
        .iter()
        .find(|s| s.name.contains("cn=ml,"))
        .unwrap();
    assert_eq!((ml.status.as_str(), ml.certificates), ("trusted", Some(3)));
    let forged = reg
        .sources
        .iter()
        .find(|s| s.name.ends_with("XA_forged.ml"))
        .unwrap();
    assert_eq!(forged.status, "rejected");
    assert!(forged
        .error
        .as_deref()
        .unwrap()
        .contains("not signed by any of the 1 XA CSCAs"));
}

#[test]
fn tampered_masterlist_fails_its_signature() {
    let ldif = std::fs::read_to_string(fixtures().join("icaopkd-synthetic.ldif")).unwrap();
    let entries = csca_registry::ldif::entries(&ldif);
    let mut ml = entries[0].der.clone();
    assert!(masterlist::load(&ml, "XA").is_ok());
    let i = ml.len() / 2;
    ml[i] ^= 1;
    assert!(masterlist::load(&ml, "XA").is_err());
}

#[test]
fn verifies_pss_explicit_brainpool_and_links() {
    let (_d, _p, reg) = build();
    let xa = cert(&reg, "XA", "root");
    assert_eq!(
        (xa.chain.as_str(), xa.signature_scheme.as_str()),
        ("verified", "rsa-pss-sha256-mgf1-sha256-salt32")
    );
    let xb = cert(&reg, "XB", "root");
    assert_eq!(
        (xb.chain.as_str(), xb.key.description.as_str()),
        ("verified", "EC-brainpoolP512r1")
    );
    let link = cert(&reg, "XB", "link");
    assert_eq!(
        link.issuer_fingerprint.as_deref(),
        Some(xb.fingerprint.as_str())
    );
    assert_eq!(link.key.description, "EC-brainpoolP384r1");
}

#[test]
fn exposes_dsc_signature_profile() {
    let (_d, _p, reg) = build();
    let xa = &reg.countries["XA"];
    assert_eq!(xa.dsc_keys.get("RSA-2048"), Some(&2));
    assert_eq!(
        xa.dsc_signature_schemes
            .get("rsa-pss-sha256-mgf1-sha256-salt32"),
        Some(&2)
    );
    assert_eq!(
        reg.countries["XB"]
            .csca_signature_schemes
            .get("ecdsa-sha512"),
        Some(&2)
    );
}

#[test]
fn commits_revocations_and_proves_non_revocation() {
    let (_d, path, reg) = build();
    let reg2 = prove::handle_verify(&path).expect("commitment reproduces");
    assert_eq!(reg2.commitment.root, reg.commitment.root);

    let xa_key = cert(&reg, "XA", "root").key.id.clone().unwrap();
    assert_eq!(reg.revocations.len(), 1);
    assert_eq!(
        (
            reg.revocations[0].serial.as_str(),
            reg.revocations[0].issuer_key.as_str()
        ),
        ("1001", xa_key.as_str())
    );
    assert!(prove::prove_not_revoked(&reg, &xa_key, "1001").is_err());
    let ok = prove::prove_not_revoked(&reg, &xa_key, "0x1002").unwrap();
    assert_eq!(ok.root, reg.commitment.root);

    let key = &reg.keys[0];
    let p = prove::prove_key(&reg, &key.id, key.periods[0].open).unwrap();
    assert_eq!(
        (p.root.as_str(), p.proof.leaf.as_str()),
        (reg.commitment.root.as_str(), key.periods[0].leaf.as_str())
    );
    assert!(prove::prove_key(&reg, &key.id, key.periods[0].close + 1).is_err());
}
