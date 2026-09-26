//! Per-country registry checks: one test per country found in the sources.
//!
//! Sources default to the committed snapshot in tests/fixtures/sources (the DE
//! and IT master lists + IT CRL); set `CSCA_SOURCES=<dir>` to run the same
//! checks against a fresh download (CI does, nightly).
//!
//! Every country must have: at least one CSCA and one committed key; every
//! certificate's signature either verified or its issuer absent from all
//! sources (never a failed or unsupported check against its own issuer);
//! disjoint, ordered validity periods whose leaves recompute and prove into
//! the registry root; and a non-empty signature profile.

use csca_registry::commitment::{self, KeyHeader};
use csca_registry::output::Registry;
use csca_registry::registry::{self, Builder};
use libtest_mimic::{Arguments, Failed, Trial};
use std::path::PathBuf;
use std::sync::Arc;

fn main() {
    let args = Arguments::from_args();
    let dir = std::env::var_os("CSCA_SOURCES").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sources"),
        PathBuf::from,
    );
    let mut builder = Builder::default();
    builder.add_path(&dir).expect("read sources");
    let reg = Arc::new(builder.finish().expect("build registry"));

    let mut trials = vec![Trial::test("sources::all_trusted", {
        let reg = Arc::clone(&reg);
        move || {
            let bad: Vec<_> = reg
                .sources
                .iter()
                .filter(|s| matches!(s.status.as_str(), "rejected" | "error"))
                .map(|s| format!("{}: {}", s.name, s.error.clone().unwrap_or_default()))
                .collect();
            ensure(bad.is_empty(), format!("untrusted sources: {bad:#?}"))
        }
    })];
    trials.extend(reg.countries.keys().map(|cc| {
        let (reg, cc) = (Arc::clone(&reg), cc.clone());
        Trial::test(format!("country::{cc}"), move || check_country(&reg, &cc))
    }));
    libtest_mimic::run(&args, trials).exit();
}

fn ensure(ok: bool, why: impl Into<String>) -> Result<(), Failed> {
    if ok {
        Ok(())
    } else {
        Err(why.into().into())
    }
}

fn check_country(reg: &Registry, cc: &str) -> Result<(), Failed> {
    let profile = &reg.countries[cc];
    ensure(profile.cscas > 0, "no CSCA certificates")?;
    ensure(profile.keys > 0, "no key committed")?;
    ensure(
        !profile.csca_keys.is_empty() && !profile.csca_signature_schemes.is_empty(),
        "empty signature profile",
    )?;

    for c in reg.certificates.iter().filter(|c| c.country == cc) {
        ensure(
            matches!(c.chain.as_str(), "verified" | "issuer-missing"),
            format!(
                "{} ({}): chain {} — {:?}",
                c.fingerprint, c.subject, c.chain, c.chain_detail
            ),
        )?;
    }

    let (tree, revs) = registry::trees(reg).map_err(|e| e.to_string())?;
    let root = commitment::to_hex(&commitment::state_root(tree.root(), revs.root()));
    ensure(
        root == reg.commitment.root,
        "registry root does not reproduce",
    )?;

    for k in reg.keys.iter().filter(|k| k.country == cc) {
        ensure(!k.periods.is_empty(), format!("key {} has no period", k.id))?;
        let key_hash = commitment::from_hex(&k.key_hash).map_err(|e| e.to_string())?;
        let [c0, c1] = k.country.as_bytes() else {
            return Err(format!("country {} is not alpha-2", k.country).into());
        };
        for (i, p) in k.periods.iter().enumerate() {
            ensure(
                p.open < p.close,
                format!("key {} period {i} is empty", k.id),
            )?;
            if i > 0 {
                ensure(
                    k.periods[i - 1].close < p.open,
                    format!("key {} periods overlap", k.id),
                )?;
            }
            let header = KeyHeader {
                country: [*c0, *c1],
                key_type: k.key_type,
                curve: k.curve,
                bits: k.bits,
                exponent: k.exponent,
                open: u64::try_from(p.open).unwrap_or(0),
                close: u64::try_from(p.close).unwrap_or(0),
            };
            let leaf = commitment::key_leaf(&header, key_hash);
            ensure(
                commitment::to_hex(&leaf) == p.leaf,
                format!("key {} leaf does not recompute", k.id),
            )?;
            let proof = tree.proof(p.index);
            ensure(
                proof.leaf == leaf && proof.root() == tree.root(),
                format!("key {} leaf does not prove", k.id),
            )?;
        }
    }
    Ok(())
}
