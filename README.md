# csca-registry

[![CI](https://github.com/zk-experiments/csca-registry/actions/workflows/ci.yml/badge.svg)](https://github.com/zk-experiments/csca-registry/actions/workflows/ci.yml)

A deduplicated, signature-checked list of the **Country Signing CA (CSCA)** certificates behind passports, ID and residence cards (eMRTDs), built from ICAO PKD and national master lists. It has three parts:

- **Validity periods** per public key, as `[open, close]` pairs.
- **Per-country profiles** of the key types and signature schemes each country uses.
- **A Poseidon2 Merkle commitment** over keys and revocations. Poseidon2 here is BN254 and noir-compatible, via [`pso-poseidon`](https://github.com/psonet/pso-poseidon).

It is the first building block for verifying encrypted identity-document envelopes on-chain. A circuit proves "the document was signed under a CSCA key that was valid on date D and the DSC is not revoked", against the registry `root`.

## Usage

```sh
./scripts/fetch.sh                                  # DE, IT, NL and ICAO (pinned) master lists, IT and NL CRLs -> sources/auto/
# optional: ICAO PKD LDIFs (captcha + T&C, manual) -> sources/icao/
#   https://pkddownload.icao.int  "eMRTD CSCA ML" (master lists)
#                                 "eMRTD PKI Objects" (CRLs + DSCs -> dsc_* country profile)
cargo run --release -- build sources -o registry.json
cargo run --release -- verify --registry registry.json
cargo run --release -- prove key --key <key id | key_hash> --at <unix seconds>
cargo run --release -- prove not-revoked --issuer-key <key id> --serial <hex>
```

`prove` prints JSON with the leaf inputs, the leaf, its index and siblings, plus both roots.

## Inputs

| file | handling |
|---|---|
| `XX_*.ml` | CMS master list. The file-name prefix `XX` is the publisher country. |
| `*.ldif` | ICAO PKD export: master lists (publisher = `c=` in the DN), CRLs, and DSCs (counted for the country profile only). |
| `*.crl` | CRL, DER or PEM. |
| `*.cer/.crt/.der/.pem` | Loose certificates, trusted as operator-provided (`status: manual`). |


`fetch.sh` downloads every master list published without a captcha or terms to accept, Germany's (BSI), Italy's and the Netherlands' (NPKD), plus Italy's and the Netherlands' CSCA CRLs, and the ICAO Master List (signed by the United Nations CSCA, hence `UN_`). ICAO's download page sits behind its terms and a captcha, so `fetch.sh` pins one edition by URL and SHA-256: when ICAO issues a new one, accept the terms at icao.int/icao-pkd/icao-master-list and update both. Together they hold CSCA keys of 137 countries. The PKD LDIFs (with the lists Switzerland and Hungary publish through ICAO, and DSCs) stay manual inputs (`sources/icao/`).
## Trust model

A master list contributes certificates only if both checks pass:

1. The CMS signature verifies. With signed attributes, the `messageDigest` must match the content and `contentType` must be `id-icao-cscaMasterList`.
2. The signer certificate is signed by a key of a publisher-country CSCA **contained in that list**.

Rejected lists stay in `sources[]` with the reason. Check 2 is self-referential, so the real assurance comes from two things:

- **Corroboration:** every certificate lists every source that carried it.
- **Pinning:** publisher anchors (`sources[].anchor`) can be pinned out of band.

With DE + IT today, 585 of 693 certificates are in both lists.

Chains are resolved by hand. An issuer is looked up by canonical DN and by AKI→SKI match, and then its signature must verify. `certificates[].chain` records the result:

| `chain` | meaning |
|---|---|
| `verified` | The issuer's signature checks out. |
| `issuer-missing` | No source carries the issuer, usually a link certificate from a retired key. Still trusted via the signed list that carried it. |
| `invalid` / `unsupported` | The certificate's own issuer (AKI-matched, or itself when self-signed) failed or could not be checked. The per-country tests fail on either. |

CRLs are applied only if a registry key verifies them.

## Cryptography

Everything is Rust; OpenSSL is banned in `deny.toml`, as in psonet:

| scheme | crate |
|---|---|
| RSA PKCS#1 v1.5 and PSS (any salt, SHA-1/2) | `rsa` |
| ECDSA on P-256/384/521 | `p256`, `p384`, `p521` |
| ECDSA on brainpoolP256r1/P384r1 | `bp256`, `bp384` |
| ECDSA on brainpoolP512r1 | `src/crypto/bp512.rs` (built from RustCrypto's `primefield` + `primeorder`, as `bp384` is) |

X9.62 DER and BSI plain `r||s` signature encodings are both accepted. Keys with explicit curve parameters, common among CSCAs, are matched to their named curve by domain parameters. `ring` alone isn't enough: it has no brainpool and no P-521 support, and its PSS verification only accepts salt length equal to the hash length.

## Output (`registry.json`)

The output is deterministic for the same inputs. It has these sections:

- `commitment`: `root`, `keys_root`, `revocations_root`, and the tree heights (16 and 14).
- `countries.XX`: the country's key and signature profile.
  - `csca_keys` / `csca_signature_schemes`: CSCA key types and the schemes CSCAs sign with. These schemes are how DSCs are signed.
  - `dsc_keys` / `dsc_signature_schemes`: DSC key types and schemes. The DSC key signs the document's SOD, so these are the schemes found in issued documents. Only present when ICAO PKD "PKI Objects" LDIFs are among the inputs.
- `certificates[]`: fingerprint, country, `kind` (root/link/orphan), `chain`, `signature_scheme`, key, validity, `private_key_usage_period`, `revoked_at`, `sources`.
- `keys[]`: one entry per public key.
  - `key_hash`: Poseidon2 of the key material.
  - Leaf header fields.
  - `periods[]`: disjoint `[open, close]` windows, each with its `leaf` and `index`.
- `revocations[]`: `(issuer key, serial)` pairs from verified CRLs, each with its `leaf` and `index`.
- `sources[]`: every input with its sha256, status, anchor and signer scheme.

## Commitment

```text
key_hash   = H(pack(key material))           RSA modulus | EC x||y
key leaf   = H(header, key_hash)             one leaf per (key, period)
header     = be(version:2 | type=1:1 | country:3 | key_type:1 | curve:1
                | bits:2 | exponent:4 | open:8 | close:8)
revocation = H(issuer key_hash, H(pack(serial)))
root       = H(version, keys_root, revocations_root)
```

- `H` is `Poseidon2::hash` from `noir-lang/poseidon` v0.3.0, the sponge Barretenberg uses; the Rust side calls `pso-poseidon`'s `Poseidon2::hash_noir` (0.5+), not its `hash`, which differs when the input length is a multiple of 3.
- Circuits verify against the commitment with the Noir library in [`noir/csca_registry`](noir/csca_registry/README.md); import it by git tag, never re-implement the leaf.
- `pack` splits big-endian bytes into 31-byte chunks, the short chunk taken from the front, least significant chunk first.
- Leaves are sorted ascending; empty slots are zero.
- Revocation non-membership is proven by the two adjacent committed leaves that bracket the target; the exact rules are in the [Noir library README](noir/csca_registry/README.md).
- Curve ids are rows of `src/crypto/curves.rs` + 1. For example, 18 = brainpoolP512r1.
- `country` is the ICAO three-letter code a circuit compares with the MRZ issuing state (`src/country.rs`: ISO 3166-1 alpha-3 plus ICAO issuer codes such as `EUE`, `UNO`, `RKS`, `XOM`; the MRZ writes Germany as `D<<`, which circuits normalise to `DEU`). An issuer without a code is committed as `XX_`, which can never match an MRZ.

**Validity on date D:** the document is valid if all of these hold:
- the document's expiry (DG1) is on or after D;
- the SOD is signed by a DSC;
- the DSC is signed by a key whose leaf has `open ≤ D ≤ close`, or `open ≤ DSC.not_before ≤ close` under ICAO's chain model;
- `prove not-revoked` holds for the DSC serial under that key.

## Data releases

Nightly (04:00 UTC, or on demand via *Run workflow* on `main`), CI does the following:

1. Fetches the publishers' current master lists and CRLs.
2. Runs the per-country suite on them. This is the gate: nothing is published from sources that fail it.
3. Builds `registry.json` with `main`'s code.
4. Publishes a **`registry-YYYYMMDD-HHMM`** GitHub release, but only if the source checksums or the commitment root changed since the previous `registry-*` release.
5. Mirrors the newest `registry-*` release to the public registry at `https://registry.zk-eid.dev` (Cloudflare R2), whether or not step 4 published a new one.

Each release carries `registry.json`, `sources.SHA256SUMS` and `SHA256SUMS`. Its notes give the new and previous roots and a diff of the source checksums. Consumers, such as the circuit prover or the job that updates the on-chain root, take the newest `registry-*` release:

```sh
gh release list -R zk-experiments/csca-registry --json tagName,createdAt \
  -q '[.[]|select(.tagName|startswith("registry-"))]|sort_by(.createdAt)|last|.tagName'
```

Or, with no GitHub access, from the public registry:

- `https://registry.zk-eid.dev/latest/latest.json`: `{"tag", "root"}` of the newest release (cached for 5 minutes);
- `https://registry.zk-eid.dev/latest/registry.json` (and `sources.SHA256SUMS`, `SHA256SUMS`): its files;
- `https://registry.zk-eid.dev/<tag>/registry.json`: any mirrored release, immutable.

Check `registry.json` against `SHA256SUMS`, and its root against the one you trust (on-chain, say): the registry host is a mirror, not a trust anchor.

CI publishes with the organization settings `R2_REGISTRY_TOKEN` (secret: an R2 API token with write access to the registry bucket, used through R2's S3 API), `R2_REGISTRY_BUCKET` and `R2_ACCOUNT_ID` (variables; the account ID is shared with eid-circuits' bucket). Without the bucket variable the step is skipped.

Code releases (`v*`, cut by cog) are separate and also attach a registry built at release time.

## Development

The conventions are psonet's:

- **Toolchain:** pinned in `rust-toolchain.toml` (1.94).
- **Lints:** lint levels live in `Cargo.toml` `[lints]`, and CI adds pso-poseidon's clippy code-smell set.
- **Tests:** `cargo nextest` with `.config/nextest.toml`.
- **Supply chain:** `cargo deny` and `cargo audit` both gate. The one documented ignore is in `deny.toml` and `.cargo/audit.toml`.
- **Spelling:** `typos`.
- **Commits and releases:** conventional commits, checked by commitlint. `cog` bumps the version and tags on `main`, and the tag release attaches the binaries, a freshly built `registry.json`, and `SHA256SUMS`.

```sh
cargo nextest run              # unit + synthetic PKI + one test per country (fixtures)
CSCA_SOURCES=sources cargo nextest run --test countries   # same checks on a fresh download
cargo deny check && cargo audit
```

Tests:

- **`tests/countries.rs`:** one trial per country found in the sources. It checks that each country has keys; that there are no `invalid` or `unsupported` chains; that periods are ordered and disjoint; that every leaf recomputes and proves into `root`; and that the signature profile is non-empty. CI also runs it nightly against the live downloads.
- **`tests/synthetic.rs`:** a generated PKI (`tests/fixtures/synthetic/gen.py`) covering the LDIF path, a forged master list, RSA-PSS, explicit-parameter brainpoolP512r1, link certificates, CRL → revocation, and the proofs.
