# csca-registry

Builds one deduplicated, signature-checked list of eMRTD **CSCA** certificates (passports,
ID/residence cards) from ICAO PKD and national master lists, with validity windows per
certificate and merged per public key. First building block for verifying encrypted
document envelopes on-chain: the circuit proves "signed by a CSCA key that was valid on
date D", and this registry is where those keys and dates come from.

Reference: [zkpassport/circuits](https://github.com/zkpassport/circuits) (`src/rust/masterlist-interpreter`)
and [zkpassport/registry](https://github.com/zkpassport/registry).

## Usage

```sh
./scripts/fetch.sh                        # DE (BSI) + IT master lists, IT CRL -> sources/auto/
# optional: ICAO PKD LDIFs (captcha + T&C, manual) -> sources/icao/
#   https://pkddownload.icao.int  "eMRTD CSCA ML" and "eMRTD PKI Objects" (for CRLs)
cargo run --release -- sources -o registry.json
cargo test
```

macOS: if the openssl crate can't find OpenSSL, `export OPENSSL_DIR=$(brew --prefix openssl@3)`.

## Inputs

| file | handling |
|---|---|
| `XX_*.ml` | CMS master list; `XX` (file-name prefix) = publisher country |
| `*.ldif` | ICAO PKD: master lists (publisher = `c=` in the DN) and CRLs; DSC entries skipped |
| `*.crl` | CRL (DER/PEM) |
| `*.cer/.crt/.der/.pem` | loose certificates, trusted as operator-provided (`status: manual`) |

## Trust model

A master list is accepted only if
1. the CMS signature over its content verifies, and
2. the ML signer certificate is signed by a key of a publisher-country CSCA **contained in that list**.

Rejected lists are reported in `sources[]` with the reason and contribute nothing.
(2) is self-referential, so the real assurance is corroboration: each certificate records
every source that listed it (`sources[]`); with DE + IT today 585/693 certs are in both.
Pin publisher anchors (`sources[].anchor`) out-of-band when that is not enough.

Chain checks are done by hand, not with `X509_verify_cert`: OpenSSL 3 rejects keys with
explicit EC parameters (`X509_V_ERR_EC_KEY_EXPLICIT_PARAMS`), and several CSCAs (DE, LT, …) use them.

CRLs are applied only if signed by a CSCA in the registry.

## Output (`registry.json`, deterministic for the same inputs)

- `certificates[]` — one per unique DER (`fingerprint` = sha256):
  `country`, `kind` (`root` self-signed | `link` signed by another listed CSCA | `orphan`
  issuer not in registry, typically a link cert from a retired key), `key` {`id`, `type`, `bits`,
  `curve` — explicit params resolved to the named curve}, `not_before`/`not_after`,
  `private_key_usage_period` (when the CSCA may issue DSCs), `revoked_at`, `sources`.
- `keys[]` — per public key (`id` = sha256 of RSA modulus / uncompressed EC point):
  `periods` = union of the validity windows of every cert carrying that key, as disjoint
  `[open, close]` unix-second pairs (close is cut at `revoked_at`).
- `revocations[]` — (`issuer_fingerprint`, `serial`, `revoked_at`) from verified CRLs;
  mostly DSC serials, i.e. what an on-chain check needs to reject revoked DSCs.
- `sources[]` — every input with sha256, status, and for master lists the anchor CSCA.

## Validity on date D (for the circuit side)

Document valid on D ⇔ document expiry (DG1) ≥ D, SOD signed by a DSC, the DSC signed by a
key in `keys[]` with D (or, under ICAO's chain model, the DSC's `not_before`) inside one of
its `periods`, and the DSC serial not in `revocations[]` for that issuer.

## Not done yet

- Poseidon/Merkle commitment of `keys[]` + `revocations[]` for the circuit (zkpassport's
  `certificate_root` layout is the reference).
- Scheduled CI refresh; ICAO LDIF path has unit coverage only, not yet run on a real PKD dump.
- More national sources: add a `curl` line to `scripts/fetch.sh` (file name must start with the country code).
