# Security

Report vulnerabilities privately to the repository maintainers (GitHub security advisory on this repository), not in public issues.

## What the registry guarantees

- A master list contributes certificates only if its CMS signature verifies and its signer certificate is signed by a CSCA of the publishing country contained in the same list. That check is self-referential; assurance comes from cross-source agreement (`certificates[].sources`) and from pinning publisher anchors (`sources[].anchor`) out of band.
- CRLs apply only when signed by a key in the registry.
- The commitment in `registry.json` is reproducible from its own leaves: `csca-registry verify --registry registry.json`.

## Cryptography

Verification uses RustCrypto (`rsa`, `p256`, `p384`, `p521`, `bp256`, `bp384`). brainpoolP512r1 is assembled locally (`src/crypto/bp512.rs`) from RustCrypto's `primefield`/`primeorder` with the crypto-bigint backend, which RustCrypto marks experimental. It is exercised by every brainpoolP512r1 signature in the fixtures (DE, FI, CH, SE, BR, NG, ET, VN) and by the synthetic PKI.

`rsa` carries RUSTSEC-2023-0071 (Marvin, private-key timing). Only public-key verification happens here; see the ignore in `deny.toml`.

## Release artifacts

Each release attaches `registry.json`, CLI binaries and `SHA256SUMS`, built by `.github/workflows/ci.yml` on the tag. They are not sigstore-signed while the repository is private (keyless signing publishes the repository identity to the public Rekor log).
