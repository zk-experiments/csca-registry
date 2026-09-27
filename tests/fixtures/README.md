# Test fixtures

## sources/ — real master lists (snapshot)

Inputs to the per-country suite (`tests/countries.rs`). Public files, fetched 2026-09-27 by `scripts/fetch.sh`; refresh by re-running it and copying.

| file | publisher | sha256 |
|---|---|---|
| `DE_ML_2026-08-19-10-28-54.ml` | BSI (DE), bsi.bund.de/csca | `b0dfa486ef25ab2d…` |
| `IT_CSCA.crl` | Ministero dell'Interno (IT), csca-ita.interno.gov.it | `6beacbc84fa75941…` |
| `IT_MasterListCSCA.ml` | Ministero dell'Interno (IT), csca-ita.interno.gov.it | `70eeab7edd6cd41d…` |
| `NL_CSCA.crl` | NPKD (NL), crl.npkd.nl | `0e6388d0df1d6c60…` |
| `NL_MasterList.ml` | NPKD (NL), npkd.nl/masterlist.html | `65c155933710e2af…` |
| `UN_ICAO_ML.ml` | ICAO Master List, signed by the UN CSCA (icao.int/icao-pkd/icao-master-list, edition 2026-09-24) | `baad83a907529f9b…` |

## un-csca-2012.der

The United Nations' first CSCA (2012-2022, from the ICAO Master List), which writes `C=ZZ`: the fixture of `cert::tests::united_nations_zz_csca_is_un`.

## synthetic/ — generated PKI

`gen.py` (needs the `openssl` CLI; the crate does not) writes an ICAO-style LDIF with a master list, a CRL and two DSCs for country XA (RSA-PSS), an explicit-parameter brainpoolP512r1 CSCA with a brainpoolP384r1 link certificate for XB, and `XA_forged.ml` whose signer chains to XB.
