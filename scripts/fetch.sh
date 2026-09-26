#!/bin/sh
# Downloads the master lists / CRLs that are published without a captcha into
# sources/auto/ and records their SHA-256 in sources/auto/SHA256SUMS.
# ICAO PKD LDIFs need a manual download (captcha + T&C): put them in sources/icao/.
# Standalone master lists must keep a `<publisher alpha-2>_` file-name prefix.
set -eu
d=sources/auto
mkdir -p "$d"
cd "$d"

rm -f DE_ML_*.ml
curl -fsSL -o de.zip 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.zip?__blob=publicationFile'
unzip -oq de.zip && rm de.zip

curl -fsSL -o it.zip https://csca-ita.interno.gov.it/certificatiCSCA/IT_MasterListCSCA.zip
unzip -oq it.zip && rm it.zip
curl -fsSL -o IT_CSCA.crl https://csca-ita.interno.gov.it/certificatiCSCA/CRL_CSCA.crl

shasum -a 256 *.ml *.crl > SHA256SUMS
cat SHA256SUMS
