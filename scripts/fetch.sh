#!/bin/sh
# Downloads the master lists / CRLs that are published without a captcha into
# sources/auto/ and records their SHA-256 in sources/auto/SHA256SUMS.
# ICAO PKD LDIFs need a manual download (captcha + T&C): put them in sources/icao/.
# The ICAO Master List is fetched from a pinned URL (see below).
# Standalone master lists must keep a `<publisher alpha-2>_` file-name prefix.
set -eu
d=sources/auto
mkdir -p "$d"
cd "$d"

rm -f DE_ML_*.ml NL_MasterList.ml UN_ICAO_ML.ml
curl -fsSL -o de.zip 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.zip?__blob=publicationFile'
unzip -oq de.zip && rm de.zip

curl -fsSL -o it.zip https://csca-ita.interno.gov.it/certificatiCSCA/IT_MasterListCSCA.zip
unzip -oq it.zip && rm it.zip
curl -fsSL -o IT_CSCA.crl https://csca-ita.interno.gov.it/certificatiCSCA/CRL_CSCA.crl
# Netherlands (NPKD): a CMS master list (.mls) and the Dutch CSCA's CRL.
curl -fsSL -o NL_MasterList.ml https://www.npkd.nl/files/ml/NL_MASTERLIST.mls
curl -fsSL -o NL_CSCA.crl http://crl.npkd.nl/crls/NLD.crl
# ICAO Master List (CSCAs of ICAO PKD participants, signed by the United
# Nations CSCA, hence UN_). Its download page sits behind ICAO's terms and a
# captcha, so the edition is pinned: when ICAO issues a new one, accept the
# terms at https://www.icao.int/icao-pkd/icao-master-list and update the URL
# and SHA-256 below.
icao_ml_url='https://www.icao.int/sites/default/files/Security/FAL/MasterList/ICAO_ML_20260924155216.ml'
icao_ml_sha256='baad83a907529f9b11fc1fc2210efc142a7c7913ba6d43906c813f6fec26b8bb'
curl -fsSL -o UN_ICAO_ML.ml "$icao_ml_url"
echo "$icao_ml_sha256  UN_ICAO_ML.ml" | shasum -a 256 -c -

shasum -a 256 *.ml *.crl > SHA256SUMS
cat SHA256SUMS
