#!/usr/bin/env python3
"""Regenerates the synthetic PKI fixture (needs the openssl CLI; the crate does not).

XA: RSA-2048 CSCA signing with RSA-PSS, an EC P-256 master-list signer, two RSA
    DSCs (serial 1001 revoked by the XA CRL, 1002 not).
XB: brainpoolP512r1 CSCA with *explicit* curve parameters, and a link
    certificate to a new brainpoolP384r1 key.
Outputs icaopkd-synthetic.ldif (master list + CRL + DSCs, as ICAO PKD ships
them) and XA_forged.ml (claims XA, signer chains to XB: must be rejected).
"""
import base64, os, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
tmp = tempfile.mkdtemp()
def sh(*a, **kw): subprocess.run(a, check=True, cwd=tmp, capture_output=True, **kw)
def p(n): return os.path.join(tmp, n)

PSS = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"]
def key_rsa(n): sh("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", n)
def key_ec(n, curve, explicit=False):
    sh("openssl", "ecparam", "-name", curve, "-genkey", "-noout", "-out", n,
       *(["-param_enc", "explicit"] if explicit else []))
def ext(name, body):
    open(p(name), "w").write(body)
    return name
CA = ext("ca.ext", "basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
MLS = ext("mls.ext", "keyUsage=critical,digitalSignature\nextendedKeyUsage=critical,2.23.136.1.1.3\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
DSC = ext("dsc.ext", "keyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")

def root(name, subj, key, md, sigopt=()):
    sh("openssl", "req", "-x509", "-new", "-key", key, "-subj", subj, "-days", "3650", f"-{md}",
       "-set_serial", "1", "-addext", "basicConstraints=critical,CA:true",
       "-addext", "keyUsage=critical,keyCertSign,cRLSign", *sigopt, "-out", name)
def issue(name, subj, key, ca, ca_key, serial, extfile, md, sigopt=()):
    sh("openssl", "req", "-new", "-key", key, "-subj", subj, "-out", name + ".csr")
    sh("openssl", "x509", "-req", "-in", name + ".csr", "-CA", ca, "-CAkey", ca_key, "-set_serial", str(serial),
       "-days", "1825", f"-{md}", "-extfile", extfile, *sigopt, "-out", name)
def der(pem):
    return subprocess.run(["openssl", "x509", "-in", p(pem), "-outform", "DER"], check=True, capture_output=True).stdout

key_rsa("xa.key"); root("xa.pem", "/C=XA/O=Synthetic/CN=CSCA XA", "xa.key", "sha256", PSS)
key_ec("xa-mls.key", "prime256v1"); issue("xa-mls.pem", "/C=XA/O=Synthetic/CN=ML Signer XA", "xa-mls.key", "xa.pem", "xa.key", 2, MLS, "sha256", PSS)
key_rsa("dsc1.key"); issue("dsc1.pem", "/C=XA/O=Synthetic/CN=DSC 1", "dsc1.key", "xa.pem", "xa.key", 0x1001, DSC, "sha256", PSS)
key_rsa("dsc2.key"); issue("dsc2.pem", "/C=XA/O=Synthetic/CN=DSC 2", "dsc2.key", "xa.pem", "xa.key", 0x1002, DSC, "sha256", PSS)
key_ec("xb.key", "brainpoolP512r1", explicit=True); root("xb.pem", "/C=XB/O=Synthetic/CN=CSCA XB", "xb.key", "sha512")
key_ec("xb2.key", "brainpoolP384r1"); issue("xb-link.pem", "/C=XB/O=Synthetic/CN=CSCA XB", "xb2.key", "xb.pem", "xb.key", 3, CA, "sha512")
key_ec("xb-mls.key", "prime256v1"); issue("xb-mls.pem", "/C=XA/O=Synthetic/CN=ML Signer XA", "xb-mls.key", "xb.pem", "xb.key", 4, MLS, "sha512")

def tlv(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + body
def masterlist(out, certs, signer, signer_key):
    content = tlv(0x30, b"\x02\x01\x00" + tlv(0x31, b"".join(der(c) for c in certs)))
    open(p("content.der"), "wb").write(content)
    sh("openssl", "cms", "-sign", "-binary", "-nodetach", "-in", "content.der", "-signer", signer, "-inkey", signer_key,
       "-econtent_type", "2.23.136.1.1.2", "-md", "sha256", "-outform", "DER", "-out", out)
    return open(p(out), "rb").read()

ml = masterlist("xa.ml", ["xa.pem", "xb.pem", "xb-link.pem"], "xa-mls.pem", "xa-mls.key")
forged = masterlist("forged.ml", ["xa.pem", "xb.pem"], "xb-mls.pem", "xb-mls.key")

open(p("index.txt"), "w").write("R\t350101000000Z\t250601000000Z\t1001\tunknown\t/C=XA/O=Synthetic/CN=DSC 1\n")
open(p("crlnumber"), "w").write("01\n")
open(p("ca.cnf"), "w").write(f"[ca]\ndefault_ca=d\n[d]\ndatabase={p('index.txt')}\ncrlnumber={p('crlnumber')}\ndefault_md=sha256\ndefault_crl_days=3650\n")
sh("openssl", "ca", "-gencrl", "-config", "ca.cnf", "-cert", "xa.pem", "-keyfile", "xa.key", *PSS, "-out", "xa.crl.pem")
crl = subprocess.run(["openssl", "crl", "-in", p("xa.crl.pem"), "-outform", "DER"], check=True, capture_output=True).stdout

def entry(dn, attr, blob):
    b64 = base64.b64encode(blob).decode()
    lines = [f"dn: {dn}", f"{attr}:: " + b64[:60]] + [" " + b64[i:i + 76] for i in range(60, len(b64), 76)]
    return "\n".join(lines) + "\n\n"
ldif = "version: 1\n\n"
ldif += entry("cn=ml,o=ml,c=XA,dc=data,dc=download,dc=pkd,dc=icao,dc=int", "pkdMasterListContent", ml)
ldif += entry("cn=crl,o=crl,c=XA,dc=data,dc=download,dc=pkd,dc=icao,dc=int", "certificateRevocationList;binary", crl)
for i, d in enumerate(["dsc1.pem", "dsc2.pem"], 1):
    ldif += entry(f"cn=dsc{i},o=dsc,c=XA,dc=data,dc=download,dc=pkd,dc=icao,dc=int", "userCertificate;binary", der(d))
open(os.path.join(HERE, "icaopkd-synthetic.ldif"), "w").write(ldif)
open(os.path.join(HERE, "XA_forged.ml"), "wb").write(forged)
print("ok")
