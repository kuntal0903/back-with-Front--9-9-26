"""
app/scanners/tls/parser.py

Decodes DER peer certificates and extracts structured key-value metadata,
SHA-256 fingerprint, signature algorithms, and key parameters.
"""

import hashlib
import os
import ssl
import tempfile
from typing import Any

from app.scanners.tls.models import CertDetails


def parse_der_certificate(der_bytes: bytes) -> CertDetails:
    """
    Convert DER bytes to PEM string, compute SHA-256 fingerprint, write to temp file,
    and decode natively using standard library's internal ASN.1 decoder.
    
    Args:
        der_bytes: DER encoded binary certificate.
        
    Returns:
        CertDetails: Decoded metadata schema.
    """
    # 1. Compute SHA-256 fingerprint
    fingerprint_sha256 = hashlib.sha256(der_bytes).hexdigest().upper()

    # 2. Convert DER to PEM string format
    pem = ssl.DER_cert_to_PEM_cert(der_bytes)

    # 3. Write to temp file for the native decoder
    with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".pem") as f:
        f.write(pem)
        temp_path = f.name

    try:
        raw_dict = ssl._ssl._test_decode_cert(temp_path)
    finally:
        try:
            os.unlink(temp_path)
        except Exception:
            pass

    # 4. Parse decoded attributes
    subject = _flat_rdn(raw_dict.get("subject", ()))
    issuer = _flat_rdn(raw_dict.get("issuer", ()))
    serial_number = raw_dict.get("serialNumber")

    validity_start = raw_dict.get("notBefore")
    validity_end = raw_dict.get("notAfter")

    # Extract Subject Alternative Names (SANs)
    subject_alt_names = []
    raw_sans = raw_dict.get("subjectAltName", ())
    for san in raw_sans:
        if len(san) == 2:
            # san is e.g. ('DNS', '*.google.com')
            subject_alt_names.append(san[1])

    sig_alg = raw_dict.get("signatureAlgorithm") or raw_dict.get("signature_algorithm")
    pub_alg = raw_dict.get("publicKeyAlgorithm") or "RSA"  # standard fallback if key info present

    return CertDetails(
        subject=subject,
        issuer=issuer,
        serial_number=serial_number,
        validity_start=validity_start,
        validity_end=validity_end,
        subject_alt_names=subject_alt_names,
        fingerprint_sha256=fingerprint_sha256,
        signature_algorithm=sig_alg,
        public_key_algorithm=pub_alg,
    )


def _flat_rdn(rdn_tuple: tuple[Any, ...]) -> dict[str, str]:
    """
    Helper converting nested ASN.1 RDN tuples into a flat key-value dictionary.
    
    Nested input example:
        ((('countryName', 'US'),), (('organizationName', 'Google Trust Services'),))
    """
    flat = {}
    if not rdn_tuple:
        return flat

    for item in rdn_tuple:
        for pair in item:
            if len(pair) == 2:
                key, val = pair
                flat[str(key)] = str(val)

    return flat
