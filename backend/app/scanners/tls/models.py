"""
app/scanners/tls/models.py

Pydantic models representing structured data for the Live TLS Scanner.
"""

from pydantic import BaseModel, Field


class CertDetails(BaseModel):
    """
    Structured metadata decoded from a peer SSL/TLS certificate.
    """

    subject: dict[str, str] = Field(
        default_factory=dict,
        description="Certificate Subject fields mapping (commonName, organizationName, etc.).",
    )
    issuer: dict[str, str] = Field(
        default_factory=dict,
        description="Certificate Issuer fields mapping.",
    )
    serial_number: str | None = Field(default=None, description="Hex serial number string.")
    validity_start: str | None = Field(default=None, description="Start date (notBefore field).")
    validity_end: str | None = Field(default=None, description="Expiration date (notAfter field).")
    subject_alt_names: list[str] = Field(
        default_factory=list,
        description="Extracted Subject Alternative Names (SANs) for asset discovery.",
    )
    fingerprint_sha256: str | None = Field(default=None, description="SHA-256 certificate fingerprint string.")
    signature_algorithm: str | None = Field(default=None, description="Certificate signature algorithm name.")
    public_key_algorithm: str | None = Field(default=None, description="Public key algorithm (e.g. RSA, EC).")
    public_key_bits: int | None = Field(default=None, description="Public key size in bits (e.g. 2048, 256).")


class TlsRecord(BaseModel):
    """
    Standard scanner output record containing TLS handshake, negotiated parameters, and certificate findings.
    """

    port: int = Field(..., ge=1, le=65535, description="Scanned TLS port.")
    host: str = Field(..., description="Target host analyzed.")
    ip_address: str | None = Field(default=None, description="Resolved target IP address.")
    ip_version: str | None = Field(default=None, description="Target IP protocol version: IPv4 | IPv6.")
    sni_hostname: str | None = Field(default=None, description="SNI hostname passed during Client Hello.")
    negotiated_tls_version: str | None = Field(
        default=None,
        description="The active protocol negotiated (e.g. 'TLSv1.3').",
    )
    negotiated_cipher: str | None = Field(default=None, description="Negotiated cipher suite name.")
    alpn_negotiated: str | None = Field(default=None, description="ALPN application protocol negotiated (h2, http/1.1, none).")
    certificate: CertDetails | None = Field(
        default=None,
        description="Parsed metadata of peer certificate. None if connection had no cert.",
    )
    chain_status: str = Field(default="complete", description="Presented certificate chain status: complete | incomplete.")
    supported_protocols: list[str] = Field(
        default_factory=list,
        description="List of TLS/SSL protocol versions supported by the server.",
    )
    weak_ciphers_accepted: bool = Field(
        default=False,
        description="True if the server accepted at least one weak cipher suite.",
    )
    weak_ciphers_negotiated: list[str] = Field(
        default_factory=list,
        description="List of weak cipher suite names negotiated during connection tests.",
    )
    trust_status: str = Field(
        default="unknown",
        description="Certificate trust assessment: valid | expired | self_signed | hostname_mismatch | unknown.",
    )
    hostname_verification: str = Field(
        default="unknown",
        description="Explicit hostname matching assessment: valid | mismatch | unknown.",
    )
    connection_status: str = Field(
        default="success",
        description="TLS connection lifecycle status: success | tcp_refused | timeout | tls_error.",
    )
