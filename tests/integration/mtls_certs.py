"""Deterministic, test-only PKI fixtures for the producer-mTLS spike
(Phase 1A, docs/spikes/producer-mtls-certificate-exposure.md).

Every certificate here is generated fresh, in-process, each time a test
runs — nothing here is committed to the repository, and nothing here is fit
for, or reusable in, any real deployment. Private keys are 2048-bit RSA,
generated with no passphrase, solely to drive local TLS handshakes against
``127.0.0.1`` for the lifetime of a single test process. Common names and
URI SAN values are obviously synthetic (``*.test`` / ``example.test``,
per RFC 2606).

This module produces:
  - a self-signed test CA ("BASIS Spike Test CA") — the CA the spike server
    trusts;
  - a second, independent self-signed CA ("BASIS Spike UNTRUSTED Test CA")
    — used only to sign the ``client_untrusted_ca`` certificate, so tests
    can prove the configured trust store is actually enforced;
  - a server certificate for 127.0.0.1 / localhost, signed by the trusted
    CA;
  - client certificates covering every URI SAN shape ADR-0008 cares about:
      * ``client_one_uri_san``   — exactly one URI SAN (the admitted shape)
      * ``client_zero_uri_san``  — no SAN extension at all
      * ``client_multi_uri_san`` — two URI SANs
      * ``client_expired``      — one URI SAN, but already expired
      * ``client_untrusted_ca`` — one URI SAN, signed by the untrusted CA
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ONE_URI_SAN = "spiffe://example.test/basis/reference-producer-01"
MULTI_URI_SAN_A = "spiffe://example.test/basis/reference-producer-01"
MULTI_URI_SAN_B = "spiffe://example.test/basis/reference-producer-02"

_KEY_SIZE = 2048


@dataclass(frozen=True)
class GeneratedCert:
    """A generated certificate/key pair, written to disk as PEM files."""

    cert_path: Path
    key_path: Path
    cert_pem: bytes
    key_pem: bytes


@dataclass(frozen=True)
class MTLSFixtureSet:
    """Every certificate the spike tests need, all signed by ``ca`` except
    ``client_untrusted_ca`` (signed by the independent ``untrusted_ca``)."""

    ca: GeneratedCert
    untrusted_ca: GeneratedCert
    server: GeneratedCert
    client_one_uri_san: GeneratedCert
    client_zero_uri_san: GeneratedCert
    client_multi_uri_san: GeneratedCert
    client_expired: GeneratedCert
    client_untrusted_ca: GeneratedCert


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=_KEY_SIZE)


def _self_signed_ca(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _new_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf_cert(
    *,
    common_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    san: x509.SubjectAlternativeName | None,
    not_before_delta: datetime.timedelta = datetime.timedelta(days=-1),
    not_after_delta: datetime.timedelta = datetime.timedelta(days=30),
    is_server: bool = False,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _new_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + not_before_delta)
        .not_valid_after(now + not_after_delta)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH]
                if is_server
                else [ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
    )
    if san is not None:
        builder = builder.add_extension(san, critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _write(
    directory: Path, name: str, key: rsa.RSAPrivateKey, cert: x509.Certificate
) -> GeneratedCert:
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path = directory / f"{name}.cert.pem"
    key_path = directory / f"{name}.key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return GeneratedCert(cert_path=cert_path, key_path=key_path, cert_pem=cert_pem, key_pem=key_pem)


def build_fixture_set(tmp_dir: Path) -> MTLSFixtureSet:
    """Generate the full spike PKI fresh, writing PEM files under ``tmp_dir``.

    Nothing returned here is a secret in any meaningful sense — it is
    regenerated on every test run and never leaves the test process's
    temporary directory.
    """
    ca_key, ca_cert = _self_signed_ca("BASIS Spike Test CA")
    ca = _write(tmp_dir, "ca", ca_key, ca_cert)

    untrusted_ca_key, untrusted_ca_cert = _self_signed_ca("BASIS Spike UNTRUSTED Test CA")
    untrusted_ca = _write(tmp_dir, "untrusted-ca", untrusted_ca_key, untrusted_ca_cert)

    server_key, server_cert = _leaf_cert(
        common_name="127.0.0.1",
        ca_key=ca_key,
        ca_cert=ca_cert,
        san=x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        ),
        is_server=True,
    )
    server = _write(tmp_dir, "server", server_key, server_cert)

    one_key, one_cert = _leaf_cert(
        common_name="reference-producer-01",
        ca_key=ca_key,
        ca_cert=ca_cert,
        san=x509.SubjectAlternativeName([x509.UniformResourceIdentifier(ONE_URI_SAN)]),
    )
    client_one_uri_san = _write(tmp_dir, "client-one-san", one_key, one_cert)

    zero_key, zero_cert = _leaf_cert(
        common_name="no-uri-san-producer",
        ca_key=ca_key,
        ca_cert=ca_cert,
        san=None,
    )
    client_zero_uri_san = _write(tmp_dir, "client-zero-san", zero_key, zero_cert)

    multi_key, multi_cert = _leaf_cert(
        common_name="multi-uri-san-producer",
        ca_key=ca_key,
        ca_cert=ca_cert,
        san=x509.SubjectAlternativeName(
            [
                x509.UniformResourceIdentifier(MULTI_URI_SAN_A),
                x509.UniformResourceIdentifier(MULTI_URI_SAN_B),
            ]
        ),
    )
    client_multi_uri_san = _write(tmp_dir, "client-multi-san", multi_key, multi_cert)

    expired_key, expired_cert = _leaf_cert(
        common_name="expired-producer",
        ca_key=ca_key,
        ca_cert=ca_cert,
        san=x509.SubjectAlternativeName([x509.UniformResourceIdentifier(ONE_URI_SAN)]),
        not_before_delta=datetime.timedelta(days=-10),
        not_after_delta=datetime.timedelta(days=-1),
    )
    client_expired = _write(tmp_dir, "client-expired", expired_key, expired_cert)

    untrusted_client_key, untrusted_client_cert = _leaf_cert(
        common_name="untrusted-ca-producer",
        ca_key=untrusted_ca_key,
        ca_cert=untrusted_ca_cert,
        san=x509.SubjectAlternativeName([x509.UniformResourceIdentifier(ONE_URI_SAN)]),
    )
    client_untrusted_ca = _write(
        tmp_dir, "client-untrusted-ca", untrusted_client_key, untrusted_client_cert
    )

    return MTLSFixtureSet(
        ca=ca,
        untrusted_ca=untrusted_ca,
        server=server,
        client_one_uri_san=client_one_uri_san,
        client_zero_uri_san=client_zero_uri_san,
        client_multi_uri_san=client_multi_uri_san,
        client_expired=client_expired,
        client_untrusted_ca=client_untrusted_ca,
    )
