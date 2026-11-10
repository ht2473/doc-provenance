"""
Удостоверяющий центр на два уровня: корневой сертификат и сертификаты подписи документов.

Корневой ключ подписывает только сертификаты и списки отзыва и хранится отдельно от службы,
которая подписывает документы: у службы — свой ключ и сертификат на ограниченный срок.
Украденный ключ службы отзывается списком отзыва, корневой при этом остаётся прежним,
и тем, кто проверяет документы, нечего менять у себя.

Ключи — ECDSA на кривой P-256, подписи — с SHA-256.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .errors import ProvenanceError

# Назначение «подпись документов» (RFC 9336).
DOCUMENT_SIGNING = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36")

ROOT_YEARS = 10
SIGNER_DAYS = 365
CRL_DAYS = 30
# Запас на расхождение часов: сертификат действует чуть раньше момента выпуска.
BACKDATE = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class Identity:
    """Закрытый ключ и сертификат к нему."""

    key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _name(common_name: str, organization: str) -> x509.Name:
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    return x509.Name(attributes)


def new_root(common_name: str, organization: str = "", *, years: int = ROOT_YEARS) -> Identity:
    """
    Корневой сертификат: подписан своим же ключом, может подписывать только сертификаты
    и списки отзыва, промежуточных центров под ним быть не может.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name(common_name, organization)
    start = _now() - BACKDATE
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return Identity(key, certificate)


def issue_signer(
    root: Identity, common_name: str, organization: str = "", *, days: int = SIGNER_DAYS
) -> Identity:
    """
    Сертификат подписи документов: не центр, годится только для подписи и только документов.

    Срок не выходит за срок корневого: сертификат, переживший своего издателя, проверку
    не прошёл бы.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    start = _now() - BACKDATE
    end = min(start + timedelta(days=days), root.certificate.not_valid_after_utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name, organization))
        .issuer_name(root.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([DOCUMENT_SIGNING]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root.key.public_key()),
            critical=False,
        )
        .sign(root.key, hashes.SHA256())
    )
    return Identity(key, certificate)


def make_crl(
    root: Identity,
    revoked: list[tuple[int, datetime]],
    *,
    number: int = 1,
    days: int = CRL_DAYS,
) -> x509.CertificateRevocationList:
    """Список отзыва: номера отозванных сертификатов и даты отзыва; ``number`` растёт с выпуском."""
    now = _now()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root.certificate.subject)
        .last_update(now)
        .next_update(now + timedelta(days=days))
        .add_extension(x509.CRLNumber(number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root.key.public_key()),
            critical=False,
        )
    )
    for serial, moment in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(moment).build()
        )
    return builder.sign(root.key, hashes.SHA256())


def fingerprint(certificate: x509.Certificate) -> str:
    """Отпечаток сертификата SHA-256 — для сверки глазами с тем, что опубликовал владелец."""
    return certificate.fingerprint(hashes.SHA256()).hex()


def serial_text(certificate: x509.Certificate) -> str:
    """Номер сертификата шестнадцатеричной записью."""
    return f"{certificate.serial_number:x}"


def common_name(name: x509.Name) -> str:
    """Имя из сертификата; без него — запись имени целиком."""
    found = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(found[0].value) if found else name.rfc4514_string()


def is_document_signer(certificate: x509.Certificate) -> bool:
    """Сертификат для подписи документов: не центр, с правом подписи и нужным назначением."""
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        purposes = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return not constraints.ca and usage.digital_signature and DOCUMENT_SIGNING in purposes


def is_root(certificate: x509.Certificate) -> bool:
    """Сертификат центра: может подписывать сертификаты и списки отзыва."""
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return constraints.ca and usage.key_cert_sign


# --- Файлы ------------------------------------------------------------------------------------


def save_key(key: ec.EllipticCurvePrivateKey, path: Path, passphrase: str = "") -> None:
    """Записать закрытый ключ в PEM; с паролем — зашифрованным."""
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    )


def load_key(path: Path, passphrase: str = "") -> ec.EllipticCurvePrivateKey:
    """Прочитать закрытый ключ из PEM."""
    try:
        key = serialization.load_pem_private_key(
            path.read_bytes(), passphrase.encode() if passphrase else None
        )
    except (ValueError, TypeError) as error:
        raise ProvenanceError(f"ключ {path.name} не читается: {error}") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ProvenanceError(f"ключ {path.name} — не ключ ECDSA")
    return key


def save_certificate(certificate: x509.Certificate, path: Path) -> None:
    """Записать сертификат в PEM."""
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def load_certificate(path: Path) -> x509.Certificate:
    """Прочитать сертификат из PEM."""
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except ValueError as error:
        raise ProvenanceError(f"сертификат {path.name} не читается: {error}") from error


def save_crl(crl: x509.CertificateRevocationList, path: Path) -> None:
    """Записать список отзыва в PEM."""
    path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))


def load_crl(path: Path) -> x509.CertificateRevocationList:
    """Прочитать список отзыва из PEM."""
    try:
        return x509.load_pem_x509_crl(path.read_bytes())
    except ValueError as error:
        raise ProvenanceError(f"список отзыва {path.name} не читается: {error}") from error
