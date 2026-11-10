"""Подпись документа: что проверка принимает и почему отказывает."""

from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from provenance import ca, cms
from provenance.errors import Code, VerifyError

from .conftest import DOCUMENT


def refusal(content: bytes, signature: bytes, roots: list[x509.Certificate], **options) -> Code:
    """Причина отказа проверки."""
    with pytest.raises(VerifyError) as caught:
        cms.verify(content, signature, roots, **options)
    return caught.value.code


def test_signed_document_is_verified(root: ca.Identity, signer: ca.Identity) -> None:
    """Подпись сходится: названы подписавший, время и корень, до которого дошла проверка."""
    signature = cms.sign(DOCUMENT, signer)
    verified = cms.verify(DOCUMENT, signature, [root.certificate])
    assert verified.signer == "Служба подписи"
    assert verified.organization == "RegionLens"
    assert verified.serial == ca.serial_text(signer.certificate)
    assert verified.root_fingerprint == ca.fingerprint(root.certificate)
    assert abs(datetime.now(UTC) - verified.signing_time) < timedelta(minutes=1)
    assert not verified.crl_checked


def test_signature_does_not_contain_the_document(signer: ca.Identity) -> None:
    """Подпись отсоединённая: документа в ней нет, размер от него не зависит."""
    small = cms.sign(b"x", signer)
    large = cms.sign(b"x" * 500_000, signer)
    assert abs(len(small) - len(large)) < 16
    assert b"x" * 64 not in large


@pytest.mark.parametrize("position", [0, 7, len(DOCUMENT) - 1])
def test_changed_document_is_refused(root: ca.Identity, signer: ca.Identity, position: int) -> None:
    """Один изменённый байт документа — отказ."""
    signature = cms.sign(DOCUMENT, signer)
    changed = bytearray(DOCUMENT)
    changed[position] ^= 0x01
    assert refusal(bytes(changed), signature, [root.certificate]) is Code.DOCUMENT_CHANGED


def test_line_endings_are_part_of_the_document(root: ca.Identity, signer: ca.Identity) -> None:
    """Подписаны байты файла как есть: смена перевода строки — уже другой документ."""
    signature = cms.sign(DOCUMENT, signer)
    windows = DOCUMENT.replace(b"\n", b"\r\n")
    assert refusal(windows, signature, [root.certificate]) is Code.DOCUMENT_CHANGED


def test_every_changed_byte_of_the_signature_is_refused(
    root: ca.Identity, signer: ca.Identity
) -> None:
    """Подпись, испорченная в любом месте, не проходит ни с какой причиной, кроме отказа."""
    signature = cms.sign(DOCUMENT, signer)
    for position in range(len(signature)):
        broken = bytearray(signature)
        broken[position] ^= 0x01
        with pytest.raises(VerifyError):
            cms.verify(DOCUMENT, bytes(broken), [root.certificate])


def test_signature_of_another_document_is_refused(root: ca.Identity, signer: ca.Identity) -> None:
    """Подпись, перенесённая с другого документа, не подходит."""
    other = cms.sign(b"another document", signer)
    assert refusal(DOCUMENT, other, [root.certificate]) is Code.DOCUMENT_CHANGED


def test_foreign_authority_is_refused(root: ca.Identity, stranger: ca.Identity) -> None:
    """Чужой центр с теми же именами в сертификатах доверия не получает."""
    signature = cms.sign(DOCUMENT, stranger)
    assert refusal(DOCUMENT, signature, [root.certificate]) is Code.UNTRUSTED


def test_self_signed_signer_is_refused(root: ca.Identity) -> None:
    """Сертификат, подписанный самим собой, не выпущен доверенным центром."""
    lone = ca.new_root("Служба подписи")
    signature = cms.sign(DOCUMENT, lone)
    assert refusal(DOCUMENT, signature, [root.certificate]) is Code.UNTRUSTED


def test_signer_certificate_is_not_a_trust_anchor(signer: ca.Identity) -> None:
    """Сертификат подписи, поданный как «корень», корнем не считается."""
    signature = cms.sign(DOCUMENT, signer)
    assert refusal(DOCUMENT, signature, [signer.certificate]) is Code.UNTRUSTED


def test_root_cannot_sign_documents(root: ca.Identity) -> None:
    """Корневым ключом документы не подписывают: у сертификата другое назначение."""
    signature = cms.sign(DOCUMENT, root)
    assert refusal(DOCUMENT, signature, [root.certificate]) in {
        Code.UNTRUSTED,
        Code.WRONG_PURPOSE,
    }


def test_certificate_for_another_purpose_is_refused(root: ca.Identity) -> None:
    """Сертификат того же центра, но не для подписи документов, — отказ."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Веб-сервер")]))
        .issuer_name(root.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root.key, hashes.SHA256())
    )
    signature = cms.sign(DOCUMENT, ca.Identity(key, certificate))
    assert refusal(DOCUMENT, signature, [root.certificate]) is Code.WRONG_PURPOSE


def test_revoked_certificate_is_refused(root: ca.Identity, signer: ca.Identity) -> None:
    """Отозванный сертификат — отказ, даже если подпись сделана до отзыва."""
    signature = cms.sign(DOCUMENT, signer)
    clean = ca.make_crl(root, [])
    verified = cms.verify(DOCUMENT, signature, [root.certificate], crl=clean)
    assert verified.crl_checked
    assert verified.crl_fresh
    later = datetime.now(UTC) + timedelta(hours=1)
    revoked = ca.make_crl(root, [(signer.certificate.serial_number, later)], number=2)
    assert refusal(DOCUMENT, signature, [root.certificate], crl=revoked) is Code.REVOKED


def test_revocation_list_of_another_authority_is_refused(
    root: ca.Identity, signer: ca.Identity
) -> None:
    """Список отзыва принимается только от центра, выпустившего сертификат."""
    signature = cms.sign(DOCUMENT, signer)
    foreign = ca.make_crl(ca.new_root("Другой центр"), [])
    assert refusal(DOCUMENT, signature, [root.certificate], crl=foreign) is Code.BAD_CRL
    same_name = ca.make_crl(ca.new_root("Проверочный центр", "RegionLens"), [])
    assert refusal(DOCUMENT, signature, [root.certificate], crl=same_name) is Code.BAD_CRL


def test_stale_revocation_list(root: ca.Identity, signer: ca.Identity) -> None:
    """Устаревший список отзыва отмечается; с требованием свежего — отказ."""
    signature = cms.sign(DOCUMENT, signer)
    crl = ca.make_crl(root, [], days=1)
    later = datetime.now(UTC) + timedelta(days=3)
    verified = cms.verify(DOCUMENT, signature, [root.certificate], crl=crl, now=later)
    assert not verified.crl_fresh
    code = refusal(
        DOCUMENT, signature, [root.certificate], crl=crl, now=later, require_fresh_crl=True
    )
    assert code is Code.BAD_CRL


def test_signature_from_the_future_is_refused(root: ca.Identity, signer: ca.Identity) -> None:
    """Подпись со временем позже проверки — отказ."""
    signature = cms.sign(DOCUMENT, signer)
    earlier = datetime.now(UTC) - timedelta(hours=2)
    assert refusal(DOCUMENT, signature, [root.certificate], now=earlier) is Code.FROM_FUTURE


def test_expired_certificate_cannot_sign(root: ca.Identity) -> None:
    """Подпись, сделанная после конца срока сертификата, — отказ."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Служба подписи")]))
        .issuer_name(root.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=4))
        .not_valid_after(now - timedelta(minutes=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, True, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ca.DOCUMENT_SIGNING]), critical=False)
        .sign(root.key, hashes.SHA256())
    )
    signature = cms.sign(DOCUMENT, ca.Identity(key, certificate))
    assert refusal(DOCUMENT, signature, [root.certificate]) is Code.NOT_VALID_THEN


def test_signature_stays_valid_after_certificate_expires(
    root: ca.Identity, signer: ca.Identity
) -> None:
    """Документ, подписанный в срок действия сертификата, проверяется и после его конца."""
    signature = cms.sign(DOCUMENT, signer)
    later = signer.certificate.not_valid_after_utc + timedelta(days=30)
    assert cms.verify(DOCUMENT, signature, [root.certificate], now=later).signer


def test_document_inside_the_signature_is_refused(root: ca.Identity, signer: ca.Identity) -> None:
    """Подпись с документом внутри не принимается: проверялся бы он, а не данный файл."""
    attached = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(DOCUMENT)
        .add_signer(signer.certificate, signer.key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )
    assert refusal(b"another file", attached, [root.certificate]) is Code.UNSUPPORTED


def test_other_algorithms_are_refused(root: ca.Identity) -> None:
    """Подпись RSA не из принятого набора — отказ, а не проверка «как получится»."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RSA")]))
        .issuer_name(root.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(root.key, hashes.SHA256())
    )
    signature = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(DOCUMENT)
        .add_signer(certificate, key, hashes.SHA256())
        .sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary],
        )
    )
    assert refusal(DOCUMENT, signature, [root.certificate]) is Code.UNSUPPORTED


@pytest.mark.parametrize("garbage", [b"", b"\x30", b"not a signature", b"\x30\x80\x00\x00"])
def test_garbage_is_refused(root: ca.Identity, garbage: bytes) -> None:
    assert refusal(DOCUMENT, garbage, [root.certificate]) is Code.MALFORMED


def test_no_trusted_roots_means_no_trust(signer: ca.Identity) -> None:
    signature = cms.sign(DOCUMENT, signer)
    assert refusal(DOCUMENT, signature, []) is Code.UNTRUSTED


def test_describe_reads_without_trust(signer: ca.Identity) -> None:
    """Сведения из подписи читаются и без проверки — и помечены как непроверенные."""
    described = cms.describe(cms.sign(DOCUMENT, signer))
    assert described["signer"] == "Служба подписи"
    assert described["issuer"] == "Проверочный центр"


# --- Независимая проверка: OpenSSL --------------------------------------------------------------

OPENSSL = shutil.which("openssl")
needs_openssl = pytest.mark.skipif(OPENSSL is None, reason="нет openssl")


def openssl_verify(folder: Path, document: bytes, signature: bytes, root: ca.Identity) -> int:
    """Код возврата ``openssl cms -verify`` для документа и подписи."""
    (folder / "document").write_bytes(document)
    (folder / "document.p7s").write_bytes(signature)
    ca.save_certificate(root.certificate, folder / "root.crt")
    command = [
        str(OPENSSL), "cms", "-verify", "-binary", "-inform", "DER",
        "-in", "document.p7s", "-content", "document",
        "-CAfile", "root.crt", "-purpose", "any", "-out", "verified",
    ]  # fmt: skip
    return subprocess.run(command, cwd=folder, capture_output=True, check=False).returncode


@needs_openssl
def test_openssl_agrees_on_a_valid_signature(
    tmp_path: Path, root: ca.Identity, signer: ca.Identity
) -> None:
    """Подпись принимает и OpenSSL: проверка не зависит от этой библиотеки."""
    assert openssl_verify(tmp_path, DOCUMENT, cms.sign(DOCUMENT, signer), root) == 0
    assert (tmp_path / "verified").read_bytes() == DOCUMENT


@needs_openssl
def test_openssl_agrees_on_refusals(
    tmp_path: Path, root: ca.Identity, signer: ca.Identity, stranger: ca.Identity
) -> None:
    """Изменённый документ и чужой центр отклоняет и OpenSSL."""
    signature = cms.sign(DOCUMENT, signer)
    assert openssl_verify(tmp_path, DOCUMENT + b" ", signature, root) != 0
    assert openssl_verify(tmp_path, DOCUMENT, cms.sign(DOCUMENT, stranger), root) != 0


@needs_openssl
def test_signature_made_by_openssl_is_verified(
    tmp_path: Path, root: ca.Identity, signer: ca.Identity
) -> None:
    """Подпись, сделанная OpenSSL тем же ключом, проходит проверку библиотеки."""
    (tmp_path / "document").write_bytes(DOCUMENT)
    ca.save_key(signer.key, tmp_path / "signer.key")
    ca.save_certificate(signer.certificate, tmp_path / "signer.crt")
    command = [
        str(OPENSSL), "cms", "-sign", "-binary", "-md", "sha256", "-nosmimecap",
        "-in", "document", "-signer", "signer.crt", "-inkey", "signer.key",
        "-outform", "DER", "-out", "document.p7s",
    ]  # fmt: skip
    subprocess.run(command, cwd=tmp_path, capture_output=True, check=True)
    signature = (tmp_path / "document.p7s").read_bytes()
    assert cms.verify(DOCUMENT, signature, [root.certificate]).signer == "Служба подписи"
