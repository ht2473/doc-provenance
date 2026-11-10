"""
Подпись документа и её проверка.

Подпись — отсоединённая, в формате CMS (RFC 5652, файл ``.p7s``): сам документ не меняется,
рядом лежит подпись с сертификатом подписавшего. Такую подпись проверяет и OpenSSL
(``openssl cms -verify``), то есть проверка не зависит от этой библиотеки.

Что именно подписано. В подписи лежат «подписанные атрибуты»: вид содержимого, хэш документа
SHA-256 и время подписи. Ключ подписывает запись этих атрибутов, а не документ напрямую.
Поэтому проверка идёт в два шага: хэш документа сравнивается с записанным в атрибутах,
затем подпись атрибутов — с открытым ключом из сертификата. Третий шаг — доверие: сертификат
должен быть выпущен центром, которому проверяющий доверяет заранее, и не отозван.

Набор алгоритмов один: ECDSA P-256 с SHA-256. Подпись другого вида отклоняется, а не
проверяется «как получится»: чем меньше принимается вариантов, тем меньше места для подмены.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7

from . import ca, der
from .errors import Code, VerifyError

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_DATA = "1.2.840.113549.1.7.1"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"

# Теги с неявной разметкой внутри SignedData и SignerInfo.
TAG_EXPLICIT_0 = 0xA0
TAG_CERTIFICATES = 0xA0
TAG_CRLS = 0xA1
TAG_SIGNED_ATTRS = 0xA0
TAG_NULL = 0x05
TAG_BIT_STRING = 0x03

# Часы подписавшего и проверяющего могут расходиться.
CLOCK_SKEW = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class Verified:
    """Итог удачной проверки: кто подписал, когда и чем это подтверждено."""

    signer: str
    organization: str
    serial: str
    signing_time: datetime
    digest: str
    certificate: x509.Certificate
    root: x509.Certificate
    crl_checked: bool
    crl_fresh: bool

    @property
    def root_fingerprint(self) -> str:
        """Отпечаток корневого сертификата, до которого дошла проверка."""
        return ca.fingerprint(self.root)


# --- Подпись ----------------------------------------------------------------------------------


def sign(content: bytes, signer: ca.Identity) -> bytes:
    """Подписать документ; вернуть отсоединённую подпись CMS в DER."""
    return (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(content)
        .add_signer(signer.certificate, signer.key, hashes.SHA256())
        .sign(
            serialization.Encoding.DER,
            [
                pkcs7.PKCS7Options.DetachedSignature,
                # Без этого содержимое перед хэшированием приводилось бы к виду почтового
                # текста (переводы строк), и хэш считался бы не от тех байтов, что в файле.
                pkcs7.PKCS7Options.Binary,
                pkcs7.PKCS7Options.NoCapabilities,
            ],
        )
    )


# --- Разбор подписи ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Parsed:
    certificates: list[x509.Certificate]
    issuer: bytes
    serial: int
    signed_attrs: der.Node
    digest: bytes
    signing_time: datetime
    signature: bytes


def _unsupported(reason: str) -> VerifyError:
    return VerifyError(Code.UNSUPPORTED, f"подпись не принятого вида: {reason}")


def _algorithm(node: der.Node, expected: str, what: str) -> None:
    """Идентификатор алгоритма — последовательность, первым в которой стоит его номер."""
    items = der.expect(node, der.SEQUENCE, what).children()
    if not items or der.oid(items[0]) != expected:
        raise _unsupported(f"{what} — не из принятого набора")
    # Параметров у принятых алгоритмов нет: допускается только пустое значение NULL.
    if len(items) > 2 or (len(items) == 2 and (items[1].tag != TAG_NULL or items[1].content)):
        raise _unsupported(f"{what} — с параметрами")


def _attributes(node: der.Node) -> dict[str, der.Node]:
    """Подписанные атрибуты: номер — значение; каждый атрибут один раз и с одним значением."""
    found: dict[str, der.Node] = {}
    for item in node.children():
        parts = der.expect(item, der.SEQUENCE, "атрибут").children()
        if len(parts) != 2:
            raise VerifyError(Code.MALFORMED, "подпись повреждена: атрибут записан неверно")
        values = der.expect(parts[1], der.SET, "значения атрибута").children()
        name = der.oid(parts[0])
        if name in found or len(values) != 1:
            raise VerifyError(Code.MALFORMED, "подпись повреждена: атрибут повторяется")
        found[name] = values[0]
    return found


def _strict_certificate(node: der.Node) -> None:
    """
    Запись сертификата без вольностей: три поля, подпись — строка бит без неиспользуемых.

    Библиотека разбора сертификатов лишние биты в конце подписи пропускает; без этой проверки
    один байт подписи CMS можно было бы изменить незаметно.
    """
    parts = der.expect(node, der.SEQUENCE, "сертификат").children()
    if len(parts) != 3 or parts[2].tag != TAG_BIT_STRING or parts[2].content[:1] != b"\x00":
        raise VerifyError(Code.MALFORMED, "подпись повреждена: сертификат записан неверно")


def _parse(signature: bytes) -> _Parsed:
    """Разобрать подпись CMS: сертификаты, подписанные атрибуты, значение подписи."""
    certificates, signer = _signed_data(signature)
    return _signer_info(signer, certificates)


def _signed_data(signature: bytes) -> tuple[list[x509.Certificate], der.Node]:
    """Внешняя часть подписи: сертификат и сведения о единственном подписавшем."""
    outer = der.expect(der.parse(signature), der.SEQUENCE, "подпись").children()
    if len(outer) != 2 or der.oid(outer[0]) != OID_SIGNED_DATA:
        raise _unsupported("это не подписанные данные CMS")
    wrapped = der.expect(outer[1], TAG_EXPLICIT_0, "подписанные данные").children()
    if len(wrapped) != 1:
        raise VerifyError(Code.MALFORMED, "подпись повреждена: лишние данные")
    fields = der.expect(wrapped[0], der.SEQUENCE, "подписанные данные").children()
    if len(fields) < 4:
        raise VerifyError(Code.MALFORMED, "подпись повреждена: не хватает полей")

    # Поля вне подписанных атрибутов подписью не защищены, поэтому принимается один их вид:
    # иначе в подписи можно было бы менять байты, не нарушая её.
    if der.integer(fields[0]) != 1:
        raise _unsupported("версия подписанных данных")
    digests = der.expect(fields[1], der.SET, "хэш-функции").children()
    if len(digests) != 1:
        raise _unsupported("хэш-функция должна быть одна")
    _algorithm(digests[0], OID_SHA256, "хэш-функция")
    content_info = der.expect(fields[2], der.SEQUENCE, "сведения о содержимом").children()
    if not content_info or der.oid(content_info[0]) != OID_DATA:
        raise _unsupported("подписано не содержимое файла")
    if len(content_info) != 1:
        # Документ внутри подписи: проверялся бы он, а не файл, который дали проверить.
        raise _unsupported("подпись содержит документ внутри себя, нужна отсоединённая")

    rest = fields[3:]
    if not rest or rest[0].tag != TAG_CERTIFICATES:
        raise VerifyError(Code.UNKNOWN_SIGNER, "в подписи нет сертификата подписавшего")
    items = rest[0].children()
    if len(items) != 1:
        raise _unsupported("в подписи должен быть один сертификат — подписавшего")
    _strict_certificate(items[0])
    try:
        certificates = [x509.load_der_x509_certificate(items[0].raw)]
    except (ValueError, x509.InvalidVersion) as error:
        raise VerifyError(Code.MALFORMED, "подпись повреждена: сертификат не читается") from error
    rest = rest[1:]
    if rest and rest[0].tag == TAG_CRLS:
        # Списку отзыва из самой подписи верить нельзя: его приносит проверяющий.
        raise _unsupported("список отзыва внутри подписи не принимается")
    if len(rest) != 1:
        raise VerifyError(Code.MALFORMED, "подпись повреждена: нет сведений о подписавшем")
    signers = der.expect(rest[0], der.SET, "подписавшие").children()
    if len(signers) != 1:
        raise _unsupported("подписавший должен быть один")
    return certificates, signers[0]


def _signer_info(node: der.Node, certificates: list[x509.Certificate]) -> _Parsed:
    """Сведения о подписавшем: на какой сертификат указано, что подписано и чем."""
    info = der.expect(node, der.SEQUENCE, "подписавший").children()
    if len(info) != 6:
        raise _unsupported("нужны подписанные атрибуты и не допускаются неподписанные")
    if der.integer(info[0]) != 1:
        raise _unsupported("версия сведений о подписавшем")
    identifier = der.expect(info[1], der.SEQUENCE, "указание на сертификат").children()
    if len(identifier) != 2:
        raise VerifyError(Code.MALFORMED, "подпись повреждена: указание на сертификат")
    der.expect(identifier[0], der.SEQUENCE, "имя издателя")
    _algorithm(info[2], OID_SHA256, "хэш-функция")
    signed_attrs = der.expect(info[3], TAG_SIGNED_ATTRS, "подписанные атрибуты")
    _algorithm(info[4], OID_ECDSA_SHA256, "алгоритм подписи")
    value = der.expect(info[5], der.OCTET_STRING, "значение подписи").content

    attributes = _attributes(signed_attrs)
    for required in (OID_CONTENT_TYPE, OID_MESSAGE_DIGEST, OID_SIGNING_TIME):
        if required not in attributes:
            raise _unsupported("в подписи нет обязательного атрибута")
    if der.oid(attributes[OID_CONTENT_TYPE]) != OID_DATA:
        raise _unsupported("подписано не содержимое файла")
    return _Parsed(
        certificates=certificates,
        issuer=identifier[0].raw,
        serial=der.integer(identifier[1]),
        signed_attrs=signed_attrs,
        digest=der.expect(
            attributes[OID_MESSAGE_DIGEST], der.OCTET_STRING, "хэш документа"
        ).content,
        signing_time=der.time(attributes[OID_SIGNING_TIME]),
        signature=value,
    )


# --- Проверка ---------------------------------------------------------------------------------


def _signer_certificate(parsed: _Parsed) -> x509.Certificate:
    for certificate in parsed.certificates:
        if (
            certificate.serial_number == parsed.serial
            and certificate.issuer.public_bytes() == parsed.issuer
        ):
            return certificate
    raise VerifyError(Code.UNKNOWN_SIGNER, "в подписи нет сертификата подписавшего")


def _issuing_root(
    certificate: x509.Certificate, roots: Iterable[x509.Certificate]
) -> x509.Certificate:
    """Доверенный корневой сертификат, выпустивший сертификат подписавшего."""
    for root in roots:
        if not ca.is_root(root):
            continue
        try:
            # Сверяет имя издателя и подпись сертификата ключом издателя.
            certificate.verify_directly_issued_by(root)
        except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
            continue
        return root
    raise VerifyError(
        Code.UNTRUSTED,
        "сертификат подписавшего выпущен не тем центром, которому вы доверяете",
    )


def _within(certificate: x509.Certificate, moment: datetime) -> bool:
    return certificate.not_valid_before_utc <= moment <= certificate.not_valid_after_utc


def _check_crl(
    crl: x509.CertificateRevocationList,
    certificate: x509.Certificate,
    root: x509.Certificate,
    now: datetime,
) -> bool:
    """Отклонить отозванный сертификат; вернуть, свеж ли список отзыва."""
    public_key = root.public_key()
    if crl.issuer != root.subject or not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise VerifyError(Code.BAD_CRL, "список отзыва выпущен другим центром")
    if not crl.is_signature_valid(public_key):
        raise VerifyError(Code.BAD_CRL, "подпись списка отзыва не сходится")
    entry = crl.get_revoked_certificate_by_serial_number(certificate.serial_number)
    if entry is not None:
        # Отозванному ключу не верят и за прошлое: время подписи пишет сам подписавший,
        # и укравший ключ поставил бы любое.
        raise VerifyError(
            Code.REVOKED,
            f"сертификат подписавшего отозван {entry.revocation_date_utc:%d.%m.%Y}",
        )
    return crl.next_update_utc is None or crl.next_update_utc >= now


def verify(
    content: bytes,
    signature: bytes,
    roots: Iterable[x509.Certificate],
    *,
    crl: x509.CertificateRevocationList | None = None,
    now: datetime | None = None,
    require_fresh_crl: bool = False,
) -> Verified:
    """
    Проверить подпись документа; при любой неудаче — ``VerifyError`` с причиной.

    ``roots`` — корневые сертификаты, которым проверяющий доверяет: он получает их заранее
    и не из подписи. ``crl`` — список отзыва от того же центра; без него отзыв не проверяется,
    и итог это отмечает (``crl_checked``).
    """
    now = now or datetime.now(UTC)
    try:
        return _verify(content, signature, list(roots), crl=crl, now=now, fresh=require_fresh_crl)
    except VerifyError:
        raise
    except Exception as error:
        # Сертификат с испорченным расширением или ключом библиотека разбирает лениво
        # и отказывает уже при обращении к полю, причём ошибками разных видов. Проверка
        # на любую из них отвечает отказом, а не падением.
        raise VerifyError(Code.MALFORMED, "подпись повреждена: сертификат не читается") from error


def _verify(
    content: bytes,
    signature: bytes,
    roots: list[x509.Certificate],
    *,
    crl: x509.CertificateRevocationList | None,
    now: datetime,
    fresh: bool,
) -> Verified:
    parsed = _parse(signature)

    # Шаг 1. Документ тот самый: его хэш равен записанному в подписанных атрибутах.
    digest = hashlib.sha256(content).digest()
    if digest != parsed.digest:
        raise VerifyError(
            Code.DOCUMENT_CHANGED,
            "документ изменён после подписи или подпись сделана для другого файла",
        )

    # Шаг 2. Атрибуты подписал владелец сертификата. Подписывается их запись с тегом
    # набора (0x31), хотя в подписи она лежит под тегом [0] (RFC 5652, раздел 5.4).
    certificate = _signer_certificate(parsed)
    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise _unsupported("ключ подписавшего — не ECDSA P-256")
    signed = bytes([der.SET]) + parsed.signed_attrs.raw[1:]
    try:
        public_key.verify(parsed.signature, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as error:
        raise VerifyError(
            Code.BAD_SIGNATURE, "подпись не сходится с ключом из сертификата"
        ) from error

    # Шаг 3. Сертификату можно верить: его выпустил доверенный центр, он для подписи
    # документов, действовал в момент подписи и не отозван.
    root = _issuing_root(certificate, roots)
    if not ca.is_document_signer(certificate):
        raise VerifyError(
            Code.WRONG_PURPOSE, "сертификат подписавшего не предназначен для подписи документов"
        )
    if parsed.signing_time > now + CLOCK_SKEW:
        raise VerifyError(Code.FROM_FUTURE, "время подписи позже времени проверки")
    if not _within(certificate, parsed.signing_time) or not _within(root, parsed.signing_time):
        raise VerifyError(Code.NOT_VALID_THEN, "в момент подписи сертификат не действовал")
    crl_fresh = False
    if crl is not None:
        crl_fresh = _check_crl(crl, certificate, root, now)
        if fresh and not crl_fresh:
            raise VerifyError(Code.BAD_CRL, "список отзыва устарел: нужен свежий")

    organization = certificate.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    return Verified(
        signer=ca.common_name(certificate.subject),
        organization=str(organization[0].value) if organization else "",
        serial=ca.serial_text(certificate),
        signing_time=parsed.signing_time,
        digest=digest.hex(),
        certificate=certificate,
        root=root,
        crl_checked=crl is not None,
        crl_fresh=crl_fresh,
    )


def describe(signature: bytes) -> dict[str, str]:
    """
    Что написано в подписи — без проверки: кто назван подписавшим и когда.

    Этим сведениям нельзя верить, пока подпись не проверена: их пишет тот, кто её создал.
    """
    parsed = _parse(signature)
    certificate = _signer_certificate(parsed)
    return {
        "signer": ca.common_name(certificate.subject),
        "issuer": ca.common_name(certificate.issuer),
        "serial": ca.serial_text(certificate),
        "signing_time": parsed.signing_time.isoformat(),
        "digest": parsed.digest.hex(),
    }
