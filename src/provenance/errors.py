"""Причины отказа проверки: код для программы и объяснение для человека."""

from __future__ import annotations

from enum import StrEnum


class Code(StrEnum):
    """Почему проверка не прошла. Код устойчив: по нему вызывающая программа выбирает свой текст."""

    MALFORMED = "malformed"
    """Подпись, сертификат или журнал не разбираются."""

    UNSUPPORTED = "unsupported"
    """Разобрано, но вид подписи или алгоритм не из принятого набора."""

    DOCUMENT_CHANGED = "document_changed"
    """Хэш документа не совпадает с подписанным: документ изменён или подпись от другого файла."""

    BAD_SIGNATURE = "bad_signature"
    """Подпись не сходится с открытым ключом подписавшего."""

    UNKNOWN_SIGNER = "unknown_signer"
    """В подписи нет сертификата подписавшего."""

    UNTRUSTED = "untrusted"
    """Сертификат подписавшего выпущен не доверенным центром."""

    WRONG_PURPOSE = "wrong_purpose"
    """Сертификат не предназначен для подписи документов (или это сертификат центра)."""

    NOT_VALID_THEN = "not_valid_then"
    """В момент подписи сертификат ещё или уже не действовал."""

    FROM_FUTURE = "from_future"
    """Время подписи позже времени проверки."""

    REVOKED = "revoked"
    """Сертификат подписавшего отозван."""

    BAD_CRL = "bad_crl"
    """Список отзыва не подписан центром, выпустившим сертификат, или устарел."""

    LOG_MISMATCH = "log_mismatch"
    """Записи журнала не сходятся с подписанной вершиной дерева."""

    LOG_REWRITTEN = "log_rewritten"
    """Журнал не продолжает прежнюю подписанную вершину: записи изменены или убраны."""


class ProvenanceError(Exception):
    """Общая ошибка библиотеки: неверные входные данные, отсутствующие файлы."""


class VerifyError(ProvenanceError):
    """Проверка не прошла; ``code`` — причина."""

    def __init__(self, code: Code, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
