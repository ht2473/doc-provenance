"""
Чтение DER — ровно столько, сколько нужно для разбора подписи CMS.

Разбор строгий: длина только определённая и в кратчайшей записи, хвост после значения —
ошибка. Подпись проверяется над байтами в том виде, в каком они записаны, поэтому узел
помнит своё место в исходных данных и отдаёт запись целиком (``raw``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .errors import Code, VerifyError

SEQUENCE = 0x30
SET = 0x31
INTEGER = 0x02
OCTET_STRING = 0x04
OID = 0x06
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18
# Признак составного значения в первом октете.
CONSTRUCTED = 0x20
# Глубже подпись CMS не бывает; предел защищает от вложенности, растущей без конца.
MAX_DEPTH = 16


def _fail(reason: str) -> VerifyError:
    return VerifyError(Code.MALFORMED, f"подпись повреждена: {reason}")


@dataclass(frozen=True, slots=True)
class Node:
    """Значение DER: тег, место заголовка и содержимого в исходных данных."""

    data: bytes
    tag: int
    start: int
    body: int
    end: int

    @property
    def raw(self) -> bytes:
        """Запись целиком: тег, длина, содержимое."""
        return self.data[self.start : self.end]

    @property
    def content(self) -> bytes:
        """Содержимое без тега и длины."""
        return self.data[self.body : self.end]

    def children(self, depth: int = 0) -> list[Node]:
        """Вложенные значения составного узла."""
        if not self.tag & CONSTRUCTED:
            raise _fail("ожидалось составное значение")
        if depth > MAX_DEPTH:
            raise _fail("слишком глубокая вложенность")
        found = []
        offset = self.body
        while offset < self.end:
            child = read(self.data, offset, self.end)
            found.append(child)
            offset = child.end
        return found


def read(data: bytes, offset: int = 0, limit: int | None = None) -> Node:
    """Прочитать одно значение, начиная с ``offset``; оно должно уместиться до ``limit``."""
    limit = len(data) if limit is None else limit
    if offset + 2 > limit:
        raise _fail("значение обрывается")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise _fail("теги с длинным номером не используются")
    first = data[offset + 1]
    body = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise _fail("недопустимая запись длины")
        if body + count > limit:
            raise _fail("значение обрывается")
        length = int.from_bytes(data[body : body + count], "big")
        # DER требует кратчайшей записи: иначе у одних и тех же данных было бы много записей.
        if length < 0x80 or data[body] == 0:
            raise _fail("длина записана не кратчайшим способом")
        body += count
    end = body + length
    if end > limit:
        raise _fail("значение длиннее данных")
    return Node(data=data, tag=tag, start=offset, body=body, end=end)


def parse(data: bytes) -> Node:
    """Разобрать данные как одно значение без хвоста."""
    node = read(data)
    if node.end != len(data):
        raise _fail("после значения есть лишние данные")
    return node


def expect(node: Node, tag: int, what: str) -> Node:
    """Узел с ожидаемым тегом."""
    if node.tag != tag:
        raise _fail(f"{what}: тег {node.tag:#04x} вместо {tag:#04x}")
    return node


def oid(node: Node) -> str:
    """Идентификатор объекта в записи через точку."""
    content = expect(node, OID, "идентификатор").content
    if not content or content[-1] & 0x80:
        raise _fail("идентификатор обрывается")
    parts: list[int] = []
    value = 0
    opening = True
    for octet in content:
        # Часть идентификатора не начинается с пустой семёрки бит: это не кратчайшая запись.
        if opening and octet == 0x80:
            raise _fail("идентификатор записан не кратчайшим способом")
        value = (value << 7) | (octet & 0x7F)
        opening = not octet & 0x80
        if opening:
            parts.append(value)
            value = 0
    first = parts[0]
    head = (2, first - 80) if first >= 80 else divmod(first, 40)
    return ".".join(str(part) for part in (*head, *parts[1:]))


def integer(node: Node) -> int:
    """Целое число."""
    content = expect(node, INTEGER, "целое").content
    if not content:
        raise _fail("пустое целое")
    return int.from_bytes(content, "big", signed=True)


def time(node: Node) -> datetime:
    """Время UTCTime или GeneralizedTime; только в UTC и с секундами, как требует DER."""
    text = node.content.decode("ascii", errors="replace")
    try:
        if node.tag == UTC_TIME:
            moment = datetime.strptime(text, "%y%m%d%H%M%SZ")
            # RFC 5280: двузначный год до 50 — это 20xx, от 50 — 19xx.
            year = moment.year if moment.year < 2050 else moment.year - 100
            moment = moment.replace(year=year)
        elif node.tag == GENERALIZED_TIME:
            moment = datetime.strptime(text, "%Y%m%d%H%M%SZ")
        else:
            raise _fail("ожидалось время")
    except ValueError as error:
        raise _fail("время записано не по правилам DER") from error
    return moment.replace(tzinfo=UTC)
