"""
Журнал с подписанной вершиной: неизменность перечня записей.

Запись журнала — строка (например, строка описи архива: хэш файла, размер, откуда получен).
Над записями строится дерево хэшей, а его вершина вместе с числом записей и временем
подписывается — это «вершина журнала». Подписанная вершина закрывает то, чего не закрывает
простой перечень хэшей: подменивший файл поправит и строку описи, но подписать новую вершину
ему нечем.

Тот, кто сохранил прежнюю вершину (копия, распечатка, публикация), замечает и откат:
новый журнал обязан продолжать прежний, не меняя его записей.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509

from . import ca, cms, merkle
from .errors import Code, ProvenanceError, VerifyError


@dataclass(frozen=True, slots=True)
class Head:
    """Вершина журнала: имя, число записей, вершина дерева и время подписи."""

    name: str
    size: int
    root: str
    time: str

    def to_bytes(self) -> bytes:
        """
        Запись вершины для подписи: поля по алфавиту, без лишних пробелов.

        Подписываются байты, поэтому запись должна получаться одной и той же при любом
        порядке полей в памяти.
        """
        text = json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return text.encode("utf-8") + b"\n"

    @classmethod
    def from_bytes(cls, data: bytes) -> Head:
        """Прочитать вершину; чужой или испорченный файл — ошибка."""
        try:
            raw: dict[str, Any] = json.loads(data)
            head = cls(
                name=str(raw["name"]),
                size=int(raw["size"]),
                root=str(raw["root"]),
                time=str(raw["time"]),
            )
            bytes.fromhex(head.root)
        except (ValueError, KeyError, TypeError) as error:
            raise VerifyError(Code.MALFORMED, "вершина журнала не читается") from error
        if head.size < 0 or len(head.root) != 64:
            raise VerifyError(Code.MALFORMED, "вершина журнала не читается")
        return head


@dataclass(frozen=True, slots=True)
class Checked:
    """Итог проверки журнала: вершина, кто её подписал и сколько записей после неё."""

    head: Head
    signature: cms.Verified
    unsealed: int


def split_records(data: bytes) -> list[bytes]:
    """Записи журнала из файла: по строке на запись, перевод строки в запись не входит."""
    lines = data.replace(b"\r\n", b"\n").split(b"\n")
    if lines and not lines[-1]:
        lines.pop()
    return lines


def _leaves(records: Iterable[bytes]) -> list[bytes]:
    return [merkle.leaf_hash(record) for record in records]


def make_head(name: str, records: Sequence[bytes], now: datetime | None = None) -> Head:
    """Вершина над записями журнала."""
    moment = (now or datetime.now(UTC)).replace(microsecond=0)
    return Head(
        name=name,
        size=len(records),
        root=merkle.root(_leaves(records)).hex(),
        time=moment.isoformat(),
    )


def seal(
    name: str, records: Sequence[bytes], signer: ca.Identity, now: datetime | None = None
) -> tuple[bytes, bytes]:
    """Подписать журнал: вернуть запись вершины и подпись к ней."""
    head = make_head(name, records, now).to_bytes()
    return head, cms.sign(head, signer)


def check(
    records: Sequence[bytes],
    head_bytes: bytes,
    signature: bytes,
    roots: Iterable[x509.Certificate],
    *,
    crl: x509.CertificateRevocationList | None = None,
    now: datetime | None = None,
) -> Checked:
    """
    Проверить журнал: вершина подписана доверенным ключом, записи сходятся с вершиной.

    Записи после подписанной вершины (``unsealed``) подписью не покрыты: решать, допустимы ли
    они, — тому, кто проверяет.
    """
    verified = cms.verify(head_bytes, signature, roots, crl=crl, now=now)
    head = Head.from_bytes(head_bytes)
    if len(records) < head.size:
        raise VerifyError(
            Code.LOG_MISMATCH,
            f"в журнале {len(records)} записей, а подписано {head.size}: записи убраны",
        )
    if merkle.root(_leaves(records[: head.size])).hex() != head.root:
        raise VerifyError(
            Code.LOG_MISMATCH, "записи журнала не сходятся с подписанной вершиной: журнал изменён"
        )
    return Checked(head=head, signature=verified, unsealed=len(records) - head.size)


def extends(old: Head, records: Sequence[bytes]) -> None:
    """Убедиться, что журнал продолжает прежнюю вершину; иначе — ``LOG_REWRITTEN``."""
    if len(records) < old.size or merkle.root(_leaves(records[: old.size])).hex() != old.root:
        raise VerifyError(
            Code.LOG_REWRITTEN,
            f"журнал не продолжает вершину от {old.time} ({old.size} записей): "
            "прежние записи изменены или убраны",
        )


# --- Доказательства для того, у кого нет всего журнала ----------------------------------------


def prove_inclusion(index: int, records: Sequence[bytes]) -> dict[str, Any]:
    """Доказательство, что запись ``index`` входит в журнал: её место и хэши соседей."""
    leaves = _leaves(records)
    try:
        path = merkle.inclusion_proof(index, leaves)
    except IndexError as error:
        raise ProvenanceError(str(error)) from error
    return {
        "index": index,
        "size": len(leaves),
        "record": records[index].decode("utf-8", errors="replace"),
        "path": [item.hex() for item in path],
    }


def check_inclusion(record: bytes, proof: dict[str, Any], head: Head) -> bool:
    """Запись входит в журнал с этой вершиной."""
    try:
        path = [bytes.fromhex(item) for item in proof["path"]]
        index, size = int(proof["index"]), int(proof["size"])
    except (KeyError, ValueError, TypeError):
        return False
    if size != head.size:
        return False
    return merkle.verify_inclusion(
        merkle.leaf_hash(record), index, size, path, bytes.fromhex(head.root)
    )


def prove_consistency(old_size: int, records: Sequence[bytes]) -> list[str]:
    """Доказательство, что журнал продолжает свой прежний вид из ``old_size`` записей."""
    try:
        return [item.hex() for item in merkle.consistency_proof(old_size, _leaves(records))]
    except IndexError as error:
        raise ProvenanceError(str(error)) from error


def check_consistency(old: Head, new: Head, proof: Sequence[str]) -> bool:
    """Новая вершина продолжает прежнюю; проверяется по одним вершинам, без записей."""
    try:
        path = [bytes.fromhex(item) for item in proof]
    except ValueError:
        return False
    return merkle.verify_consistency(
        old.size, new.size, bytes.fromhex(old.root), bytes.fromhex(new.root), path
    )


# --- Журнал в файле ---------------------------------------------------------------------------
#
# Рядом с файлом журнала лежат три файла: вершина, подпись к ней и история прежних вершин.
# История нужна для проверки, что журнал только пополнялся; сохранённая вне сервера, она
# ловит и откат к прежнему состоянию.

HEAD_SUFFIX = ".head.json"
SIGNATURE_SUFFIX = ".head.p7s"
HISTORY_SUFFIX = ".heads.jsonl"


def paths(journal: Path) -> tuple[Path, Path, Path]:
    """Файлы вершины, подписи и истории вершин для журнала."""
    return (
        journal.with_name(journal.name + HEAD_SUFFIX),
        journal.with_name(journal.name + SIGNATURE_SUFFIX),
        journal.with_name(journal.name + HISTORY_SUFFIX),
    )


def history(journal: Path) -> list[Head]:
    """Прежние вершины журнала по порядку."""
    _head, _signature, history_path = paths(journal)
    if not history_path.exists():
        return []
    return [
        Head.from_bytes(line) for line in history_path.read_bytes().split(b"\n") if line.strip()
    ]


def seal_file(
    journal: Path, signer: ca.Identity, name: str = "", now: datetime | None = None
) -> Head:
    """
    Подписать журнал в файле. Отказ, если журнал не продолжает прежнюю вершину: подписывать
    переписанную историю нельзя.
    """
    records = split_records(journal.read_bytes())
    head_path, signature_path, history_path = paths(journal)
    previous = history(journal)
    if previous:
        extends(previous[-1], records)
    head_bytes, signature = seal(name or journal.name, records, signer, now)
    head = Head.from_bytes(head_bytes)
    if previous and previous[-1].root == head.root and previous[-1].size == head.size:
        # Записей не прибавилось: история не растёт, подпись обновляется.
        head_bytes = previous[-1].to_bytes()
        signature = cms.sign(head_bytes, signer)
        head = previous[-1]
    else:
        with history_path.open("ab") as output:
            output.write(head_bytes)
    head_path.write_bytes(head_bytes)
    signature_path.write_bytes(signature)
    return head


def check_file(
    journal: Path,
    roots: Iterable[x509.Certificate],
    *,
    crl: x509.CertificateRevocationList | None = None,
    now: datetime | None = None,
) -> Checked:
    """Проверить журнал в файле: подпись вершины, записи и все прежние вершины."""
    head_path, signature_path, _history_path = paths(journal)
    if not head_path.exists() or not signature_path.exists():
        raise VerifyError(Code.LOG_MISMATCH, "у журнала нет подписанной вершины")
    records = split_records(journal.read_bytes())
    checked = check(
        records, head_path.read_bytes(), signature_path.read_bytes(), roots, crl=crl, now=now
    )
    for old in history(journal):
        extends(old, records)
    return checked
