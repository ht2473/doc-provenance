"""Журнал с подписанной вершиной: подмена, удаление, откат, доказательства."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from provenance import ca, log
from provenance.errors import Code, VerifyError


def manifest(count: int) -> list[bytes]:
    """Строки описи архива: хэш файла, размер, имя."""
    rows = []
    for index in range(count):
        body = f"выпуск {index}".encode()
        rows.append(
            f"{hashlib.sha256(body).hexdigest()},{len(body)},rosstat,file{index}.xlsx".encode()
        )
    return rows


def write(path: Path, rows: list[bytes]) -> None:
    path.write_bytes(b"\n".join(rows) + b"\n")


def refusal(action, *arguments, **options) -> Code:
    with pytest.raises(VerifyError) as caught:
        action(*arguments, **options)
    return caught.value.code


def test_sealed_log_is_verified(root: ca.Identity, signer: ca.Identity) -> None:
    rows = manifest(9)
    head, signature = log.seal("архив", rows, signer)
    checked = log.check(rows, head, signature, [root.certificate])
    assert checked.head.size == 9
    assert checked.unsealed == 0
    assert checked.signature.signer == "Служба подписи"


def test_head_bytes_do_not_depend_on_field_order() -> None:
    """Подписываются байты вершины: запись должна быть одной при любом порядке полей."""
    head = log.Head(name="архив", size=3, root="ab" * 32, time="2026-11-10T00:00:00+00:00")
    again = log.Head(time=head.time, root=head.root, size=3, name="архив")
    assert head.to_bytes() == again.to_bytes()
    assert log.Head.from_bytes(head.to_bytes()) == head


@pytest.mark.parametrize("position", [0, 4, 8])
def test_changed_record_is_refused(root: ca.Identity, signer: ca.Identity, position: int) -> None:
    """Подмена строки описи (файл и его хэш вместе) — отказ: вершина уже другая."""
    rows = manifest(9)
    head, signature = log.seal("архив", rows, signer)
    forged = list(rows)
    forged[position] = rows[position].replace(b"rosstat", b"forgery")
    assert refusal(log.check, forged, head, signature, [root.certificate]) is Code.LOG_MISMATCH


def test_swapped_and_removed_records_are_refused(root: ca.Identity, signer: ca.Identity) -> None:
    rows = manifest(6)
    head, signature = log.seal("архив", rows, signer)
    swapped = [rows[1], rows[0], *rows[2:]]
    assert refusal(log.check, swapped, head, signature, [root.certificate]) is Code.LOG_MISMATCH
    assert refusal(log.check, rows[:-1], head, signature, [root.certificate]) is Code.LOG_MISMATCH
    assert refusal(log.check, rows[1:], head, signature, [root.certificate]) is Code.LOG_MISMATCH


def test_forged_head_is_refused(
    root: ca.Identity, signer: ca.Identity, stranger: ca.Identity
) -> None:
    """Подменивший записи пересчитает вершину, но подписать её ему нечем."""
    rows = manifest(5)
    _head, signature = log.seal("архив", rows, signer)
    forged = [*rows[:-1], b"forged row"]
    own_head = log.make_head("архив", forged).to_bytes()
    assert (
        refusal(log.check, forged, own_head, signature, [root.certificate]) is Code.DOCUMENT_CHANGED
    )
    resealed_head, resealed_signature = log.seal("архив", forged, stranger)
    assert (
        refusal(log.check, forged, resealed_head, resealed_signature, [root.certificate])
        is Code.UNTRUSTED
    )


def test_records_after_the_head_are_reported(root: ca.Identity, signer: ca.Identity) -> None:
    """Записи, добавленные после подписи, вершиной не покрыты — и это видно."""
    rows = manifest(4)
    head, signature = log.seal("архив", rows, signer)
    checked = log.check([*rows, b"appended later"], head, signature, [root.certificate])
    assert checked.unsealed == 1


def test_old_head_catches_rewritten_history(signer: ca.Identity) -> None:
    """Сохранённая прежняя вершина ловит журнал, в котором прежние записи изменены."""
    rows = manifest(7)
    old = log.make_head("архив", rows[:4])
    log.extends(old, rows)
    rewritten = [b"rewritten", *rows[1:]]
    assert refusal(log.extends, old, rewritten) is Code.LOG_REWRITTEN
    assert refusal(log.extends, old, rows[:3]) is Code.LOG_REWRITTEN


def test_inclusion_proof_needs_only_the_head() -> None:
    """Запись доказывается одной вершиной и коротким путём — без остального журнала."""
    rows = manifest(20)
    head = log.make_head("архив", rows)
    proof = log.prove_inclusion(13, rows)
    assert len(proof["path"]) == 5
    assert log.check_inclusion(rows[13], proof, head)
    assert not log.check_inclusion(rows[12], proof, head)
    assert not log.check_inclusion(rows[13], {**proof, "index": 12}, head)
    assert not log.check_inclusion(rows[13], proof, log.make_head("архив", rows[:19]))
    assert not log.check_inclusion(rows[13], {"path": ["zz"]}, head)


def test_consistency_proof_needs_only_two_heads() -> None:
    """Продолжение журнала доказывается по двум вершинам — без записей."""
    rows = manifest(20)
    old, new = log.make_head("архив", rows[:7]), log.make_head("архив", rows)
    proof = log.prove_consistency(7, rows)
    assert log.check_consistency(old, new, proof)
    rewritten = [b"rewritten", *rows[1:]]
    forged = log.make_head("архив", rewritten)
    assert not log.check_consistency(old, forged, log.prove_consistency(7, rewritten))


class TestFiles:
    """Журнал в файле: вершина, подпись и история рядом с ним."""

    def test_seal_append_seal(self, tmp_path: Path, root: ca.Identity, signer: ca.Identity) -> None:
        journal = tmp_path / "MANIFEST.csv"
        rows = manifest(5)
        write(journal, rows[:3])
        assert log.seal_file(journal, signer).size == 3
        write(journal, rows)
        assert log.seal_file(journal, signer).size == 5
        checked = log.check_file(journal, [root.certificate])
        assert checked.head.size == 5
        assert [head.size for head in log.history(journal)] == [3, 5]

    def test_resealing_unchanged_log_keeps_history(
        self, tmp_path: Path, root: ca.Identity, signer: ca.Identity
    ) -> None:
        journal = tmp_path / "MANIFEST.csv"
        write(journal, manifest(3))
        log.seal_file(journal, signer)
        log.seal_file(journal, signer)
        assert len(log.history(journal)) == 1
        assert log.check_file(journal, [root.certificate]).head.size == 3

    def test_rewritten_log_is_not_sealed(self, tmp_path: Path, signer: ca.Identity) -> None:
        """Журнал с изменённой прежней записью заново не подписывается."""
        journal = tmp_path / "MANIFEST.csv"
        rows = manifest(4)
        write(journal, rows)
        log.seal_file(journal, signer)
        write(journal, [b"rewritten", *rows[1:], b"new"])
        assert refusal(log.seal_file, journal, signer) is Code.LOG_REWRITTEN

    def test_rollback_is_caught_by_history(
        self, tmp_path: Path, root: ca.Identity, signer: ca.Identity
    ) -> None:
        """Откат к прежнему состоянию с его же верной подписью выдаёт история вершин."""
        journal = tmp_path / "MANIFEST.csv"
        head_path, signature_path, _history = log.paths(journal)
        rows = manifest(6)
        write(journal, rows[:4])
        log.seal_file(journal, signer)
        old_head, old_signature = head_path.read_bytes(), signature_path.read_bytes()
        write(journal, rows)
        log.seal_file(journal, signer)

        write(journal, rows[:4])
        head_path.write_bytes(old_head)
        signature_path.write_bytes(old_signature)
        assert refusal(log.check_file, journal, [root.certificate]) is Code.LOG_REWRITTEN

    def test_log_without_head_is_refused(self, tmp_path: Path, root: ca.Identity) -> None:
        journal = tmp_path / "MANIFEST.csv"
        write(journal, manifest(2))
        assert refusal(log.check_file, journal, [root.certificate]) is Code.LOG_MISMATCH

    def test_line_endings_do_not_change_records(self) -> None:
        assert log.split_records(b"a\r\nb\r\n") == log.split_records(b"a\nb\n") == [b"a", b"b"]
        assert log.split_records(b"") == []
