"""
Командная строка: удостоверяющий центр, подпись и проверка документов, журнал.

Проверка (``provenance verify``) ничего не знает о службе, выдавшей документ: ей нужны только
файл, подпись и корневой сертификат, полученный заранее.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__, ca, cms, log
from .errors import ProvenanceError, VerifyError

ROOT_KEY = "root.key"
ROOT_CERTIFICATE = "root.crt"
REVOKED = "revoked.json"
CRL = "crl.pem"
SIGNER_KEY = "signer.key"
SIGNER_CERTIFICATE = "signer.crt"
SIGNATURE_SUFFIX = ".p7s"
# Пароль корневого ключа берётся из окружения: в истории команд он не остаётся.
PASSPHRASE_VARIABLE = "PROVENANCE_PASSPHRASE"  # noqa: S105 — имя переменной, не пароль


def _say(text: str) -> None:
    sys.stdout.write(text + "\n")


def _passphrase() -> str:
    return os.environ.get(PASSPHRASE_VARIABLE, "")


def _root(directory: Path) -> ca.Identity:
    key_path, certificate_path = directory / ROOT_KEY, directory / ROOT_CERTIFICATE
    if not key_path.exists() or not certificate_path.exists():
        raise ProvenanceError(f"в {directory} нет удостоверяющего центра (ca init)")
    return ca.Identity(ca.load_key(key_path, _passphrase()), ca.load_certificate(certificate_path))


def _signer(arguments: argparse.Namespace) -> ca.Identity:
    return ca.Identity(ca.load_key(arguments.key), ca.load_certificate(arguments.cert))


def _revoked(directory: Path) -> dict[str, Any]:
    path = directory / REVOKED
    if not path.exists():
        return {"number": 0, "revoked": []}
    return dict(json.loads(path.read_text(encoding="utf-8")))


def _write_crl(directory: Path, root: ca.Identity, state: dict[str, Any]) -> None:
    state["number"] = int(state["number"]) + 1
    entries = [
        (int(item["serial"], 16), datetime.fromisoformat(item["date"])) for item in state["revoked"]
    ]
    ca.save_crl(ca.make_crl(root, entries, number=state["number"]), directory / CRL)
    (directory / REVOKED).write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


# --- Удостоверяющий центр ---------------------------------------------------------------------


def ca_init(arguments: argparse.Namespace) -> int:
    """Создать корневой ключ и сертификат и первый, пустой список отзыва."""
    directory: Path = arguments.directory
    if (directory / ROOT_KEY).exists():
        raise ProvenanceError(f"в {directory} уже есть удостоверяющий центр")
    directory.mkdir(parents=True, exist_ok=True)
    root = ca.new_root(arguments.name, arguments.org, years=arguments.years)
    ca.save_key(root.key, directory / ROOT_KEY, _passphrase())
    ca.save_certificate(root.certificate, directory / ROOT_CERTIFICATE)
    _write_crl(directory, root, _revoked(directory))
    _say(f"Корневой сертификат: {directory / ROOT_CERTIFICATE}")
    _say(f"Отпечаток SHA-256:   {ca.fingerprint(root.certificate)}")
    _say(f"Закрытый ключ:       {directory / ROOT_KEY} — хранить отдельно от службы подписи")
    if not _passphrase():
        _say(f"Ключ не зашифрован: пароль задаётся переменной {PASSPHRASE_VARIABLE}")
    return 0


def ca_issue(arguments: argparse.Namespace) -> int:
    """Выпустить сертификат подписи документов."""
    root = _root(arguments.directory)
    signer = ca.issue_signer(root, arguments.name, arguments.org, days=arguments.days)
    out: Path = arguments.out
    out.mkdir(parents=True, exist_ok=True)
    ca.save_key(signer.key, out / SIGNER_KEY)
    ca.save_certificate(signer.certificate, out / SIGNER_CERTIFICATE)
    _say(f"Сертификат подписи: {out / SIGNER_CERTIFICATE}")
    _say(f"Номер:              {ca.serial_text(signer.certificate)}")
    _say(f"Действует до:       {signer.certificate.not_valid_after_utc:%d.%m.%Y}")
    return 0


def ca_revoke(arguments: argparse.Namespace) -> int:
    """Отозвать сертификат и выпустить новый список отзыва."""
    root = _root(arguments.directory)
    certificate = ca.load_certificate(arguments.certificate)
    state = _revoked(arguments.directory)
    serial = ca.serial_text(certificate)
    if all(item["serial"] != serial for item in state["revoked"]):
        moment = datetime.now(UTC).replace(microsecond=0).isoformat()
        state["revoked"].append({"serial": serial, "date": moment})
    _write_crl(arguments.directory, root, state)
    _say(f"Сертификат {serial} отозван; список отзыва: {arguments.directory / CRL}")
    return 0


def ca_crl(arguments: argparse.Namespace) -> int:
    """Выпустить свежий список отзыва: у него есть срок."""
    root = _root(arguments.directory)
    state = _revoked(arguments.directory)
    _write_crl(arguments.directory, root, state)
    _say(f"Список отзыва № {state['number']}: {arguments.directory / CRL}")
    return 0


# --- Документы --------------------------------------------------------------------------------


def sign(arguments: argparse.Namespace) -> int:
    """Подписать файл."""
    target: Path = arguments.out or arguments.file.with_name(arguments.file.name + SIGNATURE_SUFFIX)
    target.write_bytes(cms.sign(arguments.file.read_bytes(), _signer(arguments)))
    _say(f"Подпись: {target}")
    return 0


def _trust(arguments: argparse.Namespace) -> tuple[list[Any], Any]:
    roots = [ca.load_certificate(path) for path in arguments.root]
    crl = ca.load_crl(arguments.crl) if arguments.crl else None
    return roots, crl


def _report(verified: cms.Verified) -> None:
    who = verified.signer + (f", {verified.organization}" if verified.organization else "")
    _say(f"  подписал:      {who}")
    _say(f"  сертификат №:  {verified.serial}")
    _say(f"  время подписи: {verified.signing_time:%d.%m.%Y %H:%M:%S} UTC")
    _say(f"  корень:        {verified.root_fingerprint}")
    if not verified.crl_checked:
        _say("  отзыв не проверялся: список отзыва не дан (--crl)")
    elif not verified.crl_fresh:
        _say("  список отзыва устарел: возьмите свежий у владельца центра")


def verify(arguments: argparse.Namespace) -> int:
    """Проверить подпись файла."""
    signature: Path = arguments.signature or arguments.file.with_name(
        arguments.file.name + SIGNATURE_SUFFIX
    )
    roots, crl = _trust(arguments)
    try:
        verified = cms.verify(
            arguments.file.read_bytes(),
            signature.read_bytes(),
            roots,
            crl=crl,
            require_fresh_crl=arguments.fresh_crl,
        )
    except VerifyError as error:
        _say(f"НЕ ПОДТВЕРЖДЕНО: {error.message} [{error.code}]")
        return 1
    _say(f"ПОДЛИННЫЙ: {arguments.file.name}")
    _say(f"  SHA-256:       {verified.digest}")
    _report(verified)
    return 0


def show(arguments: argparse.Namespace) -> int:
    """Показать, что написано в подписи, ничего не проверяя."""
    for key, value in cms.describe(arguments.signature.read_bytes()).items():
        _say(f"{key}: {value}")
    _say("Это написано в подписи и не проверено: проверяет команда verify.")
    return 0


# --- Журнал -----------------------------------------------------------------------------------


def log_seal(arguments: argparse.Namespace) -> int:
    """Подписать вершину журнала."""
    try:
        head = log.seal_file(arguments.journal, _signer(arguments), arguments.name)
    except VerifyError as error:
        _say(f"НЕ ПОДПИСАНО: {error.message} [{error.code}]")
        return 1
    _say(f"Журнал подписан: записей {head.size}, вершина {head.root}")
    return 0


def log_verify(arguments: argparse.Namespace) -> int:
    """Проверить журнал."""
    roots, crl = _trust(arguments)
    try:
        checked = log.check_file(arguments.journal, roots, crl=crl)
    except VerifyError as error:
        _say(f"НЕ ПОДТВЕРЖДЕНО: {error.message} [{error.code}]")
        return 1
    _say(f"ЖУРНАЛ ЦЕЛ: записей {checked.head.size}, вершина {checked.head.root}")
    _report(checked.signature)
    if checked.unsealed:
        _say(f"  после подписанной вершины есть ещё записи: {checked.unsealed} — они не подписаны")
        return 1
    return 0


def log_prove(arguments: argparse.Namespace) -> int:
    """Выдать доказательство, что запись входит в журнал."""
    records = log.split_records(arguments.journal.read_bytes())
    proof = log.prove_inclusion(arguments.index, records)
    text = json.dumps(proof, ensure_ascii=False, indent=2) + "\n"
    if arguments.out:
        arguments.out.write_text(text, encoding="utf-8")
        _say(f"Доказательство: {arguments.out} (хэшей в пути: {len(proof['path'])})")
    else:
        _say(text.rstrip())
    return 0


def log_check_proof(arguments: argparse.Namespace) -> int:
    """Проверить доказательство включения по одной вершине — без самого журнала."""
    proof = json.loads(arguments.proof.read_text(encoding="utf-8"))
    head = log.Head.from_bytes(arguments.head.read_bytes())
    if log.check_inclusion(str(proof.get("record", "")).encode("utf-8"), proof, head):
        _say(f"ЗАПИСЬ В ЖУРНАЛЕ: № {proof['index']} из {head.size}")
        return 0
    _say("НЕ ПОДТВЕРЖДЕНО: запись не входит в журнал с этой вершиной")
    return 1


# --- Разбор командной строки ------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provenance",
        description="Подпись документов и журнал с подписанной вершиной",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    authority = commands.add_parser("ca", help="удостоверяющий центр").add_subparsers(
        dest="action", required=True
    )
    init = authority.add_parser("init", help="создать корневой ключ и сертификат")
    init.add_argument("directory", type=Path)
    init.add_argument("--name", required=True, help="имя центра в сертификате")
    init.add_argument("--org", default="", help="организация")
    init.add_argument("--years", type=int, default=ca.ROOT_YEARS)
    init.set_defaults(run=ca_init)

    issue = authority.add_parser("issue", help="выпустить сертификат подписи документов")
    issue.add_argument("directory", type=Path)
    issue.add_argument("--name", required=True, help="имя службы в сертификате")
    issue.add_argument("--org", default="", help="организация")
    issue.add_argument("--days", type=int, default=ca.SIGNER_DAYS)
    issue.add_argument("--out", type=Path, required=True, help="куда положить ключ и сертификат")
    issue.set_defaults(run=ca_issue)

    revoke = authority.add_parser("revoke", help="отозвать сертификат")
    revoke.add_argument("directory", type=Path)
    revoke.add_argument("certificate", type=Path)
    revoke.set_defaults(run=ca_revoke)

    crl = authority.add_parser("crl", help="выпустить свежий список отзыва")
    crl.add_argument("directory", type=Path)
    crl.set_defaults(run=ca_crl)

    def signer_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--key", type=Path, required=True, help="закрытый ключ подписи")
        command.add_argument("--cert", type=Path, required=True, help="сертификат подписи")

    def trust_options(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--root",
            type=Path,
            required=True,
            action="append",
            help="доверенный корневой сертификат",
        )
        command.add_argument("--crl", type=Path, help="список отзыва")

    signing = commands.add_parser("sign", help="подписать файл")
    signing.add_argument("file", type=Path)
    signer_options(signing)
    signing.add_argument("--out", type=Path, help="файл подписи (по умолчанию ФАЙЛ.p7s)")
    signing.set_defaults(run=sign)

    checking = commands.add_parser("verify", help="проверить подпись файла")
    checking.add_argument("file", type=Path)
    checking.add_argument("--signature", type=Path, help="файл подписи (по умолчанию ФАЙЛ.p7s)")
    trust_options(checking)
    checking.add_argument("--fresh-crl", action="store_true", help="отказ при устаревшем списке")
    checking.set_defaults(run=verify)

    showing = commands.add_parser("show", help="что написано в подписи (без проверки)")
    showing.add_argument("signature", type=Path)
    showing.set_defaults(run=show)

    journal = commands.add_parser("log", help="журнал с подписанной вершиной").add_subparsers(
        dest="action", required=True
    )
    seal = journal.add_parser("seal", help="подписать вершину журнала")
    seal.add_argument("journal", type=Path)
    signer_options(seal)
    seal.add_argument("--name", default="", help="имя журнала в вершине")
    seal.set_defaults(run=log_seal)

    check = journal.add_parser("verify", help="проверить журнал")
    check.add_argument("journal", type=Path)
    trust_options(check)
    check.set_defaults(run=log_verify)

    prove = journal.add_parser("prove", help="доказательство, что запись входит в журнал")
    prove.add_argument("journal", type=Path)
    prove.add_argument("index", type=int, help="номер записи с нуля")
    prove.add_argument("--out", type=Path)
    prove.set_defaults(run=log_prove)

    proof = journal.add_parser("check-proof", help="проверить доказательство по вершине")
    proof.add_argument("proof", type=Path)
    proof.add_argument("--head", type=Path, required=True)
    proof.set_defaults(run=log_check_proof)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Точка входа команды ``provenance``."""
    for stream in (sys.stdout, sys.stderr):
        # Консоль Windows по умолчанию не в UTF-8: русский текст иначе не выводится.
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    arguments = _parser().parse_args(argv)
    try:
        return int(arguments.run(arguments))
    except (ProvenanceError, OSError) as error:
        sys.stderr.write(f"Ошибка: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
