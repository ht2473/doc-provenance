"""
Показ по шагам: центр, подпись документа, пять атак и журнал с подписанной вершиной.

Запуск из корня проекта:  python demo/run_demo.py
Все файлы остаются в demo/out — их можно открыть и проверить командой ``provenance``
или OpenSSL.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from provenance import ca, cms, log
from provenance.errors import VerifyError

OUT = Path(__file__).resolve().parent / "out"
DOCUMENT = (
    "Показатель;Регион;Год;Значение\n"
    "Валовой региональный продукт на душу населения, руб.;Псковская область;2023;432118,6\n"
    "Валовой региональный продукт на душу населения, руб.;Новгородская область;2023;608774,2\n"
).encode()


def step(number: int, title: str) -> None:
    print(f"\n=== Шаг {number}. {title} ===")


def attempt(title: str, action) -> None:
    """Выполнить проверку и напечатать её исход."""
    try:
        result = action()
    except VerifyError as error:
        print(f"  {title}: ОТКАЗ — {error.message} [{error.code}]")
    else:
        detail = f" (подписал: {result.signer})" if hasattr(result, "signer") else ""
        print(f"  {title}: ПРИНЯТО{detail}")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)

    step(1, "Удостоверяющий центр и сертификат службы подписи")
    root = ca.new_root("Корневой центр показа", "doc-provenance")
    signer = ca.issue_signer(root, "Служба подписи документов", "doc-provenance")
    ca.save_certificate(root.certificate, OUT / "root.crt")
    ca.save_certificate(signer.certificate, OUT / "signer.crt")
    ca.save_key(signer.key, OUT / "signer.key")
    ca.save_crl(ca.make_crl(root, []), OUT / "crl.pem")
    print(f"  корневой сертификат, отпечаток SHA-256: {ca.fingerprint(root.certificate)}")
    print(f"  сертификат службы № {ca.serial_text(signer.certificate)}")
    print("  корневой ключ на диск не пишется: служба подписи его не видит")
    roots = [root.certificate]

    step(2, "Подпись документа")
    (OUT / "report.csv").write_bytes(DOCUMENT)
    signature = cms.sign(DOCUMENT, signer)
    (OUT / "report.csv.p7s").write_bytes(signature)
    print(f"  документ {len(DOCUMENT)} байт, SHA-256 {hashlib.sha256(DOCUMENT).hexdigest()}")
    print(f"  подпись CMS {len(signature)} байт — отдельный файл report.csv.p7s")

    step(3, "Проверка подлинного документа")
    attempt("документ как выдан", lambda: cms.verify(DOCUMENT, signature, roots))

    step(4, "Атака: в документе изменено одно число")
    forged = DOCUMENT.replace(b"432118,6", b"532118,6")
    (OUT / "report_forged.csv").write_bytes(forged)
    attempt("изменённый документ со старой подписью", lambda: cms.verify(forged, signature, roots))

    step(5, "Атака: документ подписан своим «центром» с теми же именами")
    fake_root = ca.new_root("Корневой центр показа", "doc-provenance")
    fake_signer = ca.issue_signer(fake_root, "Служба подписи документов", "doc-provenance")
    fake_signature = cms.sign(forged, fake_signer)
    print(f"  в подписи написано: {cms.describe(fake_signature)['signer']} — имена те же")
    attempt("изменённый документ с подписью чужого центра",
            lambda: cms.verify(forged, fake_signature, roots))  # fmt: skip

    step(6, "Атака: ключ службы украден — сертификат отозван")
    stolen_signature = cms.sign(forged, signer)
    attempt("подделка, подписанная украденным ключом, без списка отзыва",
            lambda: cms.verify(forged, stolen_signature, roots))  # fmt: skip
    revoked = ca.make_crl(root, [(signer.certificate.serial_number, datetime.now(UTC))], number=2)
    ca.save_crl(revoked, OUT / "crl_after_theft.pem")
    attempt("та же подделка со свежим списком отзыва",
            lambda: cms.verify(forged, stolen_signature, roots, crl=revoked))  # fmt: skip

    step(7, "Независимая проверка: OpenSSL")
    openssl = shutil.which("openssl")
    if openssl is None:
        print("  openssl не найден — шаг пропущен")
    else:
        for name in ("report.csv", "report_forged.csv"):
            command = [
                openssl, "cms", "-verify", "-binary", "-inform", "DER",
                "-in", "report.csv.p7s", "-content", name,
                "-CAfile", "root.crt", "-purpose", "any", "-out", "openssl_out.txt",
            ]  # fmt: skip
            done = subprocess.run(command, cwd=OUT, capture_output=True, text=True, check=False)
            verdict = "ПРИНЯТО" if done.returncode == 0 else "ОТКАЗ"
            print(f"  openssl cms -verify, {name}: {verdict}")

    step(8, "Журнал: опись архива исходных файлов с подписанной вершиной")
    journal = OUT / "MANIFEST.csv"
    files = {f"release_{index}.xlsx": f"данные выпуска {index}".encode() for index in range(1, 6)}
    rows = [
        f"{hashlib.sha256(body).hexdigest()},{len(body)},rosstat,{name}".encode()
        for name, body in files.items()
    ]
    journal.write_bytes(b"\n".join(rows[:3]) + b"\n")
    first = log.seal_file(journal, signer, "архив выпусков")
    head_path, signature_path, _history = log.paths(journal)
    old_head, old_signature = head_path.read_bytes(), signature_path.read_bytes()
    print(f"  подписано 3 записи, вершина {first.root[:16]}…")
    journal.write_bytes(b"\n".join(rows) + b"\n")
    second = log.seal_file(journal, signer, "архив выпусков")
    print(f"  добавлено 2 записи, подписано 5, вершина {second.root[:16]}…")
    attempt("журнал как есть", lambda: log.check_file(journal, roots).signature)

    step(9, "Атака: файл архива подменён, строка описи исправлена под него")
    body = "подменённые данные".encode()
    tampered = list(rows)
    tampered[1] = f"{hashlib.sha256(body).hexdigest()},{len(body)},rosstat,release_2.xlsx".encode()
    journal.write_bytes(b"\n".join(tampered) + b"\n")
    print("  хэш файла и строка описи сходятся между собой — простая сверка ничего не заметит")
    attempt("журнал с подменённой строкой", lambda: log.check_file(journal, roots).signature)

    step(10, "Атака: откат к прежнему журналу с его же верной подписью")
    journal.write_bytes(b"\n".join(rows[:3]) + b"\n")
    head_path.write_bytes(old_head)
    signature_path.write_bytes(old_signature)
    print("  подпись прежней вершины настоящая — выдаёт откат только история вершин")
    attempt("журнал после отката", lambda: log.check_file(journal, roots).signature)

    step(11, "Доказательство включения: одна запись и путь вместо всего журнала")
    journal.write_bytes(b"\n".join(rows) + b"\n")
    head_path.write_bytes(second.to_bytes())
    proof = log.prove_inclusion(3, rows)
    accepted = log.check_inclusion(rows[3], proof, second)
    rejected = log.check_inclusion(tampered[1], proof, second)
    print(f"  запись № 3 из {second.size}: хэшей в пути {len(proof['path'])}")
    print(f"  настоящая запись: {'входит в журнал' if accepted else 'не входит'}")
    print(f"  чужая запись с тем же путём: {'входит в журнал' if rejected else 'не входит'}")

    print(f"\nФайлы показа: {OUT}")


if __name__ == "__main__":
    main()
