"""Удостоверяющий центр, разбор DER и командная строка."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from provenance import ca, cli, der
from provenance.errors import Code, ProvenanceError, VerifyError


class TestAuthority:
    def test_root_signs_only_certificates(self, root: ca.Identity) -> None:
        """Корневой сертификат — центр без промежуточных: подписывает сертификаты и списки."""
        certificate = root.certificate
        constraints = certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert constraints.critical and constraints.value.ca
        assert constraints.value.path_length == 0
        assert usage.critical and usage.value.key_cert_sign and usage.value.crl_sign
        assert not usage.value.digital_signature
        assert certificate.issuer == certificate.subject
        assert ca.is_root(certificate) and not ca.is_document_signer(certificate)

    def test_signer_only_signs_documents(self, root: ca.Identity, signer: ca.Identity) -> None:
        """Сертификат подписи — не центр, только подпись и только документов."""
        certificate = signer.certificate
        usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        purposes = certificate.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        assert usage.digital_signature and not usage.key_cert_sign
        assert list(purposes) == [ca.DOCUMENT_SIGNING]
        assert ca.is_document_signer(certificate) and not ca.is_root(certificate)
        certificate.verify_directly_issued_by(root.certificate)
        assert certificate.not_valid_after_utc <= root.certificate.not_valid_after_utc

    def test_serials_are_random(self, root: ca.Identity) -> None:
        serials = {ca.issue_signer(root, "служба").certificate.serial_number for _ in range(5)}
        assert len(serials) == 5

    def test_key_file_with_passphrase(self, tmp_path: Path, root: ca.Identity) -> None:
        """Ключ с паролем без пароля не читается."""
        path = tmp_path / "root.key"
        ca.save_key(root.key, path, "длинный пароль")
        assert b"ENCRYPTED" in path.read_bytes()
        loaded = ca.load_key(path, "длинный пароль")
        assert loaded.public_key().public_numbers() == root.key.public_key().public_numbers()
        with pytest.raises(ProvenanceError):
            ca.load_key(path)
        with pytest.raises(ProvenanceError):
            ca.load_key(path, "не тот")

    def test_crl_lists_revoked(self, root: ca.Identity, signer: ca.Identity) -> None:
        moment = signer.certificate.not_valid_before_utc
        crl = ca.make_crl(root, [(signer.certificate.serial_number, moment)], number=7)
        assert crl.is_signature_valid(root.key.public_key())
        assert crl.get_revoked_certificate_by_serial_number(signer.certificate.serial_number)
        assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 7


class TestDer:
    def test_oid_and_integer(self) -> None:
        assert der.oid(der.parse(bytes.fromhex("06092a864886f70d010702"))) == "1.2.840.113549.1.7.2"
        assert der.oid(der.parse(bytes.fromhex("0603551d0f"))) == "2.5.29.15"
        assert der.integer(der.parse(bytes.fromhex("020101"))) == 1
        assert der.integer(der.parse(bytes.fromhex("0202ff7f"))) == -129

    def test_time(self) -> None:
        moment = der.time(der.parse(b"\x17\x0d" + b"261110063000Z"))
        assert moment.isoformat() == "2026-11-10T06:30:00+00:00"
        assert der.time(der.parse(b"\x17\x0d" + b"991231235959Z")).year == 1999

    @pytest.mark.parametrize(
        "data",
        [
            "30",  # обрыв
            "3003020101" + "00",  # хвост
            "308000",  # длина неопределённая
            "30810100",  # длина не кратчайшая
            "3082000100",  # длина с ведущим нулём
            "3005020101",  # длиннее данных
            "1f0100",  # длинный номер тега
        ],
    )
    def test_strictness(self, data: str) -> None:
        with pytest.raises(VerifyError) as caught:
            der.parse(bytes.fromhex(data))
        assert caught.value.code is Code.MALFORMED

    def test_bad_values(self) -> None:
        for data in ("0600", "06028000", "060281", "0200", "170d32363131313036333030305a00"):
            with pytest.raises(VerifyError):
                node = der.parse(bytes.fromhex(data))
                der.oid(node) if data.startswith("06") else None
                der.integer(node) if data.startswith("02") else None
                der.time(node) if data.startswith("17") else None

    def test_nesting_limit(self) -> None:
        data = b""
        for _ in range(40):
            data = bytes([0x30, len(data)]) + data if len(data) < 0x80 else data
        node = der.parse(data)
        with pytest.raises(VerifyError):
            depth = 0
            while True:
                node = node.children(depth)[0]
                depth += 1


class TestCommandLine:
    """Полный путь: центр, сертификат, подпись, проверка, отзыв, журнал."""

    @pytest.fixture
    def stand(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
        assert cli.main(["ca", "init", str(tmp_path / "ca"), "--name", "Центр", "--org", "RL"]) == 0
        assert (
            cli.main(
                ["ca", "issue", str(tmp_path / "ca"), "--name", "Служба", "--org", "RL",
                 "--out", str(tmp_path / "service")]
            )
            == 0
        )  # fmt: skip
        (tmp_path / "report.csv").write_bytes(b"region;value\nPskov;612.3\n")
        capsys.readouterr()
        return tmp_path

    def trust(self, stand: Path) -> list[str]:
        return ["--root", str(stand / "ca" / "root.crt"), "--crl", str(stand / "ca" / "crl.pem")]

    def signer(self, stand: Path) -> list[str]:
        return ["--key", str(stand / "service" / "signer.key"),
                "--cert", str(stand / "service" / "signer.crt")]  # fmt: skip

    def test_sign_and_verify(self, stand: Path, capsys: pytest.CaptureFixture[str]) -> None:
        report = str(stand / "report.csv")
        assert cli.main(["sign", report, *self.signer(stand)]) == 0
        assert cli.main(["verify", report, *self.trust(stand)]) == 0
        output = capsys.readouterr().out
        assert "ПОДЛИННЫЙ" in output and "Служба, RL" in output

        (stand / "report.csv").write_bytes(b"region;value\nPskov;999.9\n")
        assert cli.main(["verify", report, *self.trust(stand)]) == 1
        assert "document_changed" in capsys.readouterr().out

    def test_revocation(self, stand: Path, capsys: pytest.CaptureFixture[str]) -> None:
        report = str(stand / "report.csv")
        cli.main(["sign", report, *self.signer(stand)])
        assert (
            cli.main(["ca", "revoke", str(stand / "ca"), str(stand / "service" / "signer.crt")])
            == 0
        )
        assert cli.main(["verify", report, *self.trust(stand)]) == 1
        assert "revoked" in capsys.readouterr().out
        state = json.loads((stand / "ca" / "revoked.json").read_text(encoding="utf-8"))
        assert state["number"] == 2 and len(state["revoked"]) == 1

    def test_show_and_missing_files(self, stand: Path, capsys: pytest.CaptureFixture[str]) -> None:
        report = str(stand / "report.csv")
        cli.main(["sign", report, *self.signer(stand)])
        assert cli.main(["show", report + ".p7s"]) == 0
        assert "не проверено" in capsys.readouterr().out
        assert cli.main(["verify", str(stand / "absent.csv"), *self.trust(stand)]) == 2
        assert cli.main(["ca", "init", str(stand / "ca"), "--name", "Второй"]) == 2

    def test_log(self, stand: Path, capsys: pytest.CaptureFixture[str]) -> None:
        journal = stand / "MANIFEST.csv"
        journal.write_bytes(b"aa,1,rosstat,a.xlsx\nbb,2,cbr,b.xlsx\ncc,3,fns,c.xlsx\n")
        assert cli.main(["log", "seal", str(journal), *self.signer(stand)]) == 0
        assert cli.main(["log", "verify", str(journal), *self.trust(stand)]) == 0
        proof = stand / "proof.json"
        assert cli.main(["log", "prove", str(journal), "1", "--out", str(proof)]) == 0
        head = str(journal) + ".head.json"
        assert cli.main(["log", "check-proof", str(proof), "--head", head]) == 0

        journal.write_bytes(b"aa,1,rosstat,a.xlsx\nXX,2,cbr,b.xlsx\ncc,3,fns,c.xlsx\n")
        capsys.readouterr()
        assert cli.main(["log", "verify", str(journal), *self.trust(stand)]) == 1
        assert "log_mismatch" in capsys.readouterr().out
        assert cli.main(["log", "seal", str(journal), *self.signer(stand)]) == 1
