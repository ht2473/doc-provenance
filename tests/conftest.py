"""Общее для проверок: удостоверяющий центр и сертификат подписи."""

from __future__ import annotations

import pytest

from provenance import ca

DOCUMENT = "Регион;2024\nПсковская область;612,3\n".encode()


@pytest.fixture(scope="session")
def root() -> ca.Identity:
    """Корневой сертификат проверок."""
    return ca.new_root("Проверочный центр", "RegionLens")


@pytest.fixture(scope="session")
def signer(root: ca.Identity) -> ca.Identity:
    """Сертификат подписи документов, выпущенный корневым."""
    return ca.issue_signer(root, "Служба подписи", "RegionLens")


@pytest.fixture(scope="session")
def stranger() -> ca.Identity:
    """Сертификат подписи чужого центра с теми же именами."""
    return ca.issue_signer(ca.new_root("Проверочный центр", "RegionLens"), "Служба подписи")
