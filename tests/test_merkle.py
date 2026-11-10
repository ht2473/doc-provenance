"""Дерево хэшей: контрольные значения RFC 6962 и полный перебор малых деревьев."""

from __future__ import annotations

import hashlib

import pytest

from provenance import merkle

# Записи и вершины из проверок эталонной реализации Certificate Transparency.
RECORDS = [
    bytes.fromhex(item)
    for item in (
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    )
]
ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
LEAVES = [merkle.leaf_hash(record) for record in RECORDS]


def sample(count: int) -> list[bytes]:
    """Хэши ``count`` различных записей."""
    return [merkle.leaf_hash(f"запись {index}".encode()) for index in range(count)]


def test_empty_tree_is_hash_of_nothing() -> None:
    assert merkle.root([]) == hashlib.sha256(b"").digest()


@pytest.mark.parametrize("size", range(1, 9))
def test_reference_roots(size: int) -> None:
    """Вершины совпадают с эталонными для деревьев от одной до восьми записей."""
    assert merkle.root(LEAVES[:size]).hex() == ROOTS[size - 1]


def test_reference_inclusion_path() -> None:
    """Путь для первой записи в дереве из восьми — как в эталонной реализации."""
    path = [item.hex() for item in merkle.inclusion_proof(0, LEAVES)]
    assert path == [
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
    ]


def test_leaf_and_node_are_hashed_differently() -> None:
    """Узел нельзя выдать за запись: у листа и узла разные приставки."""
    left, right = LEAVES[0], LEAVES[1]
    assert merkle.node_hash(left, right) != merkle.leaf_hash(left + right)


@pytest.mark.parametrize("size", range(1, 34))
def test_every_record_is_provable(size: int) -> None:
    """Доказательство включения сходится для каждой записи дерева любого размера."""
    leaves = sample(size)
    top = merkle.root(leaves)
    for index in range(size):
        path = merkle.inclusion_proof(index, leaves)
        assert merkle.verify_inclusion(leaves[index], index, size, path, top)
        assert len(path) <= (size - 1).bit_length()


@pytest.mark.parametrize("size", [1, 2, 3, 7, 8, 13])
def test_inclusion_rejects_everything_else(size: int) -> None:
    """
    Чужая запись, чужое место, испорченный, обрезанный или удлинённый путь — отказ.

    Размер журнала доказательство само не удостоверяет (у соседних размеров путь бывает тем
    же): его берут из подписанной вершины.
    """
    leaves = sample(size)
    top = merkle.root(leaves)
    stranger = merkle.leaf_hash(b"not in the log")
    for index in range(size):
        path = merkle.inclusion_proof(index, leaves)
        assert not merkle.verify_inclusion(stranger, index, size, path, top)
        assert not merkle.verify_inclusion(leaves[index], size, size, path, top)
        assert not merkle.verify_inclusion(leaves[index], -1, size, path, top)
        if size > 1:
            other = (index + 1) % size
            assert not merkle.verify_inclusion(leaves[index], other, size, path, top)
            assert not merkle.verify_inclusion(leaves[index], index, size, path[:-1], top)
            broken = [bytes(32), *path[1:]]
            assert not merkle.verify_inclusion(leaves[index], index, size, broken, top)
        assert not merkle.verify_inclusion(leaves[index], index, size, [*path, bytes(32)], top)


@pytest.mark.parametrize("new_size", range(1, 26))
def test_every_prefix_is_consistent(new_size: int) -> None:
    """Журнал согласован с каждым своим началом."""
    leaves = sample(new_size)
    new_root = merkle.root(leaves)
    for old_size in range(new_size + 1):
        old_root = merkle.root(leaves[:old_size])
        path = merkle.consistency_proof(old_size, leaves)
        assert merkle.verify_consistency(old_size, new_size, old_root, new_root, path)


@pytest.mark.parametrize("new_size", [2, 3, 5, 8, 9, 16, 21])
def test_rewritten_history_is_not_consistent(new_size: int) -> None:
    """Журнал, в котором изменена прежняя запись, прежнюю вершину не продолжает."""
    leaves = sample(new_size)
    for old_size in range(1, new_size):
        old_root = merkle.root(leaves[:old_size])
        for changed in range(old_size):
            forged = list(leaves)
            forged[changed] = merkle.leaf_hash(b"rewritten")
            path = merkle.consistency_proof(old_size, forged)
            assert not merkle.verify_consistency(
                old_size, new_size, old_root, merkle.root(forged), path
            )


def test_consistency_rejects_wrong_sizes_and_paths() -> None:
    leaves = sample(11)
    old_root, new_root = merkle.root(leaves[:6]), merkle.root(leaves)
    path = merkle.consistency_proof(6, leaves)
    assert merkle.verify_consistency(6, 11, old_root, new_root, path)
    assert not merkle.verify_consistency(11, 6, new_root, old_root, path)
    assert not merkle.verify_consistency(5, 11, old_root, new_root, path)
    assert not merkle.verify_consistency(6, 11, old_root, new_root, path[:-1])
    assert not merkle.verify_consistency(6, 11, old_root, new_root, [*path, bytes(32)])
    assert not merkle.verify_consistency(6, 11, new_root, new_root, path)
    assert not merkle.verify_consistency(6, 6, old_root, old_root, path)
    assert not merkle.verify_consistency(0, 11, old_root, new_root, [])
    assert merkle.verify_consistency(0, 11, merkle.EMPTY_ROOT, new_root, [])


def test_proofs_refuse_missing_records() -> None:
    with pytest.raises(IndexError):
        merkle.inclusion_proof(3, sample(3))
    with pytest.raises(IndexError):
        merkle.consistency_proof(4, sample(3))
