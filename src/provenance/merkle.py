"""
Дерево хэшей (дерево Меркла) по RFC 6962 — как в журналах Certificate Transparency.

Все записи журнала сводятся к одному хэшу — вершине. Изменить, убрать или переставить
запись, не изменив вершину, нельзя. Сверх этого дерево даёт два коротких доказательства:

* включения — «эта запись есть в журнале с такой вершиной»: нужны только хэши соседей
  по пути от записи к вершине, их около log2(n);
* согласованности — «журнал из n записей продолжает журнал из m записей, ничего в нём
  не меняя»: так тот, кто запомнил старую вершину, ловит переписанную историю.

Лист и узел хэшируются с разными приставками (0x00 и 0x01): иначе внутренний узел можно
было бы выдать за запись.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

LEAF = b"\x00"
NODE = b"\x01"
# Вершина пустого дерева — хэш пустой строки.
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(record: bytes) -> bytes:
    """Хэш записи журнала."""
    return hashlib.sha256(LEAF + record).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Хэш узла над двумя поддеревьями."""
    return hashlib.sha256(NODE + left + right).digest()


def _split(size: int) -> int:
    """Наибольшая степень двойки, строго меньшая ``size``: столько листьев уходит налево."""
    return 1 << ((size - 1).bit_length() - 1)


def root(leaves: Sequence[bytes]) -> bytes:
    """Вершина дерева над хэшами листьев."""
    if not leaves:
        return EMPTY_ROOT
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Хэши соседей на пути от листа ``index`` к вершине — снизу вверх."""
    if not 0 <= index < len(leaves):
        raise IndexError("такой записи в журнале нет")
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return [*inclusion_proof(index, leaves[:k]), root(leaves[k:])]
    return [*inclusion_proof(index - k, leaves[k:]), root(leaves[:k])]


def verify_inclusion(
    leaf: bytes, index: int, size: int, proof: Sequence[bytes], expected_root: bytes
) -> bool:
    """Запись с хэшем ``leaf`` стоит под номером ``index`` в журнале из ``size`` записей."""
    if not 0 <= index < size:
        return False
    position, last, current = index, size - 1, leaf
    for sibling in proof:
        if last == 0:
            return False
        if position & 1 or position == last:
            current = node_hash(sibling, current)
            # Правый край неполного дерева поднимается сразу на несколько уровней.
            while not position & 1 and position:
                position >>= 1
                last >>= 1
        else:
            current = node_hash(current, sibling)
        position >>= 1
        last >>= 1
    return last == 0 and current == expected_root


def consistency_proof(old_size: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Доказательство, что первые ``old_size`` записей журнала остались прежними."""
    if not 0 <= old_size <= len(leaves):
        raise IndexError("прежний журнал длиннее нынешнего")
    if old_size in {0, len(leaves)}:
        return []
    return _subproof(old_size, leaves, whole=True)


def _subproof(old_size: int, leaves: Sequence[bytes], *, whole: bool) -> list[bytes]:
    if old_size == len(leaves):
        return [] if whole else [root(leaves)]
    k = _split(len(leaves))
    if old_size <= k:
        return [*_subproof(old_size, leaves[:k], whole=whole), root(leaves[k:])]
    return [*_subproof(old_size - k, leaves[k:], whole=False), root(leaves[:k])]


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: Sequence[bytes]
) -> bool:
    """Журнал с вершиной ``new_root`` продолжает журнал с вершиной ``old_root``."""
    if old_size > new_size or old_size < 0:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        # Пустой журнал продолжается любым.
        return not proof and old_root == EMPTY_ROOT
    path = list(proof)
    if old_size & (old_size - 1) == 0:
        # Прежний журнал — полное поддерево: его вершина и есть первый элемент пути.
        path.insert(0, old_root)
    if not path:
        return False
    position, last = old_size - 1, new_size - 1
    while position & 1:
        position >>= 1
        last >>= 1
    old_current = new_current = path[0]
    for sibling in path[1:]:
        if last == 0:
            return False
        if position & 1 or position == last:
            old_current = node_hash(sibling, old_current)
            new_current = node_hash(sibling, new_current)
            while not position & 1 and position:
                position >>= 1
                last >>= 1
        else:
            new_current = node_hash(new_current, sibling)
        position >>= 1
        last >>= 1
    return last == 0 and old_current == old_root and new_current == new_root
