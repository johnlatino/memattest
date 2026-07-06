"""RFC 6962 Merkle tree: hashing, root computation, inclusion and consistency proofs."""
import hashlib
from typing import Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root_hash(leaves: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash (RFC 6962 §2.1) over raw leaf data."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _split(n)
    return node_hash(root_hash(leaves[:k]), root_hash(leaves[k:]))


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Audit path for leaf `index` (RFC 6962 §2.1.1)."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, leaves[:k]) + [root_hash(leaves[k:])]
    return inclusion_proof(index - k, leaves[k:]) + [root_hash(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, tree_size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 §2.1.3.2 verification algorithm."""
    if index >= tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash(leaf)
    for p in proof:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_proof(old_size: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Proof that the first `old_size` leaves are a prefix (RFC 6962 §2.1.2)."""
    n = len(leaves)
    if old_size == 0 or old_size >= n:
        return []
    return _subproof(old_size, leaves, True)


def _subproof(m: int, leaves: Sequence[bytes], known_root: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if known_root else [root_hash(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], known_root) + [root_hash(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root_hash(leaves[:k])]


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2 verification algorithm."""
    if old_size > new_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        return not proof  # the empty prefix is consistent with any tree
    path = list(proof)
    if old_size & (old_size - 1) == 0:  # old tree is a complete subtree; its root is implied
        path = [old_root] + path
    fn, sn = old_size - 1, new_size - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1
    if not path:
        return False
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root
