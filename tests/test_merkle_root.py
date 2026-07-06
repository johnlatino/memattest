import hashlib

from memattest.merkle import leaf_hash, node_hash, root_hash

# CT reference test vectors: leaf inputs (hex) and tree roots (hex) for sizes 1..8.
LEAF_INPUTS = [
    "", "00", "10", "2021", "3031", "40414243",
    "5051525354555657", "606162636465666768696a6b6c6d6e6f",
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


def _naive(leaves: list[bytes]) -> bytes:
    """Independent reference implementation, structured differently on purpose."""
    n = len(leaves)
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + _naive(leaves[:k]) + _naive(leaves[k:])).digest()


def test_empty_tree_root_is_hash_of_empty_string():
    assert root_hash([]) == hashlib.sha256(b"").digest()


def test_leaf_and_node_prefixes():
    assert leaf_hash(b"x") == hashlib.sha256(b"\x00x").digest()
    assert node_hash(b"L", b"R") == hashlib.sha256(b"\x01LR").digest()


def test_ct_reference_vectors():
    leaves = [bytes.fromhex(h) for h in LEAF_INPUTS]
    for size in range(1, 9):
        assert root_hash(leaves[:size]).hex() == ROOTS[size - 1], f"size {size}"


def test_matches_naive_reference_for_all_sizes_to_33():
    leaves = [f"entry-{i}".encode() for i in range(33)]
    for size in range(1, 34):
        assert root_hash(leaves[:size]) == _naive(leaves[:size]), f"size {size}"
