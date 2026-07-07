from memattest.merkle import (
    consistency_proof,
    inclusion_proof,
    root_hash,
    verify_consistency,
    verify_inclusion,
)

LEAVES = [f"entry-{i}".encode() for i in range(33)]


def test_inclusion_all_indices_all_sizes():
    for size in range(1, 34):
        leaves = LEAVES[:size]
        root = root_hash(leaves)
        for i in range(size):
            proof = inclusion_proof(i, leaves)
            assert verify_inclusion(leaves[i], i, size, proof, root), f"size={size} i={i}"


def test_inclusion_rejects_wrong_leaf_and_index():
    leaves = LEAVES[:7]
    root = root_hash(leaves)
    proof = inclusion_proof(3, leaves)
    assert not verify_inclusion(b"tampered", 3, 7, proof, root)
    assert not verify_inclusion(leaves[3], 2, 7, proof, root)
    assert not verify_inclusion(leaves[3], 3, 7, proof, root_hash(LEAVES[:8]))


def test_consistency_all_prefixes_all_sizes():
    for new in range(1, 34):
        leaves = LEAVES[:new]
        new_root = root_hash(leaves)
        for old in range(0, new + 1):
            proof = consistency_proof(old, leaves)
            old_root = root_hash(leaves[:old])
            assert verify_consistency(old, new, old_root, new_root, proof), f"{old}->{new}"


def test_consistency_rejects_rewritten_history():
    good = LEAVES[:8]
    # History where entry 2 was altered before extension:
    bad = good[:2] + [b"rewritten"] + good[3:]
    proof = consistency_proof(4, bad)
    assert not verify_consistency(4, 8, root_hash(good[:4]), root_hash(bad), proof)
