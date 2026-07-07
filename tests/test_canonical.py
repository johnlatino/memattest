from memattest.canonical import canonical_json


def test_key_order_is_deterministic():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_compact_sorted_utf8():
    assert canonical_json({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode("utf-8")


def test_nested_structures():
    obj = {"z": [1, {"y": None, "x": True}], "a": "s"}
    assert canonical_json(obj) == b'{"a":"s","z":[1,{"x":true,"y":null}]}'
