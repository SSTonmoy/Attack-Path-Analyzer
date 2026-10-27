import pathlib
import pytest
from src.loader import load_json


def test_load_sample_small_success():
    data_path = pathlib.Path(__file__).parents[1] / "data" / "sample_small.json"
    data = load_json(str(data_path))
    # basic sanity checks
    assert isinstance(data, dict)
    assert data["entry"] == "internet"
    assert data["targets"] == ["db01"]
    assert len(data["nodes"]) == 7
    assert len(data["edges"]) == 9


def test_load_missing_file():
    with pytest.raises(ValueError) as exc:
        load_json("nonexistent.json")
    assert "File not found" in str(exc.value)


def test_load_invalid_probability(tmp_path: pathlib.Path):
    # copy the valid sample and tamper a probability to 0
    import json, copy
    data_path = pathlib.Path(__file__).parents[1] / "data" / "sample_small.json"
    data = json.loads(data_path.read_text(encoding="utf-8"))
    bad = copy.deepcopy(data)
    bad["edges"][0]["p"] = 0
    # write to isolated tmp_path
    bad_file = tmp_path / "tmp_invalid.json"
    bad_file.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_json(str(bad_file))
    assert "probability 'p' must be in (0, 1]" in str(exc.value)


def test_load_duplicate_edges(tmp_path: pathlib.Path):
    """Verify that duplicate directed edges raise ValueError."""
    import json
    data = {
        "nodes": [
            {"id": "a", "zone": "z", "criticality": 1},
            {"id": "b", "zone": "z", "criticality": 2},
        ],
        "edges": [
            {"src": "a", "dst": "b", "p": 0.5, "required": False},
            {"src": "a", "dst": "b", "p": 0.8, "required": True},
        ],
        "entry": "a",
        "targets": ["b"],
    }
    p = tmp_path / "dup_edges.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate directed edge"):
        load_json(str(p))


def test_load_json_with_bom(tmp_path: pathlib.Path):
    """Verify that JSON files with UTF-8 BOM are loaded cleanly without crashing."""
    import json
    data = {
        "nodes": [
            {"id": "entry_node", "zone": "ext", "criticality": 0},
            {"id": "target_node", "zone": "int", "criticality": 10},
        ],
        "edges": [
            {"src": "entry_node", "dst": "target_node", "p": 0.8, "required": True, "vuln": "exploit"}
        ],
        "entry": "entry_node",
        "targets": ["target_node"],
    }
    bom_file = tmp_path / "bom_sample.json"
    bom_file.write_bytes(b"\xef\xbb\xbf" + json.dumps(data).encode("utf-8"))
    loaded = load_json(str(bom_file))
    assert loaded["entry"] == "entry_node"
    assert len(loaded["nodes"]) == 2


def test_load_boolean_criticality_rejected():
    """Verify that boolean criticality (e.g. True/False) is rejected in loader validation."""
    from src.loader import validate_network
    bad_data = {
        "nodes": [{"id": "a", "zone": "z", "criticality": True}],
        "edges": [],
        "entry": "a",
        "targets": ["a"],
    }
    with pytest.raises(ValueError, match="criticality must be an integer"):
        validate_network(bad_data)


def test_load_boolean_probability_rejected():
    """Verify that boolean probability (e.g. p: True) is rejected in loader validation."""
    from src.loader import validate_network
    bad_data = {
        "nodes": [
            {"id": "a", "zone": "z", "criticality": 1},
            {"id": "b", "zone": "z", "criticality": 2},
        ],
        "edges": [{"src": "a", "dst": "b", "p": True, "required": False}],
        "entry": "a",
        "targets": ["b"],
    }
    with pytest.raises(ValueError, match="probability 'p' must be a number"):
        validate_network(bad_data)
