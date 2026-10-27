import pathlib
import pytest
from src.loader import load_json, _error


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


def test_load_invalid_probability():
    # copy the valid sample and tamper a probability to 0
    import json, copy
    data_path = pathlib.Path(__file__).parents[1] / "data" / "sample_small.json"
    data = json.loads(pathlib.Path(data_path).read_text())
    bad = copy.deepcopy(data)
    bad["edges"][0]["p"] = 0
    # write a temporary file
    tmp_path = pathlib.Path(__file__).parent / "tmp_invalid.json"
    tmp_path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_json(str(tmp_path))
    assert "probability 'p' must be in (0, 1]" in str(exc.value)
    tmp_path.unlink()
