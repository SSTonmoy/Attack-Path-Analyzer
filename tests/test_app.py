"""tests/test_app.py
=================

Smoke and unit tests for app.py:
1. Safe cell-reading helpers (handling NaN, empty strings, Excel boolean edge cases).
2. Streamlit AppTest smoke test ensuring the UI initializes and runs without exceptions.
"""

import pathlib
from streamlit.testing.v1 import AppTest

from app import _safe_str, _safe_int, _safe_float, _safe_bool


def test_safe_cell_helpers():
    """Verify that cell-reading helpers handle NaN, empty, and irregular values safely."""
    # Strings
    assert _safe_str("test") == "test"
    assert _safe_str(None) == ""
    assert _safe_str(float("nan")) == ""
    assert _safe_str("nan") == ""
    assert _safe_str("  ") == ""
    assert _safe_str(float("nan"), default="internal") == "internal"

    # Integers
    assert _safe_int(10) == 10
    assert _safe_int("5") == 5
    assert _safe_int("5.0") == 5
    assert _safe_int(float("nan"), default=0) == 0
    assert _safe_int(None, default=3) == 3
    assert _safe_int("invalid", default=0) == 0

    # Floats
    assert _safe_float(0.85) == 0.85
    assert _safe_float("0.75") == 0.75
    assert _safe_float(float("nan"), default=0.5) == 0.5
    assert _safe_float(None, default=0.5) == 0.5

    # Booleans
    assert _safe_bool(True) is True
    assert _safe_bool(False) is False
    assert _safe_bool("true") is True
    assert _safe_bool("yes") is True
    assert _safe_bool("1") is True
    assert _safe_bool("false") is False
    assert _safe_bool(float("nan"), default=False) is False
    assert _safe_bool(None, default=False) is False


def test_app_smoke_apptest():
    """Verify that app.py runs without unhandled exceptions on startup."""
    app_path = pathlib.Path(__file__).parents[1] / "app.py"
    at = AppTest.from_file(str(app_path.resolve()))
    at.run(timeout=20)
    assert len(at.exception) == 0, [e.value for e in at.exception]


def test_analyze_and_materialize():
    """Verify that analyze_and_materialize generates per-network artifacts cleanly."""
    from app import analyze_and_materialize
    from src.builders import generate_random_network
    net_dict = generate_random_network(num_nodes=5, edge_density=0.4, seed=777)
    results = analyze_and_materialize(net_dict)
    assert "risk" in results
    assert "blast_radius" in results
    assert "boundary_violations" in results
    assert pathlib.Path(results["report_path"]).is_file()
    assert pathlib.Path(results["graph_path"]).is_file()


def test_display_analysis_dashboard_key_prefix():
    """Verify that display_analysis_dashboard accepts key_prefix without error."""
    from app import analyze_and_materialize, display_analysis_dashboard
    from src.builders import generate_random_network
    net_dict = generate_random_network(num_nodes=5, edge_density=0.4, seed=888)
    results = analyze_and_materialize(net_dict)
    # Ensure display_analysis_dashboard executes cleanly with distinct prefixes
    display_analysis_dashboard(results, net_dict, key_prefix="test_prefix_1")
    display_analysis_dashboard(results, net_dict, key_prefix="test_prefix_2")
