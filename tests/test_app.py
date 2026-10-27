"""tests/test_app.py
=================

Smoke and unit tests for app.py:
1. Safe cell-reading helpers (handling NaN, empty strings, Excel boolean edge cases).
2. Streamlit AppTest smoke test ensuring the UI initializes and runs without exceptions.
"""

import pathlib
import pytest
import pandas as pd
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
