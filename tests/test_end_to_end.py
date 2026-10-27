"""tests/test_end_to_end.py
==========================

End‑to‑end integration test for the full analysis pipeline.
The test invokes ``run_analysis`` from ``main.py`` and verifies that:

* The result dictionary contains the expected top‑level keys.
* The risk evaluation returns a band of ``High`` for the sample fixture (the
  most likely path yields a score ≈ 5.04 as defined in the risk tests).
* The generated artefacts – a Markdown report and a PNG graph – exist on
  disk.
"""

import pathlib

from main import run_analysis


def test_end_to_end_pipeline(tmp_path: pathlib.Path):
    # Run the full pipeline.
    results = run_analysis()

    # Expected top‑level keys.
    expected_keys = {
        "risk",
        "hardening",
        "segments",
        "report_path",
        "graph_path",
    }
    assert set(results.keys()) == expected_keys

    # Risk band should be "High" for the sample data.
    assert results["risk"]["band"] == "High"

    # The report and graph files should exist.
    report_path = pathlib.Path(results["report_path"])
    graph_path = pathlib.Path(results["graph_path"])
    assert report_path.is_file()
    assert graph_path.is_file()

    # Optionally, verify that the report contains the risk band text.
    report_text = report_path.read_text(encoding="utf-8")
    assert "High" in report_text
