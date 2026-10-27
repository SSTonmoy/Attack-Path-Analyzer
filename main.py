"""main.py
==========

Entry point that ties the individual analysis components together.
The function ``run_analysis`` performs the full pipeline on the bundled
``sample_small.json`` fixture and returns a dictionary of the most important
results.  It also writes a Markdown report and a PNG visualisation to the
``output`` directory.

The public API for this step is deliberately tiny – the test suite only needs
to import ``run_analysis`` and verify that it returns the expected structure.
"""

from __future__ import annotations

import pathlib
from typing import Dict, List

from src.loader import load_json
from src.graph_builder import build_graph
from src.pathfinder import dijkstra, path_probability
from src.risk import score_path
from src.hardening import harden
from src.segmentation import find_segments
from src.visualize import draw_graph
from src.report import build_report


def run_analysis() -> Dict:
    """Execute the complete attack‑path analysis pipeline.

    Returns
    -------
    dict
        A dictionary with keys ``risk``, ``hardening`` and ``segments`` that
        contain the respective module outputs.  The function also generates a
        Markdown report (``output/report.md``) and a graph image
        (``output/graph.png``).
    """
    # ------------------------------------------------------------
    # 1️⃣ Load data and build the directed graph.
    # ------------------------------------------------------------
    data_path = pathlib.Path(__file__).parent / "data" / "sample_small.json"
    data = load_json(str(data_path))
    G = build_graph(data)

    # ------------------------------------------------------------
    # 2️⃣ Find the most likely (shortest‑weight) path from entry to target.
    # ------------------------------------------------------------
    entry = data["entry"]
    target = data["targets"][0]
    # ``dijkstra`` returns a list when ``target`` is supplied (see step 7).
    path = dijkstra(G, source=entry, target=target)  # type: ignore[assignment]
    assert isinstance(path, list), "dijkstra should return a path list"

    # ------------------------------------------------------------
    # 3️⃣ Compute risk for that path.
    # ------------------------------------------------------------
    risk_result = score_path(G, path)

    # ------------------------------------------------------------
    # 4️⃣ Hardening plan (MST based).
    # ------------------------------------------------------------
    hardening_result = harden(G, entry=entry, targets=[target])

    # ------------------------------------------------------------
    # 5️⃣ Segmentation (weakly‑connected components).
    # ------------------------------------------------------------
    segments = find_segments(G)

    # ------------------------------------------------------------
    # 6️⃣ Produce artefacts – a report and a visualisation.
    # ------------------------------------------------------------
    output_dir = pathlib.Path(__file__).parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / "report.md"
    build_report(
        {
            "risk_summary": risk_result,
            "hardening_plan": hardening_result,
            "segments": segments,
        },
        str(report_path),
    )

    graph_path = output_dir / "graph.png"
    draw_graph(
        G,
        out_path=str(graph_path),
        highlight_path=path,
        removed_edges=hardening_result.get("removed"),
    )

    # ------------------------------------------------------------
    # 7️⃣ Return a compact result dictionary for programmatic use.
    # ------------------------------------------------------------
    return {
        "risk": risk_result,
        "hardening": hardening_result,
        "segments": segments,
        "report_path": str(report_path),
        "graph_path": str(graph_path),
    }


if __name__ == "__main__":
    results = run_analysis()
    print("Analysis complete. Summary:")
    print(f"  Risk band: {results['risk']['band']}")
    print(f"  Report written to: {results['report_path']}")
    print(f"  Graph image: {results['graph_path']}")
