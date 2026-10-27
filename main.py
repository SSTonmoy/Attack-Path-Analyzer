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
from typing import Dict

from src.loader import load_json, validate_network
from src.graph_builder import build_graph
from src.pathfinder import dijkstra
from src.risk import score_path
from src.hardening import harden
from src.segmentation import find_segments, boundary_violations, blast_radius
from src.visualize import draw_graph
from src.report import build_report


def run_analysis(
    input_path: str | pathlib.Path | dict | None = None,
    output_dir: str | pathlib.Path | None = None,
) -> Dict:
    """Execute the complete attack‑path analysis pipeline.

    Parameters
    ----------
    input_path: str | Path | dict | None
        Path to the input JSON file, or an in-memory network dictionary.
        Defaults to data/sample_small.json.
    output_dir: str | Path | None
        Path to the directory where reports and images are written.
        Defaults to output/.

    Returns
    -------
    dict
        A dictionary with keys ``risk``, ``hardening``, ``segments``,
        ``boundary_violations``, ``blast_radius``, ``report_path``, and
        ``graph_path``.
    """
    # ------------------------------------------------------------
    # 1️⃣ Load data and build the directed graph.
    # ------------------------------------------------------------
    if isinstance(input_path, dict):
        data = validate_network(input_path)
    elif input_path is not None:
        data = load_json(str(input_path))
    else:
        default_path = pathlib.Path(__file__).parent / "data" / "sample_small.json"
        data = load_json(str(default_path))

    G = build_graph(data)

    # ------------------------------------------------------------
    # 2️⃣ Find the most likely (highest-risk) path across all targets.
    # ------------------------------------------------------------
    entry = data["entry"]
    targets = data.get("targets", [])
    if not targets:
        raise ValueError("Network specification must contain at least one target.")

    best_path: list[str] | None = None
    best_risk: dict | None = None

    for tgt in targets:
        try:
            cand_path = dijkstra(G, source=entry, target=tgt)
            if isinstance(cand_path, list):
                cand_risk = score_path(G, cand_path)
                if best_risk is None or cand_risk["score"] > best_risk["score"]:
                    best_risk = cand_risk
                    best_path = cand_path
        except (ValueError, KeyError):
            continue

    if best_path is None or best_risk is None:
        raise ValueError(
            f"No attack path found from entry '{entry}' to target(s): {', '.join(targets)}"
        )

    # ------------------------------------------------------------
    # 3️⃣ Compute hardening, segmentation, violations, and blast radius.
    # ------------------------------------------------------------
    hardening_result = harden(G, entry=entry, targets=targets)
    segments = find_segments(G)
    violations = boundary_violations(G)
    radius = blast_radius(G, entry=entry)

    # ------------------------------------------------------------
    # 4️⃣ Produce artefacts – a report and a visualisation.
    # ------------------------------------------------------------
    if output_dir is None:
        out_dir = pathlib.Path(__file__).parent / "output"
    else:
        out_dir = pathlib.Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    report_path = out_dir / "report.md"
    build_report(
        {
            "risk_summary": best_risk,
            "hardening_plan": hardening_result,
            "segments": segments,
            "boundary_violations": violations,
            "blast_radius": radius,
        },
        str(report_path),
    )

    graph_path = out_dir / "graph.png"
    draw_graph(
        G,
        out_path=str(graph_path),
        highlight_path=best_path,
        removed_edges=hardening_result.get("removed"),
    )

    # ------------------------------------------------------------
    # 5️⃣ Return a compact result dictionary for programmatic use.
    # ------------------------------------------------------------
    return {
        "risk": best_risk,
        "hardening": hardening_result,
        "segments": segments,
        "boundary_violations": violations,
        "blast_radius": radius,
        "report_path": str(report_path),
        "graph_path": str(graph_path),
    }


if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(description="Attack Path Analyzer")
    parser.add_argument("--input", default="data/sample_small.json", help="Input JSON file")
    parser.add_argument("--out", default="output", help="Output directory")
    args = parser.parse_args()

    try:
        results = run_analysis(input_path=args.input, output_dir=args.out)
        print("Analysis complete. Summary:")
        print(f"  Risk band: {results['risk']['band']}")
        print(f"  Report written to: {results['report_path']}")
        print(f"  Graph image: {results['graph_path']}")
    except (ValueError, FileNotFoundError) as err:
        print(f"[ERROR] {err}", file=sys.stderr)
        sys.exit(1)
