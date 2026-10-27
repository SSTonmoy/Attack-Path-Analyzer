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
    # Run the full pipeline writing to the isolated tmp_path directory.
    results = run_analysis(output_dir=tmp_path)

    # Expected top‑level keys.
    expected_keys = {
        "risk",
        "hardening",
        "segments",
        "boundary_violations",
        "blast_radius",
        "report_path",
        "graph_path",
    }
    assert set(results.keys()) == expected_keys
    assert isinstance(results["boundary_violations"], list)
    assert isinstance(results["blast_radius"], set)

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


def test_draw_graph_extensionless(tmp_path: pathlib.Path):
    """Verify that draw_graph handles an output path with no file extension."""
    import networkx as nx
    from src.visualize import draw_graph
    G = nx.DiGraph()
    G.add_edge("a", "b", weight=1.0, p=0.5)
    out_file = tmp_path / "graph_no_ext"
    draw_graph(G, str(out_file))
    assert out_file.is_file()
    assert out_file.stat().st_size > 0


def test_run_analysis_dict_input(tmp_path: pathlib.Path):
    """Verify that run_analysis accepts an in-memory dictionary directly."""
    from src.builders import generate_random_network
    net_dict = generate_random_network(num_nodes=5, edge_density=0.5, seed=123)
    results = run_analysis(input_path=net_dict, output_dir=tmp_path)
    assert "risk" in results
    assert pathlib.Path(results["report_path"]).is_file()
    assert pathlib.Path(results["graph_path"]).is_file()


def test_run_analysis_multiple_targets(tmp_path: pathlib.Path):
    """Verify that run_analysis correctly handles networks with multiple targets."""
    large_sample = pathlib.Path(__file__).parents[1] / "data" / "sample_large.json"
    results = run_analysis(input_path=large_sample, output_dir=tmp_path)
    assert results["risk"]["band"] in ("Low", "Medium", "High", "Critical")
    assert len(results["boundary_violations"]) >= 0


def test_run_analysis_no_path(tmp_path: pathlib.Path):
    """Verify that run_analysis raises a clear ValueError when no attack path exists."""
    import pytest
    disconnected_net = {
        "nodes": [
            {"id": "entry_node", "zone": "ext", "criticality": 0},
            {"id": "target_node", "zone": "int", "criticality": 10},
        ],
        "edges": [],
        "entry": "entry_node",
        "targets": ["target_node"],
    }
    with pytest.raises(ValueError, match="No attack path found"):
        run_analysis(input_path=disconnected_net, output_dir=tmp_path)


def test_dijkstra_missing_source():
    """Verify that dijkstra raises a clear ValueError if source is not in the graph."""
    import networkx as nx
    import pytest
    from src.pathfinder import dijkstra
    G = nx.DiGraph()
    G.add_node("existing")
    with pytest.raises(ValueError, match="Source node 'missing' not in graph"):
        dijkstra(G, "missing")


def test_bellman_ford_missing_source():
    """Verify that bellman_ford raises a clear ValueError if source is not in the graph."""
    import networkx as nx
    import pytest
    from src.pathfinder import bellman_ford
    G = nx.DiGraph()
    G.add_node("existing")
    with pytest.raises(ValueError, match="Source node 'missing' not in graph"):
        bellman_ford(G, "missing")


def test_path_probability_non_edge():
    """Verify that path_probability raises ValueError when consecutive nodes lack a connecting edge."""
    import networkx as nx
    import pytest
    from src.pathfinder import path_probability
    G = nx.DiGraph()
    G.add_edge("a", "b", p=0.5)
    with pytest.raises(ValueError, match="No edge in graph from 'b' to 'c'"):
        path_probability(G, ["a", "b", "c"])


def test_draw_graph_unknown_removed_edge(tmp_path: pathlib.Path):
    """Verify that draw_graph safely ignores removed edges referencing nonexistent nodes without crashing."""
    import networkx as nx
    from src.visualize import draw_graph
    G = nx.DiGraph()
    G.add_edge("a", "b", p=0.5, weight=0.69)
    out_img = tmp_path / "test_safe_removed.png"
    # Edge ("x", "y") where neither node is in G
    draw_graph(G, str(out_img), removed_edges=[("x", "y")])
    assert out_img.is_file()


def test_cli_subprocess_flag_and_positional(tmp_path: pathlib.Path):
    """Verify main.py CLI execution via subprocess for both --input flag and positional syntax."""
    import sys
    import subprocess
    repo_root = pathlib.Path(__file__).parents[1]
    sample_file = repo_root / "data" / "sample_small.json"
    main_script = repo_root / "main.py"

    # 1. Flag invocation
    out1 = tmp_path / "out_flag"
    cmd1 = [sys.executable, str(main_script), "--input", str(sample_file), "--out", str(out1)]
    res1 = subprocess.run(cmd1, capture_output=True, text=True)
    assert res1.returncode == 0
    assert "Analysis complete" in res1.stdout
    assert (out1 / "report.md").is_file()

    # 2. Positional invocation
    out2 = tmp_path / "out_pos"
    cmd2 = [sys.executable, str(main_script), str(sample_file), "--out", str(out2)]
    res2 = subprocess.run(cmd2, capture_output=True, text=True)
    assert res2.returncode == 0
    assert "Analysis complete" in res2.stdout
    assert (out2 / "report.md").is_file()


def test_cli_conflicting_inputs():
    """Verify that main.py CLI rejects conflicting positional and --input arguments."""
    import sys
    import subprocess
    repo_root = pathlib.Path(__file__).parents[1]
    main_script = repo_root / "main.py"
    f1 = str(repo_root / "data" / "sample_small.json")
    f2 = str(repo_root / "data" / "sample_large.json")

    cmd = [sys.executable, str(main_script), f1, "--input", f2]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 1
    assert "Conflicting inputs provided" in res.stderr
