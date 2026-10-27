# tests/test_risk.py
"""Tests for the risk scoring module.

The tests use the small sample network ``sample_small.json`` which defines a
few nodes with ``exploit_prob`` edges and a ``criticality`` attribute on the
target nodes.  We build the graph with the existing ``graph_builder`` helper and
exercise ``risk.score_path`` on two representative paths.
"""

from pathlib import Path

import networkx as nx
import pytest

# Import the helper functions from the package under test.
from src.loader import load_json
from src.graph_builder import build_graph
from src.pathfinder import dijkstra
from src.risk import score_path

# Helper to load the sample graph used across tests.
def _load_sample_graph() -> nx.DiGraph:
    data_path = Path(__file__).parents[1] / "data" / "sample_small.json"
    data = load_json(str(data_path))
    return build_graph(data)


def test_score_path_high_risk():
    """The most likely path should be classified as *High* risk.

    For ``sample_small.json`` the shortest‑probability path from ``internet``
    to the critical database ``db01`` is:

    ``internet → web01 → app01 → db01``

    The edge probabilities (as defined in the fixture) yield a total
    ``probability ≈ 0.504`` and the target node ``db01`` has a criticality of 10.
    Therefore ``score = 0.504 * 10 ≈ 5.04`` which falls into the ``High`` band.
    """
    G = _load_sample_graph()
    # Compute the most likely path using Dijkstra (which works on the log‑weights).
    path = dijkstra(G, source="internet", target="db01")
    result = score_path(G, path)

    assert pytest.approx(result["prob"], rel=1e-3) == 0.504
    assert result["criticality"] == 10
    assert pytest.approx(result["score"], rel=1e-3) == 5.04
    assert result["band"] == "High"


def test_score_path_low_risk():
    """A less likely path should fall into the *Low* band.

    Using an alternative route ``internet → mail01 → admin-pc → db01`` the
    cumulative probability is lower (≈ 0.21) while the criticality of ``db01``
    stays the same.  The resulting score ≈ 2.1 yields the ``Low`` band.
    """
    G = _load_sample_graph()
    alt_path = ["internet", "mail01", "admin-pc", "db01"]
    result = score_path(G, alt_path)

    assert pytest.approx(result["prob"], rel=1e-3) == 0.21
    assert result["criticality"] == 10
    assert pytest.approx(result["score"], rel=1e-3) == 2.1
    assert result["band"] == "Low"

