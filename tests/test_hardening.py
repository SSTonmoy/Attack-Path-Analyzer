"""tests/test_hardening.py
==========================

Simple verification of the hardening helpers.
We build the sample graph, run ``kruskal_mst`` and check that the number of
edges kept plus removed equals the total number of edges and that the kept set
forms a spanning tree (|V|-1 edges for a connected graph).
"""

from pathlib import Path

import networkx as nx
import pytest

from src.loader import load_json
from src.graph_builder import build_graph
from src.hardening import kruskal_mst, harden


def _load_sample_graph() -> nx.DiGraph:
    data_path = Path(__file__).parents[1] / "data" / "sample_small.json"
    data = load_json(str(data_path))
    return build_graph(data)


def test_kruskal_mst_properties():
    G = _load_sample_graph()
    kept, removed = kruskal_mst(G)
    # Total edges should be unchanged.
    assert len(kept) + len(removed) == G.number_of_edges()
    # For a connected undirected graph the MST must contain |V|-1 edges.
    # We treat the directed graph as undirected for this check.
    assert len(kept) == G.number_of_nodes() - 1


def test_harden_returns_mst_structure():
    G = _load_sample_graph()
    result = harden(G, entry="internet", targets=["db01"])
    assert set(result.keys()) == {"kept", "removed"}
    assert isinstance(result["kept"], list)
    assert isinstance(result["removed"], list)
    # Consistency with kruskal_mst.
    kept, removed = kruskal_mst(G)
    assert result["kept"] == kept
    assert result["removed"] == removed
