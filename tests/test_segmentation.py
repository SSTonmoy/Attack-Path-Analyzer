"""tests/test_segmentation.py
=============================

Test the ``find_segments`` function from ``src.segmentation``.  For the small
sample fixture ``sample_small.json`` the underlying undirected graph is fully
connected, so a single segment containing every node is expected.
"""

from pathlib import Path

import networkx as nx
import pytest

from src.loader import load_json
from src.graph_builder import build_graph
from src.segmentation import find_segments


def _load_sample_graph() -> nx.DiGraph:
    data_path = Path(__file__).parents[1] / "data" / "sample_small.json"
    data = load_json(str(data_path))
    return build_graph(data)


def test_find_segments_single_component():
    G = _load_sample_graph()
    segments = find_segments(G)
    # All nodes should belong to a single segment with id 0.
    assert len(segments) == 1
    all_nodes = set(G.nodes)
    assert segments[0] == all_nodes
