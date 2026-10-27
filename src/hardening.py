"""hardening.py
===================

Implementation of the hardening utilities referenced in ``INTERFACES.md``.
The public API must match exactly:

```python
kruskal_mst(g: nx.DiGraph) -> (kept: list, removed: list)
harden(g: nx.DiGraph, entry: str, targets: list[str]) -> dict
```

* ``kruskal_mst`` builds a Minimum Spanning Tree (MST) of the *undirected*
  version of the directed graph ``g`` using Kruskal's algorithm.  It returns two
  lists of edges – ``kept`` (edges that belong to the MST) and ``removed`` (the
  remaining edges).
* ``harden`` is a thin wrapper that, for the purpose of this project, simply
  calls ``kruskal_mst`` and returns a dictionary containing the same information.

Both functions rely on the ``UnionFind`` implementation from ``src.segmentation``
so that we keep a single authoritative disjoint‑set data structure.
"""

from __future__ import annotations

from typing import List, Tuple, Dict

import networkx as nx

from .segmentation import UnionFind


def kruskal_mst(g: nx.DiGraph) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """Return the edges kept in a Minimum Spanning Tree and those removed.

    The algorithm treats the directed graph as undirected: an edge ``u -> v``
    contributes a single undirected connection between ``u`` and ``v`` with the
    same ``weight`` attribute used for Dijkstra/Bellman‑Ford.

    Parameters
    ----------
    g: nx.DiGraph
        Input graph whose ``weight`` attribute on each edge defines the cost.

    Returns
    -------
    kept: list[tuple[str, str]]
        Edges that belong to the MST.
    removed: list[tuple[str, str]]
        Edges that are discarded because they would form a cycle.
    """
    # Gather all edges with their weight; ignore direction for Kruskal.
    edges: List[Tuple[float, str, str]] = []
    for u, v, data in g.edges(data=True):
        w = data.get("weight", 0.0)
        # Store weight first for easy sorting.
        edges.append((w, u, v))

    # Sort edges by ascending weight.
    edges.sort(key=lambda e: e[0])

    uf = UnionFind()
    # Initialise UnionFind with all nodes.
    for node in g.nodes:
        uf._make_set(node)

    kept: List[Tuple[str, str]] = []
    removed: List[Tuple[str, str]] = []

    # Phase 1: force-include required edges
    for w, u, v in edges:
        if g[u][v].get("required", False):
            uf.union(u, v)
            kept.append((u, v))

    # Phase 2: normal Kruskal for non-required edges
    for w, u, v in edges:
        if g[u][v].get("required", False):
            continue  # already handled
        if not uf.connected(u, v):
            uf.union(u, v)
            kept.append((u, v))
        else:
            removed.append((u, v))

    return kept, removed


def harden(g: nx.DiGraph, entry: str, targets: List[str]) -> Dict[str, List[Tuple[str, str]]]:
    """Hardening helper that returns the MST edge sets.

    In a full implementation this function would compute a *hardening plan*
    that isolates the ``entry`` node from the ``targets`` while preserving a
    minimal set of connections.  For the current step we simply expose the MST
    produced by :func:`kruskal_mst` so that the test suite can verify the basic
    algorithmic behaviour.

    Parameters
    ----------
    g: nx.DiGraph
        The attack‑path graph.
    entry: str
        Identifier of the entry point (e.g., ``"internet"``).
    targets: list[str]
        Critical assets to protect.

    Returns
    -------
    dict
        ``{"kept": [...], "removed": [...]}`` where the lists contain edge
        tuples ``(src, dst)``.
    """
    kept, removed = kruskal_mst(g)
    return {"kept": kept, "removed": removed}


__all__ = ["kruskal_mst", "harden"]
