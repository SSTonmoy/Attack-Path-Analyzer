"""segmentation.py
===================

Utility for partitioning a directed graph into *segments* (weakly‑connected
components).  The public API is frozen in ``INTERFACES.md`` and must match the
signatures exactly:

```
class UnionFind:
    find(x)
    union(a, b)
    connected(a, b)

find_segments(g: nx.DiGraph) -> dict[int, set[str]]
```

The implementation uses a classic Union‑Find (disjoint‑set) data structure with
path compression and union‑by‑rank for near‑constant‑time operations.
"""

from __future__ import annotations

from typing import Dict, Set, List, Tuple

import networkx as nx


class UnionFind:
    """Disjoint‑set data structure.

    The container lazily creates entries for elements on first access, allowing
    callers to add items without an explicit ``make_set`` call.
    """

    def __init__(self) -> None:
        self._parent: Dict[str, str] = {}
        self._rank: Dict[str, int] = {}

    def _make_set(self, x: str) -> None:
        """Initialise a singleton set for *x* if it does not yet exist."""
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0

    def find(self, x: str) -> str:
        """Return the representative element (root) of the set containing *x*.

        Path compression flattens the tree so subsequent ``find`` calls are fast.
        """
        self._make_set(x)
        if self._parent[x] != x:
            # Recursively find the root and compress the path.
            self._parent[x] = self.find(self._parent[x])
        return self._parent[x]

    def union(self, a: str, b: str) -> None:
        """Merge the sets containing *a* and *b*.

        Union‑by‑rank attaches the shorter tree under the taller one, keeping the
        resulting forest shallow.
        """
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a == root_b:
            return  # already in the same set

        rank_a = self._rank[root_a]
        rank_b = self._rank[root_b]
        if rank_a < rank_b:
            self._parent[root_a] = root_b
        elif rank_a > rank_b:
            self._parent[root_b] = root_a
        else:
            # Ranks are equal – choose one as new root and increase its rank.
            self._parent[root_b] = root_a
            self._rank[root_a] += 1

    def connected(self, a: str, b: str) -> bool:
        """Return ``True`` if *a* and *b* belong to the same set."""
        return self.find(a) == self.find(b)


def find_segments(g: nx.DiGraph) -> Dict[int, Set[str]]:
    """Partition *g* into weakly‑connected segments.

    The algorithm treats each directed edge as an undirected connection – two
    vertices belong to the same segment if there is any path between them when
    edge direction is ignored.  The result is a mapping from a **stable integer
    identifier** (0‑based) to the set of node identifiers belonging to that
    segment.
    """
    uf = UnionFind()

    # Ensure every node appears in the union‑find structure even if it has no
    # incident edges.
    for node in g.nodes:
        uf._make_set(node)

    # Merge the endpoints of each edge, ignoring direction.
    for u, v in g.edges:
        uf.union(u, v)

    # Collect members of each root into a temporary dict.
    root_to_nodes: Dict[str, Set[str]] = {}
    for node in g.nodes:
        root = uf.find(node)
        root_to_nodes.setdefault(root, set()).add(node)

    # Convert the arbitrary root keys to stable integer IDs.
    segments: Dict[int, Set[str]] = {}
    for idx, nodes in enumerate(root_to_nodes.values()):
        segments[idx] = nodes

    return segments


def boundary_violations(g: nx.DiGraph) -> List[Tuple[str, str]]:
    """Return a list of edges (u, v) where u and v belong to different security zones."""
    violations: List[Tuple[str, str]] = []
    for u, v in g.edges:
        zone_u = g.nodes[u].get("zone")
        zone_v = g.nodes[v].get("zone")
        if zone_u != zone_v:
            violations.append((u, v))
    return violations


def blast_radius(g: nx.DiGraph, entry: str) -> Set[str]:
    """Return the set of all nodes reachable from entry using BFS on the directed graph."""
    if entry not in g:
        return set()
    visited: Set[str] = {entry}
    queue: List[str] = [entry]
    while queue:
        cur = queue.pop(0)
        for neighbor in g.successors(cur):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return visited


__all__ = ["UnionFind", "find_segments", "boundary_violations", "blast_radius"]
