INTERFACES.md
==============

This file holds the frozen public API signatures for the project.  The signatures are taken directly from the design document and must not be changed without agreement.

```
# loader.py
load_json(path: str) -> dict

# graph_builder.py
build_graph(data: dict) -> nx.DiGraph

# pathfinder.py
dijkstra(g: nx.DiGraph, src: str) -> (dist: dict, prev: dict)
bellman_ford(g: nx.DiGraph, src: str) -> (dist: dict, prev: dict)
reconstruct_path(prev: dict, src: str, tgt: str) -> list[str] | None
path_probability(g: nx.DiGraph, path: list[str]) -> float
top_k_paths(g: nx.DiGraph, src: str, tgt: str, k: int = 3) -> list[list[str]]

# risk.py
score_path(g: nx.DiGraph, path: list[str]) -> dict

# segmentation.py
class UnionFind:
    find(x)
    union(a, b)
    connected(a, b)
find_segments(g: nx.DiGraph) -> dict[int, set[str]]
boundary_violations(g: nx.DiGraph) -> list[tuple[str, str]]
blast_radius(g: nx.DiGraph, entry: str) -> set[str]

# hardening.py
kruskal_mst(g: nx.DiGraph) -> (kept: list, removed: list)
harden(g: nx.DiGraph, entry: str, targets: list[str]) -> dict

# visualize.py
draw_graph(g: nx.DiGraph, out_path: str, highlight_path=None, removed_edges=None) -> None

# report.py
build_report(results: dict, out_path: str) -> None
```
```