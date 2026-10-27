# INTERFACES.md

This file holds the public API signatures for the project. These signatures represent the contract between modules, tests, CLI, and dashboard.

```python
# main.py
run_analysis(input_path: str | pathlib.Path | dict | None = None, output_dir: str | pathlib.Path | None = None) -> dict

# loader.py
load_json(path: str) -> dict
validate_network(data: dict) -> dict

# graph_builder.py
build_graph(data: dict) -> nx.DiGraph

# builders.py
parse_csv_content(csv_input: str | pathlib.Path | io.StringIO) -> list[dict[str, str]]
csv_to_network_dict(nodes_csv: str | pathlib.Path | io.StringIO, edges_csv: str | pathlib.Path | io.StringIO, entry: str | None = None, targets: Sequence[str] | None = None) -> dict
generate_random_network(num_nodes: int = 7, edge_density: float = 0.35, seed: int | None = 42) -> dict

# pathfinder.py
dijkstra(graph: nx.DiGraph, source: str, target: str | None = None) -> tuple[dict, dict] | list[str]
bellman_ford(graph: nx.DiGraph, source: str) -> tuple[dict, dict]
reconstruct_path(prev: dict, source: str, target: str) -> list[str] | None
path_probability(graph: nx.DiGraph, path: list[str]) -> float
top_k_paths(graph: nx.DiGraph, source: str, target: str, k: int = 3) -> list[list[str]]

# risk.py
score_path(graph: nx.DiGraph, path: list[str]) -> dict

# segmentation.py
class UnionFind:
    find(x: str) -> str
    union(a: str, b: str) -> None
    connected(a: str, b: str) -> bool

find_segments(g: nx.DiGraph) -> dict[int, set[str]]
boundary_violations(g: nx.DiGraph) -> list[tuple[str, str]]
blast_radius(g: nx.DiGraph, entry: str) -> set[str]

# hardening.py
kruskal_mst(g: nx.DiGraph) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]
harden(g: nx.DiGraph, entry: str, targets: list[str]) -> dict

# visualize.py
draw_graph(g: nx.DiGraph, out_path: str, highlight_path=None, removed_edges=None) -> None

# report.py
build_report(results: dict, out_path: str) -> None
```
