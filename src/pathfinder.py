import heapq
from typing import Dict, List, Tuple
import networkx as nx


def dijkstra(
    graph: nx.DiGraph, source: str, **kwargs
) -> Tuple[Dict[str, float], Dict[str, str | None]] | List[str]:
    """Hand‑written Dijkstra's algorithm.

    If a ``target`` keyword argument is supplied, the function returns the
    reconstructed shortest path (list of node identifiers) instead of the
    ``(dist, prev)`` tuple. This matches the test suite's usage where
    ``dijkstra(G, source="internet", target="db01")`` is expected to yield a
    path list.
    """
    # Initialise distances and predecessor map
    dist: Dict[str, float] = {n: float("inf") for n in graph.nodes}
    prev: Dict[str, str | None] = {n: None for n in graph.nodes}
    dist[source] = 0.0

    # Priority queue of (distance, node). ``heapq`` guarantees the smallest
    # distance is popped first.
    heap: List[Tuple[float, str]] = [(0.0, source)]
    visited = set()

    while heap:
        cur_dist, u = heapq.heappop(heap)
        if u in visited:
            continue
        visited.add(u)
        for v in graph.successors(u):
            w = graph[u][v].get("weight", 0.0)
            alt = cur_dist + w
            if alt < dist[v]:
                dist[v] = alt
                prev[v] = u
                heapq.heappush(heap, (alt, v))

    # If a target was supplied, reconstruct and return the path.
    target = kwargs.get("target")
    if target is not None:
        path = reconstruct_path(prev, source, target)
        if path is None:
            raise ValueError(f"No path from {source} to {target}")
        return path

    return dist, prev


def reconstruct_path(
    prev: Dict[str, str | None], source: str, target: str
) -> List[str] | None:
    """Reconstruct a path from ``source`` to ``target`` using the predecessor map.

    Returns ``None`` if ``target`` is unreachable from ``source``.
    """
    if target not in prev:
        return None
    if prev[target] is None and target != source:
        return None
    path: List[str] = []
    cur = target
    while cur is not None:
        path.append(cur)
        cur = prev.get(cur)
    path.reverse()
    if path[0] != source:
        return None
    return path


def bellman_ford(
    graph: nx.DiGraph, source: str
) -> Tuple[Dict[str, float], Dict[str, str | None]]:
    """Hand‑written Bellman‑Ford algorithm.

    Returns the same ``dist`` and ``prev`` structures as ``dijkstra``.
    Raises ``ValueError`` if a reachable negative‑weight cycle exists.
    """
    dist: Dict[str, float] = {n: float("inf") for n in graph.nodes}
    prev: Dict[str, str | None] = {n: None for n in graph.nodes}
    dist[source] = 0.0
    edges = [(u, v, graph[u][v].get("weight", 0.0)) for u, v in graph.edges]
    V = graph.number_of_nodes()
    for _ in range(V - 1):
        updated = False
        for u, v, w in edges:
            if dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
                prev[v] = u
                updated = True
        if not updated:
            break
    for u, v, w in edges:
        if dist[u] + w < dist[v]:
            raise ValueError("Graph contains a reachable negative‑weight cycle")
    return dist, prev


def top_k_paths(
    graph: nx.DiGraph, source: str, target: str, k: int = 3
) -> List[List[str]]:
    """Return the ``k`` best simple paths ordered by total ``weight``.

    The implementation relies on ``networkx.shortest_simple_paths`` (Yen's
    algorithm) which yields paths from lowest to highest weight.
    """
    if k <= 0:
        return []
    gen = nx.shortest_simple_paths(graph, source, target, weight="weight")
    paths: List[List[str]] = []
    for _ in range(k):
        try:
            paths.append(next(gen))
        except StopIteration:
            break
    return paths


def path_probability(graph: nx.DiGraph, path: List[str]) -> float:
    """Calculate the product of the ``p`` attribute for a given node list.

    Returns ``1.0`` for an empty or single‑node path.
    """
    if len(path) < 2:
        return 1.0
    prob = 1.0
    for src, dst in zip(path, path[1:]):
        prob *= graph[src][dst]["p"]
    return prob
