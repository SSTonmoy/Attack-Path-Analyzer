"""visualize.py
=================

Utility for rendering a directed attack‑path graph to an image file.
The public signature is frozen in ``INTERFACES.md`` and must match exactly:

```python
draw_graph(g: nx.DiGraph, out_path: str, highlight_path=None, removed_edges=None) -> None
```

* ``g`` – the graph to draw.
* ``out_path`` – full path (including filename) where the image will be saved.
* ``highlight_path`` – optional list of node identifiers representing a path to
  emphasise (drawn in a distinct colour).
* ``removed_edges`` – optional list of edge tuples ``(src, dst)`` that should be
  drawn as *removed* (e.g., dashed red lines).

The implementation uses ``matplotlib`` with the non‑interactive ``Agg`` backend
so it works in headless environments (CI, tests).  Nodes are positioned using
NetworkX's spring layout for reproducibility.
"""

from __future__ import annotations

import pathlib
from typing import Iterable, Tuple, Optional

import matplotlib

# Use a non‑interactive backend – required for headless test environments.
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx


def _prepare_layout(g: nx.DiGraph) -> dict:
    """Return a deterministic layout for *g*.

    ``spring_layout`` with a fixed seed ensures the same node positions across
    runs, which is helpful for stable visual output in tests.
    """
    return nx.spring_layout(g, seed=42)


def draw_graph(
    g: nx.DiGraph,
    out_path: str,
    highlight_path: Optional[Iterable[str]] = None,
    removed_edges: Optional[Iterable[Tuple[str, str]]] = None,
) -> None:
    """Render *g* to ``out_path``.

    Parameters
    ----------
    g: nx.DiGraph
        The attack‑path graph.
    out_path: str
        Destination filename (e.g., ``"graph.png"``).  Parent directories are
        created automatically.
    highlight_path: iterable of str, optional
        Sequence of node identifiers that form a path to be highlighted in
        ``orange``.  Nodes and the connecting edges are drawn with a larger
        linewidth.
    removed_edges: iterable of (src, dst) tuples, optional
        Edges that should appear as *removed* – drawn in ``red`` with a dashed
        style.
    """
    # Ensure the output directory exists.
    out_p = pathlib.Path(out_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)

    pos = _prepare_layout(g)

    plt.figure(figsize=(8, 6))
    try:
        ax = plt.gca()
        ax.set_axis_off()

        # Base drawing – all nodes and edges.
        nx.draw_networkx_nodes(g, pos, node_color="lightblue", node_size=500, ax=ax)
        nx.draw_networkx_labels(g, pos, font_size=9, ax=ax)

        # Normal edges.
        nx.draw_networkx_edges(
            g,
            pos,
            edge_color="gray",
            width=1.5,
            arrows=True,
            arrowstyle="->",
            arrowsize=12,
            ax=ax,
        )

        # Highlighted path – if supplied.
        if highlight_path:
            path_nodes = list(highlight_path)
            # Draw path nodes with a distinct colour.
            nx.draw_networkx_nodes(
                g,
                pos,
                nodelist=path_nodes,
                node_color="orange",
                node_size=600,
                ax=ax,
            )
            # Draw edges along the path.
            path_edges = list(zip(path_nodes, path_nodes[1:]))
            nx.draw_networkx_edges(
                g,
                pos,
                edgelist=path_edges,
                edge_color="orange",
                width=3,
                arrows=True,
                arrowstyle="->",
                arrowsize=15,
                ax=ax,
            )

        # Removed edges – drawn red and dashed (safely filtered for node presence in pos).
        if removed_edges:
            safe_removed = [
                (u, v) for u, v in removed_edges
                if u in pos and v in pos
            ]
            if safe_removed:
                nx.draw_networkx_edges(
                    g,
                    pos,
                    edgelist=safe_removed,
                    edge_color="red",
                    style="dashed",
                    width=2,
                    arrows=True,
                    arrowstyle="->",
                    arrowsize=12,
                    ax=ax,
                )

        plt.tight_layout()
        fmt = out_p.suffix.lstrip(".").lower() or "png"
        plt.savefig(out_path, format=fmt)
    finally:
        plt.close()


__all__ = ["draw_graph"]
