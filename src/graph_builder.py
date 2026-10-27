import math
import networkx as nx
from typing import Dict


def build_graph(data: Dict) -> nx.DiGraph:
    """Convert the validated JSON dictionary into a weighted directed graph.

    Parameters
    ----------
    data: dict
        The dictionary returned by ``loader.load_json``.  It must contain the
        keys ``nodes`` and ``edges`` as described in the specification.

    Returns
    -------
    nx.DiGraph
        Directed graph where:
        * each node stores ``zone`` (str) and ``criticality`` (int)
        * each edge stores ``p`` (float), ``required`` (bool) and ``weight``
          where ``weight = -ln(p)`` (the additive cost for Dijkstra).
    """
    G = nx.DiGraph()

    # ---- Add nodes -----------------------------------------------------
    for node in data["nodes"]:
        nid = node["id"]
        G.add_node(
            nid,
            zone=node["zone"],
            criticality=int(node["criticality"]),
        )

    # ---- Add edges -----------------------------------------------------
    for edge in data["edges"]:
        src = edge["src"]
        dst = edge["dst"]
        p = float(edge["p"])
        if p <= 0.0:
            raise ValueError(f"Edge probability must be > 0 (got {p}) for edge {src}->{dst}")
        required = bool(edge["required"])
        weight = -math.log(p)  # negative log turns multiplication into addition
        edge_attrs = {
            "p": p,
            "required": required,
            "weight": weight,
        }
        if "vuln" in edge and edge["vuln"]:
            edge_attrs["vuln"] = str(edge["vuln"])
        G.add_edge(src, dst, **edge_attrs)

    return G
