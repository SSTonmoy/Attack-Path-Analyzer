"""src/builders.py
=================

Utilities for constructing network topologies without manual JSON writing.
Provides:
1. CSV import for nodes and edges into valid network dictionaries.
2. Deterministic random network generation suitable for testing and simulation.
"""

from __future__ import annotations

import csv
import io
import pathlib
import random
from typing import Any, Dict, List, Optional, Sequence


def parse_csv_content(csv_input: str | pathlib.Path | io.StringIO) -> List[Dict[str, str]]:
    """Parse CSV text, file path, or StringIO into a list of row dictionaries."""
    if isinstance(csv_input, pathlib.Path):
        text = csv_input.read_text(encoding="utf-8")
        reader = csv.DictReader(io.StringIO(text))
    elif isinstance(csv_input, str):
        # Check if it is a path string or raw CSV string
        p = pathlib.Path(csv_input)
        if p.exists() and p.is_file():
            text = p.read_text(encoding="utf-8")
            reader = csv.DictReader(io.StringIO(text))
        else:
            reader = csv.DictReader(io.StringIO(csv_input))
    elif isinstance(csv_input, io.StringIO):
        reader = csv.DictReader(csv_input)
    else:
        reader = csv.DictReader(csv_input)

    rows = []
    for r in reader:
        # Strip whitespace from keys and values; safely handle None values
        clean_row = {
            k.strip(): (v.strip() if v is not None else "")
            for k, v in r.items()
            if k is not None
        }
        rows.append(clean_row)
    return rows


def csv_to_network_dict(
    nodes_csv: str | pathlib.Path | io.StringIO,
    edges_csv: str | pathlib.Path | io.StringIO,
    entry: Optional[str] = None,
    targets: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Convert nodes and edges CSV sources into a validated network dictionary.

    Parameters
    ----------
    nodes_csv: str | Path | StringIO
        CSV containing columns: `id`, `zone`, `criticality`.
        Optional columns: `is_entry`, `is_target`.
    edges_csv: str | Path | StringIO
        CSV containing columns: `src`, `dst`, `p`, `required`.
        Optional column: `vuln`.
    entry: Optional[str]
        Explicit entry node ID. If None, uses the first node or one flagged as `is_entry`.
    targets: Optional[Sequence[str]]
        Explicit target node IDs. If None, uses nodes with `is_target=True`, or the node
        with the highest criticality.

    Returns
    -------
    dict
        Dictionary containing `nodes`, `edges`, `entry`, and `targets`.
    """
    node_rows = parse_csv_content(nodes_csv)
    edge_rows = parse_csv_content(edges_csv)

    if not node_rows:
        raise ValueError("Nodes CSV must not be empty.")

    nodes: List[Dict[str, Any]] = []
    detected_entry: Optional[str] = None
    detected_targets: List[str] = []

    for r in node_rows:
        if "id" not in r or "zone" not in r or "criticality" not in r:
            raise ValueError("Nodes CSV must contain 'id', 'zone', and 'criticality' columns.")

        nid = str(r["id"])
        zone = str(r["zone"])
        try:
            criticality = int(r["criticality"])
        except ValueError:
            raise ValueError(f"Node '{nid}': criticality must be an integer.")

        # Check for entry / target flags if present in CSV
        is_entry_val = str(r.get("is_entry", "")).lower() in ("true", "1", "yes")
        is_target_val = str(r.get("is_target", "")).lower() in ("true", "1", "yes")

        if is_entry_val and detected_entry is None:
            detected_entry = nid
        if is_target_val:
            detected_targets.append(nid)

        nodes.append({
            "id": nid,
            "zone": zone,
            "criticality": criticality,
        })

    # Determine entry
    if entry is not None:
        final_entry = entry
    elif detected_entry is not None:
        final_entry = detected_entry
    else:
        final_entry = nodes[0]["id"]

    # Determine targets
    if targets is not None and len(targets) > 0:
        final_targets = list(targets)
    elif detected_targets:
        final_targets = detected_targets
    else:
        # Pick node with maximum criticality (excluding entry if multiple nodes exist)
        candidate_nodes = [n for n in nodes if n["id"] != final_entry] or nodes
        highest_crit_node = max(candidate_nodes, key=lambda n: n["criticality"])
        final_targets = [highest_crit_node["id"]]

    edges: List[Dict[str, Any]] = []
    for idx, r in enumerate(edge_rows):
        for col in ("src", "dst", "p", "required"):
            if col not in r:
                raise ValueError(f"Edges CSV row {idx}: missing required column '{col}'.")

        src = str(r["src"])
        dst = str(r["dst"])
        try:
            p = float(r["p"])
        except ValueError:
            raise ValueError(f"Edge {src}->{dst}: probability 'p' must be a number.")

        req_str = str(r["required"]).strip().lower()
        required = req_str in ("true", "1", "yes", "t")

        edge_dict: Dict[str, Any] = {
            "src": src,
            "dst": dst,
            "p": p,
            "required": required,
        }
        if "vuln" in r and r["vuln"]:
            edge_dict["vuln"] = str(r["vuln"])

        edges.append(edge_dict)

    return {
        "nodes": nodes,
        "edges": edges,
        "entry": final_entry,
        "targets": final_targets,
    }


def generate_random_network(
    num_nodes: int = 7,
    edge_density: float = 0.35,
    seed: Optional[int] = 42,
) -> Dict[str, Any]:
    """Deterministically generate a synthetic network topology guaranteed to pass validation.

    Parameters
    ----------
    num_nodes: int
        Total number of nodes (minimum 3).
    edge_density: float
        Additional edge creation probability between 0.0 and 1.0.
    seed: Optional[int]
        Random seed for full reproducibility. Same seed produces exact same network.

    Returns
    -------
    dict
        Valid network dictionary with guaranteed path from entry to target.
    """
    if num_nodes < 3:
        raise ValueError("Random network requires at least 3 nodes.")

    rng = random.Random(seed)

    zones = ["dmz", "internal", "restricted", "office"]

    # 1. Generate Nodes
    # Entry node
    nodes = [{"id": "internet", "zone": "internet", "criticality": 0}]

    # Intermediate nodes
    for i in range(1, num_nodes - 1):
        zone = zones[i % len(zones)]
        crit = rng.randint(2, 8)
        nodes.append({"id": f"srv_{i:02d}", "zone": zone, "criticality": crit})

    # Target node
    target_id = f"db_{num_nodes-1:02d}"
    nodes.append({"id": target_id, "zone": "restricted", "criticality": 10})

    entry_id = "internet"
    targets = [target_id]

    # 2. Build backbone path: ensures graph is connected and path exists
    edges: List[Dict[str, Any]] = []
    existing_edges = set()

    node_ids = [n["id"] for n in nodes]
    for i in range(len(node_ids) - 1):
        u = node_ids[i]
        v = node_ids[i + 1]
        p = round(rng.uniform(0.5, 0.95), 2)
        required = (i == 0)  # Make first edge required
        edges.append({
            "src": u,
            "dst": v,
            "vuln": f"exploit-{u}-{v}",
            "p": p,
            "required": required,
        })
        existing_edges.add((u, v))

    # 3. Add extra edges according to edge_density
    for i in range(len(node_ids)):
        for j in range(len(node_ids)):
            if i == j:
                continue
            u = node_ids[i]
            v = node_ids[j]
            if (u, v) in existing_edges:
                continue
            # Roll for extra edge
            if rng.random() < edge_density:
                p = round(rng.uniform(0.1, 0.8), 2)
                edges.append({
                    "src": u,
                    "dst": v,
                    "vuln": f"lateral-{u}-{v}",
                    "p": p,
                    "required": False,
                })
                existing_edges.add((u, v))

    return {
        "nodes": nodes,
        "edges": edges,
        "entry": entry_id,
        "targets": targets,
    }


__all__ = [
    "parse_csv_content",
    "csv_to_network_dict",
    "generate_random_network",
]
