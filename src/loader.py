import json
import pathlib
from typing import Dict, Any


def _error(msg: str) -> None:
    """Raise a ValueError with a clear, one‑line message.
    All validation helpers use this so that the CLI can simply print the
    exception string and exit with a non‑zero status.
    """
    raise ValueError(msg)


def _validate_nodes(nodes: list) -> Dict[str, Dict[str, Any]]:
    """Validate the ``nodes`` list.

    * Every node must contain ``id``, ``zone`` and ``criticality``.
    * ``id`` values must be unique.
    * ``criticality`` must be an integer in the inclusive range 0‑10.

    Returns a mapping ``node_id → node_dict`` for quick lookup when we
    validate edges later.
    """
    node_map: Dict[str, Dict[str, Any]] = {}
    for idx, node in enumerate(nodes):
        if not isinstance(node, dict):
            _error(f"Node at index {idx} is not an object.")
        for key in ("id", "zone", "criticality"):
            if key not in node:
                _error(f"Node {node.get('id', f'#{idx}')}: missing required field '{key}'.")
        nid = node["id"]
        if nid in node_map:
            _error(f"Duplicate node id '{nid}'.")
        crit = node["criticality"]
        if not isinstance(crit, int) or not (0 <= crit <= 10):
            _error(f"Node '{nid}': criticality must be an integer in [0,10].")
        node_map[nid] = node
    return node_map


def _validate_edges(edges: list, node_ids: set) -> None:
    """Validate the ``edges`` list.

    * Each edge must contain ``src``, ``dst``, ``p`` and ``required``.
    * ``src`` and ``dst`` must reference existing node ids.
    * ``(src, dst)`` directed pairs must be unique.
    * ``p`` must be a number strictly greater than 0 and at most 1.
    * ``required`` must be a boolean.
    """
    seen_edges = set()
    for idx, edge in enumerate(edges):
        if not isinstance(edge, dict):
            _error(f"Edge at index {idx} is not an object.")
        for key in ("src", "dst", "p", "required"):
            if key not in edge:
                _error(f"Edge {idx}: missing required field '{key}'.")
        src, dst = edge["src"], edge["dst"]
        if src not in node_ids:
            _error(f"Edge {idx}: source node '{src}' does not exist.")
        if dst not in node_ids:
            _error(f"Edge {idx}: destination node '{dst}' does not exist.")
        if (src, dst) in seen_edges:
            _error(f"Duplicate directed edge '{src}' -> '{dst}' at index {idx}.")
        seen_edges.add((src, dst))
        p = edge["p"]
        if not isinstance(p, (int, float)):
            _error(f"Edge {idx}: probability 'p' must be a number.")
        if not (0 < p <= 1):
            _error(f"Edge {idx}: probability 'p' must be in (0, 1]. Got {p}.")
        if not isinstance(edge["required"], bool):
            _error(f"Edge {idx}: field 'required' must be true or false.")


def _validate_entry_and_targets(entry: Any, targets: Any, node_ids: set) -> None:
    """Validate ``entry`` and ``targets`` fields.

    * ``entry`` must be a string node id present in ``node_ids``.
    * ``targets`` must be a non‑empty list of node ids, each present in ``node_ids``.
    """
    if not isinstance(entry, str):
        _error("Field 'entry' must be a string node id.")
    if entry not in node_ids:
        _error(f"Entry node '{entry}' does not exist in the node list.")
    if not isinstance(targets, list) or not targets:
        _error("Field 'targets' must be a non‑empty list of node ids.")
    for tgt in targets:
        if not isinstance(tgt, str):
            _error(f"Target '{tgt}' is not a string node id.")
        if tgt not in node_ids:
            _error(f"Target node '{tgt}' does not exist in the node list.")


def validate_network(data: Any) -> dict:
    """Validate an in-memory network specification dictionary.

    Parameters
    ----------
    data: dict
        Dictionary containing 'nodes', 'edges', 'entry', and 'targets'.

    Returns
    -------
    dict
        The validated dictionary.
    """
    if not isinstance(data, dict):
        _error("Network data must be a dictionary.")

    # Top‑level keys that must exist
    for key in ("nodes", "edges", "entry", "targets"):
        if key not in data:
            _error(f"Missing top‑level field '{key}'.")

    # Nodes
    nodes = data["nodes"]
    if not isinstance(nodes, list) or not nodes:
        _error("Field 'nodes' must be a non‑empty list.")
    node_map = _validate_nodes(nodes)
    node_ids = set(node_map)

    # Edges
    edges = data["edges"]
    if not isinstance(edges, list):
        _error("Field 'edges' must be a list.")
    _validate_edges(edges, node_ids)

    # Entry and targets
    _validate_entry_and_targets(data["entry"], data["targets"], node_ids)

    return data


def load_json(path: str) -> dict:
    """Load a network description JSON file and validate its contents.

    Parameters
    ----------
    path: str
        Path to the JSON file.

    Returns
    -------
    dict
        The parsed JSON dictionary *exactly* as it appears in the file.
        Any validation problem raises ``ValueError`` with a clear one‑line
        message, which the CLI can surface to the user.
    """
    p = pathlib.Path(path)
    if not p.is_file():
        _error(f"File not found: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _error(f"Invalid JSON syntax: {exc.msg}")

    return validate_network(data)
