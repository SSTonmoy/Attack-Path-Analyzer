"""tests/test_builders.py
======================

Tests for network builder helpers:
- CSV conversion to valid network schema
- Deterministic random network generation
"""

import json
import tempfile
import pathlib
import pytest

from src.builders import csv_to_network_dict, generate_random_network
from src.loader import load_json
from src.graph_builder import build_graph
from src.pathfinder import dijkstra


def test_csv_to_network_dict_valid():
    """Verify that CSV text is correctly converted and passes load_json validation."""
    nodes_csv = """id,zone,criticality
internet,internet,0
web_srv,dmz,4
app_srv,internal,6
db_main,restricted,10
"""
    edges_csv = """src,dst,p,required,vuln
internet,web_srv,0.9,true,cve-web
web_srv,app_srv,0.8,true,cve-app
app_srv,db_main,0.7,false,cve-db
web_srv,db_main,0.1,false,firewall-leak
"""
    net_dict = csv_to_network_dict(nodes_csv, edges_csv, entry="internet", targets=["db_main"])

    assert net_dict["entry"] == "internet"
    assert net_dict["targets"] == ["db_main"]
    assert len(net_dict["nodes"]) == 4
    assert len(net_dict["edges"]) == 4

    # Verify that it passes loader validation when saved as JSON
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(net_dict, f)
        temp_path = f.name

    try:
        loaded = load_json(temp_path)
        assert loaded["entry"] == "internet"
        assert len(loaded["nodes"]) == 4
    finally:
        pathlib.Path(temp_path).unlink(missing_ok=True)


def test_csv_to_network_dict_flags():
    """Verify auto-detection of entry and target from CSV flags."""
    nodes_csv = """id,zone,criticality,is_entry,is_target
gw01,external,0,true,false
mid01,internal,5,false,false
core_db,internal,10,false,true
"""
    edges_csv = """src,dst,p,required
gw01,mid01,0.85,true
mid01,core_db,0.65,false
"""
    net_dict = csv_to_network_dict(nodes_csv, edges_csv)
    assert net_dict["entry"] == "gw01"
    assert net_dict["targets"] == ["core_db"]


def test_csv_to_network_dict_invalid():
    """Verify appropriate error on invalid or empty CSV input."""
    with pytest.raises(ValueError, match="must not be empty"):
        csv_to_network_dict("", "")

    bad_nodes_csv = """id,criticality
n1,5
"""
    bad_edges_csv = """src,dst
n1,n2
"""
    with pytest.raises(ValueError, match="zone"):
        csv_to_network_dict(bad_nodes_csv, bad_edges_csv)


def test_parse_csv_content_ragged_rows():
    """Verify that rows with fewer columns than the header do not crash with AttributeError."""
    from src.builders import parse_csv_content
    import io
    ragged_csv = "id,zone,criticality\nnode1,dmz\nnode2,internal,5\n"
    rows = parse_csv_content(io.StringIO(ragged_csv))
    assert len(rows) == 2
    assert rows[0]["id"] == "node1"
    assert rows[0]["zone"] == "dmz"
    assert rows[0]["criticality"] == ""
    assert rows[1]["criticality"] == "5"


def test_generate_random_network_valid_and_passes_loader():
    """Verify that random networks always pass schema validation and can find attack paths."""
    net_dict = generate_random_network(num_nodes=8, edge_density=0.4, seed=42)

    assert len(net_dict["nodes"]) == 8
    assert net_dict["entry"] == "internet"
    assert len(net_dict["targets"]) == 1
    assert len(net_dict["edges"]) >= 7  # at least the backbone path

    # Dump to temporary file and pass through full loader validation
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(net_dict, f)
        temp_path = f.name

    try:
        validated_data = load_json(temp_path)
        assert validated_data["entry"] == "internet"
        # Test graph building and shortest path
        G = build_graph(validated_data)
        path = dijkstra(G, source=validated_data["entry"], target=validated_data["targets"][0])
        assert isinstance(path, list)
        assert len(path) >= 2
    finally:
        pathlib.Path(temp_path).unlink(missing_ok=True)


def test_generate_random_network_deterministic_seed():
    """Verify that the same random seed produces the exact same network."""
    net_seed_42_a = generate_random_network(num_nodes=6, edge_density=0.3, seed=42)
    net_seed_42_b = generate_random_network(num_nodes=6, edge_density=0.3, seed=42)
    net_seed_99 = generate_random_network(num_nodes=6, edge_density=0.3, seed=99)

    # Identical seed produces identical result
    assert net_seed_42_a == net_seed_42_b

    # Different seed produces different edge probabilities or edges
    assert net_seed_42_a != net_seed_99


def test_csv_with_bom_text_and_file(tmp_path: pathlib.Path):
    """Verify that CSV files or strings with Excel UTF-8 BOM are correctly parsed."""
    nodes_bom = "\ufeffid,zone,criticality\ninternet,internet,0\ndb01,internal,10\n"
    edges_bom = "\ufeffsrc,dst,p,required,vuln\ninternet,db01,0.75,true,cve-123\n"
    
    # 1. String with BOM
    net_dict = csv_to_network_dict(nodes_bom, edges_bom)
    assert net_dict["entry"] == "internet"
    assert net_dict["targets"] == ["db01"]
    assert net_dict["edges"][0]["vuln"] == "cve-123"

    # 2. Files with BOM bytes
    nodes_f = tmp_path / "nodes_bom.csv"
    edges_f = tmp_path / "edges_bom.csv"
    nodes_f.write_bytes(b"\xef\xbb\xbfid,zone,criticality\ninternet,internet,0\ndb01,internal,10\n")
    edges_f.write_bytes(b"\xef\xbb\xbfsrc,dst,p,required,vuln\ninternet,db01,0.75,true,cve-123\n")

    net_dict_f = csv_to_network_dict(nodes_f, edges_f)
    assert net_dict_f["entry"] == "internet"
    assert net_dict_f["targets"] == ["db01"]


def test_build_graph_preserves_vuln():
    """Verify that build_graph retains the optional vuln attribute on edges."""
    net_data = {
        "nodes": [
            {"id": "a", "zone": "z", "criticality": 0},
            {"id": "b", "zone": "z", "criticality": 5},
        ],
        "edges": [
            {"src": "a", "dst": "b", "p": 0.8, "required": True, "vuln": "CVE-2024-9999"}
        ],
        "entry": "a",
        "targets": ["b"],
    }
    G = build_graph(net_data)
    assert G["a"]["b"].get("vuln") == "CVE-2024-9999"
