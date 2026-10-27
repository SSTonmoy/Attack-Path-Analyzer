"""app.py
======

Streamlit web application for the Attack-Path-Analyzer.
Provides an interactive dashboard for network security analysis:
- Quick Analysis of bundled or uploaded JSON networks
- Interactive Spreadsheet-style Network Builder (st.data_editor)
- CSV Import (nodes.csv + edges.csv)
- Deterministic Synthetic Network Generator
"""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import traceback
from typing import Any, Dict

import pandas as pd
import streamlit as st

from src.loader import load_json, validate_network
from src.graph_builder import build_graph
from src.pathfinder import dijkstra, top_k_paths, path_probability
from src.risk import score_path
from src.hardening import harden
from src.segmentation import find_segments, boundary_violations, blast_radius
from src.visualize import draw_graph
from src.report import build_report
from src.builders import csv_to_network_dict, generate_random_network


# -----------------------------------------------------------------------------
# Page Configuration & Environment
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Attack-Path Analyzer",
    page_icon="🛡️",
    layout="wide",
)

project_root = pathlib.Path(__file__).parent.resolve()
output_dir = project_root / "output"
output_dir.mkdir(parents=True, exist_ok=True)

# Helper for width compatibility across Streamlit versions (Item F)
try:
    from packaging.version import Version
    _IS_MODERN_STREAMLIT = Version(st.__version__) >= Version("1.38.0")
except Exception:
    _IS_MODERN_STREAMLIT = True

CONTAINER_WIDTH: Dict[str, Any] = {"width": "stretch"} if _IS_MODERN_STREAMLIT else {"use_container_width": True}


# -----------------------------------------------------------------------------
# Safe Cell-Reading Helpers (Item A)
# -----------------------------------------------------------------------------
def _safe_str(val: Any, default: str = "") -> str:
    """Safely convert cell to clean string, preventing NaN stringification."""
    if val is None or pd.isna(val):
        return default
    s = str(val).strip()
    return default if s.lower() in ("nan", "none", "") else s


def _safe_int(val: Any, default: int = 0) -> int:
    """Safely convert cell to int, handling NaN, empty, or float representations."""
    if val is None or pd.isna(val):
        return default
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def _safe_float(val: Any, default: float = 0.5) -> float:
    """Safely convert cell to float in range (0, 1]."""
    if val is None or pd.isna(val):
        return default
    try:
        f = float(val)
        return default if pd.isna(f) else f
    except (ValueError, TypeError):
        return default


def _safe_bool(val: Any, default: bool = False) -> bool:
    """Safely parse boolean cell, preventing bool(nan) from evaluating to True."""
    if val is None or pd.isna(val):
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    return s in ("true", "1", "yes", "t")


# -----------------------------------------------------------------------------
# Cached Analysis & Per-Network Artifact Materialization (Item C)
# -----------------------------------------------------------------------------
@st.cache_data
def _compute_analysis_data(network_json_str: str) -> Dict[str, Any]:
    """Pure analysis computation cached in memory (no disk writes inside)."""
    data = json.loads(network_json_str)
    validated = validate_network(data)
    G = build_graph(validated)

    entry = validated["entry"]
    targets = validated.get("targets", [])
    if not targets:
        raise ValueError("Network specification must contain at least one target.")

    best_path = None
    best_risk = None
    for tgt in targets:
        try:
            cand_path = dijkstra(G, source=entry, target=tgt)
            if isinstance(cand_path, list):
                cand_risk = score_path(G, cand_path)
                if best_risk is None or cand_risk["score"] > best_risk["score"]:
                    best_risk = cand_risk
                    best_path = cand_path
        except (ValueError, KeyError):
            continue

    if best_path is None or best_risk is None:
        raise ValueError(
            f"No attack path found from entry '{entry}' to target(s): {', '.join(targets)}"
        )

    hardening_result = harden(G, entry=entry, targets=targets)
    segments = find_segments(G)
    violations = boundary_violations(G)
    radius = blast_radius(G, entry=entry)

    return {
        "risk": best_risk,
        "hardening": hardening_result,
        "segments": segments,
        "boundary_violations": violations,
        "blast_radius": list(radius),  # serializable for st.cache_data
        "best_path": best_path,
        "network_data": validated,
    }


def analyze_and_materialize(network_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Run cached analysis and write artifacts into a per-network hash directory."""
    net_json = json.dumps(network_dict, sort_keys=True)
    net_hash = hashlib.sha256(net_json.encode("utf-8")).hexdigest()[:12]
    net_dir = output_dir / f"net_{net_hash}"
    net_dir.mkdir(parents=True, exist_ok=True)

    # 1. Pure cached computation
    calc_results = _compute_analysis_data(net_json)

    # 2. Materialize files outside cached function
    report_path = net_dir / "report.md"
    graph_path = net_dir / "graph.png"

    validated = calc_results["network_data"]
    G = build_graph(validated)
    best_path = calc_results["best_path"]
    hardening = calc_results["hardening"]
    radius_set = set(calc_results["blast_radius"])
    violations = calc_results["boundary_violations"]

    if not report_path.is_file():
        build_report(
            {
                "risk_summary": calc_results["risk"],
                "hardening_plan": hardening,
                "segments": calc_results["segments"],
                "boundary_violations": violations,
                "blast_radius": radius_set,
            },
            str(report_path),
        )

    if not graph_path.is_file():
        draw_graph(
            G,
            out_path=str(graph_path),
            highlight_path=best_path,
            removed_edges=hardening.get("removed"),
        )

    return {
        "risk": calc_results["risk"],
        "hardening": hardening,
        "segments": calc_results["segments"],
        "boundary_violations": violations,
        "blast_radius": radius_set,
        "best_path": best_path,
        "report_path": str(report_path),
        "graph_path": str(graph_path),
    }


# -----------------------------------------------------------------------------
# Helper: Render Analysis Dashboard
# -----------------------------------------------------------------------------
def display_analysis_dashboard(results: Dict[str, Any], network_data: Dict[str, Any], key_prefix: str = "dash") -> None:
    """Render risk badge, metrics, network graph, attack paths, hardening plan, and segments."""
    # Single graph construction for all dashboard components
    G = build_graph(network_data)

    risk_info = results["risk"]
    band = risk_info.get("band", "Unknown")
    score = risk_info.get("score", 0.0)
    prob = risk_info.get("prob", 0.0)
    criticality = risk_info.get("criticality", 0)
    blast_nodes = results.get("blast_radius", set())
    total_nodes = len(network_data.get("nodes", []))
    violations = results.get("boundary_violations", [])

    # 1. Risk Summary Header & Colored Badge (Blast radius metric added)
    st.subheader("🎯 Risk Assessment")

    badge_colors = {
        "Low": ("#28a745", "white"),
        "Medium": ("#ffc107", "#212529"),
        "High": ("#fd7e14", "white"),
        "Critical": ("#dc3545", "white"),
    }
    bg_color, text_color = badge_colors.get(band, ("#6c757d", "white"))

    col1, col2, col3, col4, col5 = st.columns([1.5, 1, 1, 1, 1.2])
    with col1:
        st.markdown(
            f"""
            <div style="background-color: {bg_color}; color: {text_color};
                        padding: 12px 16px; border-radius: 8px; font-weight: bold;
                        font-size: 1.3rem; text-align: center; margin-top: 6px;">
                {band} Risk
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.metric("Risk Score", f"{score:.2f}")
    with col3:
        st.metric("Attack Probability", f"{prob * 100:.1f}%", help=f"Exact cumulative probability: {prob:.4f}")
    with col4:
        st.metric("Target Criticality", f"{criticality} / 10")
    with col5:
        st.metric(
            "Blast Radius",
            f"{len(blast_nodes)} / {total_nodes} nodes",
            help=f"Nodes reachable by attacker from entry point '{network_data.get('entry', 'internet')}'",
        )

    # Boundary Violations Warning
    if violations:
        st.warning(f"⚠️ **Security Boundary Violations ({len(violations)}):** Cross-zone attack links detected!")
        with st.expander(f"View {len(violations)} Boundary Violations"):
            for u, v in violations:
                z_u = G.nodes[u].get("zone", "unknown")
                z_v = G.nodes[v].get("zone", "unknown")
                st.markdown(f"- ⚠️ `{u}` (`{z_u}`) ➔ `{v}` (`{z_v}`)")
    else:
        st.success("✅ No cross-zone boundary violations detected.")

    st.divider()

    # 2. Network Graph & Top Attack Paths
    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.subheader("📊 Network Attack Graph")
        graph_img_path = pathlib.Path(results["graph_path"])
        if graph_img_path.is_file():
            st.image(
                str(graph_img_path),
                caption="Attack Graph: Path in Orange, Hardened Edges in Dashed Red",
                **CONTAINER_WIDTH,
            )
            # Download button for graph.png
            with open(graph_img_path, "rb") as img_file:
                st.download_button(
                    label="📥 Download graph.png",
                    data=img_file.read(),
                    file_name="attack_graph.png",
                    mime="image/png",
                    key=f"{key_prefix}_dl_img",
                )
        else:
            st.warning("Graph image was not found.")

    with col_right:
        st.subheader("🚶 Top Attack Paths")
        entry_node = network_data.get("entry", "internet")
        targets = network_data.get("targets", [])

        all_attack_paths = []
        for tgt in targets:
            try:
                found_paths = top_k_paths(G, source=entry_node, target=tgt, k=4)
                for p in found_paths:
                    p_prob = path_probability(G, p)
                    all_attack_paths.append((p, p_prob, tgt))
            except Exception:
                continue

        all_attack_paths.sort(key=lambda x: x[1], reverse=True)

        if all_attack_paths:
            for rank, (path_nodes, p_prob, tgt) in enumerate(all_attack_paths, start=1):
                path_str = " ➔ ".join(f"`{node}`" for node in path_nodes)
                st.markdown(
                    f"**#{rank}** ({p_prob*100:.1f}% / p={p_prob:.4f}) : {path_str}"
                )
        else:
            st.info("No attack path found from entry to target asset(s).")

        st.subheader("📑 Report Artifacts")
        report_file_path = pathlib.Path(results["report_path"])
        if report_file_path.is_file():
            report_text = report_file_path.read_text(encoding="utf-8-sig")
            st.download_button(
                label="📥 Download report.md",
                data=report_text,
                file_name="report.md",
                mime="text/markdown",
                key=f"{key_prefix}_dl_rep",
            )
            with st.expander("Preview Markdown Report"):
                st.code(report_text, language="markdown")

    st.divider()

    # 3. Hardening Plan & Network Segmentation
    hard_col, seg_col = st.columns([1, 1])

    with hard_col:
        st.subheader("🛡️ Hardening Plan (MST-Based)")
        hardening = results.get("hardening", {})
        removed = hardening.get("removed", [])
        kept = hardening.get("kept", [])

        st.markdown(f"**Edges Recommended for Removal / Isolation ({len(removed)}):**")
        if removed:
            for u, v in removed:
                st.markdown(f"- ✂️ Cut link: `{u}` ➔ `{v}`")
        else:
            st.info("No edges were selected for removal.")

        with st.expander(f"View Preserved Infrastructure Edges ({len(kept)})"):
            for u, v in kept:
                st.markdown(f"- 🔒 Kept link: `{u}` ➔ `{v}`")

    with seg_col:
        st.subheader("🧩 Network Segments (Weakly-Connected)")
        segments = results.get("segments", {})
        st.markdown(f"Total isolated network partitions: **{len(segments)}**")
        for seg_id, node_set in segments.items():
            nodes_formatted = ", ".join(f"`{n}`" for n in sorted(node_set))
            st.markdown(f"- **Segment {seg_id}** ({len(node_set)} nodes): {nodes_formatted}")


def execute_network_analysis(network_dict: Dict[str, Any], label: str = "custom") -> None:
    """Validate network dictionary directly, run pipeline with spinner, and display dashboard."""
    with st.spinner("Analyzing attack paths, risk scores, and network segments..."):
        try:
            results = analyze_and_materialize(network_dict)
            st.success("✅ Analysis completed successfully!")

            st.download_button(
                label="💾 Download Network JSON",
                data=json.dumps(network_dict, indent=2),
                file_name=f"network_{label}.json",
                mime="application/json",
                key=f"dl_json_{label}",
            )

            display_analysis_dashboard(results, network_dict, key_prefix=label)
        except ValueError as val_err:
            st.error(f"❌ **Validation / Analysis Error:** {val_err}")
            with st.expander("Show Error Details"):
                st.code(traceback.format_exc(), language="python")
        except Exception as exc:
            st.error(f"❌ **Unexpected Error during Analysis:** {exc}")
            with st.expander("Show Full Traceback"):
                st.code(traceback.format_exc(), language="python")


# -----------------------------------------------------------------------------
# Main Application Tabs
# -----------------------------------------------------------------------------
st.title("🛡️ Network Attack-Path Analyzer")
st.markdown("Automated risk scoring, attack-path discovery, and network hardening analysis.")

tab_dashboard, tab_builder, tab_csv, tab_random = st.tabs([
    "📊 Quick Analysis",
    "🛠️ Build Network",
    "📄 CSV Import",
    "🎲 Random Generator",
])


# =============================================================================
# TAB 1: Quick Analysis (Scoped to Tab 1 - Item E)
# =============================================================================
with tab_dashboard:
    st.subheader("📁 Select Input Dataset")
    input_option = st.radio(
        "Choose topology source for quick analysis:",
        options=["Sample small (7 nodes)", "Sample large (10 nodes)", "Upload Custom JSON"],
        index=0,
        horizontal=True,
    )

    loaded_network: Dict[str, Any] | None = None

    if input_option == "Sample small (7 nodes)":
        sample_path = project_root / "data" / "sample_small.json"
        loaded_network = load_json(str(sample_path))
        st.caption("Bundled network: 7 nodes, 9 edges, target: `db01`.")
    elif input_option == "Sample large (10 nodes)":
        sample_path = project_root / "data" / "sample_large.json"
        loaded_network = load_json(str(sample_path))
        st.caption("Bundled network: 10 nodes, 12 edges, targets: `db-main`, `domain-ctrl`.")
    else:
        uploaded = st.file_uploader(
            "Upload network description JSON:",
            type=["json"],
            key="tab1_upload",
        )
        if uploaded is not None:
            try:
                raw_dict = json.loads(uploaded.getvalue().decode("utf-8-sig"))
                loaded_network = validate_network(raw_dict)
                st.success(f"Loaded: {uploaded.name}")
            except Exception as e:
                st.error(f"❌ Failed to parse uploaded JSON: {e}")
        else:
            st.info("👆 Please upload a JSON network configuration above.")

    if loaded_network is not None:
        with st.spinner("Running attack-path and risk analysis..."):
            try:
                results = analyze_and_materialize(loaded_network)
                display_analysis_dashboard(results, loaded_network, key_prefix="quick")
            except ValueError as val_err:
                st.error(f"❌ **Validation / Analysis Error in Network JSON:** {val_err}")
                with st.expander("Show Error Details"):
                    st.code(traceback.format_exc(), language="python")
            except Exception as exc:
                st.error(f"❌ **Unexpected Error during Analysis:** {exc}")
                with st.expander("Show Full Traceback"):
                    st.code(traceback.format_exc(), language="python")


# =============================================================================
# TAB 2: Build Network (Spreadsheet Editor via st.data_editor - Item A & F)
# =============================================================================
with tab_builder:
    st.subheader("🛠️ Interactive Network Builder")
    st.markdown("Add and configure nodes and directed edges like a spreadsheet without writing JSON by hand.")

    # Default template based on sample_small
    if "builder_nodes" not in st.session_state:
        st.session_state.builder_nodes = pd.DataFrame([
            {"id": "internet", "zone": "internet", "criticality": 0},
            {"id": "web01", "zone": "dmz", "criticality": 3},
            {"id": "mail01", "zone": "dmz", "criticality": 3},
            {"id": "app01", "zone": "internal", "criticality": 5},
            {"id": "file01", "zone": "internal", "criticality": 4},
            {"id": "admin-pc", "zone": "internal", "criticality": 6},
            {"id": "db01", "zone": "internal", "criticality": 10},
        ])

    if "builder_edges" not in st.session_state:
        st.session_state.builder_edges = pd.DataFrame([
            {"src": "internet", "dst": "web01", "vuln": "path traversal", "p": 0.9, "required": True},
            {"src": "internet", "dst": "mail01", "vuln": "phishing", "p": 0.5, "required": False},
            {"src": "web01", "dst": "app01", "vuln": "sql injection", "p": 0.8, "required": True},
            {"src": "web01", "dst": "db01", "vuln": "remote code exec", "p": 0.1, "required": False},
            {"src": "mail01", "dst": "admin-pc", "vuln": "attachment exploit", "p": 0.7, "required": False},
            {"src": "app01", "dst": "db01", "vuln": "privilege escalation", "p": 0.7, "required": False},
            {"src": "app01", "dst": "file01", "vuln": "lateral movement", "p": 0.7, "required": False},
            {"src": "file01", "dst": "db01", "vuln": "credential theft", "p": 0.3, "required": False},
            {"src": "admin-pc", "dst": "db01", "vuln": "admin exploit", "p": 0.6, "required": False},
        ])

    st.markdown("#### 1. Nodes Table")
    edited_nodes = st.data_editor(
        st.session_state.builder_nodes,
        num_rows="dynamic",
        column_config={
            "id": st.column_config.TextColumn("Node ID", required=True),
            "zone": st.column_config.SelectboxColumn(
                "Zone",
                options=["internet", "dmz", "internal", "office", "restricted", "admin"],
                required=True,
            ),
            "criticality": st.column_config.NumberColumn(
                "Criticality (0-10)",
                min_value=0,
                max_value=10,
                step=1,
                required=True,
            ),
        },
        key="nodes_editor",
        **CONTAINER_WIDTH,
    )

    # Collect available node IDs for edge dropdowns
    available_nodes = [
        _safe_str(nid) for nid in edited_nodes["id"].dropna().tolist() if _safe_str(nid)
    ]

    st.markdown("#### 2. Edges Table")
    edited_edges = st.data_editor(
        st.session_state.builder_edges,
        num_rows="dynamic",
        column_config={
            "src": st.column_config.SelectboxColumn(
                "Source (src)",
                options=available_nodes,
                required=True,
            ),
            "dst": st.column_config.SelectboxColumn(
                "Destination (dst)",
                options=available_nodes,
                required=True,
            ),
            "vuln": st.column_config.TextColumn("Vulnerability / CVE"),
            "p": st.column_config.NumberColumn(
                "Exploit Probability (p)",
                min_value=0.01,
                max_value=1.00,
                step=0.05,
                format="%.2f",
                required=True,
            ),
            "required": st.column_config.CheckboxColumn("Required Link?", default=False),
        },
        key="edges_editor",
        **CONTAINER_WIDTH,
    )

    st.markdown("#### 3. Entry & Target Configuration")
    cfg_col1, cfg_col2 = st.columns(2)
    with cfg_col1:
        default_entry = "internet" if "internet" in available_nodes else (available_nodes[0] if available_nodes else "")
        selected_entry = st.selectbox(
            "Select Entry Point Node:",
            options=available_nodes,
            index=available_nodes.index(default_entry) if default_entry in available_nodes else 0,
        )
    with cfg_col2:
        default_target = ["db01"] if "db01" in available_nodes else ([available_nodes[-1]] if available_nodes else [])
        selected_targets = st.multiselect(
            "Select Target Asset(s):",
            options=available_nodes,
            default=default_target,
        )

    btn_build = st.button("🚀 Validate & Run Analysis", type="primary", key="btn_run_builder")

    if btn_build:
        if not available_nodes:
            st.error("Please add at least one node.")
        elif not selected_targets:
            st.error("Please specify at least one target asset.")
        else:
            # Construct dictionary safely (Item A)
            built_nodes = []
            for _, r in edited_nodes.iterrows():
                nid = _safe_str(r.get("id"))
                if nid:
                    built_nodes.append({
                        "id": nid,
                        "zone": _safe_str(r.get("zone"), "internal"),
                        "criticality": _safe_int(r.get("criticality"), 0),
                    })

            built_edges = []
            for _, r in edited_edges.iterrows():
                src = _safe_str(r.get("src"))
                dst = _safe_str(r.get("dst"))
                if src and dst:
                    e_dict = {
                        "src": src,
                        "dst": dst,
                        "p": _safe_float(r.get("p"), 0.5),
                        "required": _safe_bool(r.get("required"), False),
                    }
                    vuln = _safe_str(r.get("vuln"))
                    if vuln:
                        e_dict["vuln"] = vuln
                    built_edges.append(e_dict)

            built_network = {
                "nodes": built_nodes,
                "edges": built_edges,
                "entry": selected_entry,
                "targets": selected_targets,
            }

            execute_network_analysis(built_network, label="builder")


# =============================================================================
# TAB 3: CSV Import (nodes.csv + edges.csv - Item B)
# =============================================================================
with tab_csv:
    st.subheader("📄 Import Network from CSV")
    st.markdown("Upload two CSV files: `nodes.csv` (columns: `id`, `zone`, `criticality`) and `edges.csv` (columns: `src`, `dst`, `p`, `required`).")

    col_csv1, col_csv2 = st.columns(2)
    with col_csv1:
        csv_nodes_file = st.file_uploader("Upload Nodes CSV (`nodes.csv`)", type=["csv"], key="csv_nodes")
    with col_csv2:
        csv_edges_file = st.file_uploader("Upload Edges CSV (`edges.csv`)", type=["csv"], key="csv_edges")

    if csv_nodes_file and csv_edges_file:
        try:
            # Decode with utf-8-sig to automatically strip Excel BOMs (Item B)
            nodes_text = csv_nodes_file.getvalue().decode("utf-8-sig")
            edges_text = csv_edges_file.getvalue().decode("utf-8-sig")

            nodes_preview = pd.read_csv(io.StringIO(nodes_text))
            edges_preview = pd.read_csv(io.StringIO(edges_text))

            if nodes_preview.empty:
                st.error("Uploaded `nodes.csv` is empty.")
            elif "id" not in nodes_preview.columns:
                st.error("Uploaded `nodes.csv` must contain an 'id' column.")
            else:
                st.markdown("##### Preview Nodes CSV")
                st.dataframe(nodes_preview.head(5), **CONTAINER_WIDTH)

                st.markdown("##### Preview Edges CSV")
                st.dataframe(edges_preview.head(5), **CONTAINER_WIDTH)

                csv_node_ids = [
                    _safe_str(nid)
                    for nid in nodes_preview["id"].dropna().tolist()
                    if _safe_str(nid)
                ]

                if not csv_node_ids:
                    st.error("No valid node IDs found in `nodes.csv`.")
                else:
                    csv_col_a, csv_col_b = st.columns(2)
                    with csv_col_a:
                        csv_entry = st.selectbox("Entry Point:", options=csv_node_ids, index=0)
                    with csv_col_b:
                        default_target_idx = [csv_node_ids[-1]] if csv_node_ids else []
                        csv_targets = st.multiselect("Targets:", options=csv_node_ids, default=default_target_idx)

                    if st.button("🚀 Import CSV & Run Analysis", type="primary", key="btn_run_csv"):
                        converted_network = csv_to_network_dict(
                            nodes_csv=nodes_text,
                            edges_csv=edges_text,
                            entry=csv_entry,
                            targets=csv_targets,
                        )
                        execute_network_analysis(converted_network, label="csv_imported")

        except Exception as e:
            st.error(f"❌ Error parsing CSV files: {e}")
            with st.expander("Show Error Details"):
                st.code(traceback.format_exc(), language="python")
    else:
        st.info("Please upload both `nodes.csv` and `edges.csv` to proceed.")


# =============================================================================
# TAB 4: Random Network Generator
# =============================================================================
with tab_random:
    st.subheader("🎲 Synthetic Random Network Generator")
    st.markdown("Generate synthetic networks with guaranteed paths and full schema compliance.")

    r_col1, r_col2, r_col3 = st.columns(3)
    with r_col1:
        num_nodes_slider = st.slider("Number of Nodes", min_value=3, max_value=25, value=7, step=1)
    with r_col2:
        density_slider = st.slider("Edge Density", min_value=0.05, max_value=0.80, value=0.35, step=0.05)
    with r_col3:
        seed_input = st.number_input("Random Seed (Reproducibility)", min_value=0, max_value=999999, value=42, step=1)

    if st.button("🎲 Generate & Analyze Network", type="primary", key="btn_run_random"):
        random_net = generate_random_network(
            num_nodes=num_nodes_slider,
            edge_density=density_slider,
            seed=seed_input,
        )
        st.info(f"Generated network with {len(random_net['nodes'])} nodes and {len(random_net['edges'])} edges (Seed: {seed_input}).")
        execute_network_analysis(random_net, label=f"random_seed_{seed_input}")
