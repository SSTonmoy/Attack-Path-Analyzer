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

import io
import json
import pathlib
import tempfile
from typing import Any, Dict

import networkx as nx
import pandas as pd
import streamlit as st

from main import run_analysis
from src.loader import load_json
from src.graph_builder import build_graph
from src.pathfinder import top_k_paths, path_probability
from src.builders import csv_to_network_dict, generate_random_network


# -----------------------------------------------------------------------------
# Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Attack-Path Analyzer",
    page_icon="🛡️",
    layout="wide",
)

project_root = pathlib.Path(__file__).parent.resolve()
output_dir = project_root / "output"
output_dir.mkdir(parents=True, exist_ok=True)


# -----------------------------------------------------------------------------
# Helper: Render Analysis Dashboard
# -----------------------------------------------------------------------------
def display_analysis_dashboard(results: Dict[str, Any], network_data: Dict[str, Any]) -> None:
    """Render the risk badge, network graph, top attack paths, hardening plan, and segments."""
    risk_info = results["risk"]
    band = risk_info.get("band", "Unknown")
    score = risk_info.get("score", 0.0)
    prob = risk_info.get("prob", 0.0)
    criticality = risk_info.get("criticality", 0)

    # 1. Risk Summary Header & Colored Badge
    st.subheader("🎯 Risk Assessment")

    badge_colors = {
        "Low": ("#28a745", "white"),
        "Medium": ("#ffc107", "#212529"),
        "High": ("#fd7e14", "white"),
        "Critical": ("#dc3545", "white"),
    }
    bg_color, text_color = badge_colors.get(band, ("#6c757d", "white"))

    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
    with col1:
        st.markdown(
            f"""
            <div style="background-color: {bg_color}; color: {text_color};
                        padding: 12px 20px; border-radius: 8px; font-weight: bold;
                        font-size: 1.4rem; text-align: center; margin-top: 8px;">
                {band} Risk (Score: {score:.2f})
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.metric("Attack Probability", f"{prob:.4f}", f"{prob * 100:.1f}%")
    with col3:
        st.metric("Target Criticality", f"{criticality} / 10")
    with col4:
        st.metric("Risk Score", f"{score:.2f}")

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
                use_container_width=True,
            )
        else:
            st.warning("Graph image was not found.")

    with col_right:
        st.subheader("🚶 Top Attack Paths")
        G = build_graph(network_data)
        entry_node = network_data.get("entry", "internet")
        targets = network_data.get("targets", [])

        all_attack_paths = []
        for tgt in targets:
            try:
                found_paths = top_k_paths(G, source=entry_node, target=tgt, k=4)
                for p in found_paths:
                    p_prob = path_probability(G, p)
                    all_attack_paths.append((p, p_prob, tgt))
            except (nx.NetworkXNoPath, nx.NodeNotFound, ValueError):
                continue

        all_attack_paths.sort(key=lambda x: x[1], reverse=True)

        if all_attack_paths:
            for rank, (path_nodes, p_prob, tgt) in enumerate(all_attack_paths, start=1):
                path_str = " ➔ ".join(f"`{node}`" for node in path_nodes)
                st.markdown(
                    f"**#{rank}** ({p_prob:.4f} / {p_prob*100:.1f}%) : {path_str}"
                )
        else:
            st.info("No attack path found from entry to target asset(s).")

        st.subheader("📑 Report Artifacts")
        report_file_path = pathlib.Path(results["report_path"])
        if report_file_path.is_file():
            report_text = report_file_path.read_text(encoding="utf-8")
            st.download_button(
                label="📥 Download report.md",
                data=report_text,
                file_name="report.md",
                mime="text/markdown",
                key=f"dl_rep_{id(results)}",
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
    """Validate network dictionary, write to temp JSON, run pipeline, and display dashboard."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(network_dict, f, indent=2)
        temp_path = pathlib.Path(f.name)

    try:
        # Validate through loader
        validated = load_json(str(temp_path))
        results = run_analysis(input_path=str(temp_path), output_dir=str(output_dir))
        st.success("✅ Analysis completed successfully!")

        # Download JSON button
        st.download_button(
            label="💾 Download Network JSON",
            data=json.dumps(network_dict, indent=2),
            file_name=f"network_{label}.json",
            mime="application/json",
            key=f"dl_json_{label}",
        )

        display_analysis_dashboard(results, validated)
    except ValueError as val_err:
        st.error(f"❌ **Validation Error:** {val_err}")
    except Exception as exc:
        st.error(f"❌ **Analysis Error:** {exc}")
    finally:
        temp_path.unlink(missing_ok=True)


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
# TAB 1: Quick Analysis (Sidebar Sources)
# =============================================================================
with tab_dashboard:
    st.sidebar.header("📁 Quick Input Source")
    input_option = st.sidebar.radio(
        "Choose input source:",
        options=["Sample small", "Sample large", "Upload JSON"],
        index=0,
    )

    selected_input: pathlib.Path | None = None
    temp_clean: pathlib.Path | None = None

    if input_option == "Sample small":
        selected_input = project_root / "data" / "sample_small.json"
        st.sidebar.caption("Using bundled `sample_small.json` (7 nodes, 9 edges).")
    elif input_option == "Sample large":
        selected_input = project_root / "data" / "sample_large.json"
        st.sidebar.caption("Using bundled `sample_large.json` (10 nodes, 12 edges).")
    else:
        uploaded = st.sidebar.file_uploader(
            "Upload network description JSON:",
            type=["json"],
            key="tab1_upload",
        )
        if uploaded is not None:
            tfile = tempfile.NamedTemporaryFile(mode="wb", suffix=".json", delete=False)
            tfile.write(uploaded.getvalue())
            tfile.flush()
            tfile.close()
            selected_input = pathlib.Path(tfile.name)
            temp_clean = selected_input
            st.sidebar.success(f"Loaded: {uploaded.name}")
        else:
            st.info("👈 Please upload a JSON network configuration in the sidebar.")

    if selected_input and selected_input.exists():
        try:
            validated_data = load_json(str(selected_input))
            results = run_analysis(input_path=str(selected_input), output_dir=str(output_dir))
            display_analysis_dashboard(results, validated_data)
        except ValueError as val_err:
            st.error(f"❌ **Validation Error in Network JSON:** {val_err}")
        except Exception as exc:
            st.error(f"❌ **Unexpected Error during Analysis:** {exc}")
        finally:
            if temp_clean and temp_clean.is_file():
                temp_clean.unlink(missing_ok=True)


# =============================================================================
# TAB 2: Build Network (Spreadsheet Editor via st.data_editor)
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
        use_container_width=True,
        key="nodes_editor",
    )

    # Collect available node IDs for edge dropdowns
    available_nodes = [
        str(nid).strip() for nid in edited_nodes["id"].dropna().tolist() if str(nid).strip()
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
        use_container_width=True,
        key="edges_editor",
    )

    st.markdown("#### 3. Entry & Target Configuration")
    cfg_col1, cfg_col2 = st.columns(2)
    with cfg_col1:
        entry_idx = 0 if "internet" in available_nodes else 0
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
            # Construct dictionary
            built_nodes = []
            for _, r in edited_nodes.iterrows():
                if pd.notna(r.get("id")) and str(r["id"]).strip():
                    built_nodes.append({
                        "id": str(r["id"]).strip(),
                        "zone": str(r.get("zone", "internal")).strip(),
                        "criticality": int(r.get("criticality", 0)),
                    })

            built_edges = []
            for _, r in edited_edges.iterrows():
                if pd.notna(r.get("src")) and pd.notna(r.get("dst")):
                    e_dict = {
                        "src": str(r["src"]).strip(),
                        "dst": str(r["dst"]).strip(),
                        "p": float(r.get("p", 0.5)),
                        "required": bool(r.get("required", False)),
                    }
                    if pd.notna(r.get("vuln")) and str(r["vuln"]).strip():
                        e_dict["vuln"] = str(r["vuln"]).strip()
                    built_edges.append(e_dict)

            built_network = {
                "nodes": built_nodes,
                "edges": built_edges,
                "entry": selected_entry,
                "targets": selected_targets,
            }

            execute_network_analysis(built_network, label="builder")


# =============================================================================
# TAB 3: CSV Import (nodes.csv + edges.csv)
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
            nodes_text = csv_nodes_file.getvalue().decode("utf-8")
            edges_text = csv_edges_file.getvalue().decode("utf-8")

            nodes_preview = pd.read_csv(io.StringIO(nodes_text))
            edges_preview = pd.read_csv(io.StringIO(edges_text))

            st.markdown("##### Preview Nodes CSV")
            st.dataframe(nodes_preview.head(5), use_container_width=True)

            st.markdown("##### Preview Edges CSV")
            st.dataframe(edges_preview.head(5), use_container_width=True)

            csv_node_ids = nodes_preview["id"].astype(str).str.strip().tolist()

            csv_col_a, csv_col_b = st.columns(2)
            with csv_col_a:
                csv_entry = st.selectbox("Entry Point:", options=csv_node_ids, index=0)
            with csv_col_b:
                csv_targets = st.multiselect("Targets:", options=csv_node_ids, default=[csv_node_ids[-1]])

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
