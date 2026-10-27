# Attack-Path-Analyzer 🛡️

Automated network attack-path analysis, quantitative risk scoring, network segmentation, and MST-based hardening recommendations with an interactive Streamlit web dashboard.

---

## 🚀 How to Launch (One-Click)

### 1. Browser Application (Recommended)
Simply **double-click** `run.bat` in the project root folder.
- Automatically activates `.venv`
- Installs dependencies from `requirements.txt` if missing
- Launches the Streamlit app and opens your default browser at `http://localhost:8501`

### 2. Quick CLI Run
**Double-click** `run_cli.bat` to run the analysis on `data/sample_small.json`.
- Writes `output/report.md` and `output/graph.png`
- Automatically opens both files upon completion

---

## 🖥️ Web Application Guide (Tabs)

The web dashboard is organized into four intuitive tabs:

### 1. 📊 Quick Analysis
- **Sidebar Selection**: Choose between bundled datasets (`Sample small`, `Sample large`) or select **Upload JSON** to drop your own network configuration.
- **Risk Assessment**: Color-coded risk badge (`Low`, `Medium`, `High`, `Critical`), overall exploit probability, target asset criticality, and numeric risk score.
- **Network Attack Graph**: Visual diagram of the network with the primary attack path highlighted in orange and hardened edges shown in dashed red.
- **Top Attack Paths**: Ranked simple attack paths from entry point to target asset(s) with calculated cumulative exploit probabilities.
- **Hardening Plan**: MST-based edge recommendations (edges to isolate/cut vs. essential links to preserve).
- **Network Segments**: Disjoint network partitions detected via Union-Find.
- **Artifacts**: Download button for `report.md` with live Markdown preview.

### 2. 🛠️ Build Network (No Manual JSON)
- **Spreadsheet Editing**: Interactive `st.data_editor` tables for **Nodes** (`id`, `zone`, `criticality`) and **Edges** (`src`, `dst`, `vuln`, `p`, `required`).
- **Endpoint Dropdowns**: Source and destination edge selectors automatically populate from the node IDs entered in the Nodes table.
- **Entry & Target Selection**: Dropdowns to choose entry point and target asset(s).
- **Instant Analysis & Export**: Click **Validate & Run Analysis** to verify schema compliance and generate results, or **Download Network JSON** to save your topology.

### 3. 📄 CSV Import
- Import topologies directly by uploading two CSV files:
  - `nodes.csv` (Columns: `id`, `zone`, `criticality`)
  - `edges.csv` (Columns: `src`, `dst`, `p`, `required`, optional `vuln`)
- Features data previews, entry/target selection, instant pipeline execution, and JSON export.

### 4. 🎲 Random Network Generator
- Generate reproducible synthetic networks using customizable parameters:
  - **Number of Nodes** (slider from 3 to 25)
  - **Edge Density** (slider from 0.05 to 0.80)
  - **Random Seed** (guarantees identical networks for identical seeds)
- Generated networks are guaranteed to pass schema validation and maintain a viable path from entry to target.

---

## 💻 Command Line Interface (CLI)

You can also run the analyzer from PowerShell or CMD:

```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Run analysis
python main.py --input data/sample_small.json --out output
```

Parameters:
- `--input`: Path to input JSON file (default: `data/sample_small.json`)
- `--out`: Output folder for reports and images (default: `output`)

---

## 🧪 Running the Test Suite

Run all unit, integration, rubric, and builder tests with pytest:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

All 29 tests verify:
- Dijkstra top-path probabilities & NetworkX equivalence
- Bellman-Ford distances and negative cycle detection
- Disjoint-set Union-Find connectivity & segmentation
- Kruskal MST weight equality with NetworkX MST
- Hardening edge constraints (`required: true` preservation)
- JSON loader validation (syntax, missing fields, duplicates)
- CSV conversion and deterministic random network generation
