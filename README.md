# Attack-Path-Analyzer 🛡️

Automated network attack-path analysis, quantitative risk scoring, network segmentation, and MST-based hardening recommendations with an interactive Streamlit web dashboard and command-line interface.

---

## 📋 System Requirements
- **Platform**: Windows 10 / 11 (or Linux / macOS)
- **Python Version**: Python 3.11+ (Python 3.11, 3.12, 3.13, 3.14)

---

## 🚀 How to Launch (One-Click)

### 1. Browser Application (Recommended)
Simply **double-click** `run.bat` in the project root folder.
- Checks Python installation on your PATH
- Automatically creates `.venv` if missing
- Installs dependencies from `requirements.txt` quietly
- Launches the Streamlit app and opens your default browser at `http://localhost:8501`

### 2. Quick CLI Run
**Double-click** `run_cli.bat` to run the analysis on `data/sample_small.json`.
- Automatically bootstraps `.venv` if needed
- Writes `output/report.md` and `output/graph.png`
- Automatically opens both files upon completion

---

## 🛠️ Manual Installation & CLI Execution

If you prefer using PowerShell or CMD:

```powershell
# 1. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install production dependencies
pip install -r requirements.txt

# Or install with test dependencies
pip install -r requirements-dev.txt

# 3. Run Streamlit dashboard
streamlit run app.py

# 4. Or execute CLI analysis
python main.py --input data/sample_small.json --out output
```

CLI Parameters:
- `--input`: Path to input JSON file (default: `data/sample_small.json`)
- `--out`: Output directory for report and image (default: `output`)

---

## 📂 Project Structure

```
attack-path-analyzer/
├── .gitignore               # Version control ignore rules
├── INTERFACES.md            # Frozen public API specification
├── README.md                # Project documentation
├── requirements.txt         # Production dependencies (streamlit, networkx, matplotlib, pandas)
├── requirements-dev.txt     # Development and testing dependencies (pytest)
├── run.bat                  # One-click Windows launcher for web UI
├── run_cli.bat              # One-click Windows launcher for CLI analysis
├── main.py                  # CLI entrypoint and orchestrator pipeline
├── app.py                   # Streamlit web dashboard
├── draw_demo.py             # Standalone graph visualization script
│
├── src/                     # Core library modules
│   ├── __init__.py          # Package marker
│   ├── loader.py            # JSON schema and in-memory dict validation
│   ├── graph_builder.py     # DiGraph construction and log-weight mapping
│   ├── builders.py          # CSV import parsing & random network generator
│   ├── pathfinder.py        # Hand-rolled Dijkstra, Bellman-Ford, top-k paths
│   ├── risk.py              # Quantitative path risk scoring & categorization
│   ├── hardening.py         # Kruskal MST-based edge pruning and preservation
│   ├── segmentation.py      # Union-Find partitions, boundary violations, blast radius
│   ├── visualize.py         # Matplotlib headless graph rendering
│   └── report.py            # Structured Markdown report builder
│
├── data/                    # Sample network datasets
│   ├── sample_small.json    # 7 nodes, 9 edges, single target
│   └── sample_large.json    # 10 nodes, 12 edges, multi-target (db-main, domain-ctrl)
│
├── tests/                   # Automated pytest suite (39 tests)
│   ├── __init__.py          # Test package path configuration
│   ├── conftest.py          # Pytest fixtures and sys.path setup
│   ├── test_app.py          # Streamlit AppTest smoke & cell parser tests
│   ├── test_builders.py     # CSV parsing & synthetic generator tests
│   ├── test_end_to_end.py   # Full pipeline integration tests
│   ├── test_hardening.py    # Kruskal MST property tests
│   ├── test_loader.py       # JSON schema & duplicate edge error tests
│   ├── test_risk.py         # Risk math & band scoring tests
│   ├── test_segmentation.py # Union-Find connectivity tests
│   └── test_stage10_rubric.py # Master rubric compliance test suite
│
└── output/                  # Generated reports and graph diagrams
    ├── report.md            # Generated Markdown report
    └── graph.png            # Rendered attack graph image
```

---

## 📑 Input JSON Schema

Network description files must adhere to the following JSON schema:

```json
{
  "nodes": [
    {"id": "internet", "zone": "internet", "criticality": 0},
    {"id": "web01", "zone": "dmz", "criticality": 3},
    {"id": "db01", "zone": "internal", "criticality": 10}
  ],
  "edges": [
    {
      "src": "internet",
      "dst": "web01",
      "p": 0.90,
      "required": true,
      "vuln": "path traversal"
    },
    {
      "src": "web01",
      "dst": "db01",
      "p": 0.10,
      "required": false,
      "vuln": "direct sql"
    }
  ],
  "entry": "internet",
  "targets": ["db01"]
}
```

### Schema Rules
- **`nodes`**: Non-empty array of unique node objects:
  - `id` *(string)*: Unique identifier.
  - `zone` *(string)*: Security zone (e.g. `internet`, `dmz`, `internal`, `restricted`).
  - `criticality` *(integer, 0–10)*: Asset importance score.
- **`edges`**: Array of directed links:
  - `src` *(string)*: Source node ID (must exist in `nodes`).
  - `dst` *(string)*: Destination node ID (must exist in `nodes`).
  - `p` *(float, (0, 1])*: Exploit success probability. Weight is computed as $-\ln(p)$.
  - `required` *(boolean)*: If `true`, link is designated as critical business infrastructure.
  - `vuln` *(optional string)*: Vulnerability description or CVE identifier.
  - `(src, dst)` directed pairs must be unique (duplicate directed links are rejected).
- **`entry`**: String ID of the entry point node (must exist in `nodes`).
- **`targets`**: Non-empty array of target node IDs (must exist in `nodes`).

---

## 🖥️ Web Application Guide (Tabs)

The web dashboard is organized into four intuitive tabs:

### 1. 📊 Quick Analysis
- **Scoped Dataset Selector**: Switch between `Sample small`, `Sample large`, or `Upload Custom JSON` directly inside the tab.
- **Risk Assessment**: Color-coded risk badge (`Low`, `Medium`, `High`, `Critical`), overall exploit probability, numeric risk score, target criticality, and **Attacker Blast Radius** metric.
- **Security Boundary Violations**: Immediate callout alerting when attack vectors cross security boundaries (e.g. `dmz ➔ internal`).
- **Network Attack Graph**: High-resolution network graph with primary attack path in orange, hardened edges in dashed red, and a one-click **Download graph.png** button.
- **Top Attack Paths**: Ranked simple attack paths from entry to targets with cumulative exploit probabilities.
- **Hardening Plan**: MST-based edge recommendations (edges recommended for isolation vs. essential links to preserve).
- **Network Segments**: Disjoint network partitions detected via Union-Find.
- **Artifacts**: One-click download for `report.md` with live Markdown preview.

### 2. 🛠️ Build Network (Spreadsheet Editor)
- Interactive `st.data_editor` tables for **Nodes** and **Edges** with safe cell sanitization (handles empty, NaN, and irregular values).
- Source and destination dropdowns dynamically populate from defined nodes.
- One-click validation, pipeline execution, and network JSON export.

### 3. 📄 CSV Import
- Import topologies by uploading `nodes.csv` and `edges.csv`.
- Full support for UTF-8 Byte Order Marks (`utf-8-sig`) exported from Microsoft Excel.
- Auto-detects entry points and targets with data preview tables.

### 4. 🎲 Random Network Generator
- Deterministically generates reproducible synthetic networks guaranteed to pass schema validation and maintain a viable attack path.
- Configurable node count (3–25), edge density (0.05–0.80), and random seed.

---

## 🧪 Running the Test Suite

Run all unit, integration, UI smoke, rubric, and builder tests with pytest:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

All **39 automated tests** verify:
- Dijkstra top-path probabilities & NetworkX mathematical equivalence
- Bellman-Ford distances and negative cycle detection
- Disjoint-set Union-Find connectivity, transitivity, and segmentation
- Kruskal MST weight equality with NetworkX undirected MST
- Hardening edge constraints (`required: true` preservation)
- JSON loader validation (syntax errors, missing fields, duplicate nodes, duplicate edges)
- In-memory dictionary execution and multi-target path selection
- CSV conversion with BOM support and ragged row handling
- Streamlit AppTest smoke tests and cell sanitization helpers
- Matplotlib headless rendering and extensionless file paths
