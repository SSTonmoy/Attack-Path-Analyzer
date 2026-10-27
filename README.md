# Attack Path Analyzer

A Python project for the Algorithms course that reads a JSON description of a network, finds the most likely attack paths, scores risk, performs segmentation, hardens the network with an MST, visualises before/after diagrams, and generates a Markdown report.

## Quick start
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py --input data/sample_small.json --out output
```

The repository layout and the frozen API signatures are described in `INTERFACES.md`.
