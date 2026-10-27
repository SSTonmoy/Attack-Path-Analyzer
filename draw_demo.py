# draw_demo.py
from pathlib import Path
from src.loader import load_json
from src.graph_builder import build_graph
from src.visualize import draw_graph

def main() -> None:
    data_path = Path(__file__).parent / "data" / "sample_small.json"
    G = build_graph(load_json(str(data_path)))

    draw_graph(
        G,
        out_path="output/graph.png",
        highlight_path=["internet", "web01", "db01"],
        removed_edges=[("mail01", "admin-pc")],
    )
    print("✅ Image written to:", Path("output/graph.png").resolve())

if __name__ == "__main__":
    main()