"""Red Line Demo Visualizer — renders ThreatGraph as a PNG.

Usage:
    from server.visualize_graph import visualize_graph
    visualize_graph(env._threat_graph, "snapshot.png")

Pivot edges (edge_type == 'pivoted_from') are drawn as thick bright-red lines
so the adaptive red-team lateral movement is visually undeniable in demos.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .threat_graph import ThreatGraph


_NODE_COLORS = {
    "host": "#4A90D9",
    "process": "#F5A623",
    "ioc": "#D0021B",
    "alert": "#9B9B9B",
    "vulnerability": "#7ED321",
}

_EDGE_STYLES: dict[str, dict] = {
    "pivoted_from":      {"color": "red",     "width": 3.0, "style": "solid"},
    "part_of_chain":     {"color": "#555555", "width": 1.5, "style": "dashed"},
    "exploits":          {"color": "#D0021B", "width": 1.5, "style": "solid"},
    "runs_on":           {"color": "#4A90D9", "width": 1.0, "style": "solid"},
    "involves":          {"color": "#9B9B9B", "width": 1.0, "style": "dotted"},
    "communicates_with": {"color": "#F5A623", "width": 1.0, "style": "dashed"},
}


def visualize_graph(threat_graph: "ThreatGraph", output_path: str = "threat_graph.png") -> None:
    """Render the ThreatGraph to a PNG file.

    Args:
        threat_graph: A populated ThreatGraph instance.
        output_path: Destination file path for the PNG.
    """
    try:
        import networkx as nx
        import matplotlib
        matplotlib.use("Agg")  # headless backend — safe in CI / server contexts
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
    except ImportError as exc:
        raise ImportError(
            "visualize_graph requires networkx and matplotlib. "
            "Install them with: pip install networkx matplotlib"
        ) from exc

    G = nx.DiGraph()

    # --- Add nodes ---
    node_color_map: dict[str, str] = {}

    for hostname in threat_graph.hosts:
        G.add_node(hostname)
        node_color_map[hostname] = _NODE_COLORS["host"]

    for proc_id, proc in threat_graph.processes.items():
        G.add_node(proc_id)
        node_color_map[proc_id] = _NODE_COLORS["process"]

    for ioc_value in threat_graph.iocs:
        G.add_node(ioc_value)
        node_color_map[ioc_value] = _NODE_COLORS["ioc"]

    for alert_id in threat_graph.alerts:
        G.add_node(alert_id)
        node_color_map[alert_id] = _NODE_COLORS["alert"]

    for vuln_key in threat_graph.vulnerabilities:
        G.add_node(vuln_key)
        node_color_map[vuln_key] = _NODE_COLORS["vulnerability"]

    # --- Add edges, split by type for drawing ---
    pivot_edges: list[tuple[str, str]] = []
    other_edges: list[tuple[str, str]] = []
    other_edge_styles: list[dict] = []

    for edge in threat_graph.edges:
        src, tgt = edge.source_id, edge.target_id
        # Ensure both endpoints exist as nodes (may be threat-IDs not in node sets)
        if src not in G:
            G.add_node(src)
            node_color_map[src] = "#CCCCCC"
        if tgt not in G:
            G.add_node(tgt)
            node_color_map[tgt] = "#CCCCCC"
        G.add_edge(src, tgt, edge_type=edge.edge_type)

        if edge.edge_type == "pivoted_from":
            pivot_edges.append((src, tgt))
        else:
            style = _EDGE_STYLES.get(edge.edge_type, {"color": "#AAAAAA", "width": 1.0, "style": "solid"})
            other_edges.append((src, tgt))
            other_edge_styles.append(style)

    # --- Layout ---
    fig, ax = plt.subplots(figsize=(14, 10))
    ax.set_title("CyberSOC Threat Graph", fontsize=14, fontweight="bold")
    ax.axis("off")

    pos = nx.spring_layout(G, seed=42, k=1.5)

    node_list = list(G.nodes())
    colors = [node_color_map.get(n, "#CCCCCC") for n in node_list]

    nx.draw_networkx_nodes(G, pos, nodelist=node_list, node_color=colors,
                           node_size=600, ax=ax, alpha=0.9)
    nx.draw_networkx_labels(G, pos, font_size=6, ax=ax)

    # Draw non-pivot edges grouped by style
    _style_map: dict[str, list[tuple[str, str]]] = {}
    for (src, tgt), style in zip(other_edges, other_edge_styles):
        key = f"{style['color']}|{style['width']}|{style['style']}"
        _style_map.setdefault(key, []).append((src, tgt))

    for key, elist in _style_map.items():
        color, width_s, linestyle = key.split("|")
        nx.draw_networkx_edges(
            G, pos, edgelist=elist,
            edge_color=color, width=float(width_s), style=linestyle,
            arrows=True, arrowsize=12, ax=ax, alpha=0.7,
        )

    # CRITICAL: pivot edges — thick bright red, drawn last so they sit on top
    if pivot_edges:
        nx.draw_networkx_edges(
            G, pos, edgelist=pivot_edges,
            edge_color="red", width=3.0, style="solid",
            arrows=True, arrowsize=18, ax=ax, alpha=1.0,
        )

    # --- Legend ---
    legend_handles = [
        mpatches.Patch(color=c, label=label)
        for label, c in [
            ("Host", _NODE_COLORS["host"]),
            ("Process", _NODE_COLORS["process"]),
            ("IOC", _NODE_COLORS["ioc"]),
            ("Alert", _NODE_COLORS["alert"]),
            ("Vulnerability", _NODE_COLORS["vulnerability"]),
        ]
    ]
    legend_handles.append(
        mpatches.Patch(color="red", label="Lateral Pivot (pivoted_from)")
    )
    ax.legend(handles=legend_handles, loc="lower left", fontsize=8, framealpha=0.8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
