from __future__ import annotations

import pandas as pd
import streamlit as st
import networkx as nx
import plotly.graph_objects as go

from containment.containment_engine import ContainmentEngine
from detection.anomaly_detector import GraphAnomalyDetector
from simulation.simulator import AttackGraphSimulator


# =========================================================
# NODE TYPE
# =========================================================

def get_node_type(graph, node):
    """Return the node type if available."""

    attributes = graph.nodes[node]

    node_type = (
        attributes.get("type")
        or attributes.get("node_type")
        or attributes.get("category")
    )

    if node_type:
        return str(node_type)

    return "Node"


# =========================================================
# NETWORK GRAPH VISUALIZATION
# =========================================================

def create_network_figure(graph, anomalous_nodes):
    """Create an interactive Plotly visualization."""

    if graph.number_of_nodes() == 0:
        return go.Figure()

    positions = nx.spring_layout(
        graph,
        seed=7
    )

    anomalous_set = set(anomalous_nodes)

    # -----------------------------------------------------
    # EDGES
    # -----------------------------------------------------

    edge_x = []
    edge_y = []

    for source, target in graph.edges():

        x0, y0 = positions[source]
        x1, y1 = positions[target]

        edge_x.extend([
            x0,
            x1,
            None
        ])

        edge_y.extend([
            y0,
            y1,
            None
        ])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line=dict(width=1),
        hoverinfo="none"
    )

    # -----------------------------------------------------
    # NODE DATA
    # -----------------------------------------------------

    node_x = []
    node_y = []
    node_text = []
    node_colors = []
    node_symbols = []

    # Plotly marker symbols
    type_symbols = {
        "user": "circle",
        "host": "square",
        "process": "diamond",
        "file": "triangle-up",
        "server": "star",
        "external": "hexagon"
    }

    for node in graph.nodes():

        x, y = positions[node]

        node_x.append(x)
        node_y.append(y)

        node_type = get_node_type(
            graph,
            node
        )

        node_type_lower = node_type.lower()

        degree = graph.degree(node)

        # -------------------------------------------------
        # NODE SYMBOL
        # -------------------------------------------------

        symbol = "circle"

        for type_name, type_symbol in type_symbols.items():

            if type_name in node_type_lower:

                symbol = type_symbol
                break

        node_symbols.append(symbol)

        # -------------------------------------------------
        # NODE STATUS
        # -------------------------------------------------

        if node in anomalous_set:

            node_colors.append("red")
            status = "SUSPICIOUS"

        else:

            node_colors.append("blue")
            status = "NORMAL"

        # -------------------------------------------------
        # HOVER INFORMATION
        # -------------------------------------------------

        node_text.append(
            f"Node: {node}<br>"
            f"Type: {node_type}<br>"
            f"Degree: {degree}<br>"
            f"Status: {status}"
        )

    # -----------------------------------------------------
    # NODE TRACE
    # -----------------------------------------------------

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",

        text=[
            str(node)
            for node in graph.nodes()
        ],

        textposition="top center",

        hovertext=node_text,
        hoverinfo="text",

        marker=dict(
            size=18,
            color=node_colors,
            symbol=node_symbols,
            line=dict(width=1)
        )
    )

    # -----------------------------------------------------
    # FIGURE
    # -----------------------------------------------------

    figure = go.Figure(
        data=[
            edge_trace,
            node_trace
        ]
    )

    figure.update_layout(
        title="Behavioural Network Graph",

        showlegend=False,

        hovermode="closest",

        margin=dict(
            l=10,
            r=10,
            t=50,
            b=10
        ),

        xaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False
        ),

        yaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False
        ),

        height=650
    )

    return figure


# =========================================================
# MAIN DASHBOARD
# =========================================================

def run():

    # =====================================================
    # PAGE CONFIGURATION
    # =====================================================

    st.set_page_config(
        page_title="Graph Zero-Day Detection",
        layout="wide"
    )

    st.title(
        "Graph Zero-Day Detection Dashboard"
    )

    st.caption(
        "Graph-based behavioural anomaly detection "
        "and containment framework"
    )

    # =====================================================
    # SIMULATION
    # =====================================================

    simulator = AttackGraphSimulator(
        seed=7
    )

    # Generate 20 normal baseline graphs
    baseline_graphs = [
        simulator.generate_normal_snapshot()
        for _ in range(20)
    ]

    # =====================================================
    # ANOMALY DETECTOR
    # =====================================================

    detector = GraphAnomalyDetector(
        contamination=0.1
    )

    detector.fit(
        baseline_graphs
    )

    # Generate graph to analyse
    graph = simulator.generate_normal_snapshot()

    # Inject simulated zero-day behaviour
    injected_nodes = (
        simulator.inject_zero_day_pattern(
            graph
        )
    )

    # Detect anomalous nodes
    detection = detector.detect(
        graph
    )

    anomalous_nodes = (
        detection["anomalous_nodes"]
    )

    # =====================================================
    # CONTAINMENT
    # =====================================================

    engine = ContainmentEngine()

    actions = engine.generate_actions(
        anomalous_nodes
    )

    # =====================================================
    # TEMPORARY ANOMALY INFORMATION
    # =====================================================

    # Temporary dummy information for dashboard development.
    # Later this can be replaced by actual detector output.

    dummy_anomaly_info = {

        14: {
            "anomaly_score": 0.71,
            "reasons":
                "Unusual graph behaviour"
        },

        21: {
            "anomaly_score": 0.76,
            "reasons":
                "Degree increased"
        },

        22: {
            "anomaly_score": 0.69,
            "reasons":
                "New communication detected"
        },

        30: {
            "anomaly_score": 0.84,
            "reasons":
                "Unusual connectivity pattern"
        },

        40: {
            "anomaly_score": 0.92,
            "reasons":
                "Degree increased; "
                "new communication"
        },

        41: {
            "anomaly_score": 0.88,
            "reasons":
                "Unexpected network communication"
        },

        42: {
            "anomaly_score": 0.95,
            "reasons":
                "Abnormal process behaviour"
        }
    }

    # =====================================================
    # FILTERS
    # =====================================================

    st.sidebar.header(
        "Dashboard Filters"
    )

    # -----------------------------------------------------
    # STATUS FILTER
    # -----------------------------------------------------

    status_filter = st.sidebar.selectbox(
        "Node Status",
        [
            "All",
            "Suspicious Only"
        ]
    )

    # -----------------------------------------------------
    # ANOMALY SCORE FILTER
    # -----------------------------------------------------

    minimum_score = st.sidebar.slider(
        "Minimum Anomaly Score",
        min_value=0.0,
        max_value=1.0,
        value=0.0,
        step=0.05
    )

    # =====================================================
    # FILTER SUSPICIOUS NODES
    # =====================================================

    filtered_anomalous_nodes = []

    for node in anomalous_nodes:

        info = dummy_anomaly_info.get(
            node,
            {
                "anomaly_score": 0.75,
                "reasons":
                    "Behaviour differs from baseline"
            }
        )

        score = info[
            "anomaly_score"
        ]

        # Apply anomaly score filter
        if score < minimum_score:
            continue

        # Apply status filter
        if status_filter == "Suspicious Only":

            filtered_anomalous_nodes.append(
                node
            )

        else:

            filtered_anomalous_nodes.append(
                node
            )

    # =====================================================
    # SYSTEM OVERVIEW
    # =====================================================

    st.subheader(
        "System Overview"
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:

        st.metric(
            "Total Nodes",
            graph.number_of_nodes()
        )

    with c2:

        st.metric(
            "Total Edges",
            graph.number_of_edges()
        )

    with c3:

        st.metric(
            "Suspicious Nodes",
            len(anomalous_nodes)
        )

    with c4:

        st.metric(
            "Filtered Nodes",
            len(filtered_anomalous_nodes)
        )

    # =====================================================
    # SIMULATION / DETECTION
    # =====================================================

    st.divider()

    c1, c2 = st.columns(2)

    with c1:

        st.subheader(
            "Simulation"
        )

        st.write(
            f"**Injected nodes:** "
            f"{injected_nodes}"
        )

        st.write(
            f"**Total nodes:** "
            f"{graph.number_of_nodes()}"
        )

        st.write(
            f"**Total edges:** "
            f"{graph.number_of_edges()}"
        )

    with c2:

        st.subheader(
            "Detection"
        )

        st.write(
            f"**Anomalous nodes:** "
            f"{anomalous_nodes}"
        )

        st.write(
            f"**Detected anomalies:** "
            f"{len(anomalous_nodes)}"
        )

    # =====================================================
    # BEHAVIOURAL NETWORK GRAPH
    # =====================================================

    st.divider()

    st.subheader(
        "Behavioural Network Graph"
    )

    st.write(
        "Red nodes represent suspicious nodes. "
        "Blue nodes represent normal nodes."
    )

    figure = create_network_figure(
        graph,
        anomalous_nodes
    )

    st.plotly_chart(
        figure,
        use_container_width=True
    )

    # =====================================================
    # SUSPICIOUS NODES
    # =====================================================

    st.divider()

    st.subheader(
        "Suspicious Nodes"
    )

    suspicious_data = []

    for node in filtered_anomalous_nodes:

        info = dummy_anomaly_info.get(
            node,
            {
                "anomaly_score": 0.75,
                "reasons":
                    "Behaviour differs from baseline"
            }
        )

        suspicious_data.append(
            {
                "Node": node,

                "Anomaly Score":
                    info["anomaly_score"],

                "Reasons":
                    info["reasons"],

                "Status":
                    "SUSPICIOUS"
            }
        )

    suspicious_df = pd.DataFrame(
        suspicious_data
    )

    if not suspicious_df.empty:

        st.dataframe(
            suspicious_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No suspicious nodes match the selected filters."
        )

    # =====================================================
    # GRAPH METRICS
    # =====================================================

    st.divider()

    st.subheader(
        "Graph Metrics"
    )

    # Calculate betweenness centrality
    betweenness = (
        nx.betweenness_centrality(
            graph
        )
    )

    # -----------------------------------------------------
    # BASELINE DEGREE
    # -----------------------------------------------------

    baseline_degree_values = {}

    for baseline_graph in baseline_graphs:

        for node in baseline_graph.nodes():

            degree = baseline_graph.degree(
                node
            )

            if node not in baseline_degree_values:

                baseline_degree_values[node] = []

            baseline_degree_values[node].append(
                degree
            )

    # -----------------------------------------------------
    # METRICS TABLE
    # -----------------------------------------------------

    metrics_data = []

    for node in filtered_anomalous_nodes:

        current_degree = graph.degree(
            node
        )

        if node in baseline_degree_values:

            average_baseline_degree = (
                sum(
                    baseline_degree_values[node]
                )
                /
                len(
                    baseline_degree_values[node]
                )
            )

        else:

            average_baseline_degree = 0

        degree_change = (
            current_degree
            - average_baseline_degree
        )

        info = dummy_anomaly_info.get(
            node,
            {
                "anomaly_score": 0.75
            }
        )

        metrics_data.append(
            {
                "Node":
                    node,

                "Degree":
                    current_degree,

                "Baseline Degree":
                    round(
                        average_baseline_degree,
                        2
                    ),

                "Degree Change":
                    round(
                        degree_change,
                        2
                    ),

                "Betweenness Centrality":
                    round(
                        betweenness.get(
                            node,
                            0
                        ),
                        4
                    ),

                "Anomaly Score":
                    info[
                        "anomaly_score"
                    ]
            }
        )

    metrics_df = pd.DataFrame(
        metrics_data
    )

    if not metrics_df.empty:

        st.dataframe(
            metrics_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No graph metrics match the selected filters."
        )

    # =====================================================
    # ARTICULATION POINTS
    # =====================================================

    st.divider()

    st.subheader(
        "Articulation Points"
    )

    if graph.number_of_nodes() > 0:

        articulation_points = list(
            nx.articulation_points(
                graph
            )
        )

    else:

        articulation_points = []

    if articulation_points:

        st.write(
            articulation_points
        )

    else:

        st.info(
            "No articulation points detected."
        )

    # =====================================================
    # BRIDGES
    # =====================================================

    st.subheader(
        "Bridges"
    )

    if graph.number_of_edges() > 0:

        bridges = list(
            nx.bridges(
                graph
            )
        )

    else:

        bridges = []

    if bridges:

        bridge_df = pd.DataFrame(
            bridges,
            columns=[
                "Source",
                "Target"
            ]
        )

        st.dataframe(
            bridge_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No bridges detected."
        )

    # =====================================================
    # CONTAINMENT RECOMMENDATION
    # =====================================================

    st.divider()

    st.subheader(
        "Containment Recommendation"
    )

    st.write(
        "Containment actions are generated based "
        "on the detected anomalous nodes."
    )

    if actions:

        action_df = pd.DataFrame(
            {
                "Action": actions
            }
        )

        st.dataframe(
            action_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No containment actions recommended."
        )

    # =====================================================
    # CONTAINMENT EXPLANATION
    # =====================================================

    st.info(
        "The containment recommendation is based on "
        "the simulated behavioural graph. Articulation "
        "points identify critical nodes, while bridges "
        "represent connections whose removal can "
        "disconnect parts of the graph."
    )


# =========================================================
# PROGRAM ENTRY POINT
# =========================================================

if __name__ == "__main__":
    run()