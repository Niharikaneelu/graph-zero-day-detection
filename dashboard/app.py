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
    """Create an interactive Plotly visualization of the graph."""

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

        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line=dict(width=1),
        hoverinfo="none",
    )

    # -----------------------------------------------------
    # NODES
    # -----------------------------------------------------

    node_x = []
    node_y = []
    node_text = []
    node_colors = []

    for node in graph.nodes():

        x, y = positions[node]

        node_x.append(x)
        node_y.append(y)

        node_type = get_node_type(
            graph,
            node
        )

        degree = graph.degree(node)

        if node in anomalous_set:
            node_colors.append("red")
            status = "SUSPICIOUS"
        else:
            node_colors.append("blue")
            status = "NORMAL"

        node_text.append(
            f"Node: {node}<br>"
            f"Type: {node_type}<br>"
            f"Degree: {degree}<br>"
            f"Status: {status}"
        )

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
            line=dict(width=1),
        ),
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
            showticklabels=False,
        ),
        yaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False,
        ),
        height=650,
    )

    return figure


# =========================================================
# MAIN APPLICATION
# =========================================================

def run():

    # -----------------------------------------------------
    # PAGE CONFIGURATION
    # -----------------------------------------------------

    st.set_page_config(
        page_title="Graph Zero-Day Detection",
        layout="wide"
    )

    st.title(
        "Graph Zero-Day Detection Dashboard"
    )

    # -----------------------------------------------------
    # SIMULATION
    # -----------------------------------------------------

    simulator = AttackGraphSimulator(
        seed=7
    )

    baseline_graphs = [
        simulator.generate_normal_snapshot()
        for _ in range(20)
    ]

    # -----------------------------------------------------
    # DETECTOR
    # -----------------------------------------------------

    detector = GraphAnomalyDetector(
        contamination=0.1
    )

    detector.fit(
        baseline_graphs
    )

    graph = simulator.generate_normal_snapshot()

    injected_nodes = (
        simulator.inject_zero_day_pattern(
            graph
        )
    )

    # -----------------------------------------------------
    # ACTUAL DETECTION
    # -----------------------------------------------------

    detection = detector.detect(
        graph
    )

    anomalous_nodes = detection[
        "anomalous_nodes"
    ]

    detailed_results = detector.detect_anomalies(
        graph,
        detector._baseline
    )

    # -----------------------------------------------------
    # ACTUAL CONTAINMENT
    # -----------------------------------------------------

    engine = ContainmentEngine(
        graph
    )

    containment_plan = engine.generate_containment_plan(
        graph,
        anomalous_nodes
    )

    actions = containment_plan[
        "containment_actions"
    ]

    # =====================================================
    # SUMMARY METRICS
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
            "Injected Nodes",
            len(injected_nodes)
        )

    # =====================================================
    # SIMULATION / DETECTION
    # =====================================================

    c1, c2 = st.columns(2)

    with c1:

        st.subheader(
            "Simulation"
        )

        st.write(
            f"Injected nodes: {injected_nodes}"
        )

        st.write(
            f"Total nodes: "
            f"{graph.number_of_nodes()}"
        )

        st.write(
            f"Total edges: "
            f"{graph.number_of_edges()}"
        )

    with c2:

        st.subheader(
            "Detection"
        )

        st.write(
            f"Anomalous nodes: "
            f"{anomalous_nodes}"
        )

    # =====================================================
    # NETWORK GRAPH
    # =====================================================

    st.subheader(
        "Behavioural Network Graph"
    )

    figure = create_network_figure(
        graph,
        anomalous_nodes
    )

    st.plotly_chart(
        figure,
        width="stretch"
    )

    # =====================================================
    # SUSPICIOUS NODES
    # =====================================================

    st.subheader(
        "Suspicious Nodes"
    )

    suspicious_data = []

    for result in detailed_results:

        if result["status"] != "SUSPICIOUS":
            continue

        reasons = result.get(
            "reasons",
            []
        )

        if reasons:
            reason_text = "; ".join(
                reasons
            )
        else:
            reason_text = (
                "Behaviour differs from baseline"
            )

        suspicious_data.append(
            {
                "Node": result["node"],
                "Anomaly Score": result[
                    "anomaly_score"
                ],
                "Reasons": reason_text,
                "Status": result[
                    "status"
                ],
            }
        )

    suspicious_df = pd.DataFrame(
        suspicious_data
    )

    if not suspicious_df.empty:

        suspicious_df = (
            suspicious_df
            .sort_values(
                by="Anomaly Score",
                ascending=False
            )
            .reset_index(drop=True)
        )

        st.dataframe(
            suspicious_df,
            width="stretch",
            hide_index=True,
        )

    else:

        st.info(
            "No suspicious nodes detected."
        )

    # =====================================================
    # GRAPH METRICS
    # =====================================================

    st.subheader(
        "Graph Metrics"
    )

    degree = dict(
        graph.degree()
    )

    degree_centrality = (
        nx.degree_centrality(graph)
    )

    betweenness = (
        nx.betweenness_centrality(graph)
    )

    anomaly_score_lookup = {
        result["node"]: result[
            "anomaly_score"
        ]
        for result in detailed_results
    }

    metric_data = []

    for node in anomalous_nodes:

        metric_data.append(
            {
                "Node": node,
                "Degree": degree.get(
                    node,
                    0
                ),
                "Degree Centrality": round(
                    degree_centrality.get(
                        node,
                        0.0
                    ),
                    4
                ),
                "Betweenness Centrality": round(
                    betweenness.get(
                        node,
                        0.0
                    ),
                    4
                ),
                "Anomaly Score": anomaly_score_lookup.get(
                    node,
                    0.0
                ),
            }
        )

    metrics_df = pd.DataFrame(
        metric_data
    )

    if not metrics_df.empty:

        metrics_df = (
            metrics_df
            .sort_values(
                by="Anomaly Score",
                ascending=False
            )
            .reset_index(drop=True)
        )

        st.dataframe(
            metrics_df,
            width="stretch",
            hide_index=True,
        )

    else:

        st.info(
            "No graph metrics available."
        )

    # =====================================================
    # CONTAINMENT RECOMMENDATION
    # =====================================================

    st.subheader(
        "Containment Recommendation"
    )

    # -----------------------------------------------------
    # SUSPICIOUS REGION
    # -----------------------------------------------------

    st.write(
        "**Suspicious Region**"
    )

    suspicious_region = containment_plan.get(
        "suspicious_nodes",
        []
    )

    if suspicious_region:

        suspicious_region_text = ", ".join(
            str(node)
            for node in suspicious_region
        )

        st.info(
            suspicious_region_text
        )

    else:

        st.info(
            "No suspicious region identified."
        )

    # -----------------------------------------------------
    # RECOMMENDED CUT EDGES
    # -----------------------------------------------------

    st.write(
        "**Recommended Cut Edges**"
    )

    recommended_edges = containment_plan.get(
        "recommended_edges",
        []
    )

    if recommended_edges:

        edge_data = []

        for edge in recommended_edges:

            if len(edge) >= 2:

                edge_data.append(
                    {
                        "Source": edge[0],
                        "Target": edge[1],
                    }
                )

        if edge_data:

            edge_df = pd.DataFrame(
                edge_data
            )

            st.dataframe(
                edge_df,
                width="stretch",
                hide_index=True,
            )

        else:

            st.info(
                "No recommended cut edges."
            )

    else:

        st.info(
            "No recommended cut edges."
        )

    # -----------------------------------------------------
    # ARTICULATION POINTS
    # -----------------------------------------------------

    st.write(
        "**Articulation Points**"
    )

    articulation_points = containment_plan.get(
        "articulation_points",
        []
    )

    if articulation_points:

        articulation_text = ", ".join(
            str(node)
            for node in articulation_points
        )

        st.info(
            articulation_text
        )

    else:

        st.info(
            "No articulation points identified."
        )

    # -----------------------------------------------------
    # BRIDGES
    # -----------------------------------------------------

    st.write(
        "**Bridges**"
    )

    bridges = containment_plan.get(
        "bridges",
        []
    )

    if bridges:

        bridge_data = []

        for bridge in bridges:

            if len(bridge) >= 2:

                bridge_data.append(
                    {
                        "Source": bridge[0],
                        "Target": bridge[1],
                    }
                )

        if bridge_data:

            bridge_df = pd.DataFrame(
                bridge_data
            )

            st.dataframe(
                bridge_df,
                width="stretch",
                hide_index=True,
            )

        else:

            st.info(
                "No bridges identified."
            )

    else:

        st.info(
            "No bridges identified."
        )

    # -----------------------------------------------------
    # NUMBER OF EDGES REMOVED
    # -----------------------------------------------------

    number_of_edges_removed = containment_plan.get(
        "number_of_edges_removed",
        0
    )

    st.metric(
        "Recommended Edges to Remove",
        number_of_edges_removed
    )

    # -----------------------------------------------------
    # ISOLATION STATUS
    # -----------------------------------------------------

    isolated = containment_plan.get(
        "isolated",
        False
    )

    if isolated:

        st.success(
            "Suspicious region can be isolated from the trusted region."
        )

    else:

        st.warning(
            "Complete isolation was not confirmed."
        )

    # -----------------------------------------------------
    # EXPLANATION
    # -----------------------------------------------------

    explanation = containment_plan.get(
        "explanation",
        ""
    )

    if explanation:

        st.write(
            "**Why this containment is recommended:**"
        )

        st.info(
            explanation
        )

    # =====================================================
    # CONTAINMENT ACTIONS
    # =====================================================

    st.write(
        "**Containment Actions**"
    )

    if actions:

        action_df = pd.DataFrame(
            {
                "Action": actions
            }
        )

        st.dataframe(
            action_df,
            width="stretch",
            hide_index=True,
        )

    else:

        st.info(
            "No containment actions required."
        )


# =========================================================
# APPLICATION ENTRY POINT
# =========================================================

if __name__ == "__main__":
    run()