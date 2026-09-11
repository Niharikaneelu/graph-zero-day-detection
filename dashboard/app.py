from __future__ import annotations

from pathlib import Path
import sys
import random
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

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

def create_network_figure(graph, anomalous_nodes, cut_edges=None):
    """Create an interactive Plotly visualization of the graph."""

    if graph.number_of_nodes() == 0:
        return go.Figure()

    positions = nx.spring_layout(
        graph,
        seed=7
    )

    anomalous_set = set(anomalous_nodes)
    cut_edge_set = {
        frozenset(edge)
        for edge in (cut_edges or [])
    }

    # -----------------------------------------------------
    # EDGES
    # -----------------------------------------------------

    edge_x = []
    edge_y = []
    cut_edge_x = []
    cut_edge_y = []

    for source, target in graph.edges():

        x0, y0 = positions[source]
        x1, y1 = positions[target]

        if frozenset((source, target)) in cut_edge_set:
            cut_edge_x.extend([x0, x1, None])
            cut_edge_y.extend([y0, y1, None])
        else:
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line=dict(width=1, color="#9cb8b4"),
        hoverinfo="none",
    )

    cut_edge_trace = go.Scatter(
        x=cut_edge_x,
        y=cut_edge_y,
        mode="lines",
        line=dict(width=3, color="#d85f52", dash="dash"),
        name="Recommended cut",
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
            node_colors.append("#d85f52")
            status = "SUSPICIOUS"
        else:
            node_colors.append("#147d80")
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
            cut_edge_trace,
            node_trace
        ]
    )

    figure.update_layout(
        title="Behavioural Network Graph",
        showlegend=bool(cut_edge_x),
        hovermode="closest",
        paper_bgcolor="#f7f5ef",
        plot_bgcolor="#f7f5ef",
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

    attack_scenario = st.selectbox(
        "Attack scenario",
        [
            "Injected zero-day cluster",
            "connection_burst",
            "unusual_external",
            "lateral_movement",
        ],
    )

    # -----------------------------------------------------
    # SIMULATION
    # -----------------------------------------------------

    if st.button("Generate New Simulation"):
        st.session_state.seed = random.randint(1, 100000)
    if "seed" not in st.session_state:
        st.session_state.seed = 7
    simulator = AttackGraphSimulator(
        seed=st.session_state.seed
    )


    baseline_graphs = [
        simulator.build_graph(
            simulator.generate_normal_events(num_events=20)
        )
        for _ in range(30)
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

    normal_events = simulator.generate_normal_events(num_events=20)
    graph = simulator.build_graph(normal_events)
    injected_nodes = []

    # Ground truth for the currently selected scenario. For the
    # injected zero-day cluster this is the set of brand-new nodes;
    # for the event-based scenarios it is the node the simulator
    # used as the attack source. Surfacing this lets a viewer
    # directly check the detector's output against the actual
    # attacker, rather than taking the detection on faith.
    ground_truth_nodes = []

    if attack_scenario == "Injected zero-day cluster":
        injected_nodes = simulator.inject_zero_day_pattern(graph)
        ground_truth_nodes = injected_nodes
    else:
        attack_events = simulator.generate_attack_events(
            scenario=attack_scenario,
            num_events=5,
        )
        graph = simulator.build_graph(normal_events + attack_events)
        ground_truth_nodes = [attack_events[0]["source"]]

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
        detector.get_baseline(),
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
    recommended_edges = containment_plan.get(
        "recommended_edges",
        [],
    )

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
            "Ground Truth Attack Nodes",
            len(ground_truth_nodes)
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
            f"Ground truth attack node(s): {ground_truth_nodes}"
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

        caught = set(ground_truth_nodes).issubset(set(anomalous_nodes))

        if ground_truth_nodes:
            if caught:
                st.success(
                    "All ground truth attack node(s) were detected."
                )
            else:
                missed = set(ground_truth_nodes) - set(anomalous_nodes)
                st.warning(
                    f"Missed ground truth node(s): {sorted(missed)}. "
                    "This attack scenario is known to be harder for "
                    "the detector to catch reliably."
                )

    # =====================================================
    # NETWORK GRAPH
    # =====================================================

    st.subheader(
        "Behavioural Network Graph"
    )

    figure = create_network_figure(
        graph,
        anomalous_nodes,
        recommended_edges,
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