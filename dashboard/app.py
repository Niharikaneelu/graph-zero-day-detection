from __future__ import annotations

import pandas as pd
import streamlit as st

from containment.containment_engine import ContainmentEngine
from detection.anomaly_detector import GraphAnomalyDetector
from simulation.simulator import AttackGraphSimulator


def run() -> None:
    st.set_page_config(page_title="Graph Zero-Day Detection", layout="wide")
    st.title("Graph Zero-Day Detection Dashboard")

    simulator = AttackGraphSimulator(seed=7)
    baseline_graphs = [simulator.generate_normal_snapshot() for _ in range(20)]

    detector = GraphAnomalyDetector(contamination=0.1)
    detector.fit(baseline_graphs)

    graph = simulator.generate_normal_snapshot()
    injected_nodes = simulator.inject_zero_day_pattern(graph)
    detection = detector.detect(graph)

    engine = ContainmentEngine()
    actions = engine.generate_actions(detection["anomalous_nodes"])

    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Simulation")
        st.write(f"Injected nodes: {injected_nodes}")
        st.write(f"Total nodes: {graph.number_of_nodes()}")
        st.write(f"Total edges: {graph.number_of_edges()}")

    with c2:
        st.subheader("Detection")
        st.write(f"Anomalous nodes: {detection['anomalous_nodes']}")

    st.subheader("Containment Actions")
    action_df = pd.DataFrame({"action": actions})
    st.dataframe(action_df, use_container_width=True)


if __name__ == "__main__":
    run()
