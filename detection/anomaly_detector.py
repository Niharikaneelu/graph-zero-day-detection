from __future__ import annotations

from typing import Dict, List

import networkx as nx
import numpy as np
from sklearn.ensemble import IsolationForest


class GraphAnomalyDetector:
    """Node-level anomaly detector using graph structural features."""

    def __init__(self, contamination: float = 0.08, random_state: int = 42) -> None:
        self.model = IsolationForest(contamination=contamination, random_state=random_state)
        self._is_fitted = False

    def _extract_features(self, graph: nx.Graph) -> tuple[list[int], np.ndarray]:
        nodes = list(graph.nodes())
        degrees = dict(graph.degree())
        clustering = nx.clustering(graph)

        features = np.array([
            [degrees[node], clustering[node]]
            for node in nodes
        ])
        return nodes, features

    def fit(self, baseline_graphs: List[nx.Graph]) -> None:
        all_features = []
        for graph in baseline_graphs:
            _, features = self._extract_features(graph)
            if len(features) > 0:
                all_features.append(features)

        if not all_features:
            raise ValueError("No baseline features available for training.")

        dataset = np.vstack(all_features)
        self.model.fit(dataset)
        self._is_fitted = True

    def detect(self, graph: nx.Graph) -> Dict[str, List[int]]:
        if not self._is_fitted:
            raise RuntimeError("Detector must be fitted before calling detect().")

        nodes, features = self._extract_features(graph)
        if len(features) == 0:
            return {"anomalous_nodes": []}

        predictions = self.model.predict(features)
        anomalies = [node for node, pred in zip(nodes, predictions) if pred == -1]

        return {"anomalous_nodes": anomalies}
