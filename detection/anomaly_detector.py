from __future__ import annotations

from typing import Dict

import networkx as nx


class GraphAnomalyDetector:
    """Graph-based behavioural anomaly detector."""

    # Weights used to calculate the explainable anomaly score.
    DEGREE_WEIGHT = 0.40
    DEGREE_CENTRALITY_WEIGHT = 0.25
    BETWEENNESS_WEIGHT = 0.25
    NEW_EDGE_WEIGHT = 0.10

    # Nodes with a score at or above this value are suspicious.
    SUSPICIOUS_THRESHOLD = 0.60

    def __init__(
        self,
        contamination: float = 0.08,
        random_state: int = 42,
    ) -> None:
        """
        Initialize the detector.

        contamination and random_state are retained for compatibility
        with the original detector interface.

        The current implementation uses an explainable graph-based
        scoring method rather than a machine-learning model.
        """

        self.contamination = contamination
        self.random_state = random_state
        self._baseline = None

    @staticmethod
    def calculate_metrics(graph: nx.Graph) -> Dict[str, Dict]:
        """
        Calculate structural metrics for every node.

        Returns:
            A dictionary containing:
            - degree
            - degree centrality
            - betweenness centrality
        """

        degree = dict(graph.degree())

        degree_centrality = nx.degree_centrality(graph)

        betweenness = nx.betweenness_centrality(graph)

        return {
            "degree": degree,
            "degree_centrality": degree_centrality,
            "betweenness": betweenness,
        }

    @classmethod
    def build_baseline(cls, graph: nx.Graph) -> Dict:
        """
        Build a baseline representing normal graph behaviour.

        The baseline stores structural metrics and communication
        edges from a graph representing normal activity.
        """

        metrics = cls.calculate_metrics(graph)

        return {
            "metrics": metrics,
            "edges": set(graph.edges()),
        }

    @staticmethod
    def find_new_edges(
        graph: nx.Graph,
        baseline: Dict,
    ) -> list[tuple]:
        """
        Find communication edges that were not present in the baseline.

        Returns:
            A list of edges that exist in the current graph but
            did not exist in the baseline graph.
        """

        current_edges = set(graph.edges())
        baseline_edges = baseline["edges"]

        return list(current_edges - baseline_edges)

    @staticmethod
    def _relative_change(
        current: float,
        baseline: float,
        node_in_baseline: bool = True,
    ) -> float:
        """
        Calculate the relative increase from a baseline value.

        The result is limited to the range 0.0 to 1.0.

        If the node did not exist in the baseline, its structural
        change is not treated as an anomaly by itself.
        """

        if not node_in_baseline:
            return 0.0

        if baseline == 0:
            return 1.0 if current > 0 else 0.0

        change = (current - baseline) / baseline

        # Only increases contribute to the anomaly score.
        return min(max(change, 0.0), 1.0)

    @classmethod
    def detect_anomalies(
        cls,
        graph: nx.Graph,
        baseline: Dict,
    ) -> list[Dict]:
        """
        Compare the current graph against the baseline.

        Each node receives an explainable anomaly score based on:
        - degree change
        - degree centrality change
        - betweenness centrality change
        - new communication edges

        Returns:
            A list containing one result dictionary per node.
        """

        current_metrics = cls.calculate_metrics(graph)

        baseline_metrics = baseline["metrics"]

        new_edges = cls.find_new_edges(graph, baseline)

        # Find nodes involved in newly observed communication.
        nodes_with_new_edges = set()

        for source, target in new_edges:
            nodes_with_new_edges.add(source)
            nodes_with_new_edges.add(target)

        results = []

        for node in graph.nodes():

            # Current metrics.
            current_degree = current_metrics["degree"].get(node, 0)

            current_degree_centrality = current_metrics[
                "degree_centrality"
            ].get(node, 0.0)

            current_betweenness = current_metrics[
                "betweenness"
            ].get(node, 0.0)

            # Baseline metrics.
            baseline_degree = baseline_metrics["degree"].get(node, 0)

            baseline_degree_centrality = baseline_metrics[
                "degree_centrality"
            ].get(node, 0.0)

            baseline_betweenness = baseline_metrics[
                "betweenness"
            ].get(node, 0.0)

            # Check whether this node existed in normal behaviour.
            node_in_baseline = node in baseline_metrics["degree"]

            # Calculate changes from baseline.
            degree_change = cls._relative_change(
                current_degree,
                baseline_degree,
                node_in_baseline,
            )

            degree_centrality_change = cls._relative_change(
                current_degree_centrality,
                baseline_degree_centrality,
                node_in_baseline,
            )

            betweenness_change = cls._relative_change(
                current_betweenness,
                baseline_betweenness,
                node_in_baseline,
            )

            # New communication signal.
            new_edge_signal = (
                1.0 if node in nodes_with_new_edges else 0.0
            )

            # Weighted anomaly score.
            anomaly_score = (
                cls.DEGREE_WEIGHT * degree_change
                + cls.DEGREE_CENTRALITY_WEIGHT
                * degree_centrality_change
                + cls.BETWEENNESS_WEIGHT
                * betweenness_change
                + cls.NEW_EDGE_WEIGHT * new_edge_signal
            )

            # Keep score between 0 and 1.
            anomaly_score = min(max(anomaly_score, 0.0), 1.0)

            # Generate human-readable reasons.
            reasons = []

            if degree_change > 0:
                reasons.append("degree increased")

            if degree_centrality_change > 0:
                reasons.append("degree centrality increased")

            if betweenness_change > 0:
                reasons.append("betweenness centrality increased")

            if node in nodes_with_new_edges:
                reasons.append("new communication edge detected")

            # Determine final status.
            status = (
                "SUSPICIOUS"
                if anomaly_score >= cls.SUSPICIOUS_THRESHOLD
                else "NORMAL"
            )

            results.append(
                {
                    "node": node,
                    "anomaly_score": round(anomaly_score, 2),
                    "reasons": reasons,
                    "status": status,
                }
            )

        return results

    @staticmethod
    def get_suspicious_nodes(results: list[Dict]) -> list:
        """
        Extract nodes classified as suspicious.
        """

        return [
            result["node"]
            for result in results
            if result["status"] == "SUSPICIOUS"
        ]

    # ------------------------------------------------------------------
    # Compatibility interface
    # ------------------------------------------------------------------

    def fit(self, baseline_graphs: list[nx.Graph]) -> None:
        """
        Build a baseline from multiple normal graphs.

        This method preserves compatibility with the original
        detector interface:

            detector = GraphAnomalyDetector()
            detector.fit(baseline_graphs)
            detector.detect(graph)

        The baseline is constructed by combining observations from
        all supplied normal graphs.
        """

        if not baseline_graphs:
            raise ValueError("No baseline graphs available.")

        all_nodes = set()
        all_edges = set()

        degree_values = {}
        degree_centrality_values = {}
        betweenness_values = {}

        for graph in baseline_graphs:

            metrics = self.calculate_metrics(graph)

            all_nodes.update(graph.nodes())
            all_edges.update(graph.edges())

            for node, value in metrics["degree"].items():
                degree_values.setdefault(node, []).append(value)

            for node, value in metrics["degree_centrality"].items():
                degree_centrality_values.setdefault(node, []).append(value)

            for node, value in metrics["betweenness"].items():
                betweenness_values.setdefault(node, []).append(value)

        # Average the normal metric values across baseline snapshots.
        baseline_metrics = {
            "degree": {
                node: sum(values) / len(values)
                for node, values in degree_values.items()
            },
            "degree_centrality": {
                node: sum(values) / len(values)
                for node, values in degree_centrality_values.items()
            },
            "betweenness": {
                node: sum(values) / len(values)
                for node, values in betweenness_values.items()
            },
        }

        self._baseline = {
            "metrics": baseline_metrics,
            "edges": all_edges,
        }

    def detect(self, graph: nx.Graph) -> Dict:
        """
        Compatibility wrapper for the original detector API.

        Returns:
            A dictionary containing the anomalous nodes.
        """

        if self._baseline is None:
            raise RuntimeError(
                "Detector must be fitted before calling detect()."
            )

        results = self.detect_anomalies(
            graph,
            self._baseline,
        )

        suspicious_nodes = self.get_suspicious_nodes(results)

        return {
            "anomalous_nodes": suspicious_nodes,
        }