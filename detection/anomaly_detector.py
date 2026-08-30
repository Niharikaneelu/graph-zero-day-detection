from __future__ import annotations

from typing import Dict

import networkx as nx


class GraphAnomalyDetector:
    """Graph-based behavioural anomaly detector."""

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

        The baseline stores the graph's structural metrics and
        communication edges so that a later graph can be compared
        against normal behaviour.
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
            A list of edges that exist in the current graph
            but did not exist in the baseline graph.
        """

        current_edges = set(graph.edges())
        baseline_edges = baseline["edges"]

        return list(current_edges - baseline_edges)