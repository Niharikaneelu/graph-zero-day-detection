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
    