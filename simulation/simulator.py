from __future__ import annotations

import random
from typing import List

import networkx as nx


class AttackGraphSimulator:
    """Builds baseline graph snapshots and injects simple attack-like patterns."""

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)

    def generate_normal_snapshot(self, node_count: int = 40, edge_prob: float = 0.08) -> nx.Graph:
        graph = nx.erdos_renyi_graph(node_count, edge_prob, seed=self._rng.randint(0, 10_000))
        if not nx.is_connected(graph):
            largest_cc = max(nx.connected_components(graph), key=len)
            graph = graph.subgraph(largest_cc).copy()
        return graph

    def inject_zero_day_pattern(self, graph: nx.Graph, attack_nodes: int = 3) -> List[int]:
        """Injects a dense malicious cluster and connects it to critical nodes."""
        start_id = max(graph.nodes, default=-1) + 1
        new_nodes = list(range(start_id, start_id + attack_nodes))

        graph.add_nodes_from(new_nodes)

        for i in range(len(new_nodes)):
            for j in range(i + 1, len(new_nodes)):
                graph.add_edge(new_nodes[i], new_nodes[j])

        # Bridge attack cluster into high-degree nodes to simulate lateral movement.
        degree_sorted = sorted(graph.degree, key=lambda pair: pair[1], reverse=True)
        bridge_targets = [node for node, _ in degree_sorted[: min(3, len(degree_sorted))]]

        for attacker in new_nodes:
            for target in bridge_targets:
                if attacker != target:
                    graph.add_edge(attacker, target)

        return new_nodes
