from __future__ import annotations

from typing import Any, Dict, List, Tuple

import networkx as nx


class ContainmentEngine:
    """
    Graph-based containment engine.

    The engine identifies the minimum set of edges that should be
    removed to isolate suspicious nodes from the trusted part of
    the network.

    Suspicious nodes themselves are never removed.
    """

    def __init__(self, graph: nx.Graph | None = None) -> None:
        self.graph = graph

    def generate_actions(self, anomalous_nodes: List[int]) -> List[str]:
        """
        Existing containment interface.

        Kept for compatibility with the existing project.
        """
        if not anomalous_nodes:
            return ["No containment needed. Monitor continuously."]

        actions = []

        for node_id in anomalous_nodes:
            actions.append(
                f"Isolate node {node_id} from the network segment"
            )
            actions.append(
                f"Block outbound traffic from node {node_id}"
            )
            actions.append(
                f"Trigger deep malware scan for node {node_id}"
            )

        return actions

    def find_minimum_cut(
        self,
        graph: nx.Graph | None = None,
        suspicious_nodes: List[int] | None = None,
    ) -> List[Tuple[int, int]]:
        """
        Find the minimum edge cut separating suspicious nodes
        from trusted nodes.

        Every real graph edge has capacity 1. Therefore, the
        minimum cut minimizes the number of real connections
        that need to be removed.

        A super-source is connected to suspicious nodes and a
        super-sink is connected to trusted nodes with very large
        capacity.

        Returns:
            List of graph edges recommended for removal.
        """
        graph = graph if graph is not None else self.graph

        if graph is None:
            raise ValueError("A NetworkX graph must be provided.")

        if suspicious_nodes is None:
            suspicious_nodes = []

        # Remove duplicate suspicious node IDs while preserving order.
        suspicious = list(dict.fromkeys(suspicious_nodes))

        # Only consider suspicious nodes that actually exist.
        suspicious = [
            node for node in suspicious
            if node in graph
        ]

        if not suspicious:
            return []

        # If every node is suspicious, there is no trusted region.
        trusted = [
            node for node in graph.nodes
            if node not in suspicious
        ]

        if not trusted:
            return []

        # If the suspicious nodes are already separated from all
        # trusted nodes, no edge needs to be removed.
        for suspicious_node in suspicious:
            for trusted_node in trusted:
                if nx.has_path(graph, suspicious_node, trusted_node):
                    break
            else:
                continue
            break
        else:
            return []

        # Create a directed flow graph.
        flow_graph = nx.DiGraph()

        super_source = "__CONTAINMENT_SOURCE__"
        super_sink = "__CONTAINMENT_SINK__"

        # Avoid possible name collisions.
        while super_source in graph:
            super_source += "_"

        while super_sink in graph or super_sink == super_source:
            super_sink += "_"

        # Add all original nodes.
        flow_graph.add_nodes_from(graph.nodes)

        # Every real edge has capacity 1.
        #
        # For an undirected graph, add both directions.
        for u, v in graph.edges:
            flow_graph.add_edge(u, v, capacity=1)
            flow_graph.add_edge(v, u, capacity=1)

        # Artificial source/sink connections must never be cheaper
        # than cutting real edges.
        infinite_capacity = graph.number_of_edges() + 1

        for node in suspicious:
            flow_graph.add_edge(
                super_source,
                node,
                capacity=infinite_capacity,
            )

        for node in trusted:
            flow_graph.add_edge(
                node,
                super_sink,
                capacity=infinite_capacity,
            )

        # NetworkX computes the minimum cut using a max-flow
        # algorithm internally.
        _, partition = nx.minimum_cut(
            flow_graph,
            super_source,
            super_sink,
            capacity="capacity",
        )

        source_side, sink_side = partition

        cut_edges = []

        # Find which ORIGINAL graph edges cross the cut.
        for u, v in graph.edges:
            if (
                (u in source_side and v in sink_side)
                or
                (v in source_side and u in sink_side)
            ):
                cut_edges.append((u, v))

        return cut_edges

    def find_articulation_points(
        self,
        graph: nx.Graph | None = None,
    ) -> List[int]:
        """
        Find articulation points.

        An articulation point is a node whose removal would
        increase the number of connected components.
        """
        graph = graph if graph is not None else self.graph

        if graph is None:
            raise ValueError("A NetworkX graph must be provided.")

        return list(nx.articulation_points(graph))

    def find_bridges(
        self,
        graph: nx.Graph | None = None,
    ) -> List[Tuple[int, int]]:
        """
        Find bridges.

        A bridge is an edge whose removal disconnects a connected
        component of the graph.
        """
        graph = graph if graph is not None else self.graph

        if graph is None:
            raise ValueError("A NetworkX graph must be provided.")

        return list(nx.bridges(graph))

    def is_isolated(
        self,
        graph: nx.Graph,
        suspicious_nodes: List[int],
    ) -> bool:
        """
        Check whether suspicious nodes are completely separated
        from trusted nodes.
        """
        suspicious = [
            node for node in suspicious_nodes
            if node in graph
        ]

        if not suspicious:
            return False

        trusted = set(graph.nodes) - set(suspicious)

        # No trusted nodes means there is nothing to isolate from.
        if not trusted:
            return True

        for suspicious_node in suspicious:
            for trusted_node in trusted:
                if nx.has_path(
                    graph,
                    suspicious_node,
                    trusted_node,
                ):
                    return False

        return True

    def generate_containment_plan(
        self,
        graph: nx.Graph | None = None,
        suspicious_nodes: List[int] | None = None,
    ) -> Dict[str, Any]:
        """
        Generate a complete containment recommendation.

        Returns information about:
          - suspicious nodes
          - minimum cut edges
          - containment actions
          - articulation points
          - bridges
          - number of edges to remove
          - successful isolation
          - explanation
        """
        graph = graph if graph is not None else self.graph

        if graph is None:
            raise ValueError("A NetworkX graph must be provided.")

        if suspicious_nodes is None:
            suspicious_nodes = []

        suspicious = list(dict.fromkeys(suspicious_nodes))

        valid_suspicious = [
            node for node in suspicious
            if node in graph
        ]

        articulation_points = self.find_articulation_points(graph)
        bridges = self.find_bridges(graph)

        # No suspicious nodes.
        if not valid_suspicious:
            return {
                "suspicious_nodes": [],
                "cut_edges": [],
                "recommended_edges": [],
                "containment_actions": [
                    "No suspicious nodes were detected; "
                    "no containment action required."
                ],
                "articulation_points": articulation_points,
                "bridges": bridges,
                "number_of_edges_removed": 0,
                "isolated": False,
                "explanation": (
                    "No valid suspicious nodes were provided."
                ),
            }

        recommended_edges = self.find_minimum_cut(
            graph,
            valid_suspicious,
        )

        # Verify isolation without modifying the original graph.
        test_graph = graph.copy()
        test_graph.remove_edges_from(recommended_edges)

        isolated = self.is_isolated(
            test_graph,
            valid_suspicious,
        )

        actions = []

        for u, v in recommended_edges:

            if (u, v) in bridges or (v, u) in bridges:
                reason = (
                    "This edge is a bridge, so removing it "
                    "disconnects part of the network."
                )

            elif (
                u in articulation_points
                or v in articulation_points
            ):
                reason = (
                    "This edge is connected to an articulation "
                    "point and is part of a critical network "
                    "connection."
                )

            else:
                reason = (
                    "This edge belongs to the minimum edge cut, "
                    "so removing it provides a minimum-disruption "
                    "way to isolate the suspicious region."
                )

            actions.append(
                f"Cut edge ({u}, {v}): {reason}"
            )

        if isolated:
            actions.append(
                "The suspicious region was successfully "
                "isolated from the trusted region."
            )
        else:
            actions.append(
                "The suspicious region could not be completely "
                "isolated using the calculated edge cut."
            )

        return {
            "suspicious_nodes": valid_suspicious,
            "cut_edges": recommended_edges,
            "recommended_edges": recommended_edges,
            "containment_actions": actions,
            "articulation_points": articulation_points,
            "bridges": bridges,
            "number_of_edges_removed": len(recommended_edges),
            "isolated": isolated,
            "explanation": (
                f"Minimum edge cut contains "
                f"{len(recommended_edges)} edge(s). "
                f"The suspicious region is "
                f"{'successfully' if isolated else 'not successfully'} "
                f"isolated from the trusted region."
            ),
        }

    def contain(
        self,
        graph: nx.Graph | None = None,
        suspicious_nodes: List[int] | None = None,
    ) -> Dict[str, Any]:
        """
        Compatibility alias for generating a containment plan.
        """
        return self.generate_containment_plan(
            graph,
            suspicious_nodes,
        )