from __future__ import annotations

from typing import Dict

import networkx as nx


class GraphAnomalyDetector:
    """Graph-based behavioural anomaly detector."""

    # Weights used to calculate the explainable anomaly score.
    DEGREE_WEIGHT = 0.25
    DEGREE_CENTRALITY_WEIGHT = 0.15
    BETWEENNESS_WEIGHT = 0.15
    NEW_EDGE_WEIGHT = 0.10
    NEW_NODE_WEIGHT = 0.20
    EDGE_WEIGHT_WEIGHT = 0.15
    BURST_WEIGHT = 0.50
    EXTERNAL_COMMUNICATION_WEIGHT = 0.45
    LATERAL_MOVEMENT_WEIGHT = 0.40

    # Nodes with a score at or above this value are suspicious.
    SUSPICIOUS_THRESHOLD = 0.62

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

    def _threshold(self) -> float:
        """Return the configured decision threshold."""

        if not 0.0 < self.contamination < 1.0:
            raise ValueError("contamination must be between 0 and 1.")

        return min(
            max(self.SUSPICIOUS_THRESHOLD - (self.contamination - 0.08), 0.1),
            0.95,
        )

    @staticmethod
    def calculate_metrics(graph: nx.Graph) -> Dict[str, Dict]:
        """
        Calculate structural metrics for every node.

        Returns:
            A dictionary containing:
            - degree
            - degree centrality
            - betweenness centrality
            - edge weight sum (total communication volume)
        """

        degree = dict(graph.degree())

        degree_centrality = nx.degree_centrality(graph)

        betweenness = nx.betweenness_centrality(graph)

        # Weighted degree: sum of the weights of every edge incident
        # to a node. Repeated communication on the same edge (e.g. a
        # process contacting the same host many times) raises this
        # value even when the node's plain degree stays flat, since
        # degree only counts *unique* neighbours. This is important
        # for catching burst-style attacks against a small pool of
        # targets, where unique-neighbour count saturates quickly but
        # communication volume keeps climbing. Edges without an
        # explicit weight attribute default to a weight of 1.
        edge_weight_sum = dict(graph.degree(weight="weight"))

        return {
            "degree": degree,
            "degree_centrality": degree_centrality,
            "betweenness": betweenness,
            "edge_weight_sum": edge_weight_sum,
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
    ) -> float:
        """
        Calculate the relative increase from a baseline value.

        The result is limited to the range 0.0 to 1.0.

        A missing baseline value is treated as 0, so a node that
        did not exist in the baseline but now shows any structural
        presence (e.g. a nonzero degree) registers as a full
        relative change. This matters because a previously unseen
        entity appearing with real connections is itself a
        meaningful anomaly signal, not something to be ignored.
        """

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
        threshold: float | None = None,
    ) -> list[Dict]:
        """
        Compare the current graph against the baseline.

        Each node receives an explainable anomaly score based on:
        - degree change
        - degree centrality change
        - betweenness centrality change
        - new communication edges
        - communication-volume change from edge weights
        - previously unseen nodes

        Returns:
            A list containing one result dictionary per node.
        """

        current_metrics = cls.calculate_metrics(graph)

        baseline_metrics = baseline["metrics"]
        scoring_metrics = baseline.get("scoring_metrics", baseline_metrics)

        new_edges = cls.find_new_edges(graph, baseline)

        # Find nodes involved in newly observed communication.
        nodes_with_new_edges = set()
        nodes_with_new_edge_sources = set()

        for source, target in new_edges:
            nodes_with_new_edges.add(source)
            nodes_with_new_edges.add(target)
            source_counts = graph[source][target].get(
                "source_counts",
                {},
            )
            if source_counts:
                nodes_with_new_edge_sources.update(source_counts)

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

            current_edge_weight_sum = current_metrics[
                "edge_weight_sum"
            ].get(node, 0.0)

            # Baseline metrics.
            baseline_degree = scoring_metrics["degree"].get(node, 0)

            baseline_degree_centrality = scoring_metrics[
                "degree_centrality"
            ].get(node, 0.0)

            baseline_betweenness = scoring_metrics[
                "betweenness"
            ].get(node, 0.0)

            has_edge_weight_baseline = (
                "edge_weight_sum" in scoring_metrics
            )
            baseline_edge_weight_sum = scoring_metrics.get(
                "edge_weight_sum",
                {},
            ).get(node, 0.0)

            # Check whether this node existed in normal behaviour.
            node_in_baseline = node in baseline_metrics["degree"]

            # Calculate changes from baseline. A missing baseline
            # value defaults to 0 (see the .get() calls above), so
            # _relative_change naturally treats a previously unseen
            # node's real activity as a full relative change.
            degree_change = cls._relative_change(
                current_degree,
                baseline_degree,
            )

            degree_centrality_change = cls._relative_change(
                current_degree_centrality,
                baseline_degree_centrality,
            )

            betweenness_change = cls._relative_change(
                current_betweenness,
                baseline_betweenness,
            )

            # Communication-volume change. Distinct from degree_change:
            # a node repeatedly contacting the same few neighbours
            # keeps a flat degree but a rising edge-weight sum, which
            # is exactly the fingerprint of a connection-burst attack
            # against a small pool of targets.
            edge_weight_change = (
                cls._relative_change(
                    current_edge_weight_sum,
                    baseline_edge_weight_sum,
                )
                if has_edge_weight_baseline
                else 0.0
            )

            # The event graph retains event types on each edge. A repeated
            # process-communication pattern identifies the initiating process
            # without incorrectly scoring the contacted hosts as attackers.
            process_communication_volume = 0
            outgoing_external_targets = set()
            outgoing_internal_host_targets = set()
            outgoing_network_volume = 0
            if graph.nodes[node].get("type") == "process":
                for neighbour in graph.neighbors(node):
                    edge_data = graph[node][neighbour]
                    event_types = edge_data.get("event_types", set())
                    if "PROCESS_COMMUNICATION" in event_types:
                        process_communication_volume += edge_data.get(
                            "weight",
                            1,
                        )
            for neighbour in graph.neighbors(node):
                edge_data = graph[node][neighbour]
                source_counts = edge_data.get("source_counts", {})
                if source_counts and node not in source_counts:
                    continue
                event_types = edge_data.get("event_types", set())
                if "NETWORK_CONNECTION" not in event_types:
                    continue
                outgoing_network_volume += source_counts.get(
                    node,
                    edge_data.get("weight", 1),
                )
                neighbour_type = graph.nodes[neighbour].get("type")
                if neighbour_type == "external":
                    outgoing_external_targets.add(neighbour)
                elif neighbour_type == "host":
                    outgoing_internal_host_targets.add(neighbour)

            burst_signal = (
                1.0 if process_communication_volume >= 3 else 0.0
            )
            external_signal = (
                1.0
                if outgoing_external_targets
                and graph.nodes[node].get("type") == "host"
                else 0.0
            )
            lateral_signal = (
                1.0
                if (
                    len(outgoing_internal_host_targets) >= 2
                    and outgoing_network_volume >= 3
                    and graph.nodes[node].get("type") == "host"
                )
                else 0.0
            )

            # New communication signal.
            new_edge_signal = 1.0 if node in nodes_with_new_edges else 0.0
            if nodes_with_new_edge_sources:
                new_edge_signal = (
                    1.0 if node in nodes_with_new_edge_sources else 0.0
                )

            # Previously unseen entity signal. A node that never
            # appeared in the baseline at all (a brand new user,
            # host, process, etc.) is exactly the kind of thing a
            # zero-day compromise would introduce, so this is scored
            # explicitly rather than being silently ignored.
            node_type = graph.nodes[node].get("type")
            new_node_signal = (
                0.0
                if node_in_baseline or node_type == "external"
                else 1.0
            )

            # Weighted anomaly score.
            anomaly_score = (
                cls.DEGREE_WEIGHT * degree_change
                + cls.DEGREE_CENTRALITY_WEIGHT
                * degree_centrality_change
                + cls.BETWEENNESS_WEIGHT
                * betweenness_change
                + cls.NEW_EDGE_WEIGHT * new_edge_signal
                + cls.NEW_NODE_WEIGHT * new_node_signal
                + cls.EDGE_WEIGHT_WEIGHT * edge_weight_change
                + cls.BURST_WEIGHT * burst_signal
                + cls.EXTERNAL_COMMUNICATION_WEIGHT * external_signal
                + cls.LATERAL_MOVEMENT_WEIGHT * lateral_signal
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

            if edge_weight_change > 0:
                reasons.append("communication volume increased")

            if burst_signal:
                reasons.append(
                    "repeated process communication burst detected"
                )

            if external_signal:
                reasons.append(
                    "host communicated with an external endpoint"
                )

            if lateral_signal:
                reasons.append(
                    "host made repeated connections to internal hosts"
                )

            if node in nodes_with_new_edges:
                reasons.append("new communication edge detected")

            if new_node_signal:
                reasons.append(
                    "node was not present in the baseline "
                    "(previously unseen entity)"
                )

            # Determine final status.
            status = (
                "SUSPICIOUS"
                if anomaly_score >= (
                    cls.SUSPICIOUS_THRESHOLD
                    if threshold is None
                    else threshold
                )
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
        edge_weight_sum_values = {}
        baseline_snapshot_metrics = []

        for graph in baseline_graphs:

            metrics = self.calculate_metrics(graph)
            baseline_snapshot_metrics.append(metrics)

            all_nodes.update(graph.nodes())
            all_edges.update(graph.edges())

        for metrics in baseline_snapshot_metrics:
            for node in all_nodes:
                degree_values.setdefault(node, []).append(
                    metrics["degree"].get(node, 0)
                )
                degree_centrality_values.setdefault(node, []).append(
                    metrics["degree_centrality"].get(node, 0.0)
                )
                betweenness_values.setdefault(node, []).append(
                    metrics["betweenness"].get(node, 0.0)
                )
                edge_weight_sum_values.setdefault(node, []).append(
                    metrics["edge_weight_sum"].get(node, 0.0)
                )

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
            "edge_weight_sum": {
                node: sum(values) / len(values)
                for node, values in edge_weight_sum_values.items()
            },
        }

        # A node absent from a snapshot was not observed, so it should not
        # lower that node's normal activity baseline.
        observed_metrics = {
            "degree": {},
            "degree_centrality": {},
            "betweenness": {},
            "edge_weight_sum": {},
        }
        for node in all_nodes:
            for metric_name, values_by_snapshot in (
                ("degree", degree_values),
                ("degree_centrality", degree_centrality_values),
                ("betweenness", betweenness_values),
                ("edge_weight_sum", edge_weight_sum_values),
            ):
                values = [
                    value
                    for value in values_by_snapshot[node]
                    if value > 0
                ]
                observed_metrics[metric_name][node] = (
                    sum(values) / len(values) if values else 0.0
                )

        self._baseline = {
            "metrics": baseline_metrics,
            "scoring_metrics": observed_metrics,
            "edges": all_edges,
        }

    def get_baseline(self) -> Dict:
        """Return the fitted baseline used for anomaly detection."""

        if self._baseline is None:
            raise RuntimeError(
                "Detector must be fitted before requesting the baseline."
            )

        return self._baseline

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
            threshold=self._threshold(),
        )

        suspicious_nodes = self.get_suspicious_nodes(results)

        return {
            "anomalous_nodes": suspicious_nodes,
        }