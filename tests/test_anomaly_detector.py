import networkx as nx

from detection.anomaly_detector import GraphAnomalyDetector


def test_normal_graph_has_no_suspicious_nodes():
    """A graph identical to its baseline should have no suspicious nodes."""

    graph = nx.Graph()

    graph.add_edges_from(
        [
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 1),
        ]
    )

    baseline = GraphAnomalyDetector.build_baseline(graph)

    results = GraphAnomalyDetector.detect_anomalies(
        graph,
        baseline,
    )

    suspicious_nodes = GraphAnomalyDetector.get_suspicious_nodes(results)

    assert suspicious_nodes == []


def test_new_edges_are_detected():
    """A newly introduced edge should contribute to anomaly detection."""

    baseline_graph = nx.Graph()

    baseline_graph.add_edges_from(
        [
            (1, 2),
            (2, 3),
        ]
    )

    baseline = GraphAnomalyDetector.build_baseline(baseline_graph)

    current_graph = baseline_graph.copy()
    current_graph.add_edge(3, 4)

    new_edges = GraphAnomalyDetector.find_new_edges(
        current_graph,
        baseline,
    )

    assert (3, 4) in new_edges or (4, 3) in new_edges


def test_suspicious_node_gets_higher_score():
    """A node with significant structural changes should get a higher score."""

    baseline_graph = nx.Graph()

    baseline_graph.add_edges_from(
        [
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 1),
        ]
    )

    baseline = GraphAnomalyDetector.build_baseline(baseline_graph)

    current_graph = baseline_graph.copy()

    # Add several connections involving node 1.
    current_graph.add_edges_from(
        [
            (1, 5),
            (1, 6),
            (1, 7),
        ]
    )

    results = GraphAnomalyDetector.detect_anomalies(
        current_graph,
        baseline,
    )

    scores = {
        result["node"]: result["anomaly_score"]
        for result in results
    }

    assert scores[1] > scores[2]


def test_suspicious_node_is_identified():
    """A structurally abnormal node should be classified as suspicious."""

    baseline_graph = nx.Graph()

    baseline_graph.add_edges_from(
        [
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 1),
        ]
    )

    baseline = GraphAnomalyDetector.build_baseline(baseline_graph)

    current_graph = baseline_graph.copy()

    # Create a strong structural anomaly around node 1.
    current_graph.add_edges_from(
        [
            (1, 5),
            (1, 6),
            (1, 7),
            (1, 8),
            (1, 9),
        ]
    )

    results = GraphAnomalyDetector.detect_anomalies(
        current_graph,
        baseline,
    )

    suspicious_nodes = GraphAnomalyDetector.get_suspicious_nodes(
        results
    )

    assert 1 in suspicious_nodes


def test_anomaly_scores_are_between_zero_and_one():
    """Every anomaly score should remain within the range 0 to 1."""

    baseline_graph = nx.Graph()

    baseline_graph.add_edges_from(
        [
            (1, 2),
            (2, 3),
            (3, 4),
        ]
    )

    baseline = GraphAnomalyDetector.build_baseline(baseline_graph)

    current_graph = baseline_graph.copy()

    current_graph.add_edges_from(
        [
            (1, 5),
            (1, 6),
            (1, 7),
        ]
    )

    results = GraphAnomalyDetector.detect_anomalies(
        current_graph,
        baseline,
    )

    for result in results:
        assert 0.0 <= result["anomaly_score"] <= 1.0


def test_event_based_simulator_detects_connection_burst():
    """Detector should identify an anomaly from the real event simulator."""

    from simulation.simulator import AttackGraphSimulator

    simulator = AttackGraphSimulator(seed=42)

    # Generate normal behaviour using the actual simulator.
    normal_events = simulator.generate_normal_events(
        num_events=8
    )

    normal_graph = simulator.build_graph(
        normal_events
    )

    # Build the normal-behaviour baseline.
    baseline = GraphAnomalyDetector.build_baseline(
        normal_graph
    )

    # Generate attack behaviour using the actual simulator.
    attack_events = simulator.generate_attack_events(
        scenario="connection_burst",
        num_events=5,
    )

    # Combine normal and attack events into the current graph.
    attack_graph = simulator.build_graph(
        normal_events + attack_events
    )

    # Detect anomalies.
    results = GraphAnomalyDetector.detect_anomalies(
        attack_graph,
        baseline,
    )

    suspicious_nodes = GraphAnomalyDetector.get_suspicious_nodes(
        results
    )

    # The detector should identify at least one suspicious node.
    assert len(suspicious_nodes) >= 1

    # Simulator node IDs must remain integers.
    assert all(
        isinstance(node, int)
        for node in attack_graph.nodes()
    )


def test_node_absent_from_baseline_is_flagged_suspicious():
    """
    Regression test.

    A node that never appeared in the baseline at all (a brand new
    entity) must be treated as suspicious once it shows real
    activity, not silently ignored. Previously, `_relative_change`
    zeroed out every structural signal for such nodes, capping their
    score below the suspicious threshold no matter how connected they
    were -- which meant genuinely new attacker-controlled nodes could
    never be detected.
    """

    baseline_graph = nx.Graph()

    baseline_graph.add_edges_from(
        [
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 1),
        ]
    )

    baseline = GraphAnomalyDetector.build_baseline(baseline_graph)

    current_graph = baseline_graph.copy()

    # Node 99 never existed in the baseline at all.
    current_graph.add_edges_from(
        [
            (99, 1),
            (99, 2),
            (99, 3),
        ]
    )

    results = GraphAnomalyDetector.detect_anomalies(
        current_graph,
        baseline,
    )

    suspicious_nodes = GraphAnomalyDetector.get_suspicious_nodes(
        results
    )

    assert 99 in suspicious_nodes


def test_full_pipeline_detects_injected_zero_day_nodes():
    """
    Regression test for the end-to-end detection pipeline.

    Baseline graphs are built from the event-based simulator, which
    always draws from the same fixed population of typed entities,
    so node identity is stable across baseline snapshots. A zero-day
    pattern is then injected into a fresh test graph, adding nodes
    that never appeared anywhere in the baseline. The detector must
    flag every one of those injected nodes as anomalous.
    """

    from simulation.simulator import AttackGraphSimulator

    for seed in (1, 7, 14, 21, 28):
        simulator = AttackGraphSimulator(seed=seed)

        baseline_graphs = [
            simulator.build_graph(
                simulator.generate_normal_events(num_events=15)
            )
            for _ in range(20)
        ]

        detector = GraphAnomalyDetector(contamination=0.1)
        detector.fit(baseline_graphs)

        normal_events = simulator.generate_normal_events(num_events=15)
        test_graph = simulator.build_graph(normal_events)

        injected_nodes = simulator.inject_zero_day_pattern(test_graph)

        results = detector.detect(test_graph)
        detected_nodes = set(results["anomalous_nodes"])

        assert set(injected_nodes).issubset(detected_nodes), (
            f"seed={seed}: injected nodes {injected_nodes} were not "
            f"all detected; detector found {sorted(detected_nodes)}"
        )