import networkx as nx

from detection.anomaly_detector import GraphAnomalyDetector
from simulation.simulator import AttackGraphSimulator


def test_multi_seed_zero_day_validation_has_high_recall_and_low_false_positives():
    """Validate injected-node precision, recall, and false positives."""

    trials = 100
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0

    for seed in range(trials):
        simulator = AttackGraphSimulator(seed=seed)
        baseline_graphs = [
            simulator.build_graph(
                simulator.generate_normal_events(num_events=15)
            )
            for _ in range(20)
        ]

        detector = GraphAnomalyDetector()
        detector.fit(baseline_graphs)

        attack_graph = simulator.build_graph(
            simulator.generate_normal_events(num_events=15)
        )
        injected_nodes = set(
            simulator.inject_zero_day_pattern(attack_graph)
        )
        attack_results = detector.detect(attack_graph)
        predicted = set(attack_results["anomalous_nodes"])
        normal_nodes_in_attack = set(attack_graph) - injected_nodes

        true_positives += len(predicted & injected_nodes)
        false_positives += len(predicted & normal_nodes_in_attack)
        false_negatives += len(injected_nodes - predicted)
        true_negatives += len(normal_nodes_in_attack - predicted)

    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / (true_positives + false_negatives)
    false_positive_rate = false_positives / (
        false_positives + true_negatives
    )

    assert precision > 0.60
    assert recall == 1.0
    assert false_positive_rate < 0.15


def test_dashboard_cut_edges_are_rendered_as_a_separate_trace():
    """Recommended containment edges should be visually distinguishable."""

    from dashboard.app import create_network_figure

    graph = nx.path_graph([1, 2, 3])
    figure = create_network_figure(
        graph,
        anomalous_nodes=[1],
        cut_edges=[(1, 2)],
    )

    cut_trace = next(
        trace
        for trace in figure.data
        if trace.name == "Recommended cut"
    )

    assert cut_trace.line.dash == "dash"
    assert cut_trace.line.color == "#d85f52"


def test_event_graph_nodes_include_entity_type_metadata():
    """Event-built graphs should expose stable entity types to the dashboard."""

    simulator = AttackGraphSimulator(seed=7)
    events = simulator.generate_normal_events(num_events=15)
    graph = simulator.build_graph(events)
    lookup = simulator.entity_type_lookup()

    assert graph.number_of_nodes() > 0
    assert all(
        graph.nodes[node]["type"] == lookup[node]
        for node in graph.nodes()
    )


def test_incremental_graph_nodes_match_batch_entity_types():
    """Incremental updates should preserve the batch graph node metadata."""

    simulator = AttackGraphSimulator(seed=7)
    event = simulator.generate_normal_events(num_events=1)[0]
    incremental_graph = nx.Graph()
    simulator.update_graph(incremental_graph, event)
    batch_graph = simulator.build_graph([event])

    for node in event["source"], event["target"]:
        assert incremental_graph.nodes[node]["type"] == batch_graph.nodes[node]["type"]


def test_injected_nodes_are_reserved_above_known_entity_population():
    """Injected IDs must not collide with unsampled simulator entities."""

    simulator = AttackGraphSimulator(seed=7)
    graph = simulator.build_graph(
        simulator.generate_normal_events(num_events=1)
    )

    injected_nodes = simulator.inject_zero_day_pattern(graph)

    assert min(injected_nodes) > max(simulator.entity_type_lookup())
