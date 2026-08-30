import networkx as nx

from detection.anomaly_detector import GraphAnomalyDetector


def create_normal_graph():
    graph = nx.Graph()

    graph.add_edges_from([
        ("Process_1", "Server_1"),
        ("Process_1", "Server_2"),
        ("Process_2", "Server_1"),
    ])

    return graph


def create_suspicious_graph():
    graph = nx.Graph()

    graph.add_edges_from([
        ("Process_1", "Server_1"),
        ("Process_1", "Server_2"),
        ("Process_2", "Server_1"),
        ("Process_1", "External_Server_1"),
        ("Process_1", "External_Server_2"),
        ("Process_1", "External_Server_3"),
        ("Process_1", "External_Server_4"),
    ])

    return graph


def test_normal_graph_has_no_suspicious_nodes():
    graph = create_normal_graph()

    baseline = GraphAnomalyDetector.build_baseline(graph)

    results = GraphAnomalyDetector.detect_anomalies(
        graph,
        baseline,
    )

    suspicious_nodes = GraphAnomalyDetector.get_suspicious_nodes(
        results
    )

    assert suspicious_nodes == []


def test_new_edges_are_detected():
    normal_graph = create_normal_graph()

    baseline = GraphAnomalyDetector.build_baseline(
        normal_graph
    )

    current_graph = create_suspicious_graph()

    new_edges = GraphAnomalyDetector.find_new_edges(
        current_graph,
        baseline,
    )

    assert len(new_edges) == 4


def test_suspicious_node_gets_higher_score():
    normal_graph = create_normal_graph()

    baseline = GraphAnomalyDetector.build_baseline(
        normal_graph
    )

    current_graph = create_suspicious_graph()

    results = GraphAnomalyDetector.detect_anomalies(
        current_graph,
        baseline,
    )

    process_result = next(
        result
        for result in results
        if result["node"] == "Process_1"
    )

    assert process_result["anomaly_score"] >= 0.60
    assert process_result["status"] == "SUSPICIOUS"


def test_suspicious_node_is_identified():
    normal_graph = create_normal_graph()

    baseline = GraphAnomalyDetector.build_baseline(
        normal_graph
    )

    current_graph = create_suspicious_graph()

    results = GraphAnomalyDetector.detect_anomalies(
        current_graph,
        baseline,
    )

    suspicious_nodes = GraphAnomalyDetector.get_suspicious_nodes(
        results
    )

    assert "Process_1" in suspicious_nodes


def test_anomaly_scores_are_between_zero_and_one():
    normal_graph = create_normal_graph()

    baseline = GraphAnomalyDetector.build_baseline(
        normal_graph
    )

    current_graph = create_suspicious_graph()

    results = GraphAnomalyDetector.detect_anomalies(
        current_graph,
        baseline,
    )

    for result in results:
        assert 0.0 <= result["anomaly_score"] <= 1.0