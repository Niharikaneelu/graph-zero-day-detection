"""
Tests for the graph-based containment engine.
"""


import networkx as nx

from containment.containment_engine import ContainmentEngine


class TestBasicContainment:
    """Basic containment behaviour."""

    def test_no_suspicious_nodes(self):
        graph = nx.path_graph(5)
        engine = ContainmentEngine(graph)

        result = engine.generate_containment_plan(
            graph,
            [],
        )

        assert result["suspicious_nodes"] == []
        assert result["cut_edges"] == []
        assert result["recommended_edges"] == []
        assert result["cut_edges"] == result["recommended_edges"]
        assert result["number_of_edges_removed"] == 0

    def test_suspicious_node_with_multiple_connections(self):
        graph = nx.Graph()

        graph.add_edges_from([
            (0, 1),
            (1, 2),
            (1, 3),
            (3, 4),
        ])

        engine = ContainmentEngine(graph)

        result = engine.generate_containment_plan(
            graph,
            [1],
        )

        assert result["suspicious_nodes"] == [1]
        assert result["number_of_edges_removed"] > 0
        assert result["isolated"] is True

    def test_integer_node_ids(self):
        graph = nx.Graph()

        graph.add_edges_from([
            (10, 20),
            (20, 30),
            (30, 40),
        ])

        engine = ContainmentEngine(graph)

        result = engine.generate_containment_plan(
            graph,
            [10],
        )

        assert result["suspicious_nodes"] == [10]

        for edge in result["recommended_edges"]:
            assert isinstance(edge[0], int)
            assert isinstance(edge[1], int)


class TestMinimumCut:
    """Tests for minimum edge cut calculation."""

    def test_minimum_cut_calculation(self):
        # Suspicious node 0 has two independent connections
        # to the trusted region.
        graph = nx.Graph()

        graph.add_edges_from([
            (0, 1),
            (0, 2),
            (1, 3),
            (2, 3),
        ])

        engine = ContainmentEngine(graph)

        cut = engine.find_minimum_cut(
            graph,
            [0],
        )

        # Both connections from node 0 must be removed.
        assert len(cut) == 2

        assert set(cut) == {
            (0, 1),
            (0, 2),
        }

    def test_multiple_suspicious_nodes(self):
        graph = nx.Graph()

        graph.add_edges_from([
            (0, 1),
            (1, 2),
            (2, 3),
            (2, 4),
            (3, 5),
            (4, 5),
        ])

        engine = ContainmentEngine(graph)

        suspicious = [0, 1]

        result = engine.generate_containment_plan(
            graph,
            suspicious,
        )

        assert set(result["suspicious_nodes"]) == {0, 1}
        assert result["number_of_edges_removed"] >= 1
        assert result["isolated"] is True


class TestGraphStructure:
    """Tests for articulation points and bridges."""

    def test_articulation_points(self):
        # 0 -- 1 -- 2
        #      |
        #      3
        graph = nx.Graph()

        graph.add_edges_from([
            (0, 1),
            (1, 2),
            (1, 3),
        ])

        engine = ContainmentEngine(graph)

        points = engine.find_articulation_points(graph)

        assert 1 in points

    def test_bridge_detection(self):
        # Triangle 0-1-2 plus bridge 2-3.
        graph = nx.Graph()

        graph.add_edges_from([
            (0, 1),
            (1, 2),
            (2, 0),
            (2, 3),
        ])

        engine = ContainmentEngine(graph)

        bridges = engine.find_bridges(graph)

        assert (2, 3) in bridges or (3, 2) in bridges


class TestContainmentOutput:
    """Tests for explainable containment results."""

    def test_containment_action_format(self):
        graph = nx.Graph()

        graph.add_edges_from([
            (0, 1),
            (0, 2),
            (1, 3),
            (2, 3),
        ])

        engine = ContainmentEngine(graph)

        result = engine.generate_containment_plan(
            graph,
            [0],
        )

        assert "suspicious_nodes" in result
        assert "recommended_edges" in result
        assert "containment_actions" in result
        assert "articulation_points" in result
        assert "bridges" in result
        assert "number_of_edges_removed" in result
        assert "isolated" in result
        assert "explanation" in result

        assert isinstance(
            result["containment_actions"],
            list,
        )

        for action in result["containment_actions"]:
            assert isinstance(action, str)

    def test_disconnected_graph(self):
        graph = nx.Graph()

        graph.add_edges_from([
            (0, 1),
            (2, 3),
        ])

        engine = ContainmentEngine(graph)

        result = engine.generate_containment_plan(
            graph,
            [0],
        )

        # Node 0 is disconnected from the separate component (2, 3),
        # but it is still connected to trusted node 1.
        # Therefore edge (0, 1) must be removed.
        assert result["isolated"] is True
        assert result["cut_edges"] == [(0, 1)]
        assert result["recommended_edges"] == [(0, 1)]
        assert result["cut_edges"] == result["recommended_edges"]
        assert result["number_of_edges_removed"] == 1

    def test_small_graph(self):
        graph = nx.Graph()

        graph.add_edge(0, 1)

        engine = ContainmentEngine(graph)

        result = engine.generate_containment_plan(
            graph,
            [0],
        )

        assert result["suspicious_nodes"] == [0]
        assert result["cut_edges"] == [(0, 1)]
        assert result["recommended_edges"] == [(0, 1)]
        assert result["cut_edges"] == result["recommended_edges"]
        assert result["number_of_edges_removed"] == 1
        assert result["isolated"] is True

    def test_single_node_graph(self):
        graph = nx.Graph()
        graph.add_node(0)

        engine = ContainmentEngine(graph)

        result = engine.generate_containment_plan(
            graph,
            [0],
        )

        # There is no trusted region.
        assert result["cut_edges"] == []
        assert result["recommended_edges"] == []
        assert result["cut_edges"] == result["recommended_edges"]
        assert result["number_of_edges_removed"] == 0
        assert result["isolated"] is True


class TestExistingInterface:
    """Ensure the old public API still works."""

    def test_generate_actions_empty(self):
        engine = ContainmentEngine()

        actions = engine.generate_actions([])

        assert actions == [
            "No containment needed. Monitor continuously."
        ]

    def test_generate_actions_with_nodes(self):
        engine = ContainmentEngine()

        actions = engine.generate_actions([5])

        assert isinstance(actions, list)
        assert len(actions) == 3

        assert "5" in actions[0]
        assert "5" in actions[1]
        assert "5" in actions[2]

class TestFullPipelineIntegration:
    """Test the complete simulator -> detector -> containment pipeline."""

    def test_complete_pipeline(self):
        from detection.anomaly_detector import GraphAnomalyDetector
        from simulation.simulator import AttackGraphSimulator

        simulator = AttackGraphSimulator(seed=42)

        # 1. Generate normal baseline graphs
        baseline_graphs = [
            simulator.generate_normal_snapshot()
            for _ in range(20)
        ]

        # 2. Train anomaly detector
        detector = GraphAnomalyDetector(contamination=0.1)
        detector.fit(baseline_graphs)

        # 3. Generate graph containing an attack
        attack_graph = simulator.generate_normal_snapshot()

        injected_nodes = simulator.inject_zero_day_pattern(
            attack_graph
        )

        # 4. Detect suspicious nodes
        detection = detector.detect(attack_graph)

        suspicious_nodes = detection["anomalous_nodes"]

        assert isinstance(suspicious_nodes, list)

        # Detector should return integer node IDs
        for node in suspicious_nodes:
            assert isinstance(node, int)

        # 5. Pass detector output to containment engine
        engine = ContainmentEngine()

        result = engine.generate_containment_plan(
            attack_graph,
            suspicious_nodes,
        )

        # 6. Verify containment output
        assert isinstance(result, dict)

        assert "suspicious_nodes" in result
        assert "recommended_edges" in result
        assert "containment_actions" in result
        assert "articulation_points" in result
        assert "bridges" in result
        assert "number_of_edges_removed" in result
        assert "isolated" in result
        assert "explanation" in result

        # The containment engine should preserve the
        # detector's suspicious-node information.
        assert result["suspicious_nodes"] == suspicious_nodes

        # Recommended edges must be actual edges in the graph.
        for edge in result["recommended_edges"]:
            assert len(edge) == 2
            assert attack_graph.has_edge(edge[0], edge[1])

        # The simulator's injected nodes are integer IDs.
        assert all(isinstance(node, int) for node in injected_nodes)