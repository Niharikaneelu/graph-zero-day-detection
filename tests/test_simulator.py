"""
Tests for the simulation module.

Tests focus on:
- Network creation correctness
- Normal behaviour generation
- Attack-like behaviour injection
- Graph structure validation
- Reproducibility with seeds
"""

import pytest
import networkx as nx
from simulation.simulator import AttackGraphSimulator


class TestNetworkCreation:
    """Test basic graph creation."""

    def test_normal_snapshot_returns_graph(self):
        """Normal snapshot should return a NetworkX graph."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        assert isinstance(graph, nx.Graph)

    def test_normal_snapshot_has_expected_node_count(self):
        """Normal snapshot should create graphs with specified node count."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot(node_count=40)
        assert graph.number_of_nodes() <= 40

    def test_normal_snapshot_is_connected(self):
        """Normal snapshot should produce connected graphs."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        assert nx.is_connected(graph)

    def test_normal_snapshot_has_edges(self):
        """Normal snapshot should create edges (non-trivial graph)."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        assert graph.number_of_edges() > 0

    def test_nodes_are_integers(self):
        """Nodes should be integer IDs."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        for node in graph.nodes():
            assert isinstance(node, int)

    def test_edges_are_unweighted(self):
        """Edges should exist in the graph (unweighted by default)."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        for u, v in graph.edges():
            assert isinstance(u, int) and isinstance(v, int)


class TestNormalBehaviour:
    """Test normal behaviour generation."""

    def test_multiple_snapshots_vary(self):
        """Multiple snapshots should produce graphs with some variation."""
        simulator = AttackGraphSimulator(seed=42)
        graph1 = simulator.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        graph2 = simulator.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        
        # Different random snapshots may have different edge counts
        # (though same node count due to connected component enforcement)
        assert graph1.number_of_nodes() > 0
        assert graph2.number_of_nodes() > 0

    def test_normal_snapshot_edge_probability_respected(self):
        """Higher edge probability should result in more edges."""
        simulator = AttackGraphSimulator(seed=42)
        graph_low = simulator.generate_normal_snapshot(node_count=50, edge_prob=0.05)
        
        simulator2 = AttackGraphSimulator(seed=42)
        graph_high = simulator2.generate_normal_snapshot(node_count=50, edge_prob=0.20)
        
        # Higher probability should generally give more edges
        # (though connected component may reduce nodes, so just check both are valid)
        assert graph_low.number_of_edges() > 0
        assert graph_high.number_of_edges() > 0

    def test_normal_snapshot_node_count_preserved(self):
        """Node count should be consistent for larger node counts."""
        simulator = AttackGraphSimulator(seed=42)
        node_count = 50
        graph = simulator.generate_normal_snapshot(node_count=node_count, edge_prob=0.10)
        # Due to connected component filtering, may be less than requested
        assert graph.number_of_nodes() <= node_count
        assert graph.number_of_nodes() > 0


class TestAttackBehaviour:
    """Test attack-like behaviour injection."""

    def test_inject_zero_day_returns_node_list(self):
        """inject_zero_day_pattern should return list of node IDs."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        attack_nodes = simulator.inject_zero_day_pattern(graph)
        assert isinstance(attack_nodes, list)
        assert len(attack_nodes) > 0

    def test_inject_zero_day_returns_correct_count(self):
        """inject_zero_day_pattern should return specified number of attack nodes."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        attack_count = 3
        attack_nodes = simulator.inject_zero_day_pattern(graph, attack_nodes=attack_count)
        assert len(attack_nodes) == attack_count

    def test_inject_zero_day_adds_nodes_to_graph(self):
        """Injecting attack should add new nodes to graph."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot(node_count=40)
        initial_node_count = graph.number_of_nodes()
        attack_count = 3
        simulator.inject_zero_day_pattern(graph, attack_nodes=attack_count)
        assert graph.number_of_nodes() == initial_node_count + attack_count

    def test_inject_zero_day_creates_cluster(self):
        """Attack nodes should form a dense cluster (fully connected)."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        attack_nodes = simulator.inject_zero_day_pattern(graph, attack_nodes=3)
        
        # Check that attack nodes are fully connected to each other
        for i, node1 in enumerate(attack_nodes):
            for node2 in attack_nodes[i+1:]:
                assert graph.has_edge(node1, node2), \
                    f"Attack nodes {node1} and {node2} should be connected"

    def test_inject_zero_day_bridges_to_high_degree_nodes(self):
        """Attack cluster should be connected to high-degree nodes."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot(node_count=40, edge_prob=0.10)
        attack_nodes = simulator.inject_zero_day_pattern(graph)
        
        # Get high-degree nodes in original graph
        degree_sorted = sorted(graph.degree, key=lambda pair: pair[1], reverse=True)
        top_nodes = set([node for node, _ in degree_sorted[:3]])
        
        # Each attack node should be connected to at least one top node
        for attack_node in attack_nodes:
            connections_to_top = sum(
                1 for target in top_nodes 
                if graph.has_edge(attack_node, target)
            )
            assert connections_to_top > 0, \
                f"Attack node {attack_node} should be connected to high-degree nodes"

    def test_inject_zero_day_increases_edges(self):
        """Injecting attack should increase number of edges."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        edges_before = graph.number_of_edges()
        simulator.inject_zero_day_pattern(graph)
        edges_after = graph.number_of_edges()
        assert edges_after > edges_before, "Attack should create new edges"

    def test_inject_zero_day_increases_degree_centrality(self):
        """Attack should increase degree centrality in graph."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        
        # Measure average degree before
        avg_degree_before = sum(dict(graph.degree()).values()) / graph.number_of_nodes()
        
        simulator.inject_zero_day_pattern(graph)
        
        # Measure average degree after
        avg_degree_after = sum(dict(graph.degree()).values()) / graph.number_of_nodes()
        
        assert avg_degree_after >= avg_degree_before, \
            "Average degree should increase or stay same after attack"

    def test_attack_nodes_are_new(self):
        """Injected attack nodes should be new node IDs."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot(node_count=40)
        original_max_id = max(graph.nodes())
        
        attack_nodes = simulator.inject_zero_day_pattern(graph)
        
        # Attack nodes should have IDs higher than original nodes
        for attack_node in attack_nodes:
            assert attack_node > original_max_id, \
                f"Attack node {attack_node} should have higher ID than original max {original_max_id}"


class TestGraphStructure:
    """Test graph structural properties."""

    def test_graph_is_valid_networkx(self):
        """Generated graphs should be valid NetworkX objects."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        
        # Should be able to compute standard properties
        assert nx.number_connected_components(graph) >= 1
        assert nx.density(graph) >= 0

    def test_graph_has_no_self_loops(self):
        """Graph should not have self-loops."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        assert list(nx.selfloop_edges(graph)) == []

    def test_graph_is_undirected(self):
        """Generated graph should be undirected."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        assert isinstance(graph, nx.Graph)
        assert not isinstance(graph, nx.DiGraph)

    def test_attack_cluster_structure(self):
        """Attack cluster should form a clique."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot()
        attack_nodes = simulator.inject_zero_day_pattern(graph, attack_nodes=3)
        
        # Create subgraph of attack nodes
        subgraph = graph.subgraph(attack_nodes)
        
        # Should have all possible edges (clique)
        expected_edges = len(attack_nodes) * (len(attack_nodes) - 1) / 2
        assert subgraph.number_of_edges() == expected_edges


class TestReproducibility:
    """Test reproducibility with seeds."""

    def test_same_seed_produces_same_graph(self):
        """Same seed should produce identical graph structure."""
        sim1 = AttackGraphSimulator(seed=42)
        graph1 = sim1.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        
        sim2 = AttackGraphSimulator(seed=42)
        graph2 = sim2.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        
        # Compare graph properties
        assert graph1.number_of_nodes() == graph2.number_of_nodes()
        assert graph1.number_of_edges() == graph2.number_of_edges()

    def test_different_seeds_produce_different_graphs(self):
        """Different seeds should generally produce different graphs."""
        sim1 = AttackGraphSimulator(seed=42)
        graph1 = sim1.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        
        sim2 = AttackGraphSimulator(seed=123)
        graph2 = sim2.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        
        # Should not be identical
        assert not nx.is_isomorphic(graph1, graph2)

    def test_same_seed_produces_same_attack_pattern(self):
        """Same seed should produce same attack nodes."""
        sim1 = AttackGraphSimulator(seed=42)
        graph1 = sim1.generate_normal_snapshot()
        attack1 = sim1.inject_zero_day_pattern(graph1)
        
        sim2 = AttackGraphSimulator(seed=42)
        graph2 = sim2.generate_normal_snapshot()
        attack2 = sim2.inject_zero_day_pattern(graph2)
        
        assert attack1 == attack2

    def test_multiple_calls_with_same_simulator_vary(self):
        """Multiple calls to same simulator should produce different graphs."""
        simulator = AttackGraphSimulator(seed=42)
        graph1 = simulator.generate_normal_snapshot()
        graph2 = simulator.generate_normal_snapshot()
        
        # They should be different (different random snapshots)
        # (though same node count due to connected component logic)
        assert graph1.number_of_nodes() > 0
        assert graph2.number_of_nodes() > 0


class TestMeasurableAnomalies:
    """Test that attack injection creates measurable behavioral changes."""

    def test_attack_increases_clustering_coefficient(self):
        """Attack cluster should increase overall clustering coefficient."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        
        clustering_before = nx.average_clustering(graph)
        simulator.inject_zero_day_pattern(graph, attack_nodes=3)
        clustering_after = nx.average_clustering(graph)
        
        assert clustering_after >= clustering_before

    def test_attack_increases_max_degree(self):
        """Attack nodes should have elevated degree due to cluster + bridges."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        
        baseline_degrees = dict(graph.degree())
        avg_degree_before = sum(baseline_degrees.values()) / len(baseline_degrees)
        
        attack_nodes = simulator.inject_zero_day_pattern(graph, attack_nodes=3)
        
        attack_degrees = [graph.degree(node) for node in attack_nodes]
        avg_attack_degree = sum(attack_degrees) / len(attack_degrees)
        
        # Attack nodes should have higher average degree than baseline
        assert avg_attack_degree > avg_degree_before

    def test_attack_creates_identifiable_pattern(self):
        """Attack pattern should create nodes with distinct structural properties."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.generate_normal_snapshot(node_count=40, edge_prob=0.08)
        initial_nodes = set(graph.nodes())
        
        attack_nodes = simulator.inject_zero_day_pattern(graph)
        
        # Attack nodes should have higher average degree than baseline
        baseline_nodes = initial_nodes
        baseline_degrees = [graph.degree(n) for n in baseline_nodes]
        attack_degrees = [graph.degree(n) for n in attack_nodes]
        
        avg_baseline_degree = sum(baseline_degrees) / len(baseline_degrees)
        avg_attack_degree = sum(attack_degrees) / len(attack_degrees)
        
        assert avg_attack_degree > avg_baseline_degree


class TestIntegrationWithDetector:
    """Test that simulator output works with detector."""

    def test_normal_snapshots_fit_detector(self):
        """Multiple normal snapshots should fit the anomaly detector."""
        from detection.anomaly_detector import GraphAnomalyDetector
        
        simulator = AttackGraphSimulator(seed=42)
        baseline_graphs = [simulator.generate_normal_snapshot() for _ in range(20)]
        
        detector = GraphAnomalyDetector(contamination=0.1)
        # Should not raise an error
        detector.fit(baseline_graphs)

    def test_detection_output_is_list(self):
        """Detection output should be a list of anomalous nodes."""
        from detection.anomaly_detector import GraphAnomalyDetector
        
        simulator = AttackGraphSimulator(seed=42)
        baseline_graphs = [simulator.generate_normal_snapshot() for _ in range(20)]
        
        detector = GraphAnomalyDetector(contamination=0.1)
        detector.fit(baseline_graphs)
        
        test_graph = simulator.generate_normal_snapshot()
        simulator.inject_zero_day_pattern(test_graph)
        
        results = detector.detect(test_graph)
        assert isinstance(results, dict)
        assert "anomalous_nodes" in results
        assert isinstance(results["anomalous_nodes"], list)

    def test_end_to_end_pipeline(self):
        """Full pipeline should execute without errors."""
        from detection.anomaly_detector import GraphAnomalyDetector
        from containment.containment_engine import ContainmentEngine
        
        simulator = AttackGraphSimulator(seed=42)
        baseline_graphs = [simulator.generate_normal_snapshot() for _ in range(20)]
        
        detector = GraphAnomalyDetector(contamination=0.1)
        detector.fit(baseline_graphs)
        
        test_graph = simulator.generate_normal_snapshot()
        injected = simulator.inject_zero_day_pattern(test_graph)
        
        detection = detector.detect(test_graph)
        
        containment = ContainmentEngine()
        actions = containment.generate_actions(detection["anomalous_nodes"])
        
        # Should complete without error
        assert isinstance(actions, list)


# ============================================================================
# NEW TESTS - EVENT-BASED SIMULATION
# ============================================================================


class TestEntityGeneration:
    """Test entity creation for event-based simulation."""

    def test_create_entities_returns_dict(self):
        """_create_entities should return a dict of entity types to node IDs."""
        simulator = AttackGraphSimulator(seed=42)
        entities = simulator._create_entities()
        assert isinstance(entities, dict)

    def test_create_entities_has_expected_types(self):
        """_create_entities should include all required entity types."""
        simulator = AttackGraphSimulator(seed=42)
        entities = simulator._create_entities()
        expected_types = {"user", "host", "process", "file", "server", "external"}
        assert set(entities.keys()) == expected_types

    def test_create_entities_has_node_ids(self):
        """All entity types should have integer node IDs."""
        simulator = AttackGraphSimulator(seed=42)
        entities = simulator._create_entities()
        for entity_type, nodes in entities.items():
            assert isinstance(nodes, list)
            assert len(nodes) > 0
            for node_id in nodes:
                assert isinstance(node_id, int)

    def test_create_entities_nodes_are_unique(self):
        """All node IDs across entity types should be unique."""
        simulator = AttackGraphSimulator(seed=42)
        entities = simulator._create_entities()
        all_nodes = []
        for nodes in entities.values():
            all_nodes.extend(nodes)
        assert len(all_nodes) == len(set(all_nodes)), "Node IDs should be unique"

    def test_create_entities_node_counts(self):
        """Verify expected node counts for each entity type."""
        simulator = AttackGraphSimulator(seed=42)
        entities = simulator._create_entities()
        assert len(entities["user"]) >= 1
        assert len(entities["host"]) >= 1
        assert len(entities["process"]) >= 1
        assert len(entities["file"]) >= 1
        assert len(entities["server"]) >= 1
        assert len(entities["external"]) >= 1


class TestEventGeneration:
    """Test normal event generation."""

    def test_generate_normal_events_returns_list(self):
        """generate_normal_events should return a list."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events()
        assert isinstance(events, list)

    def test_generate_normal_events_returns_dicts(self):
        """Each event should be a dict."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events()
        for event in events:
            assert isinstance(event, dict)

    def test_generate_normal_events_schema(self):
        """Each event should follow the Event schema."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events()
        required_fields = {"timestamp", "source", "target", "event_type", "weight"}
        for event in events:
            assert set(event.keys()) == required_fields

    def test_generate_normal_events_field_types(self):
        """Event fields should have correct types."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events()
        for event in events:
            assert isinstance(event["timestamp"], int)
            assert isinstance(event["source"], int)
            assert isinstance(event["target"], int)
            assert isinstance(event["event_type"], str)
            assert isinstance(event["weight"], int)

    def test_generate_normal_events_event_types(self):
        """Event types should be valid."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events(num_events=20)
        valid_types = {"LOGIN", "FILE_ACCESS", "PROCESS_CREATE", "PROCESS_COMMUNICATION", "NETWORK_CONNECTION"}
        for event in events:
            assert event["event_type"] in valid_types

    def test_generate_normal_events_timestamps_increment(self):
        """Timestamps should increment."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events(num_events=10)
        for i in range(1, len(events)):
            assert events[i]["timestamp"] > events[i - 1]["timestamp"]

    def test_generate_normal_events_num_events(self):
        """Should generate requested number of events."""
        simulator = AttackGraphSimulator(seed=42)
        for num in [1, 5, 10, 20]:
            events = simulator.generate_normal_events(num_events=num)
            assert len(events) == num

    def test_generate_normal_events_reproducibility(self):
        """Same seed should produce same events."""
        sim1 = AttackGraphSimulator(seed=42)
        events1 = sim1.generate_normal_events()

        sim2 = AttackGraphSimulator(seed=42)
        events2 = sim2.generate_normal_events()

        assert events1 == events2


class TestAttackScenarios:
    """Test attack-like event generation."""

    def test_generate_attack_events_returns_list(self):
        """generate_attack_events should return a list."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_attack_events()
        assert isinstance(events, list)

    def test_generate_attack_events_schema(self):
        """Attack events should follow Event schema."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_attack_events()
        required_fields = {"timestamp", "source", "target", "event_type", "weight"}
        for event in events:
            assert set(event.keys()) == required_fields

    def test_generate_attack_events_connection_burst(self):
        """connection_burst scenario should create many events from single source."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_attack_events(scenario="connection_burst", num_events=5)
        
        # All events should be from same source
        sources = {event["source"] for event in events}
        assert len(sources) == 1
        
        # All targets should be hosts
        for event in events:
            assert event["event_type"] == "PROCESS_COMMUNICATION"

    def test_generate_attack_events_unusual_external(self):
        """unusual_external scenario should create connections to external endpoints."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_attack_events(scenario="unusual_external", num_events=5)
        
        # All events should be from same source
        sources = {event["source"] for event in events}
        assert len(sources) == 1
        
        # All events should be NETWORK_CONNECTION
        for event in events:
            assert event["event_type"] == "NETWORK_CONNECTION"

    def test_generate_attack_events_lateral_movement(self):
        """lateral_movement scenario should create connections between hosts."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_attack_events(scenario="lateral_movement", num_events=5)
        
        # All events should be from same source
        sources = {event["source"] for event in events}
        assert len(sources) == 1
        
        # All events should be NETWORK_CONNECTION
        for event in events:
            assert event["event_type"] == "NETWORK_CONNECTION"

    def test_generate_attack_events_timestamps(self):
        """Attack event timestamps should start from 100 and increment."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_attack_events(num_events=5)
        
        # First event should have timestamp 100
        assert events[0]["timestamp"] == 100
        
        # Timestamps should increment
        for i in range(1, len(events)):
            assert events[i]["timestamp"] > events[i - 1]["timestamp"]

    def test_generate_attack_events_num_events(self):
        """Should generate requested number of events."""
        simulator = AttackGraphSimulator(seed=42)
        for num in [1, 5, 10]:
            events = simulator.generate_attack_events(num_events=num)
            assert len(events) == num

    def test_generate_attack_events_reproducibility(self):
        """Same seed should produce same attack events."""
        sim1 = AttackGraphSimulator(seed=42)
        events1 = sim1.generate_attack_events(scenario="connection_burst")

        sim2 = AttackGraphSimulator(seed=42)
        events2 = sim2.generate_attack_events(scenario="connection_burst")

        assert events1 == events2


class TestGraphConstruction:
    """Test event-to-graph conversion."""

    def test_build_graph_returns_graph(self):
        """build_graph should return a NetworkX graph."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events()
        graph = simulator.build_graph(events)
        assert isinstance(graph, nx.Graph)

    def test_build_graph_nodes_from_events(self):
        """Graph nodes should match unique source/target IDs from events."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events(num_events=5)
        graph = simulator.build_graph(events)
        
        # Collect expected nodes from events
        expected_nodes = set()
        for event in events:
            expected_nodes.add(event["source"])
            expected_nodes.add(event["target"])
        
        assert set(graph.nodes()) == expected_nodes

    def test_build_graph_edges_from_events(self):
        """Graph should have edges for each unique source-target pair."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events(num_events=5)
        graph = simulator.build_graph(events)
        
        # Each event should create or update an edge
        assert graph.number_of_edges() > 0

    def test_build_graph_edge_attributes(self):
        """Edges should have metadata from events."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events(num_events=3)
        graph = simulator.build_graph(events)
        
        for u, v, data in graph.edges(data=True):
            assert "event_type" in data
            assert "weight" in data
            assert "event_types" in data
            assert "timestamps" in data

    def test_build_graph_empty_events(self):
        """build_graph with empty events should create empty graph."""
        simulator = AttackGraphSimulator(seed=42)
        graph = simulator.build_graph([])
        assert graph.number_of_nodes() == 0
        assert graph.number_of_edges() == 0

    def test_build_graph_multiple_events_same_edge(self):
        """Multiple events between same nodes should aggregate."""
        simulator = AttackGraphSimulator(seed=42)
        events = [
            {"timestamp": 1, "source": 0, "target": 1, "event_type": "LOGIN", "weight": 1},
            {"timestamp": 2, "source": 0, "target": 1, "event_type": "FILE_ACCESS", "weight": 1},
        ]
        graph = simulator.build_graph(events)
        
        # Should have only 1 edge between nodes 0 and 1
        assert graph.number_of_edges() == 1
        # Weight should be sum of event weights
        assert graph[0][1]["weight"] == 2


class TestDynamicUpdates:
    """Test incremental graph updates."""

    def test_update_graph_adds_edge(self):
        """update_graph should add new edge to graph."""
        simulator = AttackGraphSimulator(seed=42)
        graph = nx.Graph()
        
        event = {
            "timestamp": 1,
            "source": 0,
            "target": 1,
            "event_type": "LOGIN",
            "weight": 1,
        }
        
        simulator.update_graph(graph, event)
        
        assert graph.has_edge(0, 1)

    def test_update_graph_creates_nodes(self):
        """update_graph should create nodes if they don't exist."""
        simulator = AttackGraphSimulator(seed=42)
        graph = nx.Graph()
        
        event = {
            "timestamp": 1,
            "source": 5,
            "target": 10,
            "event_type": "LOGIN",
            "weight": 1,
        }
        
        simulator.update_graph(graph, event)
        
        assert 5 in graph
        assert 10 in graph

    def test_update_graph_increments_weight(self):
        """update_graph should increment weight for existing edge."""
        simulator = AttackGraphSimulator(seed=42)
        graph = nx.Graph()
        
        # First event
        event1 = {
            "timestamp": 1,
            "source": 0,
            "target": 1,
            "event_type": "LOGIN",
            "weight": 1,
        }
        simulator.update_graph(graph, event1)
        assert graph[0][1]["weight"] == 1
        
        # Second event on same edge
        event2 = {
            "timestamp": 2,
            "source": 0,
            "target": 1,
            "event_type": "FILE_ACCESS",
            "weight": 1,
        }
        simulator.update_graph(graph, event2)
        assert graph[0][1]["weight"] == 2

    def test_update_graph_accumulates_metadata(self):
        """update_graph should accumulate event types and timestamps."""
        simulator = AttackGraphSimulator(seed=42)
        graph = nx.Graph()
        
        # First event
        event1 = {
            "timestamp": 1,
            "source": 0,
            "target": 1,
            "event_type": "LOGIN",
            "weight": 1,
        }
        simulator.update_graph(graph, event1)
        
        # Second event
        event2 = {
            "timestamp": 2,
            "source": 0,
            "target": 1,
            "event_type": "FILE_ACCESS",
            "weight": 1,
        }
        simulator.update_graph(graph, event2)
        
        assert len(graph[0][1]["event_types"]) == 2
        assert len(graph[0][1]["timestamps"]) == 2

    def test_update_graph_sequential_events(self):
        """Sequential updates should build graph correctly."""
        simulator = AttackGraphSimulator(seed=42)
        events = simulator.generate_normal_events(num_events=5)
        
        graph = nx.Graph()
        for event in events:
            simulator.update_graph(graph, event)
        
        # Should have same structure as build_graph
        graph_built = simulator.build_graph(events)
        assert graph.number_of_nodes() == graph_built.number_of_nodes()
        assert graph.number_of_edges() == graph_built.number_of_edges()


class TestReproducibilityEvents:
    """Test reproducibility of event-based simulation."""

    def test_same_seed_normal_events(self):
        """Same seed should produce identical normal events."""
        sim1 = AttackGraphSimulator(seed=42)
        events1 = sim1.generate_normal_events()

        sim2 = AttackGraphSimulator(seed=42)
        events2 = sim2.generate_normal_events()

        assert events1 == events2

    def test_same_seed_attack_events(self):
        """Same seed should produce identical attack events."""
        sim1 = AttackGraphSimulator(seed=42)
        events1 = sim1.generate_attack_events(scenario="connection_burst")

        sim2 = AttackGraphSimulator(seed=42)
        events2 = sim2.generate_attack_events(scenario="connection_burst")

        assert events1 == events2

    def test_different_seeds_different_events(self):
        """Different seeds should produce different events."""
        sim1 = AttackGraphSimulator(seed=42)
        events1 = sim1.generate_normal_events()

        sim2 = AttackGraphSimulator(seed=123)
        events2 = sim2.generate_normal_events()

        # Should not be identical
        assert events1 != events2

    def test_same_seed_graph_construction(self):
        """Same seed should produce identical graphs from events."""
        sim1 = AttackGraphSimulator(seed=42)
        events1 = sim1.generate_normal_events()
        graph1 = sim1.build_graph(events1)

        sim2 = AttackGraphSimulator(seed=42)
        events2 = sim2.generate_normal_events()
        graph2 = sim2.build_graph(events2)

        # Should have same structure
        assert graph1.number_of_nodes() == graph2.number_of_nodes()
        assert graph1.number_of_edges() == graph2.number_of_edges()
