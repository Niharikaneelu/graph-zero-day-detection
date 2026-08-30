from __future__ import annotations

import random
from typing import Dict, List

import networkx as nx


class AttackGraphSimulator:
    """Builds baseline graph snapshots and injects simple attack-like patterns.
    
    Also supports event-based simulation with typed entities and dynamic graph construction.
    """

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)

    # ============================================================================
    # EXISTING API - PRESERVED FOR COMPATIBILITY
    # ============================================================================

    def generate_normal_snapshot(self, node_count: int = 40, edge_prob: float = 0.08) -> nx.Graph:
        """Generate a connected random graph snapshot (Erdos-Renyi model).
        
        Args:
            node_count: Number of nodes in graph
            edge_prob: Probability of edge creation
            
        Returns:
            Connected NetworkX graph with integer node IDs.
        """
        graph = nx.erdos_renyi_graph(node_count, edge_prob, seed=self._rng.randint(0, 10_000))
        if not nx.is_connected(graph):
            largest_cc = max(nx.connected_components(graph), key=len)
            graph = graph.subgraph(largest_cc).copy()
        return graph

    def inject_zero_day_pattern(self, graph: nx.Graph, attack_nodes: int = 3) -> List[int]:
        """Injects a dense malicious cluster and connects it to critical nodes.
        
        Args:
            graph: NetworkX graph to modify in-place
            attack_nodes: Number of attack nodes to inject
            
        Returns:
            List of injected node IDs.
        """
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

    # ============================================================================
    # NEW API - EVENT-BASED SIMULATION
    # ============================================================================

    def _create_entities(self) -> Dict[str, List[int]]:
        """Create a small synthetic network with typed entities.
        
        Returns:
            Dict mapping entity type to list of integer node IDs.
        """
        entity_spec = {
            "user": [0, 1],
            "host": [2, 3, 4],
            "process": [5, 6],
            "file": [7, 8, 9],
            "server": [10, 11],
            "external": [12, 13],
        }
        return entity_spec

    def generate_normal_events(self, num_events: int = 8) -> List[Dict]:
        """Generate realistic normal behavior events following the Event schema.
        
        Events represent typical system activities:
        - User login to host
        - Process creation on host
        - File access by process
        - Host connection to server
        
        Args:
            num_events: Number of events to generate
            
        Returns:
            List of events, each following the Event schema:
            {
                "timestamp": int,
                "source": int,
                "target": int,
                "event_type": str,
                "weight": int
            }
        """
        entities = self._create_entities()
        events = []

        timestamp = 1

        # Define typical event patterns: (source_type, target_type, event_type)
        patterns = [
            ("user", "host", "LOGIN"),
            ("host", "process", "PROCESS_CREATE"),
            ("process", "file", "FILE_ACCESS"),
            ("host", "server", "NETWORK_CONNECTION"),
        ]

        pattern_idx = 0
        for _ in range(num_events):
            src_type, tgt_type, event_type = patterns[pattern_idx % len(patterns)]

            src_node = self._rng.choice(entities[src_type])
            tgt_node = self._rng.choice(entities[tgt_type])

            events.append({
                "timestamp": timestamp,
                "source": src_node,
                "target": tgt_node,
                "event_type": event_type,
                "weight": 1,
            })

            timestamp += 1
            pattern_idx += 1

        return events

    def generate_attack_events(
        self, scenario: str = "connection_burst", num_events: int = 5
    ) -> List[Dict]:
        """Generate attack-like events for testing anomaly detection.
        
        Scenarios:
        - "connection_burst": Single entity makes many rapid connections
        - "unusual_external": Entity communicates with external endpoints (uncommon)
        - "lateral_movement": Entity connects to multiple other internal entities
        
        Args:
            scenario: Type of attack behavior to simulate
            num_events: Number of events to generate
            
        Returns:
            List of attack-like events following the Event schema.
        """
        entities = self._create_entities()
        events = []
        timestamp = 100

        if scenario == "connection_burst":
            # Single process makes many connections to different hosts
            src = self._rng.choice(entities["process"])
            for _ in range(num_events):
                tgt = self._rng.choice(entities["host"])
                events.append({
                    "timestamp": timestamp,
                    "source": src,
                    "target": tgt,
                    "event_type": "PROCESS_COMMUNICATION",
                    "weight": 1,
                })
                timestamp += 1

        elif scenario == "unusual_external":
            # Host communicates with external endpoints (unusual pattern)
            src = self._rng.choice(entities["host"])
            for _ in range(num_events):
                tgt = self._rng.choice(entities["external"])
                events.append({
                    "timestamp": timestamp,
                    "source": src,
                    "target": tgt,
                    "event_type": "NETWORK_CONNECTION",
                    "weight": 1,
                })
                timestamp += 1

        elif scenario == "lateral_movement":
            # Host connects to many other hosts (lateral movement pattern)
            src = self._rng.choice(entities["host"])
            for _ in range(num_events):
                tgt = self._rng.choice([n for n in entities["host"] if n != src])
                events.append({
                    "timestamp": timestamp,
                    "source": src,
                    "target": tgt,
                    "event_type": "NETWORK_CONNECTION",
                    "weight": 1,
                })
                timestamp += 1

        return events

    def build_graph(self, events: List[Dict]) -> nx.Graph:
        """Convert event stream to NetworkX graph.
        
        Args:
            events: List of events following the Event schema
            
        Returns:
            NetworkX graph with integer node IDs (source/target from events).
            Edge attributes include event_type, weight, event_types (set), timestamps (list).
        """
        graph = nx.Graph()

        # Collect all unique source and target nodes
        all_nodes = set()
        for event in events:
            all_nodes.add(event["source"])
            all_nodes.add(event["target"])

        # Add nodes
        graph.add_nodes_from(all_nodes)

        # Add edges with event metadata
        for event in events:
            src = event["source"]
            tgt = event["target"]
            event_type = event["event_type"]

            if graph.has_edge(src, tgt):
                # Edge already exists - update attributes
                graph[src][tgt]["weight"] += event["weight"]
                graph[src][tgt]["event_types"].add(event_type)
                graph[src][tgt]["timestamps"].append(event["timestamp"])
            else:
                # New edge
                graph.add_edge(
                    src,
                    tgt,
                    event_type=event_type,
                    weight=event["weight"],
                    event_types={event_type},
                    timestamps=[event["timestamp"]],
                )

        return graph

    def update_graph(self, graph: nx.Graph, event: Dict) -> None:
        """Add a single event to an existing graph (incremental update).
        
        Args:
            graph: NetworkX graph to update in-place
            event: Single event following the Event schema
        """
        src = event["source"]
        tgt = event["target"]
        event_type = event["event_type"]

        # Ensure nodes exist
        if src not in graph:
            graph.add_node(src)
        if tgt not in graph:
            graph.add_node(tgt)

        # Add or update edge
        if graph.has_edge(src, tgt):
            graph[src][tgt]["weight"] += event["weight"]
            graph[src][tgt]["event_types"].add(event_type)
            graph[src][tgt]["timestamps"].append(event["timestamp"])
        else:
            graph.add_edge(
                src,
                tgt,
                event_type=event_type,
                weight=event["weight"],
                event_types={event_type},
                timestamps=[event["timestamp"]],
            )
