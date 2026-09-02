"""
Demonstration of event-based simulation with the enhanced AttackGraphSimulator.

This shows how other modules (detection, containment, dashboard) can use
the new event-based API while maintaining compatibility with the existing
graph-based API.
"""

from simulation.simulator import AttackGraphSimulator


def demo_event_based_simulation() -> None:
    """Demonstrate event-based simulation workflow."""
    
    print("=" * 70)
    print("EVENT-BASED SIMULATION DEMONSTRATION")
    print("=" * 70)
    
    # Initialize simulator with fixed seed for reproducibility
    simulator = AttackGraphSimulator(seed=42)
    
    # ========================================================================
    # STEP 1: Generate normal behavior events
    # ========================================================================
    print("\n[STEP 1] Generating normal behavior events...")
    normal_events = simulator.generate_normal_events(num_events=8)
    
    print(f"\nGenerated {len(normal_events)} normal events:")
    for i, event in enumerate(normal_events[:3], 1):
        print(f"  {i}. Timestamp={event['timestamp']:>3d} | "
              f"Source={event['source']:>2d} -> Target={event['target']:>2d} | "
              f"Type={event['event_type']:>20s}")
    print(f"  ... ({len(normal_events) - 3} more events)")
    
    # ========================================================================
    # STEP 2: Generate attack-like events (synthetic scenarios)
    # ========================================================================
    print("\n[STEP 2] Generating attack-like events (connection_burst scenario)...")
    attack_events = simulator.generate_attack_events(
        scenario="connection_burst", 
        num_events=5
    )
    
    print(f"\nGenerated {len(attack_events)} attack events:")
    for i, event in enumerate(attack_events[:3], 1):
        print(f"  {i}. Timestamp={event['timestamp']:>3d} | "
              f"Source={event['source']:>2d} -> Target={event['target']:>2d} | "
              f"Type={event['event_type']:>20s}")
    print(f"  ... ({len(attack_events) - 3} more events)")
    
    # ========================================================================
    # STEP 3: Convert events to NetworkX graph
    # ========================================================================
    print("\n[STEP 3] Converting events to NetworkX graph...")
    
    # Build graph from normal events
    normal_graph = simulator.build_graph(normal_events)
    print(f"Normal graph: {normal_graph.number_of_nodes()} nodes, "
          f"{normal_graph.number_of_edges()} edges")
    
    # Build graph from attack events
    attack_graph = simulator.build_graph(attack_events)
    print(f"Attack graph: {attack_graph.number_of_nodes()} nodes, "
          f"{attack_graph.number_of_edges()} edges")
    
    # ========================================================================
    # STEP 4: Demonstrate dynamic graph update
    # ========================================================================
    print("\n[STEP 4] Demonstrating incremental graph updates...")
    
    graph = simulator.build_graph(normal_events[:3])
    print(f"Initial graph: {graph.number_of_nodes()} nodes, "
          f"{graph.number_of_edges()} edges")
    
    # Add remaining events one by one
    for event in normal_events[3:]:
        simulator.update_graph(graph, event)
    
    print(f"After adding events: {graph.number_of_nodes()} nodes, "
          f"{graph.number_of_edges()} edges")
    
    # ========================================================================
    # STEP 5: Show graph compatibility with existing detector
    # ========================================================================
    print("\n[STEP 5] Testing graph compatibility with anomaly detector...")
    
    from detection.anomaly_detector import GraphAnomalyDetector
    
    # Generate baseline graphs
    baseline_graphs = [simulator.generate_normal_snapshot() for _ in range(20)]
    print(f"Baseline: {len(baseline_graphs)} graphs for training")
    
    # Train detector
    detector = GraphAnomalyDetector(contamination=0.1)
    detector.fit(baseline_graphs)
    print("Detector trained successfully")
    
    # Test detector on event-based graph
    test_graph = simulator.build_graph(normal_events + attack_events)
    results = detector.detect(test_graph)
    print(f"Detector results: {len(results['anomalous_nodes'])} anomalous nodes detected")
    print(f"  Anomalous nodes: {results['anomalous_nodes']}")
    
    # ========================================================================
    # STEP 6: Event schema validation
    # ========================================================================
    print("\n[STEP 6] Validating Event schema...")
    
    sample_event = normal_events[0]
    required_fields = {"timestamp", "source", "target", "event_type", "weight"}
    valid_types = {"LOGIN", "FILE_ACCESS", "PROCESS_CREATE", "PROCESS_COMMUNICATION", "NETWORK_CONNECTION"}
    
    print(f"Sample event: {sample_event}")
    print(f"  ✓ Has all required fields: {set(sample_event.keys()) == required_fields}")
    print(f"  ✓ Event type is valid: {sample_event['event_type'] in valid_types}")
    print(f"  ✓ Fields have correct types:")
    print(f"    - timestamp (int): {isinstance(sample_event['timestamp'], int)}")
    print(f"    - source (int): {isinstance(sample_event['source'], int)}")
    print(f"    - target (int): {isinstance(sample_event['target'], int)}")
    print(f"    - event_type (str): {isinstance(sample_event['event_type'], str)}")
    print(f"    - weight (int): {isinstance(sample_event['weight'], int)}")
    
    # ========================================================================
    # STEP 7: Demonstrate scenario variations
    # ========================================================================
    print("\n[STEP 7] Attack scenario comparison...")
    
    scenarios = ["connection_burst", "unusual_external", "lateral_movement"]
    for scenario in scenarios:
        events = simulator.generate_attack_events(scenario=scenario, num_events=3)
        print(f"\n  {scenario}:")
        for event in events:
            print(f"    {event['source']:>2d} -> {event['target']:>2d} ({event['event_type']})")
    
    print("\n" + "=" * 70)
    print("DEMONSTRATION COMPLETE")
    print("=" * 70)
    print("\nKey Takeaways:")
    print("  • Event-based API provides granular control over simulation")
    print("  • Events follow agreed schema (timestamp, source, target, type, weight)")
    print("  • Events convert to NetworkX graphs compatible with existing detector")
    print("  • Integer node IDs enable seamless integration with detection/containment")
    print("  • Dynamic updates allow incremental graph construction")
    print("  • Reproducible behavior with seed parameter")


if __name__ == "__main__":
    demo_event_based_simulation()
