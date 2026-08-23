from containment.containment_engine import ContainmentEngine
from detection.anomaly_detector import GraphAnomalyDetector
from simulation.simulator import AttackGraphSimulator


def run_pipeline() -> None:
    simulator = AttackGraphSimulator(seed=42)

    baseline_graphs = [simulator.generate_normal_snapshot() for _ in range(20)]

    detector = GraphAnomalyDetector(contamination=0.1)
    detector.fit(baseline_graphs)

    test_graph = simulator.generate_normal_snapshot()
    simulated_attack_nodes = simulator.inject_zero_day_pattern(test_graph)

    results = detector.detect(test_graph)

    containment_engine = ContainmentEngine()
    actions = containment_engine.generate_actions(results["anomalous_nodes"])

    print("=== Graph Zero-Day Detection Demo ===")
    print(f"Injected attack nodes: {simulated_attack_nodes}")
    print(f"Detected anomalous nodes: {results['anomalous_nodes']}")
    print("Containment actions:")
    for action in actions:
        print(f"- {action}")


if __name__ == "__main__":
    run_pipeline()
