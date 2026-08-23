from __future__ import annotations

from typing import List


class ContainmentEngine:
    """Converts anomaly detections into recommended actions."""

    def generate_actions(self, anomalous_nodes: List[int]) -> List[str]:
        if not anomalous_nodes:
            return ["No containment needed. Monitor continuously."]

        actions = []
        for node_id in anomalous_nodes:
            actions.append(f"Isolate node {node_id} from the network segment")
            actions.append(f"Block outbound traffic from node {node_id}")
            actions.append(f"Trigger deep malware scan for node {node_id}")
        return actions
