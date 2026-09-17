# Graph-Theoretic Zero-Day Detection and Containment Framework

A graph-based framework for detecting behavioural anomalies that may indicate a possible zero-day compromise and recommending graph-based containment.

> **Important:** The system does not claim to identify the unknown zero-day exploit itself. It detects unusual behavioural patterns that may indicate compromise and uses graph algorithms to recommend containment.

---

## 1. Project Overview

Zero-day attacks exploit previously unknown software vulnerabilities, making traditional signature-based detection ineffective when no known attack signature is available.

This project models system behaviour as a dynamic graph.

System entities such as:

- Users
- Computers/Hosts
- Processes
- Files
- Internal Servers
- External Network Endpoints

are represented as graph nodes.

Interactions such as:

- Login
- File access
- Process creation
- Process communication
- Network communication

are represented as graph edges.

The system compares current behavioural patterns against a baseline of normal activity and identifies structural anomalies.

When a suspicious node or region is detected, graph-based containment is performed using Max-Flow/Min-Cut analysis.

---

# 2. Core Pipeline

```text
Simulated / Log Events
        |
        v
Event Ingestion
        |
        v
Dynamic Behaviour Graph
        |
        v
Baseline Behaviour
        |
        v
Graph Metrics
        |
        v
Anomaly Scoring
        |
        v
Suspicious Node / Subgraph
        |
        v
Containment Engine
        |
        +----> Ford-Fulkerson / Max-Flow
        |
        +----> Minimum Edge Cut
        |
        +----> Articulation Points
        |
        +----> Bridge Detection
        |
        v
Isolation Recommendation
        |
        v
Interactive Dashboard

---

# 3. Module Responsibilities and Interfaces

Each module should be developed independently, but all modules must follow the same contract.

## simulation/

Purpose:

- Generate normal behavior events
- Inject suspicious behavior patterns for testing

Input:

- Configuration values (node count, edge density, attack ratio, random seed)

Output:

- A list of events using the Event schema in Section 5

## detection/

Purpose:

- Build graph features from event streams
- Score nodes/subgraphs for anomalous behavior

Input:

- Baseline events and current events in Event schema format

Output:

- Detection records using the format in Section 7

## containment/

Purpose:

- Convert suspicious detections into containment recommendations

Input:

- List of suspicious nodes from detection output
- Current graph snapshot

Output:

- Containment payload using the format in Section 8

Compatibility note:

- `cut_edges` is the canonical field for recommended containment edges.
- `recommended_edges` is also returned with the same value for compatibility
        with existing consumers.

## dashboard/

Purpose:

- Visualize graph state, anomalies, and containment recommendations

Input:

- Events, detection output, containment output

Output:

- Interactive Streamlit views (table + graph + status summary)

---

# 4. Acceptance Criteria

Work from different contributors is accepted when all items below are true:

1. Uses the exact Event schema from Section 5.
2. Uses only approved event types from Section 6 (or approved extension).
3. Detection output matches Section 7 keys and value types.
4. Containment output matches Section 8 keys and value types.
5. No unnecessary dependency added to requirements.
6. Module runs with no local path hacks.
7. Pull request includes tests or validation evidence.

---

# 5. Data Interface

All modules must follow the agreed data format.

## Event

An event should initially follow this structure:

```json
{
        "timestamp": 1,
        "source": "Process_1",
        "target": "Server_2",
        "event_type": "NETWORK_CONNECTION",
        "weight": 1
}
```

Example:

```json
{
        "timestamp": 12,
        "source": "User_1",
        "target": "Host_1",
        "event_type": "LOGIN",
        "weight": 1
}
```

---

# 6. Event Types

The initial event types are:

```text
LOGIN
FILE_ACCESS
PROCESS_CREATE
PROCESS_COMMUNICATION
NETWORK_CONNECTION
```

Additional event types can be added later after discussion with the team.

---

# 7. Detection Output

The anomaly detection module should produce results similar to:

```json
{
        "node": "Process_17",
        "anomaly_score": 0.87,
        "status": "SUSPICIOUS",
        "reasons": [
                "degree increased significantly",
                "new communication path detected",
                "betweenness centrality increased"
        ]
}
```

---

# 8. Containment Output

The containment module should produce results similar to:

```python
{
        "suspicious_nodes": [
                "Process_17"
        ],
        "cut_edges": [
                ("Process_17", "Server_3")
        ],
        "articulation_points": [
                "Host_5"
        ],
        "bridges": [
                ("Host_5", "Server_2")
        ]
}
```

`cut_edges` is the canonical containment field consumed by the dashboard.
During the compatibility period, `recommended_edges` is returned as an alias
with an identical value. Consumers should migrate to `cut_edges`.

Legacy nodes injected by `simulation.inject_zero_day_pattern` include the node
attribute `type="unknown"`. Event-built nodes retain their entity type metadata.

---

# 9. Technology Stack

## Programming Language

Python

## Graph Processing

NetworkX

## Dashboard

Streamlit

## Visualization

NetworkX / Matplotlib / Plotly

The team may add additional dependencies when required, but unnecessary dependencies should be avoided.

---

# 10. Non-Goals

To prevent scope creep, this phase does not include:

- Exploit signature generation
- Malware family attribution
- Full SOC orchestration
- Production-grade distributed data pipeline
- Real-time blocking in enterprise infrastructure

The goal is a clear and testable research prototype with graph-based anomaly detection and containment recommendation.

---

# 11. Quick Start and Minimal End-to-End Example

## Setup

1. Create virtual environment:

```text
python -m venv .venv
```

2. Activate environment (PowerShell):

```text
.\.venv\Scripts\Activate.ps1
```

3. Install dependencies:

```text
pip install -r requirements.txt
```

## Run CLI Demo

```text
python main.py
```

Expected behavior:

- Simulates graph activity
- Injects suspicious pattern
- Detects anomalous nodes
- Prints containment actions

## Run Dashboard

```text
streamlit run dashboard/app.py
```

Open the shown local URL in your browser.

## Minimal End-to-End Event Flow

1. simulation outputs Event records.
2. detection reads Event records and produces anomaly records.
3. containment reads suspicious nodes and graph structure and produces containment output.
4. dashboard reads all outputs and visualizes status.

If every module follows Sections 5 to 8 exactly, contributors can work independently with minimal merge and integration conflict.

---

# 12. Methodology and Validation Results

The detector builds a baseline from 20 event-based graph snapshots. Each
snapshot uses the same fixed typed-entity population, so node IDs retain their
meaning across snapshots. Normal events are sampled independently, while the
test graph receives either an injected zero-day cluster or one of the event
attack scenarios.

For each node, the detector combines increases in degree, degree centrality,
and betweenness centrality with new-edge, previously-unseen-node, and
communication-volume signals. Communication volume is the sum of edge weights
incident to a node, so repeated contact on an existing edge can be anomalous
even when the number of unique neighbours is unchanged.
Scores are clipped to the range 0 to 1, and scores at or above 0.64 are marked
`SUSPICIOUS`. Containment uses a minimum edge cut to separate suspicious nodes
from trusted nodes, then reports bridges and articulation points as additional
structural context.

## Graph-Theoretic Basis

- **Degree-sum principle:** For every undirected graph,
        `sum(degree(v)) = 2 * number_of_edges`. Degree changes therefore reflect
        changes in the number of unique incident connections; weighted
        communication volume requires the edge-weight metric described above.
- **Centrality measures:** Degree centrality normalizes local connectivity by
        graph size. Betweenness centrality measures how often a node lies on shortest
        paths, helping identify newly important lateral-movement bridges.
- **Max-Flow/Min-Cut theorem:** With capacity 1 on every real edge, the minimum
        cut is the smallest set of connections whose removal separates suspicious
        nodes from trusted nodes. The containment engine computes this cut and never
        removes nodes.
- **Menger's theorem:** The minimum number of edges separating two regions
        equals the maximum number of edge-disjoint paths between them. More
        independent routes therefore require a larger containment cut.
- **Articulation points and bridges:** An articulation point increases the
        number of connected components when removed. A bridge is an edge whose
        removal disconnects the graph. Both are reported as high-impact context.

A 100-seed validation run produced these aggregate node-level results:

| Measurement | Result |
| --- | ---: |
| True positives | 300 |
| False positives | 134 |
| False negatives | 0 |
| True negatives | 947 |
| Precision | 69.12% |
| Recall | 100.00% |
| Normal-node false-positive rate | 12.40% |
| `connection_burst` trials with at least one detection | 27/100 |
| `unusual_external` trials with at least one detection | 100/100 |
| `lateral_movement` trials with at least one detection | 71/100 |

These results are simulation measurements, not production accuracy claims.

# 13. Limitations

- Entity IDs are stable only because the simulator uses a fixed synthetic
        population. Real deployments require reliable entity identity resolution.
- The baseline contains only 20 short snapshots and may not represent seasonal
        or workload changes.
- The anomaly threshold and metric weights are hand-tuned for this prototype.
- Event graphs collapse repeated communication into one edge with attributes;
        temporal sequence modelling is outside the current scope.
- Detection quality varies by attack scenario, as shown by the validation
        results, and false positives require analyst review.
- The system detects suspicious behaviour and recommends containment; it does
        not identify the unknown vulnerability or automatically block production
        traffic.

---