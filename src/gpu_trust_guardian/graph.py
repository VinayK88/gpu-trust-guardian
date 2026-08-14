"""Evidence graph and attack-path extraction for GPU workload telemetry."""

from __future__ import annotations

from collections import Counter

import networkx as nx
import pandas as pd


def build_evidence_graph(frame: pd.DataFrame) -> nx.DiGraph:
    graph = nx.DiGraph()
    for row in frame.itertuples(index=False):
        user = f"user:{row.user}"
        workload = f"workload:{row.workload}"
        container = f"container:{row.container_id}"
        gpu = f"gpu:{row.gpu_uuid}"
        graph.add_edge(user, workload, relation="submitted")
        graph.add_edge(workload, container, relation="runs")
        graph.add_edge(container, gpu, relation="uses")
        previous = gpu
        if bool(row.model_access) and row.model_name != "none":
            model = f"model:{row.model_name}"
            graph.add_edge(gpu, model, relation="loaded")
            previous = model
        if row.destination != "model-registry.internal":
            destination = (
                f"external:{row.destination}"
                if str(row.destination).endswith(".invalid")
                else f"resource:{row.destination}"
            )
            graph.add_edge(previous, destination, relation="connected")
    return graph


def extract_attack_paths(frame: pd.DataFrame, suspicious_event_ids: set[str]) -> list[list[str]]:
    candidates = frame[frame["event_id"].isin(suspicious_event_ids)]
    paths: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for row in candidates.itertuples(index=False):
        path = [
            f"user:{row.user}",
            f"workload:{row.workload}",
            f"container:{row.container_id}",
            f"gpu:{row.gpu_uuid}",
        ]
        if bool(row.model_access) and row.model_name != "none":
            path.append(f"model:{row.model_name}")
        if row.destination != "model-registry.internal":
            prefix = "external" if str(row.destination).endswith(".invalid") else "resource"
            path.append(f"{prefix}:{row.destination}")
        signature = tuple(path)
        if signature not in seen:
            seen.add(signature)
            paths.append(path)
    return paths


def graph_summary(graph: nx.DiGraph) -> dict[str, int]:
    kinds = Counter(node.split(":", 1)[0] for node in graph.nodes)
    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "identities": kinds["user"],
        "workloads": kinds["workload"],
        "containers": kinds["container"],
        "gpus": kinds["gpu"],
        "models": kinds["model"],
        "external_destinations": kinds["external"],
    }
