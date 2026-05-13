"""Build provenance graph payloads for the React forensic dashboard."""

from __future__ import annotations

import json
import math
from typing import Any

try:
    import networkx as nx
except ImportError:  # pragma: no cover - requirements include networkx.
    nx = None


class ProvenanceGraphBuilder:
    """Convert forensic replay events into a compact graph response."""

    SEVERITY_RISK = {
        "CRITICAL": 1.0,
        "HIGH": 0.85,
        "WARNING": 0.7,
        "MEDIUM": 0.65,
        "ANOMALY": 0.6,
        "LOW": 0.4,
        "INFO": 0.15,
        "NONE": 0.0,
    }

    def __init__(self) -> None:
        self.graph = nx.DiGraph() if nx else None
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []

    def build_from_forensic_timeline(
        self,
        timeline: list[dict[str, Any]],
        severity_threshold: float = 0.5,
    ) -> dict[str, Any]:
        """Build a graph from `HashChainLogger.forensic_replay()["timeline"]`."""
        self._reset()
        filtered_events = [
            event for event in timeline if self._risk_from_event(event) >= severity_threshold
        ]

        previous_event_id: str | None = None
        for index, event in enumerate(filtered_events, start=1):
            risk = self._risk_from_event(event)
            sequence = event.get("sequence") or index
            event_id = f"event-{sequence}"
            source_id = f"source-{event.get('source_component') or 'unknown'}"
            target_id = f"target-{event.get('target_component') or 'unknown'}"

            self._add_node(source_id, "source", event.get("source_component") or "unknown")
            self._add_node(target_id, "target", event.get("target_component") or "unknown")
            self._add_node(
                event_id,
                "anomaly",
                f"#{index} {event.get('severity') or 'ANOMALY'}",
                risk=risk,
                metadata={
                    "severity": event.get("severity") or "ANOMALY",
                    "summary": event.get("summary") or "",
                    "sequence": sequence,
                    "occurred_at": event.get("occurred_at"),
                    "recorded_at": event.get("recorded_at"),
                    "explanation": event.get("explanation") or "",
                    "anomaly_score": self._float(event.get("anomaly_score")),
                    "source_component": event.get("source_component"),
                    "target_component": event.get("target_component"),
                    "service": event.get("service") or "observed",
                },
            )

            self._add_edge(source_id, event_id, event.get("service") or "observed")
            self._add_edge(event_id, target_id, "affected")
            if previous_event_id:
                self._add_edge(previous_event_id, event_id, "then", temporal=True)
            previous_event_id = event_id

        positions = self._compute_layout()
        attack_paths = self._compute_attack_paths()
        statistics = self._compute_statistics()

        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "positions": positions,
            "attack_paths": attack_paths,
            "statistics": statistics,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
        }

    def _reset(self) -> None:
        if self.graph is not None:
            self.graph.clear()
        self.nodes = {}
        self.edges = []

    def _add_node(
        self,
        node_id: str,
        kind: str,
        label: object,
        risk: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if node_id in self.nodes:
            return
        self.nodes[node_id] = {
            "id": node_id,
            "kind": kind,
            "label": str(label),
            "risk": risk,
            **(metadata or {}),
        }
        if self.graph is not None:
            self.graph.add_node(node_id)

    def _add_edge(
        self,
        source: str,
        target: str,
        label: object,
        temporal: bool = False,
    ) -> None:
        if source not in self.nodes or target not in self.nodes:
            return
        edge = {
            "id": f"{source}-{target}",
            "source": source,
            "target": target,
            "label": str(label),
            "temporal": temporal,
        }
        self.edges.append(edge)
        if self.graph is not None:
            self.graph.add_edge(source, target)

    def _risk_from_event(self, event: dict[str, Any]) -> float:
        """Normalize model/severity output to a 0..1 UI risk score."""
        score = self._float(event.get("anomaly_score"))
        severity = str(event.get("severity") or "ANOMALY").upper()
        severity_risk = self.SEVERITY_RISK.get(severity, 0.6)

        if score < 0:
            score_risk = min(1.0, 0.55 + abs(score) * 2.0)
        elif score <= 0.05:
            score_risk = max(0.25, 0.55 - score * 4.0)
        elif score <= 1:
            score_risk = score
        else:
            score_risk = 0.25

        return round(max(severity_risk, score_risk), 4)

    @staticmethod
    def _float(value: object, default: float = 0.0) -> float:
        try:
            return float(value or default)
        except (TypeError, ValueError):
            return default

    def _compute_layout(self) -> dict[str, tuple[float, float]]:
        if not self.nodes:
            return {}
        if self.graph is not None and len(self.graph) > 1:
            try:
                positions = nx.spring_layout(self.graph, k=2.0, iterations=60, seed=42)
                return {
                    node_id: (float(x) * 400 + 400, float(y) * 300 + 300)
                    for node_id, (x, y) in positions.items()
                }
            except Exception:
                pass
        return self._fallback_layout()

    def _fallback_layout(self) -> dict[str, tuple[float, float]]:
        grouped = {
            kind: [node_id for node_id, node in self.nodes.items() if node["kind"] == kind]
            for kind in ("source", "anomaly", "target")
        }
        columns = {"source": 140.0, "anomaly": 400.0, "target": 660.0}
        positions: dict[str, tuple[float, float]] = {}

        for kind, node_ids in grouped.items():
            for index, node_id in enumerate(node_ids, start=1):
                y = 80.0 + (index * 420.0 / (len(node_ids) + 1))
                positions[node_id] = (columns[kind], y)

        remaining = [node_id for node_id in self.nodes if node_id not in positions]
        for index, node_id in enumerate(remaining):
            angle = 2 * math.pi * index / max(len(remaining), 1)
            positions[node_id] = (400 + 200 * math.cos(angle), 300 + 200 * math.sin(angle))
        return positions

    def _compute_attack_paths(self) -> list[dict[str, Any]]:
        anomaly_ids = [
            node_id for node_id, node in self.nodes.items() if node.get("kind") == "anomaly"
        ]
        if len(anomaly_ids) < 2:
            return []

        if self.graph is None:
            return [self._path_payload(anomaly_ids)]

        paths: list[dict[str, Any]] = []
        for index, source in enumerate(anomaly_ids):
            for target in anomaly_ids[index + 1 :]:
                try:
                    if nx.has_path(self.graph, source, target):
                        paths.append(self._path_payload(nx.shortest_path(self.graph, source, target)))
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        paths.sort(key=lambda item: (-item["risk"], -int(item["temporal"]), item["length"]))
        return paths[:10]

    def _path_payload(self, path: list[str]) -> dict[str, Any]:
        temporal_edges = {
            (edge["source"], edge["target"])
            for edge in self.edges
            if edge.get("temporal")
        }
        return {
            "source": path[0],
            "target": path[-1],
            "path": path,
            "length": max(len(path) - 1, 0),
            "temporal": any((path[i], path[i + 1]) in temporal_edges for i in range(len(path) - 1)),
            "risk": max(self.nodes.get(node_id, {}).get("risk", 0.0) for node_id in path),
        }

    def _compute_statistics(self) -> dict[str, Any]:
        anomaly_risks = [
            float(node.get("risk") or 0)
            for node in self.nodes.values()
            if node.get("kind") == "anomaly"
        ]
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "anomalies": len(anomaly_risks),
            "critical_anomalies": sum(risk > 0.8 for risk in anomaly_risks),
            "high_risk_anomalies": sum(0.6 < risk <= 0.8 for risk in anomaly_risks),
            "max_risk": max(anomaly_risks) if anomaly_risks else 0,
            "avg_risk": sum(anomaly_risks) / len(anomaly_risks) if anomaly_risks else 0,
            "density": nx.density(self.graph) if self.graph is not None and len(self.graph) > 1 else 0,
        }

    def find_anomaly_clusters(self) -> list[set[str]]:
        if self.graph is None:
            return []
        return sorted(nx.weakly_connected_components(self.graph), key=len, reverse=True)

    def compute_node_influence(self) -> dict[str, float]:
        if self.graph is None or len(self.graph) == 0:
            return {}
        try:
            return dict(nx.betweenness_centrality(self.graph))
        except Exception:
            return dict(nx.degree_centrality(self.graph))

    def to_json(self) -> str:
        return json.dumps({"nodes": self.nodes, "edges": self.edges}, default=str)
