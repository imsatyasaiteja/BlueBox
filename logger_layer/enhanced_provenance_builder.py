"""
NetworkX-backed provenance graph builder for BlueBox.

The backend owns graph semantics: evidence normalization, correlations,
centrality, connected components, investigation paths, and deterministic layout.
The React UI renders this payload interactively.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Any

try:
    import networkx as nx
except ImportError:  # pragma: no cover - requirements include networkx.
    nx = None

try:
    from PIL import Image, ImageDraw
except ImportError:  # pragma: no cover - export endpoint reports the error.
    Image = None


class EnhancedProvenanceGraphBuilder:
    """Build a concise NetworkX provenance graph for cyber investigation."""

    SEVERITY_LEVELS = {
        "CRITICAL": 1.0,
        "HIGH": 0.85,
        "MEDIUM": 0.65,
        "WARNING": 0.7,
        "ANOMALY": 0.6,
        "LOW": 0.4,
        "INFO": 0.15,
        "NORMAL": 0.0,
        "NONE": 0.0,
    }

    CANONICAL_SEVERITY = {
        "CRITICAL": "HIGH",
        "HIGH": "HIGH",
        "WARNING": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "ANOMALY": "MEDIUM",
        "LOW": "LOW",
        "INFO": "LOW",
        "NORMAL": "NORMAL",
        "NONE": "NORMAL",
    }

    DOMAIN_COLORS = {
        "avionics": "#7dd3fc",
        "afdx": "#38bdf8",
        "cabin": "#f0abfc",
        "maintenance": "#fbbf24",
        "integrity": "#fb7185",
        "unknown": "#94a3b8",
    }

    DOMAIN_IP_PREFIXES = (
        ("192.168.1.", "cabin"),
        ("192.168.2.", "maintenance"),
        ("10.0.", "afdx"),
    )
    DEFAULT_ATTACKER_IP = "203.0.113.45"

    KIND_LAYER = {
        "domain": 0,
        "source": 1,
        "event": 2,
        "target": 3,
        "pattern": 4,
    }

    KIND_LABELS = {
        "domain": "Domain",
        "source": "Source",
        "event": "Evidence Event",
        "target": "Affected Target",
        "pattern": "Attack Pattern",
    }

    def __init__(self) -> None:
        self.graph = nx.DiGraph() if nx else None
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.positions: dict[str, tuple[float, float]] = {}
        self.selected_events: list[dict[str, Any]] = []

    def build_from_forensic_timeline(
        self,
        timeline: list[dict[str, Any]],
        severity_threshold: float = 0.5,
        severity_levels: list[str] | None = None,
        domains: list[str] | None = None,
        event_types: list[str] | None = None,
        time_window_ms: int | None = None,
        max_events: int | None = 10,
    ) -> dict[str, Any]:
        """Build a NetworkX graph from AI-ranked anomalies and security events."""
        self._reset()
        normalized = [self._normalize_event(event, index) for index, event in enumerate(timeline, start=1)]
        filtered = self._apply_filters(
            normalized,
            severity_threshold=severity_threshold,
            severity_levels=severity_levels or [],
            domains=domains or [],
            event_types=event_types or [],
            time_window_ms=time_window_ms,
        )
        selected = self._select_top_events(filtered, max_events=max_events)
        self.selected_events = selected

        for rank, event in enumerate(selected, start=1):
            event["rank"] = rank
            self._add_event_subgraph(event)

        self._add_event_correlations(selected)
        self._apply_networkx_metrics()
        self.positions = self._compute_networkx_layout()
        attack_paths = self._compute_attack_paths()
        components = self._components_payload()
        statistics = self._compute_statistics(filtered, attack_paths, components)

        return {
            "nodes": list(self.nodes.values()),
            "links": list(self.edges.values()),
            "positions": self.positions,
            "attack_paths": attack_paths,
            "components": components,
            "statistics": statistics,
            "filtered_count": len(filtered),
            "total_count": len(normalized),
            "displayed_count": len(selected),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "engine": "networkx",
            "layout_engine": "networkx.spring_layout",
            "view": {
                "mode": "networkx_investigation_paths",
                "max_events": max_events,
                "description": (
                    "Top AI-ranked anomalies and security events linked by source, target, "
                    "domain, pattern, sequence, and shared infrastructure."
                ),
            },
        }

    def _normalize_event(self, event: dict[str, Any], fallback_index: int) -> dict[str, Any]:
        event_type = str(event.get("event_type") or event.get("type") or "anomaly").lower()
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        event_name = str(event.get("event") or "").lower()
        if (
            event.get("kind") == "mutation_attempt"
            or event_type == "mutation_attempt"
            or event_name in {"tamper_attempt_blocked", "tamper_attempt_no_effect"}
            or (details.get("operation") and details.get("target_sequence"))
        ):
            event_type = "mutation_attempt"
        elif event.get("event") or event.get("details") or event_type == "security_event":
            event_type = "chain_integrity"

        sequence = (
            event.get("sequence")
            or event.get("target_sequence")
            or event.get("evidence_id")
            or fallback_index
        )
        domain = self._domain_from_event(event, event_type)
        raw_severity = str(
            event.get("severity")
            or ("CRITICAL" if event_type == "chain_integrity" else "ANOMALY")
        ).upper()
        severity = self._normalize_severity(raw_severity)
        risk = self._risk_from_event(event, raw_severity)
        source = self._source_from_event(event, event_type)
        target = self._target_from_event(event, event_type)
        pattern = self._pattern_from_event(event, event_type)
        timestamp = event.get("occurred_at") or event.get("recorded_at") or event.get("created_at")
        description = (
            event.get("summary")
            or event.get("explanation")
            or event.get("description")
            or event.get("event")
            or pattern
        )

        return {
            **event,
            "event_id": f"{event_type}-{sequence}",
            "sequence": sequence,
            "event_type": event_type,
            "domain": domain,
            "severity": severity,
            "risk": risk,
            "source_component": source,
            "target_component": target,
            "pattern": pattern,
            "timestamp": timestamp,
            "occurred_at": timestamp,
            "label": self._event_label(event_type, sequence, severity),
            "description": str(description),
            "top_features": event.get("top_features") or [],
        }

    def _domain_from_event(self, event: dict[str, Any], event_type: str) -> str:
        if event_type in {"chain_integrity", "mutation_attempt"}:
            return "integrity"

        domain = str(event.get("domain") or "").strip().lower()
        if domain:
            return domain

        if str(event.get("data_format") or "").upper() == "ARINC429" or event.get("label_octal"):
            return "avionics"

        for endpoint_key in ("src", "src_ip", "source_ip", "dst", "dst_ip", "destination_ip"):
            inferred = self._domain_from_endpoint(event.get(endpoint_key))
            if inferred:
                return inferred

        source_file = Path(str(event.get("source_file") or "")).name.lower()
        explanation = str(
            event.get("explanation")
            or event.get("summary")
            or event.get("description")
            or ""
        ).lower()
        service = str(event.get("service") or event.get("protocol") or "").lower()
        probe = f"{source_file} {explanation} {service}"
        for candidate in ("avionics", "maintenance", "cabin", "afdx"):
            if candidate in probe:
                return candidate
        return "unknown"

    def _domain_from_endpoint(self, endpoint: Any) -> str | None:
        value = str(endpoint or "").strip().lower()
        for prefix, domain in self.DOMAIN_IP_PREFIXES:
            if value.startswith(prefix):
                return domain
        return None

    def _source_from_event(self, event: dict[str, Any], event_type: str) -> str:
        if event_type == "mutation_attempt":
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            actor = str(details.get("actor") or event.get("actor") or "")
            actor_ip = self._ip_from_text(actor)
            return str(
                event.get("source_component")
                or event.get("attacker_ip")
                or details.get("attacker_ip")
                or details.get("actor_ip")
                or actor_ip
                or self.DEFAULT_ATTACKER_IP
            )
        if event_type == "chain_integrity":
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            return str(details.get("actor") or event.get("actor") or "Trust Monitor")
        return str(
            event.get("source_component")
            or event.get("src")
            or event.get("src_ip")
            or event.get("source_ip")
            or Path(str(event.get("source_file") or "Unknown Source")).name
        )

    def _target_from_event(self, event: dict[str, Any], event_type: str) -> str:
        if event_type == "mutation_attempt":
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            target = event.get("target_sequence") or details.get("target_sequence") or event.get("sequence")
            return f"SEQ #{target}" if target else "Evidence Chain"

        if event_type == "chain_integrity":
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            target = (
                details.get("target_sequence")
                or details.get("records_restored")
                or event.get("sequence")
            )
            return f"Evidence Chain #{target}" if target else "Evidence Chain"

        port = event.get("port") or event.get("dst_port") or event.get("destination_port")
        target = (
            event.get("target_component")
            or event.get("dst")
            or event.get("dst_ip")
            or event.get("destination_ip")
        )
        if target and port:
            return f"{target}:{port}"
        return str(target or f"{event.get('protocol') or event.get('service') or 'Observed'} target")

    def _flow_label(self, event: dict[str, Any]) -> str:
        service = str(event.get("service") or event.get("protocol") or "traffic").upper()
        port = event.get("port") or event.get("dst_port") or event.get("destination_port")
        return f"{service}:{port}" if port not in (None, "", 0, "0") else service

    def _pattern_from_event(self, event: dict[str, Any], event_type: str) -> str:
        if event_type == "mutation_attempt":
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            operation = event.get("operation") or details.get("operation") or "mutation"
            status = "Blocked" if "blocked" in str(event.get("event") or event.get("activity") or "").lower() else "Recorded"
            return f"DB {str(operation).title()} Attempt {status}"

        if event_type == "chain_integrity":
            return str(event.get("event") or "Integrity Recovery").replace("_", " ").title()

        anomaly_type = event.get("anomaly_type") or event.get("attack_type")
        if anomaly_type:
            return str(anomaly_type).replace("_", " ").title()

        features = event.get("top_features") or []
        if isinstance(features, list) and features:
            return " / ".join(str(feature).replace("_", " ").title() for feature in features[:2])

        explanation = str(event.get("explanation") or event.get("summary") or "")
        if explanation:
            return explanation.split(".")[0][:64]
        return "AI Anomaly"

    def _event_label(self, event_type: str, sequence: Any, severity: str) -> str:
        if event_type == "mutation_attempt":
            prefix = "DB Mutation Attempt"
        elif event_type == "chain_integrity":
            prefix = "Chain Integrity"
        else:
            prefix = "AI Alert"
        return f"{prefix} #{sequence} [{severity.title()}]"

    def _normalize_severity(self, severity: str) -> str:
        return self.CANONICAL_SEVERITY.get(str(severity or "NORMAL").upper(), "NORMAL")

    def _apply_filters(
        self,
        events: list[dict[str, Any]],
        severity_threshold: float,
        severity_levels: list[str],
        domains: list[str],
        event_types: list[str],
        time_window_ms: int | None,
    ) -> list[dict[str, Any]]:
        filtered = list(events)

        if time_window_ms:
            cutoff_time = datetime.now(UTC) - timedelta(milliseconds=time_window_ms)
            filtered = [
                event for event in filtered
                if self._parse_timestamp(event.get("timestamp")) >= cutoff_time
            ]

        if severity_levels:
            wanted = {item.upper() for item in severity_levels if item}
            filtered = [
                event for event in filtered
                if str(event.get("severity") or "").upper() in wanted
            ]
        else:
            filtered = [
                event for event in filtered
                if float(event.get("risk") or 0) >= severity_threshold
            ]

        if domains:
            wanted = {item.lower() for item in domains if item}
            filtered = [
                event for event in filtered
                if str(event.get("domain") or "unknown").lower() in wanted
            ]

        if event_types:
            wanted = {item.lower() for item in event_types if item}
            filtered = [
                event for event in filtered
                if str(event.get("event_type") or "anomaly").lower() in wanted
            ]

        return filtered

    def _select_top_events(
        self,
        events: list[dict[str, Any]],
        max_events: int | None,
    ) -> list[dict[str, Any]]:
        ordered = sorted(
            events,
            key=lambda event: (
                float(event.get("risk") or 0),
                abs(self._float(event.get("anomaly_score"))),
                self._parse_timestamp(event.get("timestamp")).timestamp(),
            ),
            reverse=True,
        )
        if max_events:
            selected = ordered[: max(1, max_events)]
            selected_ids = {str(event.get("event_id") or "") for event in selected}
            pinned = [
                event for event in ordered
                if str(event.get("event_type") or "").lower() == "mutation_attempt"
            ]
            for event in pinned:
                event_id = str(event.get("event_id") or "")
                if event_id and event_id not in selected_ids:
                    selected.append(event)
                    selected_ids.add(event_id)
            ordered = selected
        return sorted(
            ordered,
            key=lambda event: (
                self._parse_timestamp(event.get("timestamp")).timestamp(),
                -float(event.get("risk") or 0),
            ),
        )

    def _add_event_subgraph(self, event: dict[str, Any]) -> None:
        domain = str(event["domain"])
        color = self.DOMAIN_COLORS.get(domain, self.DOMAIN_COLORS["unknown"])
        event_id = str(event["event_id"])
        domain_id = self._node_id("domain", domain)
        source_id = self._node_id("source", event["source_component"])
        target_id = self._node_id("target", event["target_component"])
        pattern_id = self._node_id("pattern", event["pattern"])

        common = {
            "domain": domain,
            "domain_color": color,
            "color": color,
            "related_sequences": [event.get("sequence")],
        }

        self._upsert_node(
            domain_id,
            "domain",
            domain.title(),
            incident_role="Operational Domain",
            **common,
        )
        self._upsert_node(
            source_id,
            "source",
            event["source_component"],
            incident_role="Origin Or Sensor",
            **common,
        )
        self._upsert_node(
            target_id,
            "target",
            event["target_component"],
            incident_role="Affected Asset",
            **common,
        )
        self._upsert_node(
            pattern_id,
            "pattern",
            event["pattern"],
            incident_role="Attack Pattern",
            **common,
        )
        self._upsert_node(
            event_id,
            "event",
            event["label"],
            domain=domain,
            domain_color=color,
            color=color,
            incident_role="Flagged Evidence",
            sequence=event.get("sequence"),
            severity=event.get("severity"),
            risk=event.get("risk"),
            event_type=event.get("event_type"),
            anomaly_score=event.get("anomaly_score"),
            pattern=event.get("pattern"),
            timestamp=event.get("timestamp"),
            explanation=event.get("explanation") or event.get("description"),
            description=event.get("description"),
            source_component=event.get("source_component"),
            target_component=event.get("target_component"),
            service=event.get("service") or event.get("protocol"),
            top_features=event.get("top_features") or [],
            rank=event.get("rank"),
            related_sequences=[event.get("sequence")],
        )

        self._add_edge(domain_id, source_id, "contains", "domain")
        self._add_edge(domain_id, pattern_id, "pattern cluster", "domain_pattern")
        self._add_edge(source_id, target_id, self._flow_label(event), "flow")
        self._add_edge(source_id, event_id, event.get("service") or event.get("protocol") or "observed", "observed")
        self._add_edge(event_id, target_id, "affects", "target")
        self._add_edge(event_id, pattern_id, "matches", "pattern")

    def _add_event_correlations(self, events: list[dict[str, Any]]) -> None:
        for index, current in enumerate(events):
            for previous in events[:index]:
                relation = self._correlation_relation(previous, current)
                if not relation:
                    continue
                source_id = str(previous["event_id"])
                target_id = str(current["event_id"])
                self._add_edge(source_id, target_id, relation["label"], relation["relation"])

    def _correlation_relation(
        self,
        previous: dict[str, Any],
        current: dict[str, Any],
    ) -> dict[str, str] | None:
        if (
            previous.get("source_component") == current.get("source_component")
            and previous.get("target_component") == current.get("target_component")
        ):
            return {"label": "same flow", "relation": "shared_flow"}
        if previous.get("target_component") == current.get("source_component"):
            return {"label": "pivot", "relation": "pivot"}
        if previous.get("target_component") == current.get("target_component"):
            return {"label": "same target", "relation": "shared_target"}
        if previous.get("pattern") == current.get("pattern"):
            return {"label": "same pattern", "relation": "shared_pattern"}
        if previous.get("source_component") == current.get("source_component"):
            return {"label": "same source", "relation": "shared_source"}
        if previous.get("domain") == current.get("domain"):
            prev_time = self._parse_timestamp(previous.get("timestamp"))
            curr_time = self._parse_timestamp(current.get("timestamp"))
            if abs((curr_time - prev_time).total_seconds()) <= 1800:
                return {"label": "same domain", "relation": "domain_sequence"}
        return None

    def _upsert_node(self, node_id: str, kind: str, label: Any, **metadata: Any) -> None:
        clean_sequences = [
            sequence for sequence in metadata.pop("related_sequences", []) if sequence is not None
        ]
        if node_id in self.nodes:
            node = self.nodes[node_id]
            node["event_count"] = int(node.get("event_count") or 1) + 1
            existing = set(node.get("related_sequences") or [])
            node["related_sequences"] = sorted(existing.union(clean_sequences), key=str)
            if metadata.get("risk") is not None:
                node["risk"] = max(float(node.get("risk") or 0), float(metadata.get("risk") or 0))
            return

        node = {
            "id": node_id,
            "kind": kind,
            "type": kind,
            "label": str(label),
            "short_label": self._short_label(label),
            "event_count": 1,
            "related_sequences": clean_sequences,
            "layer": self.KIND_LAYER.get(kind, 2),
            "layer_label": self.KIND_LABELS.get(kind, kind.title()),
            "risk": float(metadata.get("risk") or 0),
            **metadata,
        }
        self.nodes[node_id] = node
        if self.graph is not None:
            self.graph.add_node(node_id, **self._networkx_node_attrs(node))

    def _add_edge(self, source: str, target: str, label: Any, relation: str) -> None:
        if source == target or source not in self.nodes or target not in self.nodes:
            return

        key = (source, target, relation)
        if key in self.edges:
            self.edges[key]["weight"] = int(self.edges[key].get("weight") or 1) + 1
            if self.graph is not None and self.graph.has_edge(source, target):
                self.graph[source][target]["weight"] = self.edges[key]["weight"]
            return

        edge = {
            "id": f"{source}->{target}:{relation}",
            "source": source,
            "target": target,
            "label": str(label),
            "relation": relation,
            "weight": self._edge_weight(relation),
        }
        self.edges[key] = edge
        if self.graph is not None:
            self.graph.add_edge(source, target, **edge)

    @staticmethod
    def _edge_weight(relation: str) -> int:
        weighted_relations = {
            "shared_flow": 5,
            "pivot": 5,
            "shared_pattern": 4,
            "shared_target": 4,
            "shared_source": 4,
            "domain_pattern": 3,
            "flow": 3,
            "domain_sequence": 2,
            "pattern": 2,
            "observed": 2,
            "target": 2,
            "domain": 2,
        }
        return weighted_relations.get(relation, 1)

    def _networkx_node_attrs(self, node: dict[str, Any]) -> dict[str, Any]:
        return {
            "kind": node.get("kind"),
            "domain": node.get("domain"),
            "risk": node.get("risk"),
            "subset": int(node.get("layer") or 2),
        }

    def _apply_networkx_metrics(self) -> None:
        if self.graph is None or len(self.graph) == 0:
            return

        try:
            betweenness = nx.betweenness_centrality(self.graph, weight="weight", normalized=True)
        except Exception:
            betweenness = {}
        try:
            degree = nx.degree_centrality(self.graph)
        except Exception:
            degree = {}

        for node_id, node in self.nodes.items():
            node["centrality"] = round(float(betweenness.get(node_id, 0.0)), 4)
            node["degree_centrality"] = round(float(degree.get(node_id, 0.0)), 4)
            if self.graph is not None and node_id in self.graph:
                node["in_degree"] = int(self.graph.in_degree(node_id))
                node["out_degree"] = int(self.graph.out_degree(node_id))

    def _compute_networkx_layout(self) -> dict[str, tuple[float, float]]:
        if not self.nodes:
            return {}
        if self.graph is None or len(self.graph) == 0:
            return self._fallback_layout()

        try:
            raw_positions = nx.spring_layout(
                self.graph,
                seed=17,
                k=max(0.75, 2.6 / max(len(self.graph.nodes()), 2) ** 0.5),
                iterations=250,
                weight="weight",
            )
        except Exception:
            try:
                raw_positions = nx.kamada_kawai_layout(self.graph, weight="weight")
            except Exception:
                return self._fallback_layout()

        return self._scale_positions(raw_positions)

    def _scale_positions(self, raw_positions: dict[str, Any]) -> dict[str, tuple[float, float]]:
        width = 1120.0
        height = max(520.0, 120.0 + len([n for n in self.nodes.values() if n.get("kind") == "event"]) * 44.0)
        xs = [float(pos[0]) for pos in raw_positions.values()]
        ys = [float(pos[1]) for pos in raw_positions.values()]
        min_x, max_x = min(xs, default=0.0), max(xs, default=1.0)
        min_y, max_y = min(ys, default=0.0), max(ys, default=1.0)
        span_x = max(max_x - min_x, 0.001)
        span_y = max(max_y - min_y, 0.001)

        positions: dict[str, tuple[float, float]] = {}
        for node_id, pos in raw_positions.items():
            x = 70.0 + ((float(pos[0]) - min_x) / span_x) * (width - 140.0)
            y = 70.0 + ((float(pos[1]) - min_y) / span_y) * (height - 140.0)
            positions[node_id] = (round(x, 2), round(y, 2))
        return positions

    def _fallback_layout(self) -> dict[str, tuple[float, float]]:
        positions: dict[str, tuple[float, float]] = {}
        columns = {0: 70.0, 1: 280.0, 2: 540.0, 3: 790.0, 4: 1030.0}
        grouped: dict[int, list[str]] = {}
        for node_id, node in self.nodes.items():
            grouped.setdefault(int(node.get("layer") or 2), []).append(node_id)

        max_count = max((len(items) for items in grouped.values()), default=1)
        height = max(520.0, 80.0 + max_count * 62.0)
        for layer, node_ids in grouped.items():
            node_ids.sort(key=lambda node_id: (self.nodes[node_id].get("rank") or 999, self.nodes[node_id].get("label") or ""))
            for index, node_id in enumerate(node_ids, start=1):
                y = 70.0 + index * ((height - 140.0) / (len(node_ids) + 1))
                positions[node_id] = (columns.get(layer, 540.0), round(y, 2))
        return positions

    def _compute_attack_paths(self) -> list[dict[str, Any]]:
        event_ids = [
            node_id for node_id, node in self.nodes.items()
            if node.get("kind") == "event"
        ]
        event_ids.sort(key=lambda node_id: float(self.nodes[node_id].get("risk") or 0), reverse=True)
        if len(event_ids) < 2:
            return []
        if self.graph is None:
            return []

        undirected = self.graph.to_undirected()
        paths: list[dict[str, Any]] = []
        for index, source in enumerate(event_ids[:12]):
            for target in event_ids[index + 1 : 12]:
                try:
                    path = nx.shortest_path(undirected, source, target)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                if len(path) < 2 or len(path) > 8:
                    continue
                risk = max(float(self.nodes[node_id].get("risk") or 0) for node_id in path)
                paths.append(self._path_payload(path, risk))

        paths.sort(key=lambda item: (-float(item["risk"]), int(item["length"])))
        return paths[:8]

    def _path_payload(self, path: list[str], risk: float) -> dict[str, Any]:
        labels = [self.nodes[node_id].get("short_label") or self.nodes[node_id].get("label") for node_id in path]
        relations: list[str] = []
        for source, target in zip(path, path[1:]):
            edge = self._find_edge_between(source, target)
            if edge:
                relations.append(str(edge.get("label") or edge.get("relation")))
        return {
            "source": path[0],
            "target": path[-1],
            "path": path,
            "labels": labels,
            "relations": relations,
            "length": max(len(path) - 1, 0),
            "risk": round(float(risk), 4),
            "summary": " -> ".join(str(label) for label in labels[:5]),
        }

    def _find_edge_between(self, source: str, target: str) -> dict[str, Any] | None:
        for edge in self.edges.values():
            if edge["source"] == source and edge["target"] == target:
                return edge
            if edge["source"] == target and edge["target"] == source:
                return edge
        return None

    def _components_payload(self) -> list[dict[str, Any]]:
        if self.graph is None or len(self.graph) == 0:
            return []
        components = sorted(nx.weakly_connected_components(self.graph), key=len, reverse=True)
        payload: list[dict[str, Any]] = []
        for index, component in enumerate(components, start=1):
            event_count = sum(1 for node_id in component if self.nodes.get(node_id, {}).get("kind") == "event")
            max_risk = max((float(self.nodes.get(node_id, {}).get("risk") or 0) for node_id in component), default=0.0)
            domains = sorted({str(self.nodes.get(node_id, {}).get("domain") or "unknown") for node_id in component})
            payload.append(
                {
                    "id": f"component-{index}",
                    "node_count": len(component),
                    "event_count": event_count,
                    "max_risk": round(max_risk, 4),
                    "domains": domains,
                    "nodes": sorted(component),
                }
            )
        return payload

    def _compute_statistics(
        self,
        filtered_events: list[dict[str, Any]],
        attack_paths: list[dict[str, Any]],
        components: list[dict[str, Any]],
    ) -> dict[str, Any]:
        domains: dict[str, int] = {}
        severities: dict[str, int] = {}
        patterns: dict[str, int] = {}
        event_types: dict[str, int] = {}

        for event in filtered_events:
            domains[str(event["domain"])] = domains.get(str(event["domain"]), 0) + 1
            severities[str(event["severity"])] = severities.get(str(event["severity"]), 0) + 1
            patterns[str(event["pattern"])] = patterns.get(str(event["pattern"]), 0) + 1
            event_types[str(event["event_type"])] = event_types.get(str(event["event_type"]), 0) + 1

        density = 0.0
        if self.graph is not None and len(self.graph) > 1:
            try:
                density = float(nx.density(self.graph))
            except Exception:
                density = 0.0

        top_node = None
        if self.nodes:
            top_node = max(self.nodes.values(), key=lambda node: float(node.get("centrality") or 0))

        avg_risk = (
            sum(float(event.get("risk") or 0) for event in filtered_events)
            / max(len(filtered_events), 1)
        )
        return {
            "domains": domains,
            "severities": severities,
            "patterns": patterns,
            "event_types": event_types,
            "avg_risk": round(avg_risk, 4),
            "density": round(density, 4),
            "attack_path_count": len(attack_paths),
            "component_count": len(components),
            "top_central_node": top_node.get("label") if top_node else None,
        }

    def _risk_from_event(self, event: dict[str, Any], severity: str | None = None) -> float:
        severity_risk = self.SEVERITY_LEVELS.get(str(severity or event.get("severity") or "ANOMALY").upper(), 0.6)
        score = self._float(event.get("anomaly_score"))
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
    def _node_id(kind: str, value: Any) -> str:
        text = str(value or "unknown").strip().lower()
        safe = "".join(char if char.isalnum() else "-" for char in text).strip("-")
        while "--" in safe:
            safe = safe.replace("--", "-")
        return f"{kind}-{safe or 'unknown'}"

    @staticmethod
    def _short_label(value: Any, limit: int = 24) -> str:
        text = str(value or "Unknown")
        return text if len(text) <= limit else f"{text[: limit - 1]}."

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now(UTC)

    @staticmethod
    def _ip_from_text(value: Any) -> str | None:
        text = str(value or "")
        parts = text.split()
        for part in parts:
            clean = part.strip("[](),;:")
            octets = clean.split(".")
            if len(octets) == 4 and all(item.isdigit() and 0 <= int(item) <= 255 for item in octets):
                return clean
        return None

    @staticmethod
    def _float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value if value is not None else default)
        except (TypeError, ValueError):
            return default

    def _reset(self) -> None:
        if self.graph is not None:
            self.graph.clear()
        self.nodes = {}
        self.edges = {}
        self.positions = {}
        self.selected_events = []

    def export_summary(self) -> str:
        lines = [
            "BLUEBOX NETWORKX PROVENANCE INVESTIGATION SUMMARY",
            "=" * 80,
            f"Generated: {datetime.now(UTC).isoformat()}",
            f"Displayed events: {len(self.selected_events)}",
            f"Graph nodes: {len(self.nodes)}",
            f"Graph edges: {len(self.edges)}",
            "",
        ]
        for event in self.selected_events:
            lines.append(
                f"- {event['label']} | {event['domain']} | {event['source_component']} -> "
                f"{event['target_component']} | {event['pattern']} | risk={event['risk']}"
            )
            if event.get("description"):
                lines.append(f"  {event['description']}")
        lines.append("=" * 80)
        return "\n".join(lines)

    def export_png(self, width: int = 1280, height: int = 780) -> BytesIO:
        if Image is None:
            raise RuntimeError("PIL is required for PNG export")

        img = Image.new("RGB", (width, height), color="#071522")
        draw = ImageDraw.Draw(img)
        positions = self._fit_positions(width, height)

        for edge in self.edges.values():
            source = positions.get(edge["source"])
            target = positions.get(edge["target"])
            if source and target:
                draw.line([source, target], fill="#4f6f87", width=max(1, int(edge.get("weight", 1))))

        for node_id, node in self.nodes.items():
            x, y = positions.get(node_id, (0, 0))
            color = node.get("domain_color") or self.DOMAIN_COLORS["unknown"]
            radius = 14 if node.get("kind") == "event" else 9
            draw.ellipse([x - radius, y - radius, x + radius, y + radius], fill=color)
            draw.text((x + radius + 5, y - 7), str(node.get("label", ""))[:34], fill="#E8F7FF")

        output = BytesIO()
        img.save(output, format="PNG")
        output.seek(0)
        return output

    def _fit_positions(self, width: int, height: int) -> dict[str, tuple[float, float]]:
        if not self.positions:
            return {}
        xs = [float(pos[0]) for pos in self.positions.values()]
        ys = [float(pos[1]) for pos in self.positions.values()]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        span_x = max(max_x - min_x, 0.001)
        span_y = max(max_y - min_y, 0.001)
        return {
            node_id: (
                50.0 + ((float(pos[0]) - min_x) / span_x) * (width - 100.0),
                50.0 + ((float(pos[1]) - min_y) / span_y) * (height - 100.0),
            )
            for node_id, pos in self.positions.items()
        }
