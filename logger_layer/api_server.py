#!/usr/bin/env python3
"""Local HTTP API and static server for the BlueBox logger dashboard."""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import RLock
from urllib.parse import parse_qs, urlencode, urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.shared.paths import RUNTIME_DEMO_OUTPUT_DIR
from logger_layer.hash_chain_logger import (
    DEFAULT_AI_EVIDENCE_LEDGER,
    DEFAULT_DB,
    DEFAULT_RECOVERY_LEDGER,
    HashChainLogger,
    RawEvent,
    canonical_json,
)
from logger_layer.enhanced_provenance_builder import EnhancedProvenanceGraphBuilder
from UI_layer.BB_bot.bb_bot_service import BBBotService, extract_sequence_numbers


STATIC_DIR = PROJECT_ROOT / "UI_layer" / "bluebox_react" / "dist"
DEMO_OUTPUT_DIR = RUNTIME_DEMO_OUTPUT_DIR / "logger_demo"


def normalize_local_source_file(value: object, fallback: str = "live://traffic_simulator") -> str:
    text = str(value or "").strip()
    if not text:
        return fallback
    if "://" in text:
        return text
    source_path = Path(text).expanduser()
    if not source_path.is_absolute():
        source_path = PROJECT_ROOT / source_path
    return str(source_path.resolve())


class LoggerDemoHandler(SimpleHTTPRequestHandler):
    server_version = "BlueBoxLoggerDemo/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    @property
    def logger(self) -> HashChainLogger:
        return self.server.logger  # type: ignore[attr-defined]

    def status_payload(self) -> dict[str, object]:
        return self.server.cached_status_payload()  # type: ignore[attr-defined]

    @property
    def bb_bot(self) -> BBBotService:
        return self.server.bb_bot  # type: ignore[attr-defined]

    def provenance_query(self, query: str) -> dict[str, object]:
        query_params = parse_qs(query)
        severity_threshold = 0.5
        severity_levels: list[str] = []
        domains: list[str] = []
        event_types: list[str] = []
        time_window_ms: int | None = None
        max_events = 10

        if "severity" in query_params:
            try:
                severity_threshold = float(query_params["severity"][0])
            except (ValueError, IndexError):
                pass

        if "severity_levels" in query_params:
            severity_levels = [item for item in query_params["severity_levels"][0].split(",") if item]

        if "domains" in query_params:
            domains = [item for item in query_params["domains"][0].split(",") if item]

        if "event_types" in query_params:
            event_types = [item for item in query_params["event_types"][0].split(",") if item]

        if "time_window_ms" in query_params:
            try:
                twms = float(query_params["time_window_ms"][0])
                time_window_ms = None if twms == float("inf") else int(twms)
            except (ValueError, IndexError):
                pass

        if "limit" in query_params:
            try:
                max_events = max(1, min(int(query_params["limit"][0]), 30))
            except (ValueError, IndexError):
                pass

        return {
            "severity_threshold": severity_threshold,
            "severity_levels": severity_levels,
            "domains": domains,
            "event_types": event_types,
            "time_window_ms": time_window_ms,
            "max_events": max_events,
        }

    def provenance_events(self) -> list[dict[str, object]]:
        ai = self.logger.ai_evidence_summary(limit=80)
        events = list(ai.get("ranked_anomalies", []))
        for event in ai.get("security_events", []):
            if isinstance(event, dict):
                events.append({**event, "event_type": "security_event"})
        try:
            activity = self.status_payload().get("append_only_activity", [])
        except Exception:
            activity = []
        seen_attempts = {
            str(event.get("details", {}).get("attempt_id") or event.get("attempt_id") or "")
            for event in events
            if isinstance(event, dict)
        }
        for event in activity if isinstance(activity, list) else []:
            if not isinstance(event, dict) or event.get("kind") != "mutation_attempt":
                continue
            attempt_id = str(event.get("attempt_id") or "")
            if attempt_id and attempt_id in seen_attempts:
                continue
            events.append({**event, "event_type": "mutation_attempt"})
            if attempt_id:
                seen_attempts.add(attempt_id)
        return events

    def provenance_graph_payload(self, query: str) -> dict[str, object]:
        graph_builder = EnhancedProvenanceGraphBuilder()
        return graph_builder.build_from_forensic_timeline(
            self.provenance_events(),
            **self.provenance_query(query),
        )

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/status":
                self.write_json(self.status_payload())
                return
            if parsed.path == "/api/anomaly":
                self.require_trusted_readiness()
                self.write_json(self.logger.ai_evidence_summary())
                return
            if parsed.path == "/api/replay":
                self.require_trusted_readiness()
                self.write_json(self.logger.forensic_replay())
                return
            if parsed.path == "/api/provenance-graph":
                try:
                    self.write_json(self.provenance_graph_payload(parsed.query))
                except Exception as e:
                    self.write_json({"error": str(e), "nodes": [], "links": [], "positions": {}}, status=400)
                return
            
            if parsed.path == "/api/provenance-graph/export/png":
                # Export provenance graph as PNG
                try:
                    graph_builder = EnhancedProvenanceGraphBuilder()
                    graph_builder.build_from_forensic_timeline(
                        self.provenance_events(),
                        **self.provenance_query(parsed.query),
                    )
                    png_buffer = graph_builder.export_png()
                    self.send_response(200)
                    self.send_header("Content-Type", "image/png")
                    self.send_header("Content-Length", str(len(png_buffer.getvalue())))
                    self.end_headers()
                    self.wfile.write(png_buffer.getvalue())
                except Exception as e:
                    self.write_json({"error": str(e)}, status=500)
                return
            
            if parsed.path == "/api/provenance-graph/export/summary":
                # Export provenance graph as text summary
                try:
                    graph_builder = EnhancedProvenanceGraphBuilder()
                    graph_builder.build_from_forensic_timeline(
                        self.provenance_events(),
                        **self.provenance_query(parsed.query),
                    )
                    summary = graph_builder.export_summary()
                    self.write_json({"summary": summary})
                except Exception as e:
                    self.write_json({"error": str(e)}, status=500)
                return
            if parsed.path == "/api/bb-bot/documents":
                self.write_json({"documents": self.bb_bot.list_documents()})
                return
            if parsed.path == "/api/report":
                self.require_trusted_readiness()
                report = self.logger.forensic_report()
                self.write_json({
                    "content": report.get("content", ""),
                    "filename": report.get("filename", f"BlueBox_Report_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.txt")
                })
                return
            if parsed.path == "/api/entries":
                self.require_trusted_readiness()
                limit = int(parse_qs(parsed.query).get("limit", ["50"])[0])
                self.write_json({"entries": self.logger.recent_entries(limit)})
                return
            if parsed.path.startswith("/api/entry/"):
                self.require_trusted_readiness()
                sequence = int(parsed.path.rsplit("/", 1)[-1])
                self.write_json(self.logger.decrypt_entry(sequence))
                return
        except PermissionError as exc:
            self.write_json({"error": str(exc), "trusted": False}, HTTPStatus.FORBIDDEN)
            return
        except Exception as exc:
            self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if parsed.path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            payload = self.read_json()
            if parsed.path == "/api/append":
                result = self.handle_append(payload)
                self.server.invalidate_status_cache()  # type: ignore[attr-defined]
                self.write_json(result)
            elif parsed.path == "/api/ingest":
                result = self.handle_ingest(payload)
                self.server.invalidate_status_cache()  # type: ignore[attr-defined]
                self.write_json(result)
            elif parsed.path == "/api/live-traffic":
                result = self.handle_live_traffic(payload)
                self.server.invalidate_status_cache()  # type: ignore[attr-defined]
                self.write_json(result)
            elif parsed.path == "/api/attach-ai":
                result = self.handle_attach_ai(payload)
                self.server.invalidate_status_cache()  # type: ignore[attr-defined]
                self.write_json(result)
            elif parsed.path == "/api/demo":
                result = self.handle_demo(payload)
                self.server.invalidate_status_cache()  # type: ignore[attr-defined]
                self.write_json(result)
            elif parsed.path == "/api/anchor":
                result = {"anchor": self.logger.anchor_current_head()}
                self.server.invalidate_status_cache()  # type: ignore[attr-defined]
                self.write_json(result)
            elif parsed.path == "/api/verify":
                self.write_json(self.logger.verify())
            elif parsed.path == "/api/verify-ledger":
                self.write_json(self.logger.verify_recovery_ledger())
            elif parsed.path == "/api/init-ledger":
                result = self.logger.initialize_recovery_ledger()
                self.server.invalidate_status_cache()  # type: ignore[attr-defined]
                self.write_json(result)
            elif parsed.path == "/api/restore-ledger":
                result = self.handle_restore_ledger(payload)
                self.server.invalidate_status_cache()  # type: ignore[attr-defined]
                self.write_json(result)
            elif parsed.path == "/api/tamper-attempt":
                result = self.handle_tamper_attempt(payload)
                self.server.invalidate_status_cache()  # type: ignore[attr-defined]
                self.write_json(result)
            elif parsed.path == "/api/chat":
                self.write_json(self.handle_chat(payload))
            elif parsed.path == "/api/bb-bot/upload":
                self.write_json(self.bb_bot.save_upload(payload))
            elif parsed.path == "/api/bb-bot/delete":
                self.write_json(self.bb_bot.delete_document(payload))
            elif parsed.path == "/api/bb-bot/context":
                self.require_trusted_readiness()
                self.write_json(self.handle_bb_bot_context(payload))
            else:
                self.write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except PermissionError as exc:
            self.write_json({"error": str(exc), "trusted": False}, HTTPStatus.FORBIDDEN)
        except Exception as exc:
            self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def require_trusted_readiness(self) -> dict[str, object]:
        status = self.status_payload()
        readiness = status.get("trusted_readiness")
        if isinstance(readiness, dict) and readiness.get("trusted"):
            return readiness
        raise PermissionError(f"trusted-read gate failed: {readiness}")

    def handle_append(self, payload: dict[str, object]) -> dict[str, object]:
        event_payload = payload.get("payload")
        if not isinstance(event_payload, dict):
            raise ValueError("payload must contain a JSON object at key 'payload'")
        entry_hash = self.logger.append_json(
            event_payload,
            source_file=str(payload.get("source_file", "browser")),
            source_type=str(payload.get("source_type", "JSON")),
            metadata={"ingest_mode": "browser_append"},
        )
        return {"entry_hash": entry_hash, "status": self.logger.integrity_panel()}

    def handle_ingest(self, payload: dict[str, object]) -> dict[str, object]:
        source = Path(str(payload.get("path", ""))).expanduser()
        if not source.is_absolute():
            source = PROJECT_ROOT / source
        source = source.resolve()
        if not source.exists():
            raise FileNotFoundError(source)
        count = self.logger.ingest_path(source)
        return {"ingested_entries": count, "source": str(source), "status": self.logger.integrity_panel()}

    def handle_live_traffic(self, payload: dict[str, object]) -> dict[str, object]:
        self.server.mark_live_traffic_activity()  # type: ignore[attr-defined]
        records = payload.get("records")
        if not isinstance(records, list) or not records:
            raise ValueError("records must be a non-empty list")

        events: list[RawEvent] = []
        ai_items: list[tuple[RawEvent, dict[str, object], str | Path | None, int | None]] = []
        has_ai = False
        for index, item in enumerate(records):
            if not isinstance(item, dict):
                raise ValueError(f"records[{index}] must be an object")
            event_payload = item.get("payload")
            if not isinstance(event_payload, dict):
                raise ValueError(f"records[{index}].payload must be an object")

            source_file = normalize_local_source_file(
                item.get("source_file") or payload.get("source_file")
            )
            source_type = str(item.get("source_type") or payload.get("source_type") or "LIVE_TRAFFIC")
            source_offset = int(item.get("source_offset", index))
            metadata = {
                "ingest_mode": "live_traffic_simulator",
                "scenario": payload.get("scenario"),
                "domain": event_payload.get("domain"),
                "data_format": event_payload.get("data_format"),
                "anomaly_type": event_payload.get("anomaly_type"),
                "occurred_at": event_payload.get("timestamp"),
            }
            event = RawEvent(
                source_file=source_file,
                source_type=source_type,
                source_offset=source_offset,
                payload=canonical_json(event_payload).encode("utf-8"),
                metadata={key: value for key, value in metadata.items() if value not in (None, "")},
            )
            verdict = item.get("verdict")
            if isinstance(verdict, dict):
                has_ai = True
                ai_items.append((event, verdict, source_file, source_offset))
            else:
                events.append(event)

        if has_ai and events:
            raise ValueError("live traffic batch cannot mix AI-scored and raw-only records")

        if has_ai:
            evidence_ids = self.logger.append_many_with_ai_evidence(ai_items)
            checkpoint = (
                self.logger.create_ai_evidence_checkpoint(
                    evidence_ids,
                    checkpoint_type="live_traffic_ai_batch",
                )
                if evidence_ids
                else None
            )
            return {
                "ingested_entries": len(ai_items),
                "ai_evidence_records": len(evidence_ids),
                "checkpoint": checkpoint,
            }

        count = self.logger.append_many(events)
        return {
            "ingested_entries": count,
            "ai_evidence_records": 0,
            "checkpoint": None,
        }

    def handle_attach_ai(self, payload: dict[str, object]) -> dict[str, object]:
        self.server.mark_live_traffic_activity()  # type: ignore[attr-defined]
        source_csv = Path(str(payload.get("source_csv", ""))).expanduser()
        score_csv = Path(str(payload.get("score_csv", ""))).expanduser()
        if not source_csv.is_absolute():
            source_csv = PROJECT_ROOT / source_csv
        if not score_csv.is_absolute():
            score_csv = PROJECT_ROOT / score_csv
        source_csv = source_csv.resolve()
        score_csv = score_csv.resolve()
        if not source_csv.exists():
            raise FileNotFoundError(source_csv)
        if not score_csv.exists():
            raise FileNotFoundError(score_csv)
        result = self.logger.attach_ai_evidence_from_csv(
            source_csv,
            score_csv,
            include_shap=bool(payload.get("include_shap", True)),
        )
        self.server.mark_live_traffic_activity()  # type: ignore[attr-defined]
        return {
            **result,
            "ai_evidence_records": result.get("attached", 0),
        }

    def handle_demo(self, payload: dict[str, object]) -> dict[str, object]:
        from demo.traffic_simulator import (
            TrafficGenerator,
            default_score_path,
            load_scenario_yaml,
            test_anomaly_detection,
        )

        scenario = str(payload.get("scenario", "normal"))
        duration = max(1, min(int(payload.get("duration", 3)), 30))
        output_dir = DEMO_OUTPUT_DIR / scenario
        scenario_config = load_scenario_yaml(scenario)
        TrafficGenerator(scenario_config, duration, output_dir).generate_all_domains()
        ai_results = {}
        ai_attachments = {}
        ingested_entries = 0
        csv_paths = sorted(output_dir.glob("*.csv"))
        traffic_csv_paths = [
            path for path in csv_paths
            if not path.stem.endswith("_labels") and not path.stem.endswith("_scores")
        ]
        sidecar_csv_paths = [
            path for path in csv_paths
            if path.stem.endswith("_labels")
        ]
        pcap_paths = sorted(output_dir.glob("*.pcap"))

        for csv_path in traffic_csv_paths:
            score_path = default_score_path(csv_path)
            ai_results[csv_path.name] = test_anomaly_detection(csv_path, score_path)
            ingested_entries += self.logger.ingest_path(csv_path)
            ai_attachments[csv_path.name] = self.logger.attach_ai_evidence_from_csv(
                csv_path,
                score_path,
                include_shap=True,
            )

        for raw_artifact_path in [*sidecar_csv_paths, *pcap_paths]:
            if raw_artifact_path.name.endswith("_scores.csv"):
                continue
            ingested_entries += self.logger.ingest_path(raw_artifact_path)
        artifacts = [
            {
                "path": str(path),
                "bytes": path.stat().st_size,
            }
            for path in sorted(output_dir.glob("*"))
            if path.is_file()
        ]
        manifest = {
            "event": "combined_ai_logger_demo",
            "scenario": scenario,
            "duration": duration,
            "created_at": datetime.now(UTC).isoformat(),
            "output_dir": str(output_dir),
            "ai_results": ai_results,
            "ai_attachments": ai_attachments,
            "artifacts": artifacts,
        }
        manifest_path = output_dir / "demo_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
        entry_hash = self.logger.append_json(
            manifest,
            source_file=str(manifest_path),
            source_type="DEMO_MANIFEST",
            metadata={"ingest_mode": "demo_manifest"},
        )
        return {
            "scenario": scenario,
            "duration": duration,
            "output_dir": str(output_dir),
            "ai_results": ai_results,
            "ai_attachments": ai_attachments,
            "ingested_entries": ingested_entries + 1,
            "entry_hash": entry_hash,
            "status": self.logger.integrity_panel(),
        }

    def handle_tamper_attempt(self, payload: dict[str, object]) -> dict[str, object]:
        sequence_value = payload.get("sequence")
        sequence = int(sequence_value) if sequence_value not in (None, "") else None
        return self.logger.simulate_tamper_attempt(
            operation=str(payload.get("operation", "delete")),
            sequence=sequence,
            actor=str(payload.get("actor", "203.0.113.45")),
        )

    def handle_restore_ledger(self, payload: dict[str, object]) -> dict[str, object]:
        return self.logger.restore_from_recovery_ledger(
            reason=str(payload.get("reason", "analyst_requested_restore")),
            actor=str(payload.get("actor", "dashboard")),
        )

    def handle_bb_bot_context(self, payload: dict[str, object]) -> dict[str, object]:
        filters = payload.get("graph_filters") if isinstance(payload.get("graph_filters"), dict) else {}
        query_parts: dict[str, object] = {}
        if isinstance(filters, dict):
            for key, value in filters.items():
                if value in (None, "", [], {}):
                    continue
                if isinstance(value, list):
                    query_parts[key] = ",".join(str(item) for item in value)
                else:
                    query_parts[key] = value
        query = urlencode(query_parts)
        graph_context = {
            "graph": self.provenance_graph_payload(query),
            "status": self.status_payload(),
            "anomaly": self.logger.ai_evidence_summary(limit=1000),
            "replay": self.logger.forensic_replay(),
            "report": self.logger.forensic_report(),
        }
        return self.bb_bot.stage_forensic_context(payload, graph_context)

    def handle_chat(self, payload: dict[str, object]) -> dict[str, object]:
        question = str(payload.get("question", "")).strip()
        extra_context = payload.get("context") if isinstance(payload.get("context"), dict) else {}
        if BBBotService._is_simple_smalltalk(question):
            return self.bb_bot.answer(question, {})

        lower = question.lower()
        wants_graph = any(
            term in lower
            for term in (
                "attack",
                "path",
                "pattern",
                "graph",
                "relationship",
                "linked",
                "evidence",
                "anomaly",
                "incident",
                "mutation",
                "critical",
                "response",
                "demo",
                "narrative",
                "source",
                "target",
            )
        )
        wants_replay = any(term in lower for term in ("timeline", "replay"))
        page_context = dict(extra_context)
        sequences = extract_sequence_numbers(question)
        if sequences:
            raw_sequence_entries: list[dict[str, object]] = []
            for sequence in sequences[:5]:
                try:
                    raw_sequence_entries.append(self.logger.decrypt_entry(sequence))
                except Exception as exc:
                    raw_sequence_entries.append(
                        {
                            "sequence": sequence,
                            "source_type": "unavailable",
                            "severity": "LOW",
                            "summary": f"Raw sequence entry is not available: {exc}",
                        }
                    )
            page_context["raw_sequence_entries"] = raw_sequence_entries
            page_context["sequence_entries"] = self.status_payload().get("sequence_entries", [])

        live_context = {
            "status": self.status_payload(),
            "latest_ai_summary": self.logger.ai_evidence_summary(limit=200),
            "page_context": page_context,
        }
        if wants_replay and not sequences and not page_context.get("evidence_entries"):
            try:
                live_context["forensic_replay"] = self.logger.forensic_replay(limit=80)
            except Exception:
                live_context["forensic_replay"] = {}
        if wants_graph:
            try:
                live_context["provenance_graph"] = self.provenance_graph_payload("limit=30")
            except Exception:
                live_context["provenance_graph"] = {}
        return self.bb_bot.answer(question, live_context)

    def read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def write_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def log_message(self, format: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))


class LoggerDemoServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_class, logger: HashChainLogger):
        super().__init__(server_address, handler_class)
        self.logger = logger
        self.bb_bot = BBBotService(logger)
        self._status_cache: tuple[float, dict[str, object]] | None = None
        self._status_cache_lock = RLock()
        self._live_traffic_last_seen = 0.0

    def invalidate_status_cache(self) -> None:
        with self._status_cache_lock:
            self._status_cache = None

    def mark_live_traffic_activity(self) -> None:
        self._live_traffic_last_seen = time.monotonic()
        self.invalidate_status_cache()

    def live_traffic_status(self) -> dict[str, object]:
        elapsed = time.monotonic() - self._live_traffic_last_seen
        active = self._live_traffic_last_seen > 0 and elapsed <= 5.0
        return {
            "active": active,
            "seconds_since_last_batch": round(elapsed, 2) if self._live_traffic_last_seen > 0 else None,
        }

    def cached_status_payload(self, ttl_seconds: float = 1.0) -> dict[str, object]:
        now = time.monotonic()
        with self._status_cache_lock:
            if self._status_cache and now - self._status_cache[0] <= ttl_seconds:
                payload = dict(self._status_cache[1])
                payload["live_traffic"] = self.live_traffic_status()
                return payload
            payload = self.logger.integrity_panel()
            payload["demo_capabilities"] = {
                "demo_attaches_ai_evidence": True,
                "demo_default_scenario": "mixed_attack",
                "protected_read_gate": True,
            }
            payload["live_traffic"] = self.live_traffic_status()
            self._status_cache = (now, payload)
            return dict(payload)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the BlueBox logger dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--recovery-ledger", type=Path, default=DEFAULT_RECOVERY_LEDGER)
    parser.add_argument("--ai-evidence-ledger", type=Path, default=DEFAULT_AI_EVIDENCE_LEDGER)
    args = parser.parse_args()

    if not STATIC_DIR.exists():
        raise FileNotFoundError(f"static UI directory not found: {STATIC_DIR}")

    server = LoggerDemoServer(
        (args.host, args.port),
        LoggerDemoHandler,
        HashChainLogger(
            db_path=args.db,
            recovery_ledger_path=args.recovery_ledger,
            ai_evidence_ledger_path=args.ai_evidence_ledger,
        ),
    )
    print(f"BlueBox logger dashboard: http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
