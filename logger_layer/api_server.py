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
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.shared.paths import RUNTIME_DEMO_OUTPUT_DIR
from logger_layer.hash_chain_logger import (
    DEFAULT_AI_EVIDENCE_LEDGER,
    DEFAULT_DB,
    DEFAULT_RECOVERY_LEDGER,
    HashChainLogger,
)
from logger_layer.provenance_graph_builder import ProvenanceGraphBuilder


STATIC_DIR = PROJECT_ROOT / "UI_layer" / "bluebox_react" / "dist"
DEMO_OUTPUT_DIR = RUNTIME_DEMO_OUTPUT_DIR / "logger_demo"


class LoggerDemoHandler(SimpleHTTPRequestHandler):
    server_version = "BlueBoxLoggerDemo/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    @property
    def logger(self) -> HashChainLogger:
        return self.server.logger  # type: ignore[attr-defined]

    def status_payload(self) -> dict[str, object]:
        return self.server.cached_status_payload()  # type: ignore[attr-defined]

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
                # Note: Not requiring trusted readiness for forensic analysis
                # as this is read-only historical analysis
                try:
                    # Get forensic replay data
                    replay_data = self.logger.forensic_replay(limit=50)
                    timeline = replay_data.get("timeline", [])
                    
                    # Parse severity threshold from query params
                    severity_threshold = 0.5
                    query_params = parse_qs(parsed.query)
                    if "severity" in query_params:
                        try:
                            severity_threshold = float(query_params["severity"][0])
                        except (ValueError, IndexError):
                            pass
                    
                    # Build provenance graph using NetworkX
                    graph_builder = ProvenanceGraphBuilder()
                    graph_data = graph_builder.build_from_forensic_timeline(
                        timeline,
                        severity_threshold=severity_threshold
                    )
                    
                    self.write_json(graph_data)
                except Exception as e:
                    self.write_json({"error": str(e), "nodes": {}, "edges": [], "positions": {}}, status=400)
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
                self.require_trusted_readiness()
                self.write_json(self.handle_chat(payload))
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
        for csv_path in sorted(output_dir.glob("*.csv")):
            if csv_path.stem.endswith("_labels") or csv_path.stem.endswith("_scores"):
                continue
            score_path = default_score_path(csv_path)
            ai_results[csv_path.name] = test_anomaly_detection(csv_path, score_path)
            ingested_entries += self.logger.ingest_path(csv_path)
            ai_attachments[csv_path.name] = self.logger.attach_ai_evidence_from_csv(
                csv_path,
                score_path,
                include_shap=True,
            )
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
            actor=str(payload.get("actor", "dashboard")),
        )

    def handle_restore_ledger(self, payload: dict[str, object]) -> dict[str, object]:
        return self.logger.restore_from_recovery_ledger(
            reason=str(payload.get("reason", "analyst_requested_restore")),
            actor=str(payload.get("actor", "dashboard")),
        )

    def handle_chat(self, payload: dict[str, object]) -> dict[str, object]:
        question = str(payload.get("question", "")).strip()
        lower = question.lower()
        status = self.logger.integrity_panel()
        ai = self.logger.ai_evidence_summary(limit=5)
        anomalies = list(ai.get("ranked_anomalies", []))
        if not question:
            answer = "Ask about anomalies, SHAP explanations, chain integrity, or report readiness."
        elif "chain" in lower or "tamper" in lower or "hash" in lower or "integrity" in lower:
            answer = (
                f"Chain status is {status['status']}. "
                f"{status['checked_entries']} entries were checked. "
                f"Recovery ledger is {status['recovery_ledger'].get('status', 'unknown')} and "
                f"trusted readiness is {status['trusted_readiness'].get('trusted', False)}."
            )
        elif "shap" in lower or "explain" in lower or "why" in lower:
            if anomalies:
                top = anomalies[0]
                features = ", ".join(top.get("top_features", [])) or "no SHAP features stored"
                answer = (
                    f"Latest anomaly evidence #{top['evidence_id']} maps to sequence "
                    f"#{top['sequence']}. Top SHAP drivers: {features}. "
                    f"{top.get('explanation') or 'No explanation text was attached.'}"
                )
            else:
                answer = "No anomaly with SHAP explanation is currently attached."
        elif "anomal" in lower or "suspicious" in lower or "alert" in lower:
            answer = (
                f"{ai['anomalies']} anomalies are attached out of "
                f"{ai['total_ai_records']} AI evidence records. "
                f"Severity counts: {ai['severity_counts']}."
            )
        elif "report" in lower or "compliance" in lower:
            answer = (
                "Use Download Report in Anomaly Detection. The report includes chain status, "
                "AI evidence counts, latest anomaly references, SHAP notes, and replay head."
            )
        else:
            answer = (
                "BlueBox can answer from the local evidence index: anomaly counts, SHAP drivers, "
                "chain integrity, recovery status, and report readiness."
            )
        return {"question": question, "answer": answer, "context": {"ai": ai, "status": status}}

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
        self._status_cache: tuple[float, dict[str, object]] | None = None
        self._status_cache_lock = RLock()

    def invalidate_status_cache(self) -> None:
        with self._status_cache_lock:
            self._status_cache = None

    def cached_status_payload(self, ttl_seconds: float = 1.0) -> dict[str, object]:
        now = time.monotonic()
        with self._status_cache_lock:
            if self._status_cache and now - self._status_cache[0] <= ttl_seconds:
                return dict(self._status_cache[1])
            payload = self.logger.integrity_panel()
            payload["demo_capabilities"] = {
                "demo_attaches_ai_evidence": True,
                "demo_default_scenario": "mixed_attack",
                "protected_read_gate": True,
            }
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
