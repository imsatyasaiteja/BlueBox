#!/usr/bin/env python3
"""Local HTTP API and static server for the BlueBox logger demo."""

from __future__ import annotations

import json
import sys
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from logger_layer.hash_chain_logger import DEFAULT_DB, HashChainLogger


STATIC_DIR = PROJECT_ROOT / "UI_layer" / "logger_page"
DEMO_OUTPUT_DIR = PROJECT_ROOT / "data" / "generated" / "logger_demo"


class LoggerDemoHandler(SimpleHTTPRequestHandler):
    server_version = "BlueBoxLoggerDemo/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    @property
    def logger(self) -> HashChainLogger:
        return self.server.logger  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            self.write_json(self.logger.integrity_panel())
            return
        if parsed.path == "/api/entries":
            limit = int(parse_qs(parsed.query).get("limit", ["50"])[0])
            self.write_json({"entries": self.logger.recent_entries(limit)})
            return
        if parsed.path.startswith("/api/entry/"):
            sequence = int(parsed.path.rsplit("/", 1)[-1])
            self.write_json(self.logger.decrypt_entry(sequence))
            return
        if parsed.path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            payload = self.read_json()
            if parsed.path == "/api/append":
                self.write_json(self.handle_append(payload))
            elif parsed.path == "/api/ingest":
                self.write_json(self.handle_ingest(payload))
            elif parsed.path == "/api/demo":
                self.write_json(self.handle_demo(payload))
            elif parsed.path == "/api/anchor":
                self.write_json({"anchor": self.logger.anchor_current_head()})
            elif parsed.path == "/api/verify":
                self.write_json(self.logger.verify())
            elif parsed.path == "/api/verify-ledger":
                self.write_json(self.logger.verify_recovery_ledger())
            elif parsed.path == "/api/init-ledger":
                self.write_json(self.logger.initialize_recovery_ledger())
            elif parsed.path == "/api/restore-ledger":
                self.write_json(self.handle_restore_ledger(payload))
            elif parsed.path == "/api/tamper-attempt":
                self.write_json(self.handle_tamper_attempt(payload))
            else:
                self.write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

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
        from demo.traffic_simulator import TrafficGenerator, load_scenario_yaml

        scenario = str(payload.get("scenario", "normal"))
        duration = max(1, min(int(payload.get("duration", 3)), 30))
        output_dir = DEMO_OUTPUT_DIR / scenario
        scenario_config = load_scenario_yaml(scenario)
        TrafficGenerator(scenario_config, duration, output_dir).generate_all_domains()
        count = self.logger.ingest_path(output_dir)
        return {
            "scenario": scenario,
            "duration": duration,
            "output_dir": str(output_dir),
            "ingested_entries": count,
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

    def log_message(self, format: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))


class LoggerDemoServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_class, logger: HashChainLogger):
        super().__init__(server_address, handler_class)
        self.logger = logger


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the BlueBox logger demo web app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    args = parser.parse_args()

    if not STATIC_DIR.exists():
        raise FileNotFoundError(f"static UI directory not found: {STATIC_DIR}")

    server = LoggerDemoServer(
        (args.host, args.port),
        LoggerDemoHandler,
        HashChainLogger(db_path=args.db),
    )
    print(f"BlueBox logger demo: http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
