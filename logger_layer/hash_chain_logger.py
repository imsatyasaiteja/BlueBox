"""SQLite-backed encrypted hash-chain logger for BlueBox raw records."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import shutil
import sqlite3
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Iterator, TypedDict

from backend.shared.paths import (
    PROJECT_ROOT,
    RUNTIME_AI_EVIDENCE_LEDGER_DIR,
    RUNTIME_KEYS_DIR,
    RUNTIME_RECOVERY_LEDGER_DIR,
    RUNTIME_SQLITE_DIR,
)

try:
    from logger_layer.encryption_utils import (
        DEFAULT_DATA_KEY,
        decrypt_payload,
        encrypt_payload,
        load_or_create_data_key,
    )
    from logger_layer.rsa_utils import (
        key_fingerprint,
        load_public_key,
        signer_from_environment,
        verify_digest,
    )
except ModuleNotFoundError:
    from encryption_utils import (  # type: ignore
        DEFAULT_DATA_KEY,
        decrypt_payload,
        encrypt_payload,
        load_or_create_data_key,
    )
    from rsa_utils import (  # type: ignore
        key_fingerprint,
        load_public_key,
        signer_from_environment,
        verify_digest,
    )


GENESIS_HASH = "0" * 64
RECORD_VERSION = 3
DEFAULT_DB = RUNTIME_SQLITE_DIR / "bluebox_log.db"
DEFAULT_RECOVERY_LEDGER = RUNTIME_RECOVERY_LEDGER_DIR / "bluebox_recovery.jsonl"
DEFAULT_AI_EVIDENCE_LEDGER = RUNTIME_AI_EVIDENCE_LEDGER_DIR / "bluebox_ai_evidence.jsonl"
DEFAULT_PRIVATE_KEY = RUNTIME_KEYS_DIR / "logger_private.json"
DEFAULT_PUBLIC_KEY = RUNTIME_KEYS_DIR / "logger_public.json"
DEFAULT_ATTACKER_IP = "203.0.113.45"
PCAP_CHUNK_BYTES = 64 * 1024
SQLITE_BUSY_TIMEOUT_MS = 30_000
SQLITE_BUSY_RETRY_ATTEMPTS = 5
SQLITE_BUSY_RETRY_DELAY_SEC = 0.2
RESERVED_METADATA_KEYS = {
    "record_version",
    "storage",
    "encryption",
    "associated_data_sha256",
    "signer_provider",
}


def source_file_candidates(source_file: str | Path) -> list[str]:
    """Build source path variants used by live ingest and legacy attachments."""
    raw = str(source_file)
    candidates: list[str] = []

    def add(value: str | Path) -> None:
        text = str(value)
        if text and text not in candidates:
            candidates.append(text)

    add(raw)
    if "://" in raw:
        return candidates

    path = Path(raw).expanduser()
    rooted_path = path if path.is_absolute() else PROJECT_ROOT / path
    add(path)
    add(rooted_path)
    add(rooted_path.resolve())
    add(rooted_path.as_posix())
    add(rooted_path.resolve().as_posix())

    try:
        relative_path = rooted_path.resolve().relative_to(PROJECT_ROOT)
        add(relative_path)
        add(relative_path.as_posix())
    except ValueError:
        pass

    return candidates


@dataclass(frozen=True)
class RawEvent:
    source_file: str
    source_type: str
    source_offset: int
    payload: bytes
    metadata: dict[str, object]


class ChainHead(TypedDict):
    sequence: int
    entry_count: int
    head_hash: str


def sanitize_display_text(value: object) -> str:
    return str(value or "").replace("\u00e2\u20ac\u201d", "-").replace("\u2014", "-")


class HashChainLogger:
    def __init__(
        self,
        db_path: Path = DEFAULT_DB,
        private_key_path: Path = DEFAULT_PRIVATE_KEY,
        public_key_path: Path = DEFAULT_PUBLIC_KEY,
        data_key_path: Path = DEFAULT_DATA_KEY,
        anchor_log_path: Path | None = None,
        recovery_ledger_path: Path = DEFAULT_RECOVERY_LEDGER,
        ai_evidence_ledger_path: Path = DEFAULT_AI_EVIDENCE_LEDGER,
        require_tpm: bool = False,
    ) -> None:
        self.db_path = Path(db_path).expanduser().resolve()
        self.private_key_path = Path(private_key_path).expanduser().resolve()
        self.public_key_path = Path(public_key_path).expanduser().resolve()
        self.data_key_path = Path(data_key_path).expanduser().resolve()
        self.recovery_ledger_path = Path(recovery_ledger_path).expanduser().resolve()
        self.ai_evidence_ledger_path = Path(ai_evidence_ledger_path).expanduser().resolve()
        self.anchor_log_path = (
            Path(anchor_log_path).expanduser().resolve()
            if anchor_log_path
            else self.db_path.with_name(f"{self.db_path.name}.anchors.jsonl")
        )
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.anchor_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.recovery_ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.ai_evidence_ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.signer = signer_from_environment(
            self.private_key_path,
            self.public_key_path,
            require_tpm=require_tpm,
        )
        self.key_id = self.signer.key_id
        self.data_key = load_or_create_data_key(self.data_key_path)
        self._explanation_cache: dict[tuple[str, int], dict[str, object] | None] = {}
        self._init_db()
        self.ensure_recovery_ledger_initialized()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
            return conn
        except Exception:
            conn.close()
            raise

    def _connect_without_init(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def _is_sqlite_busy(exc: sqlite3.Error) -> bool:
        message = str(exc).lower()
        return "database is locked" in message or "database is busy" in message

    def _anchor_current_head_with_retry(self) -> dict[str, object] | None:
        delay = SQLITE_BUSY_RETRY_DELAY_SEC
        for attempt in range(SQLITE_BUSY_RETRY_ATTEMPTS):
            try:
                return self.anchor_current_head()
            except sqlite3.OperationalError as exc:
                if not self._is_sqlite_busy(exc) or attempt == SQLITE_BUSY_RETRY_ATTEMPTS - 1:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 2.0)
        return None

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS log_entries (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_offset INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    rsa_key_id TEXT NOT NULL,
                    rsa_signature TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tamper_attempts (
                    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    operation TEXT NOT NULL,
                    target_sequence INTEGER,
                    sqlite_action TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    chain_entry_hash TEXT
                );

                CREATE TABLE IF NOT EXISTS bluebox_correlation_map (
                    source_file TEXT NOT NULL,
                    source_offset INTEGER NOT NULL,
                    sequence INTEGER NOT NULL UNIQUE,
                    entry_hash TEXT NOT NULL UNIQUE,
                    source_type TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (source_file, source_offset, sequence),
                    FOREIGN KEY(sequence) REFERENCES log_entries(sequence)
                );

                CREATE TABLE IF NOT EXISTS ai_evidence_records (
                    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    source_offset INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    entry_hash TEXT NOT NULL,
                    ai_artifact_path TEXT,
                    ai_artifact_row_index INTEGER,
                    ai_result_sha256 TEXT NOT NULL,
                    verdict_json TEXT NOT NULL,
                    model_used TEXT,
                    anomaly_score REAL,
                    predicted_anomaly INTEGER,
                    severity TEXT,
                    FOREIGN KEY(sequence) REFERENCES log_entries(sequence),
                    FOREIGN KEY(entry_hash) REFERENCES log_entries(entry_hash)
                );

                CREATE TABLE IF NOT EXISTS ai_evidence_checkpoints (
                    checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    checkpoint_type TEXT NOT NULL,
                    batch_size INTEGER NOT NULL,
                    first_evidence_id INTEGER NOT NULL,
                    last_evidence_id INTEGER NOT NULL,
                    merkle_root TEXT NOT NULL,
                    leaf_hashes_json TEXT NOT NULL,
                    ledger_hash TEXT NOT NULL UNIQUE,
                    rsa_key_id TEXT NOT NULL,
                    rsa_signature TEXT NOT NULL
                );

                DROP TRIGGER IF EXISTS prevent_log_update;
                DROP TRIGGER IF EXISTS prevent_log_delete;
                DROP TRIGGER IF EXISTS prevent_correlation_update;
                DROP TRIGGER IF EXISTS prevent_correlation_delete;
                DROP TRIGGER IF EXISTS prevent_ai_evidence_update;
                DROP TRIGGER IF EXISTS prevent_ai_evidence_delete;
                DROP TRIGGER IF EXISTS prevent_ai_checkpoint_update;
                DROP TRIGGER IF EXISTS prevent_ai_checkpoint_delete;

                CREATE TRIGGER prevent_log_update
                BEFORE UPDATE ON log_entries
                BEGIN
                    INSERT INTO tamper_attempts (
                        operation, target_sequence, sqlite_action, details_json
                    )
                    VALUES (
                        'update',
                        OLD.sequence,
                        'BEFORE UPDATE ON log_entries',
                        json_object(
                            'old_entry_hash', OLD.entry_hash,
                            'old_source_file', OLD.source_file,
                            'old_source_type', OLD.source_type
                        )
                    );
                    SELECT RAISE(IGNORE);
                END;

                CREATE TRIGGER prevent_log_delete
                BEFORE DELETE ON log_entries
                BEGIN
                    INSERT INTO tamper_attempts (
                        operation, target_sequence, sqlite_action, details_json
                    )
                    VALUES (
                        'delete',
                        OLD.sequence,
                        'BEFORE DELETE ON log_entries',
                        json_object(
                            'old_entry_hash', OLD.entry_hash,
                            'old_source_file', OLD.source_file,
                            'old_source_type', OLD.source_type
                        )
                    );
                    SELECT RAISE(IGNORE);
                END;

                CREATE INDEX IF NOT EXISTS idx_log_entries_source
                ON log_entries(source_file, source_offset);

                CREATE INDEX IF NOT EXISTS idx_correlation_source
                ON bluebox_correlation_map(source_file, source_offset);

                CREATE INDEX IF NOT EXISTS idx_ai_evidence_source
                ON ai_evidence_records(source_file, source_offset);

                CREATE INDEX IF NOT EXISTS idx_ai_evidence_sequence
                ON ai_evidence_records(sequence);

                CREATE INDEX IF NOT EXISTS idx_ai_checkpoint_range
                ON ai_evidence_checkpoints(first_evidence_id, last_evidence_id);
                """
            )
            conn.executescript(
                """
                CREATE TRIGGER prevent_correlation_update
                BEFORE UPDATE ON bluebox_correlation_map
                BEGIN
                    INSERT INTO tamper_attempts (
                        operation, target_sequence, sqlite_action, details_json
                    )
                    VALUES (
                        'update',
                        OLD.sequence,
                        'BEFORE UPDATE ON bluebox_correlation_map',
                        json_object(
                            'table', 'bluebox_correlation_map',
                            'old_source_file', OLD.source_file,
                            'old_source_type', OLD.source_type,
                            'old_source_offset', OLD.source_offset
                        )
                    );
                    SELECT RAISE(IGNORE);
                END;

                CREATE TRIGGER prevent_correlation_delete
                BEFORE DELETE ON bluebox_correlation_map
                BEGIN
                    INSERT INTO tamper_attempts (
                        operation, target_sequence, sqlite_action, details_json
                    )
                    VALUES (
                        'delete',
                        OLD.sequence,
                        'BEFORE DELETE ON bluebox_correlation_map',
                        json_object(
                            'table', 'bluebox_correlation_map',
                            'old_source_file', OLD.source_file,
                            'old_source_type', OLD.source_type,
                            'old_source_offset', OLD.source_offset
                        )
                    );
                    SELECT RAISE(IGNORE);
                END;

                CREATE TRIGGER prevent_ai_evidence_update
                BEFORE UPDATE ON ai_evidence_records
                BEGIN
                    INSERT INTO tamper_attempts (
                        operation, target_sequence, sqlite_action, details_json
                    )
                    VALUES (
                        'update',
                        OLD.sequence,
                        'BEFORE UPDATE ON ai_evidence_records',
                        json_object(
                            'table', 'ai_evidence_records',
                            'evidence_id', OLD.evidence_id,
                            'old_source_file', OLD.source_file,
                            'old_source_offset', OLD.source_offset
                        )
                    );
                    SELECT RAISE(IGNORE);
                END;

                CREATE TRIGGER prevent_ai_evidence_delete
                BEFORE DELETE ON ai_evidence_records
                BEGIN
                    INSERT INTO tamper_attempts (
                        operation, target_sequence, sqlite_action, details_json
                    )
                    VALUES (
                        'delete',
                        OLD.sequence,
                        'BEFORE DELETE ON ai_evidence_records',
                        json_object(
                            'table', 'ai_evidence_records',
                            'evidence_id', OLD.evidence_id,
                            'old_source_file', OLD.source_file,
                            'old_source_offset', OLD.source_offset
                        )
                    );
                    SELECT RAISE(IGNORE);
                END;

                CREATE TRIGGER prevent_ai_checkpoint_update
                BEFORE UPDATE ON ai_evidence_checkpoints
                BEGIN
                    INSERT INTO tamper_attempts (
                        operation, target_sequence, sqlite_action, details_json
                    )
                    VALUES (
                        'update',
                        OLD.last_evidence_id,
                        'BEFORE UPDATE ON ai_evidence_checkpoints',
                        json_object(
                            'table', 'ai_evidence_checkpoints',
                            'checkpoint_id', OLD.checkpoint_id,
                            'checkpoint_type', OLD.checkpoint_type,
                            'first_evidence_id', OLD.first_evidence_id,
                            'last_evidence_id', OLD.last_evidence_id
                        )
                    );
                    SELECT RAISE(IGNORE);
                END;

                CREATE TRIGGER prevent_ai_checkpoint_delete
                BEFORE DELETE ON ai_evidence_checkpoints
                BEGIN
                    INSERT INTO tamper_attempts (
                        operation, target_sequence, sqlite_action, details_json
                    )
                    VALUES (
                        'delete',
                        OLD.last_evidence_id,
                        'BEFORE DELETE ON ai_evidence_checkpoints',
                        json_object(
                            'table', 'ai_evidence_checkpoints',
                            'checkpoint_id', OLD.checkpoint_id,
                            'checkpoint_type', OLD.checkpoint_type,
                            'first_evidence_id', OLD.first_evidence_id,
                            'last_evidence_id', OLD.last_evidence_id
                        )
                    );
                    SELECT RAISE(IGNORE);
                END;
                """
            )
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(log_entries)").fetchall()
            }
            if "entry_material_json" not in columns:
                conn.execute("ALTER TABLE log_entries ADD COLUMN entry_material_json TEXT")
            conn.execute(
                """
                INSERT OR IGNORE INTO bluebox_correlation_map (
                    source_file, source_offset, sequence, entry_hash,
                    source_type, payload_sha256, created_at
                )
                SELECT source_file, source_offset, sequence, entry_hash,
                       source_type, payload_sha256, created_at
                FROM log_entries
                """
            )
            conn.commit()
        finally:
            conn.close()

    def append(self, event: RawEvent) -> str:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            entry_hash = self._append_with_connection(conn, event)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        self._anchor_current_head_with_retry()
        return entry_hash

    def append_json(
        self,
        payload: dict[str, Any],
        source_file: str = "manual",
        source_type: str = "JSON",
        source_offset: int | None = None,
        metadata: dict[str, object] | None = None,
    ) -> str:
        head = self.current_head()
        event = RawEvent(
            source_file=source_file,
            source_type=source_type,
            source_offset=head["sequence"] + 1 if source_offset is None else source_offset,
            payload=canonical_json(payload).encode("utf-8"),
            metadata=metadata or {"ingest_mode": "manual_json"},
        )
        return self.append(event)

    def record_security_event(
        self,
        event_name: str,
        severity: str,
        details: dict[str, object],
    ) -> str:
        return self.append_json(
            {
                "event": event_name,
                "severity": severity,
                "detected_at": datetime.now(UTC).isoformat(),
                "details": details,
            },
            source_file="logger_layer/security_monitor",
            source_type="SECURITY_EVENT",
            metadata={
                "ingest_mode": "security_event",
                "event_name": event_name,
                "severity": severity,
            },
        )

    def sync_tamper_attempts(self, limit: int = 50) -> dict[str, object]:
        verification = self.verify()
        if not verification["ok"]:
            return {
                "synced": 0,
                "skipped": True,
                "reason": "chain verification failed; refusing to append audit events",
                "verification": verification,
            }

        with self._connect() as conn:
            attempts = conn.execute(
                """
                SELECT attempt_id, detected_at, operation, target_sequence,
                       sqlite_action, details_json
                FROM tamper_attempts
                WHERE chain_entry_hash IS NULL
                ORDER BY attempt_id ASC
                LIMIT ?
                """,
                (max(1, min(limit, 500)),),
            ).fetchall()

        synced = []
        for attempt in attempts:
            details = {
                "attempt_id": attempt["attempt_id"],
                "detected_at": attempt["detected_at"],
                "operation": attempt["operation"],
                "target_sequence": attempt["target_sequence"],
                "sqlite_action": attempt["sqlite_action"],
                "trigger_details": json.loads(attempt["details_json"]),
                "blocked_by_sqlite": True,
            }
            entry_hash = self.record_security_event(
                "tamper_attempt_blocked",
                "HIGH",
                details,
            )
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE tamper_attempts
                    SET chain_entry_hash = ?
                    WHERE attempt_id = ?
                    """,
                    (entry_hash, attempt["attempt_id"]),
                )
            synced.append(
                {"attempt_id": attempt["attempt_id"], "chain_entry_hash": entry_hash}
            )

        return {"synced": len(synced), "attempts": synced, "skipped": False}

    def simulate_tamper_attempt(
        self,
        operation: str,
        sequence: int | None = None,
        actor: str = "unknown",
    ) -> dict[str, object]:
        operation = operation.lower().strip()
        if operation not in {"delete", "update"}:
            raise ValueError("operation must be 'delete' or 'update'")

        head_before = self.current_head()
        if head_before["entry_count"] == 0:
            entry_hash = self.record_security_event(
                "tamper_attempt_skipped",
                "LOW",
                {
                    "actor": actor,
                    "operation": operation,
                    "reason": "no log entries exist yet",
                    "head_before": head_before,
                },
            )
            return {
                "blocked": True,
                "logged": True,
                "entry_hash": entry_hash,
                "reason": "no log entries exist yet",
            }

        target_sequence = sequence or head_before["sequence"]
        attempted_sql = (
            "DELETE FROM log_entries WHERE sequence = ?"
            if operation == "delete"
            else "UPDATE log_entries SET source_type = source_type || '_tampered' WHERE sequence = ?"
        )
        sqlite_error = None
        rowcount = 0

        try:
            with self._connect() as conn:
                cursor = conn.execute(attempted_sql, (target_sequence,))
                rowcount = cursor.rowcount
                conn.commit()
        except sqlite3.DatabaseError as exc:
            sqlite_error = str(exc)

        verification_after = self.verify()
        head_after = self.current_head()
        blocked = sqlite_error is not None or rowcount == 0
        chain_intact = bool(verification_after["ok"])
        details = {
            "actor": actor,
            "operation": operation,
            "target_sequence": target_sequence,
            "attempted_sql": attempted_sql,
            "blocked_by_sqlite": blocked,
            "sqlite_error": sqlite_error,
            "rows_changed": rowcount,
            "chain_intact_after_attempt": chain_intact,
            "head_before": head_before,
            "head_after_attempt": head_after,
            "verification_after_attempt": verification_after,
        }

        if chain_intact:
            sync_result = self.sync_tamper_attempts()
            entry_hash = None
            if sync_result.get("synced") == 0:
                entry_hash = self.record_security_event(
                    "tamper_attempt_blocked" if blocked else "tamper_attempt_no_effect",
                    "HIGH" if blocked else "MEDIUM",
                    details,
                )
            return {
                "blocked": blocked,
                "logged": True,
                "entry_hash": entry_hash,
                "sync_result": sync_result,
                "details": details,
                "status": self.integrity_panel(),
            }

        return {
            "blocked": False,
            "logged": False,
            "details": details,
            "status": self.integrity_panel(),
            "warning": (
                "The chain is no longer trustworthy. Do not append recovery events "
                "to this database; preserve the DB and anchor file as incident evidence."
            ),
        }

    def force_corrupt_sqlite_for_demo(
        self,
        operation: str,
        sequence: int | None = None,
        actor: str = "attacker-cli",
    ) -> dict[str, object]:
        """Deliberately bypass SQLite protections for a recovery-ledger demo."""
        operation = operation.lower().strip()
        if operation not in {"delete", "update"}:
            raise ValueError("operation must be 'delete' or 'update'")

        head_before = self.current_head()
        if head_before["entry_count"] == 0:
            return {
                "forced": False,
                "operation": operation,
                "actor": actor,
                "reason": "no log entries exist yet",
                "head_before": head_before,
            }

        if sequence is not None:
            target_sequence = sequence
        elif operation == "delete" and head_before["entry_count"] > 1:
            target_sequence = max(1, int(head_before["sequence"]) // 2)
        else:
            target_sequence = head_before["sequence"]
        with self._connect_without_init() as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            target_row = conn.execute(
                """
                SELECT sequence, entry_hash, source_file, source_type
                FROM log_entries
                WHERE sequence = ?
                """,
                (target_sequence,),
            ).fetchone()
            if target_row is None:
                raise ValueError(f"no log entry exists at sequence {target_sequence}")

            conn.executescript(
                """
                DROP TRIGGER IF EXISTS prevent_log_update;
                DROP TRIGGER IF EXISTS prevent_log_delete;
                """
            )
            if operation == "delete":
                cursor = conn.execute(
                    "DELETE FROM log_entries WHERE sequence = ?",
                    (target_sequence,),
                )
                corrupted_field = "row_deleted"
            else:
                cursor = conn.execute(
                    """
                    UPDATE log_entries
                    SET payload_sha256 = ?
                    WHERE sequence = ?
                    """,
                    ("0" * 64, target_sequence),
                )
                corrupted_field = "payload_sha256"
            rows_changed = cursor.rowcount
            conn.commit()

        verification_after = self.verify()
        ledger_after = self.verify_recovery_ledger()
        return {
            "forced": True,
            "operation": operation,
            "actor": actor,
            "target_sequence": target_sequence,
            "target_entry_hash": target_row["entry_hash"],
            "target_source_file": target_row["source_file"],
            "target_source_type": target_row["source_type"],
            "rows_changed": rows_changed,
            "corrupted_field": corrupted_field,
            "head_before": head_before,
            "head_after": self.current_head(),
            "verification_after": verification_after,
            "recovery_ledger_after": ledger_after,
            "warning": (
                "This command deliberately bypasses append-only protections for a "
                "controlled recovery-ledger demonstration. Run verify to show the "
                "broken chain, then restore-ledger to rebuild SQLite from the signed "
                "recovery ledger."
            ),
        }

    def append_many(self, events: Iterable[RawEvent]) -> int:
        count = 0
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            for event in events:
                self._append_with_connection(conn, event)
                count += 1
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        if count:
            self._anchor_current_head_with_retry()
        return count

    def append_many_with_ai_evidence(
        self,
        items: Iterable[
            tuple[RawEvent, dict[str, Any], str | Path | None, int | None]
        ],
    ) -> list[int]:
        evidence_ids: list[int] = []
        appended = 0
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            for event, verdict, ai_artifact_path, ai_artifact_row_index in items:
                self._append_with_connection(conn, event)
                appended += 1
                mapping = conn.execute(
                    """
                    SELECT source_file, source_offset, sequence, entry_hash,
                           source_type, payload_sha256, created_at
                    FROM bluebox_correlation_map
                    WHERE source_file = ? AND source_offset = ?
                    ORDER BY sequence DESC
                    LIMIT 1
                    """,
                    (str(event.source_file), int(event.source_offset)),
                ).fetchone()
                if mapping is None:
                    raise RuntimeError(
                        f"no logged row for {event.source_file}:{event.source_offset}"
                    )
                evidence = self._insert_ai_evidence_with_connection(
                    conn,
                    mapping,
                    verdict,
                    ai_artifact_path=ai_artifact_path,
                    ai_artifact_row_index=ai_artifact_row_index,
                )
                evidence_ids.append(int(evidence["evidence_id"]))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        if appended:
            self._anchor_current_head_with_retry()
        return evidence_ids

    def ingest_path(self, path: Path) -> int:
        return self.append_many(events_from_path(path))

    def _append_with_connection(self, conn: sqlite3.Connection, event: RawEvent) -> str:
        created_at = datetime.now(UTC).isoformat()
        associated_data = build_associated_data(
            event.source_file,
            event.source_type,
            event.source_offset,
            event.metadata,
        )
        encrypted = encrypt_payload(event.payload, associated_data, self.data_key)
        metadata = {
            **event.metadata,
            "record_version": RECORD_VERSION,
            "storage": "encrypted",
            "encryption": encrypted.metadata,
            "associated_data_sha256": sha256(associated_data).hexdigest(),
            "signer_provider": self.signer.provider,
        }
        metadata_json = canonical_json(metadata)
        payload_hash = sha256(encrypted.ciphertext).hexdigest()
        previous_hash = self._latest_hash(conn)
        entry_material = build_entry_material(
            previous_hash=previous_hash,
            payload_hash=payload_hash,
            metadata=json.loads(metadata_json),
            source_file=event.source_file,
            source_type=event.source_type,
            source_offset=event.source_offset,
            created_at=created_at,
            rsa_key_id=self.key_id,
        )
        entry_material_json = canonical_json(entry_material)
        entry_hash = sha256(entry_material_json.encode("utf-8")).hexdigest()
        signature = self.signer.sign_digest(entry_hash)
        conn.execute(
            """
            INSERT INTO log_entries (
                created_at, source_file, source_type, source_offset,
                metadata_json, payload, payload_sha256, previous_hash,
                entry_hash, rsa_key_id, rsa_signature, entry_material_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                event.source_file,
                event.source_type,
                event.source_offset,
                metadata_json,
                encrypted.ciphertext,
                payload_hash,
                previous_hash,
                entry_hash,
                self.key_id,
                signature,
                entry_material_json,
            ),
        )
        row = conn.execute(
            """
            SELECT sequence, created_at, source_file, source_type, source_offset,
                   metadata_json, payload, payload_sha256, previous_hash,
                   entry_hash, rsa_key_id, rsa_signature, entry_material_json
            FROM log_entries
            WHERE entry_hash = ?
            """,
            (entry_hash,),
        ).fetchone()
        self._insert_correlation_mapping(conn, row)
        self.append_recovery_record(row)
        return entry_hash

    def _insert_correlation_mapping(
        self, conn: sqlite3.Connection, row: sqlite3.Row | None
    ) -> None:
        if row is None:
            raise RuntimeError("cannot map missing DB row")
        conn.execute(
            """
            INSERT INTO bluebox_correlation_map (
                source_file, source_offset, sequence, entry_hash,
                source_type, payload_sha256, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(row["source_file"]),
                int(row["source_offset"]),
                int(row["sequence"]),
                str(row["entry_hash"]),
                str(row["source_type"]),
                str(row["payload_sha256"]),
                str(row["created_at"]),
            ),
        )

    def lookup_correlation(
        self, source_file: str | Path, source_offset: int, latest: bool = True
    ) -> dict[str, object] | None:
        order = "DESC" if latest else "ASC"
        conn = self._connect()
        try:
            row = conn.execute(
                f"""
                SELECT source_file, source_offset, sequence, entry_hash,
                       source_type, payload_sha256, created_at
                FROM bluebox_correlation_map
                WHERE source_file = ? AND source_offset = ?
                ORDER BY sequence {order}
                LIMIT 1
                """,
                (str(source_file), int(source_offset)),
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def _insert_ai_evidence_with_connection(
        self,
        conn: sqlite3.Connection,
        mapping: sqlite3.Row | dict[str, object],
        verdict: dict[str, Any],
        ai_artifact_path: str | Path | None = None,
        ai_artifact_row_index: int | None = None,
    ) -> dict[str, object]:
        recorded_at = datetime.now(UTC).isoformat()
        verdict_json = canonical_json(verdict)
        ai_result_sha256 = sha256(verdict_json.encode("utf-8")).hexdigest()
        cursor = conn.execute(
            """
            INSERT INTO ai_evidence_records (
                recorded_at, source_file, source_offset, sequence, entry_hash,
                ai_artifact_path, ai_artifact_row_index, ai_result_sha256,
                verdict_json, model_used, anomaly_score, predicted_anomaly,
                severity
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                recorded_at,
                str(mapping["source_file"]),
                int(mapping["source_offset"]),
                int(mapping["sequence"]),
                str(mapping["entry_hash"]),
                str(ai_artifact_path) if ai_artifact_path is not None else None,
                int(ai_artifact_row_index) if ai_artifact_row_index is not None else None,
                ai_result_sha256,
                verdict_json,
                str(verdict.get("model_used", "")) or None,
                float(verdict["anomaly_score"]) if "anomaly_score" in verdict else None,
                int(verdict["predicted_anomaly"]) if "predicted_anomaly" in verdict else None,
                str(verdict.get("severity", "")) or None,
            ),
        )
        evidence_id = int(cursor.lastrowid)
        return {
            "evidence_id": evidence_id,
            "sequence": mapping["sequence"],
            "entry_hash": mapping["entry_hash"],
            "ai_result_sha256": ai_result_sha256,
        }

    def attach_ai_evidence(
        self,
        source_file: str | Path,
        source_offset: int,
        verdict: dict[str, Any],
        ai_artifact_path: str | Path | None = None,
        ai_artifact_row_index: int | None = None,
    ) -> dict[str, object]:
        mapping = self.lookup_correlation(source_file, source_offset)
        if mapping is None:
            raise KeyError(f"no logged row for {source_file}:{source_offset}")

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            evidence = self._insert_ai_evidence_with_connection(
                conn,
                mapping,
                verdict,
                ai_artifact_path=ai_artifact_path,
                ai_artifact_row_index=ai_artifact_row_index,
            )
            conn.commit()
            return evidence
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def attach_ai_evidence_from_csv(
        self,
        source_csv: str | Path,
        scored_csv: str | Path,
        include_shap: bool = False,
    ) -> dict[str, object]:
        source_candidates = source_file_candidates(source_csv)
        source_path = source_candidates[0]
        scored_path = Path(scored_csv)
        attached = 0
        missing = 0
        evidence_ids: list[int] = []
        explain_event = None
        event_from_record = None
        if include_shap:
            from backend.explainability.shap_explainer import explain_event as _explain_event
            from demo.traffic_simulator import event_from_record as _event_from_record

            explain_event = _explain_event
            event_from_record = _event_from_record
        with scored_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row_index, row in enumerate(reader):
                verdict = {
                    key: row[key]
                    for key in (
                        "anomaly_score",
                        "predicted_anomaly",
                        "severity",
                        "model_used",
                    )
                    if key in row
                }
                if not verdict:
                    continue
                if row.get("timestamp"):
                    verdict["occurred_at"] = row["timestamp"]
                for key in (
                    "data_format",
                    "domain",
                    "protocol",
                    "src",
                    "dst",
                    "src_ip",
                    "dst_ip",
                    "label_octal",
                    "anomaly_type",
                    "port",
                    "dst_port",
                ):
                    if row.get(key):
                        verdict[key] = row[key]
                predicted = int(verdict.get("predicted_anomaly", 0))
                if include_shap and predicted and explain_event and event_from_record:
                    explanation = explain_event(event_from_record(row))
                    verdict.update(
                        {
                            "shap_top_features": explanation["top_features"],
                            "explanation_text": explanation["explanation_text"],
                        }
                    )
                evidence = None
                for candidate in source_candidates:
                    try:
                        evidence = self.attach_ai_evidence(
                            candidate,
                            row_index,
                            verdict,
                            ai_artifact_path=scored_path,
                            ai_artifact_row_index=row_index,
                        )
                        break
                    except KeyError:
                        continue
                if evidence is None:
                    missing += 1
                    continue
                evidence_ids.append(int(evidence["evidence_id"]))
                attached += 1
        checkpoint = self.create_ai_evidence_checkpoint(evidence_ids) if evidence_ids else None
        return {
            "source_file": source_path,
            "scored_csv": str(scored_path),
            "attached": attached,
            "missing_mappings": missing,
            "checkpoint": checkpoint,
        }

    def _explain_scored_ai_row(
        self,
        artifact_path: str | Path | None,
        artifact_row_index: int | None,
    ) -> dict[str, object] | None:
        if artifact_path in (None, "") or artifact_row_index is None:
            return None
        cache_key = (str(artifact_path), int(artifact_row_index))
        if cache_key in self._explanation_cache:
            return self._explanation_cache[cache_key]
        path = Path(str(artifact_path))
        if not path.is_absolute():
            rooted_path = Path(__file__).resolve().parents[1] / path
            path = rooted_path if rooted_path.exists() else path
        if not path.exists():
            return None
        try:
            from backend.explainability.shap_explainer import explain_event
            from demo.traffic_simulator import event_from_record

            with path.open("r", newline="", encoding="utf-8") as handle:
                for row_index, row in enumerate(csv.DictReader(handle)):
                    if row_index == int(artifact_row_index):
                        explanation = explain_event(event_from_record(row))
                        self._explanation_cache[cache_key] = explanation
                        return explanation
        except Exception:
            return None
        return None

    def _load_scored_artifact_row(
        self,
        artifact_path: str | Path | None,
        artifact_row_index: int | None,
    ) -> dict[str, str]:
        if artifact_path in (None, "") or artifact_row_index is None:
            return {}
        path = Path(str(artifact_path))
        if not path.is_absolute():
            rooted_path = Path(__file__).resolve().parents[1] / path
            path = rooted_path if rooted_path.exists() else path
        if not path.exists():
            return {}
        try:
            with path.open("r", newline="", encoding="utf-8") as handle:
                for row_index, row in enumerate(csv.DictReader(handle)):
                    if row_index == int(artifact_row_index):
                        return dict(row)
        except Exception:
            return {}
        return {}

    def _component_pair_from_record(
        self,
        record: dict[str, str],
        fallback_source: str,
    ) -> tuple[str, str, str]:
        data_format = str(record.get("data_format") or "LOG").upper()
        source = (
            record.get("src")
            or record.get("src_ip")
            or record.get("source_ip")
            or record.get("source_component")
        )
        target = (
            record.get("dst")
            or record.get("dst_ip")
            or record.get("destination_ip")
            or record.get("target_component")
        )
        service = str(
            record.get("protocol")
            or record.get("service")
            or record.get("port")
            or record.get("dst_port")
            or data_format
        )
        if data_format == "PCAP":
            return source or "unknown source", target or "unknown target", service
        if data_format == "ARINC429":
            label = record.get("label_octal") or record.get("src") or "unknown label"
            return "ARINC 429 bus", f"label {label}", "avionics word"
        if source or target:
            return source or Path(fallback_source).stem or "unknown source", target or "unknown target", service
        return Path(fallback_source).stem or "log source", "BlueBox evidence", data_format

    def _event_summary(
        self,
        record: dict[str, str],
        severity: str,
        explanation: str,
    ) -> str:
        data_format = record.get("data_format") or "LOG"
        if explanation:
            return explanation
        if data_format == "PCAP":
            return "Network behavior departed from the trained aircraft-domain baseline."
        if data_format == "ARINC429":
            return "ARINC 429 word behavior departed from the trained avionics baseline."
        return f"{severity or 'Anomalous'} evidence requires maintenance review."

    def _build_attack_graph(self, events: list[dict[str, object]]) -> dict[str, object]:
        nodes: dict[str, dict[str, object]] = {}
        edges: list[dict[str, object]] = []

        def add_node(
            node_id: str,
            label: str,
            kind: str,
            risk: float | None = None,
            summary: str = "",
        ) -> None:
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "label": label,
                    "kind": kind,
                    "risk": risk,
                    "summary": summary,
                }

        ordered = sorted(events, key=lambda item: str(item.get("occurred_at") or ""))
        previous_event_id: str | None = None
        for index, event in enumerate(ordered, start=1):
            event_id = f"event-{event['sequence']}"
            source_id = f"source-{event.get('source_component', 'unknown')}"
            target_id = f"target-{event.get('target_component', 'unknown')}"
            add_node(
                source_id,
                str(event.get("source_component", "source")),
                "source",
            )
            add_node(
                target_id,
                str(event.get("target_component", "target")),
                "target",
            )
            add_node(
                event_id,
                f"#{index} {event.get('severity', 'ANOMALY')}",
                "anomaly",
                risk=float(event.get("anomaly_score") or 0),
                summary=str(event.get("summary", "")),
            )
            edges.append(
                {
                    "source": source_id,
                    "target": event_id,
                    "label": str(event.get("service", "observed")),
                }
            )
            edges.append(
                {
                    "source": event_id,
                    "target": target_id,
                    "label": "affected",
                }
            )
            if previous_event_id is not None:
                edges.append(
                    {
                        "source": previous_event_id,
                        "target": event_id,
                        "label": "then",
                        "temporal": True,
                    }
                )
            previous_event_id = event_id

        layout_engine = "python deterministic layout"
        try:
            import networkx as nx  # type: ignore

            graph = nx.DiGraph()
            graph.add_nodes_from(nodes.keys())
            graph.add_edges_from((edge["source"], edge["target"]) for edge in edges)
            positions = nx.spring_layout(graph, seed=7)
            layout_engine = "networkx.spring_layout"
            for node_id, node in nodes.items():
                x, y = positions[node_id]
                node["x"] = 0.5 + float(x) * 0.42
                node["y"] = 0.5 + float(y) * 0.38
        except Exception:
            grouped = {
                "source": [node for node in nodes.values() if node["kind"] == "source"],
                "anomaly": [node for node in nodes.values() if node["kind"] == "anomaly"],
                "target": [node for node in nodes.values() if node["kind"] == "target"],
            }
            columns = {"source": 0.16, "anomaly": 0.50, "target": 0.84}
            for kind, group in grouped.items():
                for index, node in enumerate(group):
                    node["x"] = columns[kind]
                    node["y"] = (index + 1) / (len(group) + 1)

        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "layout_engine": layout_engine,
            "top_event_count": len(events),
        }

    def verify(
        self,
        public_key_path: Path | None = None,
        verify_payload_auth: bool = True,
    ) -> dict[str, object]:
        public_key_value = load_public_key(public_key_path or self.public_key_path)
        expected_key_id = key_fingerprint(public_key_value)
        expected_previous = GENESIS_HASH
        checked = 0
        first_failure: dict[str, object] | None = None

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT sequence, created_at, source_file, source_type, source_offset,
                       metadata_json, payload, payload_sha256, previous_hash,
                       entry_hash, rsa_key_id, rsa_signature, entry_material_json
                FROM log_entries
                ORDER BY sequence ASC
                """
            )
            for row in rows:
                checked += 1
                failure = self._verify_row(
                    row,
                    public_key_value,
                    expected_key_id,
                    expected_previous,
                    verify_payload_auth,
                )
                if failure is not None:
                    first_failure = failure
                    break
                expected_previous = str(row["entry_hash"])

        anchor_verification = self.verify_anchor_log(public_key_value)
        if checked == 0 and anchor_verification["status"] == "missing":
            anchor_verification = {
                **anchor_verification,
                "ok": True,
                "status": "not_created",
                "reason": "no entries have been logged yet",
            }
        if first_failure is None and checked > 0 and not anchor_verification["ok"]:
            first_failure = {
                "sequence": None,
                "anchor_valid": False,
                "reason": anchor_verification["reason"],
            }

        return {
            "ok": first_failure is None,
            "checked_entries": checked,
            "head_hash": expected_previous if first_failure is None else None,
            "first_failure": first_failure,
            "anchor": anchor_verification,
            "recovery_ledger": self.verify_recovery_ledger(public_key_value),
        }

    def _verify_row(
        self,
        row: sqlite3.Row,
        public_key_value: Any,
        expected_key_id: str,
        expected_previous: str,
        verify_payload_auth: bool,
    ) -> dict[str, object] | None:
        metadata = json.loads(row["metadata_json"])
        payload_hash = sha256(row["payload"]).hexdigest()
        entry_material_json = row["entry_material_json"]
        if entry_material_json:
            expected_material = build_entry_material(
                previous_hash=row["previous_hash"],
                payload_hash=payload_hash,
                metadata=metadata,
                source_file=row["source_file"],
                source_type=row["source_type"],
                source_offset=row["source_offset"],
                created_at=row["created_at"],
                rsa_key_id=row["rsa_key_id"],
            )
            material_matches = entry_material_json == canonical_json(expected_material)
            recomputed_entry_hash = sha256(
                canonical_json(expected_material).encode("utf-8")
            ).hexdigest()
        else:
            material_matches = True
            recomputed_entry_hash = compute_legacy_entry_hash(
                row["previous_hash"], payload_hash, row["metadata_json"]
            )

        payload_auth_valid = True
        if verify_payload_auth and metadata.get("storage") == "encrypted":
            payload_auth_valid = self._verify_encrypted_payload_auth(
                row["payload"],
                metadata,
                row["source_file"],
                row["source_type"],
                row["source_offset"],
            )

        checks = {
            "previous_hash_matches": row["previous_hash"] == expected_previous,
            "payload_hash_matches": row["payload_sha256"] == payload_hash,
            "entry_material_matches": material_matches,
            "entry_hash_matches": row["entry_hash"] == recomputed_entry_hash,
            "rsa_key_id_matches": row["rsa_key_id"] == expected_key_id,
            "rsa_signature_valid": verify_digest(
                public_key_value, row["entry_hash"], row["rsa_signature"]
            ),
            "payload_auth_valid": payload_auth_valid,
        }
        if all(checks.values()):
            return None
        return {
            "sequence": row["sequence"],
            "expected_previous_hash": expected_previous,
            "stored_previous_hash": row["previous_hash"],
            **checks,
        }

    def _verify_encrypted_payload_auth(
        self,
        payload: bytes,
        metadata: dict[str, object],
        source_file: str,
        source_type: str,
        source_offset: int,
    ) -> bool:
        try:
            encryption = metadata["encryption"]
            if not isinstance(encryption, dict):
                return False
            associated_data = build_associated_data(
                source_file,
                source_type,
                source_offset,
                base_event_metadata(metadata),
            )
            decrypt_payload(payload, associated_data, self.data_key, encryption)
            return True
        except Exception:
            return False

    def anchor_current_head(self) -> dict[str, object] | None:
        head = self.current_head()
        if head["entry_count"] == 0:
            return None
        previous_anchor_hash = self._latest_anchor_hash()
        anchor_material = {
            "version": 2,
            "created_at": datetime.now(UTC).isoformat(),
            "db_path": str(self.db_path),
            "sequence": head["sequence"],
            "entry_count": head["entry_count"],
            "head_hash": head["head_hash"],
            "recovery_ledger_path": str(self.recovery_ledger_path),
            "recovery_ledger_hash": self._latest_recovery_ledger_hash(),
            "previous_anchor_hash": previous_anchor_hash,
            "rsa_key_id": self.key_id,
            "signer_provider": self.signer.provider,
        }
        anchor_hash = sha256(canonical_json(anchor_material).encode("utf-8")).hexdigest()
        anchor_record = {
            **anchor_material,
            "anchor_hash": anchor_hash,
            "rsa_signature": self.signer.sign_digest(anchor_hash),
        }
        with self.anchor_log_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(anchor_record) + "\n")
        return anchor_record

    def append_recovery_record(self, row: sqlite3.Row | None) -> dict[str, object]:
        if row is None:
            raise RuntimeError("cannot append recovery record for missing DB row")
        previous_ledger_hash = self._latest_recovery_ledger_hash()
        row_record = row_to_recovery_payload(row)
        material = {
            "version": 1,
            "recorded_at": datetime.now(UTC).isoformat(),
            "db_path": str(self.db_path),
            "previous_ledger_hash": previous_ledger_hash,
            "row": row_record,
        }
        ledger_hash = sha256(canonical_json(material).encode("utf-8")).hexdigest()
        ledger_record = {
            **material,
            "ledger_hash": ledger_hash,
            "rsa_key_id": self.key_id,
            "rsa_signature": self.signer.sign_digest(ledger_hash),
        }
        with self.recovery_ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(ledger_record) + "\n")
        return ledger_record

    def create_ai_evidence_checkpoint(
        self, evidence_ids: list[int], checkpoint_type: str = "ai_evidence_batch"
    ) -> dict[str, object]:
        if not evidence_ids:
            raise ValueError("evidence_ids must not be empty")
        ordered_ids = sorted(set(int(value) for value in evidence_ids))
        placeholders = ",".join("?" for _ in ordered_ids)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                f"""
                SELECT evidence_id, recorded_at, source_file, source_offset,
                       sequence, entry_hash, ai_artifact_path,
                       ai_artifact_row_index, ai_result_sha256, verdict_json,
                       model_used, anomaly_score, predicted_anomaly, severity
                FROM ai_evidence_records
                WHERE evidence_id IN ({placeholders})
                ORDER BY evidence_id ASC
                """,
                ordered_ids,
            ).fetchall()
            if len(rows) != len(ordered_ids):
                raise RuntimeError("cannot checkpoint missing AI evidence rows")
            leaf_hashes = [ai_evidence_leaf_hash(row) for row in rows]
            merkle_root = merkle_root_from_leaves(leaf_hashes)
            previous_ledger_hash = self._latest_ai_evidence_ledger_hash()
            created_at = datetime.now(UTC).isoformat()
            material = {
                "version": 1,
                "created_at": created_at,
                "checkpoint_type": checkpoint_type,
                "db_path": str(self.db_path),
                "previous_ledger_hash": previous_ledger_hash,
                "batch_size": len(rows),
                "first_evidence_id": int(rows[0]["evidence_id"]),
                "last_evidence_id": int(rows[-1]["evidence_id"]),
                "merkle_root": merkle_root,
                "leaf_hashes": leaf_hashes,
            }
            ledger_hash = sha256(canonical_json(material).encode("utf-8")).hexdigest()
            signature = self.signer.sign_digest(ledger_hash)
            checkpoint_record = {
                **material,
                "ledger_hash": ledger_hash,
                "rsa_key_id": self.key_id,
                "rsa_signature": signature,
            }
            conn.execute(
                """
                INSERT INTO ai_evidence_checkpoints (
                    created_at, checkpoint_type, batch_size,
                    first_evidence_id, last_evidence_id, merkle_root,
                    leaf_hashes_json, ledger_hash, rsa_key_id, rsa_signature
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    checkpoint_type,
                    len(rows),
                    int(rows[0]["evidence_id"]),
                    int(rows[-1]["evidence_id"]),
                    merkle_root,
                    canonical_json({"leaf_hashes": leaf_hashes}),
                    ledger_hash,
                    self.key_id,
                    signature,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        with self.ai_evidence_ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(checkpoint_record) + "\n")
        return {
            "checkpoint_type": checkpoint_type,
            "batch_size": len(rows),
            "first_evidence_id": int(rows[0]["evidence_id"]),
            "last_evidence_id": int(rows[-1]["evidence_id"]),
            "merkle_root": merkle_root,
            "ledger_hash": ledger_hash,
        }

    def append_ai_evidence_ledger_record(self, row: sqlite3.Row | None) -> dict[str, object]:
        if row is None:
            raise RuntimeError("cannot append AI evidence record for missing DB row")
        return self.create_ai_evidence_checkpoint([int(row["evidence_id"])])

    def _legacy_append_ai_evidence_ledger_record(
        self, row: sqlite3.Row | None
    ) -> dict[str, object]:
        if row is None:
            raise RuntimeError("cannot append AI evidence record for missing DB row")
        previous_ledger_hash = self._latest_ai_evidence_ledger_hash()
        reference = {
            "evidence_id": int(row["evidence_id"]),
            "recorded_at": str(row["recorded_at"]),
            "source_file": str(row["source_file"]),
            "source_offset": int(row["source_offset"]),
            "sequence": int(row["sequence"]),
            "entry_hash": str(row["entry_hash"]),
            "ai_artifact_path": row["ai_artifact_path"],
            "ai_artifact_row_index": row["ai_artifact_row_index"],
            "ai_result_sha256": str(row["ai_result_sha256"]),
            "model_used": row["model_used"],
            "anomaly_score": row["anomaly_score"],
            "predicted_anomaly": row["predicted_anomaly"],
            "severity": row["severity"],
        }
        material = {
            "version": 1,
            "recorded_at": datetime.now(UTC).isoformat(),
            "db_path": str(self.db_path),
            "previous_ledger_hash": previous_ledger_hash,
            "reference": reference,
        }
        ledger_hash = sha256(canonical_json(material).encode("utf-8")).hexdigest()
        ledger_record = {
            **material,
            "ledger_hash": ledger_hash,
            "rsa_key_id": self.key_id,
            "rsa_signature": self.signer.sign_digest(ledger_hash),
        }
        with self.ai_evidence_ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(ledger_record) + "\n")
        return ledger_record

    def verify_ai_evidence_ledger(
        self, public_key_value: Any | None = None
    ) -> dict[str, object]:
        if public_key_value is None:
            public_key_value = load_public_key(self.public_key_path)
        if not self.ai_evidence_ledger_path.exists():
            return {
                "ok": True,
                "status": "missing",
                "reason": "no AI evidence ledger has been created yet",
                "path": str(self.ai_evidence_ledger_path),
                "records_checked": 0,
            }

        expected_previous = GENESIS_HASH
        latest: dict[str, object] | None = None
        records_checked = 0
        with self.ai_evidence_ledger_path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                records_checked += 1
                record = json.loads(line)
                failure = verify_ai_evidence_ledger_record(
                    record, public_key_value, expected_previous
                )
                if failure:
                    return {
                        "ok": False,
                        "status": "failed",
                        "reason": failure,
                        "path": str(self.ai_evidence_ledger_path),
                        "line": line_no,
                        "records_checked": records_checked,
                    }
                expected_previous = str(record["ledger_hash"])
                latest = record

        if latest is None:
            return {
                "ok": True,
                "status": "empty",
                "path": str(self.ai_evidence_ledger_path),
                "records_checked": 0,
            }
        return {
            "ok": True,
            "status": "verified",
            "path": str(self.ai_evidence_ledger_path),
            "records_checked": records_checked,
            "ledger_hash": latest["ledger_hash"],
            "db_checkpoints": self.verify_ai_evidence_checkpoints(public_key_value),
        }

    def verify_ai_evidence_checkpoints(
        self, public_key_value: Any | None = None
    ) -> dict[str, object]:
        if public_key_value is None:
            public_key_value = load_public_key(self.public_key_path)
        checked = 0
        with self._connect() as conn:
            checkpoints = conn.execute(
                """
                SELECT checkpoint_id, created_at, checkpoint_type, batch_size,
                       first_evidence_id, last_evidence_id, merkle_root,
                       leaf_hashes_json, ledger_hash, rsa_key_id, rsa_signature
                FROM ai_evidence_checkpoints
                ORDER BY checkpoint_id ASC
                """
            ).fetchall()
            for checkpoint in checkpoints:
                checked += 1
                rows = conn.execute(
                    """
                    SELECT evidence_id, recorded_at, source_file, source_offset,
                           sequence, entry_hash, ai_artifact_path,
                           ai_artifact_row_index, ai_result_sha256, verdict_json,
                           model_used, anomaly_score, predicted_anomaly, severity
                    FROM ai_evidence_records
                    WHERE evidence_id BETWEEN ? AND ?
                    ORDER BY evidence_id ASC
                    """,
                    (
                        int(checkpoint["first_evidence_id"]),
                        int(checkpoint["last_evidence_id"]),
                    ),
                ).fetchall()
                leaf_hashes = [ai_evidence_leaf_hash(row) for row in rows]
                stored_leaf_hashes = json.loads(checkpoint["leaf_hashes_json"])["leaf_hashes"]
                material = {
                    "version": 1,
                    "created_at": checkpoint["created_at"],
                    "checkpoint_type": checkpoint["checkpoint_type"],
                    "db_path": str(self.db_path),
                    "previous_ledger_hash": checkpoint_previous_hash(
                        self.ai_evidence_ledger_path,
                        str(checkpoint["ledger_hash"]),
                    ),
                    "batch_size": int(checkpoint["batch_size"]),
                    "first_evidence_id": int(checkpoint["first_evidence_id"]),
                    "last_evidence_id": int(checkpoint["last_evidence_id"]),
                    "merkle_root": checkpoint["merkle_root"],
                    "leaf_hashes": stored_leaf_hashes,
                }
                recomputed_ledger_hash = sha256(
                    canonical_json(material).encode("utf-8")
                ).hexdigest()
                checks = {
                    "batch_size_matches": int(checkpoint["batch_size"]) == len(rows),
                    "leaf_hashes_match": stored_leaf_hashes == leaf_hashes,
                    "merkle_root_matches": checkpoint["merkle_root"]
                    == merkle_root_from_leaves(leaf_hashes),
                    "ledger_hash_matches": checkpoint["ledger_hash"] == recomputed_ledger_hash,
                    "rsa_signature_valid": verify_digest(
                        public_key_value,
                        str(checkpoint["ledger_hash"]),
                        str(checkpoint["rsa_signature"]),
                    ),
                }
                if not all(checks.values()):
                    return {
                        "ok": False,
                        "status": "failed",
                        "checkpoint_id": checkpoint["checkpoint_id"],
                        **checks,
                    }
        return {"ok": True, "status": "verified", "checkpoints_checked": checked}

    def verify_recovery_ledger(self, public_key_value: Any | None = None) -> dict[str, object]:
        if public_key_value is None:
            public_key_value = load_public_key(self.public_key_path)
        if not self.recovery_ledger_path.exists():
            return {
                "ok": False,
                "status": "missing",
                "reason": "recovery ledger does not exist",
                "path": str(self.recovery_ledger_path),
                "records_checked": 0,
            }

        expected_previous = GENESIS_HASH
        latest: dict[str, object] | None = None
        records_checked = 0
        with self.recovery_ledger_path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                records_checked += 1
                record = json.loads(line)
                failure = verify_recovery_record(record, public_key_value, expected_previous)
                if failure:
                    return {
                        "ok": False,
                        "status": "failed",
                        "reason": failure,
                        "path": str(self.recovery_ledger_path),
                        "line": line_no,
                        "records_checked": records_checked,
                    }
                expected_previous = str(record["ledger_hash"])
                latest = record

        if latest is None:
            return {
                "ok": False,
                "status": "missing",
                "reason": "recovery ledger is empty",
                "path": str(self.recovery_ledger_path),
                "records_checked": 0,
            }

        head = self.current_head()
        ledger_head = recovery_record_head(latest)
        head_matches = (
            head["sequence"] == ledger_head["sequence"]
            and head["entry_count"] == ledger_head["entry_count"]
            and head["head_hash"] == ledger_head["head_hash"]
        )
        return {
            "ok": True,
            "status": "verified" if head_matches else "verified_db_mismatch",
            "path": str(self.recovery_ledger_path),
            "records_checked": records_checked,
            "ledger_hash": latest["ledger_hash"],
            "ledger_head": ledger_head,
            "db_head_matches_ledger": head_matches,
        }

    def restore_from_recovery_ledger(
        self,
        reason: str = "operator_requested_restore",
        actor: str = "analyst",
    ) -> dict[str, object]:
        public_key_value = load_public_key(self.public_key_path)
        ledger_status = self.verify_recovery_ledger(public_key_value)
        if not ledger_status["ok"]:
            raise RuntimeError(f"recovery ledger is not trustworthy: {ledger_status['reason']}")

        records = self.load_latest_recovery_chain(public_key_value)
        if not records:
            raise RuntimeError("recovery ledger contains no records")

        pre_restore_verification = self.verify()
        backup_paths = self.backup_current_database_files()

        with self._connect() as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.executescript(
                """
                DROP TRIGGER IF EXISTS prevent_log_update;
                DROP TRIGGER IF EXISTS prevent_log_delete;
                DROP TRIGGER IF EXISTS prevent_correlation_update;
                DROP TRIGGER IF EXISTS prevent_correlation_delete;
                DROP TRIGGER IF EXISTS prevent_ai_evidence_update;
                DROP TRIGGER IF EXISTS prevent_ai_evidence_delete;
                DELETE FROM bluebox_correlation_map;
                DELETE FROM log_entries;
                DELETE FROM tamper_attempts;
                DELETE FROM sqlite_sequence
                WHERE name IN ('log_entries', 'tamper_attempts');
                """
            )
            for record in records:
                insert_recovery_row(conn, record["row"])
            conn.execute("PRAGMA foreign_keys = ON")

        self._init_db()
        restored_anchor = self.anchor_current_head()
        event_hash = self.record_security_event(
            "sqlite_store_restored_from_recovery_ledger",
            "CRITICAL",
            {
                "actor": actor,
                "reason": reason,
                "backup_paths": backup_paths,
                "records_restored": len(records),
                "pre_restore_verification": pre_restore_verification,
                "ledger_status_before_restore": ledger_status,
            },
        )
        return {
            "restored": True,
            "records_restored": len(records),
            "backup_paths": backup_paths,
            "restored_anchor": restored_anchor,
            "security_event_entry_hash": event_hash,
            "status": self.integrity_panel(),
        }

    def initialize_recovery_ledger(self) -> dict[str, object]:
        if self.recovery_ledger_path.exists() and self.recovery_ledger_path.stat().st_size > 0:
            return {
                "initialized": False,
                "skipped": True,
                "reason": "recovery ledger already exists and is not empty",
                "ledger_status": self.verify_recovery_ledger(),
            }

        verification = self.verify()
        if not verification["ok"]:
            raise RuntimeError("refusing to initialize recovery ledger from an untrusted DB")

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT sequence, created_at, source_file, source_type, source_offset,
                       metadata_json, payload, payload_sha256, previous_hash,
                       entry_hash, rsa_key_id, rsa_signature, entry_material_json
                FROM log_entries
                ORDER BY sequence ASC
                """
            ).fetchall()

        if self.recovery_ledger_path.exists():
            self.recovery_ledger_path.unlink()
        for row in rows:
            self.append_recovery_record(row)
        anchor = self.anchor_current_head() if rows else None
        return {
            "initialized": True,
            "records_written": len(rows),
            "path": str(self.recovery_ledger_path),
            "anchor": anchor,
            "ledger_status": self.verify_recovery_ledger(),
        }

    def ensure_recovery_ledger_initialized(self) -> dict[str, object]:
        conn = self._connect()
        try:
            row_count = int(conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0])
        finally:
            conn.close()

        if row_count == 0:
            return {
                "initialized": False,
                "skipped": True,
                "reason": "no SQLite evidence entries exist yet",
            }

        if self.recovery_ledger_path.exists() and self.recovery_ledger_path.stat().st_size > 0:
            return {
                "initialized": False,
                "skipped": True,
                "reason": "recovery ledger already exists",
                "ledger_status": self.verify_recovery_ledger(),
            }

        verification = self.verify()
        if not verification["ok"]:
            return {
                "initialized": False,
                "skipped": True,
                "reason": "current SQLite store is not trusted",
                "verification": verification,
            }

        return self.initialize_recovery_ledger()

    def load_verified_recovery_records(self, public_key_value: Any) -> list[dict[str, object]]:
        expected_previous = GENESIS_HASH
        records: list[dict[str, object]] = []
        with self.recovery_ledger_path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                failure = verify_recovery_record(record, public_key_value, expected_previous)
                if failure:
                    raise RuntimeError(f"recovery ledger verification failed at line {line_no}: {failure}")
                expected_previous = str(record["ledger_hash"])
                records.append(record)
        return records

    def load_latest_recovery_chain(self, public_key_value: Any) -> list[dict[str, object]]:
        records = self.load_verified_recovery_records(public_key_value)
        if not records:
            return []

        by_entry_hash: dict[str, dict[str, object]] = {}
        for record in records:
            row = record.get("row")
            if not isinstance(row, dict):
                continue
            by_entry_hash[str(row["entry_hash"])] = record

        chain: list[dict[str, object]] = []
        current = records[-1]
        seen: set[str] = set()
        while True:
            row = current.get("row")
            if not isinstance(row, dict):
                raise RuntimeError("invalid recovery ledger row while rebuilding latest chain")
            entry_hash = str(row["entry_hash"])
            if entry_hash in seen:
                raise RuntimeError("cycle detected in recovery ledger chain")
            seen.add(entry_hash)
            chain.append(current)

            previous_hash = str(row["previous_hash"])
            if previous_hash == GENESIS_HASH:
                break
            previous = by_entry_hash.get(previous_hash)
            if previous is None:
                raise RuntimeError(
                    "recovery ledger cannot rebuild latest chain; missing predecessor "
                    f"{previous_hash}"
                )
            current = previous

        chain.reverse()
        for expected_sequence, record in enumerate(chain, start=1):
            row = record["row"]
            if not isinstance(row, dict):
                raise RuntimeError("invalid recovery chain row")
            if int(row["sequence"]) != expected_sequence:
                raise RuntimeError(
                    "recovery chain has non-contiguous sequence numbers; "
                    f"expected {expected_sequence}, found {row['sequence']}"
                )
        return chain

    def backup_current_database_files(self) -> list[str]:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        copied: list[str] = []
        for path in (
            self.db_path,
            self.db_path.with_name(f"{self.db_path.name}-wal"),
            self.db_path.with_name(f"{self.db_path.name}-shm"),
            self.anchor_log_path,
        ):
            if not path.exists():
                continue
            backup_path = path.with_name(f"{path.name}.compromised.{stamp}")
            shutil.copy2(path, backup_path)
            copied.append(str(backup_path))
        return copied

    def verify_anchor_log(self, public_key_value: Any) -> dict[str, object]:
        if not self.anchor_log_path.exists():
            return {
                "ok": False,
                "status": "missing",
                "reason": "no signed head anchor exists",
                "path": str(self.anchor_log_path),
                "anchors_checked": 0,
            }

        previous_anchor_hash = GENESIS_HASH
        latest: dict[str, object] | None = None
        checked = 0
        with self.anchor_log_path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                checked += 1
                anchor = json.loads(line)
                failure = verify_anchor_record(
                    anchor, public_key_value, previous_anchor_hash
                )
                if failure:
                    return {
                        "ok": False,
                        "status": "failed",
                        "reason": failure,
                        "path": str(self.anchor_log_path),
                        "line": line_no,
                        "anchors_checked": checked,
                    }
                previous_anchor_hash = str(anchor["anchor_hash"])
                latest = anchor

        if latest is None:
            return {
                "ok": False,
                "status": "missing",
                "reason": "anchor log is empty",
                "path": str(self.anchor_log_path),
                "anchors_checked": 0,
            }

        current_head = self.current_head()
        head_matches = (
            latest.get("sequence") == current_head["sequence"]
            and latest.get("entry_count") == current_head["entry_count"]
            and latest.get("head_hash") == current_head["head_hash"]
        )
        return {
            "ok": head_matches,
            "status": "verified" if head_matches else "failed",
            "reason": None if head_matches else "latest anchor does not match current DB head",
            "path": str(self.anchor_log_path),
            "anchors_checked": checked,
            "anchor": latest,
            "current_head": current_head,
        }

    def current_head(self) -> ChainHead:
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT
                    COALESCE(MAX(sequence), 0) AS sequence,
                    COUNT(*) AS entry_count,
                    COALESCE(
                        (SELECT entry_hash FROM log_entries ORDER BY sequence DESC LIMIT 1),
                        ?
                    ) AS head_hash
                FROM log_entries
                """,
                (GENESIS_HASH,),
            ).fetchone()
        finally:
            conn.close()
        return {
            "sequence": int(row["sequence"]),
            "entry_count": int(row["entry_count"]),
            "head_hash": str(row["head_hash"]),
        }

    def recent_entries(self, limit: int = 25) -> list[dict[str, object]]:
        limit = max(1, min(limit, 200))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT sequence, created_at, source_file, source_type, source_offset,
                       payload_sha256, previous_hash, entry_hash, rsa_key_id,
                       metadata_json
                FROM log_entries
                ORDER BY sequence DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        entries = []
        for row in rows:
            metadata = json.loads(row["metadata_json"])
            entries.append(
                {
                    "sequence": row["sequence"],
                    "created_at": row["created_at"],
                    "source_file": row["source_file"],
                    "source_type": row["source_type"],
                    "source_offset": row["source_offset"],
                    "payload_sha256": row["payload_sha256"],
                    "previous_hash": row["previous_hash"],
                    "entry_hash": row["entry_hash"],
                    "rsa_key_id": row["rsa_key_id"],
                    "record_version": metadata.get("record_version"),
                    "ingest_mode": metadata.get("ingest_mode"),
                    "storage": metadata.get("storage"),
                }
            )
        return entries

    def sequence_entries(self, limit: int = 5000) -> list[dict[str, object]]:
        limit = max(1, min(limit, 5000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT sequence, created_at, source_file, source_type,
                       source_offset, metadata_json
                FROM log_entries
                ORDER BY sequence DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        entries: list[dict[str, object]] = []
        for row in rows:
            try:
                metadata = json.loads(row["metadata_json"])
            except (TypeError, json.JSONDecodeError):
                metadata = {}

            source_type = str(row["source_type"] or "LOG")
            ingest_mode = str(metadata.get("ingest_mode") or "")
            offset_label = "Offset"
            if ingest_mode == "csv_row":
                offset_label = "Row"
            elif ingest_mode == "binary_chunk":
                offset_label = "Chunk"
            elif source_type == "SECURITY_EVENT":
                offset_label = "Event"

            entries.append(
                {
                    "sequence": int(row["sequence"]),
                    "created_at": str(row["created_at"]),
                    "source_file": str(row["source_file"]),
                    "source_type": source_type,
                    "source_offset": int(row["source_offset"]),
                    "ingest_mode": ingest_mode,
                    "offset_label": offset_label,
                    "storage": metadata.get("storage"),
                }
            )
        return entries

    def evidence_source_summary(self, limit: int = 5000) -> list[dict[str, object]]:
        limit = max(1, min(limit, 5000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT source_file, source_type,
                       COUNT(*) AS records,
                       MIN(created_at) AS first_seen,
                       MAX(created_at) AS last_seen,
                       MIN(sequence) AS first_sequence,
                       MAX(sequence) AS last_sequence
                FROM log_entries
                GROUP BY source_file, source_type
                ORDER BY last_seen DESC, records DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def backfill_generated_artifacts(self) -> dict[str, object]:
        with self._connect() as conn:
            source_rows = conn.execute(
                """
                SELECT DISTINCT source_file
                FROM log_entries
                """
            ).fetchall()

        existing_sources = {
            normalized_source_path(row["source_file"])
            for row in source_rows
            if row["source_file"]
        }
        candidates: list[Path] = []

        for row in source_rows:
            source_file = str(row["source_file"] or "")
            source_path = resolve_project_path(source_file)
            if source_path.suffix.lower() != ".csv":
                continue
            source_name = source_path.name.lower()
            if source_name.endswith("_scores.csv") or source_name.endswith("_labels.csv"):
                continue
            if not source_path.parent.exists():
                continue

            sibling_artifacts = [
                *sorted(source_path.parent.glob("*.pcap")),
                *sorted(source_path.parent.glob("*_labels.csv")),
            ]
            for artifact in sibling_artifacts:
                artifact_key = normalized_source_path(artifact)
                if artifact_key in existing_sources:
                    continue
                existing_sources.add(artifact_key)
                candidates.append(artifact)

        ingested: list[dict[str, object]] = []
        skipped_empty: list[str] = []
        for artifact in candidates:
            count = self.ingest_path(artifact)
            if count:
                ingested.append(
                    {
                        "source_file": str(artifact),
                        "source_type": "PCAP" if artifact.suffix.lower() == ".pcap" else "CSV",
                        "entries": count,
                    }
                )
            else:
                skipped_empty.append(str(artifact))

        return {
            "ingested_files": len(ingested),
            "ingested_entries": sum(int(item["entries"]) for item in ingested),
            "sources": ingested,
            "skipped_empty": skipped_empty,
        }

    def recent_security_events(self, limit: int = 8) -> list[dict[str, object]]:
        limit = max(1, min(limit, 50))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT sequence, created_at, source_file, source_type,
                       source_offset, entry_hash, metadata_json, payload
                FROM log_entries
                WHERE source_type = 'SECURITY_EVENT'
                ORDER BY sequence DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        events: list[dict[str, object]] = []
        for row in rows:
            metadata = json.loads(row["metadata_json"])
            payload: dict[str, object] = {}
            try:
                encryption = metadata.get("encryption")
                if isinstance(encryption, dict):
                    plaintext = decrypt_payload(
                        row["payload"],
                        build_associated_data(
                            row["source_file"],
                            row["source_type"],
                            row["source_offset"],
                            base_event_metadata(metadata),
                        ),
                        self.data_key,
                        encryption,
                    )
                    payload = json.loads(decode_payload_for_display(plaintext))
            except Exception:
                payload = {}

            events.append(
                {
                    "sequence": row["sequence"],
                    "created_at": row["created_at"],
                    "source_file": row["source_file"],
                    "source_offset": row["source_offset"],
                    "event": payload.get("event") or metadata.get("event_name") or "security_event",
                    "severity": payload.get("severity") or metadata.get("severity") or "INFO",
                    "details": payload.get("details", {}),
                }
            )
        return events

    def append_only_activity(self, limit: int = 5000) -> list[dict[str, object]]:
        limit = max(25, min(limit, 5000))

        def metadata_from_row(row: sqlite3.Row) -> dict[str, object]:
            try:
                return json.loads(row["metadata_json"])
            except (TypeError, json.JSONDecodeError):
                return {}

        def details_from_row(row: sqlite3.Row) -> dict[str, object]:
            try:
                return json.loads(row["details_json"])
            except (TypeError, json.JSONDecodeError):
                return {}

        def is_critical_security_event(
            event_name: object,
            severity: object,
            operation: object = "",
        ) -> bool:
            event_text = str(event_name or "").lower()
            severity_text = str(severity or "").upper()
            operation_text = str(operation or "").lower()
            if severity_text in {"CRITICAL", "HIGH"}:
                return True
            return any(
                token in f"{event_text} {operation_text}"
                for token in ("tamper", "corrupt", "delete", "update", "failed", "failure")
            )

        with self._connect() as conn:
            log_rows = conn.execute(
                """
                SELECT sequence, created_at, source_file, source_type,
                       source_offset, metadata_json
                FROM log_entries
                ORDER BY sequence DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            ai_rows = conn.execute(
                """
                SELECT evidence_id, recorded_at, source_file, source_offset,
                       sequence, predicted_anomaly, severity, model_used
                FROM ai_evidence_records
                ORDER BY evidence_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            checkpoint_rows = conn.execute(
                """
                SELECT checkpoint_id, created_at, checkpoint_type, batch_size,
                       first_evidence_id, last_evidence_id
                FROM ai_evidence_checkpoints
                ORDER BY checkpoint_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            attempt_rows = conn.execute(
                """
                SELECT attempt_id, detected_at, operation, target_sequence,
                       sqlite_action, details_json, chain_entry_hash
                FROM tamper_attempts
                ORDER BY attempt_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        activity: list[dict[str, object]] = []
        for row in log_rows:
            metadata = metadata_from_row(row)
            source_type = str(row["source_type"] or "LOG")
            is_security_event = source_type == "SECURITY_EVENT"
            severity = metadata.get("severity") or ("INFO" if is_security_event else "NORMAL")
            event_name = metadata.get("event_name") or "security_event"
            classification = (
                "Critical"
                if is_security_event and is_critical_security_event(event_name, severity)
                else "Normal"
            )
            activity.append(
                {
                    "kind": "security_event" if is_security_event else "raw_log",
                    "kind_label": "Log",
                    "recorded_at": row["created_at"],
                    "sequence": row["sequence"],
                    "record_id": f"seq-{row['sequence']}",
                    "record_label": f"Log #{row['sequence']}",
                    "activity": "Security event appended" if is_security_event else "Raw log appended",
                    "source_file": row["source_file"],
                    "source_type": source_type,
                    "source_offset": row["source_offset"],
                    "classification": classification,
                    "context": "Encrypted, hashed, RSA-signed SQLite append",
                    "batch_key": f"log:{source_type}:{row['source_file']}",
                    "ingest_mode": metadata.get("ingest_mode"),
                    "storage": metadata.get("storage"),
                }
            )

        for row in ai_rows:
            severity = str(row["severity"] or "normal")
            flagged = int(row["predicted_anomaly"] or 0) == 1
            classification = (
                "Critical"
                if flagged or severity.upper() in {"CRITICAL", "HIGH"}
                else "Normal"
            )
            activity.append(
                {
                    "kind": "ai_evidence",
                    "kind_label": "AI",
                    "recorded_at": row["recorded_at"],
                    "sequence": row["sequence"],
                    "record_id": f"ai-{row['evidence_id']}",
                    "record_label": f"AI #{row['evidence_id']}",
                    "activity": "AI evidence stored",
                    "source_file": row["source_file"],
                    "source_type": "AI_EVIDENCE",
                    "source_offset": row["source_offset"],
                    "classification": classification,
                    "context": f"{'Flagged anomaly' if flagged else 'Normal verdict'} / {severity.title()}",
                    "batch_key": f"ai:{classification}:{row['source_file']}",
                    "model_used": row["model_used"],
                    "evidence_id": row["evidence_id"],
                }
            )

        for row in checkpoint_rows:
            activity.append(
                {
                    "kind": "ai_checkpoint",
                    "kind_label": "AI",
                    "recorded_at": row["created_at"],
                    "sequence": row["last_evidence_id"],
                    "record_id": f"ai-checkpoint-{row['checkpoint_id']}",
                    "record_label": f"AI Checkpoint #{row['checkpoint_id']}",
                    "activity": "AI checkpoint stored",
                    "source_file": "AI evidence ledger",
                    "source_type": "AI_CHECKPOINT",
                    "source_offset": row["first_evidence_id"],
                    "classification": "Normal",
                    "context": (
                        f"{row['batch_size']} evidence records, "
                        f"AI #{row['first_evidence_id']} to #{row['last_evidence_id']}"
                    ),
                    "batch_key": f"ai_checkpoint:{row['checkpoint_type']}",
                    "checkpoint_id": row["checkpoint_id"],
                }
            )

        for row in attempt_rows:
            details = details_from_row(row)
            operation = str(row["operation"] or "mutation").title()
            table_name = str(details.get("table") or row["sqlite_action"] or "protected table")
            source_file = str(details.get("old_source_file") or table_name)
            attacker_ip = str(details.get("attacker_ip") or details.get("actor_ip") or DEFAULT_ATTACKER_IP)
            activity.append(
                {
                    "kind": "mutation_attempt",
                    "kind_label": "Attempt",
                    "recorded_at": row["detected_at"],
                    "sequence": row["target_sequence"],
                    "record_id": f"attempt-{row['attempt_id']}",
                    "record_label": f"Attempt #{row['attempt_id']}",
                    "activity": f"{operation} attempt blocked",
                    "source_file": source_file,
                    "source_type": "MUTATION_ATTEMPT",
                    "source_offset": details.get("old_source_offset"),
                    "source_component": attacker_ip,
                    "attacker_ip": attacker_ip,
                    "target_component": f"SEQ #{row['target_sequence']}",
                    "classification": "Critical",
                    "context": f"Protected append-only table: {table_name}",
                    "batch_key": f"attempt:{row['operation']}:{table_name}",
                    "attempt_id": row["attempt_id"],
                    "target_sequence": row["target_sequence"],
                    "synced_to_chain": bool(row["chain_entry_hash"]),
                }
            )

        return sorted(
            activity,
            key=lambda item: str(item.get("recorded_at") or ""),
            reverse=True,
        )

    def anchor_history(self, limit: int = 12) -> list[dict[str, object]]:
        limit = max(1, min(limit, 100))
        if not self.anchor_log_path.exists():
            return []

        anchors: list[dict[str, object]] = []
        with self.anchor_log_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    anchor = json.loads(line)
                except json.JSONDecodeError:
                    continue
                anchors.append(
                    {
                        "created_at": anchor.get("created_at"),
                        "sequence": anchor.get("sequence"),
                        "entry_count": anchor.get("entry_count"),
                        "anchor_hash": anchor.get("anchor_hash"),
                        "previous_anchor_hash": anchor.get("previous_anchor_hash"),
                    }
                )
        return anchors[-limit:]

    def ai_evidence_summary(self, limit: int = 80) -> dict[str, object]:
        limit = max(1, min(limit, 200))
        trace_limit = max(40, min(limit * 2, 200))
        flagged_trace_limit = 2000
        ranked_limit = max(20, min(limit, 200))
        with self._connect() as conn:
            total_entries = int(
                conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
            )
            summary = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COALESCE(SUM(CASE WHEN predicted_anomaly = 1 THEN 1 ELSE 0 END), 0) AS anomalies,
                    COALESCE(MIN(anomaly_score), 0) AS min_score,
                    COALESCE(MAX(anomaly_score), 0) AS max_score
                FROM ai_evidence_records
                """
            ).fetchone()
            severity_rows = conn.execute(
                """
                SELECT COALESCE(severity, 'UNKNOWN') AS severity, COUNT(*) AS count
                FROM ai_evidence_records
                GROUP BY COALESCE(severity, 'UNKNOWN')
                ORDER BY count DESC
                """
            ).fetchall()
            rows = conn.execute(
                """
                SELECT evidence_id, recorded_at, source_file, source_offset,
                       sequence, entry_hash, ai_artifact_path,
                       ai_artifact_row_index, ai_result_sha256, verdict_json,
                       model_used, anomaly_score, predicted_anomaly, severity
                FROM ai_evidence_records
                ORDER BY evidence_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            trace_rows = conn.execute(
                """
                SELECT evidence_id, recorded_at, source_file, source_offset,
                       sequence, ai_artifact_path, ai_artifact_row_index,
                       verdict_json, model_used, anomaly_score,
                       predicted_anomaly, severity
                FROM ai_evidence_records
                ORDER BY evidence_id DESC
                LIMIT ?
                """,
                (trace_limit,),
            ).fetchall()
            flagged_trace_rows = conn.execute(
                """
                SELECT evidence_id, recorded_at, source_file, source_offset,
                       sequence, ai_artifact_path, ai_artifact_row_index,
                       verdict_json, model_used, anomaly_score,
                       predicted_anomaly, severity
                FROM ai_evidence_records
                WHERE predicted_anomaly = 1
                ORDER BY evidence_id ASC
                LIMIT ?
                """,
                (flagged_trace_limit,),
            ).fetchall()
            ranked_rows = conn.execute(
                """
                SELECT evidence_id, recorded_at, source_file, source_offset,
                       sequence, ai_artifact_path, ai_artifact_row_index,
                       verdict_json, model_used, anomaly_score,
                       predicted_anomaly, severity
                FROM ai_evidence_records
                WHERE predicted_anomaly = 1
                ORDER BY anomaly_score ASC, evidence_id DESC
                LIMIT ?
                """,
                (ranked_limit,),
            ).fetchall()
            checkpoint = conn.execute(
                """
                SELECT checkpoint_id, created_at, checkpoint_type, batch_size,
                       first_evidence_id, last_evidence_id, merkle_root, ledger_hash
                FROM ai_evidence_checkpoints
                ORDER BY checkpoint_id DESC
                LIMIT 1
                """
            ).fetchone()
            security_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM log_entries WHERE source_type = 'SECURITY_EVENT'"
                ).fetchone()[0]
            )
            security_rows = conn.execute(
                """
                SELECT sequence, created_at, source_file, source_type,
                       source_offset, entry_hash, metadata_json, payload
                FROM log_entries
                WHERE source_type = 'SECURITY_EVENT'
                ORDER BY sequence DESC
                LIMIT ?
                """,
                (min(limit, 20),),
            ).fetchall()

        def display_record(
            row: sqlite3.Row,
            include_explanation: bool = False,
        ) -> dict[str, object]:
            verdict = json.loads(row["verdict_json"])
            predicted = int(row["predicted_anomaly"] or 0)
            explanation_text = sanitize_display_text(verdict.get("explanation_text", ""))
            top_features = verdict.get("shap_top_features", [])
            if include_explanation and predicted and not explanation_text:
                explanation = self._explain_scored_ai_row(
                    row["ai_artifact_path"],
                    row["ai_artifact_row_index"],
                )
                if explanation:
                    explanation_text = sanitize_display_text(
                        explanation.get("explanation_text", "")
                    )
                    top_features = explanation.get("top_features", top_features)
            return {
                "evidence_id": row["evidence_id"],
                "recorded_at": row["recorded_at"],
                "occurred_at": verdict.get("occurred_at") or row["recorded_at"],
                "source_file": row["source_file"],
                "source_offset": row["source_offset"],
                "sequence": row["sequence"],
                "artifact_row_index": row["ai_artifact_row_index"],
                "model_used": row["model_used"],
                "anomaly_score": row["anomaly_score"],
                "predicted_anomaly": predicted,
                "severity": row["severity"],
                "top_features": top_features,
                "explanation": explanation_text,
                "data_format": verdict.get("data_format"),
                "domain": verdict.get("domain"),
                "protocol": verdict.get("protocol"),
                "src": verdict.get("src") or verdict.get("src_ip"),
                "dst": verdict.get("dst") or verdict.get("dst_ip"),
                "label_octal": verdict.get("label_octal"),
                "anomaly_type": verdict.get("anomaly_type"),
                "port": verdict.get("port") or verdict.get("dst_port"),
            }

        records = [display_record(row) for row in rows]

        trace_by_evidence_id = {
            int(row["evidence_id"]): display_record(row)
            for row in reversed(trace_rows)
        }
        for row in flagged_trace_rows:
            trace_by_evidence_id[int(row["evidence_id"])] = display_record(
                row,
                include_explanation=True,
            )
        score_trace = sorted(
            trace_by_evidence_id.values(),
            key=lambda item: (
                str(item.get("occurred_at") or item.get("recorded_at") or ""),
                int(item.get("evidence_id") or 0),
            ),
        )
        ranked_anomalies = [
            display_record(row, include_explanation=True) for row in ranked_rows
        ]

        security_events = []
        for row in security_rows:
            metadata = json.loads(row["metadata_json"])
            try:
                plaintext = decrypt_payload(
                    row["payload"],
                    build_associated_data(
                        row["source_file"],
                        row["source_type"],
                        row["source_offset"],
                        base_event_metadata(metadata),
                    ),
                    self.data_key,
                    metadata["encryption"],
                )
                payload = json.loads(decode_payload_for_display(plaintext))
            except Exception:
                payload = {}
            security_events.append(
                {
                    "sequence": row["sequence"],
                    "created_at": row["created_at"],
                    "source_file": row["source_file"],
                    "source_offset": row["source_offset"],
                    "event": payload.get("event", "security_event"),
                    "severity": payload.get("severity", "HIGH"),
                    "details": payload.get("details", {}),
                    "attacker_ip": (
                        payload.get("attacker_ip")
                        or (payload.get("details", {}) if isinstance(payload.get("details"), dict) else {}).get("attacker_ip")
                        or DEFAULT_ATTACKER_IP
                    ),
                }
            )

        return {
            "total_entries": total_entries,
            "total_ai_records": int(summary["total"]),
            "anomalies": int(summary["anomalies"]),
            "normal": int(summary["total"]) - int(summary["anomalies"]),
            "security_events_count": security_count,
            "total_alerts": int(summary["anomalies"]) + security_count,
            "min_score": float(summary["min_score"] or 0),
            "max_score": float(summary["max_score"] or 0),
            "severity_counts": {row["severity"]: int(row["count"]) for row in severity_rows},
            "latest_checkpoint": dict(checkpoint) if checkpoint else None,
            "records": records,
            "score_trace": score_trace,
            "ranked_anomalies": ranked_anomalies,
            "security_events": security_events,
        }

    def forensic_replay(self, limit: int = 5000) -> dict[str, object]:
        limit = max(3, min(limit, 5000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT le.sequence, le.created_at, le.source_file, le.source_type,
                       le.source_offset,
                       air.evidence_id, air.predicted_anomaly, air.severity,
                       air.anomaly_score, air.verdict_json,
                       air.ai_artifact_path, air.ai_artifact_row_index
                FROM log_entries le
                JOIN ai_evidence_records air ON air.sequence = le.sequence
                ORDER BY le.sequence ASC, air.evidence_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        evidence_stream = []
        for row in rows:
            verdict = json.loads(row["verdict_json"]) if row["verdict_json"] else {}
            artifact_row = self._load_scored_artifact_row(
                row["ai_artifact_path"],
                row["ai_artifact_row_index"],
            )
            explanation = sanitize_display_text(verdict.get("explanation_text", ""))
            top_features = verdict.get("shap_top_features", [])
            if not explanation:
                shap = self._explain_scored_ai_row(
                    row["ai_artifact_path"],
                    row["ai_artifact_row_index"],
                )
                if shap:
                    explanation = sanitize_display_text(shap.get("explanation_text", ""))
                    top_features = shap.get("top_features", top_features)
            source_component, target_component, service = self._component_pair_from_record(
                artifact_row,
                row["source_file"],
            )
            occurred_at = artifact_row.get("timestamp") or row["created_at"]
            severity = row["severity"] or ("HIGH" if row["predicted_anomaly"] else "NORMAL")
            evidence_stream.append(
                {
                    "sequence": row["sequence"],
                    "occurred_at": occurred_at,
                    "recorded_at": row["created_at"],
                    "source_type": row["source_type"],
                    "source_file": Path(str(row["source_file"])).name,
                    "source_offset": row["source_offset"],
                    "evidence_id": row["evidence_id"],
                    "predicted_anomaly": row["predicted_anomaly"] or 0,
                    "severity": severity,
                    "anomaly_score": row["anomaly_score"],
                    "explanation": explanation,
                    "top_features": top_features,
                    "source_component": source_component,
                    "target_component": target_component,
                    "service": service,
                    "summary": self._event_summary(artifact_row, severity, explanation),
                }
            )

        timeline = sorted(evidence_stream, key=lambda item: str(item.get("occurred_at") or ""))
        anomalous_timeline = [
            item for item in timeline
            if int(item.get("predicted_anomaly") or 0) == 1
        ]
        composition: dict[str, int] = {}
        for item in evidence_stream:
            key = str(item.get("service") or item.get("source_type") or "unknown")
            composition[key] = composition.get(key, 0) + 1

        return {
            "timeline": timeline,
            "evidence_stream": timeline,
            "attack_graph": self._build_attack_graph(anomalous_timeline[:8]),
            "composition": composition,
            "count": len(timeline),
            "anomaly_count": len(anomalous_timeline),
        }

    def forensic_report(self) -> dict[str, object]:
        status = self.integrity_panel()
        ai = self.ai_evidence_summary(limit=50)
        replay = self.forensic_replay(limit=50)
        generated_at = datetime.now(UTC).isoformat()
        lines = [
            "BLUEBOX CYBER FORENSIC REPORT",
            f"Generated: {generated_at}",
            "",
            "SUMMARY",
            f"Entries: {status['total_entries']}",
            f"Chain status: {status['status']}",
            f"Recovery ledger: {status['recovery_ledger']['status']}",
            f"AI evidence ledger: {status['ai_evidence_ledger']['status']}",
            f"Trusted readiness: {status['trusted_readiness']['trusted']}",
            f"AI evidence records: {ai['total_ai_records']}",
            f"Predicted anomalies: {ai['anomalies']}",
            "",
            "LATEST ANOMALIES",
        ]
        anomalies = [record for record in ai["records"] if record["predicted_anomaly"]]
        if not anomalies:
            lines.append("No predicted anomalies are currently attached.")
        for record in anomalies[:10]:
            lines.append(
                (
                    f"- evidence #{record['evidence_id']} seq #{record['sequence']} "
                    f"severity={record['severity']} score={record['anomaly_score']} "
                    f"features={', '.join(record['top_features']) or 'n/a'}"
                )
            )
            if record["explanation"]:
                lines.append(f"  {record['explanation']}")
        lines.extend(["", "REPLAY HEAD"])
        for item in replay["timeline"][:10]:
            lines.append(
                (
                    f"- seq #{item['sequence']} {item['source_type']} "
                    f"offset={item['source_offset']} score={item.get('anomaly_score', 'n/a')}"
                )
            )
        return {
            "generated_at": generated_at,
            "filename": f"BlueBox_Forensic_Report_{generated_at[:10]}.txt",
            "content": "\n".join(lines),
            "status": status,
            "ai": ai,
        }

    def trusted_readiness(
        self,
        verification: dict[str, object] | None = None,
        ai_ledger: dict[str, object] | None = None,
        ai_checkpoints: dict[str, object] | None = None,
    ) -> dict[str, object]:
        verification = verification or self.verify()
        ai_ledger = ai_ledger or self.verify_ai_evidence_ledger()
        ai_checkpoints = ai_checkpoints or self.verify_ai_evidence_checkpoints()
        with self._connect() as conn:
            ai_evidence_count = int(
                conn.execute("SELECT COUNT(*) FROM ai_evidence_records").fetchone()[0]
            )
            ai_checkpoint_count = int(
                conn.execute("SELECT COUNT(*) FROM ai_evidence_checkpoints").fetchone()[0]
            )
        ai_checkpoint_ready = ai_evidence_count == 0 or ai_checkpoint_count > 0
        checks = {
            "chain_verified": bool(verification["ok"]),
            "recovery_ledger_verified": bool(verification["recovery_ledger"]["ok"]),
            "ai_evidence_ledger_verified": bool(ai_ledger["ok"]),
            "ai_checkpoints_verified": bool(ai_checkpoints["ok"]),
            "ai_evidence_checkpointed": ai_checkpoint_ready,
        }
        return {
            "trusted": all(checks.values()),
            "checks": checks,
            "chain_status": "verified" if verification["ok"] else "failed",
            "recovery_ledger_status": verification["recovery_ledger"]["status"],
            "ai_evidence_ledger_status": ai_ledger["status"],
            "ai_checkpoint_status": ai_checkpoints["status"],
            "ai_evidence_count": ai_evidence_count,
            "ai_checkpoint_count": ai_checkpoint_count,
        }

    def require_trusted_readiness(self) -> dict[str, object]:
        readiness = self.trusted_readiness()
        if not readiness["trusted"]:
            raise RuntimeError(f"trusted-read gate failed: {readiness['checks']}")
        return readiness

    def decrypt_entry(self, sequence: int) -> dict[str, object]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT sequence, source_file, source_type, source_offset,
                       metadata_json, payload
                FROM log_entries
                WHERE sequence = ?
                """,
                (sequence,),
            ).fetchone()
        if row is None:
            raise KeyError(f"log entry not found: {sequence}")

        metadata = json.loads(row["metadata_json"])
        encryption = metadata.get("encryption")
        if not isinstance(encryption, dict):
            raise ValueError("entry is not encrypted")
        plaintext = decrypt_payload(
            row["payload"],
            build_associated_data(
                row["source_file"],
                row["source_type"],
                row["source_offset"],
                base_event_metadata(metadata),
            ),
            self.data_key,
            encryption,
        )
        return {
            "sequence": row["sequence"],
            "source_file": row["source_file"],
            "source_type": row["source_type"],
            "source_offset": row["source_offset"],
            "payload_text": decode_payload_for_display(plaintext),
            "payload_sha256": sha256(plaintext).hexdigest(),
            "metadata": base_event_metadata(metadata),
        }

    def integrity_panel(self) -> dict[str, object]:
        artifact_backfill = self.backfill_generated_artifacts()
        tamper_attempt_sync = self.sync_tamper_attempts()
        verification = self.verify()
        ai_ledger = self.verify_ai_evidence_ledger()
        readiness = self.trusted_readiness(verification=verification, ai_ledger=ai_ledger)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*), MIN(created_at), MAX(created_at) FROM log_entries"
            ).fetchone()

        status = "verified" if verification["ok"] else "failed"
        if row[0] == 0:
            status = "empty"
        if status == "verified" and verification["anchor"]["status"] == "missing":
            status = "unanchored"
        display_status = {
            "anchor": (
                "not trusted"
                if not verification["ok"]
                else verification["anchor"]["status"]
            ),
            "recovery_ledger": (
                "restore ready"
                if not verification["ok"] and verification["recovery_ledger"].get("ok")
                else verification["recovery_ledger"]["status"]
            ),
        }
        return {
            "status": status,
            "total_entries": row[0],
            "checked_entries": verification["checked_entries"],
            "head": self.current_head(),
            "anchor": verification["anchor"],
            "recovery_ledger": verification["recovery_ledger"],
            "display_status": display_status,
            "ai_evidence_ledger": ai_ledger,
            "trusted_readiness": readiness,
            "rsa_key_id": self.key_id,
            "signer_provider": self.signer.provider,
            "payload_storage": "AES-256-GCM",
            "first_seen": row[1],
            "last_seen": row[2],
            "verified_at": datetime.now(UTC).isoformat() if verification["ok"] else None,
            "first_failure": verification["first_failure"],
            "tamper_attempt_sync": tamper_attempt_sync,
            "artifact_backfill": artifact_backfill,
            "source_summary": self.evidence_source_summary(),
            "sequence_entries": self.sequence_entries(),
            "recent_security_events": self.recent_security_events(),
            "append_only_activity": self.append_only_activity(),
            "anchor_history": self.anchor_history(),
        }

    def _latest_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT entry_hash FROM log_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return str(row["entry_hash"]) if row else GENESIS_HASH

    def _latest_anchor_hash(self) -> str:
        if not self.anchor_log_path.exists():
            return GENESIS_HASH
        latest_hash = GENESIS_HASH
        with self.anchor_log_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                latest_hash = str(json.loads(line).get("anchor_hash", GENESIS_HASH))
        return latest_hash

    def _latest_recovery_ledger_hash(self) -> str:
        if not self.recovery_ledger_path.exists():
            return GENESIS_HASH
        latest_hash = GENESIS_HASH
        with self.recovery_ledger_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                latest_hash = str(json.loads(line).get("ledger_hash", GENESIS_HASH))
        return latest_hash

    def _latest_ai_evidence_ledger_hash(self) -> str:
        if not self.ai_evidence_ledger_path.exists():
            return GENESIS_HASH
        latest_hash = GENESIS_HASH
        with self.ai_evidence_ledger_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                latest_hash = str(json.loads(line).get("ledger_hash", GENESIS_HASH))
        return latest_hash


def canonical_json(value: dict[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def base_event_metadata(metadata: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in metadata.items() if key not in RESERVED_METADATA_KEYS}


def build_associated_data(
    source_file: str,
    source_type: str,
    source_offset: int,
    metadata: dict[str, object],
) -> bytes:
    return canonical_json(
        {
            "source_file": source_file,
            "source_type": source_type,
            "source_offset": source_offset,
            "metadata": metadata,
        }
    ).encode("utf-8")


def build_entry_material(
    previous_hash: str,
    payload_hash: str,
    metadata: dict[str, object],
    source_file: str,
    source_type: str,
    source_offset: int,
    created_at: str,
    rsa_key_id: str,
) -> dict[str, object]:
    return {
        "record_version": RECORD_VERSION,
        "created_at": created_at,
        "source_file": source_file,
        "source_type": source_type,
        "source_offset": source_offset,
        "metadata": metadata,
        "payload_sha256": payload_hash,
        "previous_hash": previous_hash,
        "rsa_key_id": rsa_key_id,
    }


def resolve_project_path(value: object) -> Path:
    path = Path(str(value or ""))
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def normalized_source_path(value: object) -> str:
    try:
        return str(resolve_project_path(value).resolve()).casefold()
    except OSError:
        return str(resolve_project_path(value)).casefold()


def compute_legacy_entry_hash(previous_hash: str, payload_hash: str, metadata_json: str) -> str:
    return sha256(
        canonical_json(
            {
                "previous_hash": previous_hash,
                "payload_sha256": payload_hash,
                "metadata": json.loads(metadata_json),
            }
        ).encode("utf-8")
    ).hexdigest()


def verify_anchor_record(
    anchor: dict[str, object], public_key_value: Any, previous_anchor_hash: str
) -> str | None:
    anchor_hash = anchor.get("anchor_hash")
    signature = anchor.get("rsa_signature")
    material = {
        key: value for key, value in anchor.items() if key not in {"anchor_hash", "rsa_signature"}
    }
    recomputed_hash = sha256(canonical_json(material).encode("utf-8")).hexdigest()
    if anchor_hash != recomputed_hash:
        return "anchor hash mismatch"
    if anchor.get("previous_anchor_hash") != previous_anchor_hash:
        return "anchor chain mismatch"
    if not isinstance(signature, str) or not isinstance(anchor_hash, str):
        return "anchor signature fields are invalid"
    if not verify_digest(public_key_value, anchor_hash, signature):
        return "anchor RSA signature is invalid"
    return None


def row_to_recovery_payload(row: sqlite3.Row) -> dict[str, object]:
    return {
        "sequence": row["sequence"],
        "created_at": row["created_at"],
        "source_file": row["source_file"],
        "source_type": row["source_type"],
        "source_offset": row["source_offset"],
        "metadata_json": row["metadata_json"],
        "payload_b64": base64.b64encode(row["payload"]).decode("ascii"),
        "payload_sha256": row["payload_sha256"],
        "previous_hash": row["previous_hash"],
        "entry_hash": row["entry_hash"],
        "rsa_key_id": row["rsa_key_id"],
        "rsa_signature": row["rsa_signature"],
        "entry_material_json": row["entry_material_json"],
    }


def verify_recovery_record(
    record: dict[str, object],
    public_key_value: Any,
    expected_previous_ledger_hash: str,
) -> str | None:
    ledger_hash = record.get("ledger_hash")
    signature = record.get("rsa_signature")
    material = {
        key: value
        for key, value in record.items()
        if key not in {"ledger_hash", "rsa_key_id", "rsa_signature"}
    }
    recomputed_hash = sha256(canonical_json(material).encode("utf-8")).hexdigest()
    if ledger_hash != recomputed_hash:
        return "recovery ledger hash mismatch"
    if record.get("previous_ledger_hash") != expected_previous_ledger_hash:
        return "recovery ledger chain mismatch"
    if not isinstance(ledger_hash, str) or not isinstance(signature, str):
        return "recovery ledger signature fields are invalid"
    if not verify_digest(public_key_value, ledger_hash, signature):
        return "recovery ledger RSA signature is invalid"

    row = record.get("row")
    if not isinstance(row, dict):
        return "recovery ledger row is invalid"
    payload = base64.b64decode(str(row.get("payload_b64", "")), validate=True)
    if sha256(payload).hexdigest() != row.get("payload_sha256"):
        return "recovery ledger payload hash mismatch"

    entry_material_json = row.get("entry_material_json")
    if entry_material_json:
        expected_entry_hash = sha256(str(entry_material_json).encode("utf-8")).hexdigest()
    else:
        expected_entry_hash = compute_legacy_entry_hash(
            str(row["previous_hash"]),
            str(row["payload_sha256"]),
            str(row["metadata_json"]),
        )
    if row.get("entry_hash") != expected_entry_hash:
        return "recovery ledger entry hash mismatch"
    return None


def verify_ai_evidence_ledger_record(
    record: dict[str, object],
    public_key_value: Any,
    expected_previous_ledger_hash: str,
) -> str | None:
    if "reference" not in record and "merkle_root" in record:
        return verify_ai_evidence_checkpoint_record(
            record, public_key_value, expected_previous_ledger_hash
        )
    ledger_hash = record.get("ledger_hash")
    signature = record.get("rsa_signature")
    material = {
        key: value
        for key, value in record.items()
        if key not in {"ledger_hash", "rsa_key_id", "rsa_signature"}
    }
    recomputed_hash = sha256(canonical_json(material).encode("utf-8")).hexdigest()
    if ledger_hash != recomputed_hash:
        return "AI evidence ledger hash mismatch"
    if record.get("previous_ledger_hash") != expected_previous_ledger_hash:
        return "AI evidence ledger chain mismatch"
    if not isinstance(ledger_hash, str) or not isinstance(signature, str):
        return "AI evidence ledger signature fields are invalid"
    if not verify_digest(public_key_value, ledger_hash, signature):
        return "AI evidence ledger RSA signature is invalid"
    reference = record.get("reference")
    if not isinstance(reference, dict):
        return "AI evidence ledger reference is invalid"
    required = {"sequence", "entry_hash", "ai_result_sha256"}
    if not required.issubset(reference):
        return "AI evidence ledger reference is incomplete"
    return None


def verify_ai_evidence_checkpoint_record(
    record: dict[str, object],
    public_key_value: Any,
    expected_previous_ledger_hash: str,
) -> str | None:
    ledger_hash = record.get("ledger_hash")
    signature = record.get("rsa_signature")
    material = {
        key: value
        for key, value in record.items()
        if key not in {"ledger_hash", "rsa_key_id", "rsa_signature"}
    }
    recomputed_hash = sha256(canonical_json(material).encode("utf-8")).hexdigest()
    if ledger_hash != recomputed_hash:
        return "AI evidence checkpoint hash mismatch"
    if record.get("previous_ledger_hash") != expected_previous_ledger_hash:
        return "AI evidence checkpoint chain mismatch"
    if not isinstance(ledger_hash, str) or not isinstance(signature, str):
        return "AI evidence checkpoint signature fields are invalid"
    if not verify_digest(public_key_value, ledger_hash, signature):
        return "AI evidence checkpoint RSA signature is invalid"
    leaf_hashes = record.get("leaf_hashes")
    if not isinstance(leaf_hashes, list) or not leaf_hashes:
        return "AI evidence checkpoint leaf hashes are invalid"
    if record.get("batch_size") != len(leaf_hashes):
        return "AI evidence checkpoint batch size mismatch"
    if record.get("merkle_root") != merkle_root_from_leaves([str(v) for v in leaf_hashes]):
        return "AI evidence checkpoint Merkle root mismatch"
    return None


def ai_evidence_leaf_hash(row: sqlite3.Row) -> str:
    return sha256(
        canonical_json(
            {
                "evidence_id": int(row["evidence_id"]),
                "recorded_at": str(row["recorded_at"]),
                "source_file": str(row["source_file"]),
                "source_offset": int(row["source_offset"]),
                "sequence": int(row["sequence"]),
                "entry_hash": str(row["entry_hash"]),
                "ai_artifact_path": row["ai_artifact_path"],
                "ai_artifact_row_index": row["ai_artifact_row_index"],
                "ai_result_sha256": str(row["ai_result_sha256"]),
                "verdict_json": str(row["verdict_json"]),
                "model_used": row["model_used"],
                "anomaly_score": row["anomaly_score"],
                "predicted_anomaly": row["predicted_anomaly"],
                "severity": row["severity"],
            }
        ).encode("utf-8")
    ).hexdigest()


def merkle_root_from_leaves(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        return GENESIS_HASH
    level = [str(value) for value in leaf_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            sha256((level[index] + level[index + 1]).encode("ascii")).hexdigest()
            for index in range(0, len(level), 2)
        ]
    return level[0]


def checkpoint_previous_hash(ledger_path: Path, ledger_hash: str) -> str:
    if not ledger_path.exists():
        return GENESIS_HASH
    with ledger_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("ledger_hash") == ledger_hash:
                return str(record.get("previous_ledger_hash", GENESIS_HASH))
    return GENESIS_HASH


def recovery_record_head(record: dict[str, object]) -> ChainHead:
    row = record["row"]
    if not isinstance(row, dict):
        raise ValueError("invalid recovery ledger row")
    return {
        "sequence": int(row["sequence"]),
        "entry_count": int(row["sequence"]),
        "head_hash": str(row["entry_hash"]),
    }


def insert_recovery_row(conn: sqlite3.Connection, row: dict[str, object]) -> None:
    conn.execute(
        """
        INSERT INTO log_entries (
            sequence, created_at, source_file, source_type, source_offset,
            metadata_json, payload, payload_sha256, previous_hash,
            entry_hash, rsa_key_id, rsa_signature, entry_material_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(row["sequence"]),
            str(row["created_at"]),
            str(row["source_file"]),
            str(row["source_type"]),
            int(row["source_offset"]),
            str(row["metadata_json"]),
            base64.b64decode(str(row["payload_b64"]), validate=True),
            str(row["payload_sha256"]),
            str(row["previous_hash"]),
            str(row["entry_hash"]),
            str(row["rsa_key_id"]),
            str(row["rsa_signature"]),
            str(row["entry_material_json"]) if row.get("entry_material_json") else None,
        ),
    )
    conn.execute(
        """
        INSERT INTO bluebox_correlation_map (
            source_file, source_offset, sequence, entry_hash,
            source_type, payload_sha256, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(row["source_file"]),
            int(row["source_offset"]),
            int(row["sequence"]),
            str(row["entry_hash"]),
            str(row["source_type"]),
            str(row["payload_sha256"]),
            str(row["created_at"]),
        ),
    )


def decode_payload_for_display(payload: bytes) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload.hex()


def events_from_path(path: Path) -> Iterator[RawEvent]:
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file():
                yield from events_from_path(child)
        return

    suffix = path.suffix.lower()
    if suffix == ".csv":
        yield from csv_events(path)
    elif suffix == ".pcap":
        yield from binary_chunk_events(path, "PCAP")
    else:
        yield from binary_chunk_events(path, suffix.lstrip(".").upper() or "BINARY")


def csv_events(path: Path) -> Iterator[RawEvent]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row_index, row in enumerate(reader):
            yield RawEvent(
                source_file=str(path),
                source_type="CSV",
                source_offset=row_index,
                payload=canonical_json(row).encode("utf-8"),
                metadata={
                    "row_index": row_index,
                    "columns": reader.fieldnames or [],
                    "ingest_mode": "csv_row",
                },
            )


def binary_chunk_events(path: Path, source_type: str) -> Iterator[RawEvent]:
    with path.open("rb") as handle:
        chunk_index = 0
        while True:
            chunk = handle.read(PCAP_CHUNK_BYTES)
            if not chunk:
                break
            yield RawEvent(
                source_file=str(path),
                source_type=source_type,
                source_offset=chunk_index,
                payload=chunk,
                metadata={
                    "chunk_index": chunk_index,
                    "chunk_size": len(chunk),
                    "ingest_mode": "binary_chunk",
                },
            )
            chunk_index += 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BlueBox hash-chain logger")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--private-key", type=Path, default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY)
    parser.add_argument("--data-key", type=Path, default=DEFAULT_DATA_KEY)
    parser.add_argument("--anchor-log", type=Path, default=None)
    parser.add_argument("--recovery-ledger", type=Path, default=DEFAULT_RECOVERY_LEDGER)
    parser.add_argument("--ai-evidence-ledger", type=Path, default=DEFAULT_AI_EVIDENCE_LEDGER)
    parser.add_argument("--require-tpm", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="append raw files to the hash chain")
    ingest.add_argument("source", type=Path)

    lookup = subparsers.add_parser("lookup", help="lookup a raw source row mapping")
    lookup.add_argument("source_file")
    lookup.add_argument("source_offset", type=int)

    attach_ai = subparsers.add_parser(
        "attach-ai-evidence",
        help="attach a scored CSV to already-ingested source rows",
    )
    attach_ai.add_argument("source_csv", type=Path)
    attach_ai.add_argument("scored_csv", type=Path)

    append = subparsers.add_parser("append-json", help="append one JSON event")
    append.add_argument("payload", help="JSON object string")
    append.add_argument("--source-file", default="manual")
    append.add_argument("--source-type", default="JSON")

    entry = subparsers.add_parser("entry", help="decrypt one entry for inspection")
    entry.add_argument("sequence", type=int)

    subparsers.add_parser("anchor", help="write a signed anchor for the current DB head")
    subparsers.add_parser("init-ledger", help="initialize recovery ledger from a verified DB")
    subparsers.add_parser("verify-ledger", help="verify the append-only recovery ledger")
    subparsers.add_parser(
        "verify-ai-evidence-ledger",
        help="verify the append-only AI evidence reference ledger",
    )
    restore = subparsers.add_parser("restore-ledger", help="restore SQLite from the recovery ledger")
    restore.add_argument("--reason", default="operator_requested_restore")
    restore.add_argument("--actor", default="cli")
    tamper = subparsers.add_parser(
        "simulate-tamper",
        help="attempt a protected SQLite update/delete against log_entries",
    )
    tamper.add_argument("operation", choices=("delete", "update"))
    tamper.add_argument("--sequence", type=int)
    tamper.add_argument("--actor", default="attacker-cli")
    force_corrupt = subparsers.add_parser(
        "force-corrupt",
        help="deliberately bypass protections and corrupt SQLite for a recovery demo",
    )
    force_corrupt.add_argument("operation", choices=("delete", "update"))
    force_corrupt.add_argument("--sequence", type=int)
    force_corrupt.add_argument("--actor", default="attacker-cli")
    subparsers.add_parser("verify", help="verify chain hashes and RSA signatures")
    subparsers.add_parser("panel", help="print chain integrity panel JSON")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logger = HashChainLogger(
        args.db,
        args.private_key,
        args.public_key,
        args.data_key,
        args.anchor_log,
        args.recovery_ledger,
        args.ai_evidence_ledger,
        require_tpm=args.require_tpm,
    )

    if args.command == "ingest":
        count = logger.ingest_path(args.source)
        print(json.dumps({"ingested_entries": count, "db": str(args.db)}, indent=2))
    elif args.command == "lookup":
        print(json.dumps(logger.lookup_correlation(args.source_file, args.source_offset), indent=2))
    elif args.command == "attach-ai-evidence":
        print(json.dumps(logger.attach_ai_evidence_from_csv(args.source_csv, args.scored_csv), indent=2))
    elif args.command == "append-json":
        payload = json.loads(args.payload)
        entry_hash = logger.append_json(payload, args.source_file, args.source_type)
        print(json.dumps({"entry_hash": entry_hash}, indent=2))
    elif args.command == "entry":
        print(json.dumps(logger.decrypt_entry(args.sequence), indent=2))
    elif args.command == "anchor":
        print(json.dumps(logger.anchor_current_head(), indent=2))
    elif args.command == "init-ledger":
        print(json.dumps(logger.initialize_recovery_ledger(), indent=2))
    elif args.command == "verify-ledger":
        print(json.dumps(logger.verify_recovery_ledger(), indent=2))
    elif args.command == "verify-ai-evidence-ledger":
        print(json.dumps(logger.verify_ai_evidence_ledger(), indent=2))
    elif args.command == "restore-ledger":
        print(json.dumps(logger.restore_from_recovery_ledger(args.reason, args.actor), indent=2))
    elif args.command == "simulate-tamper":
        print(
            json.dumps(
                logger.simulate_tamper_attempt(
                    operation=args.operation,
                    sequence=args.sequence,
                    actor=args.actor,
                ),
                indent=2,
            )
        )
    elif args.command == "force-corrupt":
        print(
            json.dumps(
                logger.force_corrupt_sqlite_for_demo(
                    operation=args.operation,
                    sequence=args.sequence,
                    actor=args.actor,
                ),
                indent=2,
            )
        )
    elif args.command == "verify":
        print(json.dumps(logger.verify(args.public_key), indent=2))
    elif args.command == "panel":
        print(json.dumps(logger.integrity_panel(), indent=2))


if __name__ == "__main__":
    main()
