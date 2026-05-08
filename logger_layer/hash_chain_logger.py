"""SQLite-backed encrypted hash-chain logger for BlueBox raw records."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Iterator, TypedDict

from backend.shared.paths import RUNTIME_KEYS_DIR, RUNTIME_RECOVERY_LEDGER_DIR, RUNTIME_SQLITE_DIR

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
DEFAULT_PRIVATE_KEY = RUNTIME_KEYS_DIR / "logger_private.json"
DEFAULT_PUBLIC_KEY = RUNTIME_KEYS_DIR / "logger_public.json"
PCAP_CHUNK_BYTES = 64 * 1024
RESERVED_METADATA_KEYS = {
    "record_version",
    "storage",
    "encryption",
    "associated_data_sha256",
    "signer_provider",
}


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


class HashChainLogger:
    def __init__(
        self,
        db_path: Path = DEFAULT_DB,
        private_key_path: Path = DEFAULT_PRIVATE_KEY,
        public_key_path: Path = DEFAULT_PUBLIC_KEY,
        data_key_path: Path = DEFAULT_DATA_KEY,
        anchor_log_path: Path | None = None,
        recovery_ledger_path: Path = DEFAULT_RECOVERY_LEDGER,
        require_tpm: bool = False,
    ) -> None:
        self.db_path = Path(db_path)
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)
        self.data_key_path = Path(data_key_path)
        self.recovery_ledger_path = Path(recovery_ledger_path)
        self.anchor_log_path = anchor_log_path or self.db_path.with_name(
            f"{self.db_path.name}.anchors.jsonl"
        )
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.anchor_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.recovery_ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.signer = signer_from_environment(
            self.private_key_path,
            self.public_key_path,
            require_tpm=require_tpm,
        )
        self.key_id = self.signer.key_id
        self.data_key = load_or_create_data_key(self.data_key_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _connect_without_init(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
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

                DROP TRIGGER IF EXISTS prevent_log_update;
                DROP TRIGGER IF EXISTS prevent_log_delete;

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
                """
            )
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(log_entries)").fetchall()
            }
            if "entry_material_json" not in columns:
                conn.execute("ALTER TABLE log_entries ADD COLUMN entry_material_json TEXT")

    def append(self, event: RawEvent) -> str:
        with self._connect() as conn:
            entry_hash = self._append_with_connection(conn, event)
        self.anchor_current_head()
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

    def append_many(self, events: Iterable[RawEvent]) -> int:
        count = 0
        with self._connect() as conn:
            for event in events:
                self._append_with_connection(conn, event)
                count += 1
        if count:
            self.anchor_current_head()
        return count

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
        self.append_recovery_record(row)
        return entry_hash

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
            conn.executescript(
                """
                DROP TRIGGER IF EXISTS prevent_log_update;
                DROP TRIGGER IF EXISTS prevent_log_delete;
                DELETE FROM log_entries;
                DELETE FROM tamper_attempts;
                DELETE FROM sqlite_sequence WHERE name IN ('log_entries', 'tamper_attempts');
                """
            )
            for record in records:
                insert_recovery_row(conn, record["row"])

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
        with self._connect() as conn:
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
        tamper_attempt_sync = self.sync_tamper_attempts()
        verification = self.verify()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*), MIN(created_at), MAX(created_at) FROM log_entries"
            ).fetchone()

        status = "verified" if verification["ok"] else "failed"
        if row[0] == 0:
            status = "empty"
        if status == "verified" and verification["anchor"]["status"] == "missing":
            status = "unanchored"
        return {
            "status": status,
            "total_entries": row[0],
            "checked_entries": verification["checked_entries"],
            "head": self.current_head(),
            "anchor": verification["anchor"],
            "recovery_ledger": verification["recovery_ledger"],
            "rsa_key_id": self.key_id,
            "signer_provider": self.signer.provider,
            "payload_storage": "AES-256-GCM",
            "first_seen": row[1],
            "last_seen": row[2],
            "first_failure": verification["first_failure"],
            "tamper_attempt_sync": tamper_attempt_sync,
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
    parser.add_argument("--require-tpm", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="append raw files to the hash chain")
    ingest.add_argument("source", type=Path)

    append = subparsers.add_parser("append-json", help="append one JSON event")
    append.add_argument("payload", help="JSON object string")
    append.add_argument("--source-file", default="manual")
    append.add_argument("--source-type", default="JSON")

    entry = subparsers.add_parser("entry", help="decrypt one entry for inspection")
    entry.add_argument("sequence", type=int)

    subparsers.add_parser("anchor", help="write a signed anchor for the current DB head")
    subparsers.add_parser("init-ledger", help="initialize recovery ledger from a verified DB")
    subparsers.add_parser("verify-ledger", help="verify the append-only recovery ledger")
    restore = subparsers.add_parser("restore-ledger", help="restore SQLite from the recovery ledger")
    restore.add_argument("--reason", default="operator_requested_restore")
    restore.add_argument("--actor", default="cli")
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
        require_tpm=args.require_tpm,
    )

    if args.command == "ingest":
        count = logger.ingest_path(args.source)
        print(json.dumps({"ingested_entries": count, "db": str(args.db)}, indent=2))
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
    elif args.command == "restore-ledger":
        print(json.dumps(logger.restore_from_recovery_ledger(args.reason, args.actor), indent=2))
    elif args.command == "verify":
        print(json.dumps(logger.verify(args.public_key), indent=2))
    elif args.command == "panel":
        print(json.dumps(logger.integrity_panel(), indent=2))


if __name__ == "__main__":
    main()
