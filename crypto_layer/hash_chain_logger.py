"""Hash-chain logger for BlueBox raw data.

Each append-only record stores:
- encrypted payload bytes
- SHA-256(encrypted_payload)
- SHA-256(previous_entry_hash || payload_hash || metadata)
- RSA signature over the entry hash
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Iterable, Iterator, TypedDict

try:
    from crypto_layer.encryption_utils import (
        DEFAULT_DATA_KEY,
        decrypt_payload,
        encrypt_payload,
        load_or_create_data_key,
    )
    from crypto_layer.rsa_utils import (
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
        load_public_key,
        signer_from_environment,
        verify_digest,
    )


GENESIS_HASH = "0" * 64
DEFAULT_DB = Path(__file__).resolve().parent / "sqlite_db" / "bluebox_log.db"
DEFAULT_PRIVATE_KEY = Path(__file__).resolve().parent / "keys" / "logger_private.json"
DEFAULT_PUBLIC_KEY = Path(__file__).resolve().parent / "keys" / "logger_public.json"
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
        require_tpm: bool = False,
    ) -> None:
        self.db_path = db_path
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.data_key_path = data_key_path
        self.anchor_log_path = anchor_log_path or self._default_anchor_log_path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.anchor_log_path.parent.mkdir(parents=True, exist_ok=True)
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
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
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

                CREATE TRIGGER IF NOT EXISTS prevent_log_update
                BEFORE UPDATE ON log_entries
                BEGIN
                    SELECT RAISE(ABORT, 'log_entries is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS prevent_log_delete
                BEFORE DELETE ON log_entries
                BEGIN
                    SELECT RAISE(ABORT, 'log_entries is append-only');
                END;

                CREATE INDEX IF NOT EXISTS idx_log_entries_source
                ON log_entries(source_file, source_offset);
                """
            )

    def append(self, event: RawEvent) -> str:
        with self._connect() as conn:
            entry_hash = self._append_with_connection(conn, event)
        self.anchor_current_head()
        return entry_hash

    def append_many(self, events: Iterable[RawEvent]) -> int:
        count = 0
        with self._connect() as conn:
            for event in events:
                self._append_with_connection(conn, event)
                count += 1
        if count:
            self.anchor_current_head()
        return count

    def _append_with_connection(self, conn: sqlite3.Connection, event: RawEvent) -> str:
        associated_data = build_associated_data(
            event.source_file,
            event.source_type,
            event.source_offset,
            event.metadata,
        )
        encrypted = encrypt_payload(event.payload, associated_data, self.data_key)
        metadata = {
            **event.metadata,
            "record_version": 2,
            "storage": "encrypted",
            "encryption": encrypted.metadata,
            "associated_data_sha256": sha256(associated_data).hexdigest(),
            "signer_provider": self.signer.provider,
        }
        metadata_json = canonical_json(metadata)
        payload_hash = sha256(encrypted.ciphertext).hexdigest()
        previous_hash = self._latest_hash(conn)
        entry_hash = compute_entry_hash(previous_hash, payload_hash, metadata_json)
        signature = self.signer.sign_digest(entry_hash)
        conn.execute(
            """
            INSERT INTO log_entries (
                created_at, source_file, source_type, source_offset,
                metadata_json, payload, payload_sha256, previous_hash,
                entry_hash, rsa_key_id, rsa_signature
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
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
            ),
        )
        return entry_hash

    def verify(
        self,
        public_key_path: Path | None = None,
        verify_payload_auth: bool = True,
    ) -> dict[str, object]:
        verifier_key = load_public_key(public_key_path or self.public_key_path)
        expected_previous = GENESIS_HASH
        checked = 0
        first_failure: dict[str, object] | None = None

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT sequence, metadata_json, payload, payload_sha256,
                       previous_hash, entry_hash, rsa_signature,
                       source_file, source_type, source_offset
                FROM log_entries
                ORDER BY sequence ASC
                """
            )
            for row in rows:
                (
                    sequence,
                    metadata_json,
                    payload,
                    stored_payload_hash,
                    stored_previous_hash,
                    stored_entry_hash,
                    signature,
                    source_file,
                    source_type,
                    source_offset,
                ) = row
                checked += 1
                metadata = json.loads(metadata_json)
                payload_hash = sha256(payload).hexdigest()
                recomputed_entry_hash = compute_entry_hash(
                    stored_previous_hash,
                    payload_hash,
                    metadata_json,
                )
                payload_auth_valid = True
                if verify_payload_auth and metadata.get("storage") == "encrypted":
                    payload_auth_valid = self._verify_encrypted_payload_auth(
                        payload,
                        metadata,
                        source_file,
                        source_type,
                        source_offset,
                    )
                valid = (
                    stored_previous_hash == expected_previous
                    and stored_payload_hash == payload_hash
                    and stored_entry_hash == recomputed_entry_hash
                    and verify_digest(verifier_key, stored_entry_hash, signature)
                    and payload_auth_valid
                )
                if not valid:
                    first_failure = {
                        "sequence": sequence,
                        "expected_previous_hash": expected_previous,
                        "stored_previous_hash": stored_previous_hash,
                        "payload_hash_matches": stored_payload_hash == payload_hash,
                        "entry_hash_matches": stored_entry_hash == recomputed_entry_hash,
                        "rsa_signature_valid": verify_digest(
                            verifier_key, stored_entry_hash, signature
                        ),
                        "payload_auth_valid": payload_auth_valid,
                    }
                    break
                expected_previous = stored_entry_hash

        anchor_verification = self.verify_latest_anchor(verifier_key)
        if first_failure is None and not anchor_verification["ok"]:
            first_failure = {
                "sequence": None,
                "anchor_valid": False,
                "reason": anchor_verification["reason"],
                "expected_anchor": anchor_verification.get("anchor"),
                "current_head": anchor_verification.get("current_head"),
            }

        return {
            "ok": first_failure is None,
            "checked_entries": checked,
            "head_hash": expected_previous if first_failure is None else None,
            "first_failure": first_failure,
            "anchor": anchor_verification,
        }

    def anchor_current_head(self) -> dict[str, object] | None:
        head = self.current_head()
        if head["entry_count"] == 0:
            return None

        previous_anchor_hash = self._latest_anchor_hash()
        anchor_material = {
            "version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "db_path": str(self.db_path),
            "sequence": head["sequence"],
            "entry_count": head["entry_count"],
            "head_hash": head["head_hash"],
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

    def verify_latest_anchor(self, public_key_value) -> dict[str, object]:
        anchor = self._latest_anchor()
        if anchor is None:
            return {
                "ok": False,
                "status": "missing",
                "reason": "no signed head anchor exists; tail deletion cannot be detected",
                "path": str(self.anchor_log_path),
            }

        anchor_hash = anchor.get("anchor_hash")
        signature = anchor.get("rsa_signature")
        material = {
            key: value
            for key, value in anchor.items()
            if key not in {"anchor_hash", "rsa_signature"}
        }
        recomputed_anchor_hash = sha256(
            canonical_json(material).encode("utf-8")
        ).hexdigest()
        current_head = self.current_head()
        signature_valid = (
            isinstance(anchor_hash, str)
            and isinstance(signature, str)
            and verify_digest(public_key_value, anchor_hash, signature)
        )
        anchor_valid = (
            anchor_hash == recomputed_anchor_hash
            and signature_valid
            and anchor.get("sequence") == current_head["sequence"]
            and anchor.get("entry_count") == current_head["entry_count"]
            and anchor.get("head_hash") == current_head["head_hash"]
        )
        return {
            "ok": anchor_valid,
            "status": "verified" if anchor_valid else "failed",
            "path": str(self.anchor_log_path),
            "anchor_hash_matches": anchor_hash == recomputed_anchor_hash,
            "rsa_signature_valid": signature_valid,
            "anchor": anchor,
            "current_head": current_head,
            "reason": None
            if anchor_valid
            else "current DB head does not match the latest signed anchor",
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
            return bool(decrypt_payload(payload, associated_data, self.data_key, encryption))
        except Exception:
            return False

    def integrity_panel(self) -> dict[str, object]:
        verification = self.verify()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*), MIN(created_at), MAX(created_at)
                FROM log_entries
                """
            ).fetchone()
            latest = conn.execute(
                """
                SELECT sequence, source_file, source_type, source_offset, entry_hash
                FROM log_entries
                ORDER BY sequence DESC
                LIMIT 1
                """
            ).fetchone()

        total_entries, first_seen, last_seen = row
        status = "verified" if verification["ok"] else "failed"
        if status == "verified" and verification["anchor"]["status"] == "missing":
            status = "unanchored"
        return {
            "status": status,
            "total_entries": total_entries,
            "checked_entries": verification["checked_entries"],
            "head_hash": verification["head_hash"],
            "anchor": verification["anchor"],
            "rsa_key_id": self.key_id,
            "signer_provider": self.signer.provider,
            "payload_storage": "encrypted_for_new_entries",
            "first_seen": first_seen,
            "last_seen": last_seen,
            "latest_entry": {
                "sequence": latest[0],
                "source_file": latest[1],
                "source_type": latest[2],
                "source_offset": latest[3],
                "entry_hash": latest[4],
            }
            if latest
            else None,
            "first_failure": verification["first_failure"],
        }

    @staticmethod
    def _latest_hash(conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT entry_hash FROM log_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS_HASH

    def current_head(self) -> ChainHead:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COALESCE(MAX(sequence), 0),
                    COUNT(*),
                    COALESCE(
                        (SELECT entry_hash
                         FROM log_entries
                         ORDER BY sequence DESC
                         LIMIT 1),
                        ?
                    )
                FROM log_entries
                """,
                (GENESIS_HASH,),
            ).fetchone()
        return {
            "sequence": int(row[0]),
            "entry_count": int(row[1]),
            "head_hash": str(row[2]),
        }

    def _latest_anchor_hash(self) -> str:
        anchor = self._latest_anchor()
        if anchor and isinstance(anchor.get("anchor_hash"), str):
            return str(anchor["anchor_hash"])
        return GENESIS_HASH

    def _latest_anchor(self) -> dict[str, object] | None:
        if not self.anchor_log_path.exists():
            return None
        latest: dict[str, object] | None = None
        with self.anchor_log_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                latest = json.loads(line)
        return latest

    @staticmethod
    def _default_anchor_log_path(db_path: Path) -> Path:
        return db_path.with_name(f"{db_path.name}.anchors.jsonl")


def canonical_json(value: dict[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def base_event_metadata(metadata: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in metadata.items()
        if key not in RESERVED_METADATA_KEYS
    }


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


def compute_entry_hash(previous_hash: str, payload_hash: str, metadata_json: str) -> str:
    material = {
        "previous_hash": previous_hash,
        "payload_sha256": payload_hash,
        "metadata": json.loads(metadata_json),
    }
    return sha256(canonical_json(material).encode("utf-8")).hexdigest()


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
            payload = canonical_json(row).encode("utf-8")
            yield RawEvent(
                source_file=str(path),
                source_type="CSV",
                source_offset=row_index,
                payload=payload,
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
    parser.add_argument(
        "--anchor-log",
        type=Path,
        default=None,
        help="signed head-anchor JSONL path; defaults to <db>.anchors.jsonl",
    )
    parser.add_argument(
        "--require-tpm",
        action="store_true",
        help="fail unless BLUEBOX_TPM_SIGN_COMMAND and BLUEBOX_TPM_KEY_ID are configured",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="append raw files to the hash chain")
    ingest.add_argument("source", type=Path)

    subparsers.add_parser("anchor", help="write a signed anchor for the current DB head")
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
        require_tpm=args.require_tpm,
    )

    if args.command == "ingest":
        count = logger.append_many(events_from_path(args.source))
        print(json.dumps({"ingested_entries": count, "db": str(args.db)}, indent=2))
    elif args.command == "anchor":
        print(json.dumps(logger.anchor_current_head(), indent=2))
    elif args.command == "verify":
        print(json.dumps(logger.verify(args.public_key), indent=2))
    elif args.command == "panel":
        print(json.dumps(logger.integrity_panel(), indent=2))


if __name__ == "__main__":
    main()
