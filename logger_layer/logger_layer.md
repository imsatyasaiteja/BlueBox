# BlueBox Logger Layer

This layer is the tamper-evident and recoverable logger for BlueBox. It stores raw records in SQLite as AES-256-GCM encrypted payloads, links every record into a SHA-256 hash chain, signs every entry hash with RSA, writes signed head anchors, and mirrors encrypted rows into a signed append-only recovery ledger.

AI explainability is not part of this layer.

## Files

```text
logger_layer/
|-- api_server.py           # Local web API and static UI server
|-- encryption_utils.py     # AES-256-GCM authenticated payload encryption
|-- hash_chain_logger.py    # SQLite hash-chain logger
|-- rsa_utils.py            # RSA signing and verification
`-- __init__.py

runtime/
|-- config/keys/            # Development keys, ignored by git
`-- evidence/
    |-- sqlite/             # SQLite evidence stores and anchors, ignored by git
    |-- recovery_ledger/    # Signed append-only recovery ledgers, ignored by git
    `-- demo_output/        # Generated demo traffic, ignored by git
```

## Runtime Files

The logger creates these files automatically when first used:

```text
runtime/evidence/sqlite/bluebox_log.db
runtime/evidence/sqlite/bluebox_log.db.anchors.jsonl
runtime/evidence/recovery_ledger/bluebox_recovery.jsonl
runtime/config/keys/logger_private.json
runtime/config/keys/logger_public.json
runtime/config/keys/logger_data_key.json
```

The files in `runtime/config/keys/` are development keys. Do not use them for production.

## Command Line Tests

Run commands from the project root.

Append one JSON event:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger append-json '{"event":"manual_test","status":"ok"}'
```

Ingest raw project data:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger ingest .\data\raw
```

Initialize and verify the recovery ledger:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger init-ledger
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger verify-ledger
```

Verify the hash chain:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger verify
```

View a compact status panel:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger panel
```

Restore SQLite from the verified recovery ledger:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger restore-ledger --reason successful_sqlite_tamper_detected --actor analyst
```

Decrypt one entry for inspection:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger entry 1
```

## Web Demo

Start the local logger dashboard:

```powershell
.\bluebox-env\Scripts\python.exe .\logger_layer\api_server.py --host 127.0.0.1 --port 8080
```

Open:

```text
http://127.0.0.1:8080
```

The dashboard can append manual events, ingest files, generate demo traffic, verify the hash chain, anchor the current chain head, initialize and restore from the recovery ledger, simulate blocked SQLite tamper attempts, and inspect recent entries.

## Tamper Attempt Behavior

1. Blocked attempt: an attacker tries `UPDATE` or `DELETE` through SQLite, but append-only triggers reject it. The hash chain remains valid, and the logger appends a signed `SECURITY_EVENT`.
2. Successful out-of-band tampering without a recovery ledger: verification fails, but missing rows cannot be reconstructed.
3. Successful out-of-band tampering with a valid recovery ledger: verification fails, the ledger is verified, SQLite is rebuilt from the signed ledger, and a CRITICAL `SECURITY_EVENT` is appended.

## Recovery Ledger Security

The recovery ledger is trusted only when every record hash, previous-ledger hash, RSA signature, encrypted payload hash, entry hash, and restored SQLite head check passes.

For production, copy the recovery ledger and latest anchor to a separate trust boundary such as WORM storage, a remote verifier, a TPM NV index, or a hardened server.

## Tamper Detection Check

Use a disposable database for destructive tests:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\tamper_test.db --recovery-ledger .\runtime\evidence\recovery_ledger\tamper_test.jsonl ingest .\data\raw\arinc429_logs.csv
```

Bypass the append-only triggers and delete a middle row:

```powershell
.\bluebox-env\Scripts\python.exe -c "import sqlite3; c=sqlite3.connect(r'runtime\evidence\sqlite\tamper_test.db'); c.execute('DROP TRIGGER IF EXISTS prevent_log_update'); c.execute('DROP TRIGGER IF EXISTS prevent_log_delete'); c.execute('DELETE FROM log_entries WHERE sequence=10'); c.commit()"
```

Verify again:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\tamper_test.db --recovery-ledger .\runtime\evidence\recovery_ledger\tamper_test.jsonl verify
```

Restore from the recovery ledger:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\tamper_test.db --recovery-ledger .\runtime\evidence\recovery_ledger\tamper_test.jsonl restore-ledger --reason successful_sqlite_delete_sequence_10 --actor analyst
```

Delete the disposable database after the test:

```powershell
Remove-Item .\runtime\evidence\sqlite\tamper_test.db*
Remove-Item .\runtime\evidence\recovery_ledger\tamper_test.jsonl
```
