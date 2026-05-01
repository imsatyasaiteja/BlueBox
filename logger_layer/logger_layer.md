# BlueBox Logger Layer

This layer is the tamper-evident and recoverable logger for BlueBox. It stores raw records in SQLite as AES-256-GCM encrypted payloads, links every record into a SHA-256 hash chain, signs every entry hash with RSA, writes signed head anchors, and mirrors every encrypted row into a signed append-only recovery ledger.

AI explainability is not part of this layer.

## Files

```text
logger_layer/
├── api_server.py              # Local web API and static UI server
├── encryption_utils.py        # AES-256-GCM authenticated payload encryption
├── hash_chain_logger.py       # SQLite hash-chain logger
├── rsa_utils.py               # RSA signing and verification
├── keys/                      # Development keys for local testing
├── recovery_ledger/           # Signed append-only recovery ledger
└── sqlite_db/                 # Runtime databases, ignored by git
```

Git ignored runtime files:

```text
logger_layer/sqlite_db/*.db
logger_layer/sqlite_db/*.db-*
logger_layer/sqlite_db/*.jsonl
logger_layer/recovery_ledger/*.jsonl
data/generated/
*.log
```

## Setup

Run commands from the project root:

```powershell
.\bluebox-env\Scripts\python.exe -m pip install -r requirements.txt
```

The logger creates these files automatically when first used:

```text
logger_layer/sqlite_db/bluebox_log.db
logger_layer/sqlite_db/bluebox_log.db.anchors.jsonl
```

The files in `logger_layer/keys/` are development keys. Do not use them for production.

## Command Line Tests

Append one JSON event:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger append-json '{"event":"manual_test","status":"ok"}'
```

Ingest raw project data:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger ingest .\data\raw
```

Initialize the recovery ledger for an existing trusted database:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger init-ledger
```

Verify the chain:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger verify
```

Expected clean result:

```json
{
  "ok": true,
  "first_failure": null,
  "anchor": {
    "status": "verified"
  }
}
```

View a compact status panel:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger panel
```

Verify only the recovery ledger:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger verify-ledger
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

The dashboard can:

- append a manual JSON event
- ingest a file or folder path
- generate demo traffic and ingest it
- verify the hash chain and RSA signatures
- anchor the current chain head
- initialize, verify, and restore from the recovery ledger
- simulate blocked SQLite delete/update attempts and log them as `SECURITY_EVENT`
- inspect recent entries and decrypt one payload

## Tamper Attempt Behavior

There are two separate cases:

1. Blocked attempt: an attacker tries `UPDATE` or `DELETE` through SQLite, but the append-only triggers reject it. The hash chain remains valid, and the logger appends a signed `SECURITY_EVENT` entry describing the failed attempt.
2. Successful out-of-band tampering without a recovery ledger: an attacker bypasses the logger and deletes data before a ledger exists. Verification fails, but the missing row cannot be reconstructed.
3. Successful out-of-band tampering with a valid recovery ledger: verification fails, the ledger is verified, SQLite is rebuilt from the signed ledger, and a CRITICAL `SECURITY_EVENT` is appended to the restored database.

The dashboard's `Attempt Delete` and `Attempt Update` buttons exercise case 1.

## Recovery Ledger Security

The recovery ledger is not trusted because it exists. It is trusted only when all checks pass:

- every ledger record has a valid SHA-256 hash
- every ledger record links to the previous ledger hash
- every ledger record has a valid RSA signature
- each stored encrypted row still matches its payload hash and entry hash
- the latest ledger head matches the restored SQLite head

An attacker can corrupt or delete the local ledger file, but that will be detected. An attacker cannot inject modified rows into a valid ledger unless they also have the RSA signing key.

For production, copy the recovery ledger and latest anchor to a separate trust boundary such as WORM storage, a remote verifier, a TPM NV index, or a hardened server.

## Recommended Test Flow

1. Start the web demo.
2. Click `Append JSON`.
3. Click `Verify Chain`.
4. Click `Anchor Head`.
5. Click `Initialize Ledger`.
6. Click `Generate + Ingest` with `normal` for a short duration.
7. Open a recent entry and inspect the decrypted payload.

## Tamper Detection Check

Use a disposable database for destructive tests:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\logger_layer\sqlite_db\tamper_test.db --recovery-ledger .\logger_layer\recovery_ledger\tamper_test.jsonl ingest .\data\raw\arinc429_logs.csv
```

Bypass the append-only triggers and delete a middle row:

```powershell
.\bluebox-env\Scripts\python.exe -c "import sqlite3; c=sqlite3.connect(r'logger_layer\sqlite_db\tamper_test.db'); c.execute('DROP TRIGGER IF EXISTS prevent_log_update'); c.execute('DROP TRIGGER IF EXISTS prevent_log_delete'); c.execute('DELETE FROM log_entries WHERE sequence=10'); c.commit()"
```

Verify again:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\logger_layer\sqlite_db\tamper_test.db --recovery-ledger .\logger_layer\recovery_ledger\tamper_test.jsonl verify
```

Expected result:

```json
{
  "ok": false,
  "head_hash": null
}
```

Restore from the recovery ledger:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\logger_layer\sqlite_db\tamper_test.db --recovery-ledger .\logger_layer\recovery_ledger\tamper_test.jsonl restore-ledger --reason successful_sqlite_delete_sequence_10 --actor analyst
```

Expected result:

```json
{
  "restored": true,
  "records_restored": 1000,
  "security_event_entry_hash": "..."
}
```

Delete the disposable database after the test:

```powershell
Remove-Item .\logger_layer\sqlite_db\tamper_test.db*
Remove-Item .\logger_layer\recovery_ledger\tamper_test.jsonl
```
