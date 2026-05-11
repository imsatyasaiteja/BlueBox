# BlueBox Logger Layer

This layer is the tamper-evident and recoverable logger for BlueBox. It stores raw records in SQLite as AES-256-GCM encrypted payloads, links every record into a SHA-256 hash chain, signs every entry hash with RSA, writes signed head anchors, and mirrors encrypted rows into a signed append-only recovery ledger.

AI outputs are attached after scoring as compact sidecar evidence. The logger does
not rewrite trained models, scored CSVs, generated datasets, or aircraft log
payloads.

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
runtime/trust_boundary/
    |-- recovery_ledger/    # Signed append-only recovery copy, ignored by git
    |-- ai_evidence_ledger/ # Signed AI evidence checkpoints, ignored by git
    `-- demo_output/        # Generated demo traffic, ignored by git
```

## Runtime Files

The logger creates these files automatically when first used:

```text
runtime/evidence/sqlite/bluebox_log.db
runtime/evidence/sqlite/bluebox_log.db.anchors.jsonl
runtime/trust_boundary/recovery_ledger/bluebox_recovery.jsonl
runtime/trust_boundary/ai_evidence_ledger/bluebox_ai_evidence.jsonl
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

Look up the stable identity for one ingested CSV row:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger lookup .\data\raw\arinc429_logs.csv 0
```

The lookup returns `source_file`, `source_offset`, SQLite `sequence`, and
`entry_hash`. Those fields are the join basis for AI evidence.

Initialize and verify the recovery ledger:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger init-ledger
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger verify-ledger
```

Verify the hash chain:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger verify
```

Verify the compact AI evidence checkpoint ledger:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger verify-ai-evidence-ledger
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

## End-to-End AI Evidence Test

Use a disposable database so you can test without changing the default
`bluebox_log.db`:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\ai_test.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\ai_test_recovery.jsonl --ai-evidence-ledger .\runtime\trust_boundary\ai_evidence_ledger\ai_test_ai.jsonl ingest .\data\raw\arinc429_logs.csv
```

Score a CSV with the existing AI layer:

```powershell
.\bluebox-env\Scripts\python.exe -c "from demo.traffic_simulator import test_anomaly_detection; test_anomaly_detection(r'.\data\raw\arinc429_logs.csv', r'.\runtime\evidence\demo_output\arinc429_logs_scores.csv')"
```

Attach compact AI results back to the logged raw rows. This creates sidecar
records and a signed Merkle batch checkpoint:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\ai_test.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\ai_test_recovery.jsonl --ai-evidence-ledger .\runtime\trust_boundary\ai_evidence_ledger\ai_test_ai.jsonl attach-ai-evidence .\data\raw\arinc429_logs.csv .\runtime\evidence\demo_output\arinc429_logs_scores.csv
```

Verify all integrity material:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\ai_test.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\ai_test_recovery.jsonl --ai-evidence-ledger .\runtime\trust_boundary\ai_evidence_ledger\ai_test_ai.jsonl verify
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\ai_test.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\ai_test_recovery.jsonl --ai-evidence-ledger .\runtime\trust_boundary\ai_evidence_ledger\ai_test_ai.jsonl verify-ai-evidence-ledger
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\ai_test.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\ai_test_recovery.jsonl --ai-evidence-ledger .\runtime\trust_boundary\ai_evidence_ledger\ai_test_ai.jsonl panel
```

Expected files:

```text
runtime/evidence/sqlite/ai_test.db
runtime/evidence/sqlite/ai_test.db.anchors.jsonl
runtime/trust_boundary/recovery_ledger/ai_test_recovery.jsonl
runtime/trust_boundary/ai_evidence_ledger/ai_test_ai.jsonl
runtime/evidence/demo_output/arinc429_logs_scores.csv
runtime/config/keys/logger_private.json
runtime/config/keys/logger_public.json
runtime/config/keys/logger_data_key.json
```

`ai_test.db` contains raw encrypted rows, `bluebox_correlation_map`,
`ai_evidence_records`, and `ai_evidence_checkpoints`. The recovery JSONL is the
full encrypted recovery copy. The AI JSONL is only a compact signed Merkle
checkpoint ledger.

## Web Demo

Start the local logger dashboard:

```powershell
.\bluebox-env\Scripts\python.exe .\logger_layer\api_server.py --host 127.0.0.1 --port 8080
```

Open:

```text
http://127.0.0.1:8080
```

The analyst dashboard verifies the hash chain, anchors the current chain head,
initializes and restores from the recovery ledger, displays AI evidence, and
inspects recent trusted entries. Attacker-style tamper attempts are run from CLI
or API commands outside the UI.

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
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\tamper_test.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\tamper_test.jsonl ingest .\data\raw\arinc429_logs.csv
```

Bypass the append-only triggers and corrupt a row:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\tamper_test.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\tamper_test.jsonl force-corrupt update --actor attacker-cli
```

Verify again:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\tamper_test.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\tamper_test.jsonl verify
```

Restore from the recovery ledger:

```powershell
.\bluebox-env\Scripts\python.exe -m logger_layer.hash_chain_logger --db .\runtime\evidence\sqlite\tamper_test.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\tamper_test.jsonl restore-ledger --reason forced_sqlite_corruption_demo --actor analyst
```

Delete the disposable database after the test:

```powershell
Remove-Item .\runtime\evidence\sqlite\tamper_test.db*
Remove-Item .\runtime\trust_boundary\recovery_ledger\tamper_test.jsonl
```
