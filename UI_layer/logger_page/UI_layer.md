# Logger Page

This page is a local dashboard for testing the BlueBox logger layer.

Run it with:

```powershell
.\bluebox-env\Scripts\python.exe .\logger_layer\api_server.py --host 127.0.0.1 --port 8080
```

Open:

```text
http://127.0.0.1:8080/index.html
http://127.0.0.1:8080/logger.html
http://127.0.0.1:8080/replay.html
```

## What It Tests

- Separate operational pages for anomaly detection, logger controls, and
  forensic replay.
- Append a JSON event into the encrypted hash chain.
- Ingest CSV/PCAP files from a path.
- Generate demo traffic and ingest it.
- Score generated demo traffic with the backend anomaly models before ingestion.
- Attach compact AI verdicts and SHAP explanations to the logged raw rows.
- Create signed Merkle checkpoints for AI evidence batches.
- Append a signed demo manifest with AI metrics and generated artifact paths.
- Verify hashes, RSA signatures, encrypted payload authentication, anchors,
  recovery evidence, AI evidence, and Merkle checkpoints before showing records.
- Simulate blocked SQLite delete/update attempts.
- Inspect decrypted payloads for selected entries.

Runtime databases, ledgers, keys, and generated demo files live under `runtime/`.

## How To Use The Page

1. Start the server and open `http://127.0.0.1:8080`.
2. On Anomaly Detection, click `Generate + Score + Ingest` to create demo traffic, score it, ingest raw rows,
   attach AI sidecar evidence, checkpoint the evidence, and append a demo
   manifest.
3. Check the status area. The record table stays hidden until the chain,
   recovery ledger, AI evidence ledger, and Merkle checkpoints verify.
4. Click `Open` on an entry to decrypt and inspect a trusted raw payload.
5. Click `Verify Chain` and `Verify Ledger` to inspect the verification JSON.
6. Use the CLI attacker commands in `demo/demo.md` to test append-only trigger
   protection. Blocked attempts are recorded as signed security events.

The main files created by the web demo are:

```text
runtime/evidence/sqlite/bluebox_log.db
runtime/evidence/sqlite/bluebox_log.db.anchors.jsonl
runtime/trust_boundary/recovery_ledger/bluebox_recovery.jsonl
runtime/trust_boundary/ai_evidence_ledger/bluebox_ai_evidence.jsonl
runtime/evidence/demo_output/logger_demo/<scenario>/
runtime/config/keys/logger_private.json
runtime/config/keys/logger_public.json
runtime/config/keys/logger_data_key.json
```

## Tamper Attempt Commands

Tamper attempts are attacker actions and are not exposed in the analyst UI. Run
the CLI/API commands in `demo/demo.md` to attempt direct SQLite operations
against `log_entries`. The append-only triggers should reject the operation. When
rejected, the logger appends a signed `SECURITY_EVENT` entry to the same hash
chain.

If verification fails because the DB was modified out of band, preserve the database
and anchor file as evidence. Do not append recovery records to a chain that is already
untrusted.

## Related Docs

See:

```text
logger_layer/logger_layer.md
```
