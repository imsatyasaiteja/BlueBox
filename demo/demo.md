# BlueBox Final Presentation Demo

This demo folder supports the judged BlueBox walkthrough. It generates aircraft
network traffic, scores it with the anomaly model, attaches explainable AI
evidence to logged rows, protects the evidence in the hash-chain logger, and
drives the forensic replay UI.

## Demo Scenarios

Keep the scenario set focused:

```text
mixed_attack        presentation scenario covering all model feature families
normal              baseline traffic for comparison
lateral_movement    maintenance-to-avionics movement and scan behavior
command_injection   control-command tampering and abnormal ARINC values
replay_attack       duplicated or repeated command behavior
```

`injection_attack.yaml` was removed because it overlapped with
`command_injection.yaml` and did not add a clearer aircraft-specific story.

## Start The UI Demo

Use BlueBox database and ledgers so the demo is repeatable without deleting
previous evidence:

```powershell
.\bluebox-env\Scripts\python.exe .\logger_layer\api_server.py --host 127.0.0.1 --port 8080 --db .\runtime\evidence\sqlite\bluebox_log.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\bluebox_recovery.jsonl --ai-evidence-ledger .\runtime\trust_boundary\ai_evidence_ledger\bluebox_ai_evidence.jsonl
```

Open the React dashboard:

```text
http://127.0.0.1:8080
```

The dashboard auto-refreshes every 3 seconds. Use `Refresh` for immediate updates.

## UI Walkthrough

1. In the Anomaly Detection view, choose `command_injection` or `lateral_movement`.
   Use `mixed_attack` for the final judged walkthrough.
2. Set duration to `3` seconds for a short demo, or `5` seconds for more rows.
3. Click `Generate + Score + Ingest`.
4. Watch Logger metrics update: entries, verified rows, anchor, ledger, chain
   head, and verification gauge.
5. In the Anomaly Detection view, show AI evidence count, anomaly score trace,
   classification mix, flagged anomalies, and SHAP reasons.
6. In the Forensic Replay view, show attack graph, replay procedure, chain timeline,
   event composition, evidence stream, and decrypted evidence viewer.
7. Run attacker delete/update attempts from CLI only. Blocked attempts appear as
   signed security events after refresh.
8. For the recovery proof, run a forced SQLite corruption command from CLI,
   verify that the chain fails, then restore from the recovery ledger.

TPM-backed RSA storage, LLM chat, and report download are intentionally outside
this presentation flow.

## Expected Result

After `Generate + Score + Ingest`, the backend should:

- generate PCAP and ARINC CSV traffic under `runtime/evidence/demo_output/logger_demo/<scenario>/`
- score each generated CSV with `backend.detection.anomaly_model.score_event()`
- ingest raw CSV rows into the encrypted SQLite hash chain
- attach scored AI sidecar evidence to the logged raw rows
- create signed Merkle checkpoints for AI evidence batches
- verify chain, recovery ledger, AI evidence ledger, and checkpoints before the
  evidence/replay APIs return data

If the anomaly page shows zero flagged rows, check the selected scenario first.
`normal` is intentionally low-noise and may produce few or no model-predicted
anomalies in a short run. For the judged demo, use `mixed_attack`; it generates
rows that match the trained model feature families: PCAP size spikes, frequency
bursts, cross-domain movement, port/protocol anomalies, and ARINC SSM/parity/data
field anomalies.

If the page says `Server restart required`, stop the old Python server and start
it again. Static HTML can update while the already-running Python process still
has the old `/api/demo` code loaded, which is the common reason for seeing raw
logger entries but no AI sidecar evidence.

## Clean Runtime Before A Demo

Use this when you want a clean BlueBox demo run. It removes generated runtime
evidence, demo output, and derived score files. It does not delete source code,
models, keys, or files under `data/raw`.

```powershell
$root = Resolve-Path .
$targets = @(
  "runtime\evidence\sqlite\bluebox_log.db*",
  "runtime\trust_boundary\recovery_ledger\bluebox_recovery*.jsonl",
  "runtime\trust_boundary\ai_evidence_ledger\bluebox_ai_evidence*.jsonl",
  "runtime\evidence\demo_output\logger_demo",
  "runtime\evidence\demo_output\standalone_*",
  "data\derived"
)
foreach ($item in $targets) {
  Get-ChildItem -Path $item -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
}
```

## Useful CLI Attack Checks

These commands assume the BlueBox demo server above is running.

Use one shared argument list for the logger CLI:

```powershell
$loggerArgs = @(
  "-m", "logger_layer.hash_chain_logger",
  "--db", ".\runtime\evidence\sqlite\bluebox_log.db",
  "--recovery-ledger", ".\runtime\trust_boundary\recovery_ledger\bluebox_recovery.jsonl",
  "--ai-evidence-ledger", ".\runtime\trust_boundary\ai_evidence_ledger\bluebox_ai_evidence.jsonl"
)
```

<!-- Try to read protected anomaly data before the chain is trusted:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/api/anomaly
```

Expected before ingestion: HTTP `403`. -->

Show blocked SQLite tamper attempts:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/tamper-attempt -ContentType "application/json" -Body '{"operation":"delete","actor":"attacker-cli"}'
Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/tamper-attempt -ContentType "application/json" -Body '{"operation":"update","actor":"attacker-cli"}'
```

The protected path should keep `verify.ok = true` because SQLite triggers block
the attack and the logger records signed `SECURITY_EVENT` rows.

```powershell
.\bluebox-env\Scripts\python.exe @loggerArgs verify
```

Show the recovery-ledger proof with a successful out-of-band corruption:

```powershell
.\bluebox-env\Scripts\python.exe @loggerArgs force-corrupt update --actor attacker-cli
.\bluebox-env\Scripts\python.exe @loggerArgs verify
```

Expected after `force-corrupt`: `ok` is `false`, `first_failure` names the
damaged sequence, and the UI read gate hides anomaly/replay evidence until trust
is restored. The recovery ledger should remain valid; on the dashboard it is
shown as `restore ready` because that verified copy is what proves recovery
effectiveness. A payload-only update can leave the signed head anchor
cryptographically valid, so the UI marks it `not trusted` while the chain is
failed instead of presenting it as an independent pass.

Confirm the recovery copy is still valid, then rebuild SQLite:

```powershell
.\bluebox-env\Scripts\python.exe @loggerArgs verify-ledger
.\bluebox-env\Scripts\python.exe @loggerArgs restore-ledger --reason forced_sqlite_corruption_demo --actor analyst
.\bluebox-env\Scripts\python.exe @loggerArgs verify
```

Expected after `restore-ledger`: `verify.ok` returns to `true`, the recovery
result shows `restored: true`, and Logger/Replayer pages show a CRITICAL
`sqlite_store_restored_from_recovery_ledger` security event after refresh.

Use `force-corrupt delete` instead of `force-corrupt update` if you want to show
a missing-row attack. By default it deletes a middle row so the next row fails
the previous-hash check. The restore flow is the same.

## Traffic Generation via CLI

Use this when you want to show the generator without the UI:

```powershell
.\bluebox-env\Scripts\python.exe .\demo\traffic_simulator.py --scenario command_injection --duration 3 --output-dir .\runtime\evidence\demo_output\standalone_command_injection --test
```

Generate all kept scenarios:

```powershell
.\bluebox-env\Scripts\python.exe .\demo\traffic_simulator.py --scenario all --duration 3 --output-dir .\runtime\evidence\demo_output\standalone_all --test
```

<!-- For a full local reset of all generated runtime evidence:

```powershell
$safeRoot = (Resolve-Path .).Path
$runtime = Join-Path $safeRoot "runtime"
if ((Resolve-Path $runtime).Path.StartsWith($safeRoot)) {
  Get-ChildItem runtime\evidence\sqlite -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne ".gitkeep" } | Remove-Item -Recurse -Force
  Get-ChildItem runtime\evidence\demo_output -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
  Get-ChildItem runtime\trust_boundary\recovery_ledger -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne ".gitkeep" } | Remove-Item -Recurse -Force
  Get-ChildItem runtime\trust_boundary\ai_evidence_ledger -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne ".gitkeep" } | Remove-Item -Recurse -Force
} 
```
-->
