# BlueBox Demo

The full setup guide and user manual now live in [`../readme.md`](../readme.md). This file is the command checklist for users who already know the project.

## 1. Build the Dashboard

Windows:

```powershell
Push-Location .\UI_layer\bluebox_react
npm install
npm run build
Pop-Location
```

Linux or macOS:

```bash
cd UI_layer/bluebox_react
npm install
npm run build
cd ../..
```

## 2. Start the API Server

Windows:

```powershell
.\bluebox-env\Scripts\python.exe .\logger_layer\api_server.py --host 127.0.0.1 --port 8080 --db .\runtime\evidence\sqlite\bluebox_log.db --recovery-ledger .\runtime\trust_boundary\recovery_ledger\bluebox_recovery.jsonl --ai-evidence-ledger .\runtime\trust_boundary\ai_evidence_ledger\bluebox_ai_evidence.jsonl
```

Linux or macOS:

```bash
./bluebox-env/bin/python logger_layer/api_server.py --host 127.0.0.1 --port 8080 --db runtime/evidence/sqlite/bluebox_log.db --recovery-ledger runtime/trust_boundary/recovery_ledger/bluebox_recovery.jsonl --ai-evidence-ledger runtime/trust_boundary/ai_evidence_ledger/bluebox_ai_evidence.jsonl
```

Open `http://127.0.0.1:8080`.

## 3. Generate Demo Evidence

Use `mixed_attack` for the main demo.

Windows:

```powershell
.\bluebox-env\Scripts\python.exe .\demo\traffic_simulator.py --scenario mixed_attack --duration 1 --output-dir .\runtime\evidence\demo_output\standalone_mixed_attack --test
```

Linux or macOS:

```bash
./bluebox-env/bin/python demo/traffic_simulator.py --scenario mixed_attack --duration 1 --output-dir runtime/evidence/demo_output/standalone_mixed_attack --test
```

## 4. Show the Three Dashboard Features

1. **Anomaly Detection** - show flagged traffic, source/target IPs, severity, and SHAP reasons.
2. **Logger Control** - show verified hash chain, recovery ledger, anchors, and trusted readiness.
3. **Forensic Replay and BB Chat** - show sequence replay, provenance graph, DB mutation attempts, RAG upload, and Part-IS response guidance.

## 5. Optional Tamper Attempt

Windows:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/tamper-attempt -ContentType "application/json" -Body '{"operation":"delete","actor":"203.0.113.45"}'
```

Linux or macOS:

```bash
curl -X POST http://127.0.0.1:8080/api/tamper-attempt -H "Content-Type: application/json" -d '{"operation":"delete","actor":"203.0.113.45"}'
```

Expected result: the mutation is blocked, logged as a security event, and shown in Forensic Replay and the provenance graph.
