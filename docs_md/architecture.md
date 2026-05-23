# BlueBox Architecture

This page explains the BlueBox system in simple terms.

## High-Level Flow

```text
Traffic generator or raw files
  -> backend normalization
  -> anomaly scoring and explanations
  -> hash-chain logger
  -> recovery and AI evidence ledgers
  -> API server
  -> React dashboard and BB Chat
```

## Main Layers

### 1. Demo and Data Layer

Location:

```text
demo/
data/
runtime/evidence/demo_output/
```

What it does:

- Generates normal and attack traffic.
- Produces PCAP, CSV, and ARINC-style evidence.
- Can stream scored rows into the dashboard during a live demo.

### 2. Backend AI Layer

Location:

```text
backend/
models/
data/derived/
```

What it does:

- Normalizes aircraft traffic fields.
- Scores traffic with anomaly models.
- Produces compact explanations for suspicious rows.
- Writes derived scored files and explanation artifacts.

### 3. Logger Layer

Location:

```text
logger_layer/
runtime/evidence/sqlite/
runtime/trust_boundary/
```

What it does:

- Appends evidence to encrypted SQLite.
- Links entries with previous hashes.
- Signs anchors and ledger checkpoints.
- Maintains recovery data outside the main SQLite DB.
- Blocks protected reads when verification fails.

### 4. API Layer

Location:

```text
logger_layer/api_server.py
```

What it does:

- Serves the dashboard.
- Provides `/api/status`, `/api/anomaly`, `/api/replay`, `/api/provenance-graph`, and BB Chat endpoints.
- Verifies trust before returning protected evidence views.

### 5. UI and BB Chat Layer

Location:

```text
UI_layer/bluebox_react/
UI_layer/BB_bot/
```

What it does:

- Shows anomaly, logger, and forensic replay dashboards.
- Renders the D3 provenance graph.
- Lets analysts upload RAG documents.
- Answers investigation questions using evidence context, Part-IS templates, and Ollama when available.

## Trust Boundary

BlueBox separates the evidence database from trust records:

```text
runtime/evidence/sqlite/bluebox_log.db
runtime/trust_boundary/recovery_ledger/bluebox_recovery.jsonl
runtime/trust_boundary/ai_evidence_ledger/bluebox_ai_evidence.jsonl
```

This makes it possible to detect SQLite tampering and restore from the recovery ledger.

## Protected Read Model

Before returning anomaly or replay data, BlueBox checks:

- Hash chain verification
- Recovery ledger verification
- AI evidence ledger verification
- AI checkpoint verification

If trust fails, protected API reads are blocked until recovery succeeds.

## Main Dashboard Pages

| Page | Purpose |
|---|---|
| Anomaly Detection | Review AI-flagged evidence and explanations |
| Logger Control | Check chain, anchor, ledger, and recovery state |
| Forensic Replay | Replay sequence entries, graph relationships, and chat with BB |
