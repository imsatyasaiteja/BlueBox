# Provenance Graph Guide

This is the single provenance graph guide for BlueBox. The old setup-only document was removed because this file now covers both user workflow and technical reference.

## Purpose

The provenance graph helps an analyst understand how evidence is connected. It links domains, sources, evidence events, targets, and attack patterns in one view.

Use it to answer:

- Which systems are involved?
- Which source reached which target?
- Which sequence or event is most important?
- Are AI anomalies connected to chain integrity or DB mutation events?
- What should be included in the investigation report?

## Where to Find It

Open the dashboard, then go to:

```text
Forensic Replay -> Unified Evidence Trace Graph
```

The graph is served by the backend API and rendered in React with D3.

## What the Nodes Mean

| Node kind | Meaning |
|---|---|
| Domain | Aircraft area such as cabin, maintenance, AFDX, avionics, or integrity |
| Source | Source IP, bus, actor, or attacker identifier |
| Evidence | AI anomaly, chain integrity event, or DB mutation attempt |
| Target | Destination IP, port, ARINC label, or targeted sequence |
| Pattern | Attack or behavior pattern inferred from the evidence |

## Event Types

| Event type | Meaning |
|---|---|
| `anomaly` | AI layer flagged the evidence row |
| `chain_integrity` | Logger, recovery, verification, or security event |
| `mutation_attempt` | Blocked or recorded DB mutation attempt |

For mutation attempts, the expected source is the attacker IP and the expected target is the affected sequence, for example:

```text
203.0.113.45 -> SEQ #355
```

## Filters

The graph supports these filters:

| Filter | Purpose |
|---|---|
| Severity | Show high, medium, low, or normal events |
| Domain | Limit graph to avionics, AFDX, cabin, maintenance, integrity, or unknown |
| Event type | Limit graph to anomalies, chain integrity, or DB mutation attempts |
| Time window | Show all time or recent events only |
| Limit | Control how many top evidence events are shown |

Filters are applied by the backend first. The UI then renders the returned graph.

## Exports

The graph can export:

- PNG image of the current graph
- Text summary of the current graph

The summary is useful for reports because it includes graph counts, severity distribution, domain distribution, event types, and selected evidence details.

## API Reference

### Get graph JSON

```text
GET /api/provenance-graph
```

Common query parameters:

| Parameter | Example | Meaning |
|---|---|---|
| `severity` | `0.5` | Minimum risk threshold when no severity level is selected |
| `severity_levels` | `HIGH,MEDIUM` | Only include selected severity labels |
| `domains` | `maintenance,afdx` | Only include selected domains |
| `event_types` | `anomaly,mutation_attempt` | Only include selected event types |
| `time_window_ms` | `3600000` | Only include events from the last hour |
| `limit` | `30` | Maximum top evidence events before graph expansion |

Example:

```text
http://127.0.0.1:8080/api/provenance-graph?severity=0.5&event_types=mutation_attempt&limit=30
```

### Export PNG

```text
GET /api/provenance-graph/export/png
```

Uses the same query parameters as `/api/provenance-graph`.

### Export text summary

```text
GET /api/provenance-graph/export/summary
```

Uses the same query parameters as `/api/provenance-graph`.

## Implementation Files

```text
logger_layer/api_server.py
logger_layer/enhanced_provenance_builder.py
UI_layer/bluebox_react/src/components/charts/ProvenanceGraphD3.jsx
UI_layer/bluebox_react/src/components/charts/ProvenanceGraphD3.css
UI_layer/bluebox_react/src/api/client.js
UI_layer/bluebox_react/src/pages/ForensicReplayPage.jsx
```

## How Data Flows

```text
HashChainLogger
  -> AI evidence summary and security events
  -> api_server.py /api/provenance-graph
  -> EnhancedProvenanceGraphBuilder
  -> React API client
  -> ProvenanceGraphD3
  -> Forensic Replay page
```

## Troubleshooting

### Graph is empty

Run a traffic scenario first:

```bash
./bluebox-env/bin/python demo/traffic_simulator.py --scenario mixed_attack --duration 1 --output-dir runtime/evidence/demo_output/standalone_mixed_attack --test
```

On Windows:

```powershell
.\bluebox-env\Scripts\python.exe .\demo\traffic_simulator.py --scenario mixed_attack --duration 1 --output-dir .\runtime\evidence\demo_output\standalone_mixed_attack --test
```

### Mutation attempts do not appear

Run a tamper attempt while the API server is running:

```bash
curl -X POST http://127.0.0.1:8080/api/tamper-attempt -H "Content-Type: application/json" -d '{"operation":"delete","actor":"203.0.113.45"}'
```

On Windows:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/tamper-attempt -ContentType "application/json" -Body '{"operation":"delete","actor":"203.0.113.45"}'
```

Then refresh Forensic Replay.

### Export fails

Check that `Pillow` is installed:

```bash
pip install "Pillow>=10.0.0"
```

Also confirm the API server is running:

```bash
curl http://127.0.0.1:8080/api/status
```

### Filters show no results

Clear filters or select `All Time`. A strict time window can hide older demo events.
