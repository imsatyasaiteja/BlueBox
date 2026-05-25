# Event Schema

This document defines the normalized event format that the ML pipeline
produces and the logger consumes.

---

## 1. PCAP-sourced events (Cabin / Maintenance / AFDX domains)

These come from parsing .pcap files. One row per packet.

| Field        | Type   | Example                  | Notes                          |
|--------------|--------|--------------------------|--------------------------------|
| timestamp    | string | "2026-01-01T14:32:11.4"  | ISO 8601                       |
| domain       | string | "cabin"                  | cabin / maintenance / afdx     |
| data_format  | string | "PCAP"                   | always "PCAP" for these        |
| src          | string | "192.168.1.10"           | source IP                      |
| dst          | string | "192.168.1.1"            | destination IP                 |
| packet_size  | float  | 512.0                    | bytes                          |
| frequency    | float  | 100.0                    | packets per second             |
| protocol     | string | "UDP"                    | TCP / UDP / ICMP               |
| port         | int    | 443                      | destination port               |
| is_anomaly   | int    | 0                        | 0 = normal, 1 = anomaly        |

---

## 2. ARINC 429-sourced events (Legacy avionics domain)

These come from parsing arinc429_logs.csv. One row per 32-bit word.

| Field        | Type   | Example                  | Notes                          |
|--------------|--------|--------------------------|--------------------------------|
| timestamp    | string | "2026-01-01T14:32:11.4"  | ISO 8601                       |
| domain       | string | "avionics"               | always "avionics"              |
| data_format  | string | "ARINC429"               | always "ARINC429" for these    |
| src          | string | "BUS_A"                  | ARINC bus identifier           |
| dst          | string | "LABEL_206"              | ARINC label (octal)            |
| packet_size  | float  | 4.0                      | always 4 (32-bit word = 4 bytes)|
| frequency    | float  | 50.0                     | words per second               |
| protocol     | string | "ARINC429"               | always "ARINC429"              |
| port         | int    | 0                        | not applicable, set to 0       |
| is_anomaly   | int    | 0                        | 0 = normal, 1 = anomaly        |

---

## 3. ML verdict envelope

The Isolation Forest and SHAP artifacts remain unchanged. After scoring, BlueBox
can attach a compact sidecar verdict to the already-logged raw record:

| Field             | Type    | Example                                    |
|-------------------|---------|--------------------------------------------|
| anomaly_score     | float   | -0.42                                      |
| severity          | string  | "HIGH" / "MEDIUM" / "LOW" / "NONE"         |
| shap_top_features | list    | ["packet_size", "frequency"]               |
| llm_summary       | string  | "Unusual packet spike on maintenance port."|

---

## 4. Logger correlation and sidecar evidence

Raw records are joined back to AI results through logger-owned identity, not by
rewriting aircraft logs or model outputs.

| Table                    | Purpose |
|--------------------------|---------|
| `bluebox_correlation_map` | Maps `source_file + source_offset` to SQLite `sequence`, `entry_hash`, source type, payload hash, and creation time. It is populated automatically when raw rows are ingested. |
| `ai_evidence_records`     | Append-only sidecar records containing the compact AI verdict, scored-artifact path/row index, AI-result hash, and references to the exact raw log row. Predicted anomalies may include SHAP top features and a short explanation. |
| `ai_evidence_checkpoints` | Batch checkpoints over sidecar rows. Each checkpoint stores a Merkle root, leaf hashes, range of evidence IDs, and RSA signature. |

The compact AI evidence reference ledger lives separately from the SQLite
recovery ledger:

    runtime/trust_boundary/ai_evidence_ledger/bluebox_ai_evidence.jsonl

This ledger stores signed Merkle batch checkpoints over compact evidence rows;
it does not duplicate trained models, generated datasets, raw log payloads, or
full AI output files.

The dashboard/API applies verification last: record-list and record-open
endpoints only return rows after the hash chain, recovery ledger, AI evidence
ledger, and Merkle checkpoints verify.

---


## Raw data location

    data/raw/cabin_traffic.pcap
    data/raw/maintenance_traffic.pcap
    data/raw/afdx_traffic.pcap
    data/raw/cabin_traffic_labels.csv
    data/raw/maintenance_traffic_labels.csv
    data/raw/afdx_traffic_labels.csv
    data/raw/arinc429_logs.csv

## Derived data location

    data/derived/normalized/traffic_normalized.csv
    data/derived/scored/traffic_scored.csv
    data/derived/explanations/anomaly_explanations.json
