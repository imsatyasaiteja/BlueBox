# BlueBox Event Schema

This document defines the normalized event format that the ML pipeline
produces and the logger consumes.

---

## 1. PCAP-sourced events (Cabin / Maintenance / AFDX domains)

These come from parsing .pcap files. One row per packet.

| Field        | Type   | Example                  | Notes                          |
|--------------|--------|--------------------------|--------------------------------|
| timestamp    | string | "2026-01-01T14:32:11.4"  | ISO 8601                       |
| domain       | string | "cabin"                  | cabin / maintenance / avionics |
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

## 3. ML verdict envelope (what ML pipeline hands to the logger)

After the Isolation Forest + SHAP runs, each event is wrapped with these
additional fields before being handed to the logger to hash and store:

| Field             | Type    | Example                                    |
|-------------------|---------|--------------------------------------------|
| anomaly_score     | float   | -0.42                                      |
| severity          | string  | "HIGH" / "MEDIUM" / "LOW" / "NONE"         |
| shap_top_features | list    | ["packet_size", "frequency"]               |
| llm_summary       | string  | "Unusual packet spike on maintenance port."|

---


## Raw data location

    data/raw/cabin_traffic.pcap
    data/raw/maintenance_traffic.pcap
    data/raw/afdx_traffic.pcap
    data/raw/cabin_traffic_labels.csv
    data/raw/maintenance_traffic_labels.csv
    data/raw/afdx_traffic_labels.csv
    data/raw/arinc429_logs.csv