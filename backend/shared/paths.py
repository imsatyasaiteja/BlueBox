"""Canonical project paths used by ingestion, detection, and explainability."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
DERIVED_DATA_DIR = DATA_DIR / "derived"
NORMALIZED_DATA_DIR = DERIVED_DATA_DIR / "normalized"
SCORED_DATA_DIR = DERIVED_DATA_DIR / "scored"
EXPLANATIONS_DATA_DIR = DERIVED_DATA_DIR / "explanations"

TRAFFIC_NORMALIZED_CSV = NORMALIZED_DATA_DIR / "traffic_normalized.csv"
TRAFFIC_SCORED_CSV = SCORED_DATA_DIR / "traffic_scored.csv"
ANOMALY_EXPLANATIONS_JSON = EXPLANATIONS_DATA_DIR / "anomaly_explanations.json"

ARINC_RAW_CSV = RAW_DATA_DIR / "arinc429_logs.csv"
PCAP_DOMAIN_FILES = [
    ("cabin", RAW_DATA_DIR / "cabin_traffic.pcap", RAW_DATA_DIR / "cabin_traffic_labels.csv"),
    (
        "maintenance",
        RAW_DATA_DIR / "maintenance_traffic.pcap",
        RAW_DATA_DIR / "maintenance_traffic_labels.csv",
    ),
    ("afdx", RAW_DATA_DIR / "afdx_traffic.pcap", RAW_DATA_DIR / "afdx_traffic_labels.csv"),
]

MODELS_DIR = PROJECT_ROOT / "models"

RUNTIME_DIR = PROJECT_ROOT / "runtime"
RUNTIME_CONFIG_DIR = RUNTIME_DIR / "config"
RUNTIME_KEYS_DIR = RUNTIME_CONFIG_DIR / "keys"
RUNTIME_EVIDENCE_DIR = RUNTIME_DIR / "evidence"
RUNTIME_SQLITE_DIR = RUNTIME_EVIDENCE_DIR / "sqlite"
RUNTIME_RECOVERY_LEDGER_DIR = RUNTIME_EVIDENCE_DIR / "recovery_ledger"
RUNTIME_DEMO_OUTPUT_DIR = RUNTIME_EVIDENCE_DIR / "demo_output"

