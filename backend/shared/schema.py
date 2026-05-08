"""Shared event schema constants."""

UNIFIED_COLUMNS = [
    "timestamp",
    "domain",
    "data_format",
    "src",
    "dst",
    "packet_size",
    "frequency",
    "protocol",
    "port",
    "is_anomaly",
    "cross_domain_flag",
    "port_anomaly_flag",
    "protocol_anomaly_flag",
]

BASE_EVENT_COLUMNS = UNIFIED_COLUMNS[:10]

PCAP_DOMAINS = ["cabin", "maintenance", "afdx"]

PCAP_FEATURES = [
    "packet_size",
    "frequency",
    "packet_size_zscore",
    "frequency_zscore",
    "cross_domain_flag",
    "port_anomaly_flag",
    "protocol_anomaly_flag",
]

ARINC_FEATURES = ["ssm_int", "parity_valid", "data_bits_zscore", "frequency"]

