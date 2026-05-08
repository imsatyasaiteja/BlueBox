"""
BlueBox normalization layer.

Concatenates the PCAP and ARINC 429 parsers into one DataFrame, cleans it,
and writes the unified CSV the Isolation Forest model will train on.
"""

import ipaddress
import os
import sys

# Make repo root importable when this file is run as a script.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pandas as pd  # noqa: E402

from backend.ingestion import pcap_parser, arinc_parser  # noqa: E402
from backend.shared.paths import TRAFFIC_NORMALIZED_CSV  # noqa: E402
from backend.shared.schema import UNIFIED_COLUMNS  # noqa: E402


OUTPUT_PATH = str(TRAFFIC_NORMALIZED_CSV)

# ── Security flag constants ───────────────────────────────────────────────────

_DOMAIN_NETWORKS = {
    "cabin":       ipaddress.ip_network("192.168.1.0/24"),
    "maintenance": ipaddress.ip_network("192.168.2.0/24"),
    "afdx":        ipaddress.ip_network("10.0.0.0/16"),
}

_SENSITIVE_PORTS = {22, 23, 502, 2404, 161}

_EXPECTED_PORTS = {
    "cabin":       {80, 443, 8080, 8443},
    "maintenance": {22, 102, 443, 8080, 8443},  # 22 is normal SSH in maintenance
    # avionics (afdx): standard web ports + the AFDX virtual-link port range 7000-8000
}


def _port_is_expected(domain: str, port: int) -> bool:
    """Return True if port is normal for the given domain."""
    if domain == "afdx":
        return port in {80, 443} or 7000 <= port <= 8000
    return port in _EXPECTED_PORTS.get(domain, set())

_EXPECTED_PROTOCOLS = {
    "cabin":       {"TCP", "UDP"},
    "maintenance": {"TCP", "UDP"},
    "afdx":        {"TCP", "UDP", "ICMP"},
}


def _ip_domain(ip_str: str):
    """Return the domain name for an IP string, or None if it doesn't match any subnet."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for name, net in _DOMAIN_NETWORKS.items():
        if addr in net:
            return name
    return None


def _compute_flags(df: pd.DataFrame) -> pd.DataFrame:
    """Compute binary security flags for PCAP rows; ARINC429 rows get 0 for all flags."""
    df = df.copy()
    is_pcap = df["data_format"] == "PCAP"

    def _cdf(row):
        sd, dd = _ip_domain(row["src"]), _ip_domain(row["dst"])
        return int(sd is not None and dd is not None and sd != dd)

    def _paf(row):
        p = int(row["port"])
        # Domain-expected ports take priority — if this port is normal here, don't flag it.
        if _port_is_expected(row["domain"], p):
            return 0
        if p in _SENSITIVE_PORTS:
            return 1
        return int(not _port_is_expected(row["domain"], p))

    def _prof(row):
        return int(row["protocol"] not in _EXPECTED_PROTOCOLS.get(row["domain"], set()))

    for col, fn in [
        ("cross_domain_flag",     _cdf),
        ("port_anomaly_flag",     _paf),
        ("protocol_anomaly_flag", _prof),
    ]:
        df[col] = 0
        df.loc[is_pcap, col] = df[is_pcap].apply(fn, axis=1)

    return df


def normalize(output_path: str = OUTPUT_PATH) -> pd.DataFrame:
    """Run both parsers, merge, clean, and persist the unified CSV."""
    pcap_df = pcap_parser.parse_all()
    arinc_df = arinc_parser.parse_arinc()

    df = pd.concat([pcap_df, arinc_df], ignore_index=True)
    df = df.dropna().reset_index(drop=True)

    # Enforce dtypes for downstream model code.
    df = df.astype({
        "timestamp":   "float64",
        "domain":      "string",
        "data_format": "string",
        "src":         "string",
        "dst":         "string",
        "packet_size": "int64",
        "frequency":   "int64",
        "protocol":    "string",
        "port":        "int64",
        "is_anomaly":  "int64",
    })

    # Compute and append binary security flags.
    df = _compute_flags(df)
    df = df.astype({
        "cross_domain_flag":     "int64",
        "port_anomaly_flag":     "int64",
        "protocol_anomaly_flag": "int64",
    })

    df = df[UNIFIED_COLUMNS]

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)

    # Summary
    print("=" * 60)
    print(f"Normalized rows : {len(df)}")
    print(f"Anomalies       : {int(df['is_anomaly'].sum())}")
    print("Rows per domain:")
    print(df["domain"].value_counts().to_string())
    print("Rows per data_format:")
    print(df["data_format"].value_counts().to_string())
    # Sanity-check that the per-domain frequency feature actually separates
    # burst anomalies from normal traffic.
    freq_means = df.groupby("is_anomaly")["frequency"].mean()
    print("Mean frequency by is_anomaly:")
    print(freq_means.to_string())
    print(f"Output          : {output_path}")
    print("=" * 60)

    return df


if __name__ == "__main__":
    normalize()
