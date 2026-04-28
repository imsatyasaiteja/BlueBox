"""
BlueBox PCAP parser.

Reads each of the three domain PCAPs (cabin / maintenance / AFDX) plus its
sidecar label CSV and emits a DataFrame in the unified schema:

    timestamp, domain, data_format, src, dst, packet_size,
    frequency, protocol, label

`frequency` is a per-src rolling 1-second packet rate.
"""

import os

import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP, Raw, rdpcap


# (domain_label, pcap_path, label_csv_path)
DOMAIN_FILES = [
    ("cabin",       "data/raw/cabin_traffic.pcap",       "data/raw/cabin_traffic_labels.csv"),
    ("maintenance", "data/raw/maintenance_traffic.pcap", "data/raw/maintenance_traffic_labels.csv"),
    ("afdx",        "data/raw/afdx_traffic.pcap",        "data/raw/afdx_traffic_labels.csv"),
]

UNIFIED_COLUMNS = [
    "timestamp", "domain", "data_format", "src", "dst",
    "packet_size", "frequency", "protocol", "port", "is_anomaly",
]


def _protocol_of(pkt) -> str:
    """Return one of TCP / UDP / ICMP / OTHER for a scapy packet."""
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def _payload_size(pkt) -> int:
    """Bytes of L4 payload (Raw layer); 0 if absent."""
    if pkt.haslayer(Raw):
        return len(pkt[Raw].load)
    return 0


def _rolling_freq_per_domain(df: pd.DataFrame) -> pd.Series:
    """Rolling 1-second packet count per domain, aligned to df's index.

    Counts all packets in the same domain that fall inside the trailing
    1-second window. Burst anomalies in a domain spike this feature.
    """
    work = df[["timestamp", "domain"]].copy()
    work["t_dt"] = pd.to_datetime(work["timestamp"], unit="s")
    work = work.sort_values("t_dt")

    counts = (
        work.set_index("t_dt")
            .groupby("domain", group_keys=False)["timestamp"]
            .rolling("1s")
            .count()
            .astype(int)
    )
    counts = counts.reset_index(level=0, drop=True)
    work["frequency"] = counts.values
    return work.sort_index()["frequency"]


def parse_pcap(pcap_path: str, labels_csv_path: str, domain: str) -> pd.DataFrame:
    """Parse a single domain PCAP + its label sidecar into the unified schema."""
    packets = rdpcap(pcap_path)
    labels_df = pd.read_csv(labels_csv_path)
    # Map packet_index -> is_anomaly (0/1) for fast lookup.
    label_by_idx = dict(zip(labels_df["packet_index"], labels_df["is_anomaly"]))

    rows = []
    for idx, pkt in enumerate(packets):
        # Some packets may lack an IP layer in pathological captures; skip those.
        if not pkt.haslayer(IP):
            continue

        # Destination port: dport for TCP/UDP, else 0.
        if pkt.haslayer(TCP):
            port = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            port = int(pkt[UDP].dport)
        else:
            port = 0

        rows.append({
            "timestamp":   float(pkt.time),
            "domain":      domain,
            "data_format": "PCAP",
            "src":         pkt[IP].src,
            "dst":         pkt[IP].dst,
            "packet_size": _payload_size(pkt),
            "protocol":    _protocol_of(pkt),
            "port":        port,
            "is_anomaly":  int(label_by_idx.get(idx, 0)),
        })

    df = pd.DataFrame(rows)
    df["frequency"] = _rolling_freq_per_domain(df)
    return df[UNIFIED_COLUMNS]


def parse_all() -> pd.DataFrame:
    """Parse all three domain PCAPs and concatenate."""
    frames = [parse_pcap(p, l, d) for d, p, l in DOMAIN_FILES]
    return pd.concat(frames, ignore_index=True)


if __name__ == "__main__":
    df = parse_all()
    print(f"Parsed {len(df)} packets across {df['domain'].nunique()} domains")
    print(df["domain"].value_counts())
    print(df.head())
    print(f"\nAnomalies: {int(df['is_anomaly'].sum())}")
    print(f"Frequency range: {df['frequency'].min()} - {df['frequency'].max()}")
