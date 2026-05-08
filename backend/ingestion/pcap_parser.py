"""
BlueBox PCAP parser.

Reads each of the three domain PCAPs (cabin / maintenance / AFDX) plus its
sidecar label CSV and emits a DataFrame in the unified schema:

    timestamp, domain, data_format, src, dst, packet_size,
    frequency, protocol, label

`frequency` is a per-src rolling 1-second packet rate.
"""

import os
import sys

import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP, Raw, rdpcap

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from backend.shared.paths import PCAP_DOMAIN_FILES
from backend.shared.schema import BASE_EVENT_COLUMNS


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


def _local_pps_per_domain(df: pd.DataFrame) -> pd.Series:
    """Instantaneous packet rate = 1 / inter-packet delay, per domain.

    Unlike a rolling window count, IPD-based rate has no carry-over: only the
    packet whose arrival triggered the interval is affected. Normal packets at
    X pps have IPD = 1/X → local_pps = X. Burst anomaly packets at 1000 pps
    have IPD = 0.001s → local_pps = 1000. Rate is clamped to [1, 10000] pps.
    The first packet in each domain (no predecessor) is assigned the domain median.
    """
    result = pd.Series(0.0, index=df.index, dtype=float)

    for domain, grp in df.groupby("domain"):
        grp_s = grp.sort_values("timestamp")
        dt = grp_s["timestamp"].diff()          # NaN for first row
        pps = (1.0 / dt.clip(lower=1e-4)).clip(upper=10000.0)
        # Fill first packet with median of the rest.
        pps.iloc[0] = float(pps.iloc[1:].median())
        result[grp_s.index] = pps.values

    return result


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
    df["frequency"] = _local_pps_per_domain(df)
    return df[BASE_EVENT_COLUMNS]


def parse_all() -> pd.DataFrame:
    """Parse all three domain PCAPs and concatenate."""
    frames = [parse_pcap(str(p), str(l), d) for d, p, l in PCAP_DOMAIN_FILES]
    return pd.concat(frames, ignore_index=True)


if __name__ == "__main__":
    df = parse_all()
    print(f"Parsed {len(df)} packets across {df['domain'].nunique()} domains")
    print(df["domain"].value_counts())
    print(df.head())
    print(f"\nAnomalies: {int(df['is_anomaly'].sum())}")
    print(f"Frequency range: {df['frequency'].min()} - {df['frequency'].max()}")
