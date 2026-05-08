"""
BlueBox PCAP simulator.

Generates synthetic Ethernet/IP traffic for three aircraft network domains
(cabin, maintenance, AFDX/ARINC 664 backbone) and writes one PCAP per domain
plus a sidecar CSV with per-packet ground-truth anomaly labels.

Anomaly types injected (~2% of packets):
  - "size":              payload abnormally large (~5000 B), simulating data exfil.
  - "frequency":         tight burst (~1000 pps), simulating lateral-movement scans.
  - "lateral_movement":  src in one domain subnet, dst in a different domain subnet.
  - "command_injection": packets to sensitive control ports [22,23,502,2404,161].
  - "replay":            burst of 10-20 identical packets at 1 ms intervals.
"""

import csv
import os
import random
from dataclasses import dataclass

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


# Total packets per pcap and target anomaly rate.
PACKETS_PER_PCAP = 3000
ANOMALY_RATE = 0.02

# Anomaly magnitudes.
ANOMALY_SIZE_BYTES = 5000
SPIKE_PPS = 1000
SPIKE_BURST_LEN = 100  # packets per frequency-spike burst

# New attack generator counts.
LATERAL_MOVEMENT_COUNT  = 20
COMMAND_INJECTION_COUNT = 15
REPLAY_MIN, REPLAY_MAX  = 10, 20
COMMAND_INJECTION_PORTS = [22, 23, 502, 2404, 161]


@dataclass
class DomainConfig:
    name: str
    ip_prefix: str          # e.g. "192.168.1" or "10.0"
    ip_octets: int          # 3 -> /24, 2 -> /16
    proto: str              # "tcp" or "udp"
    ports: list             # destination ports to choose from
    port_range: tuple       # used for UDP unicast (AFDX); (lo, hi) inclusive
    normal_size: int
    normal_pps: int
    output_pcap: str
    output_csv: str


DOMAINS = [
    DomainConfig(
        name="cabin",
        ip_prefix="192.168.1", ip_octets=3,
        proto="tcp", ports=[80, 443], port_range=None,
        normal_size=512, normal_pps=100,
        output_pcap="data/raw/cabin_traffic.pcap",
        output_csv="data/raw/cabin_traffic_labels.csv",
    ),
    DomainConfig(
        name="maintenance",
        ip_prefix="192.168.2", ip_octets=3,
        proto="tcp", ports=[8080, 22], port_range=None,
        normal_size=256, normal_pps=50,
        output_pcap="data/raw/maintenance_traffic.pcap",
        output_csv="data/raw/maintenance_traffic_labels.csv",
    ),
    DomainConfig(
        name="afdx",
        ip_prefix="10.0", ip_octets=2,
        proto="udp", ports=None, port_range=(7000, 8000),
        normal_size=128, normal_pps=200,
        output_pcap="data/raw/afdx_traffic.pcap",
        output_csv="data/raw/afdx_traffic_labels.csv",
    ),
]


def _random_ip(prefix: str, octets: int) -> str:
    """Build a random IP within the domain's address space."""
    if octets == 3:
        return f"{prefix}.{random.randint(1, 254)}"
    # /16 — fill the last two octets
    return f"{prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _build_packet(cfg: DomainConfig, payload_size: int):
    """Construct a single scapy packet matching the domain's profile."""
    src = _random_ip(cfg.ip_prefix, cfg.ip_octets)
    dst = _random_ip(cfg.ip_prefix, cfg.ip_octets)
    sport = random.randint(1024, 65535)

    if cfg.proto == "tcp":
        dport = random.choice(cfg.ports)
        l4 = TCP(sport=sport, dport=dport)
    else:
        lo, hi = cfg.port_range
        dport = random.randint(lo, hi)
        l4 = UDP(sport=sport, dport=dport)

    # Subtract a rough header overhead (Ether 14 + IP 20 + L4 20) so total
    # frame size lands near the requested size. Floor at 1 byte.
    payload_len = max(1, payload_size - 54)
    # Explicit MACs avoid scapy's per-packet ARP lookup against fake IPs.
    eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    return eth / IP(src=src, dst=dst) / l4 / Raw(load=b"\x00" * payload_len)


def _select_anomaly_indices(total: int, rate: float):
    """Pick anomalous packet indices and assign a type to each.

    Size anomalies: randomly scattered — large payload at a normal timestamp.
    Frequency burst: one CONTIGUOUS block of SPIKE_BURST_LEN consecutive
    indices so that all burst packets cluster tightly in time.  Random scatter
    would spread them across seconds and make the rolling-rate feature flat.
    """
    n_anomalies = int(total * rate)
    # 80% of the budget goes to the frequency burst so the rolling-rate feature
    # has enough contiguous packets to create a visible separation from normal.
    # The remaining 20% are size anomalies to keep both anomaly types present.
    n_freq = min(SPIKE_BURST_LEN, int(n_anomalies * 0.8))
    n_size = n_anomalies - n_freq

    labels = {}

    # Size anomalies: random positions.
    size_indices = random.sample(range(total), n_size)
    for idx in size_indices:
        labels[idx] = "size"

    # Frequency burst: one contiguous block, avoiding size-anomaly positions.
    size_set = set(size_indices)
    for _ in range(100):  # retry until a clean run is found
        start = random.randint(0, total - n_freq)
        block = range(start, start + n_freq)
        if not any(p in size_set for p in block):
            for idx in block:
                labels[idx] = "frequency"
            break
    else:
        # Fallback: pick remaining n_freq positions that aren't already labeled.
        remaining = [i for i in range(total) if i not in size_set]
        for idx in random.sample(remaining, n_freq):
            labels[idx] = "frequency"

    return labels


def lateral_movement_attack(
    cfg: DomainConfig,
    packets: list,
    label_rows: list,
    ts: float,
    start_idx: int,
) -> tuple:
    """Append cross-domain packets: src in cfg's subnet, dst in a different domain."""
    other = random.choice([d for d in DOMAINS if d.name != cfg.name])
    idx = start_idx

    for _ in range(LATERAL_MOVEMENT_COUNT):
        src = _random_ip(cfg.ip_prefix, cfg.ip_octets)
        dst = _random_ip(other.ip_prefix, other.ip_octets)
        sport = random.randint(1024, 65535)

        if cfg.proto == "tcp":
            dport = random.choice(cfg.ports)
            l4 = TCP(sport=sport, dport=dport)
        else:
            lo, hi = cfg.port_range
            dport = random.randint(lo, hi)
            l4 = UDP(sport=sport, dport=dport)

        payload_len = max(1, cfg.normal_size - 54)
        eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        pkt = eth / IP(src=src, dst=dst) / l4 / Raw(load=b"\x00" * payload_len)
        pkt.time = ts

        packets.append(pkt)
        label_rows.append((idx, 1, "lateral_movement"))
        idx += 1
        ts += 1.0 / cfg.normal_pps

    return ts, idx


def command_injection_attack(
    cfg: DomainConfig,
    packets: list,
    label_rows: list,
    ts: float,
    start_idx: int,
) -> tuple:
    """Append packets to sensitive control ports, simulating command injection."""
    idx = start_idx

    for _ in range(COMMAND_INJECTION_COUNT):
        src = _random_ip(cfg.ip_prefix, cfg.ip_octets)
        dst = _random_ip(cfg.ip_prefix, cfg.ip_octets)
        sport = random.randint(1024, 65535)
        dport = random.choice(COMMAND_INJECTION_PORTS)
        proto = random.choice(["tcp", "udp"])

        l4 = TCP(sport=sport, dport=dport) if proto == "tcp" else UDP(sport=sport, dport=dport)
        payload_len = max(1, cfg.normal_size - 54)
        eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        pkt = eth / IP(src=src, dst=dst) / l4 / Raw(load=b"\x00" * payload_len)
        pkt.time = ts

        packets.append(pkt)
        label_rows.append((idx, 1, "command_injection"))
        idx += 1
        ts += 1.0 / cfg.normal_pps

    return ts, idx


def replay_attack(
    cfg: DomainConfig,
    packets: list,
    label_rows: list,
    ts: float,
    start_idx: int,
) -> tuple:
    """Append 10-20 identical packets at 1 ms spacing, simulating a replay attack."""
    n = random.randint(REPLAY_MIN, REPLAY_MAX)
    template = _build_packet(cfg, cfg.normal_size)
    idx = start_idx

    for i in range(n):
        pkt = template.copy()
        pkt.time = ts + i * 0.001
        packets.append(pkt)
        label_rows.append((idx, 1, "replay"))
        idx += 1

    ts += n * 0.001
    return ts, idx


def generate_domain(cfg: DomainConfig, base_ts: float = 1_700_000_000.0):
    """Generate one PCAP + label CSV for a single domain.

    Returns a dict summarizing what was written.
    """
    os.makedirs(os.path.dirname(cfg.output_pcap), exist_ok=True)

    anomaly_map = _select_anomaly_indices(PACKETS_PER_PCAP, ANOMALY_RATE)
    normal_dt = 1.0 / cfg.normal_pps
    spike_dt = 1.0 / SPIKE_PPS

    packets = []
    label_rows = []
    ts = base_ts

    for idx in range(PACKETS_PER_PCAP):
        atype = anomaly_map.get(idx, "none")

        if atype == "size":
            size = ANOMALY_SIZE_BYTES
            dt = normal_dt
        elif atype == "frequency":
            size = cfg.normal_size
            dt = spike_dt
        else:
            size = cfg.normal_size
            dt = normal_dt

        pkt = _build_packet(cfg, size)
        pkt.time = ts
        packets.append(pkt)

        label_rows.append((idx, 1 if atype != "none" else 0, atype))
        ts += dt

    next_idx = PACKETS_PER_PCAP
    ts, next_idx = lateral_movement_attack(cfg, packets, label_rows, ts, next_idx)
    ts, next_idx = command_injection_attack(cfg, packets, label_rows, ts, next_idx)
    ts, next_idx = replay_attack(cfg, packets, label_rows, ts, next_idx)

    wrpcap(cfg.output_pcap, packets)

    with open(cfg.output_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["packet_index", "is_anomaly", "anomaly_type"])
        w.writerows(label_rows)

    n_anom = sum(1 for r in label_rows if r[1] == 1)
    return {
        "domain": cfg.name,
        "pcap": cfg.output_pcap,
        "csv": cfg.output_csv,
        "total": len(packets),
        "anomalies": n_anom,
    }


def generate(seed: int = 42):
    """Generate PCAPs for all domains. Returns list of per-domain summaries."""
    random.seed(seed)
    return [generate_domain(cfg) for cfg in DOMAINS]


if __name__ == "__main__":
    for summary in generate():
        pct = 100.0 * summary["anomalies"] / summary["total"]
        print(
            f"[{summary['domain']:>11}] {summary['total']} pkts, "
            f"{summary['anomalies']} anomalies ({pct:.2f}%) -> {summary['pcap']}"
        )
