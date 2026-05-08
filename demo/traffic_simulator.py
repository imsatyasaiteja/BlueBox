#!/usr/bin/env python3
"""Generate synthetic BlueBox traffic and score it with the backend model."""

from __future__ import annotations

import argparse
import csv
import logging
import random
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from backend.detection.anomaly_model import score_event
    from backend.shared.paths import RUNTIME_DEMO_OUTPUT_DIR
except ImportError:
    score_event = None
    RUNTIME_DEMO_OUTPUT_DIR = PROJECT_ROOT / "runtime" / "evidence" / "demo_output"


DEFAULT_SCENARIO_DIR = PROJECT_ROOT / "demo" / "attack_scenarios"
DEFAULT_OUTPUT_DIR = RUNTIME_DEMO_OUTPUT_DIR
SCENARIOS = (
    "normal",
    "lateral_movement",
    "command_injection",
    "injection_attack",
    "replay_attack",
)

LOGGER = logging.getLogger("bluebox.traffic_simulator")


@dataclass(frozen=True)
class DomainConfig:
    name: str
    data_format: str
    ip_prefix: str
    ip_octets: int
    protocol: str
    ports: tuple[int, ...]
    port_range: tuple[int, int] | None
    packet_size: int
    frequency: int
    pcap_name: str | None
    csv_name: str


DOMAINS = (
    DomainConfig(
        name="cabin",
        data_format="PCAP",
        ip_prefix="192.168.1",
        ip_octets=3,
        protocol="tcp",
        ports=(80, 443),
        port_range=None,
        packet_size=458,
        frequency=100,
        pcap_name="cabin_traffic.pcap",
        csv_name="cabin_traffic.csv",
    ),
    DomainConfig(
        name="maintenance",
        data_format="PCAP",
        ip_prefix="192.168.2",
        ip_octets=3,
        protocol="tcp",
        ports=(22, 8080),
        port_range=None,
        packet_size=202,
        frequency=50,
        pcap_name="maintenance_traffic.pcap",
        csv_name="maintenance_traffic.csv",
    ),
    DomainConfig(
        name="afdx",
        data_format="PCAP",
        ip_prefix="10.0",
        ip_octets=2,
        protocol="udp",
        ports=(),
        port_range=(7000, 8000),
        packet_size=74,
        frequency=200,
        pcap_name="afdx_traffic.pcap",
        csv_name="afdx_traffic.csv",
    ),
    DomainConfig(
        name="avionics",
        data_format="ARINC429",
        ip_prefix="10.0",
        ip_octets=2,
        protocol="udp",
        ports=(),
        port_range=(7000, 8000),
        packet_size=74,
        frequency=200,
        pcap_name=None,
        csv_name="avionics_traffic_arinc429.csv",
    ),
)

DOMAIN_NETWORKS = {
    "cabin": ("192.168.1", 3),
    "maintenance": ("192.168.2", 3),
    "afdx": ("10.0", 2),
}
SENSITIVE_PORTS = (23, 502, 2404, 161)


@dataclass
class DomainMetrics:
    domain: str
    records: int = 0
    normal_records: int = 0
    anomaly_records: int = 0
    duration_sec: float = 0.0

    @property
    def throughput(self) -> float:
        return self.records / self.duration_sec if self.duration_sec else 0.0


def utc_timestamp() -> str:
    return datetime.now(UTC).isoformat()


def load_scenario_yaml(
    scenario_name: str, scenario_dir: Path | str = DEFAULT_SCENARIO_DIR
) -> dict[str, Any]:
    scenario_path = Path(scenario_dir) / f"{scenario_name}.yaml"
    if not scenario_path.exists():
        raise FileNotFoundError(f"Scenario file not found: {scenario_path}")

    with scenario_path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def random_ip(prefix: str, octets: int) -> str:
    if octets == 3:
        return f"{prefix}.{random.randint(1, 254)}"
    return f"{prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def adjusted_packet_size(domain: DomainConfig, anomaly_type: str | None) -> int:
    if anomaly_type in {
        "command_injection",
        "control_surface_tampering",
        "data_injection",
        "data_exfiltration",
    }:
        return max(domain.packet_size * 3, 5000)
    return domain.packet_size


def adjusted_frequency(domain: DomainConfig, anomaly_type: str | None) -> int:
    if anomaly_type in {
        "burst_traffic",
        "network_scan",
        "replay_attack",
        "command_duplication",
        "sequence_violation",
    }:
        return domain.frequency * 5
    return domain.frequency


def _other_domain_ip(domain: DomainConfig) -> str:
    choices = [
        (prefix, octets)
        for name, (prefix, octets) in DOMAIN_NETWORKS.items()
        if name != domain.name
    ]
    prefix, octets = random.choice(choices)
    return random_ip(prefix, octets)


def _expected_port(domain: DomainConfig) -> int:
    if domain.protocol == "tcp":
        return random.choice(domain.ports)
    low, high = domain.port_range or (1024, 65535)
    return random.randint(low, high)


def generate_pcap_record(
    domain: DomainConfig, anomaly: bool, anomaly_type: str | None
) -> tuple[Any, dict[str, Any]]:
    src_ip = random_ip(domain.ip_prefix, domain.ip_octets)
    dst_ip = random_ip(domain.ip_prefix, domain.ip_octets)
    src_port = random.randint(1024, 65535)
    packet_size = adjusted_packet_size(domain, anomaly_type if anomaly else None)
    frequency = adjusted_frequency(domain, anomaly_type if anomaly else None)
    cross_domain_flag = 0
    port_anomaly_flag = 0
    protocol_anomaly_flag = 0

    if anomaly and anomaly_type == "lateral_movement":
        dst_ip = _other_domain_ip(domain)
        cross_domain_flag = 1

    if anomaly and anomaly_type in {"command_injection", "control_surface_tampering"}:
        dst_port = random.choice(SENSITIVE_PORTS)
        port_anomaly_flag = 1
    else:
        dst_port = _expected_port(domain)

    if domain.protocol == "tcp":
        transport = TCP(sport=src_port, dport=dst_port)
    else:
        transport = UDP(sport=src_port, dport=dst_port)

    payload_len = max(packet_size, 1)
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=src_ip, dst=dst_ip)
        / transport
        / Raw(load=b"\x00" * payload_len)
    )

    return packet, {
        "timestamp": utc_timestamp(),
        "data_format": "PCAP",
        "domain": domain.name,
        "protocol": domain.protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src": src_ip,
        "dst": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "port": dst_port,
        "packet_size": payload_len,
        "frequency": frequency,
        "cross_domain_flag": cross_domain_flag,
        "port_anomaly_flag": port_anomaly_flag,
        "protocol_anomaly_flag": protocol_anomaly_flag,
        "is_anomaly": int(anomaly),
        "anomaly_type": anomaly_type if anomaly else "none",
    }


def odd_parity_bit(payload31: int) -> int:
    ones = payload31.bit_count()
    return 0 if ones % 2 else 1


def generate_arinc_record(anomaly: bool, anomaly_type: str | None) -> dict[str, Any]:
    label = random.choice(("203", "206", "360"))
    label_int = int(label, 8)
    data_bits_int = random.randint(0, (1 << 19) - 1)
    if anomaly and anomaly_type in {"command_injection", "control_surface_tampering", "data_injection"}:
        data_bits_int = random.randint((1 << 18), (1 << 19) - 1)

    ssm_bits = "00" if anomaly else "11"
    frequency = 1000 if anomaly_type in {"burst_traffic", "replay_attack"} else 200

    payload31 = (label_int << 23) | (data_bits_int << 4) | (int(ssm_bits, 2) << 2)
    parity = odd_parity_bit(payload31)
    word = (parity << 31) | payload31

    if anomaly and anomaly_type in {"replay_attack", "bit_flip", "data_injection"}:
        # Flip an odd number of observable bits so parity_valid=0 is visible.
        word ^= 0x1

    return {
        "timestamp": utc_timestamp(),
        "data_format": "ARINC429",
        "domain": "avionics",
        "label_octal": label,
        "src": label,
        "raw_hex": f"0x{word:08X}",
        "data_bits": f"{data_bits_int:019b}",
        "ssm_bits": ssm_bits,
        "frequency": frequency,
        "is_anomaly": int(anomaly),
        "anomaly_type": anomaly_type if anomaly else "none",
    }


class TrafficGenerator:
    def __init__(
        self,
        scenario: dict[str, Any],
        duration_sec: int,
        output_dir: Path | str = DEFAULT_OUTPUT_DIR,
    ) -> None:
        self.scenario = scenario
        self.duration_sec = duration_sec
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def in_attack_window(self, elapsed: float) -> bool:
        start_ratio = self.scenario.get("attack_window_start")
        if start_ratio is None:
            return False

        window_start = self.duration_sec * float(start_ratio)
        window_duration = self.duration_sec * float(
            self.scenario.get("attack_window_duration", 0.2)
        )
        return window_start <= elapsed <= window_start + window_duration

    def should_inject_anomaly(self, elapsed: float) -> bool:
        baseline_rate = 0.01
        if self.in_attack_window(elapsed):
            return random.random() < float(self.scenario.get("anomaly_rate", 0.15))
        return random.random() < baseline_rate

    def anomaly_type(self) -> str:
        attack_types = [
            item
            for item in self.scenario.get("attack_types", ("none",))
            if item and item != "none"
        ]
        return random.choice(attack_types or ["baseline_noise"])

    def generate_domain(self, domain: DomainConfig) -> DomainMetrics:
        start_time = time.monotonic()
        next_record_time = 0.0
        interval = 1.0 / domain.frequency
        packets: list[Any] = []
        records: list[dict[str, Any]] = []
        label_rows: list[dict[str, Any]] = []
        metrics = DomainMetrics(domain=domain.name)

        while True:
            elapsed = time.monotonic() - start_time
            if elapsed >= self.duration_sec:
                break

            sleep_for = next_record_time - elapsed
            if sleep_for > 0:
                time.sleep(min(sleep_for, 0.01))
                continue

            anomaly = self.should_inject_anomaly(elapsed)
            anomaly_type = self.anomaly_type() if anomaly else None

            if domain.data_format == "PCAP":
                packet, record = generate_pcap_record(domain, anomaly, anomaly_type)
                packets.append(packet)
            else:
                record = generate_arinc_record(anomaly, anomaly_type)

            records.append(record)
            if domain.data_format == "PCAP":
                label_rows.append(
                    {
                        "packet_index": len(records) - 1,
                        "is_anomaly": record["is_anomaly"],
                        "anomaly_type": record["anomaly_type"],
                    }
                )
            metrics.records += 1
            metrics.anomaly_records += int(anomaly)
            metrics.normal_records += int(not anomaly)
            next_record_time += interval

        metrics.duration_sec = time.monotonic() - start_time
        self.write_outputs(domain, packets, records, label_rows)
        return metrics

    def write_outputs(
        self,
        domain: DomainConfig,
        packets: list[Any],
        records: list[dict[str, Any]],
        label_rows: list[dict[str, Any]],
    ) -> None:
        if packets and domain.pcap_name:
            pcap_path = self.output_dir / domain.pcap_name
            wrpcap(str(pcap_path), packets)
            LOGGER.info("Wrote %s (%d packets)", pcap_path, len(packets))

        if records:
            csv_path = self.output_dir / domain.csv_name
            with csv_path.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=records[0].keys())
                writer.writeheader()
                writer.writerows(records)
            LOGGER.info("Wrote %s (%d records)", csv_path, len(records))

        if label_rows and domain.pcap_name:
            label_path = self.output_dir / f"{Path(domain.pcap_name).stem}_labels.csv"
            with label_path.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=label_rows[0].keys())
                writer.writeheader()
                writer.writerows(label_rows)
            LOGGER.info("Wrote %s (%d labels)", label_path, len(label_rows))

    def generate_all_domains(self) -> list[DomainMetrics]:
        scenario_name = self.scenario.get("name", "unknown")
        LOGGER.info(
            "Generating scenario=%s duration=%ss output=%s",
            scenario_name,
            self.duration_sec,
            self.output_dir,
        )
        return [self.generate_domain(domain) for domain in DOMAINS]


def event_from_record(record: dict[str, str]) -> dict[str, Any]:
    if record.get("data_format") == "ARINC429":
        return {
            "data_format": "ARINC429",
            "raw_hex": record["raw_hex"],
            "data_bits": record["data_bits"],
            "ssm_bits": record["ssm_bits"],
            "label_octal": record.get("label_octal", record.get("src", "")),
            "src": record.get("src", record.get("label_octal", "")),
            "frequency": float(record.get("frequency", 0)),
        }

    return {
        "data_format": "PCAP",
        "domain": record["domain"],
        "packet_size": float(record["packet_size"]),
        "frequency": float(record["frequency"]),
        "cross_domain_flag": int(record.get("cross_domain_flag", 0)),
        "port_anomaly_flag": int(record.get("port_anomaly_flag", 0)),
        "protocol_anomaly_flag": int(record.get("protocol_anomaly_flag", 0)),
    }


def default_score_path(csv_file: Path) -> Path:
    return csv_file.with_name(f"{csv_file.stem}_scores.csv")


def test_anomaly_detection(
    csv_file: Path | str, output_file: Path | str | None = None
) -> dict[str, float | int]:
    if score_event is None:
        raise RuntimeError("backend.detection.anomaly_model.score_event is unavailable")

    csv_path = Path(csv_file)
    output_path = Path(output_file) if output_file else default_score_path(csv_path)
    results: dict[str, float | int] = {
        "total_records": 0,
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "detection_rate": 0.0,
        "false_positive_rate": 0.0,
        "processing_time_sec": 0.0,
        "throughput_records_per_sec": 0.0,
    }
    scored_rows: list[dict[str, Any]] = []
    started = time.monotonic()

    with csv_path.open("r", newline="", encoding="utf-8") as file:
        for record in csv.DictReader(file):
            results["total_records"] += 1
            score = score_event(event_from_record(record))
            predicted = int(score["predicted_anomaly"])
            expected = int(record.get("is_anomaly", "0"))

            if predicted and expected:
                results["true_positives"] += 1
            elif predicted and not expected:
                results["false_positives"] += 1
            elif expected and not predicted:
                results["false_negatives"] += 1

            scored_rows.append(
                {
                    **record,
                    "anomaly_score": score["anomaly_score"],
                    "predicted_anomaly": predicted,
                    "severity": score["severity"],
                    "model_used": score["model_used"],
                }
            )

    elapsed = time.monotonic() - started
    total = int(results["total_records"])
    true_positives = int(results["true_positives"])
    false_positives = int(results["false_positives"])
    false_negatives = int(results["false_negatives"])
    total_anomalies = true_positives + false_negatives
    total_normal = total - total_anomalies

    results["processing_time_sec"] = elapsed
    results["throughput_records_per_sec"] = total / elapsed if elapsed else 0.0
    if total_anomalies:
        results["detection_rate"] = true_positives / total_anomalies
    if total_normal:
        results["false_positive_rate"] = false_positives / total_normal

    if scored_rows:
        with output_path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=scored_rows[0].keys())
            writer.writeheader()
            writer.writerows(scored_rows)

    LOGGER.info(
        "Scored %s: total=%d detection_rate=%.1f%% false_positive_rate=%.1f%% output=%s",
        csv_path,
        total,
        float(results["detection_rate"]) * 100,
        float(results["false_positive_rate"]) * 100,
        output_path,
    )
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate BlueBox demo traffic and optionally score it."
    )
    parser.add_argument("--scenario", choices=(*SCENARIOS, "all"), default="normal")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--yaml-dir", type=Path, default=DEFAULT_SCENARIO_DIR)
    parser.add_argument("--test", action="store_true", help="Score generated CSV files")
    parser.add_argument("--test-only", type=Path, help="Score an existing CSV file")
    parser.add_argument("--seed", type=int, help="Random seed for repeatable output")
    return parser


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = build_parser().parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.test_only:
        test_anomaly_detection(args.test_only)
        return 0

    scenario_names = SCENARIOS if args.scenario == "all" else (args.scenario,)
    for scenario_name in scenario_names:
        scenario = load_scenario_yaml(scenario_name, args.yaml_dir)
        output_dir = args.output_dir / scenario_name if args.scenario == "all" else args.output_dir
        metrics = TrafficGenerator(scenario, args.duration, output_dir).generate_all_domains()
        for item in metrics:
            LOGGER.info(
                "%s records=%d normal=%d anomaly=%d throughput=%.0f records/sec",
                item.domain,
                item.records,
                item.normal_records,
                item.anomaly_records,
                item.throughput,
            )

        if args.test:
            for csv_path in sorted(output_dir.glob("*.csv")):
                if csv_path.stem.endswith("_scores") or csv_path.stem.endswith("_labels"):
                    continue
                test_anomaly_detection(csv_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
