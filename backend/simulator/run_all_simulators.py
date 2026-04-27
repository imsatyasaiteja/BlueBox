"""
BlueBox simulator runner.

Invokes the PCAP simulator (cabin / maintenance / AFDX) and the ARINC 429
simulator, then prints a summary of every output artifact and its anomaly
rate. Run from the repo root:

    python backend/simulator/run_all_simulators.py
"""

import os
import sys

# Allow running this file directly: ensure the project root is on sys.path
# so the sibling modules import cleanly regardless of CWD.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from backend.simulator import pcap_simulator, arinc_simulator  # noqa: E402


def main():
    print("Running PCAP simulator...")
    pcap_summaries = pcap_simulator.generate()

    print("Running ARINC 429 simulator...")
    arinc_summary = arinc_simulator.generate()

    print()
    print("=" * 72)
    print(f"{'artifact':<40} {'count':>8} {'anomalies':>10} {'rate':>8}")
    print("-" * 72)
    for s in pcap_summaries:
        rate = 100.0 * s["anomalies"] / s["total"]
        print(f"{s['pcap']:<40} {s['total']:>8} {s['anomalies']:>10} "
              f"{rate:>7.2f}%")
    rate = 100.0 * arinc_summary["anomalies"] / arinc_summary["total"]
    print(f"{arinc_summary['csv']:<40} {arinc_summary['total']:>8} "
          f"{arinc_summary['anomalies']:>10} {rate:>7.2f}%")
    print("=" * 72)


if __name__ == "__main__":
    main()
