"""
BlueBox normalization layer.

Concatenates the PCAP and ARINC 429 parsers into one DataFrame, cleans it,
and writes the unified CSV the Isolation Forest model will train on.
"""

import os
import sys

# Make repo root importable when this file is run as a script.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pandas as pd  # noqa: E402

from backend.ingestion import pcap_parser, arinc_parser  # noqa: E402


OUTPUT_PATH = "data/normalized/traffic_normalized.csv"

UNIFIED_COLUMNS = [
    "timestamp", "domain", "data_format", "src", "dst",
    "packet_size", "frequency", "protocol", "port", "is_anomaly",
]


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
