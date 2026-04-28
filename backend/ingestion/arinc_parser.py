"""
BlueBox ARINC 429 parser.

Reads `data/raw/arinc429_logs.csv` and emits a DataFrame in the unified schema:

    timestamp, domain, data_format, src, dst, packet_size,
    frequency, protocol, label

Mappings:
  - domain       = "avionics"
  - data_format  = "ARINC429"
  - src          = label_octal (the ARINC 429 label)
  - dst          = "BUS_A"
  - packet_size  = ceil(len(data_bits) / 8)  (data field length in bytes)
  - frequency    = rolling word rate per second (global)
  - protocol     = "ARINC429"
  - label        = is_anomaly
"""

import math

import pandas as pd


UNIFIED_COLUMNS = [
    "timestamp", "domain", "data_format", "src", "dst",
    "packet_size", "frequency", "protocol", "port", "is_anomaly",
]


def _data_bits_bytes(s) -> int:
    """Length in bytes of the data_bits binary string field."""
    if not isinstance(s, str):
        return 0
    return math.ceil(len(s) / 8)


def _rolling_word_rate(timestamps: pd.Series) -> pd.Series:
    """Rolling 1-second word count, aligned to the input series index."""
    t_dt = pd.to_datetime(timestamps, unit="s")
    tmp = pd.DataFrame({"t_dt": t_dt, "n": 1}).sort_values("t_dt")
    counts = tmp.set_index("t_dt")["n"].rolling("1s").count().astype(int)
    tmp["frequency"] = counts.values
    return tmp.sort_index()["frequency"]


def parse_arinc(csv_path: str = "data/raw/arinc429_logs.csv") -> pd.DataFrame:
    """Parse the ARINC 429 CSV into the unified schema."""
    raw = pd.read_csv(csv_path)

    df = pd.DataFrame({
        "timestamp":   raw["timestamp"].astype(float),
        "domain":      "avionics",
        "data_format": "ARINC429",
        "src":         raw["label_octal"].astype(str),
        "dst":         "BUS_A",
        "packet_size": raw["data_bits"].apply(_data_bits_bytes).astype(int),
        "protocol":    "ARINC429",
        # ARINC 429 has no concept of a port; fill with 0 to match unified schema.
        "port":        0,
        "is_anomaly":  raw["is_anomaly"].astype(int),
    })
    df["frequency"] = _rolling_word_rate(df["timestamp"])
    return df[UNIFIED_COLUMNS]


if __name__ == "__main__":
    df = parse_arinc()
    print(f"Parsed {len(df)} ARINC 429 words")
    print(f"Anomalies: {int(df['is_anomaly'].sum())}")
    print(f"Frequency range: {df['frequency'].min()} - {df['frequency'].max()}")
    print(df.head())
