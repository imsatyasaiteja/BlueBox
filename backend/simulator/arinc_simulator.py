"""
BlueBox ARINC 429 simulator.

Synthesizes ~1000 32-bit ARINC 429 words covering airspeed (label 206),
altitude (label 203), and heading (label 360). About 2% of words are
anomalous: corrupted data bits, invalid SSM, or flipped parity.

Word layout (bit 1 = LSB ... bit 32 = MSB):
  bits 1-8   label    (transmitted in reversed bit order per the spec)
  bits 9-10  SDI      (source/destination identifier)
  bits 11-29 data     (19 bits, BNR-encoded value)
  bits 30-31 SSM      (sign/status matrix)
  bit  32    parity   (odd parity over bits 1-31)

We hand-pack the 32-bit word with bit operations rather than depending on
the niche `arinc429` PyPI package, since the format is simple and stable.
"""

import csv
import os
import random
import time

TOTAL_WORDS = 1000
ANOMALY_COUNT = 20  # ~2%

# Label catalog: octal label -> (description, value range, BNR scale, valid SSM bits).
# SSM for BNR words: 00=Failure Warning, 01=No Computed Data, 10=Functional Test, 11=Normal Op.
LABELS = {
    0o206: {"name": "airspeed",  "vmin": 0,    "vmax": 600,    "valid_ssm": [0b11]},
    0o203: {"name": "altitude",  "vmin": -1000, "vmax": 50000,  "valid_ssm": [0b11]},
    0o360: {"name": "heading",   "vmin": 0,    "vmax": 360,    "valid_ssm": [0b11]},
}


def _reverse_8(byte: int) -> int:
    """Reverse the bit order of an 8-bit value (ARINC 429 transmits label LSB-first)."""
    b = byte & 0xFF
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2)
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1)
    return b


def _odd_parity(word31: int) -> int:
    """Compute odd parity over the lower 31 bits."""
    x = word31 & 0x7FFFFFFF
    p = 0
    while x:
        p ^= x & 1
        x >>= 1
    # odd parity: total number of 1s (including parity bit) must be odd
    return 1 ^ p


def _encode_bnr(value: float, vmin: float, vmax: float, bits: int = 19) -> int:
    """Linear-scale a real-world value into an unsigned BNR field."""
    if vmax == vmin:
        return 0
    span = vmax - vmin
    norm = max(0.0, min(1.0, (value - vmin) / span))
    return int(norm * ((1 << bits) - 1)) & ((1 << bits) - 1)


def _pack_word(label_octal: int, sdi: int, data19: int, ssm: int,
               force_parity: int = None) -> int:
    """Pack fields into a 32-bit ARINC 429 word."""
    label_byte = _reverse_8(label_octal)
    word = label_byte & 0xFF
    word |= (sdi & 0x3) << 8
    word |= (data19 & 0x7FFFF) << 10
    word |= (ssm & 0x3) << 29
    parity = _odd_parity(word) if force_parity is None else force_parity
    word |= (parity & 0x1) << 31
    return word & 0xFFFFFFFF


def _make_normal_word(label_octal: int):
    """Return (word, fields_dict) for a clean, valid word for the given label."""
    spec = LABELS[label_octal]
    value = random.uniform(spec["vmin"], spec["vmax"])
    data19 = _encode_bnr(value, spec["vmin"], spec["vmax"])
    sdi = random.randint(0, 3)
    ssm = random.choice(spec["valid_ssm"])
    word = _pack_word(label_octal, sdi, data19, ssm)
    return word, {"label_octal": f"{label_octal:o}",
                  "sdi": sdi, "data19": data19, "ssm": ssm,
                  "parity": (word >> 31) & 1}


def _corrupt(word: int, label_octal: int):
    """Apply one of three anomaly mutations to a clean word."""
    kind = random.choice(["data", "ssm", "parity"])
    if kind == "data":
        # XOR a random subset of the 19 data bits.
        mask = random.randint(1, (1 << 19) - 1) << 10
        word ^= mask
    elif kind == "ssm":
        # Force an SSM that is NOT in the label's valid set.
        valid = set(LABELS[label_octal]["valid_ssm"])
        bad = random.choice([s for s in (0b00, 0b01, 0b10, 0b11) if s not in valid])
        word = (word & ~(0b11 << 29)) | (bad << 29)
    else:  # parity flip
        word ^= (1 << 31)
    return word, kind


def generate(seed: int = 1337,
             output_csv: str = "data/raw/arinc429_logs.csv"):
    """Generate the ARINC 429 log CSV. Returns a summary dict."""
    random.seed(seed)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    anomaly_indices = set(random.sample(range(TOTAL_WORDS), ANOMALY_COUNT))
    label_keys = list(LABELS.keys())

    rows = []
    t0 = time.time()
    for i in range(TOTAL_WORDS):
        label = random.choice(label_keys)
        word, fields = _make_normal_word(label)

        is_anom = 0
        if i in anomaly_indices:
            word, _kind = _corrupt(word, label)
            is_anom = 1
            # Refresh fields from the (possibly mutated) word.
            fields["data19"] = (word >> 10) & 0x7FFFF
            fields["ssm"] = (word >> 29) & 0x3
            fields["parity"] = (word >> 31) & 0x1

        ts = t0 + i * 0.001  # 1 kHz nominal cadence
        rows.append({
            "timestamp": f"{ts:.6f}",
            "label_octal": fields["label_octal"],
            "ssm_bits": f"{fields['ssm']:02b}",
            "data_bits": f"{fields['data19']:019b}",
            "parity_bit": fields["parity"],
            "raw_hex": f"0x{word:08X}",
            "is_anomaly": is_anom,
        })

    with open(output_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    return {
        "csv": output_csv,
        "total": TOTAL_WORDS,
        "anomalies": sum(r["is_anomaly"] for r in rows),
    }


if __name__ == "__main__":
    s = generate()
    pct = 100.0 * s["anomalies"] / s["total"]
    print(f"[arinc429] {s['total']} words, {s['anomalies']} anomalies "
          f"({pct:.2f}%) -> {s['csv']}")
