"""
BlueBox ingestion runner.

End-to-end: parse PCAPs + ARINC 429, normalize, write unified CSV, and
verify the output. Run from the repo root:

    python backend/ingestion/run_ingestion.py
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from backend.ingestion import normalizer  # noqa: E402


def main():
    print("Running BlueBox ingestion pipeline...")
    df = normalizer.normalize()

    out = normalizer.OUTPUT_PATH
    if os.path.exists(out) and os.path.getsize(out) > 0:
        print(f"SUCCESS: wrote {len(df)} rows to {out} "
              f"({os.path.getsize(out)} bytes)")
        return 0
    print(f"FAILURE: expected output at {out} but it is missing or empty")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
