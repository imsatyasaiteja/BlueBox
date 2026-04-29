"""
BlueBox SHAP explainability layer.

Computes per-feature SHAP attributions for flagged anomalies from both the
PCAP and ARINC429 Isolation Forest models and generates human-readable
plain-English explanations driven by template logic (no LLM here).

Actual trained features (corrected from raw field names):
  PCAP model (2D)  : packet_size_zscore, frequency_zscore
  ARINC model (4D) : ssm_int, parity_valid, data_bits_zscore, frequency

Public API
----------
  explain_event(event: dict) -> dict
      Score a single raw event dict; returns shap_values, top_features,
      and explanation_text.

Run as __main__ to batch-explain all anomalies in traffic_scored.csv and
write data/explanations/anomaly_explanations.json.
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap

# Make repo root importable when run as a script.
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from backend.detection.anomaly_model import (  # noqa: E402
    _parity_valid,
    apply_pcap_zscores,
    build_arinc_features,
)

# ── Paths ─────────────────────────────────────────────────────────────────────

PROJECT_ROOT     = Path(__file__).resolve().parents[2]
DATA_SCORED      = PROJECT_ROOT / "data" / "normalized" / "traffic_scored.csv"
EXPLANATIONS_OUT = PROJECT_ROOT / "data" / "explanations" / "anomaly_explanations.json"
MODELS_DIR       = PROJECT_ROOT / "models"

# ── Feature names ─────────────────────────────────────────────────────────────

PCAP_FEATURES  = ["packet_size_zscore", "frequency_zscore"]
ARINC_FEATURES = ["ssm_int", "parity_valid", "data_bits_zscore", "frequency"]

# Maps internal trained-feature names to human-readable aliases used in output.
FEATURE_ALIAS = {
    "packet_size_zscore": "packet_size",
    "frequency_zscore":   "frequency",
    "ssm_int":            "ssm_bits",
    "parity_valid":       "parity_bit",
    "data_bits_zscore":   "data_bits",
    "frequency":          "frequency",
}

# ── Lazy-load cache ───────────────────────────────────────────────────────────

_PCAP_MODEL      = None
_ARINC_MODEL     = None
_PCAP_STATS      = None
_ARINC_STATS     = None
_PCAP_EXPLAINER  = None
_ARINC_EXPLAINER = None


def _ensure_loaded() -> None:
    global _PCAP_MODEL, _ARINC_MODEL, _PCAP_STATS, _ARINC_STATS
    global _PCAP_EXPLAINER, _ARINC_EXPLAINER
    if _PCAP_MODEL is not None:
        return
    _PCAP_MODEL  = joblib.load(MODELS_DIR / "isolation_forest_pcap.pkl")
    _ARINC_MODEL = joblib.load(MODELS_DIR / "isolation_forest_arinc.pkl")
    _PCAP_STATS  = json.loads((MODELS_DIR / "pcap_domain_stats.json").read_text())
    _ARINC_STATS = json.loads((MODELS_DIR / "arinc_label_stats.json").read_text())
    # tree_path_dependent avoids the need for a background dataset and works
    # correctly with IsolationForest's ExtraTreeRegressor internals.
    _PCAP_EXPLAINER  = shap.TreeExplainer(
        _PCAP_MODEL, feature_perturbation="tree_path_dependent"
    )
    _ARINC_EXPLAINER = shap.TreeExplainer(
        _ARINC_MODEL, feature_perturbation="tree_path_dependent"
    )


# ── Explanation text templates ─────────────────────────────────────────────────

def _pcap_explanation(top: list, event: dict, stats: dict, sv_dict: dict) -> str:
    domain       = event.get("domain", "")
    domain_stats = stats.get(domain, {})
    parts        = []

    # Only describe a feature as an anomaly driver if its SHAP value is negative
    # (negative = pushing the decision_function score down = more anomalous).
    # With only 2 PCAP features both always appear in top_features, so without
    # this guard a size-anomaly row would falsely claim a "frequency spike."
    if "packet_size" in top and sv_dict.get("packet_size", 0) < 0:
        mean = domain_stats.get("packet_size_mean", 0.0)
        parts.append(
            f"Anomaly driven by unusually large packet size "
            f"({int(event['packet_size'])} bytes vs domain average of {mean:.0f} bytes)."
        )
    if "frequency" in top and sv_dict.get("frequency", 0) < 0:
        mean = domain_stats.get("frequency_mean", 0.0)
        parts.append(
            f"Frequency spike detected "
            f"({float(event['frequency']):.0f} pps vs domain baseline of {mean:.0f} pps)."
        )
    return " ".join(parts) if parts else "Anomaly detected in PCAP traffic."


def _arinc_explanation(top: list, event: dict, sv_dict: dict) -> str:
    parts = []

    # Same sign guard: only describe a feature as an anomaly driver if SHAP < 0.
    if "ssm_bits" in top and sv_dict.get("ssm_bits", 0) < 0:
        parts.append("Invalid SSM bits detected — data validity flag is corrupted.")
    if "parity_bit" in top and sv_dict.get("parity_bit", 0) < 0:
        parts.append("Parity bit error — word integrity check failed.")
    if "data_bits" in top and sv_dict.get("data_bits", 0) < 0:
        label = event.get("src", "unknown")
        parts.append(f"Abnormal data field value on ARINC bus (label {label}).")
    if "frequency" in top and sv_dict.get("frequency", 0) < 0:
        freq = float(event.get("frequency", 0))
        parts.append(f"Anomalous word rate detected ({freq:.0f} words/s).")

    return " ".join(parts) if parts else "Anomaly detected in ARINC 429 traffic."


# ── Public API ────────────────────────────────────────────────────────────────

def explain_event(event: dict) -> dict:
    """
    Takes a single raw event dict (matching SCHEMA.md).
    Routes to the correct SHAP explainer based on event['data_format'].

    Returns:
      {
        shap_values:      dict   # feature_alias → shap value for this event
        top_features:     list   # top 2 features by absolute shap value
        explanation_text: str    # plain English, 1-2 sentences
      }

    PCAP events need: data_format, domain, packet_size, frequency.
    ARINC429 events additionally need: ssm_bits, raw_hex, data_bits, src.
    """
    _ensure_loaded()
    fmt = event["data_format"]

    if fmt == "PCAP":
        stats = _PCAP_STATS[event["domain"]]
        ps_z  = max(0.0, (float(event["packet_size"]) - stats["packet_size_mean"]) / stats["packet_size_std"])
        fr_z  = max(0.0, (float(event["frequency"])   - stats["frequency_mean"])   / stats["frequency_std"])
        X     = np.array([[ps_z, fr_z]])
        sv    = np.asarray(_PCAP_EXPLAINER.shap_values(X)).reshape(-1)  # (2,)
        sv_dict = {FEATURE_ALIAS[f]: float(v) for f, v in zip(PCAP_FEATURES, sv)}
        top     = sorted(sv_dict, key=lambda k: abs(sv_dict[k]), reverse=True)[:2]
        text    = _pcap_explanation(top, event, _PCAP_STATS, sv_dict)

    else:  # ARINC429
        label  = str(event.get("src", ""))
        ssm    = int(str(event.get("ssm_bits", "11")), 2)
        pv     = _parity_valid(str(event.get("raw_hex", "0x0")))
        raw_d  = int(str(event.get("data_bits", "0" * 19)), 2)
        lst    = _ARINC_STATS.get(label, {"data_bits_mean": 0.0, "data_bits_std": 1.0})
        data_z = (raw_d - lst["data_bits_mean"]) / lst["data_bits_std"]
        X      = np.array([[ssm, pv, data_z, float(event["frequency"])]])
        sv     = np.asarray(_ARINC_EXPLAINER.shap_values(X)).reshape(-1)  # (4,)
        sv_dict = {FEATURE_ALIAS[f]: float(v) for f, v in zip(ARINC_FEATURES, sv)}
        top     = sorted(sv_dict, key=lambda k: abs(sv_dict[k]), reverse=True)[:2]
        text    = _arinc_explanation(top, event, sv_dict)

    return {"shap_values": sv_dict, "top_features": top, "explanation_text": text}


# ── Batch helpers ─────────────────────────────────────────────────────────────

def _batch_pcap(pcap_df: pd.DataFrame) -> list:
    """Compute explanations for all PCAP anomalous rows in one pass."""
    feat_df = apply_pcap_zscores(pcap_df.copy(), _PCAP_STATS)
    X       = feat_df[PCAP_FEATURES].values
    sv_all  = np.asarray(_PCAP_EXPLAINER.shap_values(X))  # (n, 2)

    records = []
    for i, (_, row) in enumerate(pcap_df.iterrows()):
        sv_dict = {FEATURE_ALIAS[f]: float(v) for f, v in zip(PCAP_FEATURES, sv_all[i])}
        top     = sorted(sv_dict, key=lambda k: abs(sv_dict[k]), reverse=True)[:2]
        text    = _pcap_explanation(top, row.to_dict(), _PCAP_STATS, sv_dict)
        records.append({
            **row.to_dict(),
            "shap_values":      sv_dict,
            "top_features":     top,
            "explanation_text": text,
        })
    return records


def _batch_arinc(arinc_df: pd.DataFrame) -> list:
    """Compute explanations for all ARINC anomalous rows in one pass.

    Joins with the raw ARINC CSV (via build_arinc_features) to reconstruct
    ssm_int, parity_valid, and data_bits_zscore before computing SHAP.
    The joined columns are used only for feature computation and explanation
    templating; the output record retains only the original scored-CSV columns.
    """
    original_cols = list(arinc_df.columns)
    merged, _     = build_arinc_features(arinc_df.copy(), label_stats=_ARINC_STATS)
    X             = merged[ARINC_FEATURES].values
    sv_all        = np.asarray(_ARINC_EXPLAINER.shap_values(X))  # (n, 4)

    records = []
    for i, (_, row) in enumerate(merged.iterrows()):
        sv_dict = {FEATURE_ALIAS[f]: float(v) for f, v in zip(ARINC_FEATURES, sv_all[i])}
        top     = sorted(sv_dict, key=lambda k: abs(sv_dict[k]), reverse=True)[:2]
        # Pass full merged row (has ssm_bits) to the template, then strip to
        # original columns for the output record.
        text    = _arinc_explanation(top, row.to_dict(), sv_dict)
        base    = {col: row[col] for col in original_cols if col in row.index}
        records.append({
            **base,
            "shap_values":      sv_dict,
            "top_features":     top,
            "explanation_text": text,
        })
    return records


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    _ensure_loaded()

    scored     = pd.read_csv(DATA_SCORED)
    pcap_anom  = scored[(scored["data_format"] == "PCAP")    & (scored["predicted_anomaly"] == 1)].copy()
    arinc_anom = scored[(scored["data_format"] == "ARINC429") & (scored["predicted_anomaly"] == 1)].copy()

    pcap_records  = _batch_pcap(pcap_anom)
    arinc_records = _batch_arinc(arinc_anom)

    all_records = sorted(
        pcap_records + arinc_records,
        key=lambda r: float(r["timestamp"]),
    )

    EXPLANATIONS_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(EXPLANATIONS_OUT, "w") as fh:
        json.dump(all_records, fh, indent=2)
    print(f"Wrote {len(all_records)} explanations → {EXPLANATIONS_OUT}")

    # ── Sanity check — examples ───────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  3 PCAP examples (one per domain)")
    print("=" * 60)
    for domain in ["cabin", "maintenance", "afdx"]:
        ex = next((r for r in pcap_records if r["domain"] == domain), None)
        if ex:
            print(f"\n  [{domain}]")
            print(f"    shap_values:  {ex['shap_values']}")
            print(f"    top_features: {ex['top_features']}")
            print(f"    explanation:  {ex['explanation_text']}")

    print("\n" + "=" * 60)
    print("  2 ARINC examples")
    print("=" * 60)
    for ex in arinc_records[:2]:
        print(f"\n  [avionics / label {ex.get('src', '?')}]")
        print(f"    shap_values:  {ex['shap_values']}")
        print(f"    top_features: {ex['top_features']}")
        print(f"    explanation:  {ex['explanation_text']}")

    # ── Assertions ────────────────────────────────────────────────────────────
    assert all(len(r["top_features"]) == 2 for r in all_records), \
        "top_features must always have exactly 2 entries"
    assert all(r["explanation_text"] for r in all_records), \
        "explanation_text must never be empty"
    print(f"\nAll assertions passed.")
    print(f"Total explanations written: {len(all_records)}")


if __name__ == "__main__":
    main()
