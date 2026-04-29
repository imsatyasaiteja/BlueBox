"""
BlueBox anomaly detection — dual Isolation Forest architecture.

One model per data format, each trained on format-appropriate features:

  PCAP model   (models/isolation_forest_pcap.pkl)
    features:  packet_size_zscore_upper, frequency_zscore_upper
               Upper-tail z-scores (max(0, z)) are used rather than raw
               packet_size + frequency for two reasons:
               (a) Raw packet_size is multimodal across domains (AFDX=74,
                   maintenance=202, cabin=458) causing normal AFDX rows to
                   look isolated compared to cabin/maintenance in the combined
                   model — false positives that eat the contamination budget.
               (b) Rolling-window ramp-up produces extreme *negative* z-scores
                   on normal early packets; upper-tail clipping ensures only
                   above-mean values (burst anomalies) register as anomalous.
    stats:     models/pcap_domain_stats.json

  ARINC429 model  (models/isolation_forest_arinc.pkl)
    features:  ssm_int, parity_valid, data_bits_zscore, frequency
               parity_valid (1=correct, 0=violated) replaces the raw
               parity_bit field because raw parity_bit=0 is valid for normal
               words when bits 1-31 already have an odd 1-count. The
               correct test is to recompute expected parity from the full word
               (read from raw_hex). Critically, SSM corruption that flips a
               single bit also invalidates parity, so parity_valid catches both
               SSM-single-flip and parity-flip anomalies simultaneously.
               data_bits_zscore: per-label normalisation prevents high-altitude
               BNR values (data_bits_int near 524287) from looking anomalous
               when compared to heading words (valid range ~0-131071).
    stats:     models/arinc_label_stats.json

The public entry point for the FastAPI /predict endpoint is score_event().
"""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_IN      = PROJECT_ROOT / "data" / "normalized" / "traffic_normalized.csv"
DATA_OUT     = PROJECT_ROOT / "data" / "normalized" / "traffic_scored.csv"
ARINC_RAW    = PROJECT_ROOT / "data" / "raw" / "arinc429_logs.csv"
MODELS_DIR   = PROJECT_ROOT / "models"

PCAP_MODEL_PATH  = MODELS_DIR / "isolation_forest_pcap.pkl"
ARINC_MODEL_PATH = MODELS_DIR / "isolation_forest_arinc.pkl"
PCAP_STATS_PATH  = MODELS_DIR / "pcap_domain_stats.json"
ARINC_STATS_PATH = MODELS_DIR / "arinc_label_stats.json"

SEVERITY_THRESHOLDS = [(-0.1, "HIGH"), (0.0, "MEDIUM"), (0.05, "LOW")]

_PCAP_MODEL  = None
_ARINC_MODEL = None
_PCAP_STATS  = None
_ARINC_STATS = None


def _ensure_loaded():
    global _PCAP_MODEL, _ARINC_MODEL, _PCAP_STATS, _ARINC_STATS
    if _PCAP_MODEL is None:
        _PCAP_MODEL  = joblib.load(PCAP_MODEL_PATH)
        _ARINC_MODEL = joblib.load(ARINC_MODEL_PATH)
        _PCAP_STATS  = json.loads(PCAP_STATS_PATH.read_text())
        _ARINC_STATS = json.loads(ARINC_STATS_PATH.read_text())


def _severity(score: float) -> str:
    for cutoff, label in SEVERITY_THRESHOLDS:
        if score < cutoff:
            return label
    return "NONE"


# ── ARINC parity helper ───────────────────────────────────────────────────────

def _parity_valid(raw_hex_str: str) -> int:
    """Return 1 if the 32-bit word's parity is correct (odd), 0 otherwise.

    Recomputes expected parity from bits 1-31 of the word and compares against
    actual bit 32. This is the clean binary anomaly signal: parity-flip anomalies
    set it to 0, and SSM corruptions that flip an odd number of SSM bits (e.g.
    3→1 or 3→2) also set it to 0 — so a single feature catches both types.
    """
    word = int(raw_hex_str, 16) & 0xFFFFFFFF
    x, p = word & 0x7FFFFFFF, 0
    while x:
        p ^= x & 1
        x >>= 1
    expected = 1 ^ p          # 1 if bits 1-31 have even count, 0 otherwise
    actual   = (word >> 31) & 1
    return int(expected == actual)


# ── PCAP helpers ──────────────────────────────────────────────────────────────

def compute_pcap_domain_stats(pcap_df: pd.DataFrame) -> dict:
    """Per-domain mean + population std computed from NORMAL rows only.

    Using only is_anomaly==0 rows gives a clean baseline uncontaminated by
    the 12 size anomalies that would inflate packet_size_std and by the 48
    burst anomalies that would inflate frequency_std — both effects deflate
    z-scores for true anomalies and hurt model separation.
    """
    stats = {}
    normal = pcap_df[pcap_df["is_anomaly"] == 0]
    for domain, grp in normal.groupby("domain"):
        stats[domain] = {
            "packet_size_mean": float(grp["packet_size"].mean()),
            "packet_size_std":  max(float(grp["packet_size"].std(ddof=0)), 1.0),
            "frequency_mean":   float(grp["frequency"].mean()),
            "frequency_std":    max(float(grp["frequency"].std(ddof=0)), 1.0),
        }
    return stats


def apply_pcap_zscores(df: pd.DataFrame, stats: dict) -> pd.DataFrame:
    """Add upper-tail z-score features. Returns a copy."""
    df = df.copy()
    ps_mean = df["domain"].map(lambda d: stats[d]["packet_size_mean"])
    ps_std  = df["domain"].map(lambda d: stats[d]["packet_size_std"])
    fr_mean = df["domain"].map(lambda d: stats[d]["frequency_mean"])
    fr_std  = df["domain"].map(lambda d: stats[d]["frequency_std"])
    df["packet_size_zscore"] = ((df["packet_size"] - ps_mean) / ps_std).clip(lower=0)
    df["frequency_zscore"]   = ((df["frequency"]   - fr_mean) / fr_std).clip(lower=0)
    return df


# ── ARINC helpers ─────────────────────────────────────────────────────────────

def compute_arinc_label_stats(merged: pd.DataFrame) -> dict:
    """Per-label mean + std for data_bits_int (src == label_octal string)."""
    stats = {}
    for label, grp in merged.groupby("src"):
        stats[str(label)] = {
            "data_bits_mean": float(grp["data_bits_int"].mean()),
            "data_bits_std":  max(float(grp["data_bits_int"].std(ddof=0)), 1.0),
        }
    return stats


def build_arinc_features(arinc_norm: pd.DataFrame,
                         label_stats: dict | None = None
                         ) -> tuple[pd.DataFrame, dict]:
    """Join raw ARINC CSV to recover bit fields; derive features. Returns (df, stats)."""
    raw = pd.read_csv(
        ARINC_RAW,
        dtype={"ssm_bits": str, "data_bits": str, "raw_hex": str},
    )
    merged = arinc_norm.merge(
        raw[["timestamp", "ssm_bits", "parity_bit", "data_bits", "raw_hex"]],
        on="timestamp", how="left",
    )
    assert merged["ssm_bits"].isnull().sum() == 0, (
        "ARINC join failed — timestamps don't match. Re-run data generation."
    )

    merged["ssm_int"]        = merged["ssm_bits"].apply(lambda s: int(str(s), 2))
    merged["data_bits_int"]  = merged["data_bits"].apply(lambda s: int(str(s), 2))
    merged["parity_valid"]   = merged["raw_hex"].apply(_parity_valid)

    if label_stats is None:
        label_stats = compute_arinc_label_stats(merged)

    merged["data_bits_zscore"] = merged.apply(
        lambda r: (
            (r["data_bits_int"] - label_stats[str(r["src"])]["data_bits_mean"])
            / label_stats[str(r["src"])]["data_bits_std"]
        ), axis=1,
    )
    return merged, label_stats


# ── Public runtime function ───────────────────────────────────────────────────

def score_event(event: dict) -> dict:
    """Score a single raw event dict, routing to the correct model by data_format.

    PCAP events need: data_format, domain, packet_size, frequency.
    ARINC429 events additionally need: raw_hex (the full 32-bit word as a hex
    string, e.g. '0xF85E7E61'), data_bits, label_octal (or src).

    Returns anomaly_score, predicted_anomaly, severity, model_used.
    """
    _ensure_loaded()
    fmt = event["data_format"]

    if fmt == "PCAP":
        stats = _PCAP_STATS[event["domain"]]
        ps    = float(event["packet_size"])
        fr    = float(event["frequency"])
        ps_z  = max(0.0, (ps - stats["packet_size_mean"]) / stats["packet_size_std"])
        fr_z  = max(0.0, (fr - stats["frequency_mean"])   / stats["frequency_std"])
        X     = np.array([[ps_z, fr_z]])
        model = _PCAP_MODEL
    else:  # ARINC429
        ssm     = int(str(event.get("ssm_bits",  "11")), 2)
        pv      = _parity_valid(str(event.get("raw_hex", "0x0")))
        label   = str(event.get("label_octal", event.get("src", "")))
        raw_d   = int(str(event.get("data_bits", "0" * 19)), 2)
        lst     = _ARINC_STATS.get(label, {"data_bits_mean": 0.0, "data_bits_std": 1.0})
        data_z  = (raw_d - lst["data_bits_mean"]) / lst["data_bits_std"]
        X       = np.array([[ssm, pv, data_z, float(event["frequency"])]])
        model   = _ARINC_MODEL

    score     = float(model.decision_function(X)[0])
    predicted = int(model.predict(X)[0] == -1)
    return {
        "anomaly_score":     score,
        "predicted_anomaly": predicted,
        "severity":          _severity(score),
        "model_used":        fmt,
    }


# ── Training + evaluation ─────────────────────────────────────────────────────

def _print_eval(name: str, y_true, predicted, scores, domain_col=None):
    print(f"\n{'=' * 70}")
    print(f"  {name} model evaluation")
    print(f"{'=' * 70}")
    print(classification_report(y_true, predicted, target_names=["normal", "anomaly"]))

    cm = confusion_matrix(y_true, predicted)
    tn, fp, fn, tp = cm.ravel()
    print("Confusion matrix:")
    print(f"               pred_normal   pred_anomaly")
    print(f"  true_normal  {tn:>11d}   {fp:>12d}")
    print(f"  true_anomaly {fn:>11d}   {tp:>12d}")
    print()

    dr  = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    acc = (tp + tn) / cm.sum()
    print("KPIs")
    print(f"  Detection rate : {dr:.4f}  {'✓' if dr >= 0.85 else '✗ (target ≥ 0.85)'}")
    print(f"  FPR            : {fpr:.4f}  {'✓' if fpr <= 0.05 else '✗ (target ≤ 0.05)'}")
    print(f"  Accuracy       : {acc:.4f}")

    if domain_col is not None:
        print("\nPer-domain detection rate:")
        tmp = pd.DataFrame({"domain": domain_col, "y": y_true, "pred": predicted})
        for d in sorted(tmp["domain"].unique()):
            sub  = tmp[tmp["domain"] == d]
            anom = sub[sub["y"] == 1]
            if not len(anom): continue
            caught = int((anom["pred"] == 1).sum())
            print(f"    {d:>12s}: {caught:>3d}/{len(anom):<3d}  ({caught/len(anom):.1%})")

    mn = float(np.mean(scores[y_true == 0]))
    ma = float(np.mean(scores[y_true == 1]))
    print(f"\nScore distribution:")
    print(f"  is_anomaly=0 mean: {mn:+.4f}")
    print(f"  is_anomaly=1 mean: {ma:+.4f}")


def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(DATA_IN)

    # ── PCAP model ────────────────────────────────────────────────────────────
    pcap_df = df[df["data_format"] == "PCAP"].copy()
    pcap_stats = compute_pcap_domain_stats(pcap_df)
    with open(PCAP_STATS_PATH, "w") as fh:
        json.dump(pcap_stats, fh, indent=2)

    pcap_df = apply_pcap_zscores(pcap_df, pcap_stats)
    X_pcap  = pcap_df[["packet_size_zscore", "frequency_zscore"]].values
    y_pcap  = pcap_df["is_anomaly"].astype(int).values

    # Tiny Gaussian jitter (σ=0.01) breaks exact identical clusters.
    # The 12 size anomalies per domain all have the same z-score (simulator
    # uses a constant anomaly size), so IsolationForest applies the cluster
    # correction c(12)≈4.1 which inflates their path length and suppresses
    # their anomaly score. Jitter forces individual isolation paths at <0.1%
    # perturbation, which has no practical effect on the feature distribution.
    rng = np.random.default_rng(42)
    X_pcap_train = X_pcap + rng.normal(0, 0.01, X_pcap.shape)

    pcap_model = IsolationForest(contamination=0.02, n_estimators=200, random_state=42)
    pcap_model.fit(X_pcap_train)
    joblib.dump(pcap_model, PCAP_MODEL_PATH)

    pcap_pred   = (pcap_model.predict(X_pcap) == -1).astype(int)
    pcap_scores = pcap_model.decision_function(X_pcap)
    _print_eval("PCAP", y_pcap, pcap_pred, pcap_scores,
                domain_col=pcap_df["domain"].values)

    # ── ARINC429 model ────────────────────────────────────────────────────────
    arinc_norm = df[df["data_format"] == "ARINC429"].copy()
    arinc_merged, arinc_label_stats = build_arinc_features(arinc_norm)
    with open(ARINC_STATS_PATH, "w") as fh:
        json.dump(arinc_label_stats, fh, indent=2)

    X_arinc = arinc_merged[["ssm_int", "parity_valid",
                              "data_bits_zscore", "frequency"]].values
    y_arinc = arinc_merged["is_anomaly"].astype(int).values

    arinc_model = IsolationForest(contamination=0.02, n_estimators=200, random_state=42)
    arinc_model.fit(X_arinc)
    joblib.dump(arinc_model, ARINC_MODEL_PATH)

    arinc_pred   = (arinc_model.predict(X_arinc) == -1).astype(int)
    arinc_scores = arinc_model.decision_function(X_arinc)
    _print_eval("ARINC429", y_arinc, arinc_pred, arinc_scores)

    # ── Assemble scored CSV ───────────────────────────────────────────────────
    result = df.copy()
    result["anomaly_score"]     = 0.0
    result["predicted_anomaly"] = 0
    result["severity"]          = "NONE"
    result["model_used"]        = ""

    pi = result.index[result["data_format"] == "PCAP"]
    ai = result.index[result["data_format"] == "ARINC429"]

    result.loc[pi, "anomaly_score"]     = pcap_scores
    result.loc[pi, "predicted_anomaly"] = pcap_pred
    result.loc[pi, "severity"]          = [_severity(s) for s in pcap_scores]
    result.loc[pi, "model_used"]        = "PCAP"

    result.loc[ai, "anomaly_score"]     = arinc_scores
    result.loc[ai, "predicted_anomaly"] = arinc_pred
    result.loc[ai, "severity"]          = [_severity(s) for s in arinc_scores]
    result.loc[ai, "model_used"]        = "ARINC429"

    result.to_csv(DATA_OUT, index=False)
    print(f"\nScored CSV: {DATA_OUT}  ({len(result)} rows)")
    print(f"  severity:\n{result['severity'].value_counts().to_string()}")

    # ── Smoke-test score_event ────────────────────────────────────────────────
    print("\nSmoke test — score_event():")
    print("-" * 70)
    # PCAP size anomaly (packet_size=4946)
    size_row = pcap_df[(pcap_df["is_anomaly"] == 1) & (pcap_df["packet_size"] > 1000)]
    if len(size_row):
        r = {**size_row.iloc[0].to_dict(), "data_format": "PCAP"}
        res = score_event(r)
        print(f"  [PCAP size anom]  ps={r['packet_size']:.0f}  "
              f"score={res['anomaly_score']:+.4f}  pred={res['predicted_anomaly']}  "
              f"sev={res['severity']}")
    # PCAP normal row
    r_n = {**pcap_df[pcap_df["is_anomaly"] == 0].iloc[200].to_dict(), "data_format": "PCAP"}
    res_n = score_event(r_n)
    print(f"  [PCAP normal]     ps={r_n['packet_size']:.0f}  "
          f"score={res_n['anomaly_score']:+.4f}  pred={res_n['predicted_anomaly']}  "
          f"sev={res_n['severity']}")
    # ARINC anomaly
    arinc_anom = arinc_merged[arinc_merged["is_anomaly"] == 1].iloc[0]
    arinc_event = {
        "data_format": "ARINC429",
        "ssm_bits":   arinc_anom["ssm_bits"],
        "raw_hex":    arinc_anom["raw_hex"],
        "data_bits":  arinc_anom["data_bits"],
        "frequency":  float(arinc_anom["frequency"]),
        "src":        str(arinc_anom["src"]),
    }
    res_a = score_event(arinc_event)
    print(f"  [ARINC anomaly]   ssm={arinc_anom['ssm_bits']}  "
          f"parity_valid={_parity_valid(arinc_anom['raw_hex'])}  "
          f"score={res_a['anomaly_score']:+.4f}  pred={res_a['predicted_anomaly']}  "
          f"sev={res_a['severity']}")

    print(f"\nSaved: {PCAP_MODEL_PATH}")
    print(f"Saved: {ARINC_MODEL_PATH}")
    print(f"Saved: {PCAP_STATS_PATH}")
    print(f"Saved: {ARINC_STATS_PATH}")


if __name__ == "__main__":
    main()
