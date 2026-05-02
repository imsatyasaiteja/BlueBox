"""
BlueBox anomaly detection — per-domain Isolation Forest architecture.

Three per-domain PCAP models (one per network domain) plus one ARINC429 model:

  PCAP models  — one per domain, trained only on that domain's rows:
    models/isolation_forest_pcap_cabin.pkl
    models/isolation_forest_pcap_maintenance.pkl
    models/isolation_forest_pcap_afdx.pkl
    features:  packet_size, frequency,
               packet_size_zscore, frequency_zscore (upper-tail clipped),
               cross_domain_flag, port_anomaly_flag, protocol_anomaly_flag
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

Per-domain PCAP models eliminate cross-domain feature leakage: anomaly semantics
differ by domain (e.g. afdx uses ports 7000-8000 which are legitimate there
but would pollute a combined model with 50% base rate on port_anomaly_flag).

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

ARINC_MODEL_PATH = MODELS_DIR / "isolation_forest_arinc.pkl"
PCAP_STATS_PATH  = MODELS_DIR / "pcap_domain_stats.json"
ARINC_STATS_PATH = MODELS_DIR / "arinc_label_stats.json"

# Canonical domain values as they appear in traffic_normalized.csv.
PCAP_DOMAINS = ["cabin", "maintenance", "afdx"]

# Model filename suffix == domain name (identity mapping; kept as a dict so
# _pcap_model_path stays a single, testable indirection point).
_DOMAIN_TO_MODEL_NAME = {
    "cabin":       "cabin",
    "maintenance": "maintenance",
    "afdx":        "afdx",
}

PCAP_FEATURES = [
    "packet_size", "frequency",
    "packet_size_zscore", "frequency_zscore",
    "cross_domain_flag", "port_anomaly_flag", "protocol_anomaly_flag",
]

SEVERITY_THRESHOLDS = [(-0.1, "HIGH"), (0.0, "MEDIUM"), (0.05, "LOW")]

# ── Lazy-load caches ──────────────────────────────────────────────────────────

_PCAP_MODELS: dict = {}   # keyed by domain name ("cabin", "maintenance", "afdx")
_ARINC_MODEL = None
_PCAP_STATS  = None
_ARINC_STATS = None


def _pcap_model_path(domain: str) -> Path:
    return MODELS_DIR / f"isolation_forest_pcap_{_DOMAIN_TO_MODEL_NAME[domain]}.pkl"


def _ensure_arinc_loaded() -> None:
    global _ARINC_MODEL, _ARINC_STATS
    if _ARINC_MODEL is None:
        _ARINC_MODEL = joblib.load(ARINC_MODEL_PATH)
        _ARINC_STATS = json.loads(ARINC_STATS_PATH.read_text())


def _ensure_pcap_loaded(domain: str) -> None:
    global _PCAP_STATS
    if domain not in _PCAP_MODELS:
        _PCAP_MODELS[domain] = joblib.load(_pcap_model_path(domain))
    if _PCAP_STATS is None:
        _PCAP_STATS = json.loads(PCAP_STATS_PATH.read_text())


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
    size/burst anomalies that would inflate the standard deviations and deflate
    z-scores for true anomalies.
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
    """Score a single raw event dict, routing to the correct model.

    PCAP events need: data_format, domain, packet_size, frequency.
    ARINC429 events additionally need: raw_hex (the full 32-bit word as a hex
    string, e.g. '0xF85E7E61'), data_bits, label_octal (or src).

    Returns anomaly_score, predicted_anomaly, severity, model_used.
    """
    fmt = event["data_format"]

    if fmt == "PCAP":
        domain = event["domain"]
        _ensure_pcap_loaded(domain)
        stats = _PCAP_STATS[domain]
        ps    = float(event["packet_size"])
        fr    = float(event["frequency"])
        ps_z  = max(0.0, (ps - stats["packet_size_mean"]) / stats["packet_size_std"])
        fr_z  = max(0.0, (fr - stats["frequency_mean"])   / stats["frequency_std"])
        cd    = float(event.get("cross_domain_flag",     0))
        pa    = float(event.get("port_anomaly_flag",     0))
        pra   = float(event.get("protocol_anomaly_flag", 0))
        X     = np.array([[ps, fr, ps_z, fr_z, cd, pa, pra]])
        model = _PCAP_MODELS[domain]
    else:  # ARINC429
        _ensure_arinc_loaded()
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

def _eval_kpis(name: str, y_true, predicted, scores) -> tuple[float, float]:
    """Print evaluation block; return (dr, fpr)."""
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
    print(f"  Detection rate : {dr:.4f}  {'✓' if dr >= 0.95 else '✗ (target ≥ 0.95)'}")
    print(f"  FPR            : {fpr:.4f}  {'✓' if fpr <= 0.005 else '✗ (target ≤ 0.005)'}")
    print(f"  Accuracy       : {acc:.4f}")

    mn = float(np.mean(scores[y_true == 0]))
    ma = float(np.mean(scores[y_true == 1]))
    print(f"\nScore distribution:")
    print(f"  is_anomaly=0 mean: {mn:+.4f}")
    print(f"  is_anomaly=1 mean: {ma:+.4f}")
    return dr, fpr


def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(DATA_IN)

    # ── Per-domain stats (shared across all three PCAP models) ────────────────
    pcap_all = df[df["data_format"] == "PCAP"].copy()
    pcap_stats = compute_pcap_domain_stats(pcap_all)
    with open(PCAP_STATS_PATH, "w") as fh:
        json.dump(pcap_stats, fh, indent=2)

    pcap_all = apply_pcap_zscores(pcap_all, pcap_stats)

    # ── Per-domain PCAP models ─────────────────────────────────────────────────
    summary_rows: list[dict] = []
    all_pcap_scores  = np.zeros(len(pcap_all))
    all_pcap_pred    = np.zeros(len(pcap_all), dtype=int)

    for domain in PCAP_DOMAINS:
        dom_df = pcap_all[pcap_all["domain"] == domain].copy()
        X = dom_df[PCAP_FEATURES].values
        y = dom_df["is_anomaly"].astype(int).values

        # Tiny Gaussian jitter (σ=0.01) breaks exact-duplicate feature vectors
        # that arise when the simulator uses a constant anomaly payload size —
        # IsolationForest's cluster-correction would otherwise inflate path
        # lengths and suppress anomaly scores for those points.
        rng = np.random.default_rng(42)
        X_train = X + rng.normal(0, 0.01, X.shape)

        contamination = float(np.clip(y.mean(), 1e-3, 0.5))
        model = IsolationForest(
            contamination=contamination, n_estimators=200, random_state=42
        )
        model.fit(X_train)
        # Recalibrate threshold on clean scores — jitter shifts the training-score
        # distribution, so sklearn's offset_ (percentile of X_train scores) is wrong
        # at test time. Recompute from unperturbed X so the threshold aligns.
        model.offset_ = np.percentile(model.score_samples(X), 100.0 * contamination)
        path = _pcap_model_path(domain)
        joblib.dump(model, path)
        print(f"\n[PCAP/{domain}] contamination={contamination:.4f}  saved→{path.name}")

        pred   = (model.predict(X) == -1).astype(int)
        scores = model.decision_function(X)

        dr, fpr = _eval_kpis(f"PCAP/{domain}", y, pred, scores)
        summary_rows.append({"domain": domain, "dr": dr, "fpr": fpr})

        # Write back into the full-PCAP arrays at the correct positions.
        all_pcap_scores[pcap_all["domain"].values == domain]  = scores
        all_pcap_pred[pcap_all["domain"].values == domain]    = pred

    # ── ARINC429 model ────────────────────────────────────────────────────────
    arinc_norm = df[df["data_format"] == "ARINC429"].copy()
    arinc_merged, arinc_label_stats = build_arinc_features(arinc_norm)
    with open(ARINC_STATS_PATH, "w") as fh:
        json.dump(arinc_label_stats, fh, indent=2)

    X_arinc = arinc_merged[["ssm_int", "parity_valid",
                              "data_bits_zscore", "frequency"]].values
    y_arinc = arinc_merged["is_anomaly"].astype(int).values

    arinc_contamination = float(np.clip(y_arinc.mean(), 1e-3, 0.5))
    arinc_model = IsolationForest(
        contamination=arinc_contamination, n_estimators=200, random_state=42
    )
    rng_arinc = np.random.default_rng(42)
    X_arinc_train = X_arinc + rng_arinc.normal(0, 0.01, X_arinc.shape)
    arinc_model.fit(X_arinc_train)
    arinc_model.offset_ = np.percentile(
        arinc_model.score_samples(X_arinc), 100.0 * arinc_contamination
    )
    joblib.dump(arinc_model, ARINC_MODEL_PATH)

    arinc_pred   = (arinc_model.predict(X_arinc) == -1).astype(int)
    arinc_scores = arinc_model.decision_function(X_arinc)
    arinc_dr, arinc_fpr = _eval_kpis("ARINC429", y_arinc, arinc_pred, arinc_scores)
    summary_rows.append({"domain": "ARINC429", "dr": arinc_dr, "fpr": arinc_fpr})

    # ── Summary table ─────────────────────────────────────────────────────────
    print(f"\n{'=' * 45}")
    print(f"  {'Domain':<13} | {'DR':>7}  | {'FPR':>7}")
    print(f"  {'-'*13}-+-{'-'*8}-+-{'-'*7}")
    for row in summary_rows:
        dr_ok  = "✓" if row["dr"]  >= 0.95  else "✗"
        fpr_ok = "✓" if row["fpr"] <= 0.005 else "✗"
        print(f"  {row['domain']:<13} | {row['dr']:>6.1%} {dr_ok} | {row['fpr']:>6.2%} {fpr_ok}")
    print(f"{'=' * 45}")

    # ── Assemble scored CSV ───────────────────────────────────────────────────
    result = df.copy()
    result["anomaly_score"]     = 0.0
    result["predicted_anomaly"] = 0
    result["severity"]          = "NONE"
    result["model_used"]        = ""

    pi = result.index[result["data_format"] == "PCAP"]
    ai = result.index[result["data_format"] == "ARINC429"]

    result.loc[pi, "anomaly_score"]     = all_pcap_scores
    result.loc[pi, "predicted_anomaly"] = all_pcap_pred
    result.loc[pi, "severity"]          = [_severity(s) for s in all_pcap_scores]
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
    size_row = pcap_all[(pcap_all["is_anomaly"] == 1) & (pcap_all["packet_size"] > 1000)]
    if len(size_row):
        r = {**size_row.iloc[0].to_dict(), "data_format": "PCAP"}
        res = score_event(r)
        print(f"  [PCAP size anom]  ps={r['packet_size']:.0f}  "
              f"score={res['anomaly_score']:+.4f}  pred={res['predicted_anomaly']}  "
              f"sev={res['severity']}")
    r_n = {**pcap_all[pcap_all["is_anomaly"] == 0].iloc[200].to_dict(), "data_format": "PCAP"}
    res_n = score_event(r_n)
    print(f"  [PCAP normal]     ps={r_n['packet_size']:.0f}  "
          f"score={res_n['anomaly_score']:+.4f}  pred={res_n['predicted_anomaly']}  "
          f"sev={res_n['severity']}")
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

    print(f"\nSaved: {ARINC_MODEL_PATH}")
    print(f"Saved: {PCAP_STATS_PATH}")
    print(f"Saved: {ARINC_STATS_PATH}")
    for d in PCAP_DOMAINS:
        print(f"Saved: {_pcap_model_path(d)}")


if __name__ == "__main__":
    main()
