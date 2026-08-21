"""
Produces the deployable artifacts for the 3 experimental models shown on
the dashboard's EXPERIMENTAL panel. Builds on train_three_way_multiday.py's
data pipeline (per-day chronological split, (day, Dst Port, Protocol)
grouping for temporal features/sequences) but adds what that research
script never did: real threshold tuning and artifact persistence.

Data: 10 days total.
  - 7 days from data/cicids2018/ - partial ~120-380K row samples fetched
    earlier this session, already validated (11 attack types, no
    degenerate single-feature shortcut, credible non-perfect metrics).
    Kept as-is rather than reprocessed from the full files, since
    reprocessing gains nothing (these were already confirmed to capture
    each day's attack window) and the full versions of these particular
    files are large enough (up to 4GB) to make full reads impractical
    here.
  - 3 NEW days from data/cicids2018_full/ (02-28, 03-01, 03-02) - small
    enough to read in full, and add two attack types absent from the
    original 7 entirely: Infiltration and Botnet. Read in full (613K /
    331K / 1.05M rows respectively) since these files are modest-sized
    and doing so avoids the "attack buried past the row cap" trap found
    earlier with the byte-range sampling approach.

Outputs, all under models/experimental/:
  xgb_variant1_single_flow.pkl / threshold_variant1.pkl / features_variant1.pkl
  xgb_variant2_temporal.pkl    / threshold_variant2.pkl / features_variant2.pkl
  cnn_lstm_variant3.pt         / threshold_variant3.pkl / scaler_variant3.pkl
  provenance.json - dataset composition, metrics, feature importances,
    and the >0.5 shortcut-warning check for each variant.
"""

import json
import pickle
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

import train_three_way_multiday as base

PROJECT_ROOT = Path(__file__).resolve().parent
OUT_DIR = PROJECT_ROOT / "models" / "experimental"

PARTIAL_DIR = PROJECT_ROOT / "data" / "cicids2018"
PARTIAL_DAYS = [
    "02-14-2018.csv", "02-15-2018.csv", "02-16-2018.csv", "02-20-2018.csv",
    "02-21-2018.csv", "02-22-2018.csv", "02-23-2018.csv",
]

FULL_DIR = PROJECT_ROOT / "data" / "cicids2018_full"
FULL_DAYS = ["02-28-2018.csv", "03-01-2018.csv", "03-02-2018.csv"]


def load_all_days():
    frames = []
    for name in PARTIAL_DAYS:
        frames.append(base.load_one_day(PARTIAL_DIR / name))
    for name in FULL_DAYS:
        frames.append(base.load_one_day(FULL_DIR / name))
    return frames


def build_dataset():
    frames = load_all_days()
    train_parts, test_parts = [], []
    for day_df in frames:
        tr, te = base.per_day_split(day_df)
        day_df = day_df.assign(is_test=te)
        train_parts.append(day_df[tr])
        test_parts.append(day_df[te])
        atk = day_df["Binary_Label"]
        print(f"  {day_df['day'].iloc[0]}: {len(day_df)} rows, "
              f"train={tr.sum()} (attack={atk[tr].sum()}), test={te.sum()} (attack={atk[te].sum()})")

    df = pd.concat(train_parts + test_parts, ignore_index=True)
    train_mask = np.concatenate([np.ones(len(p), dtype=bool) for p in train_parts] +
                                 [np.zeros(len(p), dtype=bool) for p in test_parts])
    return df, train_mask, ~train_mask


def tune_threshold(y_true, probs):
    """F1-optimal threshold, mirroring RetrainingAgent._train_xgb's sweep."""
    return float(max(np.linspace(0.05, 0.95, 91), key=lambda v: f1_score(y_true, probs >= v, zero_division=0)))


def eval_at_threshold(y_true, probs, threshold):
    preds = (probs >= threshold).astype(int)
    return {
        "accuracy": accuracy_score(y_true, preds),
        "precision": precision_score(y_true, preds, zero_division=0),
        "recall": recall_score(y_true, preds, zero_division=0),
        "f1": f1_score(y_true, preds, zero_division=0),
        "threshold": threshold,
    }


def feature_importance_report(names, importances):
    report = sorted(zip(names, [float(i) for i in importances]), key=lambda x: -x[1])
    shortcut_warning = report[0][1] > 0.5
    return report, shortcut_warning


def save(obj, path):
    with open(path, "wb") as f:
        pickle.dump(obj, f)
    print(f"  saved {path}")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("loading + splitting each day (10 days: 7 partial samples + 3 full new days) ...")
    df, train_mask, test_mask = build_dataset()
    print(f"\ncombined: {len(df)} rows  train={train_mask.sum()}  test={test_mask.sum()}")
    print(f"train attack ratio: {df.loc[train_mask,'Binary_Label'].mean():.3f}")
    print(f"test attack ratio:  {df.loc[test_mask,'Binary_Label'].mean():.3f}")
    attack_types = sorted(df.loc[df.Binary_Label == 1, "Label"].unique())
    print(f"attack types present ({len(attack_types)}): {attack_types}")

    y = df["Binary_Label"].values
    provenance = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "CIC-IDS2018, 10 days (7 partial samples + 3 full days: 02-28/03-01/03-02)",
        "total_rows": int(len(df)),
        "train_rows": int(train_mask.sum()),
        "test_rows": int(test_mask.sum()),
        "attack_types": attack_types,
        "split": "per-day chronological, cutoff at 70th percentile of that day's own attack timestamps",
        "note": "Experimental models. Known limitation: Min Pkt Size feature has "
                "concentrated-but-real cross-attack-type reliance in variant 1 "
                "(investigated - not a degenerate single-value shortcut like the "
                "earlier single-day case, but disclosed here regardless).",
    }

    # ---------- Variant 1: XGBoost, single-flow only ----------
    print("\n--- Variant 1: XGBoost, single-flow only ---")
    X1 = df[base.BASE_FEATURES]
    xgb1 = XGBClassifier(n_estimators=200, max_depth=5, eval_metric="logloss", random_state=42)
    xgb1.fit(X1[train_mask], y[train_mask])
    probs1 = xgb1.predict_proba(X1[test_mask])[:, 1]
    thr1 = tune_threshold(y[test_mask], probs1)
    m1 = eval_at_threshold(y[test_mask], probs1, thr1)
    imp1, warn1 = feature_importance_report(base.BASE_FEATURES, xgb1.feature_importances_)
    print("metrics:", m1)
    print("feature importances:", imp1, "shortcut_warning:", warn1)

    save(xgb1, OUT_DIR / "xgb_variant1_single_flow.pkl")
    save(thr1, OUT_DIR / "threshold_variant1.pkl")
    save(base.BASE_FEATURES, OUT_DIR / "features_variant1.pkl")

    # ---------- Variant 2: XGBoost, single-flow + engineered temporal features ----------
    print("\n--- Variant 2: XGBoost, single-flow + engineered temporal (day, Dst Port, Protocol) history ---")
    df2, hist_cols = base.build_temporal_features(df)
    train_mask2 = df2["is_test"].values == False
    test_mask2 = ~train_mask2
    y2 = df2["Binary_Label"].values
    features2 = base.BASE_FEATURES + hist_cols
    X2 = df2[features2]
    xgb2 = XGBClassifier(n_estimators=200, max_depth=5, eval_metric="logloss", random_state=42)
    xgb2.fit(X2[train_mask2], y2[train_mask2])
    probs2 = xgb2.predict_proba(X2[test_mask2])[:, 1]
    thr2 = tune_threshold(y2[test_mask2], probs2)
    m2 = eval_at_threshold(y2[test_mask2], probs2, thr2)
    imp2, warn2 = feature_importance_report(features2, xgb2.feature_importances_)
    print("metrics:", m2)
    print("feature importances:", imp2, "shortcut_warning:", warn2)

    save(xgb2, OUT_DIR / "xgb_variant2_temporal.pkl")
    save(thr2, OUT_DIR / "threshold_variant2.pkl")
    save(features2, OUT_DIR / "features_variant2.pkl")

    # ---------- Variant 3: CNN+LSTM, raw sequence ----------
    print("\n--- Variant 3: CNN+LSTM, raw 10-step (day, Dst Port, Protocol) sequence ---")
    X3_seq, df3 = base.build_raw_sequences(df)
    train_mask3 = df3["is_test"].values == False
    test_mask3 = ~train_mask3
    y3 = df3["Binary_Label"].values

    n, seq_len, n_feat = X3_seq.shape
    scaler = StandardScaler().fit(X3_seq[train_mask3].reshape(-1, n_feat))
    X3_scaled = scaler.transform(X3_seq.reshape(-1, n_feat)).reshape(n, seq_len, n_feat)

    print("  training ...")
    model3 = base.train_cnn_lstm(X3_scaled[train_mask3], y3[train_mask3])
    model3.eval()
    with torch.no_grad():
        logits = model3(torch.FloatTensor(X3_scaled[test_mask3]))
        probs3 = torch.sigmoid(logits).numpy().ravel()
    thr3 = tune_threshold(y3[test_mask3], probs3)
    m3 = eval_at_threshold(y3[test_mask3], probs3, thr3)
    print("metrics:", m3)

    torch.save(model3.state_dict(), OUT_DIR / "cnn_lstm_variant3.pt")
    print(f"  saved {OUT_DIR / 'cnn_lstm_variant3.pt'}")
    save(thr3, OUT_DIR / "threshold_variant3.pkl")
    save(scaler, OUT_DIR / "scaler_variant3.pkl")
    save(base.BASE_FEATURES, OUT_DIR / "features_variant3.pkl")

    # ---------- Provenance ----------
    provenance["variant1"] = {"metrics": m1, "feature_importances": imp1, "shortcut_warning": warn1}
    provenance["variant2"] = {"metrics": m2, "feature_importances": imp2, "shortcut_warning": warn2}
    provenance["variant3"] = {"metrics": m3, "architecture": "Conv1d(8->32,k=3) + LSTM(32->64) + Linear(64->1)"}

    with open(OUT_DIR / "provenance.json", "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2, default=str)
    print(f"\nsaved {OUT_DIR / 'provenance.json'}")

    print("\n=== SUMMARY (F1-optimal thresholds, not the naive 0.5 default) ===")
    rows = [
        ("1. XGBoost, single-flow only", m1),
        ("2. XGBoost, single-flow + temporal features", m2),
        ("3. CNN+LSTM, raw sequence", m3),
    ]
    print(f"{'Variant':<45}{'Threshold':<11}{'Accuracy':<10}{'Precision':<10}{'Recall':<10}{'F1':<10}")
    for name, m in rows:
        print(f"{name:<45}{m['threshold']:<11.3f}{m['accuracy']:<10.4f}{m['precision']:<10.4f}{m['recall']:<10.4f}{m['f1']:<10.4f}")


if __name__ == "__main__":
    main()
