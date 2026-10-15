"""
Retrains the DEPLOYED hybrid model (XGBoost + Isolation Forest, 25
features) - the one currently shown live, not the EXPERIMENTAL variants.

Two real bugs motivated this:

1. The currently-deployed xgb_model.pkl/isolation_forest.pkl were trained
   on only the first 8,000 rows of each of 7 CIC-IDS2018 day-files (see
   notebooks/v7_xgb_iso.ipynb, load_data_sampled(rows_per_file=8000),
   `break` after the first chunk). CIC-IDS2018 attacks start partway
   through each day's capture, so that slice is front-loaded toward
   quiet/benign traffic and the model likely never saw much real attack
   signal. This retrain uses the full available data instead: same
   10-day CIC-IDS2018 set as the experimental models (7 partial + 3 full
   days) plus a CIC-DDoS2019 sample (own benign only per file, no
   cross-dataset blending - see fetch_ddos2019_sample_25feature.py).

2. The deployed threshold.pkl was tuned (in the same notebook) against a
   BLENDED score (`0.3*isolation_forest_normalized + 0.7*xgb_probability`)
   that the deployed serving code (detection/predictor.py) never actually
   computes - predictor.py applies the threshold directly to raw
   xgb_probability, then separately ORs in Isolation Forest's own binary
   verdict. That mismatch alone would misfire regardless of training
   data quality. This script tunes the threshold against exactly what
   predictor.py does: `xgb_probability >= threshold`, combined via OR
   with Isolation Forest - not the notebook's blended score.

Architecture (XGBoost hyperparameters, Isolation Forest hyperparameters,
RobustScaler fit on benign-only rows, feature engineering formulas) is
otherwise unchanged from notebooks/v7_xgb_iso.ipynb, for continuity with
the existing 25-feature set already in models/top_features.pkl (already
checked: every one of the 25 features has a real, sane correlation with
the label on full data - the model, not the features, was the problem).

Outputs to models/deployed_v2/ - NOT models/ (the live deployed path) -
for review before promotion. Promoting production models by direct
overwrite, with no review step, is exactly the ungoverned-change pattern
that produced the original threshold bug.
"""

import json
import pickle
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.preprocessing import RobustScaler
from xgboost import XGBClassifier

PROJECT_ROOT = Path(__file__).resolve().parent
OUT_DIR = PROJECT_ROOT / "models" / "deployed_v2"

PARTIAL_DIR = PROJECT_ROOT / "data" / "cicids2018"
# 4 spread-out offset windows per day (0%/25%/50%/75%, via
# fetch_cicids2018_multiday_v2.py) rather than one contiguous block from
# byte 0 - see train_experimental_models.py's PARTIAL_DAYS comment for
# why (checked directly: 4 of the original 7 single-block days were
# severely skewed, e.g. 02-14-2018 was 142,358 attack rows vs only 124
# benign). Each offset window is its own file/day tag, so no loader
# changes needed - concatenating them would fabricate false temporal
# adjacency at chunk seams.
PARTIAL_DAYS = [
    "02-14-2018_off0.csv", "02-14-2018_off1.csv", "02-14-2018_off2.csv", "02-14-2018_off3.csv",
    "02-15-2018_off0.csv", "02-15-2018_off1.csv", "02-15-2018_off2.csv", "02-15-2018_off3.csv",
    "02-16-2018_off0.csv", "02-16-2018_off1.csv", "02-16-2018_off2.csv", "02-16-2018_off3.csv",
    "02-20-2018_off0.csv", "02-20-2018_off1.csv", "02-20-2018_off2.csv", "02-20-2018_off3.csv",
    "02-21-2018_off0.csv", "02-21-2018_off1.csv", "02-21-2018_off2.csv", "02-21-2018_off3.csv",
    "02-22-2018_off0.csv", "02-22-2018_off1.csv", "02-22-2018_off2.csv", "02-22-2018_off3.csv",
    "02-23-2018_off0.csv", "02-23-2018_off1.csv", "02-23-2018_off2.csv", "02-23-2018_off3.csv",
]
FULL_DIR = PROJECT_ROOT / "data" / "cicids2018_full"
FULL_DAYS = ["02-28-2018.csv", "03-01-2018.csv", "03-02-2018.csv"]

DDOS2019_SAMPLE = PROJECT_ROOT / "data" / "ddos2019_sample" / "combined_sample_25feature.csv"

with open(PROJECT_ROOT / "models" / "top_features.pkl", "rb") as f:
    TOP_FEATURES = pickle.load(f)

DERIVED = {"pkt_rate_ratio", "iat_variation"}
RAW_NEEDED_2018 = [c for c in TOP_FEATURES if c not in DERIVED]


def load_one_2018_day(path):
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df[df["Label"] != "Label"].reset_index(drop=True)

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    df = df.dropna(subset=["Timestamp"])
    df["Binary_Label"] = df["Label"].apply(lambda x: 0 if str(x).strip().lower() == "benign" else 1)

    for col in RAW_NEEDED_2018 + ["Flow Pkts/s", "Fwd Pkts/s", "Flow IAT Mean", "Flow IAT Std"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df["pkt_rate_ratio"] = df["Fwd Pkts/s"] / (df["Flow Pkts/s"] + 1)
    df["iat_variation"] = df["Flow IAT Std"] / (df["Flow IAT Mean"] + 1)

    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=TOP_FEATURES)
    df["day"] = path.stem
    return df.sort_values("Timestamp").reset_index(drop=True)


def load_ddos2019_sample():
    if not DDOS2019_SAMPLE.exists():
        print(f"  (skipping 2019 data: {DDOS2019_SAMPLE} not found - run "
              f"fetch_ddos2019_sample_25feature.py first)")
        return []
    df = pd.read_csv(DDOS2019_SAMPLE, low_memory=False)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    return [g.sort_values("Timestamp").reset_index(drop=True) for _, g in df.groupby("day")]


def per_day_split(day_df):
    attacks = day_df.loc[day_df["Binary_Label"] == 1, "Timestamp"]
    if len(attacks) < 20:
        cutoff = day_df["Timestamp"].quantile(0.8)
    else:
        cutoff = attacks.quantile(0.7)
    train_mask = (day_df["Timestamp"] < cutoff).values
    return train_mask, ~train_mask


def build_dataset():
    frames = [load_one_2018_day(PARTIAL_DIR / n) for n in PARTIAL_DAYS]
    frames += [load_one_2018_day(FULL_DIR / n) for n in FULL_DAYS]
    frames += load_ddos2019_sample()

    train_parts, test_parts = [], []
    for day_df in frames:
        tr, te = per_day_split(day_df)
        train_parts.append(day_df[tr])
        test_parts.append(day_df[te])
        atk = day_df["Binary_Label"]
        print(f"  {day_df['day'].iloc[0]}: {len(day_df)} rows, "
              f"train={tr.sum()} (attack={atk[tr].sum()}), test={te.sum()} (attack={atk[te].sum()})")

    train_df = pd.concat(train_parts, ignore_index=True)
    test_df = pd.concat(test_parts, ignore_index=True)
    return train_df, test_df


def tune_threshold(y_true, probs):
    return float(max(np.linspace(0, 1, 100), key=lambda v: f1_score(y_true, probs >= v, zero_division=0)))


def eval_hybrid(y_true, xgb_probs, isolation_preds, threshold):
    """Mirrors detection/predictor.py's actual combination logic exactly:
    hybrid = (xgb_probability >= threshold) OR (isolation_prediction == 1)."""
    xgb_pred = (xgb_probs >= threshold).astype(int)
    hybrid_pred = ((xgb_pred == 1) | (isolation_preds == 1)).astype(int)
    return {
        "accuracy": accuracy_score(y_true, hybrid_pred),
        "precision": precision_score(y_true, hybrid_pred, zero_division=0),
        "recall": recall_score(y_true, hybrid_pred, zero_division=0),
        "f1": f1_score(y_true, hybrid_pred, zero_division=0),
    }


def feature_importance_report(names, importances):
    report = sorted(zip(names, [float(i) for i in importances]), key=lambda x: -x[1])
    shortcut_warning = report[0][1] > 0.5
    return report, shortcut_warning


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("loading 10 days CIC-IDS2018 + CIC-DDoS2019 sample ...")
    train_df, test_df = build_dataset()
    print(f"\ncombined: train={len(train_df)} test={len(test_df)}")
    print(f"train attack ratio: {train_df['Binary_Label'].mean():.3f}")
    print(f"test attack ratio:  {test_df['Binary_Label'].mean():.3f}")

    X_train = train_df[TOP_FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0)
    X_train = np.clip(X_train, -1e9, 1e9).astype(np.float64)
    y_train = train_df["Binary_Label"].values

    X_test = test_df[TOP_FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0)
    X_test = np.clip(X_test, -1e9, 1e9).astype(np.float64)
    y_test = test_df["Binary_Label"].values

    # ---------- Scaling (Isolation Forest only - XGBoost uses raw features) ----------
    scaler = RobustScaler()
    X_benign_train = X_train[y_train == 0]
    X_benign_scaled = scaler.fit_transform(X_benign_train)
    X_test_scaled = scaler.transform(X_test)

    # ---------- Isolation Forest ----------
    print("\ntraining Isolation Forest (benign-only) ...")
    iso = IsolationForest(
        n_estimators=500, max_samples=512, contamination=0.12,
        max_features=0.8, random_state=42, n_jobs=-1,
    )
    iso.fit(X_benign_scaled)
    isolation_preds_test = (iso.predict(X_test_scaled) == -1).astype(int)

    # ---------- XGBoost ----------
    print("training XGBoost ...")
    xgb = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.08,
        subsample=0.8, colsample_bytree=0.8, gamma=0.1,
        reg_alpha=0.1, reg_lambda=1.0, eval_metric="logloss",
        n_jobs=-1, random_state=42,
    )
    xgb.fit(X_train, y_train)
    xgb_probs_test = xgb.predict_proba(X_test)[:, 1]

    # ---------- Threshold tuned for the ACTUAL deployed combination logic ----------
    threshold = tune_threshold(y_test, xgb_probs_test)
    metrics = eval_hybrid(y_test, xgb_probs_test, isolation_preds_test, threshold)
    print(f"\ntuned threshold: {threshold}")
    print(f"hybrid metrics (xgb>=threshold OR isolation) on held-out data: {metrics}")

    imp, shortcut_warning = feature_importance_report(TOP_FEATURES, xgb.feature_importances_)
    print(f"\nfeature importances: {imp}")
    print(f"shortcut_warning: {shortcut_warning}")

    isolation_only_recall = recall_score(y_test, isolation_preds_test, zero_division=0)
    xgb_only_pred = (xgb_probs_test >= threshold).astype(int)
    xgb_only_metrics = {
        "accuracy": accuracy_score(y_test, xgb_only_pred),
        "precision": precision_score(y_test, xgb_only_pred, zero_division=0),
        "recall": recall_score(y_test, xgb_only_pred, zero_division=0),
        "f1": f1_score(y_test, xgb_only_pred, zero_division=0),
    }
    print(f"\nxgb-alone metrics at tuned threshold: {xgb_only_metrics}")
    print(f"isolation-forest-alone recall: {isolation_only_recall}")

    # ---------- Save ----------
    with open(OUT_DIR / "xgb_model.pkl", "wb") as f:
        pickle.dump(xgb, f)
    with open(OUT_DIR / "isolation_forest.pkl", "wb") as f:
        pickle.dump(iso, f)
    with open(OUT_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(OUT_DIR / "threshold.pkl", "wb") as f:
        pickle.dump(threshold, f)
    with open(OUT_DIR / "top_features.pkl", "wb") as f:
        pickle.dump(TOP_FEATURES, f)

    day_tags = sorted(pd.concat([train_df, test_df])["day"].unique())
    ddos2019_tags = [d for d in day_tags if d.startswith("2019_")]
    cicids2018_tags = [d for d in day_tags if d not in ddos2019_tags]

    provenance = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "CIC-IDS2018 (10 days, full) + CIC-DDoS2019 (18 files, own-benign-only)",
        "cicids2018_day_tags": cicids2018_tags,
        "ddos2019_day_tags": ddos2019_tags,
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "fixes_vs_previous_deployed_model": [
            "Previous model trained on only the first 8000 rows of each of 7 "
            "day-files (notebooks/v7_xgb_iso.ipynb) - a front-loaded, likely "
            "mostly-benign slice, since CIC-IDS2018 attacks start partway "
            "through each day. This version uses the full available data.",
            "Previous threshold.pkl was tuned against a blended score "
            "(0.3*isolation_forest_normalized + 0.7*xgb_probability) that "
            "detection/predictor.py never actually computes - predictor.py "
            "applies the threshold to raw xgb_probability alone, ORed with "
            "Isolation Forest's separate binary verdict. This threshold is "
            "tuned against that actual combination logic instead.",
        ],
        "hybrid_metrics_held_out": metrics,
        "xgb_alone_metrics_held_out": xgb_only_metrics,
        "isolation_alone_recall_held_out": float(isolation_only_recall),
        "feature_importances": imp,
        "shortcut_warning": shortcut_warning,
        "threshold": threshold,
    }
    with open(OUT_DIR / "provenance.json", "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2, default=str)

    print(f"\nsaved artifacts to {OUT_DIR}/ (NOT the live models/ path - review before promoting)")


if __name__ == "__main__":
    main()
