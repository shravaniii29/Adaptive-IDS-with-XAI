"""Trains a candidate XGBoost classifier on the deployed model's own
25-feature TOP_FEATURES schema PLUS cross-flow temporal/rate features
(rolling mean/std of Flow Pkts/s, Flow Duration, TotLen Fwd Pkts over
prior flows in the same (day, Dst Port, Protocol) group, plus flow count
and time-since-last) - the same temporal-feature recipe variant2 already
uses (train_three_way_multiday.py::build_temporal_features), just applied
on top of the deployed feature set instead of variant1's 8-feature set.

Why: every model built on the plain 25-feature TOP_FEATURES schema
(deployed hybrid + all 3 family models) shows near-zero recall on HTTP
flood/port scan in live testing, while variant2 (single-flow + temporal
history) is the one model that shows real signal there. Hypothesis: those
attacks are only visible in the RATE/REPETITION pattern across flows to
the same destination, invisible to any single flow's own stats - this
tests that hypothesis directly on the deployed model's own richer feature
set.

2018-only: the 2019 sample data was pre-processed into two incompatible
cuts by earlier fetch scripts - combined_sample.csv has Dst Port/Protocol
but only the 8 BASE_FEATURES, combined_sample_25feature.csv has the full
25 TOP_FEATURES but not Dst Port/Protocol. Neither has everything this
needs together. 2018 has all of it AND is the actual source of the
HTTP-flood attack types (Hulk, GoldenEye, Slowloris, SlowHTTPTest) this
candidate is meant to help detect, so this isn't a real loss for what's
being tested here.

Writes ONLY to models/temporal25_candidate/ - never touches models/
(the actual deployed artifacts). Reuses train_attack_family_models.py's
loaders/per_day_split/tune_threshold so the data pipeline matches exactly
what every other model in this project was trained on.
"""
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from train_attack_family_models import (
    PARTIAL_DIR, PARTIAL_DAYS, TOP_FEATURES,
    load_one_2018_day, per_day_split, tune_threshold,
)

PROJECT_ROOT = Path(__file__).resolve().parent
OUT_DIR = PROJECT_ROOT / "models" / "temporal25_candidate"

# "Flow Byts/s" dropped from the usual 4-column recipe (variant2 uses
# it too) - the 2019 sample data is pre-filtered to the deployed model's
# TOP_FEATURES schema, which doesn't include it. The other 3 are all
# already part of TOP_FEATURES itself, so guaranteed present everywhere.
HIST_COLUMNS = ["Flow Pkts/s", "Flow Duration", "TotLen Fwd Pkts"]
WINDOW = 10
GROUP_KEYS = ["day", "Dst Port", "Protocol"]


def load_all_frames():
    print("loading 2018 partial days ...")
    frames_2018 = []
    for name in PARTIAL_DAYS:
        path = PARTIAL_DIR / name
        if not path.exists():
            continue
        df = load_one_2018_day(path)
        for col in HIST_COLUMNS + ["Dst Port", "Protocol"]:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        frames_2018.append(df)
    print(f"  {len(frames_2018)} 2018 day-frames loaded")

    return frames_2018


def build_temporal_features(df):
    """Same recipe as train_three_way_multiday.py::build_temporal_features -
    rolling stats over strictly PRIOR flows (shift(1)) in the same
    (day, Dst Port, Protocol) group, cold-start-safe (fillna(0))."""
    df = df.sort_values(GROUP_KEYS[:1] + ["Timestamp"]).reset_index(drop=True)
    grp = df.groupby(GROUP_KEYS, sort=False)

    hist_cols = []
    for col in HIST_COLUMNS:
        shifted = grp[col].shift(1)
        df["_shifted"] = shifted
        roll = df.groupby(GROUP_KEYS)["_shifted"]
        safe = col.replace("/", "_").replace(" ", "_")
        mean_col, std_col = f"hist_mean_{safe}", f"hist_std_{safe}"
        df[mean_col] = roll.rolling(window=WINDOW, min_periods=1).mean().reset_index(level=list(range(len(GROUP_KEYS))), drop=True)
        df[std_col] = roll.rolling(window=WINDOW, min_periods=1).std().reset_index(level=list(range(len(GROUP_KEYS))), drop=True)
        hist_cols += [mean_col, std_col]
    df.drop(columns=["_shifted"], inplace=True)

    df["hist_flow_count"] = grp.cumcount().clip(upper=WINDOW)
    df["time_since_last"] = (df["Timestamp"] - grp["Timestamp"].shift(1)).dt.total_seconds()
    hist_cols += ["hist_flow_count", "time_since_last"]

    df[hist_cols] = df[hist_cols].fillna(0)
    return df, hist_cols


def main():
    frames = load_all_frames()

    train_parts, test_parts = [], []
    for day_df in frames:
        tr, te = per_day_split(day_df)
        train_parts.append(day_df[tr])
        test_parts.append(day_df[te])

    df = pd.concat(train_parts + test_parts, ignore_index=True)
    is_train = np.concatenate([np.ones(len(p), dtype=bool) for p in train_parts] +
                               [np.zeros(len(p), dtype=bool) for p in test_parts])

    print(f"\ncombined: {len(df)} rows ({is_train.sum()} train, {(~is_train).sum()} test)")

    df, hist_cols = build_temporal_features(df)
    feature_cols = TOP_FEATURES + hist_cols
    print(f"feature set: {len(TOP_FEATURES)} deployed + {len(hist_cols)} temporal = {len(feature_cols)} total")

    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

    X_train, X_test = df.loc[is_train, feature_cols], df.loc[~is_train, feature_cols]
    y_train, y_test = df.loc[is_train, "Binary_Label"], df.loc[~is_train, "Binary_Label"]
    print(f"train attack ratio: {y_train.mean():.3f}  test attack ratio: {y_test.mean():.3f}")

    print("\ntraining XGBoost ...")
    xgb = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.08, subsample=0.8,
                         colsample_bytree=0.8, gamma=0.1, reg_alpha=0.1, reg_lambda=1.0,
                         eval_metric="logloss", n_jobs=-1, random_state=42)
    xgb.fit(X_train, y_train)
    probs = xgb.predict_proba(X_test)[:, 1]
    threshold = tune_threshold(y_test.values, probs)
    xgb_pred = (probs >= threshold).astype(int)

    print("\ntraining Isolation Forest (benign-only) ...")
    scaler = StandardScaler().fit(X_train)
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    iso = IsolationForest(n_estimators=300, max_samples=512, contamination=0.12,
                           max_features=0.8, random_state=42, n_jobs=-1)
    iso.fit(X_train_scaled[y_train.values == 0])
    iso.n_jobs = 1  # live-serving perf fix, same as detection/predictor.py
    iso_pred = (iso.predict(X_test_scaled) == -1).astype(int)

    hybrid_pred = ((xgb_pred == 1) | (iso_pred == 1)).astype(int)

    metrics = {
        "xgb_only": {
            "accuracy": accuracy_score(y_test, xgb_pred), "precision": precision_score(y_test, xgb_pred, zero_division=0),
            "recall": recall_score(y_test, xgb_pred, zero_division=0), "f1": f1_score(y_test, xgb_pred, zero_division=0),
        },
        "hybrid": {
            "accuracy": accuracy_score(y_test, hybrid_pred), "precision": precision_score(y_test, hybrid_pred, zero_division=0),
            "recall": recall_score(y_test, hybrid_pred, zero_division=0), "f1": f1_score(y_test, hybrid_pred, zero_division=0),
        },
    }
    print(f"\nheld-out threshold={threshold:.3f}")
    print(f"xgb-only:  {metrics['xgb_only']}")
    print(f"hybrid:    {metrics['hybrid']}")

    imp = sorted(zip(feature_cols, [float(i) for i in xgb.feature_importances_]), key=lambda x: -x[1])
    print("\ntop 10 feature importances:")
    for name, score in imp[:10]:
        print(f"  {name:30s} {score:.4f}")
    shortcut_warning = imp[0][1] > 0.5

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "xgb_model.pkl", "wb") as f:
        pickle.dump(xgb, f)
    with open(OUT_DIR / "isolation_forest.pkl", "wb") as f:
        pickle.dump(iso, f)
    with open(OUT_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(OUT_DIR / "threshold.pkl", "wb") as f:
        pickle.dump(threshold, f)
    with open(OUT_DIR / "feature_cols.pkl", "wb") as f:
        pickle.dump(feature_cols, f)
    with open(OUT_DIR / "hist_cols.pkl", "wb") as f:
        pickle.dump(hist_cols, f)

    print(f"\nshortcut_warning: {shortcut_warning} (top feature: {imp[0][0]}={imp[0][1]:.4f})")
    print(f"wrote candidate artifacts to {OUT_DIR}/ (NOT models/ - deployed artifacts untouched)")


if __name__ == "__main__":
    main()
