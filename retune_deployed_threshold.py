"""
Re-tunes models/threshold.pkl for the DEPLOYED xgb_model.pkl, using the
same F1-optimal sweep already used everywhere else in this project
(agents/retraining_agent.py's np.linspace(0, 1, 100) sweep) - the
currently-deployed value (0.0010152356699109077) does not land on that
grid at all, meaning it was not produced by any tracked mechanism in
this repo. Diagnosed after live-traffic testing found the deployed
model at 14.7% specificity: xgb_probability was 0.03-0.04 on ordinary
benign flows, comfortably above a threshold this low, so nearly
anything scores as "attack".

This does NOT retrain the model - it only re-scores the existing
xgb_model.pkl against held-out CIC-IDS2018 data and finds a better
decision threshold for the SAME model.

Does not overwrite models/threshold.pkl - prints the recommended value
and its metrics for review first.
"""

import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data" / "cicids2018"
DAY_FILES = [
    "02-14-2018.csv", "02-15-2018.csv", "02-16-2018.csv", "02-20-2018.csv",
    "02-21-2018.csv", "02-22-2018.csv", "02-23-2018.csv",
]

with open(PROJECT_ROOT / "models" / "top_features.pkl", "rb") as f:
    TOP_FEATURES = pickle.load(f)

with open(PROJECT_ROOT / "models" / "xgb_model.pkl", "rb") as f:
    xgb_model = pickle.load(f)

with open(PROJECT_ROOT / "models" / "threshold.pkl", "rb") as f:
    CURRENT_THRESHOLD = pickle.load(f)

# The two derived features not present directly in the raw CSV - must
# match feature_extraction/feature_extractor.py's formulas exactly.
DERIVED = {"pkt_rate_ratio", "iat_variation"}
RAW_NEEDED = [c for c in TOP_FEATURES if c not in DERIVED]


def load_one_day(path):
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df[df["Label"] != "Label"].reset_index(drop=True)

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    df = df.dropna(subset=["Timestamp"])
    df["Binary_Label"] = df["Label"].apply(lambda x: 0 if str(x).strip().lower() == "benign" else 1)

    for col in RAW_NEEDED + ["Flow Pkts/s", "Fwd Pkts/s", "Flow IAT Mean", "Flow IAT Std"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # pkt_rate_ratio = Fwd Pkts/s / (Flow Pkts/s + 1)
    df["pkt_rate_ratio"] = df["Fwd Pkts/s"] / (df["Flow Pkts/s"] + 1)

    # iat_variation = std/mean computed in SECONDS, before the live
    # extractor's microsecond conversion - CIC-IDS2018's own "Flow IAT
    # Mean"/"Flow IAT Std" columns are already in microseconds, so
    # divide by 1e6 first to match.
    iat_mean_s = df["Flow IAT Mean"] / 1_000_000
    iat_std_s = df["Flow IAT Std"] / 1_000_000
    df["iat_variation"] = iat_std_s / (iat_mean_s + 1)

    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=TOP_FEATURES)
    df["day"] = path.stem
    return df.sort_values("Timestamp").reset_index(drop=True)


def per_day_split(day_df):
    attacks = day_df.loc[day_df["Binary_Label"] == 1, "Timestamp"]
    if len(attacks) < 20:
        cutoff = day_df["Timestamp"].quantile(0.8)
    else:
        cutoff = attacks.quantile(0.7)
    train_mask = (day_df["Timestamp"] < cutoff).values
    return train_mask, ~train_mask


def tune_threshold(y_true, probs):
    return float(max(np.linspace(0, 1, 100), key=lambda v: f1_score(y_true, probs >= v, zero_division=0)))


def eval_at_threshold(y_true, probs, threshold):
    preds = (probs >= threshold).astype(int)
    return {
        "accuracy": accuracy_score(y_true, preds),
        "precision": precision_score(y_true, preds, zero_division=0),
        "recall": recall_score(y_true, preds, zero_division=0),
        "f1": f1_score(y_true, preds, zero_division=0),
    }


def main():
    print(f"currently deployed threshold: {CURRENT_THRESHOLD}")
    print("loading 7 days of CIC-IDS2018 ...")

    test_parts = []
    for name in DAY_FILES:
        day_df = load_one_day(DATA_DIR / name)
        _, te = per_day_split(day_df)
        test_parts.append(day_df[te])
        print(f"  {name}: {len(day_df)} rows, held-out test={te.sum()}")

    test_df = pd.concat(test_parts, ignore_index=True)
    X_test = test_df[TOP_FEATURES]
    y_test = test_df["Binary_Label"].values

    probs = xgb_model.predict_proba(X_test)[:, 1]

    print(f"\nheld-out test set: {len(test_df)} rows, attack ratio={y_test.mean():.3f}")

    current_metrics = eval_at_threshold(y_test, probs, CURRENT_THRESHOLD)
    print(f"\ncurrent threshold ({CURRENT_THRESHOLD:.4f}) on held-out CIC-IDS2018: {current_metrics}")

    new_threshold = tune_threshold(y_test, probs)
    new_metrics = eval_at_threshold(y_test, probs, new_threshold)
    print(f"\nF1-optimal threshold ({new_threshold:.4f}) on held-out CIC-IDS2018: {new_metrics}")

    print(f"\nRECOMMENDATION: {new_threshold} (not written to models/threshold.pkl - review first)")


if __name__ == "__main__":
    main()
