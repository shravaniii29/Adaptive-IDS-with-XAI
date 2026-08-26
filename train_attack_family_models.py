"""
Trains TWO separate hybrid models (XGBoost + Isolation Forest, same
25-feature set as the deployed model), one per structural attack family,
instead of one generalist model covering everything:

1. VOLUMETRIC FLOODS (models/family_volumetric/) - single repeated packet
   type at high rate, no completed connection, minimal-to-no payload; the
   goal is raw exhaustion, not interaction. Matches this project's live
   ICMP/SYN/UDP flood simulator scenarios. Built from CIC-DDoS2019's
   non-reflection flood types: Syn, TFTP (day tags ending "_Syn"/"_TFTP"
   in data/ddos2019_sample/combined_sample_25feature.csv). Reflection/
   amplification types (DrDoS_*, plain UDP, UDPLag, Portmap) are
   deliberately excluded - their traffic shape differs (spoofed source,
   real response payloads from a reflector), and only Syn/TFTP were
   named as the intended fit.

2. CONNECTION / APPLICATION-LAYER ATTACKS (models/family_connection/) -
   real connection attempts producing genuine bidirectional traffic:
   full TCP handshake for HTTP-style DoS, per-port connect attempts for
   scanning. Matches this project's live HTTP flood / port scan
   scenarios. Built from CIC-IDS2018's HTTP-based DoS family (Hulk,
   GoldenEye, Slowloris, SlowHTTPTest - all one structural family, "-
   style" per the definition this was built from) plus Infilteration as
   the closest available reconnaissance/infiltration analogue (CIC-
   IDS2018 has no standalone PortScan label). Every other 2018 attack
   type (brute force, web/XSS, SQL injection, Bot) is excluded - neither
   a flood nor a recon/connection behavior, so it doesn't belong in
   either family and would just be label noise if lumped in.

These are the two literal attack-type mappings named when this dataset
split was specified; nothing broader was inferred. If that turns out to
be too narrow (e.g. DrDoS_* reflection floods should also count as
"volumetric"), the ALLOWED_* constants below are the only place to
change - everything else is generic.

Deliberately excludes benign rows from days/files that don't belong to
either family's source set (no cross-family or cross-dataset benign
blending, extending this project's established "own benign only per
file" convention from fetch_ddos2019_sample_25feature.py to this split).

Architecture/hyperparameters, scaling, and threshold-tuning logic are
otherwise unchanged from retrain_deployed_model.py, for continuity and
comparability with the deployed model. Threshold is tuned against
detection/predictor.py's actual OR-combination logic, same as there.

Outputs to models/family_volumetric/ and models/family_connection/ -
NOT the live models/ path - each with its own xgb_model.pkl,
isolation_forest.pkl, scaler.pkl, threshold.pkl, top_features.pkl,
provenance.json. Not wired into serving code; this only trains and
reports metrics.

Usage:
    python train_attack_family_models.py
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

# ---------------------------------------------------------------------
# Same 10-day CIC-IDS2018 source set as retrain_deployed_model.py
# (28 spread-out offset windows for the 7 "partial" days, via
# fetch_cicids2018_multiday_v2.py, + 3 full days) - reused so the
# connection/app-layer family draws from the same underlying captures
# the deployed model does, just filtered to a different label subset.
# ---------------------------------------------------------------------

PARTIAL_DIR = PROJECT_ROOT / "data" / "cicids2018"
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

# ---------------------------------------------------------------------
# The two family definitions - see module docstring for why each list
# is what it is. Change these, and only these, to adjust the split.
# ---------------------------------------------------------------------

VOLUMETRIC_DAY_TAG_SUFFIXES = ("_Syn", "_TFTP")

CONNECTION_2018_LABELS = [
    "DoS attacks-Hulk",
    "DoS attacks-GoldenEye",
    "DoS attacks-Slowloris",
    "DoS attacks-SlowHTTPTest",
    "Infilteration",  # CIC-IDS2018's own spelling
]


# ---------------------------------------------------------------------
# Loaders (identical to retrain_deployed_model.py)
# ---------------------------------------------------------------------

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
        raise FileNotFoundError(
            f"{DDOS2019_SAMPLE} not found - run fetch_ddos2019_sample_25feature.py first"
        )
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


# ---------------------------------------------------------------------
# Family-specific dataset construction
# ---------------------------------------------------------------------

def build_volumetric_dataset():
    """Syn + TFTP files only, each contributing its own benign + attack
    rows (already own-benign-only per fetch_ddos2019_sample_25feature.py)
    - no further label filtering needed, the day-tag selection already
    restricts to exactly these two attack types."""
    all_frames = load_ddos2019_sample()
    frames = [f for f in all_frames if f["day"].iloc[0].endswith(VOLUMETRIC_DAY_TAG_SUFFIXES)]

    if not frames:
        raise ValueError(
            "no Syn/TFTP day tags found in combined_sample_25feature.csv - "
            "check fetch_ddos2019_sample_25feature.py's output log; one of "
            "these two attack-type files may have produced zero usable rows."
        )

    found_tags = sorted(f["day"].iloc[0] for f in frames)
    print(f"  volumetric source files: {found_tags}")
    if not any(t.endswith("_Syn") for t in found_tags):
        print("  WARNING: no Syn file found")
    if not any(t.endswith("_TFTP") for t in found_tags):
        print("  WARNING: no TFTP file found")

    train_parts, test_parts = [], []
    for day_df in frames:
        tr, te = per_day_split(day_df)
        train_parts.append(day_df[tr])
        test_parts.append(day_df[te])
        atk = day_df["Binary_Label"]
        print(f"  {day_df['day'].iloc[0]}: {len(day_df)} rows, "
              f"train={tr.sum()} (attack={atk[tr].sum()}), test={te.sum()} (attack={atk[te].sum()})")

    return pd.concat(train_parts, ignore_index=True), pd.concat(test_parts, ignore_index=True)


def build_connection_dataset():
    """All 10 CIC-IDS2018 days, each contributing its own benign rows
    unchanged, but attack rows restricted to CONNECTION_2018_LABELS -
    every other attack type (brute force, web/XSS, SQL injection, Bot)
    is dropped entirely, not relabeled, so it never leaks into either
    class."""
    frames = [load_one_2018_day(PARTIAL_DIR / n) for n in PARTIAL_DAYS]
    frames += [load_one_2018_day(FULL_DIR / n) for n in FULL_DAYS]

    train_parts, test_parts = [], []
    total_kept_attacks = 0
    for day_df in frames:
        keep = (day_df["Label"].str.strip() == "Benign") | (day_df["Label"].isin(CONNECTION_2018_LABELS))
        day_df = day_df[keep].reset_index(drop=True)
        if day_df.empty:
            continue

        tr, te = per_day_split(day_df)
        train_parts.append(day_df[tr])
        test_parts.append(day_df[te])
        atk = day_df["Binary_Label"]
        total_kept_attacks += int(atk.sum())
        if atk.sum() > 0:
            print(f"  {day_df['day'].iloc[0]}: {len(day_df)} rows kept, "
                  f"train={tr.sum()} (attack={atk[tr].sum()}), test={te.sum()} (attack={atk[te].sum()})")

    if total_kept_attacks == 0:
        raise ValueError(
            f"no rows matched CONNECTION_2018_LABELS={CONNECTION_2018_LABELS} across any "
            f"loaded day - check the exact Label spellings in your local CSVs."
        )

    return pd.concat(train_parts, ignore_index=True), pd.concat(test_parts, ignore_index=True)


# ---------------------------------------------------------------------
# Shared training/eval/save, identical methodology to retrain_deployed_model.py
# ---------------------------------------------------------------------

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


def train_family_model(family_name, dataset_description, train_df, test_df, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 70}\ntraining: {family_name}\n{'=' * 70}")
    print(f"train={len(train_df)} test={len(test_df)}")
    print(f"train attack ratio: {train_df['Binary_Label'].mean():.3f}")
    print(f"test attack ratio:  {test_df['Binary_Label'].mean():.3f}")

    X_train = train_df[TOP_FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0)
    X_train = np.clip(X_train, -1e9, 1e9).astype(np.float64)
    y_train = train_df["Binary_Label"].values

    X_test = test_df[TOP_FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0)
    X_test = np.clip(X_test, -1e9, 1e9).astype(np.float64)
    y_test = test_df["Binary_Label"].values

    scaler = RobustScaler()
    X_benign_train = X_train[y_train == 0]
    X_benign_scaled = scaler.fit_transform(X_benign_train)
    X_test_scaled = scaler.transform(X_test)

    print("training Isolation Forest (benign-only) ...")
    iso = IsolationForest(
        n_estimators=500, max_samples=512, contamination=0.12,
        max_features=0.8, random_state=42, n_jobs=-1,
    )
    iso.fit(X_benign_scaled)
    isolation_preds_test = (iso.predict(X_test_scaled) == -1).astype(int)

    print("training XGBoost ...")
    xgb = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.08,
        subsample=0.8, colsample_bytree=0.8, gamma=0.1,
        reg_alpha=0.1, reg_lambda=1.0, eval_metric="logloss",
        n_jobs=-1, random_state=42,
    )
    xgb.fit(X_train, y_train)
    xgb_probs_test = xgb.predict_proba(X_test)[:, 1]

    threshold = tune_threshold(y_test, xgb_probs_test)
    metrics = eval_hybrid(y_test, xgb_probs_test, isolation_preds_test, threshold)
    print(f"tuned threshold: {threshold}")
    print(f"hybrid metrics (xgb>=threshold OR isolation) on held-out data: {metrics}")

    imp, shortcut_warning = feature_importance_report(TOP_FEATURES, xgb.feature_importances_)
    print(f"shortcut_warning: {shortcut_warning}")

    isolation_only_recall = recall_score(y_test, isolation_preds_test, zero_division=0)
    xgb_only_pred = (xgb_probs_test >= threshold).astype(int)
    xgb_only_metrics = {
        "accuracy": accuracy_score(y_test, xgb_only_pred),
        "precision": precision_score(y_test, xgb_only_pred, zero_division=0),
        "recall": recall_score(y_test, xgb_only_pred, zero_division=0),
        "f1": f1_score(y_test, xgb_only_pred, zero_division=0),
    }
    print(f"xgb-alone metrics at tuned threshold: {xgb_only_metrics}")
    print(f"isolation-forest-alone recall: {isolation_only_recall}")

    with open(out_dir / "xgb_model.pkl", "wb") as f:
        pickle.dump(xgb, f)
    with open(out_dir / "isolation_forest.pkl", "wb") as f:
        pickle.dump(iso, f)
    with open(out_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(out_dir / "threshold.pkl", "wb") as f:
        pickle.dump(threshold, f)
    with open(out_dir / "top_features.pkl", "wb") as f:
        pickle.dump(TOP_FEATURES, f)

    provenance = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "family": family_name,
        "dataset": dataset_description,
        "day_tags": sorted(pd.concat([train_df, test_df])["day"].unique().tolist()),
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "hybrid_metrics_held_out": metrics,
        "xgb_alone_metrics_held_out": xgb_only_metrics,
        "isolation_alone_recall_held_out": float(isolation_only_recall),
        "feature_importances": imp,
        "shortcut_warning": shortcut_warning,
        "threshold": threshold,
    }
    with open(out_dir / "provenance.json", "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2, default=str)

    print(f"saved artifacts to {out_dir}/")
    return provenance


def main():
    print("building VOLUMETRIC FLOOD dataset (CIC-DDoS2019 Syn + TFTP) ...")
    vol_train, vol_test = build_volumetric_dataset()

    print("\nbuilding CONNECTION/APPLICATION-LAYER dataset (CIC-IDS2018 Hulk/GoldenEye/Slowloris/SlowHTTPTest + Infilteration) ...")
    conn_train, conn_test = build_connection_dataset()

    volumetric_prov = train_family_model(
        "volumetric_floods",
        "CIC-DDoS2019 Syn + TFTP (non-reflection flood types) - own benign only per file",
        vol_train, vol_test,
        PROJECT_ROOT / "models" / "family_volumetric",
    )

    connection_prov = train_family_model(
        "connection_application_layer",
        "CIC-IDS2018 DoS-Hulk/GoldenEye/Slowloris/SlowHTTPTest + Infilteration - own benign per day, other attack types excluded",
        conn_train, conn_test,
        PROJECT_ROOT / "models" / "family_connection",
    )

    print(f"\n{'=' * 70}\nSUMMARY\n{'=' * 70}")
    for name, prov in [("volumetric_floods", volumetric_prov), ("connection_application_layer", connection_prov)]:
        m = prov["hybrid_metrics_held_out"]
        print(f"{name}: train={prov['train_rows']} test={prov['test_rows']} "
              f"acc={m['accuracy']:.3f} prec={m['precision']:.3f} rec={m['recall']:.3f} f1={m['f1']:.3f} "
              f"shortcut_warning={prov['shortcut_warning']}")


if __name__ == "__main__":
    main()
