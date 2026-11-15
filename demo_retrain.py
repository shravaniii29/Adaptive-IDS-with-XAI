"""Lightweight candidate retraining for the demo, off locally available data.

The full RetrainingAgent (agents/retraining_agent.py) retrains on the
CIC-IDS2018 CSVs, which are not on this machine. This trains a candidate on
the labelled 25-feature flow CSVs in data/lsnm2024/ instead, so a retrain can
actually run and produce a candidate during a demo in a few seconds.

Like the agent, it is candidate-only: it writes a new candidate under
models/candidates/<timestamp>/ with its metrics and provenance, and never
touches the deployed artifacts in models/. Promotion (replacing the deployed
model) is a separate, explicitly-approved step - see /retrain/candidates/
{id}/promote in app/main.py.

    python demo_retrain.py        # train one candidate, print where it went
"""

import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parent
MODELS = ROOT / "models"
CANDIDATES = MODELS / "candidates"
DATA_DIR = ROOT / "data" / "lsnm2024"
# The attack+benign 25-feature CSVs; each already carries a Binary_Label column.
SOURCE_GLOB = "*_25feature.csv"
ROWS_PER_FILE = 4000


def _load_deployed():
    def load(name):
        with open(MODELS / name, "rb") as fh:
            return pickle.load(fh)
    return load("scaler.pkl"), load("threshold.pkl"), load("top_features.pkl"), load("xgb_model.pkl")


def _load_dataset(top_features):
    files = sorted(DATA_DIR.glob(SOURCE_GLOB))
    if not files:
        raise FileNotFoundError(f"no training CSVs found in {DATA_DIR}")
    frames = []
    counts = {}
    for path in files:
        df = pd.read_csv(path, nrows=ROWS_PER_FILE)
        frames.append(df)
        counts[path.name] = len(df)
    raw = pd.concat(frames, ignore_index=True)
    if "Binary_Label" in raw.columns:
        y = raw["Binary_Label"].astype(int)
    else:
        y = (raw["Label"].astype(str).str.strip().str.upper() != "BENIGN").astype(int)
    X = raw.reindex(columns=top_features, fill_value=0)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0).clip(-1e9, 1e9).astype(np.float64)
    return X, y, counts


def _split(X, y, scaler):
    # Stratified-ish split per label so both sides have benign and attack.
    train_idx, val_idx = [], []
    rng = np.random.default_rng(42)
    for label in (0, 1):
        idx = y[y == label].index.to_numpy().copy()
        rng.shuffle(idx)
        cut = int(len(idx) * 0.8)
        train_idx += list(idx[:cut])
        val_idx += list(idx[cut:])
    Xtr, Xval = X.loc[train_idx], X.loc[val_idx]
    ytr, yval = y.loc[train_idx], y.loc[val_idx]
    return Xtr, scaler.transform(Xtr), ytr, Xval, scaler.transform(Xval), yval


def _metrics(model, X, y, threshold):
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= threshold).astype(int)
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
    }


def run_demo_retrain():
    """Train one candidate and write it under models/candidates/. Returns a
    result dict; raises on failure (caller records the error)."""
    scaler, threshold, top_features, deployed_xgb = _load_deployed()
    X, y, counts = _load_dataset(top_features)
    if y.nunique() < 2 or len(X) < 50:
        raise ValueError("local data lacks enough benign and attack rows to retrain")

    Xtr, Xtr_s, ytr, Xval, Xval_s, yval = _split(X, y, scaler)

    deployed_metrics = _metrics(deployed_xgb, Xval, yval, threshold)

    candidate_xgb = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1, subsample=0.8,
        colsample_bytree=0.8, eval_metric="logloss",
    )
    candidate_xgb.fit(Xtr, ytr)
    candidate_metrics = _metrics(candidate_xgb, Xval, yval, threshold)

    candidate_iso = IsolationForest(n_estimators=150, contamination=0.1, random_state=42)
    candidate_iso.fit(Xtr_s[ytr.to_numpy() == 0] if (ytr.to_numpy() == 0).any() else Xtr_s)

    accepted = (
        candidate_metrics["recall"] >= deployed_metrics["recall"] - 0.05
        and candidate_metrics["f1"] >= deployed_metrics["f1"] - 0.03
    )

    ts = time.strftime("%Y%m%d_%H%M%S")
    out = CANDIDATES / ts
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "xgb_model.pkl", "wb") as fh:
        pickle.dump(candidate_xgb, fh)
    with open(out / "isolation_forest.pkl", "wb") as fh:
        pickle.dump(candidate_iso, fh)

    provenance = {
        "id": ts,
        "created_at": time.time(),
        "dataset": "data/lsnm2024 (local labelled 25-feature flows)",
        "source_files": counts,
        "training_rows": int(len(Xtr)),
        "validation_rows": int(len(Xval)),
        "threshold": float(threshold),
        "deployed_metrics": deployed_metrics,
        "candidate_metrics": candidate_metrics,
        "accepted": bool(accepted),
        "status": "pending",
        "note": "Candidate only. Deployed model was not changed. Promotion requires explicit approval.",
    }
    with open(out / "candidate.json", "w") as fh:
        json.dump(provenance, fh, indent=2)
    return provenance


if __name__ == "__main__":
    result = run_demo_retrain()
    print(json.dumps(result, indent=2))
