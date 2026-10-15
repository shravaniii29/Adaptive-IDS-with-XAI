"""
Train a candidate model on the CIC-DDoS2019 dataset (Mendeley mirror,
DOI 10.17632/ssnc74xm6r.1) and compare it against the currently deployed
model. Mirrors the safety principle in agents/retraining_agent.py:
this NEVER overwrites the deployed artifacts in models/ - it only
writes a reviewable candidate under models/candidates/.

The dataset has no Flow ID / IP / Timestamp columns and uses the newer
full-length CICFlowMeter column names, so it needs its own preprocessing
pass rather than RetrainingAgent._preprocess_v7 (which expects the raw
CIC-IDS2018 export format). Feature engineering and model training reuse
RetrainingAgent's static methods so the candidate is produced exactly the
same way the live adaptive-retraining pipeline would produce one.
"""

import pickle
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from agents.retraining_agent import RetrainingAgent

PROJECT_ROOT = Path(__file__).resolve().parent
MODELS_DIR = PROJECT_ROOT / "models"
DATASET_PATH = PROJECT_ROOT / "data" / "ddos2019" / "cicddos2019_mendeley.csv"

# Mendeley/newer CICFlowMeter column name -> abbreviated name used by
# feature_extraction/feature_extractor.py and models/top_features.pkl
COLUMN_RENAME = {
    "Flow Packets/s": "Flow Pkts/s",
    "Fwd Packets/s": "Fwd Pkts/s",
    "Packet Length Max": "Pkt Len Max",
    "Avg Packet Size": "Pkt Size Avg",
    "Fwd IAT Total": "Fwd IAT Tot",
    "Fwd Header Length": "Fwd Header Len",
    "Fwd Packets Length Total": "TotLen Fwd Pkts",
    "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Init Bwd Win Bytes": "Init Bwd Win Byts",
    "Bwd Packet Length Max": "Bwd Pkt Len Max",
    "Subflow Bwd Bytes": "Subflow Bwd Byts",
    "Bwd Packets Length Total": "TotLen Bwd Pkts",
    "Avg Bwd Segment Size": "Bwd Seg Size Avg",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean",
    "Bwd Packet Length Std": "Bwd Pkt Len Std",
    "Packet Length Mean": "Pkt Len Mean",
}


def load_deployed_artifacts():
    def load(name):
        with open(MODELS_DIR / name, "rb") as handle:
            return pickle.load(handle)
    return load("scaler.pkl"), load("threshold.pkl"), load("top_features.pkl"), load("xgb_model.pkl")


def prepare_data(top_features, scaler):
    raw = pd.read_csv(DATASET_PATH, on_bad_lines="skip")
    raw.columns = raw.columns.str.strip()
    raw = raw.rename(columns=COLUMN_RENAME)

    y = raw["Class"].astype(str).str.strip().str.lower().apply(lambda v: 0 if v == "benign" else 1)

    X = raw.drop(columns=["Unnamed: 0", "Label", "Class"], errors="ignore")
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    X = RetrainingAgent._feature_engineering_v7(X).reindex(columns=top_features, fill_value=0)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0).clip(-1e9, 1e9).astype(np.float64)

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    provenance = {
        "dataset": "CIC-DDoS2019 (Mendeley mirror)",
        "source": "https://data.mendeley.com/datasets/ssnc74xm6r/1",
        "doi": "10.17632/ssnc74xm6r.1",
        "license": "CC BY 4.0",
        "total_rows": int(len(X)),
        "training_rows": int(len(X_train)),
        "validation_rows": int(len(X_val)),
        "label_breakdown": raw["Label"].value_counts().to_dict(),
        "note": "Self-contained benign+attack split (no CIC-IDS2018 blend - "
                "those files are not present locally). Avoids mixing benign "
                "traffic from a different capture year/session with these attacks.",
    }

    return X_train, scaler.transform(X_train), y_train, X_val, scaler.transform(X_val), y_val, provenance


def write_candidate(xgb_model, iso_model, threshold, provenance, current_metrics, candidate_metrics, accepted, created_at):
    candidates_dir = MODELS_DIR / "candidates"
    candidates_dir.mkdir(parents=True, exist_ok=True)
    candidate_id = created_at.strftime("%Y%m%dT%H%M%SZ")

    paths = {
        "xgb": candidates_dir / f"xgb_candidate_ddos2019_{candidate_id}.pkl",
        "isolation_forest": candidates_dir / f"isolation_forest_candidate_ddos2019_{candidate_id}.pkl",
        "threshold": candidates_dir / f"threshold_candidate_ddos2019_{candidate_id}.pkl",
        "metadata": candidates_dir / f"candidate_ddos2019_{candidate_id}.json",
    }

    for key, artifact in (("xgb", xgb_model), ("isolation_forest", iso_model), ("threshold", threshold)):
        with open(paths[key], "wb") as handle:
            pickle.dump(artifact, handle)

    import json
    paths["metadata"].write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "created_at": created_at.isoformat(),
                "candidate_accepted": accepted,
                "current_metrics": current_metrics,
                "candidate_metrics": candidate_metrics,
                "provenance": provenance,
                "deployment": "Prototype-only: manually promote after review; restart/reload required.",
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return {key: str(path) for key, path in paths.items()}


def main():
    scaler, deployed_threshold, top_features, deployed_xgb = load_deployed_artifacts()

    print(f"Loading {DATASET_PATH.name} ...")
    X_train, X_train_scaled, y_train, X_val, X_val_scaled, y_val, provenance = prepare_data(top_features, scaler)

    print(f"Training rows: {len(X_train)}  Validation rows: {len(X_val)}")
    print(f"Train label balance: {y_train.value_counts().to_dict()}")
    print(f"Val label balance:   {y_val.value_counts().to_dict()}")

    print("\nEvaluating the CURRENTLY DEPLOYED model on this new validation split (unseen attack types)...")
    current_metrics = RetrainingAgent._evaluate_xgb(deployed_xgb, X_val, y_val, deployed_threshold)
    print("Deployed model metrics:", current_metrics)

    print("\nTraining candidate XGBoost + Isolation Forest on CIC-DDoS2019 ...")
    candidate_xgb, candidate_threshold = RetrainingAgent._train_xgb(X_train, y_train, X_val, y_val)
    candidate_iso = RetrainingAgent._train_iso(X_train_scaled, y_train)
    candidate_metrics = RetrainingAgent._evaluate_xgb(candidate_xgb, X_val, y_val, candidate_threshold)
    print("Candidate model metrics:", candidate_metrics)

    accepted = RetrainingAgent._should_accept(current_metrics, candidate_metrics)
    print(f"\nAcceptance check (recall/f1 must not regress vs deployed model): {'ACCEPTED' if accepted else 'REJECTED'}")

    now = datetime.now(timezone.utc)
    paths = write_candidate(
        candidate_xgb, candidate_iso, candidate_threshold,
        provenance, current_metrics, candidate_metrics, accepted, now,
    )

    print("\nCandidate artifacts written (deployed models/ untouched):")
    for key, path in paths.items():
        print(f"  {key}: {path}")


if __name__ == "__main__":
    main()
