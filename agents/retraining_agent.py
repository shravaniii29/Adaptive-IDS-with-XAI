"""Safe, provenance-recorded prototype retraining for the CIC-IDS2018 model."""

import json
import logging
import os
import pickle
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from xgboost import XGBClassifier

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
CANDIDATES_DIR = MODELS_DIR / "candidates"
DATASET_DIR = Path(os.environ.get("CIC_IDS2018_DATA_DIR", PROJECT_ROOT / "data" / "cicids2018"))
TRAINING_FILES = (
    "02-14-2018.csv", "02-15-2018.csv", "02-16-2018.csv", "02-20-2018.csv",
    "02-21-2018.csv", "02-22-2018.csv", "02-23-2018.csv",
)
ROWS_PER_FILE = int(os.environ.get("CIC_IDS2018_RETRAIN_ROWS_PER_FILE", "8000"))
COOLDOWN_SECONDS = 300
MIN_RECALL_DELTA = -0.05
MIN_F1_DELTA = -0.03


class RetrainingAgent:
    """Create a candidate only; it never replaces the deployed model artifacts."""

    def __init__(self):
        self._last_retrain_time = None

    def analyze(self, drift_result):
        drift_status = drift_result["status"]
        if drift_status != "MODEL DEGRADING":
            return self._no_retrain_result(drift_status)

        now = datetime.now(timezone.utc)
        if self._last_retrain_time and (now - self._last_retrain_time).total_seconds() < COOLDOWN_SECONDS:
            return self._result(False, "COOLDOWN", "Retraining skipped - cooldown period active.")

        try:
            scaler, threshold, top_features, current_xgb = self._load_deployed_artifacts()
            prepared = self._prepare_data(top_features, scaler)
            X_train, X_train_scaled, y_train, X_val, X_val_scaled, y_val, provenance = prepared
        except Exception as exc:
            log.exception("[RETRAINING] Candidate preparation failed")
            return self._result(True, "FAILED", "Candidate preparation failed.", reason=str(exc))

        current_metrics = self._evaluate_xgb(current_xgb, X_val, y_val, threshold)
        try:
            candidate_xgb, candidate_threshold = self._train_xgb(X_train, y_train, X_val, y_val)
            candidate_iso = self._train_iso(X_train_scaled, y_train)
            candidate_metrics = self._evaluate_xgb(candidate_xgb, X_val, y_val, candidate_threshold)
            accepted = self._should_accept(current_metrics, candidate_metrics)
            paths = self._write_candidate(candidate_xgb, candidate_iso, candidate_threshold, provenance, current_metrics, candidate_metrics, accepted, now)
        except Exception as exc:
            log.exception("[RETRAINING] Candidate training failed")
            return self._result(True, "FAILED", "Candidate training failed.", reason=str(exc))

        self._last_retrain_time = now
        status = "CANDIDATE_READY" if accepted else "CANDIDATE_REJECTED"
        recommendation = (
            "Candidate artifacts were saved separately for manual review; deployed artifacts were not changed. "
            "Promotion requires an explicit review and a process restart/model reload."
            if accepted else "Candidate was saved for audit but did not meet acceptance criteria; deployed artifacts were not changed."
        )
        return self._result(True, status, recommendation, current_metrics=current_metrics,
                            candidate_metrics=candidate_metrics, candidate_accepted=accepted,
                            candidate_artifacts=paths, provenance=provenance)

    def _load_deployed_artifacts(self):
        def load(name):
            with open(MODELS_DIR / name, "rb") as handle:
                return pickle.load(handle)
        return load("scaler.pkl"), load("threshold.pkl"), load("top_features.pkl"), load("xgb_model.pkl")

    def _prepare_data(self, top_features, scaler):
        source_files = [DATASET_DIR / name for name in TRAINING_FILES]
        missing = [str(path) for path in source_files if not path.is_file()]
        if missing:
            raise FileNotFoundError("CIC-IDS2018 training files missing: " + ", ".join(missing))

        frames = []
        source_rows = {}
        for path in source_files:
            chunk = next(pd.read_csv(path, chunksize=50000, low_memory=False))
            chunk.columns = chunk.columns.str.strip()
            chunk = chunk[chunk["Label"].astype(str).str.strip().str.lower() != "label"].head(ROWS_PER_FILE)
            frames.append(chunk)
            source_rows[path.name] = len(chunk)
        raw = pd.concat(frames, ignore_index=True)
        X, y = self._preprocess_v7(raw)
        X = self._feature_engineering_v7(X).reindex(columns=top_features, fill_value=0)
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0).clip(-1e9, 1e9).astype(np.float64)
        if len(X) < 10 or y.nunique() < 2:
            raise ValueError("The CIC-IDS2018 retraining sample must contain sufficient benign and attack rows.")
        # V7 sorts flows by timestamp.  Within the bounded pool, split each label
        # in timestamp order so both the train and candidate-validation sets are valid.
        train_indices, val_indices = [], []
        for label in (0, 1):
            indices = y[y == label].index.to_list()
            split = int(len(indices) * 0.8)
            if split == 0 or split == len(indices):
                raise ValueError("The bounded CIC-IDS2018 subset lacks enough rows for each binary label.")
            train_indices.extend(indices[:split])
            val_indices.extend(indices[split:])
        X_train, X_val = X.loc[train_indices], X.loc[val_indices]
        y_train, y_val = y.loc[train_indices], y.loc[val_indices]
        provenance = {
            "dataset": "CIC-IDS2018",
            "source_directory": str(DATASET_DIR),
            "source_files": list(source_rows),
            "rows_per_file": source_rows,
            "total_rows_after_v7_preprocessing": int(len(X)),
            "training_rows": int(len(X_train)),
            "validation_rows": int(len(X_val)),
            "preprocessing": "V7: timestamp sort, duplicate removal, NaN/Inf handling, binary labels, feature engineering, deployed top_features, RobustScaler",
            "excluded_final_test_files": ["02-28-2018.csv", "03-01-2018.csv", "03-02-2018.csv"],
        }
        return X_train, scaler.transform(X_train), y_train, X_val, scaler.transform(X_val), y_val, provenance

    @staticmethod
    def _preprocess_v7(df):
        df = df.copy()
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
        df = df.dropna(subset=["Timestamp"]).sort_values("Timestamp").drop_duplicates()
        df = df.replace([np.inf, -np.inf], np.nan).drop(columns=["Flow ID", "Src IP", "Dst IP", "Src Port"], errors="ignore")
        df["Label"] = df["Label"].apply(lambda value: 0 if str(value).strip().lower() == "benign" else 1)
        return df.drop(columns=["Label", "Timestamp"], errors="ignore").apply(pd.to_numeric, errors="coerce").fillna(0), df["Label"]

    @staticmethod
    def _feature_engineering_v7(X):
        X = X.copy()
        if {"TotLen Fwd Pkts", "Total Fwd Packets"} <= set(X):
            X["bytes_per_pkt"] = X["TotLen Fwd Pkts"] / (X["Total Fwd Packets"] + 1)
        if {"Fwd Pkts/s", "Flow Pkts/s"} <= set(X):
            X["pkt_rate_ratio"] = X["Fwd Pkts/s"] / (X["Flow Pkts/s"] + 1)
        if {"Flow IAT Std", "Flow IAT Mean"} <= set(X):
            X["iat_variation"] = X["Flow IAT Std"] / (X["Flow IAT Mean"] + 1)
        return X

    @staticmethod
    def _train_xgb(X_train, y_train, X_val, y_val):
        model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.08, subsample=0.8,
                              colsample_bytree=0.8, gamma=0.1, reg_alpha=0.1, reg_lambda=1.0,
                              eval_metric="logloss", n_jobs=-1, random_state=42)
        model.fit(X_train, y_train)
        probabilities = model.predict_proba(X_val)[:, 1]
        threshold = max(np.linspace(0, 1, 100), key=lambda value: f1_score(y_val, probabilities >= value, zero_division=0))
        return model, float(threshold)

    @staticmethod
    def _train_iso(X_train_scaled, y_train):
        model = IsolationForest(n_estimators=500, max_samples=512, contamination=0.12,
                                max_features=0.8, random_state=42, n_jobs=-1)
        model.fit(X_train_scaled[np.asarray(y_train) == 0])
        return model

    @staticmethod
    def _evaluate_xgb(model, X_val, y_val, threshold):
        probabilities = model.predict_proba(X_val)[:, 1]
        predictions = (probabilities >= threshold).astype(int)
        try:
            auc = round(roc_auc_score(y_val, probabilities), 4)
        except ValueError:
            auc = None
        return {"accuracy": round(accuracy_score(y_val, predictions), 4), "precision": round(precision_score(y_val, predictions, zero_division=0), 4), "recall": round(recall_score(y_val, predictions, zero_division=0), 4), "f1": round(f1_score(y_val, predictions, zero_division=0), 4), "roc_auc": auc}

    @staticmethod
    def _should_accept(current, candidate):
        return candidate["recall"] - current["recall"] >= MIN_RECALL_DELTA and candidate["f1"] - current["f1"] >= MIN_F1_DELTA

    @staticmethod
    def _write_candidate(xgb_model, iso_model, threshold, provenance, current_metrics, candidate_metrics, accepted, created_at):
        CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
        candidate_id = created_at.strftime("%Y%m%dT%H%M%SZ")
        paths = {"xgb": CANDIDATES_DIR / f"xgb_candidate_{candidate_id}.pkl", "isolation_forest": CANDIDATES_DIR / f"isolation_forest_candidate_{candidate_id}.pkl", "threshold": CANDIDATES_DIR / f"threshold_candidate_{candidate_id}.pkl", "metadata": CANDIDATES_DIR / f"candidate_{candidate_id}.json"}
        for key, artifact in (("xgb", xgb_model), ("isolation_forest", iso_model), ("threshold", threshold)):
            with open(paths[key], "wb") as handle:
                pickle.dump(artifact, handle)
        paths["metadata"].write_text(json.dumps({"candidate_id": candidate_id, "created_at": created_at.isoformat(), "candidate_accepted": accepted, "current_metrics": current_metrics, "candidate_metrics": candidate_metrics, "provenance": provenance, "deployment": "Prototype-only: manually promote after review; restart/reload required."}, indent=2), encoding="utf-8")
        return {key: str(path) for key, path in paths.items()}

    @staticmethod
    def _result(triggered, status, recommendation, **extra):
        return {"retraining_triggered": triggered, "status": status, "model_updated": False, "recommendation": recommendation, "agent_confidence": 0.95 if status == "CANDIDATE_READY" else 0.7, **extra}
