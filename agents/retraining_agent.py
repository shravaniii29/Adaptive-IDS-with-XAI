import os
import shutil
import pickle
import logging
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
from xgboost import XGBClassifier
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score,
    recall_score, f1_score, roc_auc_score
)

log = logging.getLogger(__name__)

PROJECT_ROOT      = Path(__file__).resolve().parent.parent
MODELS_DIR        = PROJECT_ROOT / "models"
DATA_DIR          = PROJECT_ROOT / "data"

MODEL_PATH        = MODELS_DIR / "xgb_model.pkl"
BACKUP_PATH       = MODELS_DIR / "xgb_model_backup.pkl"
ISO_PATH          = MODELS_DIR / "isolation_forest.pkl"
ISO_BACKUP_PATH   = MODELS_DIR / "isolation_forest_backup.pkl"
SCALER_PATH       = MODELS_DIR / "scaler.pkl"
THRESHOLD_PATH    = MODELS_DIR / "threshold.pkl"
TOP_FEATURES_PATH = MODELS_DIR / "top_features.pkl"
RETRAIN_DATA_PATH = DATA_DIR   / "retrain_buffer.csv"

COOLDOWN_SECONDS = 300
MIN_RECALL_DELTA = -0.05
MIN_F1_DELTA     = -0.03


class RetrainingAgent:
    """
    Retraining Agent

    Monitors drift severity from the Drift Agent
    and triggers adaptive retraining when the model
    is degrading. Evaluates the candidate before
    replacing the deployed model.
    """

    def __init__(self):
        self._last_retrain_time = None

    def analyze(self, drift_result):

        drift_status = drift_result["status"]
        drift_ratio  = drift_result["drift_ratio"]

        # -----------------------------------------
        # Decide whether to retrain
        # -----------------------------------------

        should_retrain = drift_status == "MODEL DEGRADING"

        if not should_retrain:
            return self._no_retrain_result(drift_status)

        # -----------------------------------------
        # Cooldown guard
        # -----------------------------------------

        now = datetime.now()
        if self._last_retrain_time is not None:
            elapsed = (now - self._last_retrain_time).total_seconds()
            if elapsed < COOLDOWN_SECONDS:
                log.info(
                    f"[RETRAINING] Cooldown active "
                    f"({elapsed:.0f}s / {COOLDOWN_SECONDS}s). Skipping."
                )
                return {
                    "retraining_triggered": False,
                    "status": "COOLDOWN",
                    "model_updated": False,
                    "recommendation":
                        "Retraining skipped — cooldown period active.",
                    "agent_confidence": 0.5
                }

        log.info("[DRIFT] Drift detected")
        log.info("[RETRAINING] Starting retraining...")

        # -----------------------------------------
        # Load artifacts
        # -----------------------------------------

        try:
            scaler, threshold, top_features, \
                current_xgb, current_iso = self._load_artifacts()
        except Exception as e:
            log.error(f"[RETRAINING] Failed to load artifacts: {e}")
            return self._failed_result(str(e))

        # -----------------------------------------
        # Prepare data
        # -----------------------------------------

        try:
            X_tr_raw, X_tr_scaled, y_tr, \
                X_val_raw, X_val_scaled, y_val = \
                self._prepare_data(top_features, scaler)
        except Exception as e:
            log.error(f"[RETRAINING] Data preparation failed: {e}")
            return self._failed_result(str(e))

        log.info(
            f"[RETRAINING] Training data prepared — "
            f"{len(X_tr_raw)} train / {len(X_val_raw)} val rows"
        )

        # -----------------------------------------
        # Evaluate current model
        # -----------------------------------------

        current_metrics = self._evaluate_xgb(
            current_xgb, X_val_raw, y_val,
            threshold, label="Current"
        )

        # -----------------------------------------
        # Train candidate
        # -----------------------------------------

        try:
            candidate_xgb, candidate_threshold = \
                self._train_xgb(X_tr_raw, y_tr)
        except Exception as e:
            log.error(f"[RETRAINING] Candidate training failed: {e}")
            return self._failed_result(str(e))

        log.info("[RETRAINING] Candidate model trained")

        # -----------------------------------------
        # Evaluate candidate
        # -----------------------------------------

        candidate_metrics = self._evaluate_xgb(
            candidate_xgb, X_val_raw, y_val,
            candidate_threshold, label="Candidate"
        )

        # -----------------------------------------
        # Accept / Reject
        # -----------------------------------------

        accepted = self._should_accept(
            current_metrics, candidate_metrics
        )

        if accepted:
            candidate_iso = self._train_iso(X_tr_scaled, y_tr)
            self._replace_artifacts(
                candidate_xgb, candidate_threshold, candidate_iso
            )
            self._last_retrain_time = now
            log.info("[MODEL] Candidate accepted")
            log.info("[MODEL] Updated successfully")

            return {
                "retraining_triggered": True,
                "status": "COMPLETED",
                "model_updated": True,
                "old_model_metrics": current_metrics,
                "new_model_metrics": candidate_metrics,
                "recommendation":
                    "Model successfully retrained and deployed. "
                    "Monitor for continued stability.",
                "agent_confidence": 0.95
            }

        else:
            self._last_retrain_time = now
            log.info("[MODEL] Candidate rejected")
            log.info("[MODEL] Existing model retained")

            return {
                "retraining_triggered": True,
                "status": "REJECTED",
                "model_updated": False,
                "old_model_metrics": current_metrics,
                "new_model_metrics": candidate_metrics,
                "recommendation":
                    "Candidate model did not meet quality threshold. "
                    "Existing model retained. Collect more data.",
                "agent_confidence": 0.70
            }

    # =====================================================
    # Internal helpers
    # =====================================================

    def _no_retrain_result(self, drift_status):
        return {
            "retraining_triggered": False,
            "status": "NOT_REQUIRED",
            "model_updated": False,
            "recommendation":
                f"Drift status is '{drift_status}'. "
                "Retraining not required at this time.",
            "agent_confidence": 0.90
        }

    def _failed_result(self, reason):
        return {
            "retraining_triggered": True,
            "status": "FAILED",
            "model_updated": False,
            "reason": reason,
            "recommendation":
                "Retraining failed. Check logs and data buffer.",
            "agent_confidence": 0.0
        }

    def _load_artifacts(self):
        def load(path):
            with open(path, "rb") as f:
                return pickle.load(f)
        return (
            load(SCALER_PATH),
            load(THRESHOLD_PATH),
            load(TOP_FEATURES_PATH),
            load(MODEL_PATH),
            load(ISO_PATH),
        )

    def _prepare_data(self, top_features, scaler):
        if not RETRAIN_DATA_PATH.exists():
            raise FileNotFoundError(
                f"Retraining buffer not found at {RETRAIN_DATA_PATH}. "
                "Populate it with labelled data before retraining."
            )

        df = pd.read_csv(RETRAIN_DATA_PATH)
        df.columns = df.columns.str.strip()

        missing = [f for f in top_features if f not in df.columns]
        if missing:
            raise ValueError(f"Buffer missing features: {missing}")
        if "label" not in df.columns:
            raise ValueError(
                "Buffer must contain a 'label' column (0=benign, 1=attack)."
            )

        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna(subset=top_features + ["label"])

        X_raw = df[top_features].values
        y     = df["label"].astype(int).values

        split        = int(len(X_raw) * 0.8)
        X_tr_raw     = X_raw[:split];   y_tr  = y[:split]
        X_val_raw    = X_raw[split:];   y_val = y[split:]
        X_tr_scaled  = scaler.transform(X_tr_raw)
        X_val_scaled = scaler.transform(X_val_raw)

        return X_tr_raw, X_tr_scaled, y_tr, X_val_raw, X_val_scaled, y_val

    def _train_xgb(self, X_raw, y):
        scale_pos_weight = (y == 0).sum() / max((y == 1).sum(), 1)
        model = XGBClassifier(
            objective="binary:logistic",
            eval_metric="aucpr",
            scale_pos_weight=scale_pos_weight,
            max_depth=10,
            n_estimators=400,
            learning_rate=0.03,
            subsample=0.8,
            colsample_bytree=0.8,
            gamma=5,
            min_child_weight=5,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_raw, y)
        probs     = model.predict_proba(X_raw)[:, 1]
        threshold = float(np.percentile(probs, 80))
        return model, threshold

    def _train_iso(self, X_scaled, y):
        X_benign     = X_scaled[y == 0]
        attack_ratio = max((y == 1).sum() / len(y), 0.01)
        iso = IsolationForest(
            n_estimators=300,
            contamination=attack_ratio,
            max_samples=256,
            max_features=0.8,
            random_state=42,
            n_jobs=-1,
        )
        iso.fit(X_benign)
        return iso

    def _evaluate_xgb(self, model, X_val_raw, y_val, threshold, label="Model"):
        probs  = model.predict_proba(X_val_raw)[:, 1]
        y_pred = (probs >= threshold).astype(int)
        try:
            auc = round(roc_auc_score(y_val, probs), 4)
        except Exception:
            auc = None
        metrics = {
            "accuracy":  round(accuracy_score(y_val, y_pred), 4),
            "precision": round(precision_score(y_val, y_pred, zero_division=0), 4),
            "recall":    round(recall_score(y_val, y_pred, zero_division=0), 4),
            "f1":        round(f1_score(y_val, y_pred, zero_division=0), 4),
            "roc_auc":   auc,
        }
        log.info(
            f"[EVALUATION] {label} — "
            f"Accuracy: {metrics['accuracy']} | "
            f"Precision: {metrics['precision']} | "
            f"Recall: {metrics['recall']} | "
            f"F1: {metrics['f1']} | "
            f"ROC-AUC: {metrics['roc_auc']}"
        )
        return metrics

    def _should_accept(self, current, candidate):
        recall_delta = candidate["recall"] - current["recall"]
        f1_delta     = candidate["f1"]     - current["f1"]
        if recall_delta < MIN_RECALL_DELTA:
            log.info(
                f"[EVALUATION] Recall dropped {recall_delta:.4f} "
                f"(limit {MIN_RECALL_DELTA}). Rejecting."
            )
            return False
        if f1_delta < MIN_F1_DELTA:
            log.info(
                f"[EVALUATION] F1 dropped {f1_delta:.4f} "
                f"(limit {MIN_F1_DELTA}). Rejecting."
            )
            return False
        return True

    def _replace_artifacts(self, xgb_model, threshold, iso_model):
        if MODEL_PATH.exists():
            shutil.copy(MODEL_PATH, BACKUP_PATH)
            log.info(f"[MODEL] XGBoost backup → {BACKUP_PATH}")
        if ISO_PATH.exists():
            shutil.copy(ISO_PATH, ISO_BACKUP_PATH)
            log.info(f"[MODEL] IsoForest backup → {ISO_BACKUP_PATH}")
        for path, obj in [
            (MODEL_PATH, xgb_model),
            (THRESHOLD_PATH, threshold),
            (ISO_PATH, iso_model),
        ]:
            with open(path, "wb") as f:
                pickle.dump(obj, f)