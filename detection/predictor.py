import json
import os
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from detection import fast_isolation_forest


# -------------------------------------------------
# Project paths
# -------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Overridable so a candidate artifact set (e.g. models/deployed_v2, under
# review before promotion) can be tested without touching the deployed
# default at models/.
MODELS_DIR = Path(os.environ.get("DEPLOYED_MODELS_DIR", PROJECT_ROOT / "models"))


# -------------------------------------------------
# Load deployment artifacts
# -------------------------------------------------

def _force_single_threaded(model):
    """Trained with n_jobs=-1 (all cores) - fine for training, but joblib's
    multiprocessing backend spins up a fresh worker pool on every single
    predict()/decision_function() call with no persistent Parallel context
    to reuse, since live serving scores one flow at a time. Profiling
    found this alone costing hundreds of ms per flow - pure process
    spawn/teardown overhead for a single-row prediction that gets no
    benefit from parallelism. n_jobs is a live attribute, not part of the
    fitted tree structure, so overriding it post-load needs no retrain."""
    if hasattr(model, "n_jobs"):
        model.n_jobs = 1
    return model


with open(MODELS_DIR / "xgb_model.pkl", "rb") as file:
    xgb_model = _force_single_threaded(pickle.load(file))


with open(MODELS_DIR / "isolation_forest.pkl", "rb") as file:
    isolation_forest = _force_single_threaded(pickle.load(file))


with open(MODELS_DIR / "scaler.pkl", "rb") as file:
    scaler = pickle.load(file)


with open(MODELS_DIR / "threshold.pkl", "rb") as file:
    threshold = pickle.load(file)


with open(MODELS_DIR / "top_features.pkl", "rb") as file:
    top_features = pickle.load(file)


# -------------------------------------------------
# Fusion of the two detectors
# -------------------------------------------------
#
# "confidence" (default): the original V7 design, a weighted score
#
#       confidence = (1 - alpha) * xgb_probability + alpha * isolation_anomaly
#
# flagged when confidence >= fusion_threshold. isolation_anomaly is
# Isolation Forest's own anomaly score s(x) in (0, 1] (higher = more
# anomalous), so no dataset-specific min/max normalisation is needed.
# Both numbers are read from MODELS_DIR/fusion_config.json, written by
# tune_fusion_threshold.py; the defaults below are only a fallback.
#
# "or": the previous rule - flag if XGBoost >= threshold OR Isolation
# Forest calls the flow an anomaly. It has high recall but flags a lot
# of ordinary traffic. Select it with IDS_FUSION_MODE=or.
#
# Caveat from the calibration run (fusion_calibration/): the tuned
# threshold sits just under a tight cluster of flood-flow scores, so
# recall is sensitive to it (0.179 -> 98% recall, 0.20 -> 51%), and
# ordinary traffic overlaps attack scores. Re-run tune_fusion_threshold.py
# whenever the models or the feature pipeline change.

FUSION_MODE = os.environ.get("IDS_FUSION_MODE", "confidence").strip().lower()

if FUSION_MODE not in ("confidence", "or"):
    raise ValueError(
        f"IDS_FUSION_MODE must be 'confidence' or 'or', got {FUSION_MODE!r}"
    )

FUSION_ALPHA = 0.3
FUSION_THRESHOLD = 0.55

_fusion_config_path = MODELS_DIR / "fusion_config.json"

if _fusion_config_path.exists():
    with open(_fusion_config_path, "r", encoding="utf-8") as file:
        _fusion_config = json.load(file)
    FUSION_ALPHA = float(_fusion_config.get("alpha", FUSION_ALPHA))
    FUSION_THRESHOLD = float(_fusion_config.get("threshold", FUSION_THRESHOLD))


# -------------------------------------------------
# Prediction function
# -------------------------------------------------

def predict_flow(features):
    """
    Run a 25-feature network flow through the deployed
    XGBoost and Isolation Forest models.
    """

    # ---------------------------------------------
    # Validate feature structure
    # ---------------------------------------------

    missing_features = [
        feature
        for feature in top_features
        if feature not in features
    ]

    if missing_features:
        raise ValueError(
            f"Missing features: {missing_features}"
        )


    # ---------------------------------------------
    # Preserve exact training feature order
    # ---------------------------------------------

    feature_values = [
        features[feature]
        for feature in top_features
    ]

    feature_frame = pd.DataFrame(
        [feature_values],
        columns=top_features
    )


    # ---------------------------------------------
    # Scale features
    # ---------------------------------------------

    scaled_features = scaler.transform(feature_frame)


  # ---------------------------------------------
    # XGBoost prediction
    # XGBoost was trained on unscaled features
    # ---------------------------------------------

    xgb_probability = float(
        xgb_model.predict_proba(feature_frame)[0][1]
    )

    xgb_prediction = int(
        xgb_probability >= threshold
    )


    # ---------------------------------------------
    # Isolation Forest prediction
    # ---------------------------------------------

    isolation_prediction_raw = int(
        fast_isolation_forest.predict(isolation_forest, scaled_features)[0]
    )

    isolation_score = float(
        fast_isolation_forest.decision_function(
            isolation_forest, scaled_features
        )[0]
    )

    # Isolation Forest:
    #  1  = normal
    # -1  = anomaly

    isolation_prediction = int(
        isolation_prediction_raw == -1
    )


    # ---------------------------------------------
    # Hybrid result
    # ---------------------------------------------

    # decision_function() = -s(x) - offset_, where s(x) in (0, 1] is the
    # Isolation Forest anomaly score. Recover s(x): higher = more anomalous.
    isolation_anomaly = float(
        -isolation_score - isolation_forest.offset_
    )

    confidence_score = (
        (1.0 - FUSION_ALPHA) * xgb_probability
        + FUSION_ALPHA * isolation_anomaly
    )

    if FUSION_MODE == "confidence":
        hybrid_prediction = int(confidence_score >= FUSION_THRESHOLD)
    else:
        hybrid_prediction = int(
            xgb_prediction == 1
            or isolation_prediction == 1
        )


    return {

        "xgb_probability": xgb_probability,

        "xgb_prediction": xgb_prediction,

        "isolation_score": isolation_score,

        "isolation_anomaly": isolation_anomaly,

        "isolation_prediction": isolation_prediction,

        "confidence_score": confidence_score,

        "fusion_mode": FUSION_MODE,

        "hybrid_prediction": hybrid_prediction,
    }