"""
V8 live prediction module.

This is a NEW file — it does NOT replace, modify, or import
detection/predictor.py (V7). V7's predictor stays fully intact and
usable for comparison/research, exactly as instructed.

Loads ONLY the 5 finalized V8 artifacts from
v8_training/models_v8/ and reproduces V8's exact hybrid
OR-fusion logic, feature ordering, and preprocessing
(RobustScaler on the Isolation Forest path only — XGBoost sees
raw/unscaled features, identical to V7's and V8's training
methodology). No new threshold, fusion method, feature, scaler,
training step, or preprocessing step is introduced here.
"""

import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


logger = logging.getLogger("ids.predictor_v8")


# -------------------------------------------------
# Project paths
# -------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

V8_MODELS_DIR = PROJECT_ROOT / "v8_training" / "models_v8"


# -------------------------------------------------
# Load V8 deployment artifacts
# (exactly the 5 finalized artifacts from V8 training —
#  nothing retrained, nothing regenerated here)
#
# Loaded with joblib.load() rather than pickle.load(): the V8
# training script (v8_training/step4_train_v8_models.py) saved
# every artifact with joblib.dump(), which — for a fitted estimator
# carrying a numpy object-dtype array attribute such as
# scikit-learn's `feature_names_in_` — embeds a nested, joblib-
# specific pickle sub-stream that plain pickle.load() cannot
# traverse (it raised _pickle.UnpicklingError: STACK_GLOBAL
# requires str on isolation_forest_v8.pkl / scaler_v8.pkl).
# joblib.load() is the format-correct counterpart to joblib.dump()
# and is already a scikit-learn dependency, so no new package is
# required. This is a loader-API fix only — no artifact, threshold,
# feature set, or prediction logic changes.
# -------------------------------------------------

xgb_model_v8 = joblib.load(V8_MODELS_DIR / "xgb_model_v8.pkl")

isolation_forest_v8 = joblib.load(V8_MODELS_DIR / "isolation_forest_v8.pkl")

scaler_v8 = joblib.load(V8_MODELS_DIR / "scaler_v8.pkl")

threshold_v8 = joblib.load(V8_MODELS_DIR / "threshold_v8.pkl")

top_features_v8 = joblib.load(V8_MODELS_DIR / "top_features_v8.pkl")


logger.info(
    "V8 predictor loaded: %d features, threshold=%.6f",
    len(top_features_v8),
    threshold_v8,
)


# -------------------------------------------------
# Prediction function
# -------------------------------------------------

def predict_flow_v8(features):
    """
    Run a V8 25-feature network flow through the finalized
    V8 XGBoost and Isolation Forest models.

    Mirrors detection/predictor.py's predict_flow() structure
    and output shape exactly, so DetectionService can use either
    interchangeably. The only differences are: (1) which artifacts
    are loaded (V8 instead of V7), (2) V8's own feature list/order,
    (3) V8's own threshold, and (4) a defensive non-finite-value
    guard described below — the OR-fusion logic itself
    (xgb_prediction OR isolation_prediction) is unchanged from V7.
    """

    # ---------------------------------------------
    # Validate feature structure
    # ---------------------------------------------

    missing_features = [
        feature
        for feature in top_features_v8
        if feature not in features
    ]

    if missing_features:
        raise ValueError(
            f"[V8] Missing features: {missing_features}"
        )

    # ---------------------------------------------
    # Preserve exact V8 training feature order
    # ---------------------------------------------

    feature_values = [
        features[feature]
        for feature in top_features_v8
    ]

    # ---------------------------------------------
    # Defensive non-finite guard (logging only).
    #
    # V8 training/evaluation already treats zero-duration flows
    # (Flow Duration == 0) by setting the derived rate features to
    # 0.0 — the live feature_extractor's zero-duration guard does
    # the same at the source (see feature_extraction/feature_extractor.py).
    # This is a safety net for any other unforeseen NaN/Inf value
    # reaching this point live (e.g. a pathological flow), so the
    # deployed service never crashes or silently feeds garbage to
    # the models. It performs no new preprocessing method — it only
    # substitutes 0.0 for a non-finite value and logs a warning, the
    # same treatment already applied to the known zero-duration case.
    # ---------------------------------------------

    cleaned_values = []

    for feature_name, value in zip(top_features_v8, feature_values):

        numeric_value = float(value)

        if not np.isfinite(numeric_value):

            logger.warning(
                "[V8] Non-finite feature value for '%s' (%r) — "
                "substituting 0.0",
                feature_name,
                value,
            )

            numeric_value = 0.0

        cleaned_values.append(numeric_value)

    feature_frame = pd.DataFrame(
        [cleaned_values],
        columns=top_features_v8
    )

    # ---------------------------------------------
    # Scale features (Isolation Forest path only —
    # V8's RobustScaler was fit on benign-train only,
    # exactly matching V8 training methodology)
    # ---------------------------------------------

    scaled_features = scaler_v8.transform(feature_frame)

    # ---------------------------------------------
    # XGBoost prediction
    # XGBoost was trained on unscaled features
    # ---------------------------------------------

    xgb_probability = float(
        xgb_model_v8.predict_proba(feature_frame)[0][1]
    )

    xgb_prediction = int(
        xgb_probability >= threshold_v8
    )

    # ---------------------------------------------
    # Isolation Forest prediction
    # ---------------------------------------------

    isolation_prediction_raw = int(
        isolation_forest_v8.predict(scaled_features)[0]
    )

    isolation_score = float(
        isolation_forest_v8.decision_function(
            scaled_features
        )[0]
    )

    # Isolation Forest:
    #  1  = normal
    # -1  = anomaly

    isolation_prediction = int(
        isolation_prediction_raw == -1
    )

    # ---------------------------------------------
    # Hybrid result — exact V8 OR-fusion formula:
    # hybrid = (xgb_probability >= threshold) OR (IF == -1)
    # ---------------------------------------------

    hybrid_prediction = int(
        xgb_prediction == 1
        or isolation_prediction == 1
    )

    # ---------------------------------------------
    # Detection source (which model(s) triggered)
    # Does not affect hybrid_prediction - additive
    # transparency field only. Matches V7's field.
    # ---------------------------------------------

    if xgb_prediction == 1 and isolation_prediction == 1:
        detection_source = "both"
    elif xgb_prediction == 1:
        detection_source = "xgboost"
    elif isolation_prediction == 1:
        detection_source = "isolation_forest"
    else:
        detection_source = "none"

    return {

        "xgb_probability": xgb_probability,

        "xgb_prediction": xgb_prediction,

        "isolation_score": isolation_score,

        "isolation_prediction": isolation_prediction,

        "hybrid_prediction": hybrid_prediction,

        "detection_source": detection_source,
    }
