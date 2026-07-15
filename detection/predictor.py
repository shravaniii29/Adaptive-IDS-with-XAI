import pickle
from pathlib import Path

import numpy as np
import pandas as pd


# -------------------------------------------------
# Project paths
# -------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODELS_DIR = PROJECT_ROOT / "models"


# -------------------------------------------------
# Load deployment artifacts
# -------------------------------------------------

with open(MODELS_DIR / "xgb_model.pkl", "rb") as file:
    xgb_model = pickle.load(file)


with open(MODELS_DIR / "isolation_forest.pkl", "rb") as file:
    isolation_forest = pickle.load(file)


with open(MODELS_DIR / "scaler.pkl", "rb") as file:
    scaler = pickle.load(file)


with open(MODELS_DIR / "threshold.pkl", "rb") as file:
    threshold = pickle.load(file)


with open(MODELS_DIR / "top_features.pkl", "rb") as file:
    top_features = pickle.load(file)


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
        isolation_forest.predict(scaled_features)[0]
    )

    isolation_score = float(
        isolation_forest.decision_function(
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
    # Hybrid result
    # ---------------------------------------------

    hybrid_prediction = int(
        xgb_prediction == 1
        or isolation_prediction == 1
    )


    return {

        "xgb_probability": xgb_probability,

        "xgb_prediction": xgb_prediction,

        "isolation_score": isolation_score,

        "isolation_prediction": isolation_prediction,

        "hybrid_prediction": hybrid_prediction,
    }