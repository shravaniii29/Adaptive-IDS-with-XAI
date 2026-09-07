"""
V8 SHAP explainability module.

This is a NEW file — it does NOT replace, modify, or import
explainability/shap_explainer.py (V7). V7's SHAPExplainer stays
fully intact and usable for comparison/research.

Explains WHY the finalized V8 XGBoost component made its
prediction, using the exact same 25 V8 features/names/order/values
predictor_v8.py feeds to the V8 XGBoost model. SHAP is purely
explanatory here — computing an explanation never alters
xgb_probability, xgb_prediction, isolation_prediction, or
hybrid_prediction. The V8 XGBoost model itself is loaded read-only
and is never retrained or modified.
"""

import pickle
from pathlib import Path

import pandas as pd
import shap
import matplotlib.pyplot as plt


# -------------------------------------------------
# Project paths
# -------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
V8_MODELS_DIR = PROJECT_ROOT / "v8_training" / "models_v8"


class SHAPExplainerV8:
    """
    SHAP Explainability module for the finalized V8 XGBoost model.

    Supports:
        • Live explanation of a single network flow
        • Summary plot (research paper)
        • Force plot (single prediction)
        • Waterfall plot (single prediction)

    Structurally identical to explainability.shap_explainer.SHAPExplainer,
    pointed at V8's artifacts instead of V7's.
    """

    def __init__(self):

        # -----------------------------------------
        # Load finalized V8 XGBoost model (read-only)
        # -----------------------------------------

        with open(V8_MODELS_DIR / "xgb_model_v8.pkl", "rb") as file:
            self.xgb_model = pickle.load(file)

        # -----------------------------------------
        # Load V8 selected feature names (authoritative
        # order — identical source predictor_v8.py uses)
        # -----------------------------------------

        with open(V8_MODELS_DIR / "top_features_v8.pkl", "rb") as file:
            self.top_features = pickle.load(file)

        # -----------------------------------------
        # Create TreeExplainer
        # -----------------------------------------

        self.explainer = shap.TreeExplainer(self.xgb_model)

    # =====================================================
    # Live explanation
    # =====================================================

    def explain_flow(self, features):
        """
        Generate SHAP explanation for one network flow.

        Parameters
        ----------
        features : dict
            Dictionary of extracted flow features.

        Returns
        -------
        list
            Top 5 contributing features, each
            {"feature": str, "value": float, "impact": float}.
        """

        feature_values = [
            features[feature]
            for feature in self.top_features
        ]

        feature_frame = pd.DataFrame(
            [feature_values],
            columns=self.top_features
        )

        shap_values = self.explainer.shap_values(feature_frame)

        return self._get_top_features(
            shap_values[0],
            feature_frame.iloc[0]
        )

    # =====================================================
    # Internal helper
    # =====================================================

    def _get_top_features(self, shap_values, feature_values):

        feature_impacts = []

        for feature, value, impact in zip(
            self.top_features,
            feature_values,
            shap_values
        ):

            feature_impacts.append(
                {
                    "feature": feature,
                    "value": float(value),
                    "impact": float(impact)
                }
            )

        feature_impacts.sort(
            key=lambda x: abs(x["impact"]),
            reverse=True
        )

        return feature_impacts[:5]

    # =====================================================
    # Global SHAP summary plot
    # =====================================================

    def summary_plot(self, dataframe):

        shap_values = self.explainer.shap_values(dataframe)

        shap.summary_plot(
            shap_values,
            dataframe
        )

    # =====================================================
    # Global SHAP bar plot
    # =====================================================

    def summary_bar_plot(self, dataframe):

        shap_values = self.explainer.shap_values(dataframe)

        shap.summary_plot(
            shap_values,
            dataframe,
            plot_type="bar"
        )

    # =====================================================
    # Single flow force plot
    # =====================================================

    def force_plot(self, dataframe, index=0):

        shap_values = self.explainer.shap_values(dataframe)

        shap.force_plot(
            self.explainer.expected_value,
            shap_values[index],
            dataframe.iloc[index],
            matplotlib=True
        )

        plt.show()

    # =====================================================
    # Single flow waterfall plot
    # =====================================================

    def waterfall_plot(self, dataframe, index=0):

        shap_values = self.explainer.shap_values(dataframe)

        shap.plots._waterfall.waterfall_legacy(
            self.explainer.expected_value,
            shap_values[index],
            feature_names=dataframe.columns
        )

        plt.show()
