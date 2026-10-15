"""SHAP explanations for the V8 XGBoost model, used by the dashboard's V8 mode.

Structurally the same as explainability/shap_explainer.py, but pointed at the
V8 artifacts that detection/experimental_models.py already loads (with joblib,
as V8's own notes require) instead of loading them a second time. Computing an
explanation never changes any prediction.
"""

import pandas as pd
import shap

from detection import experimental_models


class SHAPExplainerV8:

    def __init__(self):

        if not experimental_models.v8_available():
            raise RuntimeError("V8 artifacts are not loaded; cannot explain V8 predictions")

        self.top_features = list(experimental_models.v8_top_features)

        self.explainer = shap.TreeExplainer(experimental_models.v8_xgb)

    def explain_flow(self, features):
        """Top 5 contributing features for one flow, each
        {"feature": str, "value": float, "impact": float}."""

        frame = pd.DataFrame(
            [[features[name] for name in self.top_features]],
            columns=self.top_features,
        )

        shap_values = self.explainer.shap_values(frame)[0]

        impacts = [
            {"feature": name, "value": float(value), "impact": float(impact)}
            for name, value, impact in zip(self.top_features, frame.iloc[0], shap_values)
        ]

        impacts.sort(key=lambda item: abs(item["impact"]), reverse=True)

        return impacts[:5]
