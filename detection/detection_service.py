from feature_extraction.feature_extractor import extract_features

from detection.predictor import predict_flow
from detection.drift_detector import DriftDetector

from explainability.shap_explainer import SHAPExplainer


class DetectionService:

    def __init__(self):

        # -----------------------------------------
        # Core modules
        # -----------------------------------------

        self.drift_detector = DriftDetector()
        self.shap_explainer = SHAPExplainer()

        # -----------------------------------------
        # Statistics
        # -----------------------------------------

        self.total_flows = 0
        self.normal_flows = 0
        self.positive_flows = 0

    def detect(self, flow):

        # -----------------------------------------
        # Feature Extraction
        # -----------------------------------------

        features = extract_features(flow)

        # -----------------------------------------
        # Hybrid Prediction
        # -----------------------------------------

        prediction = predict_flow(features)

        # -----------------------------------------
        # Drift Detection
        # -----------------------------------------

        drift_detected = self.drift_detector.update(
            prediction["hybrid_prediction"]
        )

        # -----------------------------------------
        # SHAP Explainability
        # -----------------------------------------

        shap_explanation = self.shap_explainer.explain_flow(
            features
        )

        # -----------------------------------------
        # Statistics
        # -----------------------------------------

        self.total_flows += 1

        if prediction["hybrid_prediction"] == 1:
            self.positive_flows += 1
        else:
            self.normal_flows += 1

        # -----------------------------------------
        # Final Result
        # -----------------------------------------

        result = {

            "flow_id": self.total_flows,

            "packet_count": flow.packet_count,

            "duration": flow.duration,

            "features": features,

            "xgb_probability":
                prediction["xgb_probability"],

            "xgb_prediction":
                prediction["xgb_prediction"],

            "isolation_score":
                prediction["isolation_score"],

            "isolation_prediction":
                prediction["isolation_prediction"],

            "hybrid_prediction":
                prediction["hybrid_prediction"],

            "drift_detected":
                drift_detected,

            "shap_explanation":
                shap_explanation
        }

        return result

    def get_statistics(self):

        return {

            "total_flows": self.total_flows,

            "normal_flows": self.normal_flows,

            "positive_flows": self.positive_flows,
        }