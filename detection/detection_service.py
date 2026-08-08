from feature_extraction.feature_extractor import extract_features

from detection.predictor import predict_flow
from detection.drift_detector import DriftDetector

from explainability.shap_explainer import SHAPExplainer

from agents.coordinator import CoordinatorAgent


class DetectionService:
    """
    Detection Service

    Handles the complete IDS detection pipeline:

    Flow
        ↓
    Feature Extraction
        ↓
    Hybrid Prediction
        ↓
    Drift Detection
        ↓
    SHAP Explainability
        ↓
    Agentic Analysis
        ↓
    Final Detection Result
    """

    def __init__(self):

        # -----------------------------------------
        # Core modules
        # -----------------------------------------

        self.drift_detector = DriftDetector()

        self.shap_explainer = SHAPExplainer()

        self.coordinator = CoordinatorAgent()

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
        # Detection Result
        # -----------------------------------------

        result = {

            # -------------------------------------
            # Flow information
            # -------------------------------------

            "flow_id":
                self.total_flows,

            "source_ip":
                flow.src_ip,

            "destination_ip":
                flow.dst_ip,

            "packet_count":
                flow.packet_count,

            "duration":
                flow.duration,

            # -------------------------------------
            # Extracted features
            # -------------------------------------

            "features":
                features,

            # -------------------------------------
            # XGBoost
            # -------------------------------------

            "xgb_probability":
                prediction["xgb_probability"],

            "xgb_prediction":
                prediction["xgb_prediction"],

            # -------------------------------------
            # Isolation Forest
            # -------------------------------------

            "isolation_score":
                prediction["isolation_score"],

            "isolation_prediction":
                prediction["isolation_prediction"],

            # -------------------------------------
            # Hybrid prediction
            # -------------------------------------

            "hybrid_prediction":
                prediction["hybrid_prediction"],

            # -------------------------------------
            # Drift
            # -------------------------------------

            "drift_detected":
                drift_detected,

            # -------------------------------------
            # SHAP
            # -------------------------------------

            "shap_explanation":
                shap_explanation
        }

        # -----------------------------------------
        # Agentic Layer
        # -----------------------------------------

        agent_analysis = self.coordinator.analyze(

            result

        )

        # -----------------------------------------
        # Attach Agent Analysis
        # -----------------------------------------

        result["agent_analysis"] = agent_analysis

        return result

    def get_statistics(self):

        return {

            "total_flows":
                self.total_flows,

            "normal_flows":
                self.normal_flows,

            "positive_flows":
                self.positive_flows
        }