from feature_extraction.feature_extractor import extract_features

from detection.predictor_v8 import predict_flow_v8 as predict_flow
from detection.drift_detector import DriftDetector

from explainability.shap_explainer_v8 import SHAPExplainerV8 as SHAPExplainer

from agents.coordinator import CoordinatorAgent


class DetectionService:
    """
    Detection Service (V8)

    Handles the complete IDS detection pipeline:

    Flow
        ↓
    Feature Extraction
        ↓
    Hybrid Prediction (V8: XGBoost + Isolation Forest, OR-fusion)
        ↓
    Drift Detection
        ↓
    SHAP Explainability (V8 XGBoost)
        ↓
    Agentic Analysis
        ↓
    Final Detection Result

    This is the ONLY change made to this file for V8 live
    deployment: the predictor and SHAP explainer imports now point
    at the V8 modules (aliased to the same local names the rest of
    this file already used), so every line below this point is
    byte-for-byte identical to the pre-V8 version of this file.
    V7's own predictor.py / shap_explainer.py are untouched and can
    be restored here by reverting just the two import lines above.
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

            "detection_source":
                prediction["detection_source"],

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
