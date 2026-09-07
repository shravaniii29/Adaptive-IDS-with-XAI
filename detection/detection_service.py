from feature_extraction.feature_extractor import extract_features

from detection.predictor import predict_flow
from detection.drift_detector import DriftDetector
from detection import experimental_models

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

    # Placeholder shape returned for shap_explanation/agent_analysis when
    # running lightweight - kept as dicts (not None) so any caller that
    # does result["shap_explanation"].get(...) doesn't need to change.
    _SKIPPED_EXPLANATION = {"skipped": "lightweight mode - SHAP disabled"}
    _SKIPPED_AGENT_ANALYSIS = {"skipped": "lightweight mode - agents disabled"}

    def __init__(self, lightweight=False):

        # -----------------------------------------
        # Core modules
        # -----------------------------------------

        # Skips SHAP explainability + the 5-agent orchestration layer -
        # neither is read by simulate_attacks.py's Poller (it only ever
        # reads hybrid_prediction and the experimental model scores from
        # /history), but together they were measured at ~500ms of a
        # ~506ms-per-flow total detect() cost, capping live throughput at
        # ~2 flows/sec - far below what a flood scenario generates. Keep
        # lightweight=False (the default) for the real interactive
        # dashboard demo, where the explanation/agent output is the whole
        # point; set True for load-testing/simulation, and flip back to
        # False any time the SHAP/agent output itself needs debugging.
        self.lightweight = lightweight

        self.drift_detector = DriftDetector()

        self.shap_explainer = None if lightweight else SHAPExplainer()

        self.coordinator = None if lightweight else CoordinatorAgent()

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

        shap_explanation = (
            self._SKIPPED_EXPLANATION
            if self.lightweight
            else self.shap_explainer.explain_flow(features)
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

            # Needed by simulate_attacks.py's attribute_flows() to match a
            # flow to the scenario that actually generated it - destination
            # IP alone doesn't disambiguate, since every simulated scenario
            # targets the same TARGET_IP.
            "destination_port":
                flow.dst_port,

            "packet_count":
                flow.packet_count,

            "duration":
                flow.duration,

            # Real packet-capture-relative timestamp (from Npcap via
            # packet.time - unaffected by scoring delay), NOT when this
            # flow was scored. simulate_attacks.py's attribute_flows()
            # needs this instead of recorded_at: recorded_at only reflects
            # capture time when _scoring_worker has no backlog. Under a
            # flood-scale backlog (confirmed live: HTTP flood/port scan
            # can queue thousands of flows behind slower-arriving ones),
            # scoring can lag capture by minutes - far past the ~26s
            # matching window - which was silently dropping delayed flows
            # from ground truth entirely (0 flows attributed) rather than
            # misattributing them.
            "flow_start_time":
                flow.start_time,

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
                shap_explanation,

            # -------------------------------------
            # Experimental models (EXPERIMENTAL panel)
            #
            # Isolated in its own try/except: a bug here
            # must never take down the real detection
            # result the way an unhandled exception from
            # detect() as a whole would (the caller in
            # app/main.py::_handle_completed_flow catches
            # any exception from detect() and discards
            # the entire result).
            # -------------------------------------

            "experimental_models":
                self._safe_experimental_predict(flow)
        }

        # -----------------------------------------
        # Agentic Layer
        # -----------------------------------------

        agent_analysis = (
            self._SKIPPED_AGENT_ANALYSIS
            if self.lightweight
            else self.coordinator.analyze(result)
        )

        # -----------------------------------------
        # Attach Agent Analysis
        # -----------------------------------------

        result["agent_analysis"] = agent_analysis

        return result

    def _safe_experimental_predict(self, flow):
        """Never let a failure in the experimental panel propagate - a
        raised exception here would be caught by this class's own caller
        (app/main.py::_handle_completed_flow), which discards the ENTIRE
        detect() result on any exception. That must not happen just
        because the experimental models had a bad day."""

        try:

            return experimental_models.predict_all(flow)

        except Exception as exc:

            return {
                "disclaimer": experimental_models.DISCLAIMER,
                "error": str(exc),
            }

    def get_statistics(self):

        return {

            "total_flows":
                self.total_flows,

            "normal_flows":
                self.normal_flows,

            "positive_flows":
                self.positive_flows
        }