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

        # Which model is the primary detector: "confidence" (the deployed
        # hybrid with confidence-weighted fusion) or "v8" (the paper's
        # validated V8 baseline). Switchable at run time from the dashboard.
        self.mode = "confidence"

        self._v8_explainer = None

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
        # V8 mode: the paper's validated V8 model is the primary detector
        # (its verdict, probability and features replace the deployed
        # hybrid's). If V8 cannot score this flow the deployed hybrid's
        # result is used and the result says so.
        # -----------------------------------------

        explain_features = features

        explainer = self.shap_explainer

        mode_note = None

        if self.mode == "v8":

            dst_port = flow.dst_port if flow.dst_port is not None else 0

            v8 = experimental_models.score_v8_detail(flow, dst_port)

            if v8.get("available"):

                prediction = {
                    **prediction,
                    "xgb_probability": v8["xgb_probability"],
                    "xgb_prediction": v8["xgb_prediction"],
                    "isolation_score": v8["isolation_score"],
                    "isolation_anomaly": v8["isolation_anomaly"],
                    "isolation_prediction": v8["isolation_prediction"],
                    "confidence_score": None,
                    "fusion_mode": "v8",
                    "hybrid_prediction": v8["hybrid_prediction"],
                }

                explain_features = v8["features"]

                explainer = self._get_v8_explainer()

            else:

                mode_note = "V8 unavailable for this flow: " + str(v8.get("error"))

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
            else explainer.explain_flow(explain_features)
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
                explain_features,

            "mode_note":
                mode_note,

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

            "isolation_anomaly":
                prediction["isolation_anomaly"],

            # -------------------------------------
            # Hybrid prediction
            # -------------------------------------

            "confidence_score":
                prediction["confidence_score"],

            "fusion_mode":
                prediction["fusion_mode"],

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

    # -----------------------------------------
    # Detection mode (dashboard switch)
    # -----------------------------------------

    MODES = {
        "confidence": "Deployed hybrid (confidence fusion)",
        "v8": "V8 (paper baseline)",
    }

    def available_modes(self):

        return [
            {
                "id": mode_id,
                "label": label,
                "available": mode_id != "v8" or experimental_models.v8_available(),
            }
            for mode_id, label in self.MODES.items()
        ]

    def set_mode(self, mode):
        """Switch the primary detector. Raises ValueError for an unknown
        or unavailable mode. Resets the drift monitor: it watches the
        stream of verdicts, and a different model's verdicts would
        otherwise show up as a false change in the alert rate."""

        if mode not in self.MODES:

            raise ValueError(f"unknown mode {mode!r}; choose one of {list(self.MODES)}")

        if mode == "v8" and not experimental_models.v8_available():

            raise ValueError("V8 mode is unavailable: the V8 artifacts did not load")

        if mode != self.mode:

            self.mode = mode

            self.drift_detector.reset()

    def _get_v8_explainer(self):

        if self._v8_explainer is None:

            from explainability.shap_explainer_v8 import SHAPExplainerV8

            self._v8_explainer = SHAPExplainerV8()

        return self._v8_explainer

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