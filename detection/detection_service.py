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
    Hybrid Prediction (deployed hybrid) and V8 Prediction  - both, always
        ↓
    Drift Detection (one monitor per model)
        ↓
    SHAP Explainability (each model's own explainer)
        ↓
    Agentic Analysis (one coordinator per model)
        ↓
    Final Detection Result (one set of outputs per model under "variants")

    Every flow is scored by both models. `mode` only selects which model's
    results the dashboard views - see detection/result_views.py.
    """

    # Placeholder shape returned for shap_explanation/agent_analysis when
    # running lightweight - kept as dicts (not None) so any caller that
    # does result["shap_explanation"].get(...) doesn't need to change.
    _SKIPPED_EXPLANATION = {"skipped": "lightweight mode - SHAP disabled"}
    _SKIPPED_AGENT_ANALYSIS = {"skipped": "lightweight mode - agents disabled"}

    MODES = {
        "confidence": "Deployed hybrid (confidence fusion)",
        "v8": experimental_models.v8_rule_label(),
    }

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

        # One drift monitor and one agent coordinator per model: each
        # watches / remembers only its own model's verdicts.
        self.drift_detectors = {mode: DriftDetector() for mode in self.MODES}

        self.coordinators = {
            mode: (None if lightweight else CoordinatorAgent())
            for mode in self.MODES
        }

        self.shap_explainer = None if lightweight else SHAPExplainer()

        self._v8_explainer = None

        # Which model's results the dashboard is VIEWING. Both models score
        # every flow regardless; this never changes what is computed.
        self.mode = "confidence"

        # -----------------------------------------
        # Statistics
        # -----------------------------------------

        self.total_flows = 0

        self._counts = {
            mode: {"normal": 0, "positive": 0} for mode in self.MODES
        }

        # Counter values at the last "Clear Stats" (see reset_statistics)
        self._stats_baseline = self._snapshot_counts()

    # Kept so existing callers/tests that read the deployed hybrid's
    # counters keep working.
    @property
    def normal_flows(self):
        return self._counts["confidence"]["normal"]

    @property
    def positive_flows(self):
        return self._counts["confidence"]["positive"]

    # -----------------------------------------
    # Detection
    # -----------------------------------------

    def detect(self, flow):

        features = extract_features(flow)

        dst_port = flow.dst_port if flow.dst_port is not None else 0

        # -----------------------------------------
        # Score with both models
        # -----------------------------------------

        predictions = {}

        hybrid = predict_flow(features)

        predictions["confidence"] = {
            "features": features,
            "mode_note": None,
            "xgb_probability": hybrid["xgb_probability"],
            "xgb_prediction": hybrid["xgb_prediction"],
            "isolation_score": hybrid["isolation_score"],
            "isolation_anomaly": hybrid["isolation_anomaly"],
            "isolation_prediction": hybrid["isolation_prediction"],
            "confidence_score": hybrid["confidence_score"],
            "fusion_mode": hybrid["fusion_mode"],
            "hybrid_prediction": hybrid["hybrid_prediction"],
        }

        v8_note = None

        v8 = experimental_models.score_v8_detail(flow, dst_port)

        if v8.get("available"):

            predictions["v8"] = {
                "features": v8["features"],
                "mode_note": None,
                "xgb_probability": v8["xgb_probability"],
                "xgb_prediction": v8["xgb_prediction"],
                "isolation_score": v8["isolation_score"],
                "isolation_anomaly": v8["isolation_anomaly"],
                "isolation_prediction": v8["isolation_prediction"],
                "confidence_score": v8["confidence_score"],
                "fusion_mode": v8["fusion_mode"],
                "hybrid_prediction": v8["hybrid_prediction"],
            }

        else:

            v8_note = "V8 unavailable for this flow: " + str(v8.get("error"))

        # -----------------------------------------
        # Statistics (flow_id is the running total across both models)
        # -----------------------------------------

        self.total_flows += 1

        for mode, prediction in predictions.items():

            self._counts[mode][
                "positive" if prediction["hybrid_prediction"] == 1 else "normal"
            ] += 1

        # -----------------------------------------
        # Flow-level fields, shared by both models' views
        # -----------------------------------------

        result = {

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

            "v8_note":
                v8_note,

            # Experimental models (EXPERIMENTAL panel). Isolated in its own
            # try/except: a bug here must never take down the real
            # detection result the way an unhandled exception from detect()
            # as a whole would (the caller in
            # app/main.py::_handle_completed_flow catches any exception from
            # detect() and discards the entire result).
            "experimental_models":
                self._safe_experimental_predict(flow),
        }

        # -----------------------------------------
        # Per-model drift, SHAP and agent analysis
        # -----------------------------------------

        variants = {}

        for mode, prediction in predictions.items():

            try:

                variants[mode] = self._complete_variant(mode, prediction, result)

            except Exception:

                # The deployed hybrid is the primary result: never lose the
                # flow because the V8 view failed to explain itself.
                if mode == "confidence":

                    raise

        result["variants"] = variants

        # Top level mirrors the model being viewed at scoring time, so
        # anything that reads a result directly (tests, scripts) still sees
        # the flat shape.
        result.update(variants.get(self.mode, variants["confidence"]))

        return result

    def _complete_variant(self, mode, prediction, common):
        """Drift, SHAP and agent analysis for one model's prediction."""

        variant = dict(prediction)

        variant["drift_detected"] = self.drift_detectors[mode].update(
            prediction["hybrid_prediction"]
        )

        if self.lightweight:

            variant["shap_explanation"] = self._SKIPPED_EXPLANATION

        else:

            explainer = (
                self.shap_explainer if mode == "confidence"
                else self._get_v8_explainer()
            )

            variant["shap_explanation"] = explainer.explain_flow(
                prediction["features"]
            )

        # The coordinator reads a flat result, so give it this model's view.
        view = {**common, **variant}

        variant["agent_analysis"] = (
            self._SKIPPED_AGENT_ANALYSIS
            if self.lightweight
            else self.coordinators[mode].analyze(view)
        )

        return variant

    # -----------------------------------------
    # Which model the dashboard is viewing
    # -----------------------------------------

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
        """Choose which model's results are shown. Both models keep scoring
        every flow, so nothing is lost or reset by switching. Raises
        ValueError for an unknown or unavailable mode."""

        if mode not in self.MODES:

            raise ValueError(f"unknown mode {mode!r}; choose one of {list(self.MODES)}")

        if mode == "v8" and not experimental_models.v8_available():

            raise ValueError("V8 mode is unavailable: the V8 artifacts did not load")

        self.mode = mode

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

    # -----------------------------------------
    # Statistics
    # -----------------------------------------

    def _snapshot_counts(self):

        return {
            "total": self.total_flows,
            **{mode: dict(counts) for mode, counts in self._counts.items()},
        }

    def reset_statistics(self):
        """Zero the counters shown on the dashboard ("Clear Stats").

        flow_id keeps counting up from total_flows - clients (and
        simulate_attacks.py) de-duplicate flows by id, so ids must never be
        reused - which is why this records a baseline to subtract instead of
        zeroing total_flows itself."""

        self._stats_baseline = self._snapshot_counts()

        for detector in self.drift_detectors.values():

            detector.reset()

    def get_statistics(self, mode=None):
        """Counters for the model being viewed (total is the same for both)."""

        mode = mode or self.mode

        base = self._stats_baseline

        return {

            "total_flows":
                self.total_flows - base["total"],

            "normal_flows":
                self._counts[mode]["normal"] - base[mode]["normal"],

            "positive_flows":
                self._counts[mode]["positive"] - base[mode]["positive"],
        }
