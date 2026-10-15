"""Per-model views of a detection result.

Every completed flow is scored by BOTH detectors at the same time (the
deployed hybrid with confidence fusion, and the paper's V8 model). A result
keeps one complete set of model-specific outputs per model under "variants";
the dashboard's mode switch only chooses which set is shown, so switching is
instant and also re-labels flows that were scored earlier.
"""

# Every field of a result that depends on which model is being viewed.
VARIANT_FIELDS = (
    "features",
    "mode_note",
    "xgb_probability",
    "xgb_prediction",
    "isolation_score",
    "isolation_anomaly",
    "isolation_prediction",
    "confidence_score",
    "fusion_mode",
    "hybrid_prediction",
    "drift_detected",
    "shap_explanation",
    "agent_analysis",
)


def flatten_result(result, mode):
    """The result as seen in `mode`: the flow-level fields plus that model's
    own outputs at the top level, which is the shape every endpoint reads.

    A result without variants (or without the requested one, e.g. V8 could
    not score the flow) is returned unchanged / as the hybrid view."""

    variants = result.get("variants") if result else None

    if not variants:

        return result

    chosen = mode if mode in variants else "confidence"

    view = {key: value for key, value in result.items() if key != "variants"}

    view.update(variants[chosen])

    view["view_mode"] = chosen

    return view
