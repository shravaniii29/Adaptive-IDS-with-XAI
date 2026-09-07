from scapy.layers.inet import IP, TCP

from detection.predictor_v8 import predict_flow_v8
from feature_extraction.flow import Flow
from feature_extraction.feature_extractor import extract_features


# -------------------------------------------------
# Note on structure
#
# This file was originally written as a standalone assertion
# script (run via `python tests/test_predictor_v8.py`), mirroring
# the exact structure V7's tests/test_predictor.py already uses in
# this project (and matching every other tests/test_*.py file here
# — none of them define pytest-style `def test_*():` functions).
# That's why `pytest tests/test_predictor_v8.py -v` reported
# "collected 0 items": pytest only collects functions/methods
# matching `test_*`, and a bare top-level script has none — pytest
# still imports (and therefore runs) the module during collection,
# which is why the IsolationForest warning showed up in the
# "warnings summary" even though 0 test items were collected.
#
# Converted below into a real pytest test function, preserving the
# exact same synthetic flow, the exact same predict_flow_v8() call,
# and the exact same checks the original script implicitly made
# (it "passed" if prediction ran without error and returned the
# expected result shape) — now expressed as explicit asserts so
# pytest reports a real PASS/FAIL instead of silently doing nothing.
# The `__main__` block below still lets this run directly the same
# way the original script did.
# -------------------------------------------------


def _build_synthetic_flow():

    flow = Flow(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8"
    )

    packets = [

        IP(
            src="192.168.1.10",
            dst="8.8.8.8"
        ) / TCP(
            sport=50000,
            dport=443
        ),

        IP(
            src="8.8.8.8",
            dst="192.168.1.10"
        ) / TCP(
            sport=443,
            dport=50000,
            window=65535
        ),

        IP(
            src="192.168.1.10",
            dst="8.8.8.8"
        ) / TCP(
            sport=50000,
            dport=443
        ),
    ]

    timestamps = [
        1.0,
        2.0,
        4.0,
    ]

    for packet, timestamp in zip(packets, timestamps):
        packet.time = timestamp
        flow.add_packet(packet)

    return flow


def test_predictor_v8():

    print("\n" + "=" * 60)
    print("V8 MODEL INTEGRATION TEST")
    print("=" * 60)

    # ---------------------------------------------
    # Build synthetic flow + extract features
    # ---------------------------------------------

    flow = _build_synthetic_flow()

    features = extract_features(flow)

    # ---------------------------------------------
    # Prediction — the real V8 predictor, unchanged
    # ---------------------------------------------

    result = predict_flow_v8(features)

    for key, value in result.items():
        print(f"{key:<25}: {value}")

    print("=" * 60)

    # ---------------------------------------------
    # Checks (same intent as the original script:
    # prediction must run cleanly and return a complete,
    # internally-consistent result)
    # ---------------------------------------------

    required_keys = {
        "xgb_probability",
        "xgb_prediction",
        "isolation_score",
        "isolation_prediction",
        "hybrid_prediction",
        "detection_source",
    }

    assert required_keys.issubset(result.keys()), (
        f"predict_flow_v8() result missing keys: "
        f"{required_keys - result.keys()}"
    )

    assert 0.0 <= result["xgb_probability"] <= 1.0

    assert result["xgb_prediction"] in (0, 1)

    assert result["isolation_prediction"] in (0, 1)

    assert result["hybrid_prediction"] == int(
        result["xgb_prediction"] == 1
        or result["isolation_prediction"] == 1
    ), "hybrid_prediction must equal OR(xgb_prediction, isolation_prediction)"

    assert result["detection_source"] in (
        "both", "xgboost", "isolation_forest", "none",
    )

    print("\nV8 MODEL INTEGRATION TEST PASSED!")


if __name__ == "__main__":
    test_predictor_v8()
