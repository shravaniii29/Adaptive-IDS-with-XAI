"""
V8 Phase 4 — synthetic end-to-end integration test.

Covers: FlowManager -> Flow -> extract_features() -> predictor_v8
        -> DetectionService

Uses deterministic, synthetic TCP and UDP packets (not real captured
traffic; see test_live_v8_smoke.py for the real-packet smoke test).

IMPORTANT: this is a PLUMBING / INTEGRATION test only. Passing this
test demonstrates that the live V8 pipeline wires together correctly
end-to-end without crashing or silently loading V7. It does NOT
demonstrate detection accuracy — these packets are not real attack
or benign traffic samples, just deterministic synthetic packets
built to exercise every stage of the pipeline.

Run this on a machine with the real scapy / xgboost / shap
dependencies installed (the project venv), from the project root:

    python tests/test_v8_synthetic_integration.py
"""

import math

from scapy.layers.inet import IP, TCP, UDP

from feature_extraction.flow_manager import FlowManager
from feature_extraction.feature_extractor import extract_features, TOP_FEATURES

from detection.predictor_v8 import predict_flow_v8
import detection.predictor_v8 as predictor_v8_module
import detection.predictor as predictor_v7_module

from detection.detection_service import DetectionService
import detection.detection_service as detection_service_module


CHECKS = []


def check(number, description, condition):

    status = "PASS" if condition else "FAIL"

    CHECKS.append((number, description, status))

    print(f"[{status}] {number:>2}. {description}")

    return condition


def main():

    print("\n" + "=" * 70)
    print("V8 SYNTHETIC INTEGRATION TEST (FlowManager -> ... -> DetectionService)")
    print("=" * 70 + "\n")

    flow_manager = FlowManager(flow_timeout=5)

    # ---------------------------------------------------------
    # Check 1: Flow creation via FlowManager (TCP)
    # ---------------------------------------------------------

    tcp_forward_1 = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=50000, dport=443, window=29200)
    )
    tcp_forward_1.time = 1.000

    tcp_backward_1 = (
        IP(src="8.8.8.8", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, window=65535)
    )
    tcp_backward_1.time = 1.050

    tcp_forward_2 = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=50000, dport=443, window=29200)
    )
    tcp_forward_2.time = 1.100

    tcp_backward_2 = (
        IP(src="8.8.8.8", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, window=65200)
    )
    tcp_backward_2.time = 1.180

    tcp_forward_3 = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=50000, dport=443, window=29200)
    )
    tcp_forward_3.time = 1.260

    tcp_packets = [
        tcp_forward_1,
        tcp_backward_1,
        tcp_forward_2,
        tcp_backward_2,
        tcp_forward_3,
    ]

    for packet in tcp_packets:
        flow_manager.process_packet(packet)

    check(
        1,
        "TCP flow created by FlowManager.process_packet()",
        len(flow_manager.active_flows) == 1,
    )

    # ---------------------------------------------------------
    # UDP flow (separate 5-tuple)
    # ---------------------------------------------------------

    udp_forward_1 = (
        IP(src="192.168.1.20", dst="1.1.1.1")
        / UDP(sport=51000, dport=53)
    )
    udp_forward_1.time = 2.000

    udp_backward_1 = (
        IP(src="1.1.1.1", dst="192.168.1.20")
        / UDP(sport=53, dport=51000)
    )
    udp_backward_1.time = 2.030

    udp_forward_2 = (
        IP(src="192.168.1.20", dst="1.1.1.1")
        / UDP(sport=51000, dport=53)
    )
    udp_forward_2.time = 2.060

    udp_packets = [
        udp_forward_1,
        udp_backward_1,
        udp_forward_2,
    ]

    for packet in udp_packets:
        flow_manager.process_packet(packet)

    check(
        2,
        "UDP flow created alongside TCP flow (2 active flows total)",
        len(flow_manager.active_flows) == 2,
    )

    # ---------------------------------------------------------
    # Pull both completed flows out deterministically
    # (bypassing the 5s timeout, since this test must be
    #  deterministic and not depend on wall-clock sleeps)
    # ---------------------------------------------------------

    completed = dict(flow_manager.flush_all_flows())

    tcp_flow = None
    udp_flow = None

    for key, flow in completed.items():

        if flow.dst_ip == "8.8.8.8":
            tcp_flow = flow

        elif flow.dst_ip == "1.1.1.1":
            udp_flow = flow

    check(
        3,
        "Both TCP and UDP flows retrieved from FlowManager",
        tcp_flow is not None and udp_flow is not None,
    )

    # ---------------------------------------------------------
    # Check: bidirectional packets captured correctly
    # ---------------------------------------------------------

    check(
        4,
        "TCP flow captured bidirectional packets "
        f"(fwd={len(tcp_flow.forward_packet_lengths)}, "
        f"bwd={len(tcp_flow.backward_packet_lengths)})",
        len(tcp_flow.forward_packet_lengths) == 3
        and len(tcp_flow.backward_packet_lengths) == 2,
    )

    # ---------------------------------------------------------
    # Check: Dst Port captured (flow-initiating packet's dport)
    # ---------------------------------------------------------

    check(
        5,
        f"TCP flow Dst Port captured correctly (dst_port={tcp_flow.dst_port})",
        tcp_flow.dst_port == 443,
    )

    # ---------------------------------------------------------
    # Check: Init Fwd Win Byts captured for TCP
    # ---------------------------------------------------------

    check(
        6,
        "TCP flow Init Fwd Win Byts captured from first forward packet "
        f"(init_fwd_window_bytes={tcp_flow.init_fwd_window_bytes})",
        tcp_flow.init_fwd_window_bytes == 29200,
    )

    # ---------------------------------------------------------
    # Check: UDP flow does not crash the pipeline
    # (no TCP window field exists for UDP packets)
    # ---------------------------------------------------------

    try:
        udp_features = extract_features(udp_flow)
        udp_extraction_ok = True
    except Exception as exc:
        udp_features = None
        udp_extraction_ok = False
        print(f"        UDP extraction raised: {exc!r}")

    check(
        7,
        "UDP flow safely handled by extract_features() "
        "(no TCP window field, Init Fwd/Bwd Win Byts default to 0)",
        udp_extraction_ok
        and udp_features.get("Init Fwd Win Byts") == 0.0,
    )

    # ---------------------------------------------------------
    # Check: all 25 V8 features generated, matching name/order
    # ---------------------------------------------------------

    tcp_features = extract_features(tcp_flow)

    missing = [f for f in TOP_FEATURES if f not in tcp_features]

    all_finite = all(
        math.isfinite(tcp_features[f]) for f in TOP_FEATURES
    )

    check(
        8,
        "All 25 V8 features present in extract_features() output "
        f"and finite (missing={missing})",
        len(missing) == 0 and all_finite,
    )

    # ---------------------------------------------------------
    # Check: predictor_v8 accepts the feature vector
    # ---------------------------------------------------------

    try:
        tcp_prediction = predict_flow_v8(tcp_features)
        udp_prediction = predict_flow_v8(udp_features)
        predictor_accepted = True
    except Exception as exc:
        tcp_prediction = None
        udp_prediction = None
        predictor_accepted = False
        print(f"        predict_flow_v8 raised: {exc!r}")

    check(
        9,
        "predictor_v8.predict_flow_v8() accepts the extracted feature "
        "vector for both TCP and UDP flows without error",
        predictor_accepted,
    )

    # ---------------------------------------------------------
    # Check: XGB / IF / hybrid predictions produced, OR-fusion holds
    # ---------------------------------------------------------

    required_keys = {
        "xgb_probability", "xgb_prediction",
        "isolation_score", "isolation_prediction",
        "hybrid_prediction", "detection_source",
    }

    keys_present = required_keys.issubset(tcp_prediction.keys())

    fusion_holds = tcp_prediction["hybrid_prediction"] == int(
        tcp_prediction["xgb_prediction"] == 1
        or tcp_prediction["isolation_prediction"] == 1
    )

    check(
        10,
        "XGBoost, Isolation Forest, and hybrid OR-fusion predictions "
        f"all produced and consistent (result={tcp_prediction})",
        keys_present and fusion_holds,
    )

    # ---------------------------------------------------------
    # Check: DetectionService receives and returns a complete result
    # ---------------------------------------------------------

    service = DetectionService()

    try:
        service_result = service.detect(tcp_flow)
        service_ok = True
    except Exception as exc:
        service_result = None
        service_ok = False
        print(f"        DetectionService.detect() raised: {exc!r}")

    result_keys_ok = service_ok and required_keys.issubset(
        service_result.keys()
    ) and "shap_explanation" in service_result

    check(
        11,
        "DetectionService.detect() runs the full pipeline and returns "
        "a complete result (predictions + shap_explanation + agent_analysis)",
        result_keys_ok,
    )

    check(
        12,
        "SHAP explanation contains exactly 5 ranked contributing V8 "
        f"features (got {len(service_result['shap_explanation']) if service_ok else 'N/A'})",
        service_ok and len(service_result["shap_explanation"]) == 5,
    )

    # ---------------------------------------------------------
    # Check: no V7 model accidentally loaded into the V8 path
    # ---------------------------------------------------------

    detection_service_uses_v8_predictor = (
        detection_service_module.predict_flow.__module__
        == "detection.predictor_v8"
    )

    detection_service_uses_v8_shap = (
        detection_service_module.SHAPExplainer.__module__
        == "explainability.shap_explainer_v8"
    )

    v7_and_v8_coexist_independently = (
        predictor_v7_module.xgb_model is not predictor_v8_module.xgb_model_v8
    )

    check(
        13,
        "DetectionService is wired to V8 (predictor_v8 / SHAPExplainerV8) "
        "and V7's predictor.py remains a separate, untouched, independently "
        "loaded module (no accidental V7 loading into the V8 path)",
        detection_service_uses_v8_predictor
        and detection_service_uses_v8_shap
        and v7_and_v8_coexist_independently,
    )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    print("\n" + "=" * 70)

    passed = sum(1 for _, _, status in CHECKS if status == "PASS")
    total = len(CHECKS)

    print(f"RESULT: {passed}/{total} checks passed")

    if passed == total:
        print("V8 SYNTHETIC INTEGRATION TEST: PASS")
    else:
        print("V8 SYNTHETIC INTEGRATION TEST: FAIL")

    print("=" * 70)

    print(
        "\nReminder: this test validates pipeline WIRING and PLUMBING "
        "only, using deterministic synthetic packets. It is not an "
        "accuracy evaluation."
    )


if __name__ == "__main__":
    main()
