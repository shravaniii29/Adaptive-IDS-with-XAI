"""
V8 Phase 5 / Phase 9 — real live packet-capture smoke test.

Runs the COMPLETE live pipeline on real captured packets:

    real packets -> packet_capture.start_capture()
                 -> FlowManager.process_packet()
                 -> Flow
                 -> feature_extraction.feature_extractor.extract_features()
                 -> DetectionService (V8 predictor_v8 + SHAPExplainerV8)
                 -> printed detection + SHAP result

IMPORTANT — read before running:

  * This captures REAL packets from your machine's active network
    interface using Scapy (requires the privileges your existing
    tests/test_live_prediction.py already required — e.g. Npcap /
    admin on Windows).
  * This script only PASSIVELY OBSERVES your own ordinary network
    traffic. It does not generate, inject, or replay any attack
    traffic, and does not perform any destructive or intrusive
    network activity.
  * PACKET_LIMIT below bounds the capture so this always terminates
    on its own — it is not an infinite capture.
  * This is a SMOKE TEST, not an accuracy evaluation. It proves the
    real capture -> flow -> features -> V8 model -> detection result
    pipeline runs end-to-end without crashing. Whatever traffic your
    machine happens to generate during the run is very likely benign
    background traffic (DNS, HTTPS, etc.) — do NOT interpret any
    "ATTACK/ANOMALY" flag produced here as a confirmed intrusion, and
    do NOT report results from this script as detection-accuracy
    numbers. That question was already answered honestly by the
    held-out evaluation (v8_training/evaluation_results/).

Run this on your machine, from the project root, with the privileges
your existing live-capture tests already use:

    python tests/test_live_v8_smoke.py
"""

# -------------------------------------------------
# Make the project root importable regardless of how this
# script is invoked.
#
# Running `python tests/test_live_v8_smoke.py` directly only
# puts this file's own directory (tests/) on sys.path — not the
# project root — so `packet_capture`, `detection`, etc. aren't
# found (ModuleNotFoundError: No module named 'packet_capture').
# tests/test_predictor_v8.py and tests/test_shap_v8_validation.py
# don't need this because pytest resolves it differently (it
# walks up through tests/__init__.py to the project root itself);
# this script is run directly, not via pytest, since it captures
# live traffic interactively. Same PROJECT_ROOT pattern already
# used in detection/predictor_v8.py and
# explainability/shap_explainer_v8.py.
# -------------------------------------------------

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from packet_capture.capture import start_capture

from feature_extraction.flow_manager import FlowManager

from detection.detection_service import DetectionService


# Bounded capture — adjust if you need a longer/shorter smoke run.
#
# Raised from the original 300: the first real run captured 300
# packets but spread them across 11 separate flows (ordinary
# background traffic — DNS, TLS keepalives, etc. — is naturally
# fragmented across many short-lived 5-tuples), so none reached
# MIN_FLOW_PACKETS. More packets gives more opportunity for any
# single flow (e.g. one sustained page load) to accumulate enough
# packets. Still a bounded, passive, finite capture — same sniff()
# call, same no-injection behavior, just a larger count.
PACKET_LIMIT = 1500

# Ignore flows with fewer than this many packets. Lowered from the
# original 5 (which mirrored V7's test_live_prediction.py threshold)
# to 3 — still enough to rule out single-packet noise (e.g. a lone
# broadcast/ARP-adjacent packet), but low enough that an ordinary
# short flow (e.g. a DNS query + response + one more packet, or a
# TCP SYN/SYN-ACK/ACK handshake) qualifies. This only changes which
# flows this SMOKE TEST bothers to print/predict on — it does not
# touch FlowManager, feature extraction, or any V8 model/threshold
# logic, all of which stay exactly as trained.
MIN_FLOW_PACKETS = 3


flow_manager = FlowManager(flow_timeout=5)

detection_service = DetectionService()


stats = {
    "packets_seen": 0,
    "flows_completed": 0,
    "flows_processed": 0,
    "flows_skipped_too_small": 0,
    "prediction_errors": 0,
}


def report_flow(key, flow):

    stats["flows_completed"] += 1

    if flow.packet_count < MIN_FLOW_PACKETS:
        stats["flows_skipped_too_small"] += 1
        return

    try:
        result = detection_service.detect(flow)
    except Exception as exc:
        stats["prediction_errors"] += 1
        print(f"\n[ERROR] detection_service.detect() failed for {key}: {exc!r}")
        return

    stats["flows_processed"] += 1

    print("\n" + "=" * 70)
    print("V8 LIVE FLOW RESULT")
    print("=" * 70)

    print(f"Flow               : {key}")
    print(f"Source IP          : {result['source_ip']}")
    print(f"Destination IP     : {result['destination_ip']}")
    print(f"Flow ID            : {result['flow_id']}")
    print(f"Packets            : {result['packet_count']}")
    print(f"Duration           : {result['duration']:.6f} sec")
    print()
    print(f"XGB Probability    : {result['xgb_probability']:.6f}")
    print(f"XGB Prediction     : {result['xgb_prediction']}")
    print(f"Isolation Score    : {result['isolation_score']:.6f}")
    print(f"Isolation Anomaly  : {result['isolation_prediction']}")
    print(f"Hybrid Prediction  : {result['hybrid_prediction']}")
    print(f"Detection Source   : {result['detection_source']}")

    if result["hybrid_prediction"] == 1:
        print("STATUS             : FLAGGED (see disclaimer above — not a")
        print("                      confirmed attack, just this run's raw")
        print("                      hybrid output on ordinary traffic)")
    else:
        print("STATUS             : NORMAL")

    print("\nTop SHAP Features (V8 XGBoost)")
    print("-" * 40)

    for index, feature in enumerate(result["shap_explanation"], start=1):
        print(
            f"{index}. {feature['feature']}"
            f" | Value: {feature['value']:.4f}"
            f" | Impact: {feature['impact']:.6f}"
        )


def process_packet(packet):

    stats["packets_seen"] += 1

    flow_manager.process_packet(packet)

    for key, flow in flow_manager.get_expired_flows():
        report_flow(key, flow)


def main():

    print("\n" + "=" * 70)
    print("V8 LIVE SMOKE TEST")
    print("=" * 70)
    print(f"Capturing up to {PACKET_LIMIT} packets on this machine's")
    print("active interface. Passive observation only — no traffic is")
    print("generated or injected. Press Ctrl+C to stop early.\n")

    try:
        start_capture(process_packet, packet_count=PACKET_LIMIT)
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")

    print("\nCapture completed. Flushing remaining active flows...")

    for key, flow in flow_manager.flush_all_flows():
        report_flow(key, flow)

    detection_stats = detection_service.get_statistics()

    print("\n" + "=" * 70)
    print("V8 LIVE SMOKE TEST SUMMARY")
    print("=" * 70)
    print(f"Packets captured        : {stats['packets_seen']}")
    print(f"Flows completed         : {stats['flows_completed']}")
    print(f"Flows processed (>= {MIN_FLOW_PACKETS} pkts) : {stats['flows_processed']}")
    print(f"Flows skipped (too small): {stats['flows_skipped_too_small']}")
    print(f"Prediction errors        : {stats['prediction_errors']}")
    print()
    print(f"DetectionService total_flows   : {detection_stats['total_flows']}")
    print(f"DetectionService normal_flows  : {detection_stats['normal_flows']}")
    print(f"DetectionService positive_flows: {detection_stats['positive_flows']}")
    print("=" * 70)

    if stats["prediction_errors"] == 0 and stats["flows_completed"] > 0:
        print("\nV8 LIVE SMOKE TEST: PASS (pipeline ran end-to-end without errors)")
    elif stats["flows_completed"] == 0:
        print(
            "\nV8 LIVE SMOKE TEST: INCONCLUSIVE — no flows completed in this "
            "run (try increasing PACKET_LIMIT or generating some ordinary "
            "traffic, e.g. browsing, during capture)."
        )
    else:
        print("\nV8 LIVE SMOKE TEST: FAIL — see [ERROR] lines above")

    print(
        "\nReminder: this is a plumbing smoke test on ordinary traffic, "
        "not a detection-accuracy evaluation."
    )


if __name__ == "__main__":
    main()
