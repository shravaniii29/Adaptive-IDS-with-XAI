from packet_capture.capture import start_capture

from feature_extraction.flow_manager import FlowManager

from detection.detection_service import DetectionService


flow_manager = FlowManager(
    flow_timeout=5
)

detection_service = DetectionService()


def predict_completed_flow(key, flow):

    # Ignore extremely small flows
    if flow.packet_count < 5:
        return

    result = detection_service.detect(flow)

    print("\n" + "=" * 70)
    print("LIVE IDS FLOW ANALYSIS")
    print("=" * 70)

    print(f"Flow               : {key}")
    print(f"Flow ID            : {result['flow_id']}")
    print(f"Packets            : {result['packet_count']}")
    print(f"Duration           : {result['duration']:.6f} sec")

    print(
        f"XGB Probability    : "
        f"{result['xgb_probability']:.6f}"
    )

    print(
        f"XGB Prediction     : "
        f"{result['xgb_prediction']}"
    )

    print(
        f"Isolation Score    : "
        f"{result['isolation_score']:.6f}"
    )

    print(
        f"Isolation Anomaly  : "
        f"{result['isolation_prediction']}"
    )

    print(
        f"Hybrid Prediction  : "
        f"{result['hybrid_prediction']}"
    )

    print(
        f"Drift Detected     : "
        f"{result['drift_detected']}"
    )

    if result["hybrid_prediction"] == 1:
        print("STATUS             : ATTACK / ANOMALY")
    else:
        print("STATUS             : NORMAL")

    print("\nTop SHAP Features")
    print("-" * 70)

    for index, feature in enumerate(
        result["shap_explanation"],
        start=1
    ):

        print(
            f"{index}. "
            f"{feature['feature']}"
            f" | Value: {feature['value']:.4f}"
            f" | Impact: {feature['impact']:.6f}"
        )

    print("=" * 70)


def process_packet(packet):

    flow_manager.process_packet(packet)

    expired_flows = flow_manager.get_expired_flows()

    for key, flow in expired_flows:

        predict_completed_flow(
            key,
            flow,
        )


print("Starting Live Adaptive IDS...")
print("Listening for network traffic...\n")


start_capture(
    process_packet,
    packet_count=100,
)


print("\nCapture completed.")
print("Flushing remaining active flows...")


remaining_flows = flow_manager.flush_all_flows()

for key, flow in remaining_flows:

    predict_completed_flow(
        key,
        flow,
    )


stats = detection_service.get_statistics()

print("\n" + "=" * 70)
print("DETECTION SUMMARY")
print("=" * 70)

print(f"Total Flows       : {stats['total_flows']}")
print(f"Normal Flows      : {stats['normal_flows']}")
print(f"Positive Flows    : {stats['positive_flows']}")

print("=" * 70)

print("\nLive Adaptive IDS test completed.")