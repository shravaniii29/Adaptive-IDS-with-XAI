from packet_capture.capture import start_capture

from feature_extraction.flow_manager import FlowManager
from feature_extraction.feature_extractor import extract_features

from detection.predictor import predict_flow


flow_manager = FlowManager(
    flow_timeout=5
)


def predict_completed_flow(key, flow):

    # Ignore extremely small flows
    if flow.packet_count < 5:
        return

    features = extract_features(flow)

    result = predict_flow(features)

    print("\n" + "=" * 60)
    print("COMPLETED FLOW IDS PREDICTION")
    print("=" * 60)

    print(f"Flow              : {key}")
    print(f"Packets           : {flow.packet_count}")
    print(f"Duration          : {flow.duration:.6f} sec")

    print(
        f"XGB Probability   : "
        f"{result['xgb_probability']:.6f}"
    )

    print(
        f"XGB Prediction    : "
        f"{result['xgb_prediction']}"
    )

    print(
        f"Isolation Score   : "
        f"{result['isolation_score']:.6f}"
    )

    print(
        f"Isolation Anomaly : "
        f"{result['isolation_prediction']}"
    )

    print(
        f"Hybrid Prediction : "
        f"{result['hybrid_prediction']}"
    )

    if result["hybrid_prediction"] == 1:
        print("STATUS             : ATTACK / ANOMALY")
    else:
        print("STATUS             : NORMAL")

    print("=" * 60)


def process_packet(packet):

    flow_manager.process_packet(packet)

    expired_flows = (
        flow_manager.get_expired_flows()
    )

    for key, flow in expired_flows:

        predict_completed_flow(
            key,
            flow,
        )


print("Starting Live IDS...")
print("Listening for network traffic...\n")


start_capture(
    process_packet,
    packet_count=100,
)


print("\nCapture completed.")

print(
    "Flushing remaining active flows..."
)


remaining_flows = (
    flow_manager.flush_all_flows()
)


for key, flow in remaining_flows:

    predict_completed_flow(
        key,
        flow,
    )


print("\nLive IDS test completed.")