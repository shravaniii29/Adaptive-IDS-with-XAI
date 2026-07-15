from packet_capture.capture import start_capture

from feature_extraction.flow_builder import (
    add_packet_to_flow,
    flows,
)

from feature_extraction.feature_extractor import (
    extract_features,
)

from detection.predictor import predict_flow


MIN_PACKETS_FOR_PREDICTION = 5


def process_packet(packet):

    key = add_packet_to_flow(packet)

    if key is None:
        return

    flow = flows[key]

    if flow.packet_count < MIN_PACKETS_FOR_PREDICTION:
        return

    features = extract_features(flow)

    result = predict_flow(features)

    print("\n" + "=" * 60)
    print("LIVE IDS PREDICTION")
    print("=" * 60)

    print(f"Flow              : {key}")

    print(
        f"Packets           : "
        f"{flow.packet_count}"
    )

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


print("Starting Live IDS...")
print("Listening for network traffic...\n")


start_capture(
    process_packet,
    packet_count=100,
)