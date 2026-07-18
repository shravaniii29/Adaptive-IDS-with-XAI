from scapy.layers.inet import IP, TCP

from feature_extraction.flow import Flow

from detection.detection_service import DetectionService


service = DetectionService()


def create_test_flow():

    flow = Flow(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
    )

    packets = []

    for index in range(10):

        packet = (
            IP(
                src="192.168.1.10",
                dst="8.8.8.8",
            )
            / TCP(
                sport=50000,
                dport=443,
            )
        )

        packet.time = 1.0 + (
            index * 0.1
        )

        packets.append(packet)

    for packet in packets:
        flow.add_packet(packet)

    return flow


flow = create_test_flow()


result = service.detect(flow)


print("\nDETECTION RESULT")
print("----------------")

print(
    "Flow ID:",
    result["flow_id"],
)

print(
    "Packets:",
    result["packet_count"],
)

print(
    "XGB Probability:",
    result["xgb_probability"],
)

print(
    "XGB Prediction:",
    result["xgb_prediction"],
)

print(
    "Isolation Prediction:",
    result["isolation_prediction"],
)

print(
    "Hybrid Prediction:",
    result["hybrid_prediction"],
)


statistics = service.get_statistics()


print("\nDETECTION STATISTICS")
print("--------------------")

print(
    "Total Flows:",
    statistics["total_flows"],
)

print(
    "Normal Flows:",
    statistics["normal_flows"],
)

print(
    "Positive Flows:",
    statistics["positive_flows"],
)


assert result["flow_id"] == 1

assert statistics["total_flows"] == 1

assert (
    statistics["normal_flows"]
    + statistics["positive_flows"]
    == 1
)


print(
    "\nDETECTION SERVICE TEST PASSED"
)