from scapy.layers.inet import IP, TCP

from detection.predictor import predict_flow
from feature_extraction.flow import Flow
from feature_extraction.feature_extractor import extract_features


# -------------------------------------------------
# Create synthetic flow
# -------------------------------------------------

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


for packet, timestamp in zip(
    packets,
    timestamps
):

    packet.time = timestamp

    flow.add_packet(packet)


# -------------------------------------------------
# Extract features
# -------------------------------------------------

features = extract_features(flow)


print("\n" + "=" * 60)

print("MODEL INTEGRATION TEST")

print("=" * 60)


# -------------------------------------------------
# Prediction
# -------------------------------------------------

result = predict_flow(features)


for key, value in result.items():

    print(f"{key:<25}: {value}")


print("=" * 60)

print("\nMODEL INTEGRATION TEST PASSED!")