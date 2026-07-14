import pickle
from scapy.layers.inet import IP, TCP

from feature_extraction.flow_builder import (
    add_packet_to_flow,
    get_flow_key,
    flows,
)

from feature_extraction.feature_extractor import (
    extract_features,
    TOP_FEATURES,
)


# Clear previous flows
flows.clear()


# --------------------------------------------------
# Create test packets
# --------------------------------------------------

packet_1 = (
    IP(src="192.168.1.10", dst="8.8.8.8")
    / TCP(sport=50000, dport=443)
)

packet_2 = (
    IP(src="8.8.8.8", dst="192.168.1.10")
    / TCP(sport=443, dport=50000, window=65535)
)

packet_3 = (
    IP(src="192.168.1.10", dst="8.8.8.8")
    / TCP(sport=50000, dport=443)
)


# --------------------------------------------------
# Give controlled timestamps
# --------------------------------------------------

packet_1.time = 1.0
packet_2.time = 2.0
packet_3.time = 4.0


# --------------------------------------------------
# Add packets to flow
# --------------------------------------------------

add_packet_to_flow(packet_1)
add_packet_to_flow(packet_2)
add_packet_to_flow(packet_3)


# --------------------------------------------------
# Retrieve flow
# --------------------------------------------------

key = get_flow_key(packet_1)

flow = flows[key]


# --------------------------------------------------
# Extract features
# --------------------------------------------------

features = extract_features(flow)


# --------------------------------------------------
# Print results
# --------------------------------------------------

print("\nFEATURE EXTRACTION TEST")
print("=" * 60)

for index, feature_name in enumerate(TOP_FEATURES, start=1):

    print(
        f"{index:2}. "
        f"{feature_name:<25} "
        f": {features[feature_name]}"
    )


print("=" * 60)

print("Feature Count:", len(features))


# --------------------------------------------------
# Validate feature order and count
# --------------------------------------------------

assert len(features) == 25, (
    f"Expected 25 features, got {len(features)}"
)

assert list(features.keys()) == TOP_FEATURES, (
    "Feature order does not match TOP_FEATURES"
)


# --------------------------------------------------
# Validate NaN and Inf
# --------------------------------------------------

for feature_name, value in features.items():

    assert value == value, (
        f"NaN detected in {feature_name}"
    )

    assert value != float("inf"), (
        f"Positive infinity detected in {feature_name}"
    )

    assert value != float("-inf"), (
        f"Negative infinity detected in {feature_name}"
    )


print("\nALL FEATURE TESTS PASSED!")

# --------------------------------------------------
# Validate against saved deployment feature list
# --------------------------------------------------

with open("models/top_features.pkl", "rb") as file:
    saved_top_features = pickle.load(file)


print("\nSAVED MODEL FEATURE VALIDATION")
print("=" * 60)

print("Extractor Feature Count:", len(TOP_FEATURES))
print("Saved Feature Count    :", len(saved_top_features))


if TOP_FEATURES == saved_top_features:

    print("FEATURE NAMES AND ORDER MATCH SAVED MODEL!")

else:

    print("FEATURE MISMATCH DETECTED!")

    for index, (extractor_feature, saved_feature) in enumerate(
        zip(TOP_FEATURES, saved_top_features),
        start=1,
    ):

        if extractor_feature != saved_feature:

            print(
                f"{index}. "
                f"Extractor = {extractor_feature} | "
                f"Saved = {saved_feature}"
            )


assert TOP_FEATURES == saved_top_features, (
    "Extractor feature list does not match "
    "models/top_features.pkl"
)


print("\nDEPLOYMENT FEATURE VALIDATION PASSED!")