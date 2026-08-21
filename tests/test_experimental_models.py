from scapy.layers.inet import IP, TCP

from feature_extraction.flow import Flow
from detection import experimental_models


# -------------------------------------------------
# Create synthetic flow (mirrors test_predictor.py),
# with protocol/dst_port set as flow_manager.py now does
# -------------------------------------------------

flow = Flow(
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
    protocol=6,
    dst_port=443,
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

timestamps = [1.0, 2.0, 4.0]

for packet, timestamp in zip(packets, timestamps):
    packet.time = timestamp
    flow.add_packet(packet)


# -------------------------------------------------
# Feature extraction sanity checks
# -------------------------------------------------

features = experimental_models.extract_experimental_features(flow)

print("\n" + "=" * 60)
print("EXPERIMENTAL FEATURE EXTRACTION")
print("=" * 60)

for key, value in features.items():
    print(f"{key:<20}: {value}")

assert features["Protocol"] == 6.0
assert features["Tot Fwd Pkts"] == 2.0  # 2 of the 3 packets are forward (src matches flow.src_ip)
assert features["Flow Duration"] == flow.duration * 1_000_000  # microseconds, not seconds
assert features["Min Pkt Size"] >= 0.0

print("\nFeature extraction (units, formulas) - PASSED")


# -------------------------------------------------
# predict_all - must never raise, regardless of
# whether the trained artifacts exist yet
# -------------------------------------------------

result = experimental_models.predict_all(flow)

print("\n" + "=" * 60)
print("EXPERIMENTAL PREDICTION RESULT")
print("=" * 60)

assert "disclaimer" in result
assert "variant1_xgb_single_flow" in result
assert "variant2_xgb_temporal" in result
assert "variant3_cnn_lstm" in result

for variant_key in ["variant1_xgb_single_flow", "variant2_xgb_temporal", "variant3_cnn_lstm"]:
    variant = result[variant_key]
    print(f"{variant_key}: {variant}")
    assert "available" in variant
    if variant["available"]:
        assert variant["prediction"] in (0, 1)
        assert 0.0 <= variant["probability"] <= 1.0
    else:
        assert "error" in variant

print("\npredict_all always returns a well-formed result - PASSED")


# -------------------------------------------------
# History is only updated AFTER prediction - a second
# call for the same group must reflect one prior sample
# -------------------------------------------------

before = experimental_models.history_store.get_temporal_features(
    dst_port=flow.dst_port, protocol=flow.protocol
)

experimental_models.predict_all(flow)

after = experimental_models.history_store.get_temporal_features(
    dst_port=flow.dst_port, protocol=flow.protocol
)

assert after["hist_flow_count"] == before["hist_flow_count"] + 1

print("History store updates only after prediction - PASSED")

print("\nEXPERIMENTAL MODELS TEST PASSED")
