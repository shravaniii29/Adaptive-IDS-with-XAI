import math

import numpy as np

from detection.experimental_history import RollingHistoryStore

BASE_FEATURES = [
    "Flow Duration", "Tot Fwd Pkts", "TotLen Fwd Pkts",
    "Flow Byts/s", "Flow Pkts/s", "Avg Pkt Size", "Min Pkt Size", "Protocol",
]


# -------------------------------------------------
# Cold start: brand new group has no history
# -------------------------------------------------

store = RollingHistoryStore(max_groups=3, window=10, ttl_seconds=3600)

cold = store.get_temporal_features(dst_port=80, protocol=6)

assert cold["hist_flow_count"] == 0
assert cold["time_since_last"] == 0.0
assert all(
    v == 0.0
    for k, v in cold.items()
    if k.startswith("hist_mean") or k.startswith("hist_std")
)

print("Cold start: all-zero temporal features - PASSED")


# -------------------------------------------------
# Single prior sample: std must be 0, not NaN
# (pandas std is ddof=1, undefined for n=1)
# -------------------------------------------------

store.append(80, 6, {
    "Flow Pkts/s": 10.0, "Flow Byts/s": 100.0,
    "Flow Duration": 5.0, "TotLen Fwd Pkts": 50.0,
})

after_one = store.get_temporal_features(dst_port=80, protocol=6)

assert after_one["hist_flow_count"] == 1
assert after_one["hist_std_Flow_Pkts_s"] == 0.0
assert not math.isnan(after_one["hist_std_Flow_Pkts_s"])

print("Single-sample std is 0, not NaN - PASSED")


# -------------------------------------------------
# Two samples: mean/std computed correctly
# -------------------------------------------------

store.append(80, 6, {
    "Flow Pkts/s": 20.0, "Flow Byts/s": 200.0,
    "Flow Duration": 7.0, "TotLen Fwd Pkts": 70.0,
})

after_two = store.get_temporal_features(dst_port=80, protocol=6)

assert after_two["hist_mean_Flow_Pkts_s"] == 15.0
assert after_two["hist_flow_count"] == 2

print("Two-sample mean/count correct - PASSED")


# -------------------------------------------------
# LRU eviction: max_groups caps total group count
# -------------------------------------------------

for port in [1, 2, 3, 4]:
    store.append(port, 6, {
        "Flow Pkts/s": 1.0, "Flow Byts/s": 1.0,
        "Flow Duration": 1.0, "TotLen Fwd Pkts": 1.0,
    })

assert store.group_count() <= 3

print("LRU eviction caps group count at max_groups - PASSED")


# -------------------------------------------------
# Raw sequence: cold start is front-zero-padded,
# current flow is always the last timestep
# -------------------------------------------------

current = {f: 1.0 for f in BASE_FEATURES}
current["Protocol"] = 17.0

seq = store.get_raw_sequence(9999, 17, current, BASE_FEATURES)

assert seq.shape == (10, 8)
assert np.allclose(seq[:9], 0.0)
assert np.allclose(seq[9], [1, 1, 1, 1, 1, 1, 1, 17])

print("Cold-start sequence: zero-padded with current flow last - PASSED")

# Append that flow, then check the NEXT flow's sequence places the prior
# flow immediately before it.

store.append(9999, 17, current)

next_current = dict(current)
next_current["Flow Pkts/s"] = 2.0

seq2 = store.get_raw_sequence(9999, 17, next_current, BASE_FEATURES)

assert np.allclose(seq2[8], [1, 1, 1, 1, 1, 1, 1, 17])
assert seq2[9][4] == 2.0

print("Sequence ordering: prior flow precedes current flow - PASSED")

print("\nEXPERIMENTAL HISTORY STORE TEST PASSED")
