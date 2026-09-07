import numpy as np
MICROSECONDS_PER_SECOND = 1_000_000

# -------------------------------------------------
# V8 candidate feature list (reference/documentation only).
#
# This constant is NOT consumed anywhere in the codebase for
# column selection or ordering - detection/predictor.py loads its
# own authoritative `top_features` list from the trained model's
# pickled artifact (models*/top_features*.pkl) and reindexes the
# `features` dict returned by extract_features() against THAT list.
# extract_features() therefore only needs to guarantee that every
# name a trained model may have selected is present as a key in the
# returned dict; dict key order below is irrelevant to correctness.
#
# This is the V8 mutual_info_classif Top-25 selection (fit on the
# V8 training split only, random_state=42) at the time the extractor
# was last extended. It is kept here for readability/debugging, not
# as a runtime contract.
# -------------------------------------------------

TOP_FEATURES = [
    "Init Fwd Win Byts",
    "Dst Port",
    "pkt_rate_ratio",
    "Fwd Header Len",
    "Subflow Fwd Byts",
    "TotLen Fwd Pkts",
    "Fwd Pkt Len Mean",
    "Pkt Len Max",
    "Fwd Seg Size Avg",
    "Fwd Pkt Len Max",
    "Pkt Len Std",
    "Pkt Len Var",
    "Bwd Pkt Len Mean",
    "Bwd Seg Size Avg",
    "Pkt Len Mean",
    "TotLen Bwd Pkts",
    "Subflow Bwd Byts",
    "Bwd Pkt Len Max",
    "Flow IAT Max",
    "Pkt Size Avg",
    "Fwd Pkts/s",
    "Flow IAT Mean",
    "Flow Pkts/s",
    "Flow Duration",
    "Bwd Pkts/s",
]


def calculate_iats(timestamps):
    """
    Calculate inter-arrival times between consecutive packets.
    """

    if len(timestamps) < 2:
        return []

    timestamps = np.array(timestamps, dtype=float)

    return np.diff(timestamps)


def safe_mean(values):
    if len(values) == 0:
        return 0.0

    return float(np.mean(values))


def safe_std(values):
    if len(values) == 0:
        return 0.0

    return float(np.std(values))


def safe_var(values):
    if len(values) == 0:
        return 0.0

    return float(np.var(values))


def safe_max(values):
    if len(values) == 0:
        return 0.0

    return float(np.max(values))


def safe_min(values):
    if len(values) == 0:
        return 0.0

    return float(np.min(values))


def extract_features(flow):
    """
    Convert a Flow object into the named statistical flow features
    used by the trained IDS models (V7's 25 and V8's extended
    candidate set - see TOP_FEATURES above).

    CICIDS timing features are stored in microseconds,
    while Scapy packet timestamps are represented in seconds.
    """

    MICROSECONDS_PER_SECOND = 1_000_000

    # -------------------------------------------------
    # Inter-arrival times
    # -------------------------------------------------

    flow_iats = calculate_iats(flow.packet_timestamps)

    fwd_iats = calculate_iats(flow.forward_timestamps)

    # -------------------------------------------------
    # Basic counts
    # -------------------------------------------------

    forward_packet_count = len(flow.forward_packet_lengths)

    backward_packet_count = len(flow.backward_packet_lengths)

    # -------------------------------------------------
    # Flow duration
    # Raw duration is in seconds
    # -------------------------------------------------

    flow_duration_seconds = float(flow.duration)

    # -------------------------------------------------
    # Packet rates
    # IMPORTANT: calculate using SECONDS
    # -------------------------------------------------

    if flow_duration_seconds == 0:
        flow_packets_per_second = 0.0
        forward_packets_per_second = 0.0
        backward_packets_per_second = 0.0

    else:
        flow_packets_per_second = (
            flow.packet_count / flow_duration_seconds
        )

        forward_packets_per_second = (
            forward_packet_count / flow_duration_seconds
        )

        backward_packets_per_second = (
            backward_packet_count / flow_duration_seconds
        )

    # -------------------------------------------------
    # Packet rate ratio
    # Must match v7 feature engineering exactly
    # -------------------------------------------------

    pkt_rate_ratio = (
        forward_packets_per_second
        / (flow_packets_per_second + 1)
    )

    # -------------------------------------------------
    # IAT statistics
    # Raw IAT values are currently in seconds
    # -------------------------------------------------

    flow_iat_mean_seconds = safe_mean(flow_iats)

    flow_iat_std_seconds = safe_std(flow_iats)

    # -------------------------------------------------
    # Convert CICIDS timing features to microseconds
    # -------------------------------------------------

    flow_duration = (
        flow_duration_seconds
        * MICROSECONDS_PER_SECOND
    )

    flow_iat_max = (
        safe_max(flow_iats)
        * MICROSECONDS_PER_SECOND
    )

    flow_iat_mean = (
        flow_iat_mean_seconds
        * MICROSECONDS_PER_SECOND
    )

    flow_iat_min = (
        safe_min(flow_iats)
        * MICROSECONDS_PER_SECOND
    )

    flow_iat_std = (
        flow_iat_std_seconds
        * MICROSECONDS_PER_SECOND
    )

    # -------------------------------------------------
    # IAT variation
    #
    # Must match the V7 training notebook's feature_engineering()
    # exactly: notebooks/v7_xgb_iso.ipynb computes this from the raw
    # CIC-IDS2018 "Flow IAT Std"/"Flow IAT Mean" CSV columns, which are
    # already in MICROSECONDS - not from the pre-conversion seconds
    # values. Using flow_iat_std/flow_iat_mean (microseconds, computed
    # above) instead of the *_seconds variants fixes a train/serving
    # skew: the "+1" damping term behaves very differently at second
    # scale vs microsecond scale, so this is not just a units relabel.
    # -------------------------------------------------

    iat_variation = (
        flow_iat_std
        / (flow_iat_mean + 1)
    )

    fwd_iat_total = (
        float(np.sum(fwd_iats))
        * MICROSECONDS_PER_SECOND
        if len(fwd_iats) > 0
        else 0.0
    )

    fwd_iat_max = (
        safe_max(fwd_iats)
        * MICROSECONDS_PER_SECOND
    )

    fwd_iat_mean = (
        safe_mean(fwd_iats)
        * MICROSECONDS_PER_SECOND
    )

    # -------------------------------------------------
    # Feature dictionary
    # -------------------------------------------------

    features = {

        "pkt_rate_ratio": pkt_rate_ratio,

        "Flow Duration": flow_duration,

        "Flow IAT Max": flow_iat_max,

        "Flow Pkts/s": flow_packets_per_second,

        "Fwd Pkts/s": forward_packets_per_second,

        "Flow IAT Mean": flow_iat_mean,

        "Pkt Len Max": safe_max(flow.packet_lengths),

        "Pkt Size Avg": safe_mean(flow.packet_lengths),

        "Fwd IAT Tot": fwd_iat_total,

        "iat_variation": iat_variation,

        "Fwd Header Len": float(
            np.sum(flow.forward_header_lengths)
        ),

        "Fwd IAT Max": fwd_iat_max,

        "Fwd IAT Mean": fwd_iat_mean,

        "Flow IAT Std": flow_iat_std,

        "TotLen Fwd Pkts": float(
            np.sum(flow.forward_packet_lengths)
        ),

        "Subflow Fwd Byts": float(
            np.sum(flow.forward_packet_lengths)
        ),

        "Init Bwd Win Byts": float(
            flow.init_bwd_window_bytes
            if flow.init_bwd_window_bytes is not None
            else 0
        ),

        "Flow IAT Min": flow_iat_min,

        "Bwd Pkt Len Max": safe_max(
            flow.backward_packet_lengths
        ),

        "Subflow Bwd Byts": float(
            np.sum(flow.backward_packet_lengths)
        ),

        "TotLen Bwd Pkts": float(
            np.sum(flow.backward_packet_lengths)
        ),

        "Bwd Seg Size Avg": safe_mean(
            flow.backward_packet_lengths
        ),

        "Bwd Pkt Len Mean": safe_mean(
            flow.backward_packet_lengths
        ),

        "Bwd Pkt Len Std": safe_std(
            flow.backward_packet_lengths
        ),

        "Pkt Len Mean": safe_mean(
            flow.packet_lengths
        ),

        # ---------------------------------------------
        # V8 additions below this line.
        #
        # Each mirrors an existing formula pattern in this
        # file 1:1 (forward-direction / combined-direction
        # analogues of features already computed above), per
        # the Step-4 extractor-compatibility report.
        # ---------------------------------------------

        # Mirrors "Init Bwd Win Byts" above, forward direction.
        "Init Fwd Win Byts": float(
            flow.init_fwd_window_bytes
            if flow.init_fwd_window_bytes is not None
            else 0
        ),

        # Destination port of the flow-initiating packet.
        # 0 for non-TCP/UDP IP traffic (see get_packet_ports()).
        "Dst Port": float(
            flow.dst_port
            if flow.dst_port is not None
            else 0
        ),

        # Mirrors "Pkt Len Max"/"Pkt Size Avg" above, forward-only.
        "Fwd Pkt Len Max": safe_max(
            flow.forward_packet_lengths
        ),

        "Fwd Pkt Len Mean": safe_mean(
            flow.forward_packet_lengths
        ),

        # CICFlowMeter defines "Seg Size Avg" identically to
        # "Pkt Len Mean" for the same direction - this file already
        # relies on that exact equivalence for the existing
        # "Bwd Seg Size Avg" feature above (also
        # safe_mean(flow.backward_packet_lengths)), so the forward
        # analogue uses the same source data.
        "Fwd Seg Size Avg": safe_mean(
            flow.forward_packet_lengths
        ),

        # Mirrors "Bwd Pkt Len Std" above, combined packet lengths.
        "Pkt Len Std": safe_std(
            flow.packet_lengths
        ),

        "Pkt Len Var": safe_var(
            flow.packet_lengths
        ),

        # Mirrors "Fwd Pkts/s" above, backward direction.
        "Bwd Pkts/s": backward_packets_per_second,
    }

    return features
