import numpy as np
MICROSECONDS_PER_SECOND = 1_000_000

TOP_FEATURES = [
    "pkt_rate_ratio",
    "Flow Duration",
    "Flow IAT Max",
    "Flow Pkts/s",
    "Fwd Pkts/s",
    "Flow IAT Mean",
    "Pkt Len Max",
    "Pkt Size Avg",
    "Fwd IAT Tot",
    "iat_variation",
    "Fwd Header Len",
    "Fwd IAT Max",
    "Fwd IAT Mean",
    "Flow IAT Std",
    "TotLen Fwd Pkts",
    "Subflow Fwd Byts",
    "Init Bwd Win Byts",
    "Flow IAT Min",
    "Bwd Pkt Len Max",
    "Subflow Bwd Byts",
    "TotLen Bwd Pkts",
    "Bwd Seg Size Avg",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Pkt Len Mean",
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
    Convert a Flow object into the 25 features expected
    by the trained IDS model.

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

    else:
        flow_packets_per_second = (
            flow.packet_count / flow_duration_seconds
        )

        forward_packets_per_second = (
            forward_packet_count / flow_duration_seconds
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
    # IAT variation
    # Must match v7 feature engineering exactly
    #
    # IMPORTANT:
    # Calculate BEFORE microsecond conversion so the formula
    # remains aligned with the current v7 feature engineering.
    # -------------------------------------------------

    iat_variation = (
        flow_iat_std_seconds
        / (flow_iat_mean_seconds + 1)
    )

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
    }

    return features