import numpy as np


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
    """

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
    # Packet rate ratio
    # -------------------------------------------------

    if backward_packet_count == 0:
        pkt_rate_ratio = float(forward_packet_count)

    else:
        pkt_rate_ratio = (
            forward_packet_count / backward_packet_count
        )

    # -------------------------------------------------
    # Flow duration
    # -------------------------------------------------

    flow_duration = float(flow.duration)

    # -------------------------------------------------
    # Packet rates
    # -------------------------------------------------

    if flow_duration == 0:
        flow_packets_per_second = 0.0
        forward_packets_per_second = 0.0

    else:
        flow_packets_per_second = (
            flow.packet_count / flow_duration
        )

        forward_packets_per_second = (
            forward_packet_count / flow_duration
        )

    # -------------------------------------------------
    # Feature dictionary
    # -------------------------------------------------

    features = {

        "pkt_rate_ratio": pkt_rate_ratio,

        "Flow Duration": flow_duration,

        "Flow IAT Max": safe_max(flow_iats),

        "Flow Pkts/s": flow_packets_per_second,

        "Fwd Pkts/s": forward_packets_per_second,

        "Flow IAT Mean": safe_mean(flow_iats),

        "Pkt Len Max": safe_max(flow.packet_lengths),

        "Pkt Size Avg": safe_mean(flow.packet_lengths),

        "Fwd IAT Tot": (
            float(np.sum(fwd_iats))
            if len(fwd_iats) > 0
            else 0.0
        ),

        "iat_variation": safe_std(flow_iats),

        "Fwd Header Len": float(
            np.sum(flow.forward_header_lengths)
        ),

        "Fwd IAT Max": safe_max(fwd_iats),

        "Fwd IAT Mean": safe_mean(fwd_iats),

        "Flow IAT Std": safe_std(flow_iats),

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

        "Flow IAT Min": safe_min(flow_iats),

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