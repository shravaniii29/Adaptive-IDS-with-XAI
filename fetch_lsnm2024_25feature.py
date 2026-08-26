"""
Converts LSNM2024's per-PACKET Wireshark/tshark dissection CSVs into the
same 25-feature flow-level schema used everywhere else in this project
(models/top_features.pkl), so LSNM2024 can be added to
train_attack_family_models.py's raw_flood/reflection training data as a
genuinely independent-tool source (see CHANGELOG.md - this addresses the
diagnosed domain-shift: raw_flood/reflection were trained on a narrow set
of attack-tool signatures and generalize poorly to differently-generated
flood traffic).

LSNM2024 (https://data.mendeley.com/datasets/7pzyfvv9jn, CC BY 4.0,
Abu Al-Haija et al., ICICS 2024) is NOT flow-level CICFlowMeter output
despite third-party claims to the contrary - verified directly: its
columns are per-packet fields (frame length, TCP Window Size, ICMP Type,
etc.), one row per packet, not one row per flow. This script reconstructs
flow-level features from that raw packet data.

Why fixed-packet-count windows per IP-pair, not standard 5-tuple grouping:
checked directly - TCP Source/Destination Port are unreliable for a large
fraction of rows in the attack files (~50% show placeholder values of
exactly 0 or 1 rather than real ports, likely a tshark dissection/export
artifact), so grouping by the standard 5-tuple would badly misgroup
packets. IP pairs are reliable (only 2 hosts per attack file: attacker,
victim). Grouping by IP-pair, then chunking each pair's own chronological
packet sequence into fixed-size windows, sidesteps the bad port data
entirely and is conceptually similar to how CICFlowMeter itself splits a
long-lived flow at its own flow-timeout boundary.

Payload length: verified directly against IP Length - `TCP Length` is
already pure TCP payload bytes (IP Length - TCP Length = 40 exactly =
20-byte IP header + 20-byte TCP header, no options), so no header
arithmetic is needed for TCP. UDP Length is assumed to include the
8-byte UDP header (standard Wireshark convention) and is corrected here.
ICMP/other payload subtracts a fixed IP(20)+ICMP(8) header, matching the
live-serving fix already applied to feature_extraction/flow.py this
session.

Benign handling: LSNM2024 provides ONE shared Benign/normal_data.csv
across all 15 attack types, not per-attack-type embedded benign like
CIC-DDoS2019. To still give each derived attack file its own distinct
("own benign only per file") benign windows rather than literally
duplicating the same rows into every output file, the shared benign pool
is split into non-overlapping chunks, one per attack type being
converted here.

Usage:
    python fetch_lsnm2024_25feature.py
Reads data/lsnm2024/{syn_flood,icmp_flood,ddos_icmp,ddos_udp,ddos_raw,
normal_data}.csv (extracted from the LSNM2024 "Dataset-Ready" zip).
Writes data/lsnm2024/{syn_flood,icmp_flood,ddos_icmp,ddos_udp,
ddos_raw}_25feature.csv, each with its own benign chunk + that attack
type's windows, in the same schema as combined_sample_25feature.csv
(Timestamp, Label, Binary_Label, day, + the 25 TOP_FEATURES).
"""

import pickle
import re
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
LSNM_DIR = PROJECT_ROOT / "data" / "lsnm2024"

with open(PROJECT_ROOT / "models" / "top_features.pkl", "rb") as f:
    TOP_FEATURES = pickle.load(f)

WINDOW_SIZE = 50  # packets per reconstructed "flow" - comparable in scale to CIC-IDS2018's own short flood flows (median ~3-6 fwd packets, but those are per-5-tuple; this window is coarser given unreliable ports here)
MAX_WINDOW_DURATION_SECONDS = 300  # a window spanning longer than this almost certainly straddles a capture gap (the benign file's timestamps jump by days in places) - dropped rather than treated as one real flow

IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

ATTACK_FILES = {
    "syn_flood": "Syn",             # matches this project's existing CIC-DDoS2019 "Syn" label for direct comparability
    "icmp_flood": "ICMP-Flood",
    "ddos_icmp": "DDOS-ICMP",
    "ddos_udp": "DDOS-UDP",
    "ddos_raw": "DDOS-RAW",
}
BENIGN_FILE = "normal_data"

NEEDED_COLUMNS = [
    "Frame Time (Epoch)", "IP Source", "IP Destination", "Protocol", "IP Protocol",
    "frame length", "IP Length", "TCP Source Port", "TCP Destination Port", "TCP Length",
    "UDP Source Port", "UDP Destination Port", "UDP Length", "ICMP Type",
]


def load_and_clean(path):
    df = pd.read_csv(path, usecols=lambda c: c in NEEDED_COLUMNS, low_memory=False)

    # Drop non-IP rows (ARP, etc. - no flow-level meaning here) and malformed
    # IP fields (a handful of rows in the benign file contain a literal
    # comma-joined double-IP value, a CSV-export artifact).
    df = df.dropna(subset=["IP Source", "IP Destination", "Frame Time (Epoch)"])
    df = df[df["IP Source"].astype(str).str.match(IP_RE) & df["IP Destination"].astype(str).str.match(IP_RE)]

    df["Frame Time (Epoch)"] = pd.to_numeric(df["Frame Time (Epoch)"], errors="coerce")
    df = df.dropna(subset=["Frame Time (Epoch)"])

    for col in ["frame length", "IP Length", "TCP Source Port", "TCP Destination Port",
                "TCP Length", "UDP Source Port", "UDP Destination Port", "UDP Length"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    return df.sort_values("Frame Time (Epoch)").reset_index(drop=True)


def compute_payload_and_protocol(df):
    is_tcp = df["Protocol"].eq("TCP") | df["IP Protocol"].eq("TCP")
    is_udp = df["Protocol"].eq("UDP") | df["IP Protocol"].eq("UDP")
    is_icmp = df["Protocol"].eq("ICMP") | df["IP Protocol"].eq("ICMP")

    protocol_num = np.select([is_tcp, is_udp], [6, 17], default=0)

    payload = np.select(
        [is_tcp, is_udp],
        [
            df["TCP Length"].fillna(0),
            (df["UDP Length"].fillna(8) - 8).clip(lower=0),
        ],
        default=(df["IP Length"].fillna(28) - 28).clip(lower=0),
    )

    header_len = np.select(
        [is_tcp, is_udp, is_icmp],
        [
            df["IP Length"].fillna(0) - df["TCP Length"].fillna(0),
            8.0,
            8.0,
        ],
        default=20.0,
    )

    return pd.DataFrame({
        "protocol_num": protocol_num,
        "payload": payload,
        "header_len": header_len,
        "frame_length": df["frame length"].fillna(0),
        "ts": df["Frame Time (Epoch)"],
        "ip_a": df["IP Source"],
        "ip_b": df["IP Destination"],
    })


def build_pair_key(df):
    """Undirected IP-pair key (sorted so A->B and B->A packets land in the
    same pair group) - matches this project's existing convention of
    sorting flow endpoints (see feature_extraction/flow_manager.py)."""
    lo = np.minimum(df["ip_a"], df["ip_b"])
    hi = np.maximum(df["ip_a"], df["ip_b"])
    return lo + "|" + hi


def windows_to_flows(pkts, label):
    """pkts: one IP-pair's packets, already sorted by ts. Chunks them into
    fixed-size windows and computes the 25 TOP_FEATURES per window,
    exactly matching the formulas already established in this project
    (feature_extraction/feature_extractor.py, train_attack_family_models.py)."""
    if len(pkts) < 2:
        return []

    forward_ip = pkts["ip_a"].iloc[0]  # source of the first chronological packet = forward direction, matching flow.py's convention
    rows = []
    # Ceiling division, not floor: some LSNM2024 attack files (verified
    # directly - ddos_udp) spoof a different source IP on nearly every
    # packet, so almost every IP-pair group has only 1-2 packets. Floor
    # division silently produced zero windows for the whole file in that
    # case (2 packets // 50 == 0). A small leftover group still becomes
    # its own (smaller) flow instead of being discarded - this mirrors
    # how real reflection/amplification traffic in CIC-DDoS2019 also
    # produces many short (1-3 packet) flows, one per reflector.
    n_windows = max(1, -(-len(pkts) // WINDOW_SIZE))

    for w in range(n_windows):
        chunk = pkts.iloc[w * WINDOW_SIZE:(w + 1) * WINDOW_SIZE]
        duration_s = chunk["ts"].iloc[-1] - chunk["ts"].iloc[0]
        if duration_s > MAX_WINDOW_DURATION_SECONDS:
            continue  # spans a capture gap, not a real flow window - see module docstring

        # A near-/exactly-zero duration is NOT noise to discard here - for
        # a spoofed-source flood, many packets landing within the same
        # timestamp precision window (duration collapsing to ~0) IS the
        # attack signature, not an artifact. Dropping these (an earlier
        # version of this script did) silently threw out the most
        # attack-representative windows and kept only the atypical "slow"
        # ones. Floor to a 1-microsecond epsilon instead, so rate features
        # (Flow Pkts/s etc.) come out as a very large but finite number
        # correctly reflecting the burst, rather than the window being
        # discarded or the rate silently reading 0.
        duration_s = max(duration_s, 1e-6)

        is_fwd = chunk["ip_a"].values == forward_ip
        fwd = chunk[is_fwd]
        bwd = chunk[~is_fwd]

        ts_diffs_us = np.diff(chunk["ts"].values) * 1_000_000
        fwd_ts_diffs_us = np.diff(fwd["ts"].values) * 1_000_000 if len(fwd) > 1 else np.array([0.0])

        duration_us = duration_s * 1_000_000
        n_total = len(chunk)
        n_fwd = len(fwd)

        tot_len_fwd = float(fwd["payload"].sum())
        tot_len_bwd = float(bwd["payload"].sum()) if len(bwd) else 0.0
        all_pkt_len = chunk["payload"].values

        flow_pkts_s = n_total / (duration_us / 1e6) if duration_us > 0 else 0.0
        fwd_pkts_s = n_fwd / (duration_us / 1e6) if duration_us > 0 else 0.0

        row = {
            "Flow Duration": duration_us,
            "Flow IAT Max": float(np.max(ts_diffs_us)) if len(ts_diffs_us) else 0.0,
            "Flow Pkts/s": flow_pkts_s,
            "Fwd Pkts/s": fwd_pkts_s,
            "Flow IAT Mean": float(np.mean(ts_diffs_us)) if len(ts_diffs_us) else 0.0,
            "Pkt Len Max": float(np.max(all_pkt_len)) if len(all_pkt_len) else 0.0,
            "Pkt Size Avg": float(np.mean(all_pkt_len)) if len(all_pkt_len) else 0.0,
            "Fwd IAT Tot": float(np.sum(fwd_ts_diffs_us)),
            "Fwd Header Len": float(fwd["header_len"].sum()),
            "Fwd IAT Mean": float(np.mean(fwd_ts_diffs_us)),
            "Fwd IAT Max": float(np.max(fwd_ts_diffs_us)),
            "Subflow Fwd Byts": tot_len_fwd,  # CICFlowMeter's subflow-averaging not reconstructed here - approximated as the window total, documented in the module docstring
            "Flow IAT Std": float(np.std(ts_diffs_us, ddof=1)) if len(ts_diffs_us) > 1 else 0.0,
            "TotLen Fwd Pkts": tot_len_fwd,
            "Flow IAT Min": float(np.min(ts_diffs_us)) if len(ts_diffs_us) else 0.0,
            "Init Bwd Win Byts": 0.0,  # TCP Window Size field not reliably present across protocols in this dataset - left at 0 (a documented approximation)
            "Bwd Pkt Len Max": float(bwd["payload"].max()) if len(bwd) else 0.0,
            "TotLen Bwd Pkts": tot_len_bwd,
            "Subflow Bwd Byts": tot_len_bwd,
            "Bwd Seg Size Avg": float(bwd["payload"].mean()) if len(bwd) else 0.0,
            "Bwd Pkt Len Mean": float(bwd["payload"].mean()) if len(bwd) else 0.0,
            "Bwd Pkt Len Std": float(bwd["payload"].std(ddof=1)) if len(bwd) > 1 else 0.0,
            "Pkt Len Mean": float(np.mean(all_pkt_len)) if len(all_pkt_len) else 0.0,
            "Timestamp": pd.to_datetime(chunk["ts"].iloc[0], unit="s"),
            "Label": label,
            # Extra raw quantities needed for the 8-feature BASE_FEATURES
            # schema (train_experimental_models_2019.ipynb, variants 1-3) -
            # not part of TOP_FEATURES itself, dropped by build_dataset's
            # 25-feature output but kept for build_8feature_dataset below.
            "Tot Fwd Pkts": float(n_fwd),
            "Fwd Pkt Len Min": float(fwd["payload"].min()) if len(fwd) else 0.0,
            "Protocol": float(chunk["protocol_num"].mode().iloc[0]) if len(chunk) else 0.0,
        }
        rows.append(row)

    return rows


BASE_FEATURES_8 = ["Flow Duration", "Tot Fwd Pkts", "TotLen Fwd Pkts",
                   "Flow Byts/s", "Flow Pkts/s", "Avg Pkt Size", "Min Pkt Size", "Protocol"]


def build_windows(pkts_df, label):
    """Returns the full per-window row set (both the 25-feature columns
    and the extra raw quantities needed for the 8-feature schema) -
    build_dataset_25/build_dataset_8 below each select+derive their own
    view from this shared computation."""
    pkts_df = pkts_df.copy()
    pkts_df["pair_key"] = build_pair_key(pkts_df)

    all_rows = []
    for _, group in pkts_df.groupby("pair_key", sort=False):
        all_rows.extend(windows_to_flows(group.reset_index(drop=True), label))

    if not all_rows:
        return pd.DataFrame()

    out = pd.DataFrame(all_rows)
    out["pkt_rate_ratio"] = out["Fwd Pkts/s"] / (out["Flow Pkts/s"] + 1)
    out["iat_variation"] = out["Flow IAT Std"] / (out["Flow IAT Mean"] + 1)
    out["Binary_Label"] = 0 if label == "BENIGN" else 1
    return out


def to_25feature(windows_df):
    if windows_df.empty:
        return pd.DataFrame(columns=["Timestamp", "Label", "Binary_Label"] + TOP_FEATURES)
    return windows_df[["Timestamp", "Label", "Binary_Label"] + TOP_FEATURES]


def to_8feature(windows_df):
    if windows_df.empty:
        return pd.DataFrame(columns=["Timestamp", "Label", "Binary_Label"] + BASE_FEATURES_8)
    out = windows_df.copy()
    out["Flow Byts/s"] = (out["TotLen Fwd Pkts"] + out["TotLen Bwd Pkts"]) / (out["Flow Duration"] / 1_000_000).replace(0, np.nan)
    out["Flow Byts/s"] = out["Flow Byts/s"].fillna(0)
    out["Avg Pkt Size"] = out["TotLen Fwd Pkts"] / out["Tot Fwd Pkts"].replace(0, 1)
    out["Min Pkt Size"] = out["Fwd Pkt Len Min"]
    return out[["Timestamp", "Label", "Binary_Label"] + BASE_FEATURES_8]


def main():
    print("loading benign pool ...")
    benign_pkts = compute_payload_and_protocol(load_and_clean(LSNM_DIR / f"{BENIGN_FILE}.csv"))
    benign_windows = build_windows(benign_pkts, "BENIGN")
    print(f"  reconstructed {len(benign_windows)} benign flow-windows")

    n_chunks = len(ATTACK_FILES)
    shuffled_benign = benign_windows.sample(frac=1, random_state=42).reset_index(drop=True)
    chunk_bounds = np.linspace(0, len(shuffled_benign), n_chunks + 1, dtype=int)
    benign_chunks = [shuffled_benign.iloc[chunk_bounds[i]:chunk_bounds[i + 1]] for i in range(n_chunks)]

    for (stem, label), benign_chunk in zip(ATTACK_FILES.items(), benign_chunks):
        print(f"\nprocessing {stem} ...")
        path = LSNM_DIR / f"{stem}.csv"
        if not path.exists():
            print(f"  skipping - {path} not found")
            continue

        pkts = compute_payload_and_protocol(load_and_clean(path))
        attack_windows = build_windows(pkts, label)
        print(f"  reconstructed {len(attack_windows)} attack flow-windows")

        combined_windows = pd.concat(
            [attack_windows, benign_chunk.assign(Label="BENIGN", Binary_Label=0)], ignore_index=True
        ).sort_values("Timestamp").reset_index(drop=True)

        for suffix, converter in [("25feature", to_25feature), ("8feature", to_8feature)]:
            out_df = converter(combined_windows)
            out_df = out_df.copy()
            out_df["day"] = f"lsnm2024_{stem}"
            out_path = LSNM_DIR / f"{stem}_{suffix}.csv"
            out_df.to_csv(out_path, index=False)
            print(f"  wrote {out_path} ({len(out_df)} rows, "
                  f"{(out_df.Binary_Label == 1).sum()} attack + {(out_df.Binary_Label == 0).sum()} benign)")


if __name__ == "__main__":
    main()
