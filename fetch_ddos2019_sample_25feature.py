"""
Same methodology as fetch_ddos2019_sample.py (own benign only per file,
no cross-dataset blending; contiguous chronological prefix per file, not
random sampling) but for the DEPLOYED model's 25-feature set instead of
the 3 experimental variants' 8-feature set.

Usage:
    python fetch_ddos2019_sample_25feature.py
Writes data/ddos2019_sample/combined_sample_25feature.csv.
"""

from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_DIR = PROJECT_ROOT / "data" / "ddos2019_full"
OUT_DIR = PROJECT_ROOT / "data" / "ddos2019_sample"
OUT_PATH = OUT_DIR / "combined_sample_25feature.csv"

DAY_DIRS = ["01-12", "03-11"]
ATTACK_CAP_PER_FILE = 40_000
CHUNK_SIZE = 200_000

RENAME_MAP = {
    "Flow Packets/s": "Flow Pkts/s",
    "Fwd Packets/s": "Fwd Pkts/s",
    "Max Packet Length": "Pkt Len Max",
    "Average Packet Size": "Pkt Size Avg",
    "Fwd IAT Total": "Fwd IAT Tot",
    "Fwd Header Length": "Fwd Header Len",
    "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Total Length of Fwd Packets": "TotLen Fwd Pkts",
    "Init_Win_bytes_backward": "Init Bwd Win Byts",
    "Bwd Packet Length Max": "Bwd Pkt Len Max",
    "Total Length of Bwd Packets": "TotLen Bwd Pkts",
    "Subflow Bwd Bytes": "Subflow Bwd Byts",
    "Avg Bwd Segment Size": "Bwd Seg Size Avg",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean",
    "Bwd Packet Length Std": "Bwd Pkt Len Std",
    "Packet Length Mean": "Pkt Len Mean",
}

# Raw columns needed (post-rename), before deriving pkt_rate_ratio/iat_variation
RAW_NEEDED = [
    "Timestamp", "Label",
    "Flow Duration", "Flow IAT Max", "Flow Pkts/s", "Fwd Pkts/s", "Flow IAT Mean",
    "Pkt Len Max", "Pkt Size Avg", "Fwd IAT Tot", "Fwd Header Len", "Fwd IAT Mean",
    "Fwd IAT Max", "Subflow Fwd Byts", "Flow IAT Std", "TotLen Fwd Pkts", "Flow IAT Min",
    "Init Bwd Win Byts", "Bwd Pkt Len Max", "TotLen Bwd Pkts", "Subflow Bwd Byts",
    "Bwd Seg Size Avg", "Bwd Pkt Len Mean", "Bwd Pkt Len Std", "Pkt Len Mean",
]

TOP_FEATURES = [
    "pkt_rate_ratio", "Flow Duration", "Flow IAT Max", "Flow Pkts/s", "Fwd Pkts/s",
    "Flow IAT Mean", "Pkt Len Max", "Pkt Size Avg", "Fwd IAT Tot", "iat_variation",
    "Fwd Header Len", "Fwd IAT Mean", "Fwd IAT Max", "Subflow Fwd Byts", "Flow IAT Std",
    "TotLen Fwd Pkts", "Flow IAT Min", "Init Bwd Win Byts", "Bwd Pkt Len Max",
    "TotLen Bwd Pkts", "Subflow Bwd Byts", "Bwd Seg Size Avg", "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std", "Pkt Len Mean",
]

OUTPUT_COLS = ["Timestamp", "Label", "Binary_Label"] + TOP_FEATURES + ["day"]


def load_file_prefix(path, day_tag):
    kept = []
    attack_count = 0

    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        chunk = chunk.rename(columns=RENAME_MAP)
        missing = [c for c in RAW_NEEDED if c not in chunk.columns]
        if missing:
            raise ValueError(f"{path}: missing expected columns after rename: {missing}")

        chunk = chunk[RAW_NEEDED].copy()
        chunk["Binary_Label"] = chunk["Label"].apply(
            lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
        )

        benign = chunk[chunk["Binary_Label"] == 0]
        attack = chunk[chunk["Binary_Label"] == 1]

        room = ATTACK_CAP_PER_FILE - attack_count
        if room <= 0:
            attack = attack.iloc[0:0]
        elif len(attack) > room:
            attack = attack.iloc[:room]

        kept.append(pd.concat([benign, attack]))
        attack_count += len(attack)

        if attack_count >= ATTACK_CAP_PER_FILE:
            break

    if not kept:
        return None

    df = pd.concat(kept, ignore_index=True)

    numeric_cols = [c for c in RAW_NEEDED if c not in ("Timestamp", "Label")]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.dropna(subset=["Timestamp"])

    # Must match feature_extraction/feature_extractor.py's formulas exactly.
    df["pkt_rate_ratio"] = df["Fwd Pkts/s"] / (df["Flow Pkts/s"] + 1)
    df["iat_variation"] = df["Flow IAT Std"] / (df["Flow IAT Mean"] + 1)

    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=TOP_FEATURES)

    df["day"] = day_tag
    return df.sort_values("Timestamp").reset_index(drop=True)[OUTPUT_COLS]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    frames = []

    for day_dir in DAY_DIRS:
        dir_path = SOURCE_DIR / day_dir
        if not dir_path.is_dir():
            print(f"skipping missing dir: {dir_path}")
            continue
        for csv_path in sorted(dir_path.glob("*.csv")):
            day_tag = f"2019_{day_dir}_{csv_path.stem}"
            print(f"loading {csv_path} (day tag: {day_tag}) ...")
            df = load_file_prefix(csv_path, day_tag)
            if df is None or df.empty:
                print("  skipped (no usable rows)")
                continue
            n_attack = int(df["Binary_Label"].sum())
            n_benign = len(df) - n_attack
            print(f"  kept {len(df)} rows (attack={n_attack}, benign={n_benign})")
            frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    combined.to_csv(OUT_PATH, index=False)

    print(f"\nwrote {OUT_PATH}: {len(combined)} rows across {combined['day'].nunique()} day-tags")
    print(f"total attack rows: {int(combined['Binary_Label'].sum())}")
    print(f"total benign rows: {int((combined['Binary_Label'] == 0).sum())}")


if __name__ == "__main__":
    main()
