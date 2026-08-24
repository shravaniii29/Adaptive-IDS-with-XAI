"""
Builds a bounded, training-ready sample from the full CIC-DDoS2019 dataset
(data/ddos2019_full/{01-12,03-11}/*.csv, ~66M rows total across 18
attack-type files) for combining with the existing CIC-IDS2018 training
data in train_experimental_models.py.

Two deliberate design choices, both driven by problems found investigating
this dataset (see VOTING_SYSTEM_ANALYSIS.md-adjacent discussion / chat):

1. Own benign only, no cross-dataset blending. Each 2019 file is almost
   entirely one attack type (e.g. DrDoS_DNS.csv is 99.9% DrDoS_DNS,
   0.1% BENIGN). Pairing 2019 attacks with 2018's benign traffic would
   let a model learn "which capture session is this" instead of "is
   this an attack" - the same shortcut-learning failure mode already
   found and fixed twice elsewhere in this project. So: every 2019
   file contributes its OWN benign rows alongside its OWN attack rows,
   kept in their own `day` tag distinct from every 2018 day tag, so the
   downstream (day, Dst Port, Protocol) grouping used for temporal
   history/sequences (train_three_way_multiday.py) never blends a 2019
   flow's history with a 2018 flow's.

2. Contiguous chronological prefix, not random sampling, per file.
   These files are large (up to 20M rows) and already sorted by
   Timestamp. Randomly sampling rows would scatter the surviving rows
   across the full time range, destroying the true adjacency that
   variant 2 (rolling temporal features) and variant 3 (raw sequence)
   depend on - two "consecutive" sampled rows could really be minutes
   apart. Reading a contiguous prefix instead (until the attack-row cap
   is hit) preserves genuine chronological order.

Usage:
    python fetch_ddos2019_sample.py
Writes data/ddos2019_sample/combined_sample.csv.
"""

from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_DIR = PROJECT_ROOT / "data" / "ddos2019_full"
OUT_DIR = PROJECT_ROOT / "data" / "ddos2019_sample"
OUT_PATH = OUT_DIR / "combined_sample.csv"

DAY_DIRS = ["01-12", "03-11"]
ATTACK_CAP_PER_FILE = 40_000
CHUNK_SIZE = 200_000

RENAME_MAP = {
    "Destination Port": "Dst Port",
    "Total Fwd Packets": "Tot Fwd Pkts",
    "Total Length of Fwd Packets": "TotLen Fwd Pkts",
    "Fwd Packet Length Min": "Fwd Pkt Len Min",
    "Flow Bytes/s": "Flow Byts/s",
    "Flow Packets/s": "Flow Pkts/s",
}

REQUIRED_RAW = ["Timestamp", "Label", "Protocol", "Dst Port",
                "Flow Duration", "Tot Fwd Pkts", "TotLen Fwd Pkts",
                "Flow Byts/s", "Flow Pkts/s", "Fwd Pkt Len Min"]

OUTPUT_COLS = ["Timestamp", "Label", "Binary_Label", "Flow Duration",
               "Tot Fwd Pkts", "TotLen Fwd Pkts", "Flow Byts/s", "Flow Pkts/s",
               "Avg Pkt Size", "Min Pkt Size", "Protocol", "Dst Port", "day"]


def load_file_prefix(path, day_tag):
    """Reads a contiguous chronological prefix of `path`, chunk by chunk,
    keeping every benign row seen and attack rows up to ATTACK_CAP_PER_FILE.
    Stops as soon as the attack cap is reached."""
    kept = []
    attack_count = 0

    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        chunk = chunk.rename(columns=RENAME_MAP)
        missing = [c for c in REQUIRED_RAW if c not in chunk.columns]
        if missing:
            raise ValueError(f"{path}: missing expected columns after rename: {missing}")

        chunk = chunk[REQUIRED_RAW].copy()
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

    for col in ["Flow Duration", "Tot Fwd Pkts", "TotLen Fwd Pkts", "Flow Byts/s",
                "Flow Pkts/s", "Fwd Pkt Len Min", "Protocol", "Dst Port"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.dropna(subset=["Timestamp"])

    df["Avg Pkt Size"] = df["TotLen Fwd Pkts"] / df["Tot Fwd Pkts"].replace(0, 1)
    df["Min Pkt Size"] = df["Fwd Pkt Len Min"]

    base_features = ["Flow Duration", "Tot Fwd Pkts", "TotLen Fwd Pkts",
                      "Flow Byts/s", "Flow Pkts/s", "Avg Pkt Size", "Min Pkt Size", "Protocol"]
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=base_features + ["Dst Port"])

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
                print(f"  skipped (no usable rows)")
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
    print("\nattack types:", sorted(combined.loc[combined.Binary_Label == 1, "Label"].unique()))


if __name__ == "__main__":
    main()
