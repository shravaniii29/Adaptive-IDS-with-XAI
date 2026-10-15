"""
Replaces fetch_cicids2018_sample.py's single-contiguous-block approach
for the 7 "partial" CIC-IDS2018 days with a multi-offset sample per day,
extending fetch_cicids2018_multiday.py's approach (previously only
applied to 02-20-2018) to all 7.

Why: a single contiguous prefix from byte 0 can land entirely inside one
attack burst or one quiet period - checked directly, 4 of the 7 days
fetched this way turned out severely skewed (e.g. 02-14-2018: 142,358
attack rows vs only 124 benign; 02-22-2018: 362 attack rows vs 86,741
benign). Sampling 4 spread-out offsets (0%, 25%, 50%, 75% of the file)
per day gives a much more representative mix of benign/attack periods.

Sourced from the full local copies already in data/cicids2018_full/
(no network fetch needed - those files already contain complete data
for these same 7 days).

Each offset window is saved as its OWN file (e.g. 02-14-2018_off0.csv,
_off1.csv, ...), not concatenated into one - so the existing
`day = path.stem` tagging already used everywhere in this project's
training scripts gives each window its own distinct day tag for free,
with no loader changes needed. Concatenating them into a single file
instead would fabricate false temporal adjacency at the seams between
non-contiguous windows for the (day, Dst Port, Protocol) grouping used
by rolling/sequence features - the same failure mode this project
already found and fixed once for the CIC-DDoS2019 fetch.

Usage:
    python fetch_cicids2018_multiday_v2.py
Writes data/cicids2018/<day>_off{0,1,2,3}.csv (28 files total, replacing
the 7 single-block files fetch_cicids2018_sample.py produced - deletes
those first).
"""

from pathlib import Path

import pandas as pd

DAYS = ["02-14-2018", "02-15-2018", "02-16-2018", "02-20-2018",
        "02-21-2018", "02-22-2018", "02-23-2018"]

ROWS_PER_WINDOW = 40_000  # per offset window, ~160K rows/day total (4 windows) - comparable to the old single-block budget
OFFSETS_FRACTIONS = [0.0, 0.25, 0.50, 0.75]

SOURCE_DIR = Path(__file__).resolve().parent / "data" / "cicids2018_full"
OUT_DIR = Path(__file__).resolve().parent / "data" / "cicids2018"


def count_rows(path):
    """Fast line count without loading the file into memory - these
    source files run up to ~4GB."""
    count = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            count += chunk.count(b"\n")
    return count - 1  # exclude header


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Clean up the old single-block files this replaces.
    for day in DAYS:
        old = OUT_DIR / f"{day}.csv"
        if old.exists():
            old.unlink()
            print(f"removed old single-block file: {old}")

    for day in DAYS:
        source_path = SOURCE_DIR / f"{day}.csv"
        if not source_path.exists():
            print(f"skipping {day}: {source_path} not found")
            continue

        total_rows = count_rows(source_path)
        print(f"\n{day}: {total_rows} data rows in {source_path.name}")

        for i, frac in enumerate(OFFSETS_FRACTIONS):
            skip_rows = int(total_rows * frac)
            print(f"  sampling offset {frac*100:.0f}% (row {skip_rows}) ...")

            # skiprows=range(1, skip_rows+1) keeps the header (row 0) but
            # skips data rows 1..skip_rows before reading ROWS_PER_WINDOW.
            chunk = pd.read_csv(
                source_path,
                skiprows=range(1, skip_rows + 1) if skip_rows > 0 else None,
                nrows=ROWS_PER_WINDOW,
                low_memory=False,
            )

            out_path = OUT_DIR / f"{day}_off{i}.csv"
            chunk.to_csv(out_path, index=False)
            print(f"    saved {out_path} ({len(chunk)} rows)")


if __name__ == "__main__":
    main()
