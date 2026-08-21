"""
Fetch a partial sample (first N MB, truncated to the last complete line)
of each CIC-IDS2018 daily CSV from the public, unauthenticated AWS S3
bucket - no CIC registration, no Kaggle account needed.

Bucket confirmed public and listable at:
https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/

Saves files under data/cicids2018/ using the short filenames
agents/retraining_agent.py already expects (TRAINING_FILES).
"""

import urllib.request
from pathlib import Path

BASE_URL = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/"

# short local filename -> S3 object name
FILES = {
    "02-14-2018.csv": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-15-2018.csv": "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-16-2018.csv": "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-20-2018.csv": "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",  # typo is in the bucket itself
    "02-21-2018.csv": "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-22-2018.csv": "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-23-2018.csv": "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
}

SAMPLE_BYTES = 30 * 1024 * 1024  # ~30MB per day, comfortably >100k rows
OUT_DIR = Path(__file__).resolve().parent / "data" / "cicids2018"


def fetch_partial(url, n_bytes):
    req = urllib.request.Request(url, headers={"Range": f"bytes=0-{n_bytes - 1}"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for local_name, s3_name in FILES.items():
        out_path = OUT_DIR / local_name
        if out_path.exists() and out_path.stat().st_size > 1_000_000:
            print(f"skip {local_name} (already present, {out_path.stat().st_size} bytes)")
            continue

        url = BASE_URL + urllib.parse.quote(s3_name)
        print(f"fetching {local_name} <- {s3_name} ...")
        raw = fetch_partial(url, SAMPLE_BYTES)

        # Truncate to the last complete line so pandas never sees a cut-off row.
        last_newline = raw.rfind(b"\n")
        clean = raw[:last_newline + 1]

        out_path.write_bytes(clean)
        rows = clean.count(b"\n")
        print(f"  saved {out_path} ({len(clean)} bytes, ~{rows} lines)")


if __name__ == "__main__":
    import urllib.parse
    main()
