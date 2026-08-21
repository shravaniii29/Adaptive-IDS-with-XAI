"""
Fetch a spread-out, multi-offset sample of the CIC-IDS2018 Tuesday
02-20-2018 file (the only day in this AWS release that still has
Src IP / Dst IP / Flow ID columns - the rest were anonymized).
A single contiguous prefix of this file lands entirely inside one
attack burst (verified: first 30MB was 99.9% DDoS-LOIC-HTTP, 32
unique Src IPs). Sampling several offsets across the ~3.8GB file
instead gives a mix of benign and attack periods and far more
distinct source IPs to build per-source sequences from.
"""

import urllib.request
import urllib.parse
from pathlib import Path

URL = (
    "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
    "Processed%20Traffic%20Data%20for%20ML%20Algorithms/"
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"
)

TOTAL_SIZE = 4_054_925_350
CHUNK_BYTES = 15 * 1024 * 1024
OFFSETS_FRACTIONS = [0.0, 0.25, 0.50, 0.75]

OUT_PATH = Path(__file__).resolve().parent / "data" / "cicids2018" / "02-20-2018.csv"


def fetch_range(start, n_bytes):
    end = start + n_bytes - 1
    req = urllib.request.Request(URL, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(req, timeout=90) as resp:
        return resp.read()


def main():
    header = None
    body_parts = []

    for frac in OFFSETS_FRACTIONS:
        start = int(TOTAL_SIZE * frac)
        print(f"fetching offset {frac*100:.0f}% (byte {start}) ...")
        raw = fetch_range(start, CHUNK_BYTES)

        if frac == 0.0:
            first_newline = raw.find(b"\n")
            header = raw[:first_newline]
            raw = raw[first_newline + 1:]
        else:
            first_newline = raw.find(b"\n")
            raw = raw[first_newline + 1:]

        last_newline = raw.rfind(b"\n")
        raw = raw[:last_newline + 1]
        body_parts.append(raw)
        print(f"  kept {len(raw)} bytes, ~{raw.count(chr(10).encode())} lines")

    with open(OUT_PATH, "wb") as f:
        f.write(header + b"\n")
        for part in body_parts:
            f.write(part)

    print(f"\nsaved {OUT_PATH} ({OUT_PATH.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
