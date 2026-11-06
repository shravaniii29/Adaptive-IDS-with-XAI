"""Quick per-network calibration of the hybrid confidence fusion.

Every network scores a bit differently (the Isolation Forest rates ordinary
browsing/DNS on one Wi-Fi as more anomalous than on another), so the one
threshold baked into models/fusion_config.json can over- or under-flag when
you move. This finds the best confidence combination for the network you are
on right now, in a couple of minutes, without retraining anything.

How it works:
  - Benign side  = this network's own traffic. It reads the live flows the
    running backend has already captured (so just browse / play a video for a
    minute first), treating them as benign.
  - Attack side  = the stored self-generated flood/scan flows in
    fusion_calibration/calibration_flows.json (these are made on loopback and
    do not depend on the network).
  - It sweeps the fusion  c = (1 - alpha) * xgb + alpha * iso , flagged when
    c >= threshold, over alpha in {0.3, 0.5, 0.7} and every candidate
    threshold, and reports the (alpha, threshold) with the best balanced
    accuracy (mean of attack recall and this-network benign specificity).

Usage:
    # 1) start the backend and browse for ~1 min so it captures benign flows
    # 2) then:
    python calibrate_network.py                 # show the recommendation
    python calibrate_network.py --write          # also save it to fusion_config.json
    python calibrate_network.py --collect 90     # poll live flows for 90s first
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
API_BASE = os.environ.get("IDS_API_BASE", "http://127.0.0.1:8000")
STORED_ATTACKS = ROOT / "fusion_calibration" / "calibration_flows.json"
FUSION_CONFIG = ROOT / "models" / "fusion_config.json"
ALPHAS = (0.3, 0.5, 0.7)


def confidence(xgb, iso, alpha):
    return (1 - alpha) * xgb + alpha * iso


def load_stored_attacks():
    if not STORED_ATTACKS.exists():
        sys.exit(f"missing {STORED_ATTACKS} - run the attack simulation once to generate it.")
    rows = json.load(open(STORED_ATTACKS))
    atk = [(r["xgb_probability"], r["isolation_anomaly"]) for r in rows if r.get("label") == 1]
    if not atk:
        sys.exit("no attack flows in the stored calibration file.")
    return atk


def live_benign_from_history():
    """Live flows the backend has already captured on this network, as (xgb, iso)."""
    try:
        data = requests.get(f"{API_BASE}/history", timeout=5).json()
    except Exception as exc:
        sys.exit(f"could not reach the backend at {API_BASE}: {exc}")
    flows = data.get("flows", data) if isinstance(data, dict) else data
    out = []
    for f in flows:
        xgb, iso = f.get("xgb_probability"), f.get("isolation_anomaly")
        if xgb is not None and iso is not None:
            out.append((xgb, iso))
    return out


def live_benign_collect(seconds):
    """Poll /history for `seconds`, de-duplicating by flow id, so you can
    generate traffic while it watches."""
    seen, out = set(), []
    end = time.time() + seconds
    print(f"collecting this network's flows for {seconds}s - browse / stream to make traffic ...")
    while time.time() < end:
        try:
            data = requests.get(f"{API_BASE}/history", timeout=5).json()
            flows = data.get("flows", data) if isinstance(data, dict) else data
            for f in flows:
                fid = f.get("flow_id") or id(f)
                if fid in seen:
                    continue
                seen.add(fid)
                xgb, iso = f.get("xgb_probability"), f.get("isolation_anomaly")
                if xgb is not None and iso is not None:
                    out.append((xgb, iso))
        except Exception:
            pass
        print(f"  {len(out)} benign flows so far ...", end="\r")
        time.sleep(3)
    print()
    return out


def best_fusion(attacks, benign):
    """Grid-search (alpha, threshold) for the best balanced accuracy."""
    best = None
    for alpha in ALPHAS:
        atk_c = sorted(confidence(x, i, alpha) for x, i in attacks)
        ben_c = sorted(confidence(x, i, alpha) for x, i in benign)
        # candidate thresholds: midpoints between every observed confidence
        cands = sorted(set(atk_c) | set(ben_c))
        thresholds = [(cands[k] + cands[k + 1]) / 2 for k in range(len(cands) - 1)] or [0.5]
        for t in thresholds:
            recall = sum(c >= t for c in atk_c) / len(atk_c)
            spec = sum(c < t for c in ben_c) / len(ben_c)
            bal = (recall + spec) / 2
            row = (bal, alpha, round(t, 4), recall, spec)
            if best is None or row > best:
                best = row
    return best


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--collect", type=int, metavar="SECONDS",
                    help="poll live flows for this many seconds first (generate traffic meanwhile)")
    ap.add_argument("--write", action="store_true", help="save the result to models/fusion_config.json")
    args = ap.parse_args()

    attacks = load_stored_attacks()
    if args.collect:
        benign = live_benign_collect(args.collect)
    else:
        benign = live_benign_from_history()

    if len(benign) < 10:
        sys.exit(f"only {len(benign)} benign flows found - browse for a minute with the backend "
                 f"running, or pass --collect 90, so the estimate is stable.")

    print(f"\nattack flows (stored): {len(attacks)}   benign flows (this network): {len(benign)}")
    bal, alpha, t, recall, spec = best_fusion(attacks, benign)
    print("\n  recommended confidence fusion for this network")
    print("  ---------------------------------------------")
    print(f"  alpha (weight on Isolation Forest): {alpha}")
    print(f"  threshold:                          {t}")
    print(f"  -> attack recall {recall*100:.1f}%   benign specificity {spec*100:.1f}%   balanced {bal*100:.1f}%")
    print(f"\n  formula: flag when  {1-alpha:.1f}*xgb + {alpha:.1f}*iso >= {t}")

    if args.write:
        cfg = {}
        if FUSION_CONFIG.exists():
            cfg = json.load(open(FUSION_CONFIG))
        cfg.update({
            "alpha": alpha,
            "threshold": t,
            "calibrated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "method": "calibrate_network.py: best balanced accuracy, stored attacks vs this network's live benign flows",
            "network_benign_flows": len(benign),
            "network_recall": recall,
            "network_specificity": spec,
        })
        json.dump(cfg, open(FUSION_CONFIG, "w"), indent=2)
        print(f"\n  written to {FUSION_CONFIG} - restart the backend to use it.")
    else:
        print("\n  (run again with --write to save this to models/fusion_config.json)")


if __name__ == "__main__":
    main()
