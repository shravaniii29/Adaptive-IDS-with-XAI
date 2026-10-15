"""Calibrate the confidence-weighted fusion threshold on live traffic.

The deployed hybrid combines the two detectors as

    confidence = (1 - alpha) * xgb_probability + alpha * isolation_anomaly

and flags a flow when confidence >= threshold (detection/predictor.py).
This script picks that threshold from real, labelled live flows instead
of guessing it, and reports how the result compares with the previous
OR-fusion rule on flows that were NOT used for tuning.

Data comes from the same self-targeted harness as simulate_attacks.py
(this machine's own NIC; ICMP/SYN/UDP/HTTP floods, a port scan and a
benign baseline) plus a short window of the machine's ordinary
background traffic, which is assumed benign and is reported separately
because it is a far harder benign class than the synthetic baseline.

Usage (backend must already be running):

    python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
    python tune_fusion_threshold.py [out_dir] [trials] [idle_seconds] [--write]

Trials 1..N-1 are used to tune the threshold, trial N is held out.
--write stores the chosen threshold in models/fusion_config.json.
"""

import json
import sys
import time
from datetime import datetime, timezone

import numpy as np
import requests

import simulate_attacks as sa
from detection import predictor

ALPHA = predictor.FUSION_ALPHA
ORDINARY = "Ordinary traffic (assumed benign)"
# ports the harness itself creates traffic on; never count them as "ordinary"
HARNESS_PORTS = {8000, 5173, sa.VICTIM_HTTP_PORT}


class RawPoller(sa.Poller):
    """Poller that also keeps the raw /history entry, which carries the
    detector scores that ObservedFlow drops."""

    def __init__(self):
        super().__init__()
        self.raw = {}

    def _ingest(self, entries):
        for entry in entries:
            fid = entry.get("flow_id")
            if fid is not None and fid not in self.raw:
                self.raw[fid] = entry
        super()._ingest(entries)


def confidence(xgb_p, iso_anom, alpha=ALPHA):
    return (1.0 - alpha) * xgb_p + alpha * iso_anom


def build_rows(poller, scenarios, idle_window):
    rows = []
    attributed = sa.attribute_flows(poller.flows, scenarios)
    for s in scenarios:
        pass
    seen = set()
    for name, flows in attributed.items():
        for f in flows:
            if f.flow_id in seen:
                continue
            seen.add(f.flow_id)
            sc = max(
                (s for s in scenarios if s.name == name and s.start_time - 1 <= f.observed_at <= s.end_time + 36),
                key=lambda s: s.start_time,
                default=None,
            )
            e = poller.raw[f.flow_id]
            rows.append(dict(source=name, trial=sc.trial if sc else None, label=int(next(s.is_attack for s in scenarios if s.name == name)),
                             t=f.observed_at, **{k: e.get(k) for k in ("xgb_probability", "xgb_prediction", "isolation_prediction", "isolation_anomaly")}))
    t0, t1 = idle_window
    for f in poller.flows:
        if f.flow_id in seen or not (t0 <= f.observed_at <= t1):
            continue
        if f.destination_port in HARNESS_PORTS:
            continue
        e = poller.raw[f.flow_id]
        rows.append(dict(source=ORDINARY, trial=None, label=0, t=f.observed_at,
                         **{k: e.get(k) for k in ("xgb_probability", "xgb_prediction", "isolation_prediction", "isolation_anomaly")}))
    return [r for r in rows if r["xgb_probability"] is not None and r["isolation_anomaly"] is not None]


def metrics(rows, flag):
    """flag(row) -> 0/1. Returns attack recall, synthetic-benign specificity,
    ordinary-traffic specificity and balanced accuracy over the two benign classes."""
    atk = [r for r in rows if r["label"] == 1]
    syn = [r for r in rows if r["source"] == "Benign baseline"]
    ordi = [r for r in rows if r["source"] == ORDINARY]
    rec = np.mean([flag(r) for r in atk]) if atk else float("nan")
    sp_syn = np.mean([1 - flag(r) for r in syn]) if syn else float("nan")
    sp_ord = np.mean([1 - flag(r) for r in ordi]) if ordi else float("nan")
    specs = [x for x in (sp_syn, sp_ord) if not np.isnan(x)]
    spec = float(np.mean(specs)) if specs else float("nan")
    return dict(recall=rec, spec_synthetic=sp_syn, spec_ordinary=sp_ord, balanced=(rec + spec) / 2,
                n_attack=len(atk), n_synthetic=len(syn), n_ordinary=len(ordi))


def fmt(m):
    return (f"recall {m['recall']:.3f} (n={m['n_attack']}) | spec synthetic {m['spec_synthetic']:.3f} (n={m['n_synthetic']})"
            f" | spec ordinary {m['spec_ordinary']:.3f} (n={m['n_ordinary']}) | balanced {m['balanced']:.3f}")


def tune(train_rows):
    cands = sorted({round(confidence(r["xgb_probability"], r["isolation_anomaly"]), 4) for r in train_rows})
    best, best_score = None, -1
    for c in cands:
        m = metrics(train_rows, lambda r, c=c: int(confidence(r["xgb_probability"], r["isolation_anomaly"]) >= c))
        # tie-break towards the higher threshold = fewer false alarms
        if m["balanced"] > best_score or (m["balanced"] == best_score and best is not None and c > best):
            best, best_score = c, m["balanced"]
    return best, best_score


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    write = "--write" in sys.argv
    out_dir = args[0] if len(args) > 0 else "fusion_calibration"
    trials = int(args[1]) if len(args) > 1 else 3
    idle_seconds = int(args[2]) if len(args) > 2 else 90

    requests.get(f"{sa.API_BASE}/status", timeout=5).raise_for_status()
    mode = requests.get(f"{sa.API_BASE}/predict", timeout=5).json().get("fusion_mode")
    print(f"backend reachable; live fusion mode reported: {mode}")
    sa.start_victim_server()

    poller = RawPoller()
    poller.start()

    print(f"collecting {idle_seconds}s of ordinary traffic (do normal browsing; no attack running) ...")
    i0 = time.time()
    time.sleep(idle_seconds)
    idle_window = (i0, time.time())
    time.sleep(sa.DRAIN_SECONDS)  # let the last ordinary flows expire before the scenarios start

    scenarios = []
    for trial in range(1, trials + 1):
        print(f"\n#### TRIAL {trial}/{trials}")
        for fn in sa.SCENARIOS:
            s = fn()
            s.trial = trial
            scenarios.append(s)
            print(f"  {s.name}: {s.end_time - s.start_time:.1f}s")
            time.sleep(sa.SCENARIO_GAP_SECONDS)
        time.sleep(sa.TRIAL_COOLDOWN)
    time.sleep(sa.DRAIN_SECONDS)
    sa._wait_for_scoring_drain()
    poller.stop()

    rows = build_rows(poller, scenarios, (idle_window[0], idle_window[1] + 5))
    import os
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "calibration_flows.json"), "w", encoding="utf-8") as fh:
        json.dump(rows, fh)
    print(f"\n{len(rows)} labelled flows: " + ", ".join(
        f"{n}={sum(1 for r in rows if r['source'] == n)}" for n in dict.fromkeys(r['source'] for r in rows)))

    # split: attack/synthetic by trial; ordinary traffic by time (first half tune, second half held out)
    ordinary = sorted((r for r in rows if r["source"] == ORDINARY), key=lambda r: r["t"])
    half = len(ordinary) // 2
    ordinary_test = {id(r) for r in ordinary[half:]}
    is_test = lambda r: (r["trial"] == trials) if r["source"] != ORDINARY else id(r) in ordinary_test
    train = [r for r in rows if not is_test(r)]
    test = [r for r in rows if is_test(r)]

    thr, tr_score = tune(train)
    print(f"\ntuned on trials 1..{trials - 1} (+ first half of ordinary traffic): alpha={ALPHA}, threshold={thr}")

    or_rule = lambda r: int(r["xgb_prediction"] == 1 or r["isolation_prediction"] == 1)
    conf_rule = lambda r: int(confidence(r["xgb_probability"], r["isolation_anomaly"]) >= thr)
    print("\nTRAIN  OR-fusion      :", fmt(metrics(train, or_rule)))
    print("TRAIN  confidence     :", fmt(metrics(train, conf_rule)))
    print("\nHELD-OUT OR-fusion    :", fmt(metrics(test, or_rule)))
    print("HELD-OUT confidence   :", fmt(metrics(test, conf_rule)))

    print("\nper-attack recall (held-out trial):")
    for name in dict.fromkeys(r["source"] for r in test if r["label"] == 1):
        sub = [r for r in test if r["source"] == name]
        print(f"  {name:12s} n={len(sub):4d}  OR {np.mean([or_rule(r) for r in sub]):.3f}   confidence {np.mean([conf_rule(r) for r in sub]):.3f}")

    summary = dict(alpha=ALPHA, threshold=thr, trials=trials,
                   train_or=metrics(train, or_rule), train_conf=metrics(train, conf_rule),
                   test_or=metrics(test, or_rule), test_conf=metrics(test, conf_rule))
    with open(os.path.join(out_dir, "calibration_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, default=float)

    if write:
        cfg = dict(alpha=ALPHA, threshold=float(thr),
                   calibrated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   method="tune_fusion_threshold.py: maximise balanced accuracy (attack recall vs mean of synthetic-benign and "
                          "ordinary-traffic specificity) on trials 1..N-1; trial N and the second half of ordinary traffic held out",
                   heldout_confidence=summary["test_conf"], heldout_or_rule=summary["test_or"])
        with open(predictor.MODELS_DIR / "fusion_config.json", "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, default=float)
        print(f"\nwrote {predictor.MODELS_DIR / 'fusion_config.json'}")


if __name__ == "__main__":
    main()
