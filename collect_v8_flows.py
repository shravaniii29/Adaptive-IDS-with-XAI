"""Collect labelled live flows scored by V8, for choosing V8's alert rule.

Runs one trial of the simulation scenarios against this machine and keeps
every flow the backend scored, with V8's own scores (XGBoost probability and
Isolation Forest anomaly score). Flows to or from the lab address are labelled
by the scenario that produced them; every other non-loopback flow seen while
the test runs (the network's ordinary traffic, assumed benign) is labelled
benign. Needs a backend that scores discovery traffic
(IDS_IGNORE_DISCOVERY=0), otherwise the ordinary traffic that matters most is
skipped.

    set IDS_API_BASE=http://127.0.0.1:8001
    python collect_v8_flows.py [out.json] [trials]
"""

import json
import os
import sys
import time

import requests

import simulate_attacks as sa

OUT = sys.argv[1] if len(sys.argv) > 1 else "v8_calibration/v8_flows.json"
TRIALS = int(sys.argv[2]) if len(sys.argv) > 2 else 1
API = sa.API_BASE


def post(path, body):
    return requests.post(API + path, json=body, timeout=10).json()


def main():
    status = requests.get(API + "/status", timeout=10).json()
    if status.get("ignore_discovery"):
        print("WARNING: the backend ignores discovery traffic (IDS_IGNORE_DISCOVERY=0 to score it); "
              "the ordinary-traffic sample will miss it.")
    previous_mode = requests.get(API + "/mode", timeout=10).json()["mode"]
    sa.start_victim_server()

    t0 = time.time()
    scenarios = []
    for trial in range(1, TRIALS + 1):
        for fn in sa.SCENARIOS:
            s = fn()
            s.trial = trial
            scenarios.append(s)
            print(f"  trial {trial}: {s.name} ({s.end_time - s.start_time:.1f}s)", flush=True)
            time.sleep(sa.SCENARIO_GAP_SECONDS)
    time.sleep(sa.DRAIN_SECONDS)
    sa._wait_for_scoring_drain()

    post("/mode", {"mode": "v8"})  # /history now serves V8's scores
    flows = requests.get(API + "/history", timeout=30).json()["flows"]
    post("/mode", {"mode": previous_mode})

    observed = [
        sa.ObservedFlow(
            flow_id=f["flow_id"], source_ip=f.get("source_ip"), destination_ip=f.get("destination_ip"),
            destination_port=f.get("destination_port"),
            observed_at=f.get("flow_start_time") or f.get("recorded_at"),
            hybrid_prediction=f["hybrid_prediction"], variant1={}, variant2={}, variant3={},
        )
        for f in flows
        if (f.get("flow_start_time") or 0) >= t0 - 1 and sa.TARGET_IP in (str(f.get("source_ip")), str(f.get("destination_ip")))
    ]
    attributed = sa.attribute_flows(observed, scenarios)
    truth = {}
    for s in scenarios:
        for f in attributed[s.name]:
            truth[f.flow_id] = (s.name, int(s.is_attack), s.trial)

    rows = []
    for f in flows:
        if (f.get("flow_start_time") or 0) < t0 - 1:
            continue
        fid = f["flow_id"]
        if fid in truth:
            source, label, trial = truth[fid]
        elif str(f.get("destination_ip", "")).startswith("127.") or sa.TARGET_IP in (str(f.get("source_ip")), str(f.get("destination_ip"))):
            continue  # loopback or an unattributed lab flow: not a clean label
        else:
            source, label, trial = "Ordinary traffic (assumed benign)", 0, None
        rows.append(dict(source=source, label=label, trial=trial, t=f.get("flow_start_time"),
                         destination_ip=f.get("destination_ip"), destination_port=f.get("destination_port"),
                         xgb_probability=f.get("xgb_probability"), xgb_prediction=f.get("xgb_prediction"),
                         isolation_anomaly=f.get("isolation_anomaly"), isolation_prediction=f.get("isolation_prediction"),
                         paper_rule_flag=f.get("hybrid_prediction")))
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    json.dump(rows, open(OUT, "w", encoding="utf-8"))
    by = {}
    for r in rows:
        by.setdefault(r["source"], 0)
        by[r["source"]] += 1
    print(f"\nsaved {len(rows)} labelled flows to {OUT}: {by}")


if __name__ == "__main__":
    main()
