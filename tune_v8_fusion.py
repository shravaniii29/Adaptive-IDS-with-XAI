"""Choose V8's alert rule: its published OR rule or a summed confidence score.

    python tune_v8_fusion.py [flows.json] [--write]

Reads the labelled flows from collect_v8_flows.py and compares, with two-fold
cross-validation by time order (tuned on one half, scored on the other):

  - the published V8 rule: alarm if XGBoost fires OR the Isolation Forest fires
  - each detector alone
  - a summed confidence score  c = (1 - a) * xgb_probability + a * isolation_anomaly
    alarmed when c >= t, for a in {0.3, 0.5, 0.7}, t tuned on the other half

The objective is balanced accuracy where every source counts equally: recall
averaged over the attack scenarios, specificity averaged over the benign sources
(the simulation's benign baseline and the network's ordinary traffic).
--write stores the best (a, t) fitted on all flows in
models/v8_reference/v8_fusion_config.json, which switches V8 to that rule.
"""

import json
import sys
from datetime import datetime, timezone

import numpy as np

PATH = next((a for a in sys.argv[1:] if not a.startswith("--")), "v8_calibration/v8_flows.json")
WRITE = "--write" in sys.argv
ORD = "Ordinary traffic (assumed benign)"
ALPHAS = (0.3, 0.5, 0.7)

rows = json.load(open(PATH, encoding="utf-8"))
rows = [r for r in rows if r["xgb_probability"] is not None and r["isolation_anomaly"] is not None]
sources = list(dict.fromkeys(r["source"] for r in rows))
print(f"{len(rows)} labelled flows: " + ", ".join(f"{s}={sum(1 for r in rows if r['source'] == s)}" for s in sources))


def conf(r, a):
    return (1 - a) * r["xgb_probability"] + a * r["isolation_anomaly"]


def balanced(rs, flag):
    """mean recall over attack sources and mean specificity over benign sources, averaged."""
    rec, spec = [], []
    for s in dict.fromkeys(r["source"] for r in rs):
        g = [r for r in rs if r["source"] == s]
        hit = np.mean([flag(r) for r in g])
        (rec if g[0]["label"] == 1 else spec).append(hit if g[0]["label"] == 1 else 1 - hit)
    if not rec or not spec:
        return float("nan"), float("nan"), float("nan")
    return float(np.mean(rec)), float(np.mean(spec)), float((np.mean(rec) + np.mean(spec)) / 2)


# two folds by time order within each source
fold = {}
for s in sources:
    g = sorted((r for r in rows if r["source"] == s), key=lambda r: r["t"] or 0)
    for i, r in enumerate(g):
        fold[id(r)] = i % 2


def best_threshold(train, a):
    cands = sorted({round(conf(r, a), 4) for r in train})
    best, score = cands[0], -1
    for t in cands:
        _, _, b = balanced(train, lambda r, t=t: conf(r, a) >= t)
        if b > score or (b == score and t > best):
            best, score = t, b
    return best


def cv_flags(a):
    """out-of-fold alarm decision for every flow"""
    out = {}
    for k in (0, 1):
        train = [r for r in rows if fold[id(r)] != k]
        t = best_threshold(train, a)
        for r in rows:
            if fold[id(r)] == k:
                out[id(r)] = conf(r, a) >= t
    return out


results = {}
paper = lambda r: int(r["xgb_prediction"] == 1 or r["isolation_prediction"] == 1)
results["Published V8 rule (XGBoost OR Isolation Forest)"] = balanced(rows, paper)
results["XGBoost alone"] = balanced(rows, lambda r: r["xgb_prediction"] == 1)
results["Isolation Forest alone"] = balanced(rows, lambda r: r["isolation_prediction"] == 1)
cv = {}
for a in ALPHAS:
    flags = cv_flags(a)
    cv[a] = flags
    results[f"Summed confidence, weight on Isolation Forest {a} (cross-validated)"] = balanced(rows, lambda r, f=flags: f[id(r)])

print("\nbalanced result over all flows (recall over attack scenarios | specificity over benign sources | mean)")
for name, (rc, sp, b) in results.items():
    print(f"  {name:72s} {rc:6.3f} | {sp:6.3f} | {b:6.3f}")

print("\nper source, share alarmed:")
header = f"  {'source':36s} {'flows':>5} {'paper OR':>9}" + "".join(f" {'conf a=' + str(a):>10}" for a in ALPHAS)
print(header)
for s in sources:
    g = [r for r in rows if r["source"] == s]
    line = f"  {s:36s} {len(g):5d} {np.mean([paper(r) for r in g]):9.2f}" + "".join(f" {np.mean([cv[a][id(r)] for r in g]):10.2f}" for a in ALPHAS)
    print(line + ("   <- attack" if g[0]["label"] else "   <- benign"))

best_a = max(ALPHAS, key=lambda a: balanced(rows, lambda r, f=cv[a]: f[id(r)])[2])
final_t = best_threshold(rows, best_a)
print(f"\nbest weight on Isolation Forest: {best_a}; threshold tuned on all flows: {final_t}")
print("sensitivity of that rule (all flows):")
print(f"  {'threshold':>9}  {'attack recall':>13}  {'benign specificity':>18}")
for t in sorted({round(final_t + d, 4) for d in (-0.04, -0.02, -0.01, 0, 0.01, 0.02, 0.04)}):
    rc, sp, _ = balanced(rows, lambda r, t=t: conf(r, best_a) >= t)
    print(f"  {t:9.4f}  {rc:13.3f}  {sp:18.3f}{'   <- chosen' if abs(t - final_t) < 1e-9 else ''}")

if WRITE:
    cfg = dict(rule="confidence", alpha=best_a, threshold=float(final_t),
               calibrated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
               method="tune_v8_fusion.py: summed confidence c=(1-a)*xgb_probability+a*isolation_anomaly, a and t chosen by balanced accuracy "
                      "(recall over attack scenarios, specificity over benign sources) with 2-fold cross-validation by time",
               flows=len(rows), cv_balanced_accuracy=float(balanced(rows, lambda r: cv[best_a][id(r)])[2]),
               published_rule_balanced_accuracy=float(results["Published V8 rule (XGBoost OR Isolation Forest)"][2]))
    json.dump(cfg, open("models/v8_reference/v8_fusion_config.json", "w", encoding="utf-8"), indent=2)
    print("\nwrote models/v8_reference/v8_fusion_config.json")
