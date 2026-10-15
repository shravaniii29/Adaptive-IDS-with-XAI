"""Hybrid vs V8 comparison from a simulate_attacks.py run.

    python compare_hybrid_v8.py [run_dir]        (default: hybrid_vs_v8_comparison)

Reads <run_dir>/summary.json, prints the per-scenario and pooled results for
the deployed hybrid (confidence fusion) and for V8 on exactly the same live
flows, and writes <run_dir>/COMPARISON.md.
"""

import json
import math
import os
import sys

RUN = sys.argv[1] if len(sys.argv) > 1 else "hybrid_vs_v8_comparison"
MODELS = (("deployed_hybrid", "Deployed hybrid"), ("v8_candidate", "V8 (paper baseline)"))


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)


summary = json.load(open(os.path.join(RUN, "summary.json"), encoding="utf-8"))
scenarios = summary["scenarios"]
agg = summary.get("aggregate_metrics", {})

lines = []
w = lines.append

w(f"# Hybrid vs V8 - live simulation ({RUN})")
w("")
w(f"{summary.get('trials')} trial(s) of {len(scenarios)} scenarios against this machine, "
  f"both models scoring the identical live flows. Recall for the attack scenarios, specificity for the benign baseline.")
w("")
w("| Scenario | Truth | Flows | " + " | ".join(label for _, label in MODELS) + " |")
w("|---|---|---|" + "---|" * len(MODELS))
for s in scenarios:
    n = s.get("flow_count", 0)
    cells = []
    for key, _ in MODELS:
        v = s.get("model_scores", {}).get(key)
        if v is None:
            cells.append("n/a")
        else:
            k = round(v * n)
            lo, hi = wilson(k, n)
            cells.append(f"{v:.1%} ({lo:.0%}-{hi:.0%})")
    w(f"| {s['name']} | {'attack' if s.get('is_attack') else 'benign'} | {n} | " + " | ".join(cells) + " |")
w("")
w("Cells show the share correct (recall for attacks, specificity for benign) with a 95% Wilson interval.")
w("")
w("Note: the deployed hybrid's fusion rule is whichever was live when the run was made - the old OR rule for runs before "
  "15 Oct 2026 (including v8_comparison_*), the confidence-weighted rule for runs made with the current code. V8 always uses its own published rule.")
w("")
w("## Pooled over all scenarios")
w("")
w("| Metric | " + " | ".join(label for _, label in MODELS) + " |")
w("|---|" + "---|" * len(MODELS))
for metric in ("accuracy", "precision", "recall", "specificity", "f1"):
    row = []
    for key, _ in MODELS:
        m = agg.get(key) or {}
        row.append(f"{m[metric]:.3f}" if metric in m else "n/a")
    w(f"| {metric} | " + " | ".join(row) + " |")
cm_row = []
for key, _ in MODELS:
    m = (agg.get(key) or {}).get("confusion_matrix") or {}
    cm_row.append(f"TP {m.get('tp')} / FN {m.get('fn')} / TN {m.get('tn')} / FP {m.get('fp')}" if m else "n/a")
w("| confusion matrix | " + " | ".join(cm_row) + " |")
w("")

text = "\n".join(lines) + "\n"
open(os.path.join(RUN, "COMPARISON.md"), "w", encoding="utf-8").write(text)
print(text)
