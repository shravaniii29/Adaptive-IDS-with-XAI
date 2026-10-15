# 2-model voting system: analysis

## Question being tested

Would a voting system combining two of the models produce better live
detection than any single model? Specifically: does requiring the
deployed hybrid model and experimental variant 2 (XGBoost + rolling
temporal features) to **both** agree before flagging ATTACK improve on
either model alone?

Variant 2 was chosen as the voting partner because earlier live-traffic
testing showed it had much higher recall than the other two experimental
variants, but also a much worse false-positive rate — the hypothesis was
that requiring agreement with the deployed model might cut that
false-positive rate while keeping some of the recall gain.

## Method

`voting = 1 if (deployed_hybrid_prediction == 1 AND variant2_prediction == 1) else 0`

(An AND vote: both members must independently call a flow ATTACK. If
only one member's prediction is available for a flow, the vote falls
back to that one.)

Computed offline in [`visualize_simulation.py`](visualize_simulation.py)
from the flow-level predictions already captured by
[`simulate_attacks.py`](simulate_attacks.py) — not wired into the live
app. Test traffic: 6 short (~10s) self-targeted scenarios against this
machine's own LAN IP — ICMP flood, SYN flood, UDP flood, HTTP flood,
port scan, and a benign baseline for false-positive measurement.

## Result

| Scenario | Type | Flows | Deployed hybrid | Var1 (single-flow) | Var2 (temporal) | Var3 (CNN+LSTM) | **Vote (hybrid AND var2)** |
|---|---|---|---|---|---|---|---|
| Benign baseline | BENIGN | 9 | 100.0% spec | 100.0% spec | 22.2% spec | 77.8% spec | **100.0% spec** |
| ICMP flood | ATTACK | 1 | 0.0% recall | 0.0% recall | 100.0% recall | 0.0% recall | **0.0% recall** |
| SYN flood | ATTACK | 4 | 0.0% recall | 0.0% recall | 75.0% recall | 0.0% recall | **0.0% recall** |
| UDP flood | ATTACK | 3 | 0.0% recall | 0.0% recall | 66.7% recall | 0.0% recall | **0.0% recall** |
| HTTP flood | ATTACK | 3 | 0.0% recall | 0.0% recall | 66.7% recall | 0.0% recall | **0.0% recall** |
| Port scan | ATTACK | 12 | 8.3% recall | 8.3% recall | 91.7% recall | 0.0% recall | **8.3% recall** |

(recall = % of attack flows correctly flagged ATTACK. specificity = % of
benign flows correctly flagged NORMAL. Charts: [`simulation_results/charts/`](simulation_results/charts/),
raw per-flow data: [`simulation_results/`](simulation_results/).)

## Interpretation

**The hypothesis was wrong for this pairing.** The AND-vote collapsed
almost entirely into the deployed model's near-zero recall instead of
landing between the two members. This is the expected failure mode of
AND-voting two models with very asymmetric recall: because the deployed
model almost never flags ATTACK on this live traffic, requiring *both*
to agree throws away nearly all of variant 2's recall gain, while
keeping the deployed model's already-good specificity. An AND vote
between two models only helps when both members are independently
decent at recall and their false positives are what's uncorrelated —
that isn't the case here; one member (the deployed model) is barely
detecting anything at all on this traffic, so its "vote" is really a
veto.

This is a genuine, reportable negative result: two models with very
different individual recall don't combine usefully under a strict
AND rule — the weaker-recall member dominates. It also reinforces the
earlier finding (from the plain accuracy comparison) that the deployed
model and variant 2 likely differ in the *kind* of skew each has, not
just its magnitude — worth stating plainly if this goes into a paper.

## What would be worth trying instead

The fix is the voting **rule**, not necessarily the pairing:

- **OR-vote** (either member flags it → alert): would inherit variant 2's
  high recall, but also its poor specificity (22.2% on the benign
  baseline) — likely swaps one failure mode for the opposite one.
- **3-model majority vote** across variant 1 / variant 2 / variant 3
  (2-of-3 agreement): might land between the extremes since it isn't
  dominated by a single member.

Neither is implemented yet — `visualize_simulation.py` currently only
computes the AND-vote described above. Extending it to compute
additional rules is a small change (same flow-level data is already
saved in `simulation_results/*.json`; no need to re-run the simulator).

## How to reproduce

Requires the backend running with live packet capture (see
[`RUNNING.md`](RUNNING.md) for full setup):

```
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a separate terminal, once the backend is up:

```
python simulate_attacks.py
```

Runs the 6 scenarios above and writes `simulation_results/*.json` (one
file per attack type, every attributed flow's per-model prediction) plus
`simulation_results/summary.json`.

Then generate the voting comparison and charts:

```
python visualize_simulation.py
```

Writes to `simulation_results/charts/`:
- `<scenario_name>.png` — per-attack-type bar chart, all 4 models + the
  vote
- `combined_comparison.png` — every scenario side by side
- `summary.png` — average recall (attack scenarios) vs. specificity
  (benign), per model — the headline chart

To print the raw numbers behind the charts instead of just viewing
images:

```
python -c "
from visualize_simulation import load_scenarios, score_with_voting
for s in load_scenarios():
    print(s['name'], score_with_voting(s))
"
```
