"""
Generates demo-ready charts from simulate_attacks.py's per-attack-type
JSON output (simulation_results/*.json).

Adds a 2-model VOTING system on top of the 4 individually-served models:
    voting = deployed_hybrid AND variant2_xgb_temporal
i.e. both must independently flag ATTACK before the vote calls it an
attack. This pairing was chosen because the live simulation showed
variant2 (temporal features) has higher recall than the other variants
but a much worse false-positive rate - requiring agreement with the
deployed model is a way to test whether that recall can be kept while
cutting the false positives, rather than assuming it.

If a flow is missing a prediction from either voting member, the vote
falls back to whichever one is available (matches how each individual
model already handles unavailability - a partial reading over no
reading).

Usage:
    python visualize_simulation.py
Requires simulation_results/*.json to already exist (run
simulate_attacks.py first). Writes PNGs into simulation_results/charts/.
"""

import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RESULTS_DIR = sys.argv[1] if len(sys.argv) > 1 else "simulation_results"
CHARTS_DIR = os.path.join(RESULTS_DIR, "charts")

MODEL_KEYS = ["deployed_hybrid", "variant1_xgb_single_flow", "variant2_xgb_temporal", "variant3_cnn_lstm"]
MODEL_LABELS = {
    "deployed_hybrid": "Deployed hybrid",
    "variant1_xgb_single_flow": "Var1 XGB single-flow",
    "variant2_xgb_temporal": "Var2 XGB temporal",
    "variant3_cnn_lstm": "Var3 CNN+LSTM",
    "voting_hybrid_var2": "Voting (hybrid AND var2)"
}
COLORS = {
    "deployed_hybrid": "#4C72B0",
    "variant1_xgb_single_flow": "#DD8452",
    "variant2_xgb_temporal": "#55A868",
    "variant3_cnn_lstm": "#C44E52",
    "voting_hybrid_var2": "#8172B2"
}
ALL_KEYS = MODEL_KEYS + ["voting_hybrid_var2"]


def vote(flow_models, expected):
    """AND-vote between deployed_hybrid and variant2. Falls back to
    whichever member is available if the other isn't."""
    hybrid = flow_models["deployed_hybrid"]
    var2 = flow_models["variant2_xgb_temporal"]

    if hybrid["available"] and var2["available"]:
        pred = 1 if (hybrid["prediction"] == 1 and var2["prediction"] == 1) else 0
        return {"available": True, "prediction": pred, "correct": pred == expected}
    if hybrid["available"]:
        return {"available": True, "prediction": hybrid["prediction"], "correct": hybrid["correct"]}
    if var2["available"]:
        return {"available": True, "prediction": var2["prediction"], "correct": var2["correct"]}
    return {"available": False, "prediction": None, "correct": None}


def load_scenarios():
    with open(os.path.join(RESULTS_DIR, "summary.json")) as fh:
        summary = json.load(fh)

    scenarios = []
    for entry in summary["scenarios"]:
        with open(os.path.join(RESULTS_DIR, entry["file"])) as fh:
            scenarios.append(json.load(fh))
    return scenarios


def score_with_voting(scenario):
    expected = 1 if scenario["is_attack"] else 0
    scores = {k: scenario["model_scores"].get(k) for k in MODEL_KEYS}

    correct, total = 0, 0
    for flow in scenario["flows"]:
        v = vote(flow["models"], expected)
        if not v["available"]:
            continue
        total += 1
        correct += int(v["correct"])
    scores["voting_hybrid_var2"] = (correct / total) if total else None

    return scores


def bar_chart(scores, title, out_path, metric_label):
    keys = [k for k in ALL_KEYS if scores.get(k) is not None]
    if not keys:
        return False
    values = [scores[k] * 100 for k in keys]
    labels = [MODEL_LABELS[k] for k in keys]
    colors = [COLORS[k] for k in keys]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, values, color=colors)
    ax.set_ylim(0, 100)
    ax.set_ylabel(f"{metric_label} (%)")
    ax.set_title(title)
    ax.tick_params(axis="x", rotation=20)
    for bar, val in zip(bars, values):
        ax.annotate(f"{val:.1f}%", (bar.get_x() + bar.get_width() / 2, val),
                    ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return True


def combined_chart(all_scenarios, all_scores, out_path):
    import numpy as np

    names = [s["name"] for s in all_scenarios]
    n_groups = len(names)
    n_bars = len(ALL_KEYS)
    x = np.arange(n_groups)
    width = 0.8 / n_bars

    fig, ax = plt.subplots(figsize=(max(10, n_groups * 1.8), 6))
    for i, key in enumerate(ALL_KEYS):
        vals = [(all_scores[s["name"]].get(key) or 0) * 100 for s in all_scenarios]
        ax.bar(x + i * width - 0.4 + width / 2, vals, width, label=MODEL_LABELS[key], color=COLORS[key])

    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20)
    ax.set_ylabel("Recall (attack scenarios) / Specificity (benign) %")
    ax.set_ylim(0, 100)
    ax.set_title("Per-attack-type accuracy: 4 models + voting system")
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def summary_chart(all_scenarios, all_scores, out_path):
    """Average recall across attack scenarios, and specificity on the
    benign scenario, per model - the headline demo chart."""
    attack_names = [s["name"] for s in all_scenarios if s["is_attack"]]
    benign_names = [s["name"] for s in all_scenarios if not s["is_attack"]]

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    for ax, names, title, ylabel in [
        (axes[0], attack_names, "Average recall across attack scenarios", "Recall (%)"),
        (axes[1], benign_names, "Specificity on benign baseline", "Specificity (%)")
    ]:
        keys = ALL_KEYS
        avgs = []
        for key in keys:
            vals = [all_scores[n][key] for n in names if all_scores[n].get(key) is not None]
            avgs.append((sum(vals) / len(vals) * 100) if vals else 0)
        labels = [MODEL_LABELS[k] for k in keys]
        colors = [COLORS[k] for k in keys]
        bars = ax.bar(labels, avgs, color=colors)
        ax.set_ylim(0, 100)
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.tick_params(axis="x", rotation=20)
        for bar, val in zip(bars, avgs):
            ax.annotate(f"{val:.1f}%", (bar.get_x() + bar.get_width() / 2, val),
                        ha="center", va="bottom", fontsize=9)

    fig.suptitle("Deployed model vs 3 experimental variants vs 2-model voting system")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def main():
    os.makedirs(CHARTS_DIR, exist_ok=True)
    scenarios = load_scenarios()

    all_scores = {}
    for scenario in scenarios:
        scores = score_with_voting(scenario)
        all_scores[scenario["name"]] = scores

        metric = "Recall" if scenario["is_attack"] else "Specificity"
        title = f"{scenario['name']} ({'ATTACK' if scenario['is_attack'] else 'BENIGN'}, {scenario['flow_count']} flows)"
        out_path = os.path.join(CHARTS_DIR, f"{scenario['name']}.png")
        if bar_chart(scores, title, out_path, metric):
            print(f"wrote {out_path}")
        else:
            print(f"skipped {out_path} (no attributed flows / no model scored)")

    combined_chart(scenarios, all_scores, os.path.join(CHARTS_DIR, "combined_comparison.png"))
    print(f"wrote {os.path.join(CHARTS_DIR, 'combined_comparison.png')}")

    summary_chart(scenarios, all_scores, os.path.join(CHARTS_DIR, "summary.png"))
    print(f"wrote {os.path.join(CHARTS_DIR, 'summary.png')}")


if __name__ == "__main__":
    main()
