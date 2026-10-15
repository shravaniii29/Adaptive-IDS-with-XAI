"""
RL (contextual-bandit) classifier trained on THIS project's own combined
CIC-IDS2018 + CIC-DDoS2019 dataset - the same 31 2018 day-frames (28 offset
windows + 3 full days) and 18 2019 attack-type files already assembled by
train_attack_family_models.py, using its exact loaders and 25-feature
TOP_FEATURES set (models/top_features.pkl) so results sit on the same
ground truth as the deployed hybrid model and the three family models.

Unlike train_attack_family_models.py (which trains one XGBoost+Isolation-
Forest model PER attack family, with capped "borrowed" benign per family),
this pools EVERY 2018 and 2019 frame into one overall benign-vs-attack
dataset - no family split, no benign-ratio capping - since a single
combiner-facing classifier needs one policy, not three.

Same framing as this project's other RL prototypes: a one-step contextual
bandit (numpy MLP Q-network, no torch dependency). State = the 25
TOP_FEATURES for one flow. Action = 0 (benign) / 1 (attack). Reward = +1
correct / -1 incorrect (symmetric), plus an asymmetric variant where
missing a real attack costs more than a false alarm.

Usage:
    python rl_cicids_combined_classifier.py
"""

import json
import pickle
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

import train_attack_family_models as tafm

RNG = np.random.default_rng(42)
TOP_FEATURES = tafm.TOP_FEATURES


def per_day_label_split(day_df):
    """Fixes a real coverage gap in tafm.per_day_split: that function
    picks ONE cutoff per day from the combined timestamps of every attack
    label in that day, so a minority attack type whose entire time window
    falls on one side of that cutoff gets ZERO representation on the
    other side - confirmed for DDOS attack-LOIC-UDP and DoS attacks-
    Slowloris, both 0 training rows across the whole 2018+2019 pool (see
    run notes / CHANGELOG). This computes the 70th-percentile cutoff PER
    LABEL within the day (benign included) instead of once per day, so
    every label with enough rows lands in both train and test. A label
    with <20 rows in this day falls back to an 80/20 row-order split of
    just that label's own rows, same fallback tafm.per_day_split uses for
    a whole day with too few attacks."""
    train_mask = np.zeros(len(day_df), dtype=bool)
    for label in day_df["Label"].unique():
        idx = np.where(day_df["Label"].values == label)[0]
        sub_ts = day_df["Timestamp"].values[idx]
        order = np.argsort(sub_ts)
        idx = idx[order]
        if len(idx) < 20:
            cutoff_pos = int(round(len(idx) * 0.8))
        else:
            cutoff_pos = int(round(len(idx) * 0.7))
        train_mask[idx[:cutoff_pos]] = True
    return train_mask, ~train_mask


# ---------------------------------------------------------------------
# Reward functions (same shape as rl_model_combiner.py / rl_cicids_classifier.py)
# ---------------------------------------------------------------------

def symmetric_reward(action, label):
    return 1.0 if action == label else -1.0


def asymmetric_reward(action, label):
    if action == label:
        return 1.0
    return -2.0 if (label == 1 and action == 0) else -1.0


# Types with real training rows worth boosting (see run notes: DDOS
# attack-LOIC-UDP and DoS attacks-Slowloris have ZERO training rows - the
# per-day 70/30 chronological cutoff pushed their whole time window into
# test - so no reward shaping can help those two; left out on purpose).
TARGET_TYPES = ["Infilteration", "Brute Force -Web", "SQL Injection"]


def targeted_reward(action, label, orig_label):
    """Same asymmetric shape as asymmetric_reward, but with a much larger
    miss penalty (and a bonus for a correct catch) specifically for
    TARGET_TYPES, to push the policy to prioritize not missing them."""
    if orig_label in TARGET_TYPES:
        if action == label:
            return 2.0
        return -6.0 if (label == 1 and action == 0) else -1.0
    return asymmetric_reward(action, label)


# ---------------------------------------------------------------------
# Tiny numpy MLP Q-network (same architecture family as the project's
# other RL scripts)
# ---------------------------------------------------------------------

class QNetwork:
    def __init__(self, n_features, n_hidden=32, n_actions=2, lr=0.02, seed=0):
        rng = np.random.default_rng(seed)
        self.W1 = rng.normal(0, 0.5, size=(n_features, n_hidden))
        self.b1 = np.zeros(n_hidden)
        self.W2 = rng.normal(0, 0.5, size=(n_hidden, n_actions))
        self.b2 = np.zeros(n_actions)
        self.lr = lr

    def forward(self, x):
        z1 = x @ self.W1 + self.b1
        h = np.tanh(z1)
        q = h @ self.W2 + self.b2
        return q, h, z1

    def forward_batch(self, X):
        z1 = X @ self.W1 + self.b1
        h = np.tanh(z1)
        return h @ self.W2 + self.b2

    def act(self, x, epsilon):
        if RNG.random() < epsilon:
            return RNG.integers(0, 2)
        q, _, _ = self.forward(x)
        return int(np.argmax(q))

    def train_step(self, x, action, target):
        q, h, z1 = self.forward(x)
        error = q[action] - target
        d_q = np.zeros_like(q)
        d_q[action] = error
        d_W2 = np.outer(h, d_q)
        d_b2 = d_q
        d_h = d_q @ self.W2.T
        d_z1 = d_h * (1 - np.tanh(z1) ** 2)
        d_W1 = np.outer(x, d_z1)
        d_b1 = d_z1
        self.W2 -= self.lr * d_W2
        self.b2 -= self.lr * d_b2
        self.W1 -= self.lr * d_W1
        self.b1 -= self.lr * d_b1


def train(X_train, y_train, reward_fn, n_steps=200_000, epsilon_start=0.3, epsilon_end=0.02, seed=0):
    net = QNetwork(n_features=X_train.shape[1], seed=seed)
    idx_by_label = {0: np.where(y_train == 0)[0], 1: np.where(y_train == 1)[0]}
    for step in range(n_steps):
        epsilon = epsilon_start + (epsilon_end - epsilon_start) * (step / n_steps)
        label = int(RNG.random() < 0.5)
        i = idx_by_label[label][RNG.integers(0, len(idx_by_label[label]))]
        state = X_train[i]
        action = net.act(state, epsilon)
        r = reward_fn(action, label)
        net.train_step(state, action, r)
    return net


def train_targeted(X_train, y_train, orig_labels_train, n_steps=200_000,
                    epsilon_start=0.3, epsilon_end=0.02, seed=0, target_frac=0.5):
    """Like train(), but within the attack half of each step, with
    probability `target_frac` samples specifically from one of
    TARGET_TYPES (chosen uniformly among the types so Infilteration's
    112k rows don't drown out SQL Injection's 84) instead of uniformly
    from all attack rows - otherwise a rare type would rarely get sampled
    at all regardless of how its reward is shaped."""
    net = QNetwork(n_features=X_train.shape[1], seed=seed)
    idx_benign = np.where(y_train == 0)[0]
    idx_attack = np.where(y_train == 1)[0]
    idx_by_target_type = {
        t: np.where(orig_labels_train == t)[0]
        for t in TARGET_TYPES if np.any(orig_labels_train == t)
    }
    target_type_list = list(idx_by_target_type.keys())
    if not target_type_list:
        raise ValueError("none of TARGET_TYPES have any training rows")

    for step in range(n_steps):
        epsilon = epsilon_start + (epsilon_end - epsilon_start) * (step / n_steps)
        if RNG.random() < 0.5:
            i = idx_benign[RNG.integers(0, len(idx_benign))]
            label = 0
        elif RNG.random() < target_frac:
            t = target_type_list[RNG.integers(0, len(target_type_list))]
            pool = idx_by_target_type[t]
            i = pool[RNG.integers(0, len(pool))]
            label = 1
        else:
            i = idx_attack[RNG.integers(0, len(idx_attack))]
            label = 1
        state = X_train[i]
        action = net.act(state, epsilon)
        r = targeted_reward(action, label, orig_labels_train[i])
        net.train_step(state, action, r)
    return net


def evaluate(net, X_test, y_test):
    preds = np.argmax(net.forward_batch(X_test), axis=1)
    tp = int(np.sum((preds == 1) & (y_test == 1)))
    fp = int(np.sum((preds == 1) & (y_test == 0)))
    tn = int(np.sum((preds == 0) & (y_test == 0)))
    fn = int(np.sum((preds == 0) & (y_test == 1)))
    accuracy = (tp + tn) / len(y_test)
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    specificity = tn / (tn + fp) if (tn + fp) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else float("nan")
    return dict(accuracy=accuracy, precision=precision, recall=recall,
                specificity=specificity, f1=f1, tp=tp, fp=fp, tn=tn, fn=fn), preds


def per_label_recall(test_df, preds, y_test):
    rows = []
    for label in sorted(test_df.loc[y_test == 1, "Label"].unique()):
        mask = (test_df["Label"].values == label)
        n = int(mask.sum())
        if n == 0:
            continue
        rows.append((label, n, float(preds[mask].mean())))
    return rows


def main():
    t0 = time.time()
    print("loading all CIC-IDS2018 day-frames (28 offset windows + 3 full days) ...")
    all_2018_frames = [tafm.load_one_2018_day(tafm.PARTIAL_DIR / n) for n in tafm.PARTIAL_DAYS]
    all_2018_frames += [tafm.load_one_2018_day(tafm.FULL_DIR / n) for n in tafm.FULL_DAYS]
    print(f"  {len(all_2018_frames)} 2018 day-frames loaded")

    print("loading all CIC-DDoS2019 day-frames (18 attack-type files) ...")
    all_2019_frames = tafm.load_ddos2019_sample()
    print(f"  {len(all_2019_frames)} 2019 day-frames loaded")

    print(f"data loaded in {time.time()-t0:.1f}s")

    train_parts, test_parts = [], []
    for day_df in all_2018_frames + all_2019_frames:
        tr, te = per_day_label_split(day_df)
        train_parts.append(day_df[tr])
        test_parts.append(day_df[te])
    train_df = pd.concat(train_parts, ignore_index=True)
    test_df = pd.concat(test_parts, ignore_index=True)

    print(f"\ncombined pool (2018 + 2019, every attack type, no family split): "
          f"train={len(train_df)} test={len(test_df)}")
    print(f"train attack ratio: {train_df['Binary_Label'].mean():.3f}")
    print(f"test attack ratio:  {test_df['Binary_Label'].mean():.3f}")
    all_labels = sorted(pd.concat([train_df, test_df]).loc[
        pd.concat([train_df, test_df])["Binary_Label"] == 1, "Label"].unique())
    print(f"attack types present ({len(all_labels)}): {all_labels}")

    X_train_raw = train_df[TOP_FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0)
    X_train_raw = np.clip(X_train_raw, -1e9, 1e9).astype(np.float64).values
    y_train = train_df["Binary_Label"].values

    X_test_raw = test_df[TOP_FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0)
    X_test_raw = np.clip(X_test_raw, -1e9, 1e9).astype(np.float64).values
    y_test = test_df["Binary_Label"].values

    mean = X_train_raw.mean(axis=0)
    std = X_train_raw.std(axis=0)
    std[std == 0] = 1.0
    X_train = (X_train_raw - mean) / std
    X_test = (X_test_raw - mean) / std

    nets = {}
    for name, reward_fn in [("symmetric (+1/-1)", symmetric_reward),
                             ("asymmetric (miss attack = -2)", asymmetric_reward)]:
        t1 = time.time()
        net = train(X_train, y_train, reward_fn)
        nets[name] = net
        m, preds = evaluate(net, X_test, y_test)
        print(f"\n=== RL bandit - {name} reward === (trained in {time.time()-t1:.1f}s)")
        print(f"accuracy={m['accuracy']:.4f}  precision={m['precision']:.4f}  "
              f"recall={m['recall']:.4f}  specificity={m['specificity']:.4f}  f1={m['f1']:.4f}")
        print(f"confusion matrix: tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']}")
        print("per-attack-label recall (held out):")
        for label, n, recall in per_label_recall(test_df, preds, y_test):
            print(f"  {label:<28} n={n:<8} recall={recall:.3f}")

    # Saved artifact uses the asymmetric-reward net: this project's other
    # RL scripts (rl_model_combiner.py) already establish that as the
    # operationally realistic choice for an IDS (missing an attack costs
    # more than a false alarm), and it also recovered the two
    # zero-train-row types (LOIC-UDP/Slowloris) at meaningfully higher
    # recall than the symmetric net in this same run (see printed tables
    # above) without a materially worse specificity.
    save_net = nets["asymmetric (miss attack = -2)"]
    out_dir = Path(__file__).resolve().parent / "models" / "rl_verdict_classifier"
    out_dir.mkdir(parents=True, exist_ok=True)
    np.savez(out_dir / "weights.npz", W1=save_net.W1, b1=save_net.b1, W2=save_net.W2, b2=save_net.b2)
    np.savez(out_dir / "scaler.npz", mean=mean, std=std)
    with open(out_dir / "top_features.pkl", "wb") as f:
        pickle.dump(TOP_FEATURES, f)

    m, preds = evaluate(save_net, X_test, y_test)
    per_label = per_label_recall(test_df, preds, y_test)
    provenance = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model": "rl_verdict_classifier v2",
        "dataset": "CIC-IDS2018 (28 offset windows + 3 full days) + CIC-DDoS2019 (18 attack-type files), "
                   "pooled, no family split",
        "split": "per-(day, Label) chronological 70/30 (per_day_label_split) - fixes tafm.per_day_split's "
                  "coverage gap where a minority attack type's whole time window could land entirely in "
                  "test (confirmed for DDOS attack-LOIC-UDP and DoS attacks-Slowloris, both 0 train rows "
                  "under the old per-day-only split)",
        "reward": "asymmetric: +1 correct, -1 false alarm, -2 missed attack",
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "overall_metrics_held_out": {k: m[k] for k in ("accuracy", "precision", "recall", "specificity", "f1")},
        "per_attack_label_recall_held_out": [
            {"label": label, "n": n, "recall": recall} for label, n, recall in per_label
        ],
    }
    with open(out_dir / "provenance.json", "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2, default=str)
    print(f"\nsaved rl_verdict_classifier v2 artifacts to {out_dir}/")


if __name__ == "__main__":
    main()
