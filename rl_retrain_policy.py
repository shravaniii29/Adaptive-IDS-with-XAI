"""
A reinforcement-learning policy for the retrain/promote decision that
agents/retraining_agent.py currently makes with a fixed rule
(`_should_accept`: accept iff recall_delta >= -0.05 and f1_delta >= -0.03,
measured only on a held-out split of the candidate's own training data).

That rule has two blind spots this project's own history has hit
repeatedly:
1. It never checks feature-importance concentration (the shortcut_warning
   metric already computed elsewhere in this repo) - a candidate that
   reproduces a Min-Pkt-Size-style shortcut can still pass if its
   recall/F1 happen to look similar to the current model's.
2. It's held-out-only. This project's headline finding across three
   separate investigations is that held-out accuracy does not predict
   live performance - gating promotion on held-out alone reproduces
   exactly the blind spot that caused the original 14.7%-specificity
   deployed-model bug.

WHY THIS IS FRAMED AS A CONTEXTUAL BANDIT, NOT A MULTI-STEP MDP: each
retrain/promote decision in this project has been a largely independent
event (there's no meaningful "next state" that depends on this decision
the way a game's next move would) - so this is one-step reinforcement
learning: observe a state, take one of 3 actions, get one reward. Framing
it as a deeper MDP would be dressing up a bandit problem, not solving a
harder one.

WHY A SYNTHETIC TRAINING ENVIRONMENT: this project has only ~10 real,
precisely-sourced retrain/promote episodes on record (see
HISTORICAL_EPISODES below, each cited to CHANGELOG.md or a provenance.json
file) - nowhere near enough to train a policy from scratch by trial and
error. Those 10 are used here as a BACKTEST/VALIDATION set instead: the
policy is trained on a synthetic simulator whose generative rules are
calibrated to reproduce the qualitative patterns those 10 real episodes
already show (see `true_live_outcome()` below for exactly which rules
came from which finding), then evaluated against the real episodes to see
whether it would have made the same call this project's own experience
says was right.

This is a decision-support prototype, not a promotion mechanism: like
retraining_agent.py itself, "promote" here means "recommend for human
review," never an automatic overwrite of models/.

Usage:
    python rl_retrain_policy.py
"""

import numpy as np

RNG = np.random.default_rng(42)

# ---------------------------------------------------------------------
# State / action / reward spec
# ---------------------------------------------------------------------
# State (5 features, each roughly 0-1):
#   0. held_out_score       - the candidate's headline held-out metric
#                              (recall where available, else accuracy)
#   1. held_out_secondary    - a second held-out metric (precision/acc)
#   2. shortcut_score        - top single feature's importance (the
#                              existing shortcut_warning metric, as a
#                              continuous value instead of a bool)
#   3. benign_ratio           - fraction of the training set that's benign
#   4. drift_ratio            - DriftAgent's rolling ADWIN-flag ratio that
#                              triggered this retrain (not recorded for any
#                              real historical episode - imputed at 0.5 for
#                              all of them; only meaningfully varied during
#                              synthetic training)
#
# Actions: 0 = reject, 1 = hold as candidate (save for manual review,
#          don't promote), 2 = promote (recommend for human sign-off)
#
# Reward is only computable where the TRUE live (recall, specificity) is
# known - the whole point of this exercise. In training that comes from
# the synthetic simulator's hidden ground truth; in the backtest it comes
# from this project's own real live-test numbers.

ACTIONS = ("reject", "hold_as_candidate", "promote")


def reward_fn(action, live_recall, live_specificity):
    """Rewards a BALANCED outcome and penalizes either degenerate extreme
    this project has actually hit (flags-everything: recall~1,
    specificity~0; flags-nothing: recall~0, specificity~1) - not just
    high recall or high specificity in isolation.  `promote` is scored
    against the true outcome; `reject`/`hold` are scored against the
    opportunity cost of not having deployed a model that would in fact
    have been good, tempered by a smaller downside than a bad promotion."""
    balance = 1.0 - abs(live_recall - live_specificity) - max(0.0, 0.3 - min(live_recall, live_specificity))
    balance = float(np.clip(balance, -1.0, 1.0))

    if action == 2:  # promote
        return balance
    if action == 1:  # hold - safe, but forfeits most of a genuinely good outcome
        return 0.35 * balance - 0.05
    # reject - forfeits the outcome entirely, but avoids the downside of a bad one
    return -0.5 * balance - 0.05


# ---------------------------------------------------------------------
# Real historical episodes - each state value is sourced from either
# CHANGELOG.md or a models/<name>/provenance.json file, cited inline.
# `None` marks a value this project's own records don't give cleanly;
# imputed with the population mean at feature time (see `featurize`).
# `hindsight_action` is this project's own eventual real-world call,
# used only for backtest comparison, never for training.
# ---------------------------------------------------------------------

HISTORICAL_EPISODES = [
    dict(
        name="deployed_v2 (full-data + threshold-formula retrain)",
        held_out_score=0.9186, held_out_secondary=0.8767,  # provenance.json hybrid recall/precision
        shortcut_score=0.409,  # Bwd Seg Size Avg, provenance.json feature_importances[0]
        benign_ratio=None,  # not tracked for this retrain
        live_recall=0.939, live_specificity=0.118,  # simulation_results_deployed_v2/summary.json (mean recall across 5 attack scenarios; benign baseline)
        hindsight_action=2,  # promoted to models/ (models/deployed_v1_backup/ created alongside)
    ),
    dict(
        name="classifier_comparison: XGBoost candidate",
        held_out_score=0.921, held_out_secondary=None,  # provenance.json (accuracy only)
        shortcut_score=0.589,  # Min Pkt Size, CHANGELOG.md 2026-08-26 entry
        benign_ratio=None,
        live_recall=0.027, live_specificity=0.745,  # classifier_comparison_live_test/summary.json
        hindsight_action=0,  # never promoted - live result confirmed the shortcut
    ),
    dict(
        name="classifier_comparison: Random Forest candidate",
        held_out_score=0.916, held_out_secondary=None,
        shortcut_score=0.200,  # CHANGELOG.md
        benign_ratio=None,
        live_recall=0.167, live_specificity=0.945,  # classifier_comparison_live_test/summary.json
        hindsight_action=1,  # better-generalizing than XGBoost, but recall too low to replace the deployed hybrid outright
    ),
    dict(
        name="family_raw_flood v1 (benign-starved, 2.2% benign)",
        held_out_score=None, held_out_secondary=None,
        shortcut_score=None,
        benign_ratio=0.022,  # CHANGELOG.md "benign-starvation" entry
        live_recall=1.00, live_specificity=0.00,  # degenerate - flags everything
        hindsight_action=0,
    ),
    dict(
        name="family_reflection v1 (benign entirely skipped, ~5% benign)",
        held_out_score=None, held_out_secondary=None,
        shortcut_score=None,
        benign_ratio=0.05,
        live_recall=0.421, live_specificity=0.400,  # CHANGELOG.md 2026-08-26 "Add 3 attack-family models"
        hindsight_action=1,  # narrow/weak but real signal, not degenerate - kept for further work
    ),
    dict(
        name="family_connection v1 (72.8% benign, pre ratio-cap)",
        held_out_score=None, held_out_secondary=None,
        shortcut_score=None,
        benign_ratio=0.728,
        live_recall=0.882, live_specificity=0.300,  # CHANGELOG.md
        hindsight_action=1,  # strong recall, but specificity "flagged as still worth investigating, not solved"
    ),
    dict(
        name="raw_flood/reflection ratio-OVERCORRECTION (unconditional borrowed benign, ~95% benign)",
        held_out_score=None, held_out_secondary=None,
        shortcut_score=None,
        benign_ratio=0.954,
        live_recall=0.004, live_specificity=1.00,  # CHANGELOG.md - opposite degenerate failure
        hindsight_action=0,
    ),
    dict(
        name="family_raw_flood FINAL (2:1 benign:attack ratio cap)",
        held_out_score=0.996, held_out_secondary=0.858,  # provenance.json hybrid recall/precision
        shortcut_score=0.297,  # Pkt Len Max
        benign_ratio=0.667,
        live_recall=0.109, live_specificity=0.983,  # CHANGELOG.md, specialty-aware scoring
        hindsight_action=2,  # wired into the live experimental panel
    ),
    dict(
        name="family_reflection FINAL (2:1 ratio cap, shortcut_warning=True)",
        held_out_score=0.9998, held_out_secondary=0.869,
        shortcut_score=0.584,  # Pkt Size Avg - shortcut_warning=True, but this one's LEGITIMATE (see markdown)
        benign_ratio=0.667,
        live_recall=0.109, live_specificity=0.983,
        hindsight_action=2,  # promoted to the live experimental panel DESPITE shortcut_warning
    ),
    dict(
        name="family_connection FINAL (2:1 ratio cap)",
        held_out_score=0.866, held_out_secondary=0.818,
        shortcut_score=0.230,  # Bwd Seg Size Avg
        benign_ratio=0.667,
        live_recall=0.789, live_specificity=0.263,  # CHANGELOG.md, specialty-aware scoring
        hindsight_action=2,
    ),
    dict(
        name="LSNM2024 packet-level: temporal XGBoost",
        held_out_score=0.999, held_out_secondary=None,
        shortcut_score=0.956,  # hist_std_delta_t_us - CHANGELOG.md
        benign_ratio=None,
        live_recall=0.999, live_specificity=0.56,  # live_test_packet_models.py result, CHANGELOG.md
        hindsight_action=1,  # useful recall, but the shortcut is a real, flagged concern - not promoted yet
    ),
    dict(
        name="LSNM2024 packet-level: CNN+LSTM",
        held_out_score=0.999, held_out_secondary=None,
        shortcut_score=None,  # "no dominant [feature] ... a real, uneven generalization signal" - CHANGELOG.md
        benign_ratio=None,
        live_recall=0.63, live_specificity=None,  # mean of 94-99.9%/57.7%/0.4% recall across scenarios; specificity not reported
        hindsight_action=1,  # wildly uneven (0.4% on UDP flood) despite near-perfect held-out - not ready
    ),
]

_FEATURE_KEYS = ["held_out_score", "held_out_secondary", "shortcut_score", "benign_ratio", "drift_ratio"]
_POPULATION_MEANS = {
    "held_out_score": 0.85, "held_out_secondary": 0.80,
    "shortcut_score": 0.40, "benign_ratio": 0.50, "drift_ratio": 0.50,
}


def featurize(episode):
    """Historical episodes don't track drift_ratio at all (imputed at
    0.5 for all of them) and several don't track shortcut_score/
    benign_ratio/held_out metrics either - imputed with a population
    mean, same treatment `_should_accept` implicitly gives anything it
    doesn't check today (i.e. none at all)."""
    values = []
    for key in _FEATURE_KEYS:
        v = episode.get(key)
        values.append(_POPULATION_MEANS[key] if v is None else float(v))
    return np.array(values, dtype=np.float64)


# ---------------------------------------------------------------------
# Synthetic training environment - calibrated to reproduce the
# qualitative rules the real episodes above already demonstrate.
# ---------------------------------------------------------------------

def sample_synthetic_episode():
    """Samples a state and a HIDDEN ground-truth (live_recall,
    live_specificity) the policy never sees directly - only through the
    reward it gets for the action it actually took, exactly like a real
    retrain decision where you don't find out the live numbers unless
    you promote (or run a live test independent of promoting)."""
    benign_ratio = float(np.clip(RNG.normal(0.6, 0.25), 0.0, 1.0))
    drift_ratio = float(RNG.uniform(0, 1))
    held_out_score = float(np.clip(RNG.normal(0.9, 0.08), 0.4, 1.0))
    held_out_secondary = float(np.clip(held_out_score + RNG.normal(0, 0.05), 0.3, 1.0))
    shortcut_score = float(np.clip(RNG.beta(2, 3), 0.0, 1.0))
    # Unobserved latent: sometimes a high shortcut score is fine, because
    # the underlying attack family genuinely has one dominant
    # discriminating feature (family_reflection's real case) - the policy
    # can't see this directly, same as in reality, and has to hedge.
    legitimate_narrow_task = RNG.random() < 0.35

    state = dict(held_out_score=held_out_score, held_out_secondary=held_out_secondary,
                 shortcut_score=shortcut_score, benign_ratio=benign_ratio, drift_ratio=drift_ratio)

    live_recall, live_specificity = true_live_outcome(state, legitimate_narrow_task)
    return state, live_recall, live_specificity


def true_live_outcome(state, legitimate_narrow_task):
    """Rule 1 (benign-starvation / overcorrection, both real episodes
    above): benign_ratio far outside ~[0.55, 0.75] drives one of
    recall/specificity toward a degenerate extreme.
    Rule 2 (classifier_comparison XGBoost vs family_reflection, real
    episodes above): a high shortcut_score predicts poor live
    generalization UNLESS the task is a legitimate narrow specialist -
    an unobserved factor, so the policy faces genuine irreducible
    uncertainty here, same as this project's own experience.
    Rule 3 (this project's headline finding, every Part 5/9/10
    investigation): held-out metrics correlate only weakly with live
    outcome - deliberately down-weighted here relative to rules 1-2."""
    ratio = state["benign_ratio"]
    if ratio < 0.30:
        base_recall, base_specificity = 0.95, 0.05  # starved - flags everything
    elif ratio > 0.90:
        base_recall, base_specificity = 0.05, 0.95  # overcorrected - flags nothing
    else:
        base_recall, base_specificity = 0.75, 0.55  # healthy range - a real, working model

    shortcut_penalty = 0.0 if legitimate_narrow_task else state["shortcut_score"] * 0.6
    base_recall = float(np.clip(base_recall + 0.05 * (state["held_out_score"] - 0.85), 0, 1))
    base_specificity = float(np.clip(base_specificity - shortcut_penalty, 0, 1))

    noise = RNG.normal(0, 0.05, size=2)
    live_recall = float(np.clip(base_recall + noise[0], 0, 1))
    live_specificity = float(np.clip(base_specificity + noise[1], 0, 1))
    return live_recall, live_specificity


# ---------------------------------------------------------------------
# Tiny numpy MLP Q-network (no torch dependency - kept minimal and
# easy to verify) trained via one-step Q-learning / contextual-bandit
# updates: Q(s, a_taken) is pushed toward the observed reward.
# ---------------------------------------------------------------------

class QNetwork:
    def __init__(self, n_features=5, n_hidden=16, n_actions=3, lr=0.02, seed=0):
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

    def act(self, x, epsilon):
        if RNG.random() < epsilon:
            return RNG.integers(0, 3)
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
        return 0.5 * error ** 2


def train(n_episodes=20_000, epsilon_start=0.3, epsilon_end=0.02):
    net = QNetwork()
    reward_history = []
    for i in range(n_episodes):
        epsilon = epsilon_start + (epsilon_end - epsilon_start) * (i / n_episodes)
        state_dict, live_recall, live_specificity = sample_synthetic_episode()
        x = featurize(state_dict)
        action = net.act(x, epsilon)
        r = reward_fn(action, live_recall, live_specificity)
        net.train_step(x, action, r)
        reward_history.append(r)
    return net, reward_history


def backtest(net, episodes=HISTORICAL_EPISODES):
    rows = []
    correct = 0
    for ep in episodes:
        x = featurize(ep)
        q, _, _ = net.forward(x)
        policy_action = int(np.argmax(q))

        # Current hardcoded rule for comparison (agents/retraining_agent.py
        # ::_should_accept): only 2 outcomes (reject/accept), and it only
        # ever sees recall/F1 deltas vs the CURRENT model - which none of
        # these episodes cleanly recorded, so approximate with held_out_score
        # vs a neutral 0.85 baseline (same approximation the historical
        # entries above use elsewhere).
        held_out = ep.get("held_out_score")
        current_rule_action = 2 if (held_out is not None and held_out - 0.85 >= -0.05) else 0

        match = policy_action == ep["hindsight_action"]
        correct += match
        rows.append(dict(
            name=ep["name"],
            live_recall=ep["live_recall"], live_specificity=ep["live_specificity"],
            hindsight_action=ACTIONS[ep["hindsight_action"]],
            policy_action=ACTIONS[policy_action],
            current_rule_action=ACTIONS[current_rule_action],
            policy_matches_hindsight=match,
        ))
    return rows, correct / len(episodes)


def main():
    net, reward_history = train()
    window = 500
    smoothed = np.convolve(reward_history, np.ones(window) / window, mode="valid")
    print(f"mean reward, first {window} episodes: {np.mean(reward_history[:window]):.3f}")
    print(f"mean reward, last {window} episodes:  {np.mean(reward_history[-window:]):.3f}")

    rows, accuracy = backtest(net)
    print(f"\nbacktest vs {len(rows)} real historical episodes - policy matches this project's own hindsight call: {accuracy:.0%}\n")
    header = f"{'episode':<62}{'live R/S':<14}{'hindsight':<14}{'policy':<14}{'current rule':<14}"
    print(header)
    print("-" * len(header))
    for row in rows:
        rs = f"{row['live_recall']:.2f}/{row['live_specificity'] if row['live_specificity'] is not None else float('nan'):.2f}"
        print(f"{row['name']:<62}{rs:<14}{row['hindsight_action']:<14}{row['policy_action']:<14}{row['current_rule_action']:<14}")


if __name__ == "__main__":
    main()
