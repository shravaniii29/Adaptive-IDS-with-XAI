"""
Serving module for the 3 EXPERIMENTAL models shown on the dashboard,
separate from the deployed hybrid model (detection/predictor.py).

Feature computation here must exactly match the definitions used by
train_experimental_models.py (which mirrors train_three_way_multiday.py):
  - Flow Duration is in MICROSECONDS in training data; Flow.duration is
    in seconds - multiply by 1e6.
  - Min Pkt Size (Fwd Pkt Len Min) is CICFlowMeter's forward PAYLOAD
    length, not full frame length - uses Flow.forward_payload_lengths,
    not forward_packet_lengths.
  - Avg Pkt Size = TotLen Fwd Pkts / Tot Fwd Pkts exactly (not
    total_bytes / packet_count).
  - Zero-duration flows return 0 for rate features (Flow.bytes_per_second
    / packets_per_second already do this), matching how training rows
    with inf/NaN were dropped rather than propagated.

A prediction failure in any single variant must never take down the
others or the caller - every variant is wrapped in its own try/except
and returns an error stub on failure instead of raising.
"""

import os
import pickle
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier  # noqa: F401 - ensures class is registered before unpickling

from detection import fast_isolation_forest
from detection.experimental_history import RollingHistoryStore
from feature_extraction.feature_extractor import (
    extract_features as extract_deployed_features,
    safe_max,
    safe_mean,
    safe_std,
)

MICROSECONDS_PER_SECOND = 1_000_000

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Overridable so a test run can point at e.g. models/experimental_2019
# (a candidate artifact set under review) without touching the default
# deployed-in-place artifacts under models/experimental.
MODELS_DIR = Path(os.environ.get("EXPERIMENTAL_MODELS_DIR", PROJECT_ROOT / "models" / "experimental"))

# Extra single-flow classifier candidates from classifier_comparison.ipynb -
# same 8 BASE_FEATURES as variant 1, different algorithms (Random Forest,
# HistGradientBoosting), scored alongside the 3 named variants purely for
# live-test comparison. Kept separate from MODELS_DIR since these aren't
# part of the promoted variant1/2/3 set.
CANDIDATE_MODELS_DIR = Path(os.environ.get("CANDIDATE_MODELS_DIR", PROJECT_ROOT / "models" / "classifier_comparison"))
CANDIDATE_NAMES = ["xgboost", "random_forest", "histgradientboosting"]

BASE_FEATURES = [
    "Flow Duration", "Tot Fwd Pkts", "TotLen Fwd Pkts",
    "Flow Byts/s", "Flow Pkts/s", "Avg Pkt Size", "Min Pkt Size", "Protocol",
]

DISCLAIMER = (
    "Experimental research models, not the deployed detector. Trained on a "
    "limited CIC-IDS2018 sample with known train/serve feature-definition "
    "caveats and a disclosed reliance on Min Pkt Size for variant 1. See "
    "models/experimental/provenance.json for full details."
)

history_store = RollingHistoryStore()


# =====================================================
# Load artifacts (variants 1 and 2 are required; variant
# 3 degrades gracefully if torch or its artifacts are
# unavailable, per the plan's lazy-import requirement)
# =====================================================

def _force_single_threaded(obj):
    """Trained IsolationForest/RandomForest models were saved with
    n_jobs=-1 (parallelize across all CPU cores) - sensible for training
    on millions of rows, catastrophic for live serving: joblib's
    multiprocessing backend spins up a fresh worker POOL for every single
    decision_function()/predict() call, since there's never a persistent
    Parallel context here to reuse one across calls. Profiling one
    detect() call found IsolationForest.decision_function alone taking
    ~150-780ms - almost entirely multiprocessing pool spawn/teardown
    overhead for a single-row prediction that has zero use for
    parallelism. n_jobs is a live attribute (not baked into the fitted
    tree structure), so this is safe to override post-load without
    retraining - no-op for anything without the attribute (thresholds,
    feature-name lists, scalers, ...)."""
    if hasattr(obj, "n_jobs"):
        obj.n_jobs = 1
    return obj


def _load_pickle(name):
    with open(MODELS_DIR / name, "rb") as f:
        return _force_single_threaded(pickle.load(f))


def _load_pickle_from(directory, name):
    with open(directory / name, "rb") as f:
        return _force_single_threaded(pickle.load(f))


_variant1_ready = False
_variant2_ready = False
_variant3_ready = False

try:
    xgb1 = _load_pickle("xgb_variant1_single_flow.pkl")
    threshold1 = _load_pickle("threshold_variant1.pkl")
    features1 = _load_pickle("features_variant1.pkl")
    _variant1_ready = True
except Exception as exc:  # noqa: BLE001 - deliberately broad, this is a degrade-not-crash path
    _variant1_load_error = str(exc)

try:
    xgb2 = _load_pickle("xgb_variant2_temporal.pkl")
    threshold2 = _load_pickle("threshold_variant2.pkl")
    features2 = _load_pickle("features_variant2.pkl")
    _variant2_ready = True
except Exception as exc:  # noqa: BLE001
    _variant2_load_error = str(exc)

# Attack-family-specific hybrid models from train_attack_family_models.py -
# same 25-feature schema and XGBoost+IsolationForest architecture as the
# deployed model (models/), just trained on a narrower per-family label
# subset. Scored via extract_deployed_features (25 features), not the
# 8-feature extract_experimental_features used by variants 1-3.
# Overridable base dir so a prior version of the 3 family models (e.g. a
# git-recovered pre-fix backup) can be live-tested for comparison without
# touching the current models/family_*/ artifacts.
FAMILY_MODELS_BASE_DIR = Path(os.environ.get("FAMILY_MODELS_BASE_DIR", PROJECT_ROOT / "models"))
FAMILY_MODEL_DIRS = {
    "raw_flood": FAMILY_MODELS_BASE_DIR / "family_raw_flood",
    "reflection": FAMILY_MODELS_BASE_DIR / "family_reflection",
    "connection_application_layer": FAMILY_MODELS_BASE_DIR / "family_connection",
}
family_models = {}
_family_load_errors = {}

for _fname, _fdir in FAMILY_MODEL_DIRS.items():
    try:
        family_models[_fname] = {
            "xgb": _load_pickle_from(_fdir, "xgb_model.pkl"),
            "isolation": _load_pickle_from(_fdir, "isolation_forest.pkl"),
            "scaler": _load_pickle_from(_fdir, "scaler.pkl"),
            "threshold": _load_pickle_from(_fdir, "threshold.pkl"),
            "top_features": _load_pickle_from(_fdir, "top_features.pkl"),
        }
    except Exception as exc:  # noqa: BLE001 - a missing family model just isn't available, not fatal
        _family_load_errors[_fname] = str(exc)

# RL verdict classifier (rl_cicids_combined_classifier.py) - a numpy
# contextual-bandit MLP trained on the full pooled CIC-IDS2018 +
# CIC-DDoS2019 dataset (same 25-feature TOP_FEATURES schema as the
# deployed model / family models), scored the same way as the family
# models: via extract_deployed_features, not the 8-feature experimental set.
RL_VERDICT_DIR = Path(os.environ.get("RL_VERDICT_MODEL_DIR", PROJECT_ROOT / "models" / "rl_verdict_classifier"))
_rl_verdict_ready = False

try:
    _rl_weights = np.load(RL_VERDICT_DIR / "weights.npz")
    _rl_scaler = np.load(RL_VERDICT_DIR / "scaler.npz")
    rl_W1, rl_b1, rl_W2, rl_b2 = _rl_weights["W1"], _rl_weights["b1"], _rl_weights["W2"], _rl_weights["b2"]
    rl_mean, rl_std = _rl_scaler["mean"], _rl_scaler["std"]
    rl_top_features = _load_pickle_from(RL_VERDICT_DIR, "top_features.pkl")
    _rl_verdict_ready = True
except Exception as exc:  # noqa: BLE001
    _rl_verdict_load_error = str(exc)

# Temporal25 candidate (train_temporal25_candidate.py) - the deployed
# model's own 25-feature TOP_FEATURES schema PLUS cross-flow temporal/
# rate features (reuses the SAME history_store variant2 already
# populates - grouped by (dst_port, protocol), so no separate tracking
# needed). Tests whether the near-zero HTTP-flood/port-scan recall every
# other 25-feature model shows live is a feature-engineering gap (no
# model on the plain 25-feature schema can see repetition/rate across
# flows) rather than a training-data or pipeline problem. XGB-only, not
# hybrid-with-isolation-forest: the trained hybrid combination degenerated
# to the same "flags nearly everything" pattern this project has hit
# before (held-out precision 0.8%), so only the well-behaved XGB
# component (49.3% held-out recall, 87.7% precision) is served live.
TEMPORAL25_DIR = Path(os.environ.get("TEMPORAL25_MODEL_DIR", PROJECT_ROOT / "models" / "temporal25_candidate"))
_temporal25_ready = False

try:
    temporal25_xgb = _load_pickle_from(TEMPORAL25_DIR, "xgb_model.pkl")
    temporal25_threshold = _load_pickle_from(TEMPORAL25_DIR, "threshold.pkl")
    temporal25_feature_cols = _load_pickle_from(TEMPORAL25_DIR, "feature_cols.pkl")
    temporal25_hist_cols = _load_pickle_from(TEMPORAL25_DIR, "hist_cols.pkl")
    _temporal25_ready = True
except Exception as exc:  # noqa: BLE001
    _temporal25_load_error = str(exc)


def _predict_temporal25(flow, dst_port, protocol):
    if not _temporal25_ready:
        return {"available": False, "error": _temporal25_load_error}
    try:
        features_25 = extract_deployed_features(flow)
        hist_features = history_store.get_temporal_features(dst_port, protocol)
        combined = {**features_25, **{c: hist_features[c] for c in temporal25_hist_cols}}
        row = pd.DataFrame([[combined[f] for f in temporal25_feature_cols]], columns=temporal25_feature_cols)
        probability = float(temporal25_xgb.predict_proba(row)[0][1])
        return {
            "available": True,
            "label": "XGBoost (25-feature + temporal history)",
            "probability": probability,
            "prediction": int(probability >= temporal25_threshold),
            "threshold": temporal25_threshold,
        }
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


# V8 (the paper's validated final baseline, review-integration branch,
# v8_training/models_v8/) - its own independently mutual-info-selected
# 25-feature set, 17 of which overlap by name with the deployed model's
# TOP_FEATURES and 8 of which don't (Init Fwd Win Byts, Dst Port,
# Fwd Pkt Len Mean/Max, Fwd Seg Size Avg, Pkt Len Std/Var, Bwd Pkts/s -
# confirmed by diffing top_features_v8.pkl against TOP_FEATURES directly,
# not assumed). Same XGBoost + IsolationForest OR-fusion architecture as
# the deployed model and the family models, just a different feature
# subset/order and its own scaler/threshold. Loaded with joblib (not
# pickle.load, which V8's own predictor_v8.py documents as unable to
# traverse the joblib-specific nested pickle sub-stream on its
# IsolationForest/scaler artifacts) and re-scored through this project's
# fast_isolation_forest for the same determinism/speed fix already
# applied to every other model in this harness - V8's own predictor_v8.py
# calls sklearn's IsolationForest.predict()/decision_function() directly,
# which would silently reintroduce the joblib-parallel non-determinism
# this session already root-caused for the deployed model.
V8_MODELS_DIR = Path(os.environ.get("V8_MODELS_DIR", PROJECT_ROOT / "models" / "v8_reference"))
_v8_ready = False

try:
    v8_xgb = _force_single_threaded(joblib.load(V8_MODELS_DIR / "xgb_model_v8.pkl"))
    v8_isolation = _force_single_threaded(joblib.load(V8_MODELS_DIR / "isolation_forest_v8.pkl"))
    v8_scaler = joblib.load(V8_MODELS_DIR / "scaler_v8.pkl")
    v8_threshold = joblib.load(V8_MODELS_DIR / "threshold_v8.pkl")
    v8_top_features = list(joblib.load(V8_MODELS_DIR / "top_features_v8.pkl"))
    _v8_ready = True
except Exception as exc:  # noqa: BLE001
    _v8_load_error = str(exc)


def _extract_v8_features(flow, features_25, dst_port):
    """The 8 V8-only features not already in features_25 (the deployed
    model's 25-feature dict) - each mirrors an existing same-direction/
    combined-direction formula already computed for the deployed model,
    per v8_training's own extractor-compatibility notes."""
    forward_lengths = flow.forward_packet_lengths
    backward_pkt_count = len(flow.backward_packet_lengths)
    duration = float(flow.duration)
    backward_packets_per_second = (backward_pkt_count / duration) if duration > 0 else 0.0

    return {
        **features_25,
        "Init Fwd Win Byts": float(flow.init_fwd_window_bytes) if flow.init_fwd_window_bytes is not None else 0.0,
        "Dst Port": float(dst_port),
        "Fwd Pkt Len Mean": safe_mean(forward_lengths),
        "Fwd Pkt Len Max": safe_max(forward_lengths),
        "Fwd Seg Size Avg": safe_mean(forward_lengths),
        "Pkt Len Std": safe_std(flow.packet_lengths),
        "Pkt Len Var": float(np.var(flow.packet_lengths)) if flow.packet_lengths else 0.0,
        "Bwd Pkts/s": backward_packets_per_second,
    }


def _predict_v8(flow, dst_port):
    """Scores the paper's validated V8 baseline against the same live
    flow every other model in this harness sees - mirrors
    _predict_family_models' scale -> XGBoost -> Isolation Forest ->
    OR-combine structure, parameterized for V8's own feature set/order."""
    if not _v8_ready:
        return {"available": False, "error": _v8_load_error}
    try:
        features_25 = extract_deployed_features(flow)
        features_v8 = _extract_v8_features(flow, features_25, dst_port)
        row = pd.DataFrame([[features_v8[f] for f in v8_top_features]], columns=v8_top_features)
        scaled = v8_scaler.transform(row)

        xgb_probability = float(v8_xgb.predict_proba(row)[0][1])
        xgb_prediction = int(xgb_probability >= v8_threshold)
        isolation_prediction = int(fast_isolation_forest.predict(v8_isolation, scaled)[0] == -1)
        hybrid_prediction = int(xgb_prediction == 1 or isolation_prediction == 1)

        return {
            "available": True,
            "label": "V8 (paper-validated baseline)",
            "probability": xgb_probability,
            "prediction": hybrid_prediction,
            "threshold": float(v8_threshold),
        }
    except Exception as exc:  # noqa: BLE001 - one bad model must never affect the others
        return {"available": False, "error": str(exc)}


candidate_models = {}
candidate_thresholds = {}
candidate_features = None
_candidate_load_errors = {}

try:
    candidate_features = _load_pickle_from(CANDIDATE_MODELS_DIR, "features.pkl")
except Exception as exc:  # noqa: BLE001
    _candidate_load_errors["_common"] = str(exc)

if candidate_features is not None:
    for cname in CANDIDATE_NAMES:
        try:
            candidate_models[cname] = _load_pickle_from(CANDIDATE_MODELS_DIR, f"model_{cname}.pkl")
            candidate_thresholds[cname] = _load_pickle_from(CANDIDATE_MODELS_DIR, f"threshold_{cname}.pkl")
        except Exception as exc:  # noqa: BLE001 - a missing candidate (e.g. one that failed to train) just isn't available, not fatal
            _candidate_load_errors[cname] = str(exc)

try:
    import torch
    import torch.nn as nn

    torch.set_num_threads(1)

    class CNN_LSTM(nn.Module):
        def __init__(self, n_features=8, seq_len=10):
            super().__init__()
            self.conv1 = nn.Conv1d(in_channels=n_features, out_channels=32, kernel_size=3, padding=1)
            self.relu = nn.ReLU()
            self.lstm = nn.LSTM(input_size=32, hidden_size=64, batch_first=True)
            self.fc = nn.Linear(64, 1)

        def forward(self, x):
            x = x.permute(0, 2, 1)
            x = self.relu(self.conv1(x))
            x = x.permute(0, 2, 1)
            _, (h, _) = self.lstm(x)
            return self.fc(h.squeeze(0))

    cnn_lstm = CNN_LSTM(n_features=len(BASE_FEATURES))
    cnn_lstm.load_state_dict(torch.load(MODELS_DIR / "cnn_lstm_variant3.pt", map_location="cpu"))
    cnn_lstm.eval()
    threshold3 = _load_pickle("threshold_variant3.pkl")
    scaler3 = _load_pickle("scaler_variant3.pkl")
    _variant3_ready = True
except Exception as exc:  # noqa: BLE001
    _variant3_load_error = str(exc)


# =====================================================
# Feature computation - see module docstring for the
# exact train/serve parity requirements this implements
# =====================================================

def extract_experimental_features(flow):

    forward_payloads = flow.forward_payload_lengths

    tot_fwd_pkts = len(forward_payloads)
    # CICFlowMeter's TotLen Fwd Pkts sums PAYLOAD length, not full frame
    # length - confirmed against real training rows, where the vast
    # majority of attack flows (single SYN/ACK-style packets with no
    # payload) have TotLen Fwd Pkts == 0, which full-frame length never
    # would. Using forward_packet_lengths here inflated TotLen/Avg Pkt
    # Size by fixed per-packet header overhead relative to what the
    # model was trained on.
    totlen_fwd_pkts = float(np.sum(forward_payloads)) if forward_payloads else 0.0
    avg_pkt_size = totlen_fwd_pkts / tot_fwd_pkts if tot_fwd_pkts > 0 else 0.0
    min_pkt_size = float(np.min(forward_payloads)) if forward_payloads else 0.0

    return {
        "Flow Duration": float(flow.duration) * MICROSECONDS_PER_SECOND,
        "Tot Fwd Pkts": float(tot_fwd_pkts),
        "TotLen Fwd Pkts": totlen_fwd_pkts,
        "Flow Byts/s": float(flow.bytes_per_second),
        "Flow Pkts/s": float(flow.packets_per_second),
        "Avg Pkt Size": avg_pkt_size,
        "Min Pkt Size": min_pkt_size,
        "Protocol": float(flow.protocol) if flow.protocol is not None else 0.0,
    }


# =====================================================
# Per-variant prediction
# =====================================================

def _predict_variant1(features):
    if not _variant1_ready:
        return {"available": False, "error": _variant1_load_error}

    row = pd.DataFrame([[features[f] for f in features1]], columns=features1)
    probability = float(xgb1.predict_proba(row)[0][1])
    return {
        "available": True,
        "label": "XGBoost (single-flow)",
        "probability": probability,
        "prediction": int(probability >= threshold1),
        "threshold": threshold1,
    }


def _predict_variant2(features, dst_port, protocol):
    if not _variant2_ready:
        return {"available": False, "error": _variant2_load_error}

    hist_features = history_store.get_temporal_features(dst_port, protocol)
    combined = {**features, **hist_features}
    row = pd.DataFrame([[combined[f] for f in features2]], columns=features2)
    probability = float(xgb2.predict_proba(row)[0][1])
    return {
        "available": True,
        "label": "XGBoost (single-flow + temporal history)",
        "probability": probability,
        "prediction": int(probability >= threshold2),
        "threshold": threshold2,
    }


def _predict_variant3(features, dst_port, protocol):
    if not _variant3_ready:
        return {"available": False, "error": _variant3_load_error}

    try:
        raw_sequence = history_store.get_raw_sequence(dst_port, protocol, features, BASE_FEATURES)
        n_feat = len(BASE_FEATURES)
        # Scale AFTER padding - the training scaler was fit on already-
        # padded arrays, so zero-padding here must go through the same
        # transform, not be left as literal zeros.
        scaled = scaler3.transform(raw_sequence.reshape(-1, n_feat)).reshape(1, 10, n_feat)

        with torch.inference_mode():
            logits = cnn_lstm(torch.FloatTensor(scaled))
            probability = float(torch.sigmoid(logits).item())

        return {
            "available": True,
            "label": "CNN+LSTM (raw sequence)",
            "probability": probability,
            "prediction": int(probability >= threshold3),
            "threshold": threshold3,
        }
    except Exception as exc:  # noqa: BLE001 - never let variant 3 take down the others
        return {"available": False, "error": str(exc)}


def _predict_candidates(features):
    """Scores the classifier_comparison.ipynb candidates (Random Forest,
    HistGradientBoosting, and a reference XGBoost) using the exact same
    single-flow features as variant 1 - they share BASE_FEATURES exactly.
    Purely for live-test comparison; never wired into hybrid_prediction."""
    result = {}
    for cname in CANDIDATE_NAMES:
        if cname not in candidate_models:
            result[cname] = {"available": False, "error": _candidate_load_errors.get(cname, "not loaded")}
            continue
        try:
            row = pd.DataFrame([[features[f] for f in candidate_features]], columns=candidate_features)
            probability = float(candidate_models[cname].predict_proba(row)[0][1])
            threshold = candidate_thresholds[cname]
            result[cname] = {
                "available": True,
                "probability": probability,
                "prediction": int(probability >= threshold),
                "threshold": threshold,
            }
        except Exception as exc:  # noqa: BLE001 - one bad candidate must never affect the others
            result[cname] = {"available": False, "error": str(exc)}
    return result


def _predict_family_models(flow):
    """Scores the 3 attack-family models (train_attack_family_models.py)
    against the same 25-feature vector the deployed model uses - mirrors
    detection/predictor.py::predict_flow's exact logic (scale -> XGBoost
    -> Isolation Forest -> OR-combine), just parameterized per family."""
    result = {}
    try:
        features_25 = extract_deployed_features(flow)
    except Exception as exc:  # noqa: BLE001
        return {fname: {"available": False, "error": f"feature extraction failed: {exc}"} for fname in FAMILY_MODEL_DIRS}

    for fname in FAMILY_MODEL_DIRS:
        if fname not in family_models:
            result[fname] = {"available": False, "error": _family_load_errors.get(fname, "not loaded")}
            continue
        try:
            m = family_models[fname]
            top_features = m["top_features"]
            row = pd.DataFrame([[features_25[f] for f in top_features]], columns=top_features)
            scaled = m["scaler"].transform(row)

            xgb_probability = float(m["xgb"].predict_proba(row)[0][1])
            xgb_prediction = int(xgb_probability >= m["threshold"])
            isolation_prediction = int(fast_isolation_forest.predict(m["isolation"], scaled)[0] == -1)
            hybrid_prediction = int(xgb_prediction == 1 or isolation_prediction == 1)

            result[fname] = {
                "available": True,
                "probability": xgb_probability,
                "prediction": hybrid_prediction,
                "threshold": m["threshold"],
            }
        except Exception as exc:  # noqa: BLE001 - one bad family model must never affect the others
            result[fname] = {"available": False, "error": str(exc)}
    return result


def _predict_rl_verdict(flow):
    """Scores rl_verdict_classifier (rl_cicids_combined_classifier.py) -
    same 25-feature vector as the family models (extract_deployed_features),
    scaled with its own saved mean/std, forward-passed through its numpy
    Q-network. Prediction = argmax(Q); probability reported as the
    softmax over the 2 Q-values, purely for display (the network was
    trained on raw Q-value regression to reward, not a calibrated
    probability, same caveat as any Q-learning agent)."""
    if not _rl_verdict_ready:
        return {"available": False, "error": _rl_verdict_load_error}
    try:
        features_25 = extract_deployed_features(flow)
        x = np.array([features_25[f] for f in rl_top_features], dtype=np.float64)
        x = (x - rl_mean) / rl_std
        z1 = x @ rl_W1 + rl_b1
        h = np.tanh(z1)
        q = h @ rl_W2 + rl_b2
        probs = np.exp(q - q.max())
        probs /= probs.sum()
        prediction = int(np.argmax(q))
        return {
            "available": True,
            "label": "RL verdict classifier (contextual bandit)",
            "probability": float(probs[1]),
            "prediction": prediction,
            "threshold": 0.5,
        }
    except Exception as exc:  # noqa: BLE001 - never let this take down the others
        return {"available": False, "error": str(exc)}


def predict_all(flow):
    """Run all 3 experimental variants against one completed flow.
    Never raises - each variant is independently isolated, and this
    function itself is expected to be wrapped by the caller too."""

    features = extract_experimental_features(flow)
    dst_port = flow.dst_port if flow.dst_port is not None else 0
    protocol = flow.protocol if flow.protocol is not None else 0

    result = {
        "disclaimer": DISCLAIMER,
        "variant1_xgb_single_flow": _predict_variant1(features),
        "variant2_xgb_temporal": _predict_variant2(features, dst_port, protocol),
        "variant3_cnn_lstm": _predict_variant3(features, dst_port, protocol),
        "candidate_models": _predict_candidates(features),
        "family_models": _predict_family_models(flow),
        "rl_verdict_classifier": _predict_rl_verdict(flow),
        "temporal25_candidate": _predict_temporal25(flow, dst_port, protocol),
        "v8_candidate": _predict_v8(flow, dst_port),
    }

    # Record this flow's own features as history for FUTURE flows in this
    # group - strictly after producing this flow's own prediction, never
    # before (training used shift(1): only prior flows count as history).
    try:
        history_store.append(dst_port, protocol, features)
    except Exception:  # noqa: BLE001
        pass

    return result
