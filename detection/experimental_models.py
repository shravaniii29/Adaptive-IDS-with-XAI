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

import numpy as np
import pandas as pd
from xgboost import XGBClassifier  # noqa: F401 - ensures class is registered before unpickling

from detection.experimental_history import RollingHistoryStore
from feature_extraction.feature_extractor import extract_features as extract_deployed_features

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

def _load_pickle(name):
    with open(MODELS_DIR / name, "rb") as f:
        return pickle.load(f)


def _load_pickle_from(directory, name):
    with open(directory / name, "rb") as f:
        return pickle.load(f)


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
            isolation_prediction = int(m["isolation"].predict(scaled)[0] == -1)
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
    }

    # Record this flow's own features as history for FUTURE flows in this
    # group - strictly after producing this flow's own prediction, never
    # before (training used shift(1): only prior flows count as history).
    try:
        history_store.append(dst_port, protocol, features)
    except Exception:  # noqa: BLE001
        pass

    return result
