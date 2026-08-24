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

MICROSECONDS_PER_SECOND = 1_000_000

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Overridable so a test run can point at e.g. models/experimental_2019
# (a candidate artifact set under review) without touching the default
# deployed-in-place artifacts under models/experimental.
MODELS_DIR = Path(os.environ.get("EXPERIMENTAL_MODELS_DIR", PROJECT_ROOT / "models" / "experimental"))

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

    forward_lengths = flow.forward_packet_lengths
    forward_payloads = flow.forward_payload_lengths

    tot_fwd_pkts = len(forward_lengths)
    totlen_fwd_pkts = float(np.sum(forward_lengths)) if forward_lengths else 0.0
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
    }

    # Record this flow's own features as history for FUTURE flows in this
    # group - strictly after producing this flow's own prediction, never
    # before (training used shift(1): only prior flows count as history).
    try:
        history_store.append(dst_port, protocol, features)
    except Exception:  # noqa: BLE001
        pass

    return result
