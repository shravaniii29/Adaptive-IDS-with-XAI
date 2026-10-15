"""
Live test for the LSNM2024 packet-level models (notebooks/train_lsnm2024_packet_level.ipynb)
- temporal XGBoost and CNN+LSTM trained on raw packets, no flow reconstruction.

These aren't wired into the live app at all (no Flow/FlowManager dependency
by design), so this sniffs packets directly with scapy and scores each one
as it arrives, reusing simulate_attacks.py's exact scenario generators for
ground truth and feature_extraction/flow.py's already-fixed payload-length
convention (ICMP header subtraction, payload not full-frame length) for
feature computation - so this stays consistent with everything else this
project has already validated, without depending on FlowManager itself.

Requires the FastAPI backend to NOT be capturing on the same interface
simultaneously (both would fight over the same packets) - stop it first,
or just run this against loopback while nothing else sniffs.

Usage:
    python live_test_packet_models.py
"""

import pickle
import queue
import threading
import time
import traceback
from collections import deque
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from scapy.all import sniff
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether, Loopback

from packet_capture.capture import _select_interface
from simulate_attacks import SCENARIOS, TARGET_IP, VICTIM_HTTP_PORT, start_victim_server

PROJECT_ROOT = Path(__file__).resolve().parent
MODELS_DIR = PROJECT_ROOT / "models" / "lsnm2024_packet_only"

HISTORY_WINDOW = 10
SEQUENCE_LENGTH = 10
DRAIN_SECONDS = 10  # shorter than simulate_attacks.py's - no flow-expiry wait needed, packets score immediately


def load_models():
    with open(MODELS_DIR / "xgb_temporal.pkl", "rb") as f:
        xgb = pickle.load(f)
    with open(MODELS_DIR / "threshold_xgb_temporal.pkl", "rb") as f:
        xgb_threshold = pickle.load(f)
    with open(MODELS_DIR / "features_xgb_temporal.pkl", "rb") as f:
        xgb_features = pickle.load(f)
    with open(MODELS_DIR / "scaler_cnn_lstm.pkl", "rb") as f:
        lstm_scaler = pickle.load(f)
    with open(MODELS_DIR / "threshold_cnn_lstm.pkl", "rb") as f:
        lstm_threshold = pickle.load(f)
    with open(MODELS_DIR / "raw_features.pkl", "rb") as f:
        raw_features = pickle.load(f)

    class CNN_LSTM(nn.Module):
        def __init__(self, n_features, seq_len=SEQUENCE_LENGTH):
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

    lstm = CNN_LSTM(n_features=len(raw_features))
    lstm.load_state_dict(torch.load(MODELS_DIR / "cnn_lstm_packet.pt", map_location="cpu"))
    lstm.eval()

    return {
        "xgb": xgb, "xgb_threshold": xgb_threshold, "xgb_features": xgb_features,
        "lstm": lstm, "lstm_scaler": lstm_scaler, "lstm_threshold": lstm_threshold,
        "raw_features": raw_features,
    }


def payload_and_protocol(packet, packet_length):
    """Identical convention to feature_extraction/flow.py (this session's
    ICMP-header fix included) and fetch_lsnm2024_25feature.py - so the live
    features match what the model was trained on as closely as possible."""
    if Loopback in packet:
        l2_header_length = 4
    elif Ether in packet:
        l2_header_length = 14
    else:
        l2_header_length = 0

    if IP not in packet:
        return 0.0, 0.0

    ip_header_length = packet[IP].ihl or 5
    header_length = l2_header_length + ip_header_length * 4

    if TCP in packet:
        protocol_num = 6.0
        tcp_header_length = packet[TCP].dataofs or 5
        header_length += tcp_header_length * 4
    elif UDP in packet:
        protocol_num = 17.0
        header_length += 8
    elif ICMP in packet:
        protocol_num = 0.0
        header_length += 8
    else:
        protocol_num = 0.0

    payload = max(0.0, packet_length - header_length)
    return payload, protocol_num


class PacketScorer:
    """Capture and inference are decoupled: on_packet() (called from the
    scapy sniff() thread) does only cheap field extraction and pushes onto
    a queue, returning immediately. A separate worker thread drains the
    queue and does the rolling-history bookkeeping + XGBoost/LSTM
    inference. This matters here specifically: an earlier version ran
    XGBoost's predict_proba synchronously inside on_packet, and a genuine
    flood (hundreds of packets/sec) fell far enough behind that Npcap's
    capture buffer overflowed and the whole sniff() call died silently in
    its background thread (no traceback - daemon thread exceptions aren't
    surfaced) partway through the very first flood scenario, leaving every
    later scenario with zero captured packets."""

    def __init__(self, models):
        self.models = models
        self.history = deque(maxlen=HISTORY_WINDOW)
        self.sequence = deque(maxlen=SEQUENCE_LENGTH)
        self.last_ts = None
        self.records = []
        self.raw_queue = queue.Queue()
        self.worker_errors = []
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)

    def start(self):
        self.worker_thread.start()

    def on_packet(self, packet):
        """Runs on the sniff() thread - must stay fast. Only cheap field
        extraction happens here; everything else is deferred to the
        worker thread via raw_queue."""
        if IP not in packet:
            return
        ts = float(packet.time)
        frame_length = float(len(packet))
        payload, protocol_num = payload_and_protocol(packet, frame_length)
        self.raw_queue.put((ts, frame_length, payload, protocol_num))

    def _rolling_stats(self, key):
        vals = [h[key] for h in self.history]
        if not vals:
            return 0.0, 0.0
        return float(np.mean(vals)), float(np.std(vals)) if len(vals) > 1 else 0.0

    def _worker_loop(self):
        while True:
            item = self.raw_queue.get()
            if item is None:
                return
            try:
                self._process(item)
            except Exception as exc:  # noqa: BLE001 - never let the worker die silently either
                self.worker_errors.append(traceback.format_exc())
                if len(self.worker_errors) <= 3:
                    print(f"WORKER ERROR: {exc}")

    def _process(self, item):
        ts, frame_length, payload, protocol_num = item
        delta_t_us = 0.0 if self.last_ts is None else max(0.0, (ts - self.last_ts) * 1_000_000)
        self.last_ts = ts
        raw = {"frame_length": frame_length, "payload": payload, "protocol_num": protocol_num, "delta_t_us": delta_t_us}

        # temporal XGB: own features + rolling history computed BEFORE
        # appending this packet (matches shift(1) in the notebook - the
        # current packet must never leak into its own history)
        hist_mean_fl, hist_std_fl = self._rolling_stats("frame_length")
        hist_mean_pl, hist_std_pl = self._rolling_stats("payload")
        hist_mean_dt, hist_std_dt = self._rolling_stats("delta_t_us")
        hist_pkt_count = min(len(self.history), HISTORY_WINDOW)

        feat_row = {
            **raw,
            "hist_mean_frame_length": hist_mean_fl, "hist_std_frame_length": hist_std_fl,
            "hist_mean_payload": hist_mean_pl, "hist_std_payload": hist_std_pl,
            "hist_mean_delta_t_us": hist_mean_dt, "hist_std_delta_t_us": hist_std_dt,
            "hist_pkt_count": hist_pkt_count,
        }

        xgb_pred = None
        try:
            x = np.array([[feat_row[f] for f in self.models["xgb_features"]]])
            prob = self.models["xgb"].predict_proba(x)[0][1]
            xgb_pred = int(prob >= self.models["xgb_threshold"])
        except Exception:
            pass

        self.history.append(raw)
        self.sequence.append([raw[f] for f in self.models["raw_features"]])

        lstm_pred = None
        if len(self.sequence) == SEQUENCE_LENGTH:
            try:
                seq = np.array(self.sequence, dtype=np.float32).reshape(1, SEQUENCE_LENGTH, -1)
                n_feat = seq.shape[2]
                scaled = self.models["lstm_scaler"].transform(seq.reshape(-1, n_feat)).reshape(1, SEQUENCE_LENGTH, n_feat)
                with torch.inference_mode():
                    logit = self.models["lstm"](torch.FloatTensor(scaled))
                    prob = torch.sigmoid(logit).item()
                lstm_pred = int(prob >= self.models["lstm_threshold"])
            except Exception:
                pass

        self.records.append((ts, xgb_pred, lstm_pred))

    def drain(self, timeout=30):
        """Blocks until the worker has processed everything queued so far."""
        deadline = time.time() + timeout
        while not self.raw_queue.empty() and time.time() < deadline:
            time.sleep(0.05)
        self.raw_queue.put(None)
        self.worker_thread.join(timeout=5)


def attribute_and_score(records, scenarios):
    results = {}
    for s in scenarios:
        in_window = [(ts, x, l) for ts, x, l in records if s.start_time - 0.5 <= ts <= s.end_time + 0.5]
        expected = 1 if s.is_attack else 0

        def acc(preds):
            preds = [p for p in preds if p is not None]
            if not preds:
                return None, 0
            correct = sum(1 for p in preds if p == expected)
            return correct / len(preds), len(preds)

        xgb_acc, xgb_n = acc([x for _, x, _ in in_window])
        lstm_acc, lstm_n = acc([l for _, _, l in in_window])
        results[s.name] = {"is_attack": s.is_attack, "xgb": (xgb_acc, xgb_n), "lstm": (lstm_acc, lstm_n)}
    return results


def main():
    print("loading packet-level models ...")
    models = load_models()
    scorer = PacketScorer(models)

    iface = _select_interface()
    print(f"sniffing on interface: {iface!r}  target: {TARGET_IP}")

    print("starting victim HTTP server ...")
    start_victim_server()

    scorer.start()
    stop_event = threading.Event()
    sniffer_thread = threading.Thread(
        target=lambda: sniff(iface=iface, prn=scorer.on_packet, stop_filter=lambda p: stop_event.is_set(), store=False),
        daemon=True,
    )
    sniffer_thread.start()
    time.sleep(1)  # let the sniffer actually start before generating traffic

    scenarios = []
    for fn in SCENARIOS:
        print(f"\nrunning scenario: {fn.__name__} ...")
        s = fn()
        scenarios.append(s)
        print(f"  {s.name}: {s.end_time - s.start_time:.1f}s, {len(scorer.records)} packets scored so far")
        time.sleep(1)

    print(f"\ndraining ({DRAIN_SECONDS}s) ...")
    time.sleep(DRAIN_SECONDS)
    stop_event.set()
    sniffer_thread.join(timeout=5)
    scorer.drain()

    if scorer.worker_errors:
        print(f"\n{len(scorer.worker_errors)} worker error(s) occurred - first one:")
        print(scorer.worker_errors[0])

    print(f"\ntotal packets scored: {len(scorer.records)}")
    if scorer.records:
        ts_values = [r[0] for r in scorer.records]
        print(f"packet ts range: {min(ts_values):.3f} -> {max(ts_values):.3f}")
    for s in scenarios:
        print(f"  scenario window: {s.name:<20} {s.start_time:.3f} -> {s.end_time:.3f}")

    results = attribute_and_score(scorer.records, scenarios)

    print("\n" + "=" * 90)
    print("LIVE PACKET-LEVEL MODEL REPORT")
    print("=" * 90)
    print(f"{'Scenario':<20}{'Type':<10}{'Temporal XGB':<28}{'CNN+LSTM (packets)':<28}")
    print("-" * 86)
    for name, r in results.items():
        kind = "ATTACK" if r["is_attack"] else "BENIGN"
        metric = "recall" if r["is_attack"] else "specificity"
        xgb_acc, xgb_n = r["xgb"]
        lstm_acc, lstm_n = r["lstm"]
        xgb_str = f"{xgb_acc*100:.1f}% {metric} (n={xgb_n})" if xgb_acc is not None else "no packets"
        lstm_str = f"{lstm_acc*100:.1f}% {metric} (n={lstm_n})" if lstm_acc is not None else "no packets"
        print(f"{name:<20}{kind:<10}{xgb_str:<28}{lstm_str:<28}")
    print("=" * 90)


if __name__ == "__main__":
    main()
