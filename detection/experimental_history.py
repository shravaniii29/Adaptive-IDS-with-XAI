"""
Bounded, thread-safe rolling history for the experimental models' variant 2
(engineered temporal features) and variant 3 (raw sequence), keyed by
(dst_port, protocol) - something the live system can genuinely track in
real time, unlike a database of past attacker source IPs.

Exactness requirements (from the training pipeline this must mirror,
train_three_way_multiday.py::build_temporal_features / build_raw_sequences):
  - A flow's own features are appended to its group's history only AFTER
    its prediction has been produced (training used shift(1) - strictly
    PRIOR flows only). Append-before-predict would leak the current flow
    into its own "history".
  - Cold start (no prior history) must mirror pandas' min_periods=1 +
    fillna(0): hist_mean_* = 0, hist_std_* = 0, hist_flow_count = 0,
    time_since_last = 0.
  - A single prior sample gives a pandas std of NaN (ddof=1, one
    observation) which training then fills to 0 - reproduced explicitly
    here, not left to a live NaN propagating into the model.
"""

import threading
import time
from collections import OrderedDict, deque

import numpy as np

WINDOW = 10
MAX_GROUPS = 2000
GROUP_TTL_SECONDS = 3600

HIST_COLUMNS = [
    "Flow Pkts/s", "Flow Byts/s", "Flow Duration", "TotLen Fwd Pkts",
]


class RollingHistoryStore:
    """One deque(maxlen=WINDOW) of (feature_dict, timestamp) per
    (dst_port, protocol) group. OrderedDict gives LRU eviction via
    move_to_end; a TTL sweep runs amortized on each update so no separate
    timer thread is needed."""

    def __init__(self, max_groups=MAX_GROUPS, window=WINDOW, ttl_seconds=GROUP_TTL_SECONDS):
        self._groups = OrderedDict()
        self._last_seen = {}
        self._lock = threading.Lock()
        self.max_groups = max_groups
        self.window = window
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def _key(dst_port, protocol):
        return (dst_port, protocol)

    def get_temporal_features(self, dst_port, protocol):
        """Cold-start-safe rolling stats over strictly prior flows in this
        group. Returns a dict matching train_three_way_multiday.py's
        hist_* column names exactly."""

        key = self._key(dst_port, protocol)

        with self._lock:
            history = list(self._groups.get(key, ()))

        features = {}

        if not history:
            for col in HIST_COLUMNS:
                safe = col.replace("/", "_").replace(" ", "_")
                features[f"hist_mean_{safe}"] = 0.0
                features[f"hist_std_{safe}"] = 0.0
            features["hist_flow_count"] = 0
            features["time_since_last"] = 0.0
            return features

        for col in HIST_COLUMNS:
            values = np.array([entry[0][col] for entry in history], dtype=np.float64)
            safe = col.replace("/", "_").replace(" ", "_")
            features[f"hist_mean_{safe}"] = float(np.mean(values))
            # pandas std uses ddof=1; a single sample gives NaN there,
            # which the training pipeline then fills to 0 - do the same.
            features[f"hist_std_{safe}"] = float(np.std(values, ddof=1)) if len(values) > 1 else 0.0

        features["hist_flow_count"] = min(len(history), self.window)
        features["time_since_last"] = max(0.0, time.time() - history[-1][1])

        return features

    def get_raw_sequence(self, dst_port, protocol, current_features, base_feature_order):
        """Up to `window` prior raw feature vectors (base_feature_order
        order) plus the current flow's own vector as the last step,
        front-zero-padded if fewer than `window` prior flows exist.
        Matches build_raw_sequences: the anchor flow's own features are
        the final timestep."""

        key = self._key(dst_port, protocol)

        with self._lock:
            history = list(self._groups.get(key, ()))

        n_feat = len(base_feature_order)
        sequence = np.zeros((self.window, n_feat), dtype=np.float32)

        prior = history[-(self.window - 1):] if self.window > 1 else []
        rows = [entry[0] for entry in prior]
        rows.append(current_features)

        start = self.window - len(rows)
        for i, row in enumerate(rows):
            sequence[start + i] = [row[f] for f in base_feature_order]

        return sequence

    def append(self, dst_port, protocol, features):
        """Record this flow's features as history for FUTURE predictions
        in this group. Call only after this flow's own prediction has
        already been produced."""

        key = self._key(dst_port, protocol)
        now = time.time()

        with self._lock:
            if key not in self._groups:
                self._groups[key] = deque(maxlen=self.window)
            self._groups[key].append((dict(features), now))
            self._last_seen[key] = now
            self._groups.move_to_end(key)

            self._evict_stale(now)
            self._evict_lru()

    def _evict_stale(self, now):
        stale_keys = [k for k, ts in self._last_seen.items() if now - ts > self.ttl_seconds]
        for k in stale_keys:
            self._groups.pop(k, None)
            self._last_seen.pop(k, None)

    def _evict_lru(self):
        while len(self._groups) > self.max_groups:
            oldest_key, _ = self._groups.popitem(last=False)
            self._last_seen.pop(oldest_key, None)

    def group_count(self):
        with self._lock:
            return len(self._groups)
