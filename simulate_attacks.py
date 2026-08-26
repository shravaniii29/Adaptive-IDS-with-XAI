"""
Simulates a set of local, bounded-duration attack scenarios against this
machine's own network stack, then measures how accurately the DEPLOYED
hybrid model and all 3 EXPERIMENTAL models (via the live app's /predict
and /experimental endpoints) classify the resulting flows.

Safety: every scenario targets this machine's own real LAN IP (never an
external host), each scenario is capped to ~12 seconds, and there's a
benign baseline scenario so this also measures false-positive rate, not
just attack recall.

Why the real LAN IP and not 127.0.0.1: Windows loopback capture is
unreliable with Npcap without a dedicated loopback adapter - traffic to
127.0.0.1 may never reach the app's scapy sniff() at all. Routing through
the real NIC (even to itself) is what actually gets captured, same
workaround used earlier in this project's own ping testing.

Requires: the FastAPI backend (app/main.py) already running with live
packet capture active, e.g.:
    python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

Usage:
    python simulate_attacks.py
"""

import http.client
import json
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import send

API_BASE = "http://127.0.0.1:8000"
VICTIM_HTTP_PORT = 8899
POLL_INTERVAL = 0.5
DRAIN_SECONDS = 25  # >= FlowManager's active_timeout, so the last flow of a scenario has time to expire and get scored
RESULTS_DIR = "simulation_results"  # one JSON file per attack type, for demo/visualization use


def local_lan_ip():
    """This machine's real NIC IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def resolve_target_ip():
    """Prefers 127.0.0.1, captured via Npcap's loopback device
    (\\Device\\NPF_Loopback, built in since Npcap 0.9983 - no installer
    option needed). Confirmed by testing that self-targeted traffic to
    this machine's real LAN IP is NOT reliably delivered to any physical
    adapter's capture point on Windows (zero self-to-self flows captured
    across several runs, despite the correct real-NIC interface being
    watched) - Windows short-circuits it before it reaches a NIC driver.
    Falls back to the real LAN IP if the loopback device isn't available
    for some reason - same fragile behavior as before, but at least
    explicit about why."""
    from packet_capture.capture import has_npcap_loopback
    if has_npcap_loopback():
        return "127.0.0.1"
    print("WARNING: Npcap loopback capture not available - falling back to "
          "this machine's real LAN IP, which has been unreliable for "
          "self-targeted traffic capture. This is unusual for any Npcap "
          "install from the last several years; see RUNNING.md.")
    return local_lan_ip()


TARGET_IP = resolve_target_ip()


# =====================================================
# Throwaway local "victim" HTTP server
#
# Gives HTTP-flood/port-scan traffic a real responder, so
# the resulting flows have genuine backward-direction data
# (several top model features depend on it) instead of
# one-sided noise into nothing.
# =====================================================

class _QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass  # keep stdout clean


def start_victim_server():
    server = HTTPServer((TARGET_IP, VICTIM_HTTP_PORT), _QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# =====================================================
# Ground truth record for one scenario
# =====================================================

@dataclass
class Scenario:
    name: str
    is_attack: bool
    dst_ip: str
    dst_ports: set = field(default_factory=set)  # empty set = any port matches
    start_time: float = 0.0
    end_time: float = 0.0


# =====================================================
# Attack / benign traffic generators
# Each targets TARGET_IP (this machine's real NIC), runs
# for a bounded duration, and returns a Scenario recording
# what ground truth to expect.
# =====================================================

def scenario_icmp_flood(duration=10):
    start = time.time()
    end = start + duration
    while time.time() < end:
        send(IP(dst=TARGET_IP) / ICMP(), count=20, inter=0, verbose=0)
    return Scenario("ICMP flood", True, TARGET_IP, set(), start, time.time())


def scenario_syn_flood(duration=10, port=9999):
    # Fixed source port (not RandShort() per packet) so repeated packets
    # aggregate into one flood-shaped flow, matching how CICFlowMeter (and
    # this project's own FlowManager) key flows by the full 5-tuple - a
    # different source port every packet fragments what should be one
    # sustained flood into hundreds of unrepresentative 1-packet flows.
    start = time.time()
    end = start + duration
    src_port = 40000
    while time.time() < end:
        send(IP(dst=TARGET_IP) / TCP(sport=src_port, dport=port, flags="S"), count=20, inter=0, verbose=0)
    return Scenario("SYN flood", True, TARGET_IP, {port}, start, time.time())


def scenario_udp_flood(duration=10, port=9998):
    start = time.time()
    end = start + duration
    payload = b"X" * 32
    src_port = 40001
    while time.time() < end:
        send(IP(dst=TARGET_IP) / UDP(sport=src_port, dport=port) / payload, count=20, inter=0, verbose=0)
    return Scenario("UDP flood", True, TARGET_IP, {port}, start, time.time())


def scenario_http_flood(duration=10):
    start = time.time()
    end = start + duration
    while time.time() < end:
        try:
            conn = http.client.HTTPConnection(TARGET_IP, VICTIM_HTTP_PORT, timeout=1)
            conn.request("GET", "/")
            conn.getresponse().read()
            conn.close()
        except Exception:
            pass
    return Scenario("HTTP flood", True, TARGET_IP, {VICTIM_HTTP_PORT}, start, time.time())


def scenario_port_scan(duration=10):
    start = time.time()
    ports = list(range(9900, 9900 + 60))
    end = start + duration
    while time.time() < end:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            try:
                s.connect_ex((TARGET_IP, port))
            except Exception:
                pass
            finally:
                s.close()
            if time.time() >= end:
                break
    return Scenario("Port scan", True, TARGET_IP, set(ports), start, time.time())


def scenario_benign_baseline(duration=12):
    start = time.time()
    # A few normal, human-paced pings ...
    send(IP(dst=TARGET_IP) / ICMP(), count=4, inter=1, verbose=0)
    # ... and a couple of ordinary HTTP requests, spaced out.
    for _ in range(3):
        try:
            requests.get(f"http://{TARGET_IP}:{VICTIM_HTTP_PORT}/", timeout=2)
        except Exception:
            pass
        time.sleep(2)
    return Scenario("Benign baseline", False, TARGET_IP, set(), start, time.time())


SCENARIOS = [
    scenario_benign_baseline,
    scenario_icmp_flood,
    scenario_syn_flood,
    scenario_udp_flood,
    scenario_http_flood,
    scenario_port_scan,
]


# =====================================================
# Background poller: records every distinct flow seen via
# /predict + /experimental while scenarios run
# =====================================================

CANDIDATE_KEYS = ["xgboost", "random_forest", "histgradientboosting"]


@dataclass
class ObservedFlow:
    flow_id: object
    source_ip: str
    destination_ip: str
    observed_at: float
    hybrid_prediction: int
    variant1: dict
    variant2: dict
    variant3: dict
    candidates: dict = field(default_factory=dict)  # classifier_comparison.ipynb models, keyed by CANDIDATE_KEYS


def _model_result(flow, model_key):
    """Single lookup path for every model key (the 4 original + the 3
    classifier_comparison candidates), used by scoring/reporting/dump so
    they don't each need their own if/elif chain over model kinds."""
    if model_key == "deployed_hybrid":
        pred = flow.hybrid_prediction
        return pred is not None, pred
    if model_key in CANDIDATE_KEYS:
        entry = flow.candidates.get(model_key, {})
    else:
        entry = {"variant1_xgb_single_flow": flow.variant1,
                 "variant2_xgb_temporal": flow.variant2,
                 "variant3_cnn_lstm": flow.variant3}[model_key]
    available = entry.get("available", False)
    return available, (entry.get("prediction") if available else None)


class Poller:
    """Polls the bulk /history endpoint (up to 500 buffered flows) rather
    than /predict + /experimental (which only ever reflect the single
    most recent flow) - a burst of flows completing faster than
    POLL_INTERVAL would otherwise be silently missed almost entirely."""

    def __init__(self):
        self.seen_flow_ids = set()
        self.flows = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)
        self._drain_once()  # one final pull, so flows completing during the drain sleep aren't lost

    def _drain_once(self):
        try:
            data = requests.get(f"{API_BASE}/history", timeout=5).json()
        except Exception:
            return
        self._ingest(data.get("flows", []))

    def _ingest(self, entries):
        for entry in entries:
            flow_id = entry.get("flow_id")
            if flow_id is None or flow_id in self.seen_flow_ids:
                continue
            self.seen_flow_ids.add(flow_id)
            self.flows.append(ObservedFlow(
                flow_id=flow_id,
                source_ip=entry.get("source_ip"),
                destination_ip=entry.get("destination_ip"),
                observed_at=entry.get("recorded_at") or time.time(),
                hybrid_prediction=entry.get("hybrid_prediction"),
                variant1=entry.get("variant1_xgb_single_flow", {}),
                variant2=entry.get("variant2_xgb_temporal", {}),
                variant3=entry.get("variant3_cnn_lstm", {}),
                candidates=entry.get("candidate_models", {}),
            ))

    def _run(self):
        while not self._stop.is_set():
            try:
                data = requests.get(f"{API_BASE}/history", timeout=3).json()
                self._ingest(data.get("flows", []))
            except Exception:
                pass
            time.sleep(POLL_INTERVAL)


# =====================================================
# Attribution: match observed flows to the scenario that
# generated them, by destination IP + port + timing window
# =====================================================

def attribute_flows(flows, scenarios, active_timeout=20, flow_timeout=5):
    slack = active_timeout + flow_timeout + POLL_INTERVAL * 2
    attributed = {s.name: [] for s in scenarios}

    for flow in flows:
        for s in scenarios:
            if flow.destination_ip != s.dst_ip:
                continue
            if not (s.start_time - 1 <= flow.observed_at <= s.end_time + slack):
                continue
            attributed[s.name].append(flow)
            break

    return attributed


# =====================================================
# Scoring
# =====================================================

MODEL_KEYS = ["deployed_hybrid", "variant1_xgb_single_flow", "variant2_xgb_temporal", "variant3_cnn_lstm"] + CANDIDATE_KEYS
MODEL_LABELS = {
    "deployed_hybrid": "Deployed hybrid",
    "variant1_xgb_single_flow": "Var1 XGB single-flow",
    "variant2_xgb_temporal": "Var2 XGB temporal",
    "variant3_cnn_lstm": "Var3 CNN+LSTM",
    "xgboost": "Candidate: XGBoost",
    "random_forest": "Candidate: Random Forest",
    "histgradientboosting": "Candidate: HistGradientBoosting",
}


def score(attributed, scenarios):
    rows = []

    for s in scenarios:
        flows = attributed[s.name]
        if not flows:
            rows.append((s.name, s.is_attack, len(flows), {m: None for m in MODEL_KEYS}))
            continue

        results = {}
        for model in MODEL_KEYS:
            correct = 0
            total = 0
            for f in flows:
                available, pred = _model_result(f, model)
                if not available:
                    continue
                total += 1
                expected = 1 if s.is_attack else 0
                if pred == expected:
                    correct += 1
            results[model] = (correct / total) if total else None

        rows.append((s.name, s.is_attack, len(flows), results))

    return rows


def aggregate_metrics(attributed, scenarios):
    """Pools every attributed flow across all scenarios into one
    confusion matrix per model, so a single run reports overall
    accuracy/precision/recall/F1 - not just per-scenario recall/specificity.
    Ground truth for each flow comes from the scenario that generated it
    (attribute_flows already matched them by dst_ip/port/time window)."""
    scenarios_by_name = {s.name: s for s in scenarios}

    metrics = {}
    for model in MODEL_KEYS:
        tp = fp = tn = fn = 0
        for name, flows in attributed.items():
            expected = 1 if scenarios_by_name[name].is_attack else 0
            for f in flows:
                available, pred = _model_result(f, model)
                if not available:
                    continue
                if expected == 1 and pred == 1:
                    tp += 1
                elif expected == 1 and pred == 0:
                    fn += 1
                elif expected == 0 and pred == 1:
                    fp += 1
                elif expected == 0 and pred == 0:
                    tn += 1

        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total else None
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * precision * recall / (precision + recall)) if (precision and recall and (precision + recall)) else None
        specificity = tn / (tn + fp) if (tn + fp) else None

        metrics[model] = {
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "specificity": specificity,
            "total_flows": total,
        }

    return metrics


def print_aggregate_metrics(metrics):
    print("\n" + "=" * 100)
    print("OVERALL METRICS (all scenarios pooled, per model)")
    print("=" * 100)
    for model in MODEL_KEYS:
        label = MODEL_LABELS[model]
        m = metrics[model]
        cm = m["confusion_matrix"]
        if m["total_flows"] == 0:
            print(f"{label}: no scored flows")
            continue

        def fmt(v):
            return f"{v*100:.1f}%" if v is not None else "n/a"

        print(f"\n{label}  ({m['total_flows']} flows)")
        print(f"  confusion matrix: TP={cm['tp']}  FP={cm['fp']}  TN={cm['tn']}  FN={cm['fn']}")
        print(f"  accuracy={fmt(m['accuracy'])}  precision={fmt(m['precision'])}  "
              f"recall={fmt(m['recall'])}  f1={fmt(m['f1'])}  specificity={fmt(m['specificity'])}")
    print("=" * 100)


def print_report(rows):
    print("\n" + "=" * 100)
    print("ATTACK SIMULATION - PER-MODEL ACCURACY REPORT")
    print("=" * 100)
    header = f"{'Scenario':<20}{'Type':<10}{'Flows':<8}" + "".join(f"{MODEL_LABELS[k]:<25}" for k in MODEL_KEYS)
    print(header)
    print("-" * len(header))

    for name, is_attack, n_flows, results in rows:
        kind = "ATTACK" if is_attack else "BENIGN"
        metric = "recall" if is_attack else "specificity"
        line = f"{name:<20}{kind:<10}{n_flows:<8}"
        for key in MODEL_KEYS:
            val = results[key]
            line += f"{(f'{val*100:.1f}% ' + metric) if val is not None else 'no flows':<25}"
        print(line)

    print("=" * 100)
    print("recall = % of attack flows correctly flagged ATTACK. specificity = % of benign flows correctly flagged NORMAL.")


# =====================================================
# Per-attack-type export, one JSON file per scenario
#
# Splits the combined report into a separate file per attack type
# (icmp_flood.json, syn_flood.json, ...) plus one summary.json
# indexing all of them - so a demo/visualization step can load and
# chart a single attack type without re-running the simulation or
# parsing the combined report.
# =====================================================

def dump_results(rows, attributed, scenarios, out_dir=RESULTS_DIR, aggregate=None):
    os.makedirs(out_dir, exist_ok=True)

    scenarios_by_name = {s.name: s for s in scenarios}
    rows_by_name = {name: (is_attack, n_flows, results) for name, is_attack, n_flows, results in rows}

    summary = {"generated_at": time.time(), "target_ip": TARGET_IP, "scenarios": [],
               "aggregate_metrics": aggregate or {}}

    for name, s in scenarios_by_name.items():
        is_attack, n_flows, results = rows_by_name[name]
        expected = 1 if is_attack else 0

        flow_details = []
        for f in attributed[name]:
            per_model = {}
            for model in MODEL_KEYS:
                available, pred = _model_result(f, model)
                per_model[model] = {
                    "available": available,
                    "prediction": pred,
                    "correct": (pred == expected) if available else None
                }
            flow_details.append({
                "flow_id": f.flow_id,
                "source_ip": f.source_ip,
                "destination_ip": f.destination_ip,
                "observed_at": f.observed_at,
                "models": per_model
            })

        scenario_record = {
            "name": name,
            "is_attack": is_attack,
            "start_time": s.start_time,
            "end_time": s.end_time,
            "duration_seconds": s.end_time - s.start_time,
            "flow_count": n_flows,
            "model_scores": results,
            "flows": flow_details
        }

        path = os.path.join(out_dir, f"{name}.json")
        with open(path, "w") as fh:
            json.dump(scenario_record, fh, indent=2)

        summary["scenarios"].append({
            "name": name,
            "is_attack": is_attack,
            "flow_count": n_flows,
            "model_scores": results,
            "file": f"{name}.json"
        })

    with open(os.path.join(out_dir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    print(f"\nwrote {len(scenarios_by_name)} per-attack-type files + summary.json to {out_dir}/")


# =====================================================
# Main
# =====================================================

def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else RESULTS_DIR

    print(f"Target (this machine's real NIC IP): {TARGET_IP}")
    print("Checking backend is reachable ...")
    requests.get(f"{API_BASE}/status", timeout=5).raise_for_status()
    print("Backend OK. Starting local victim HTTP server ...")
    start_victim_server()

    poller = Poller()
    poller.start()

    scenarios = []
    for fn in SCENARIOS:
        print(f"\nrunning scenario: {fn.__name__} ...")
        s = fn()
        scenarios.append(s)
        print(f"  {s.name}: {s.start_time:.1f} -> {s.end_time:.1f} ({s.end_time - s.start_time:.1f}s)")
        time.sleep(2)  # cooldown gap between scenarios, for cleaner attribution

    print(f"\ndraining ({DRAIN_SECONDS}s, letting the last flows expire and get scored) ...")
    time.sleep(DRAIN_SECONDS)
    poller.stop()

    print(f"\ntotal distinct flows observed: {len(poller.flows)}")
    attributed = attribute_flows(poller.flows, scenarios)
    for s in scenarios:
        print(f"  {s.name}: {len(attributed[s.name])} flows attributed")

    rows = score(attributed, scenarios)
    print_report(rows)

    metrics = aggregate_metrics(attributed, scenarios)
    print_aggregate_metrics(metrics)

    dump_results(rows, attributed, scenarios, out_dir=out_dir, aggregate=metrics)


if __name__ == "__main__":
    main()
