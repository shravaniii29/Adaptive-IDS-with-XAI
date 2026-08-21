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
import socket
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


def local_lan_ip():
    """This machine's real NIC IP - the one that actually gets captured."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


TARGET_IP = local_lan_ip()


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

def score(attributed, scenarios):
    model_names = ["deployed_hybrid", "variant1_xgb_single_flow", "variant2_xgb_temporal", "variant3_cnn_lstm"]
    rows = []

    for s in scenarios:
        flows = attributed[s.name]
        if not flows:
            rows.append((s.name, s.is_attack, len(flows), {m: None for m in model_names}))
            continue

        results = {}
        for model in model_names:
            correct = 0
            total = 0
            for f in flows:
                if model == "deployed_hybrid":
                    pred = f.hybrid_prediction
                    available = pred is not None
                else:
                    variant = {"variant1_xgb_single_flow": f.variant1,
                               "variant2_xgb_temporal": f.variant2,
                               "variant3_cnn_lstm": f.variant3}[model]
                    available = variant.get("available", False)
                    pred = variant.get("prediction") if available else None
                if not available:
                    continue
                total += 1
                expected = 1 if s.is_attack else 0
                if pred == expected:
                    correct += 1
            results[model] = (correct / total) if total else None

        rows.append((s.name, s.is_attack, len(flows), results))

    return rows


def print_report(rows):
    model_labels = ["Deployed hybrid", "Var1 XGB single-flow", "Var2 XGB temporal", "Var3 CNN+LSTM"]
    model_keys = ["deployed_hybrid", "variant1_xgb_single_flow", "variant2_xgb_temporal", "variant3_cnn_lstm"]

    print("\n" + "=" * 100)
    print("ATTACK SIMULATION - PER-MODEL ACCURACY REPORT")
    print("=" * 100)
    header = f"{'Scenario':<20}{'Type':<10}{'Flows':<8}" + "".join(f"{lbl:<22}" for lbl in model_labels)
    print(header)
    print("-" * len(header))

    for name, is_attack, n_flows, results in rows:
        kind = "ATTACK" if is_attack else "BENIGN"
        metric = "recall" if is_attack else "specificity"
        line = f"{name:<20}{kind:<10}{n_flows:<8}"
        for key in model_keys:
            val = results[key]
            line += f"{(f'{val*100:.1f}% ' + metric) if val is not None else 'no flows':<22}"
        print(line)

    print("=" * 100)
    print("recall = % of attack flows correctly flagged ATTACK. specificity = % of benign flows correctly flagged NORMAL.")


# =====================================================
# Main
# =====================================================

def main():
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


if __name__ == "__main__":
    main()
