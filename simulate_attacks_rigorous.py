"""
Statistically-powered variant of simulate_attacks.py, forked off rather
than merged in, so simulate_attacks.py's own default behavior (and
anything already citing it) stays unchanged.

The only functional difference from simulate_attacks.py: scenario_benign_
baseline() sends 18 varied-path HTTP requests per trial (each opens its
own connection - a fresh ephemeral source port, hence a distinct flow
under this project's 5-tuple flow key) instead of 3 near-identical ones,
plus the unchanged ICMP-ping burst (still 1 flow/trial regardless of
count, since ICMP has no port to disambiguate by). That's 19 benign
flows/trial - confirmed against the actual captured output, not just
counted from this list: 25 trials -> 475 total (25 x 1 ICMP + 25 x 18
HTTP), exactly matching what shipped, with nothing uncounted for. This is
what grows the benign SAMPLE SIZE, not scenario duration - the original
3-request version left specificity estimated from just 12 flows total
across 3 trials, too small for a citable confidence interval (Wilson 95%
CI on 12/12 correct is [75.7%, 100%], not "100%"). Run with a higher
trial count than the 3-trial default to get a defensible n on every
scenario - the run this file was built for used 25 trials, n=475 benign /
3,415 attack, giving specificity 95% CI [99.2%, 100%].

IMPORTANT construct-validity caveat, distinct from the sample-size fix
above: every one of those 475 benign flows is still the SAME kind of
traffic - synthetic ICMP echo requests and HTTP GETs to this project's
own throwaway local victim server. There is no DNS, no HTTPS/TLS, no
SMB, no real-world browsing mix, and no traffic to any host but this
machine. "100% specificity" from this harness means 100% specificity
against this one narrow, scripted probe-traffic construct - it does NOT
demonstrate specificity against the diversity of protocols and
destinations a deployed SOC sensor would actually see. Report it
accordingly (e.g. "100% specificity on synthetic HTTP/ICMP probe
traffic"), not as an unqualified stand-in for general benign-traffic
performance.

Everything else - scenario set, model roster (including v8_candidate),
attribution logic, output format - is identical to simulate_attacks.py;
diff the two files if in doubt rather than trusting this comment to stay
in sync.

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

Runs 3 trials of all 6 scenarios by default (not 1) - each scenario only
produces 12-40 flows per trial, and this project has seen the same
model/scenario swing by 20+ percentage points between single-trial runs
purely from that sample size (not because the model changed). Multiple
trials give both a pooled combined-N result (more flows -> tighter
percentages) and an explicit trial-to-trial consistency report (mean +/-
std per model/scenario, flagging std > 15 percentage points) - so a
single lucky/unlucky run can't be mistaken for a stable finding.

Usage:
    python simulate_attacks_rigorous.py [out_dir] [trials]
    python simulate_attacks_rigorous.py                       # 3 trials, default out dir
    python simulate_attacks_rigorous.py my_results 25         # 25 trials, custom out dir
"""

import http.client
import json
import os
import random
import socket
import string
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

import requests
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import send

API_BASE = "http://127.0.0.1:8000"
VICTIM_HTTP_PORT = 8899
POLL_INTERVAL = 0.5
DRAIN_SECONDS = 35  # >= FlowManager's active_timeout + margin - raised from 25s since scoring now runs
                     # 10 models per flow (was 4), and slower per-flow processing under load was
                     # observed to shrink the number of flows captured per run
# >= FlowManager's active_timeout(20s), same margin as DRAIN_SECONDS. The
# previous 2s inter-scenario gap was far too short: ICMP packets all hash
# to the SAME flow key regardless of timing (get_flow_key hardcodes
# src_port=dst_port=0 for ICMP - no per-connection disambiguation), so
# with only 2s between scenario_benign_baseline's few pings and
# scenario_icmp_flood's barrage against the same target, a benign ping
# flow that hadn't yet been swept by the (synchronous, can-fall-behind-
# under-load) expiry worker would still be "active" when the flood
# started, and the flood's packets got appended to that SAME flow object
# - merging benign and attack traffic into one flow with corrupted ground
# truth. Confirmed as the cause of the wild trial-to-trial specificity
# swings the 25-feature models showed even after the attribution fix.
SCENARIO_GAP_SECONDS = 35
TRIAL_COOLDOWN = 5   # gap between trials, so one trial's tail flows don't bleed into the next trial's window
RESULTS_DIR = "simulation_results"  # one JSON file per attack type, for demo/visualization use
SCORING_DRAIN_POLL_SECONDS = 3
SCORING_DRAIN_MAX_WAIT_SECONDS = 300  # generous cap - never block forever if something's stuck


def _wait_for_scoring_drain():
    """Poll /status's scoring_queue_depth until the backend has actually
    finished scoring every flow it has captured, instead of guessing a
    fixed sleep. _scoring_worker runs 10 models + SHAP + 5 agents per flow
    - far slower than flow-creation rate during a flood - so a fixed
    DRAIN_SECONDS sleep can leave a real backlog undrained. Confirmed live:
    after a full 3-trial run, SYN flood/UDP flood/port scan (all after
    ICMP flood in schedule order) showed ZERO scored flows in /history
    minutes after the run "finished" - not because nothing was captured,
    but because a deep HTTP-flood backlog was still being worked through
    by a single scoring thread, and the fixed 35s drain gave up long
    before it cleared. Capped so a genuinely stuck backend can't hang this
    script forever - if the cap is hit, results legitimately reflect an
    unfinished backlog and that's printed so it isn't silently trusted."""
    print("waiting for the backend's scoring backlog to drain ...")
    waited = 0.0
    last_depth = None
    while waited < SCORING_DRAIN_MAX_WAIT_SECONDS:
        try:
            depth = requests.get(f"{API_BASE}/status", timeout=5).json().get("scoring_queue_depth")
        except Exception:
            depth = None
        if depth == 0:
            print(f"  scoring backlog drained after {waited:.0f}s")
            return
        if depth != last_depth:
            print(f"  scoring_queue_depth={depth} (waited {waited:.0f}s) ...")
            last_depth = depth
        time.sleep(SCORING_DRAIN_POLL_SECONDS)
        waited += SCORING_DRAIN_POLL_SECONDS
    print(f"  WARNING: scoring backlog did not drain within {SCORING_DRAIN_MAX_WAIT_SECONDS}s "
          f"(last depth={last_depth}) - results below may be missing flows still queued for scoring")


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
    # BaseHTTPRequestHandler defaults to HTTP/1.0, which closes the
    # connection after every response regardless of a client's
    # "Connection: keep-alive" header - real GoldenEye/Slowloris hold
    # connections open across many requests (confirmed against real
    # CICIDS2018 rows: median Flow Duration ~7s here vs ~4ms this
    # server previously produced), which needs the server side to
    # actually support persistence too, not just the client asking for it.
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass  # keep stdout clean


def start_victim_server():
    # Plain HTTPServer is single-threaded - fine for the old fire-and-
    # close-instantly HTTP flood (one request at a time, briefly), but
    # scenario_http_flood's workers now each hold a PERSISTENT connection
    # open for the whole scenario (see _hulk_style_worker) - several
    # concurrent long-lived connections need the server to actually
    # service them concurrently, or the ones queued behind another
    # connection's keep-alive wait time out and abort.
    server = ThreadingHTTPServer((TARGET_IP, VICTIM_HTTP_PORT), _QuietHandler)
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
    trial: int = 1  # which repeated trial produced this scenario instance


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



# Real HTTP-flood tools (Hulk, GoldenEye) don't just loop plain GETs
# sequentially from one connection - they run many CONCURRENT connections,
# rotate a pool of real browser User-Agents, cache-bust with a random
# query string per request (defeats any caching layer, and is a
# documented Hulk/GoldenEye signature), and force "Connection: close" so
# each request is its own fresh flow rather than one long-lived kept-alive
# session. A single sequential loop of identical bare GETs is structurally
# closer to one browser tab refreshing than to a DoS tool.
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]
_REFERER_POOL = [
    "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
    "https://www.facebook.com/", "https://t.co/",
]


def _hulk_style_worker(stop_time, headers_sent):
    """Holds ONE persistent (keep-alive) connection open for the whole
    scenario, pacing requests seconds apart instead of firing as fast as
    possible - real GoldenEye/Slowloris exhaust a server by keeping many
    connections alive over time, not by maximizing throughput on each
    one. Confirmed against real CICIDS2018 GoldenEye/Slowloris rows:
    median Flow Duration ~7s and Flow IAT Mean ~1.6s with real
    variation (iat_variation ~1.74) - a fire-and-close-instantly loop
    (the previous version) produced ~4ms flows with near-zero, near-
    uniform IATs, nothing like the real attack's statistical signature."""
    conn = http.client.HTTPConnection(TARGET_IP, VICTIM_HTTP_PORT, timeout=2)
    try:
        while time.time() < stop_time:
            try:
                cache_bust = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
                headers = {
                    "User-Agent": random.choice(_UA_POOL),
                    "Referer": random.choice(_REFERER_POOL),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "keep-alive",
                }
                conn.request("GET", f"/?{cache_bust}", headers=headers)
                conn.getresponse().read()
                headers_sent[0] += 1
            except Exception:
                # server/OS may have dropped the connection - reopen and
                # keep going rather than ending this worker early
                try:
                    conn.close()
                except Exception:
                    pass
                conn = http.client.HTTPConnection(TARGET_IP, VICTIM_HTTP_PORT, timeout=2)
            time.sleep(random.uniform(0.5, 2.5))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def scenario_http_flood(duration=10, concurrency=20):
    start = time.time()
    stop_time = start + duration
    headers_sent = [0]
    threads = [threading.Thread(target=_hulk_style_worker, args=(stop_time, headers_sent))
               for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return Scenario("HTTP flood", True, TARGET_IP, {VICTIM_HTTP_PORT}, start, time.time())


def scenario_port_scan(duration=10):
    # Real SYN-scan tools (Nmap -sS default) never complete the TCP
    # handshake - they send a bare SYN and read the response (SYN-ACK =
    # open, RST = closed), then move on. A full connect() + immediate
    # close (the old implementation) generates a real handshake's worth of
    # ACK/FIN/RST traffic per port that a genuine half-open scan never
    # produces - a structurally different packet/flag signature than what
    # the model's training data (generated by real scanning tools) likely
    # contains. Uses raw SYN packets, one fixed source port for the whole
    # scan (matches real scanner behavior, and this project's own
    # SYN-flood scenario's reasoning for not fragmenting flows), stepping
    # through the port range as fast as the scan tool would.
    start = time.time()
    ports = list(range(9900, 9900 + 60))
    src_port = 40002
    end = start + duration
    while time.time() < end:
        for p in ports:
            send(IP(dst=TARGET_IP) / TCP(sport=src_port, dport=p, flags="S"), verbose=0)
            if time.time() >= end:
                break
    return Scenario("Port scan", True, TARGET_IP, set(ports), start, time.time())


_BENIGN_PATHS = [
    "/", "/index.html", "/favicon.ico", "/robots.txt", "/health",
    "/status", "/about", "/api/ping", "/static/style.css", "/login",
    "/search?q=weather", "/images/logo.png", "/api/v1/users",
    "/docs", "/contact", "/news", "/products", "/cart",
]


def scenario_benign_baseline(duration=12):
    start = time.time()
    # A few normal, human-paced pings ...
    send(IP(dst=TARGET_IP) / ICMP(), count=4, inter=1, verbose=0)
    # ... and a realistic mix of ordinary, varied-path HTTP requests. Each
    # bare requests.get() call opens its own TCP connection (no session/
    # connection pooling across separate calls, so a fresh ephemeral
    # source port every time) - that's what actually grows the benign
    # SAMPLE SIZE, not scenario duration: sending more packets to the same
    # (src_port, dst_port) pair just makes one larger flow, not more flows,
    # under this project's 5-tuple flow key (feature_extraction/
    # flow_builder.py). Randomized path order, not N identical GETs, so
    # the benign class isn't a single repeated pattern - a small step
    # toward the path/protocol diversity real background traffic has that
    # a handful of identical requests never could.
    for path in random.sample(_BENIGN_PATHS, len(_BENIGN_PATHS)):
        try:
            requests.get(f"http://{TARGET_IP}:{VICTIM_HTTP_PORT}{path}", timeout=2)
        except Exception:
            pass
        time.sleep(0.35)
    # dst_ports={0, VICTIM_HTTP_PORT}, NOT the empty-set "any port
    # matches" wildcard this used to be (0 = ICMP's port-less flows, per
    # _first_packet_dst_port; VICTIM_HTTP_PORT = the actual HTTP requests
    # above) - the wildcard was sweeping in the test harness's OWN
    # /history + /status polling traffic (Poller hits API_BASE, port
    # 8000, every 0.5s - real captured loopback traffic, indistinguishable
    # from "live" traffic to the sniffer) and unrelated Windows background
    # noise, scoring both as if they were genuine benign user traffic.
    # Confirmed live: port 8000 self-polling traffic showed 21.4%
    # specificity (n=70, dominating the aggregate) while the ACTUAL
    # scripted ICMP/HTTP benign traffic was 100% correct (n=4) - the
    # model was never wrong about real benign traffic, only about traffic
    # this scenario should never have claimed credit (or blame) for.
    return Scenario("Benign baseline", False, TARGET_IP, {0, VICTIM_HTTP_PORT}, start, time.time())


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
FAMILY_KEYS = ["raw_flood", "reflection", "connection_application_layer"]
RL_KEYS = ["rl_verdict_classifier"]
TEMPORAL25_KEYS = ["temporal25_candidate"]
V8_KEYS = ["v8_candidate"]


@dataclass
class ObservedFlow:
    flow_id: object
    source_ip: str
    destination_ip: str
    destination_port: object
    observed_at: float
    hybrid_prediction: int
    variant1: dict
    variant2: dict
    variant3: dict
    candidates: dict = field(default_factory=dict)  # classifier_comparison.ipynb models, keyed by CANDIDATE_KEYS
    families: dict = field(default_factory=dict)  # train_attack_family_models.py models, keyed by FAMILY_KEYS
    rl_verdict: dict = field(default_factory=dict)  # rl_cicids_combined_classifier.py, keyed by RL_KEYS
    temporal25: dict = field(default_factory=dict)  # train_temporal25_candidate.py, keyed by TEMPORAL25_KEYS
    v8: dict = field(default_factory=dict)  # paper's validated V8 baseline (review-integration branch), keyed by V8_KEYS


def _model_result(flow, model_key):
    """Single lookup path for every model key (the 4 original + the 3
    classifier_comparison candidates + the 3 attack-family models), used
    by scoring/reporting/dump so they don't each need their own if/elif
    chain over model kinds."""
    if model_key == "deployed_hybrid":
        pred = flow.hybrid_prediction
        return pred is not None, pred
    if model_key in CANDIDATE_KEYS:
        entry = flow.candidates.get(model_key, {})
    elif model_key in FAMILY_KEYS:
        entry = flow.families.get(model_key, {})
    elif model_key in RL_KEYS:
        entry = flow.rl_verdict.get(model_key, {})
    elif model_key in TEMPORAL25_KEYS:
        entry = flow.temporal25.get(model_key, {})
    elif model_key in V8_KEYS:
        entry = flow.v8.get(model_key, {})
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
                destination_port=entry.get("destination_port"),
                # flow_start_time (real Npcap capture time) not recorded_at
                # (when this flow was SCORED) - under a scoring backlog the
                # two diverge by minutes, and recorded_at-based matching
                # was silently dropping delayed flows out of every
                # scenario's ~26s window entirely (0 flows attributed)
                # rather than just mis-timing them. Falls back to
                # recorded_at only for a backend running before this field
                # existed.
                observed_at=entry.get("flow_start_time") or entry.get("recorded_at") or time.time(),
                hybrid_prediction=entry.get("hybrid_prediction"),
                variant1=entry.get("variant1_xgb_single_flow", {}),
                variant2=entry.get("variant2_xgb_temporal", {}),
                variant3=entry.get("variant3_cnn_lstm", {}),
                candidates=entry.get("candidate_models", {}),
                families=entry.get("family_models", {}),
                rl_verdict={"rl_verdict_classifier": entry.get("rl_verdict_classifier", {})},
                temporal25={"temporal25_candidate": entry.get("temporal25_candidate", {})},
                v8={"v8_candidate": entry.get("v8_candidate", {})},
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
    """A flow's observed_at (when FlowManager finally closes it) lags when
    its packets were actually sent by up to `slack` = active_timeout +
    flow_timeout + 2*POLL_INTERVAL - real, unavoidable draining delay.
    But scenarios run only ~10s each, ~2s apart, so that same slack means
    a flow generated by scenario N can still fall inside scenario N-1's
    (or N-2's) match window too. Taking the FIRST matching scenario in
    schedule order - the previous behavior - always resolves that overlap
    in favor of the EARLIER scenario, which is backwards: a flow lands in
    a later timestamp because it drained late, so the correct read of the
    same overlap is the LATEST (most recent) matching scenario, not the
    earliest. Confirmed wrong via a live-test run where "Benign baseline"
    flows' timestamps landed inside the immediately-following ICMP-flood
    and SYN-flood windows, corrupting specificity for every model scored
    (not the model's own fault - the ground-truth label was wrong).

    Also filters on destination port (Scenario.dst_ports - "empty set =
    any port matches", per its own field comment) - previously defined
    but never actually checked here, so attribution was really just IP +
    timing. Since every scenario targets the same TARGET_IP, the IP check
    filtered nothing, and ANY loopback traffic landing in a scenario's
    time window - confirmed via direct capture to include unrelated
    background chatter on this machine (periodic local TCP connections
    on ports uninvolved in any scenario) - got attributed as that
    scenario's ground truth. A benign background flow scored "correct"
    only if a model happened to guess ATTACK; every model that correctly
    called it benign was marked wrong against a fabricated attack label.
    This was silently corrupting recall/specificity for every scenario in
    every prior test run, and unlike the scenario-overlap bug above isn't
    bounded to a boundary window - unrelated traffic anywhere inside a
    whole scenario's own window could be swept in."""
    slack = active_timeout + flow_timeout + POLL_INTERVAL * 2
    attributed = {s.name: [] for s in scenarios}

    for flow in flows:
        candidates = [
            s for s in scenarios
            if flow.destination_ip == s.dst_ip
            and (not s.dst_ports or flow.destination_port in s.dst_ports)
            and s.start_time - 1 <= flow.observed_at <= s.end_time + slack
        ]
        if not candidates:
            continue
        best = max(candidates, key=lambda s: s.start_time)
        attributed[best.name].append(flow)

    return attributed


# =====================================================
# Scoring
# =====================================================

MODEL_KEYS = (["deployed_hybrid", "variant1_xgb_single_flow", "variant2_xgb_temporal", "variant3_cnn_lstm"]
              + CANDIDATE_KEYS + FAMILY_KEYS + RL_KEYS + TEMPORAL25_KEYS + V8_KEYS)
MODEL_LABELS = {
    "deployed_hybrid": "Deployed hybrid",
    "variant1_xgb_single_flow": "Var1 XGB single-flow",
    "variant2_xgb_temporal": "Var2 XGB temporal",
    "variant3_cnn_lstm": "Var3 CNN+LSTM",
    "xgboost": "Candidate: XGBoost",
    "random_forest": "Candidate: Random Forest",
    "histgradientboosting": "Candidate: HistGradientBoosting",
    "raw_flood": "Family: Raw Flood",
    "reflection": "Family: Reflection",
    "connection_application_layer": "Family: Connection",
    "rl_verdict_classifier": "RL verdict (bandit)",
    "temporal25_candidate": "Candidate: 25feat+temporal",
    "v8_candidate": "V8 (paper baseline)",
}


def score(attributed, scenarios):
    """scenarios may contain multiple trials' worth of Scenario objects
    sharing the same name (attribute_flows already pools their flows
    together by name) - iterate unique names only, or this prints the
    same pooled row once per trial instead of once per scenario."""
    rows = []
    seen = set()
    unique_scenarios = [s for s in scenarios if not (s.name in seen or seen.add(s.name))]

    for s in unique_scenarios:
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


# Which live scenarios fall inside each attack-family model's own trained
# specialty (see train_attack_family_models.py). aggregate_metrics() above
# pools every model against every scenario - correct for the generalist
# models (deployed hybrid, variants, classifier candidates), but unfair to
# the family models: Raw Flood was never trained to recognize HTTP floods
# or port scans, so being tested against them and missing isn't a
# meaningful measure of whether it does ITS job well.
#
# Caveat, kept visible rather than hidden: none of the 6 live scenarios are
# a true reflection/amplification attack (spoofed request, large real
# response from a reflector) - the simulator only generates raw crafted
# packets. ICMP/SYN/UDP flood is the closest available proxy for BOTH
# raw_flood and reflection (both are connectionless floods at the packet
# level), so reflection's family-aware score below still isn't a fair test
# of its actual intended use case - it just removes the doubly-unfair
# penalty of also being scored against HTTP flood/port scan.
FAMILY_SCENARIO_SPECIALTY = {
    "raw_flood": {"ICMP flood", "SYN flood", "UDP flood"},
    "reflection": {"ICMP flood", "SYN flood", "UDP flood"},
    "connection_application_layer": {"HTTP flood", "Port scan"},
}


def family_aware_metrics(attributed, scenarios):
    """Same confusion-matrix/metrics computation as aggregate_metrics, but
    for each family model, attack scenarios outside FAMILY_SCENARIO_SPECIALTY
    are excluded entirely (not counted as misses) rather than pooled in.
    The benign baseline is never excluded - specificity is scenario-
    independent (falsely flagging benign traffic is a miss regardless of
    which family "should" have caught it)."""
    scenarios_by_name = {s.name: s for s in scenarios}
    metrics = {}

    for model, specialty in FAMILY_SCENARIO_SPECIALTY.items():
        tp = fp = tn = fn = 0
        for name, flows in attributed.items():
            is_attack = scenarios_by_name[name].is_attack
            if is_attack and name not in specialty:
                continue
            expected = 1 if is_attack else 0
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
            "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1,
            "specificity": specificity, "total_flows": total,
            "specialty_scenarios": sorted(specialty),
        }

    return metrics


def print_family_aware_metrics(metrics):
    print("\n" + "=" * 100)
    print("FAMILY-SPECIALTY-AWARE METRICS (each family scored only on its own trained attack types)")
    print("=" * 100)
    for model, specialty in FAMILY_SCENARIO_SPECIALTY.items():
        label = MODEL_LABELS[model]
        m = metrics[model]
        cm = m["confusion_matrix"]

        def fmt(v):
            return f"{v * 100:.1f}%" if v is not None else "n/a"

        print(f"\n{label}  ({m['total_flows']} flows; scenarios counted: {', '.join(m['specialty_scenarios'])} + Benign baseline)")
        print(f"  confusion matrix: TP={cm['tp']}  FP={cm['fp']}  TN={cm['tn']}  FN={cm['fn']}")
        print(f"  accuracy={fmt(m['accuracy'])}  precision={fmt(m['precision'])}  "
              f"recall={fmt(m['recall'])}  f1={fmt(m['f1'])}  specificity={fmt(m['specificity'])}")
    print("=" * 100)
    print("reflection has no true reflection/amplification scenario available (simulator only generates raw")
    print("packets) - ICMP/SYN/UDP flood is the closest connectionless-flood proxy, not a fair test of its")
    print("actual intended use case. Non-family models (deployed hybrid, variants, candidates) are intentionally")
    print("excluded here - they're generalists and should be judged by the OVERALL METRICS above, not a subset.")


def per_trial_scores(poller_flows, scenarios, n_trials):
    """Scores each trial independently (not pooled) so run-to-run spread
    is visible, not just the combined N-trials-pooled numbers. Returns
    {scenario_name: {model_key: [recall/specificity per trial that had
    any attributed flows]}}."""
    by_name = {s.name: {mk: [] for mk in MODEL_KEYS} for s in scenarios}
    for trial in range(1, n_trials + 1):
        trial_scenarios = [s for s in scenarios if s.trial == trial]
        if not trial_scenarios:
            continue
        attributed = attribute_flows(poller_flows, trial_scenarios)
        rows = score(attributed, trial_scenarios)
        for name, _is_attack, _n_flows, results in rows:
            for mk in MODEL_KEYS:
                if results[mk] is not None:
                    by_name[name][mk].append(results[mk])
    return by_name


def print_trial_consistency(poller_flows, scenarios, n_trials):
    """A single trial's percentages can look decisive purely from a small
    sample (12-40 flows per scenario) - this reports mean +/- population
    std across trials PLUS the raw per-trial values, so a swing that's
    actually just noise (e.g. 94.5% specificity one run, 82.2% the next,
    on the same model/scenario) is visible instead of silently trusted."""
    if n_trials < 2:
        print("\n(single trial run - see RUNNING.md / pass a trial count as the 2nd argument "
              "to check run-to-run stability, e.g. `python simulate_attacks.py out_dir 5`)")
        return

    by_name = per_trial_scores(poller_flows, scenarios, n_trials)
    print("\n" + "=" * 100)
    print(f"TRIAL-TO-TRIAL CONSISTENCY ({n_trials} trials, scored independently - not pooled)")
    print("=" * 100)
    for name, per_model in by_name.items():
        print(f"\n{name}:")
        for mk in MODEL_KEYS:
            vals = per_model[mk]
            if not vals:
                print(f"  {MODEL_LABELS[mk]:<28} no flows in any trial")
                continue
            mean = sum(vals) / len(vals)
            std = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5 if len(vals) > 1 else 0.0
            per_trial_str = ", ".join(f"{v * 100:.0f}%" for v in vals)
            flag = "  <-- high variance" if std > 0.15 else ""
            print(f"  {MODEL_LABELS[mk]:<28} {mean * 100:5.1f}% +/- {std * 100:4.1f}%  "
                  f"(trials: {per_trial_str}){flag}")
    print("=" * 100)
    print("high variance (std > 15pp) means don't trust a single-trial percentage for that model/scenario.")


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

def dump_results(rows, attributed, scenarios, out_dir=RESULTS_DIR, aggregate=None, family_aware=None):
    """Scenario names repeat across trials (attribute_flows already pools
    same-named scenarios' flows together by design - see its docstring) -
    so a plain {s.name: s} dict here would silently keep only the LAST
    trial's start/end window and drop every earlier trial's. Track the
    full list of trial windows per name instead."""
    os.makedirs(out_dir, exist_ok=True)

    windows_by_name = {}
    is_attack_by_name = {}
    for s in scenarios:
        windows_by_name.setdefault(s.name, []).append(
            {"trial": s.trial, "start_time": s.start_time, "end_time": s.end_time,
             "duration_seconds": s.end_time - s.start_time}
        )
        is_attack_by_name[s.name] = s.is_attack

    rows_by_name = {name: (is_attack, n_flows, results) for name, is_attack, n_flows, results in rows}

    summary = {"generated_at": time.time(), "target_ip": TARGET_IP, "trials": max(s.trial for s in scenarios),
               "scenarios": [], "aggregate_metrics": aggregate or {}, "family_aware_metrics": family_aware or {}}

    for name, windows in windows_by_name.items():
        is_attack = is_attack_by_name[name]
        _, n_flows, results = rows_by_name[name]
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
                "destination_port": f.destination_port,
                "observed_at": f.observed_at,
                "models": per_model
            })

        scenario_record = {
            "name": name,
            "is_attack": is_attack,
            "trial_windows": windows,
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

    print(f"\nwrote {len(windows_by_name)} per-attack-type files + summary.json to {out_dir}/")


# =====================================================
# Main
# =====================================================

def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else RESULTS_DIR
    # Default to 3 trials rather than 1: a single pass gives each scenario
    # only 12-40 flows, and consecutive live runs in this project have
    # shown the same model/scenario swing by 20+ percentage points run to
    # run (e.g. Random Forest specificity 94.5% -> 82.2%) purely from that
    # small sample size - not because anything about the model changed.
    trials = int(sys.argv[2]) if len(sys.argv) > 2 else 3

    print(f"Target (this machine's real NIC IP): {TARGET_IP}")
    print(f"Running {trials} trial(s) of all {len(SCENARIOS)} scenarios ({trials * len(SCENARIOS)} scenario runs total)")
    print("Checking backend is reachable ...")
    requests.get(f"{API_BASE}/status", timeout=5).raise_for_status()
    print("Backend OK. Starting local victim HTTP server ...")
    start_victim_server()

    poller = Poller()
    poller.start()

    scenarios = []
    for trial in range(1, trials + 1):
        print(f"\n{'#' * 20} TRIAL {trial}/{trials} {'#' * 20}")
        for fn in SCENARIOS:
            print(f"\nrunning scenario: {fn.__name__} ...")
            s = fn()
            s.trial = trial
            scenarios.append(s)
            print(f"  {s.name}: {s.start_time:.1f} -> {s.end_time:.1f} ({s.end_time - s.start_time:.1f}s)")
            print(f"  draining {SCENARIO_GAP_SECONDS}s before the next scenario (flow-key collision margin) ...")
            time.sleep(SCENARIO_GAP_SECONDS)
        if trial < trials:
            print(f"\ncooling down {TRIAL_COOLDOWN}s between trials ...")
            time.sleep(TRIAL_COOLDOWN)

    print(f"\ndraining ({DRAIN_SECONDS}s, letting the last flows expire) ...")
    time.sleep(DRAIN_SECONDS)
    _wait_for_scoring_drain()
    poller.stop()

    print(f"\ntotal distinct flows observed across all trials: {len(poller.flows)}")
    attributed = attribute_flows(poller.flows, scenarios)
    for name in dict.fromkeys(s.name for s in scenarios):  # unique names, first-seen order
        print(f"  {name}: {len(attributed[name])} flows attributed (pooled across {trials} trial(s))")

    rows = score(attributed, scenarios)
    print_report(rows)

    metrics = aggregate_metrics(attributed, scenarios)
    print_aggregate_metrics(metrics)

    family_metrics = family_aware_metrics(attributed, scenarios)
    print_family_aware_metrics(family_metrics)

    print_trial_consistency(poller.flows, scenarios, trials)

    dump_results(rows, attributed, scenarios, out_dir=out_dir, aggregate=metrics, family_aware=family_metrics)


if __name__ == "__main__":
    main()
