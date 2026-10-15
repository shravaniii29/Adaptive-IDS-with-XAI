"""
FastAPI backend for the Network IDS project.

Connects the live packet-capture pipeline to the
agentic IDS layer and exposes results to the dashboard.
"""

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import threading
import asyncio
import queue
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from detection.detection_service import DetectionService
from feature_extraction.flow_manager import FlowManager
from packet_capture.capture import start_capture

from app.state import AppState


# =====================================================
# GLOBAL STATE
# =====================================================

state = AppState()

# IDS_LIGHTWEIGHT_SCORING=1 skips SHAP explainability + the 5-agent
# orchestration layer per flow - see DetectionService.__init__ for why.
# Set for simulate_attacks.py-style load testing; leave unset (default:
# full pipeline) for the real interactive dashboard demo, or when
# debugging the SHAP/agent output itself.
_LIGHTWEIGHT_SCORING = os.environ.get("IDS_LIGHTWEIGHT_SCORING", "").lower() in ("1", "true", "yes")

detection_service = DetectionService(lightweight=_LIGHTWEIGHT_SCORING)

flow_manager = FlowManager(
    flow_timeout=5
)

EXPIRY_POLL_INTERVAL_SECONDS = 1

# Completed flows waiting to be scored, decoupled from the expiry worker
# (see _scoring_worker docstring for why this queue exists).
_completed_flow_queue = queue.Queue()


# =====================================================
# FLOW PROCESSING
# =====================================================

# Loopback flows (127.x <-> 127.x) never leave this machine: they are
# programs talking to each other. On a normal desktop they are mostly noise -
# the dashboard polling this backend, this backend's own event-loop wake-up
# connection, vendor background services - and the models, trained on
# network flows, flag a large share of them (in one observed session 16 of
# 20 loopback flows against 0 of 27 real network flows, and the dashboard's
# own polling was 112 of 174 flows). So loopback flows are skipped by
# default and counted in /status as ignored_loopback_flows.
#
# The attack simulation has to be aimed at loopback (Windows does not
# deliver a machine's traffic to its own LAN address to any capture point),
# so it targets a dedicated "lab" loopback address instead of 127.0.0.1:
# every 127.x.x.x address is loopback on Windows. Loopback flows to or from
# the lab address are always scored; every other loopback flow is ignored.
# That separates the simulation's traffic from desktop noise permanently -
# no toggle, timer or port list, nothing to change for a demo, and it also
# covers attacks started by hand against the lab address (default
# 127.0.0.77, change with IDS_LAB_ADDRESS; simulate_attacks.py reads the
# same variable). Set IDS_IGNORE_LOOPBACK=0 to score all loopback traffic.
_IGNORE_LOOPBACK = os.environ.get("IDS_IGNORE_LOOPBACK", "1").strip().lower() not in ("0", "false", "no")
_LAB_ADDRESS = os.environ.get("IDS_LAB_ADDRESS", "127.0.0.77").strip()
# Addresses whose loopback flows are scored: the default lab address plus any
# target chosen for a simulation run from the dashboard (kept until restart).
_lab_addresses = {_LAB_ADDRESS}
_ignored_flow_count = 0


def _is_loopback(ip):
    return ip is not None and (str(ip).startswith("127.") or str(ip) == "::1")


def _is_ignorable_loopback_traffic(flow):

    if not _IGNORE_LOOPBACK:

        return False

    if not (_is_loopback(flow.src_ip) and _is_loopback(flow.dst_ip)):

        return False

    return not _lab_addresses.intersection((str(flow.src_ip), str(flow.dst_ip)))


def _handle_completed_flow(flow):

    global _ignored_flow_count

    if _is_ignorable_loopback_traffic(flow):

        _ignored_flow_count += 1

        return

    try:

        result = detection_service.detect(flow)

    except Exception as exc:

        state.record_error(str(exc))

        return

    # Store complete IDS + agentic result
    state.record_result(result)

    # Push result to dashboard
    state.broadcast_soon(result)


# =====================================================
# PACKET CAPTURE WORKER
# =====================================================

def _capture_worker():

    """
    Continuously captures live packets and feeds
    them into the FlowManager.
    """

    try:

        start_capture(
            flow_manager.process_packet,
            packet_count=0
        )

    except Exception as exc:

        state.record_error(
            f"Capture thread stopped: {exc}"
        )


# =====================================================
# FLOW EXPIRY WORKER
# =====================================================

def _expiry_worker():

    """
    Periodically checks for completed flows.

    A flow becomes complete when it has been
    inactive for flow_timeout seconds.

    Only removes expired flows from FlowManager and hands them off to the
    scoring queue - never scores them itself. Scoring (detection_service
    .detect(), which runs every model including the RL verdict classifier)
    can take long enough under load that doing it inline here used to let
    this loop fall behind on its 1s cadence. Since FlowManager keys ICMP
    packets by (src_ip, dst_ip) alone - no port, so every ICMP packet
    between the same two hosts collides on one flow key regardless of
    timing - a delayed expiry check let a stale-but-not-yet-swept flow
    (e.g. a few benign pings) still be sitting in active_flows when
    unrelated new ICMP traffic (e.g. a flood) arrived moments later,
    silently merging the two into one flow with corrupted ground truth.
    Keeping this loop free of scoring work means a flow is removed from
    active_flows within ~1s of going idle no matter how backlogged
    scoring gets, so new packets on that same key correctly start a fresh
    Flow instead of extending a stale one.
    """

    while True:

        time.sleep(
            EXPIRY_POLL_INTERVAL_SECONDS
        )

        try:

            expired_flows = (
                flow_manager.get_expired_flows()
            )

        except Exception as exc:

            state.record_error(str(exc))

            continue

        for _key, flow in expired_flows:

            _completed_flow_queue.put(flow)


def _scoring_worker():

    """
    Scores completed flows off of the queue _expiry_worker fills, on its
    own thread - see _expiry_worker's docstring for why scoring must not
    happen inline there. A backlog here only delays when a result shows
    up (dashboard/API), which is a far smaller problem than the flow-key
    collision letting scoring delay cause.
    """

    while True:

        flow = _completed_flow_queue.get()

        _handle_completed_flow(flow)


# =====================================================
# FASTAPI LIFESPAN
# =====================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    state.loop = asyncio.get_event_loop()

    # Start packet capture
    capture_thread = threading.Thread(
        target=_capture_worker,
        daemon=True
    )

    capture_thread.start()

    # Start flow expiry checking
    expiry_thread = threading.Thread(
        target=_expiry_worker,
        daemon=True
    )

    expiry_thread.start()

    # Start flow scoring (decoupled from expiry timing - see
    # _expiry_worker/_scoring_worker docstrings)
    scoring_thread = threading.Thread(
        target=_scoring_worker,
        daemon=True
    )

    scoring_thread.start()

    state.start_time = time.time()

    yield


# =====================================================
# FASTAPI APPLICATION
# =====================================================

app = FastAPI(
    title="Network IDS API",
    lifespan=lifespan
)


# =====================================================
# CORS
# =====================================================

app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_methods=["*"],

    allow_headers=["*"],
)


# =====================================================
# STATUS ENDPOINT
# =====================================================

@app.post("/clear")
def clear_stats():
    """Dashboard "Clear Stats": zero the counters and forget the buffered
    flow history. The dashboard's button calls this; it previously existed
    only in the demo backend (app/demo_main.py), so on the real backend the
    button silently did nothing."""

    with state.lock:

        state.last_result = None

        state.result_history.clear()

        state.last_error = None

    detection_service.reset_statistics()

    return {"status": "cleared"}


class ModeRequest(BaseModel):
    mode: str


@app.get("/mode")
def get_mode():
    """Which model is the primary detector, and which modes can be chosen."""

    return {
        "mode": detection_service.mode,
        "modes": detection_service.available_modes(),
    }


@app.post("/mode")
def set_mode(request: ModeRequest):
    """Choose which model's results the dashboard shows ("confidence" or
    "v8"). Both models score every flow all the time, so this only switches
    the view: it applies instantly, to past flows as well as new ones, and
    nothing is lost or reset."""

    try:

        detection_service.set_mode(request.mode)

    except ValueError as exc:

        raise HTTPException(status_code=400, detail=str(exc))

    state.view_mode = detection_service.mode

    return {
        "mode": detection_service.mode,
        "modes": detection_service.available_modes(),
    }


@app.get("/status")
def get_status():

    statistics = (
        detection_service.get_statistics()
    )

    return {

        **statistics,

        "ignored_loopback_flows":
            _ignored_flow_count,

        "ignore_loopback":
            _IGNORE_LOOPBACK,

        "lab_address":
            _LAB_ADDRESS,

        "lab_addresses":
            sorted(_lab_addresses),

        "last_error":
            state.last_error,

        # Flows waiting on _scoring_worker (10 models + SHAP + 5 agents per
        # flow - far slower than flow-creation rate under flood load, so
        # this can lag real time by minutes after a heavy test). Lets
        # callers like simulate_attacks.py wait for actual completion
        # instead of guessing a fixed drain time - confirmed via a live
        # test where a fixed 35s drain left SYN flood/UDP flood/port scan
        # with ZERO scored flows because their flows were still sitting
        # behind an undrained HTTP-flood backlog.
        "scoring_queue_depth":
            _completed_flow_queue.qsize()
    }


# =====================================================
# PREDICTION ENDPOINT
# =====================================================

@app.get("/predict")
def get_predict():

    if state.last_result is None:

        return {
            "message":
                "no flows processed yet"
        }

    result = state.last_result

    agent = result.get(
        "agent_analysis",
        {}
    )

    response = agent.get(
        "response",
        {}
    )

    explanation = agent.get(
        "explanation",
        {}
    )

    memory = agent.get(
        "memory",
        {}
    )

    consensus = agent.get(
        "consensus",
        {}
    )

    incident = agent.get(
        "incident_report",
        {}
    )

    return {

        # -----------------------------------------
        # Core Detection
        # -----------------------------------------

        "flow_id":
            result.get("flow_id"),

        "source_ip":
            result.get("source_ip"),

        "destination_ip":
            result.get("destination_ip"),

        "xgb_probability":
            result.get("xgb_probability"),

        "xgb_prediction":
            result.get("xgb_prediction"),

        "isolation_prediction":
            result.get("isolation_prediction"),

        "isolation_anomaly":
            result.get("isolation_anomaly"),

        "confidence_score":
            result.get("confidence_score"),

        "fusion_mode":
            result.get("fusion_mode"),

        "hybrid_prediction":
            result.get("hybrid_prediction"),

        # -----------------------------------------
        # Response Agent
        # -----------------------------------------

        "threat_level":
            response.get("threat_level"),

        "recommended_action":
            response.get("action"),

        "response_reason":
            response.get("reason"),

        "alert":
            response.get("alert"),

        # -----------------------------------------
        # Explainability Agent
        # -----------------------------------------

        "attack_hypothesis":
            explanation.get("attack_hypothesis"),

        "confidence":
            explanation.get("confidence"),

        "summary":
            explanation.get("summary"),

        "reasoning":
            explanation.get(
                "reasoning",
                []
            ),

        "supporting_features":
            explanation.get(
                "top_features",
                []
            ),

        "detailed_explanation":
            explanation.get(
                "detailed_report",
                []
            ),

        # -----------------------------------------
        # Memory Agent
        # -----------------------------------------

        "memory_pattern":
            memory.get("pattern"),

        "memory_risk":
            memory.get("risk"),

        "memory_confidence":
            memory.get("confidence"),

        "flows_in_memory":
            memory.get("flows_in_memory"),

        "recent_attacks":
            memory.get("recent_attacks"),

        "repeated_sources":
            memory.get("repeated_sources"),

        "memory_recommendation":
            memory.get("recommendation"),

        # -----------------------------------------
        # Consensus
        # -----------------------------------------

        "consensus_score":
            consensus.get("score"),

        "agreement_level":
            consensus.get("agreement"),

        # -----------------------------------------
        # Final Incident Report
        # -----------------------------------------

        "verdict":
            incident.get("verdict"),

        "overall_confidence":
            incident.get("confidence"),

        "incident_summary":
            incident.get("summary")
    }


# =====================================================
# DRIFT ENDPOINT
# =====================================================

@app.get("/drift")
def get_drift():

    if state.last_result is None:

        return {
            "message":
                "no flows processed yet"
        }

    result = state.last_result

    agent = result.get(
        "agent_analysis",
        {}
    )

    drift = agent.get(
        "drift",
        {}
    )

    return {

        "flow_id":
            result.get("flow_id"),

        "drift_detected":
            result.get("drift_detected"),

        "status":
            drift.get("status"),

        "severity":
            drift.get("severity"),

        "trend":
            drift.get("trend"),

        "recommendation":
            drift.get("recommendation")
    }


# =====================================================
# SHAP / EXPLAINABILITY ENDPOINT
# =====================================================

@app.get("/shap")
def get_shap():

    if state.last_result is None:

        return {
            "message":
                "no flows processed yet"
        }

    result = state.last_result

    agent = result.get(
        "agent_analysis",
        {}
    )

    explanation = agent.get(
        "explanation",
        {}
    )

    return {

        "flow_id":
            result.get("flow_id"),

        # NOTE: intentionally sends detailed_report here, not
        # explanation's own "top_features" key. "top_features" there is
        # a list of bare feature-name strings (used internally by
        # ExplainabilityAgent for hypothesis generation); the frontend's
        # ShapExplanation.top_features type expects the rich
        # {feature, value, impact} objects, which live in
        # detailed_report. Sending the bare-string list here made every
        # card show "Unknown feature" (item.feature/.impact undefined on
        # a plain string).
        "top_features":
            explanation.get(
                "detailed_report",
                []
            ),

        "confidence":
            explanation.get(
                "confidence"
            ),

        "attack_hypothesis":
            explanation.get(
                "attack_hypothesis"
            ),

        "summary":
            explanation.get(
                "summary"
            ),

        "reasoning":
            explanation.get(
                "reasoning",
                []
            ),

        "detailed_explanation":
            explanation.get(
                "detailed_report",
                []
            )
    }


# =====================================================
# BULK HISTORY ENDPOINT
#
# /predict and /experimental only ever reflect the single
# most recent flow. Under a burst of flows completing faster
# than a client's poll interval (e.g. a flood, or automated
# testing), polling only the "latest" silently misses most of
# them. This returns every buffered flow (up to
# AppState.max_history) with the same summary fields, so a
# client can poll less often and still see everything.
# =====================================================

@app.get("/history/{flow_id}")
def get_history_flow(flow_id: int):

    entries = state.get_history()

    match = next(
        (r for r in entries if r.get("flow_id") == flow_id),
        None
    )

    if match is None:

        return {
            "message":
                "flow not in history buffer"
        }

    agent = match.get(
        "agent_analysis",
        {}
    )

    explanation = agent.get(
        "explanation",
        {}
    )

    experimental = match.get(
        "experimental_models",
        {}
    )

    return {

        "flow_id":
            match.get("flow_id"),

        "source_ip":
            match.get("source_ip"),

        "destination_ip":
            match.get("destination_ip"),

        "hybrid_prediction":
            match.get("hybrid_prediction"),

        "xgb_probability":
            match.get("xgb_probability"),

        "xgb_prediction":
            match.get("xgb_prediction"),

        "isolation_prediction":
            match.get("isolation_prediction"),

        "attack_hypothesis":
            explanation.get("attack_hypothesis"),

        "confidence":
            explanation.get("confidence"),

        "summary":
            explanation.get("summary"),

        "variant1_xgb_single_flow":
            experimental.get(
                "variant1_xgb_single_flow",
                {}
            ),

        "variant2_xgb_temporal":
            experimental.get(
                "variant2_xgb_temporal",
                {}
            ),

        "variant3_cnn_lstm":
            experimental.get(
                "variant3_cnn_lstm",
                {}
            ),

        "rl_verdict_classifier":
            experimental.get(
                "rl_verdict_classifier",
                {}
            ),

        "top_features":
            explanation.get(
                "detailed_report",
                []
            )
    }


@app.get("/history")
def get_history():

    entries = state.get_history()

    summaries = []

    for result in entries:

        agent = result.get(
            "agent_analysis",
            {}
        )

        experimental = result.get(
            "experimental_models",
            {}
        )

        summaries.append({

            "flow_id":
                result.get("flow_id"),

            "recorded_at":
                result.get("recorded_at"),

            "source_ip":
                result.get("source_ip"),

            "destination_ip":
                result.get("destination_ip"),

            "destination_port":
                result.get("destination_port"),

            "flow_start_time":
                result.get("flow_start_time"),

            "hybrid_prediction":
                result.get("hybrid_prediction"),

            # The two detector outputs behind the hybrid decision.
            # The dashboard's Live Logs table seeds itself from this
            # endpoint and renders both ("AI check 1" / "AI check 2"),
            # so they must be present here as well as in /predict.
            "xgb_probability":
                result.get("xgb_probability"),

            "xgb_prediction":
                result.get("xgb_prediction"),

            "isolation_prediction":
                result.get("isolation_prediction"),

            "isolation_anomaly":
                result.get("isolation_anomaly"),

            "confidence_score":
                result.get("confidence_score"),

            "fusion_mode":
                result.get("fusion_mode"),

            "variant1_xgb_single_flow":
                experimental.get(
                    "variant1_xgb_single_flow",
                    {}
                ),

            "variant2_xgb_temporal":
                experimental.get(
                    "variant2_xgb_temporal",
                    {}
                ),

            "variant3_cnn_lstm":
                experimental.get(
                    "variant3_cnn_lstm",
                    {}
                ),

            "candidate_models":
                experimental.get(
                    "candidate_models",
                    {}
                ),

            "family_models":
                experimental.get(
                    "family_models",
                    {}
                ),

            "rl_verdict_classifier":
                experimental.get(
                    "rl_verdict_classifier",
                    {}
                ),

            "temporal25_candidate":
                experimental.get(
                    "temporal25_candidate",
                    {}
                ),

            "v8_candidate":
                experimental.get(
                    "v8_candidate",
                    {}
                )
        })

    return {"flows": summaries}


# =====================================================
# EXPERIMENTAL MODELS ENDPOINT
# =====================================================

@app.get("/experimental")
def get_experimental():

    if state.last_result is None:

        return {
            "message":
                "no flows processed yet"
        }

    result = state.last_result

    experimental = result.get(
        "experimental_models",
        {}
    )

    return {

        "flow_id":
            result.get("flow_id"),

        "source_ip":
            result.get("source_ip"),

        "destination_ip":
            result.get("destination_ip"),

        "disclaimer":
            experimental.get("disclaimer"),

        "variant1_xgb_single_flow":
            experimental.get(
                "variant1_xgb_single_flow",
                {}
            ),

        "variant2_xgb_temporal":
            experimental.get(
                "variant2_xgb_temporal",
                {}
            ),

        "variant3_cnn_lstm":
            experimental.get(
                "variant3_cnn_lstm",
                {}
            ),

        "rl_verdict_classifier":
            experimental.get(
                "rl_verdict_classifier",
                {}
            )
    }


# =====================================================
# MEMORY ENDPOINT
# =====================================================

@app.get("/memory")
def get_memory():

    if state.last_result is None:

        return {
            "message":
                "no flows processed yet"
        }

    agent = state.last_result.get(
        "agent_analysis",
        {}
    )

    memory = agent.get(
        "memory",
        {}
    )

    return {

        "pattern":
            memory.get("pattern"),

        "risk":
            memory.get("risk"),

        "confidence":
            memory.get("confidence"),

        "flows_in_memory":
            memory.get("flows_in_memory"),

        "recent_attacks":
            memory.get("recent_attacks"),

        "repeated_sources":
            memory.get("repeated_sources"),

        "recommendation":
            memory.get("recommendation")
    }


# =====================================================
# SYSTEM HEALTH ENDPOINT
# =====================================================

@app.get("/system")
def get_system():

    return {

        "status":
            "ok"
            if state.last_error is None
            else "degraded",

        "uptime_seconds":
            time.time() - state.start_time,

        "last_error":
            state.last_error
    }


# =====================================================
# SIMULATION RESULTS ENDPOINTS
#
# Serves simulate_attacks.py's saved summary.json output (per-scenario
# model_scores + aggregate_metrics + family_aware_metrics) to the
# dashboard, so a live-test run's results are visualizable there instead
# of only as printed console output. Read-only, off the local
# filesystem - the name path param is validated against directory
# traversal (alphanumeric/underscore/hyphen only, and the resolved path
# is checked to stay under PROJECT_ROOT) since it comes straight from
# the URL.
# =====================================================

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SIMULATION_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def _find_simulation_dirs():
    """Any project-root directory containing a summary.json shaped like
    simulate_attacks.py's dump_results() output (has "scenarios" and
    "aggregate_metrics") - not a hardcoded list, so any future live-test
    run shows up automatically without a backend change."""

    results = []

    for entry in _PROJECT_ROOT.iterdir():

        if not entry.is_dir() or not _SIMULATION_NAME_RE.match(entry.name):
            continue

        summary_path = entry / "summary.json"

        if not summary_path.exists():
            continue

        try:
            with open(summary_path, "r") as f:
                data = json.load(f)
            if "scenarios" not in data or "aggregate_metrics" not in data:
                continue
        except Exception:
            continue

        results.append({
            "name": entry.name,
            "generated_at": data.get("generated_at"),
            "trials": data.get("trials"),
            "target_ip": data.get("target_ip"),
            "scenario_count": len(data.get("scenarios", [])),
        })

    results.sort(key=lambda r: r.get("generated_at") or 0, reverse=True)

    return results


@app.get("/simulations")
def list_simulations():

    return {"simulations": _find_simulation_dirs()}


@app.get("/simulations/{name}")
def get_simulation(name: str):

    if not _SIMULATION_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="invalid simulation name")

    sim_dir = (_PROJECT_ROOT / name).resolve()

    if _PROJECT_ROOT.resolve() not in sim_dir.parents:
        raise HTTPException(status_code=400, detail="invalid simulation name")

    summary_path = sim_dir / "summary.json"

    if not summary_path.exists():
        raise HTTPException(status_code=404, detail="simulation not found")

    with open(summary_path, "r") as f:
        return json.load(f)


# =====================================================
# SIMULATION RUN LAUNCHER
#
# Lets the dashboard actually TRIGGER a new simulate_attacks.py live
# test, not just view past ones. Runs as a genuine separate OS process
# (not an in-process import/call) since simulate_attacks.py needs to
# reach this very server over real HTTP (it polls /status and /history
# to reachability-check and collect results, exactly like a real
# external client would) and sends real packets - it can't run inside
# this async event loop. Only one run at a time: floods generated by a
# second concurrent run would corrupt the first run's own flow-key
# collision margins (see simulate_attacks.py's SCENARIO_GAP_SECONDS
# comment for why that margin matters).
# =====================================================

_simulation_run_lock = threading.Lock()
_simulation_run_state = {
    "process": None,
    "out_dir": None,
    "trials": None,
    "target_ip": None,
    "started_at": None,
    "log_path": None,
}


def _local_addresses():
    """This machine's own IPv4 addresses (including the LAN address)."""

    found = set()

    try:
        found.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        found.add(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass

    return found


def _validate_simulation_target(raw):
    """The simulation sends real floods and scans, so its target is limited
    to this machine: a loopback address (127.x.x.x) or one of its own
    addresses. Anything else is refused."""

    try:
        address = ipaddress.ip_address(str(raw).strip())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{raw!r} is not a valid IP address")

    if address.version != 4:
        raise HTTPException(status_code=400, detail="only IPv4 targets are supported")

    if address.is_loopback or str(address) in _local_addresses():
        return str(address)

    raise HTTPException(
        status_code=400,
        detail="the simulation can only target this machine: use a loopback address "
               "(127.x.x.x, e.g. 127.0.0.77) or this machine's own address",
    )


@app.post("/simulations/run")
def start_simulation_run(payload: dict = None):

    trials = 1
    out_dir = None
    target_ip = _LAB_ADDRESS

    if payload:
        trials = int(payload.get("trials", 1))
        out_dir = payload.get("out_dir")
        if payload.get("target_ip"):
            target_ip = _validate_simulation_target(payload["target_ip"])

    if trials < 1 or trials > 10:
        raise HTTPException(status_code=400, detail="trials must be between 1 and 10")

    if not out_dir:
        out_dir = f"live_test_{time.strftime('%Y%m%d_%H%M%S')}"

    if not _SIMULATION_NAME_RE.match(out_dir):
        raise HTTPException(
            status_code=400,
            detail="invalid out_dir name (letters, digits, underscore, hyphen only)"
        )

    with _simulation_run_lock:

        existing = _simulation_run_state["process"]

        if existing is not None and existing.poll() is None:
            raise HTTPException(status_code=409, detail="a simulation is already running")

        sim_dir = _PROJECT_ROOT / out_dir
        sim_dir.mkdir(parents=True, exist_ok=True)

        log_path = sim_dir / "run.log"
        log_file = open(log_path, "w")

        # Loopback flows to the chosen target are scored (all other loopback
        # traffic stays ignored); the script reads the target from SIM_TARGET_IP.
        _lab_addresses.add(target_ip)

        process = subprocess.Popen(
            [sys.executable, "simulate_attacks.py", out_dir, str(trials)],
            cwd=_PROJECT_ROOT,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env={**os.environ, "SIM_TARGET_IP": target_ip},
        )

        _simulation_run_state.update({
            "process": process,
            "out_dir": out_dir,
            "trials": trials,
            "target_ip": target_ip,
            "started_at": time.time(),
            "log_path": str(log_path),
        })

    return {"status": "started", "out_dir": out_dir, "trials": trials, "target_ip": target_ip}


@app.get("/simulations/run/status")
def get_simulation_run_status():

    with _simulation_run_lock:

        process = _simulation_run_state["process"]

        if process is None:
            return {"running": False}

        running = process.poll() is None

        log_tail = ""
        log_path = _simulation_run_state.get("log_path")

        if log_path and Path(log_path).exists():
            try:
                with open(log_path, "r", errors="replace") as f:
                    log_tail = "".join(f.readlines()[-60:])
            except Exception:
                pass

        started_at = _simulation_run_state["started_at"]

        return {
            "running": running,
            "out_dir": _simulation_run_state["out_dir"],
            "trials": _simulation_run_state["trials"],
            "target_ip": _simulation_run_state["target_ip"],
            "started_at": started_at,
            "elapsed_seconds": (time.time() - started_at) if started_at else None,
            "exit_code": None if running else process.returncode,
            "log_tail": log_tail,
        }


@app.post("/simulations/run/cancel")
def cancel_simulation_run():

    with _simulation_run_lock:

        process = _simulation_run_state["process"]

        if process is None or process.poll() is not None:
            raise HTTPException(status_code=400, detail="no simulation is currently running")

        process.terminate()

    return {"status": "cancelling"}


# =====================================================
# LIVE WEBSOCKET
# =====================================================

@app.websocket("/ws/live")
async def websocket_live(
    websocket: WebSocket
):

    await websocket.accept()

    state.add_client(
        websocket
    )

    try:

        while True:

            # Keep connection alive.
            # Server pushes IDS results whenever
            # a flow is completed.

            await websocket.receive_text()

    except WebSocketDisconnect:

        state.remove_client(
            websocket
        )