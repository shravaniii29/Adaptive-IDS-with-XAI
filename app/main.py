"""
FastAPI backend for the Network IDS project.

Connects the live packet-capture pipeline to the
agentic IDS layer and exposes results to the dashboard.
"""

import json
import os
import re
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

def _handle_completed_flow(flow):

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

@app.get("/status")
def get_status():

    statistics = (
        detection_service.get_statistics()
    )

    return {

        **statistics,

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
    "started_at": None,
    "log_path": None,
}


@app.post("/simulations/run")
def start_simulation_run(payload: dict = None):

    trials = 1
    out_dir = None

    if payload:
        trials = int(payload.get("trials", 1))
        out_dir = payload.get("out_dir")

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

        process = subprocess.Popen(
            [sys.executable, "simulate_attacks.py", out_dir, str(trials)],
            cwd=_PROJECT_ROOT,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

        _simulation_run_state.update({
            "process": process,
            "out_dir": out_dir,
            "trials": trials,
            "started_at": time.time(),
            "log_path": str(log_path),
        })

    return {"status": "started", "out_dir": out_dir, "trials": trials}


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