"""
FastAPI backend for the Network IDS project.

Connects the live packet-capture pipeline to the
agentic IDS layer and exposes results to the dashboard.
"""

import time
import threading
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from detection.detection_service import DetectionService
from feature_extraction.flow_manager import FlowManager
from packet_capture.capture import start_capture

from app.state import AppState


# =====================================================
# GLOBAL STATE
# =====================================================

state = AppState()

detection_service = DetectionService()

flow_manager = FlowManager(
    flow_timeout=5
)

EXPIRY_POLL_INTERVAL_SECONDS = 1


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
            state.last_error
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

        "top_features":
            explanation.get(
                "top_features",
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