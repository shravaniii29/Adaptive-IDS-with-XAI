"""
FastAPI backend for the Network IDS project.

Wires the real detection pipeline (DetectionService, DriftDetector,
SHAPExplainer) into the endpoints your teammate's frontend expects:

    /predict   GET  -> latest hybrid prediction result
    /status    GET  -> running flow statistics
    /drift     GET  -> latest drift status
    /shap      GET  -> latest SHAP explanation (top 5 features)
    /system    GET  -> backend health / uptime
    /ws/live   WS   -> pushes each new result as it's produced

Packet capture runs in a background thread so the API stays responsive.
Each finished flow is run through DetectionService.detect() and the
result is cached in memory (state.py) for the GET endpoints and
broadcast over the websocket for live updates.

Flow completion is timeout-based (see feature_extraction/flow_manager.py):
FlowManager.process_packet() just accumulates packets per flow key.
A flow only becomes "done" when get_expired_flows() is polled and
finds the flow's been inactive for flow_timeout seconds (default 5s).
So this file runs two background threads: one feeding packets into
the FlowManager, and one polling for expired flows on an interval.
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

state = AppState()
detection_service = DetectionService()
flow_manager = FlowManager(flow_timeout=5)

EXPIRY_POLL_INTERVAL_SECONDS = 1


def _handle_completed_flow(flow):
    try:
        result = detection_service.detect(flow)
    except Exception as exc:
        state.record_error(str(exc))
        return

    state.record_result(result)
    state.broadcast_soon(result)


def _capture_worker():
    """Runs in a background thread. Feeds every sniffed packet into
    the FlowManager. Does NOT decide completion — that's the expiry
    worker's job, since completion here is timeout-based, not
    per-packet."""

    try:
        start_capture(flow_manager.process_packet, packet_count=0)
    except Exception as exc:
        state.record_error(f"capture thread stopped: {exc}")


def _expiry_worker():
    """Runs in a background thread. Periodically checks for flows
    that have gone quiet for flow_timeout seconds and runs each one
    through detection."""

    while True:
        time.sleep(EXPIRY_POLL_INTERVAL_SECONDS)

        try:
            expired = flow_manager.get_expired_flows()
        except Exception as exc:
            state.record_error(str(exc))
            continue

        for _key, flow in expired:
            _handle_completed_flow(flow)


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.loop = asyncio.get_event_loop()

    capture_thread = threading.Thread(target=_capture_worker, daemon=True)
    capture_thread.start()

    expiry_thread = threading.Thread(target=_expiry_worker, daemon=True)
    expiry_thread.start()

    state.start_time = time.time()
    yield


app = FastAPI(title="Network IDS API", lifespan=lifespan)

# Loosen this once you know your frontend's actual origin/port.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/status")
def get_status():
    return {
        **detection_service.get_statistics(),
        "last_error": state.last_error,
    }


@app.get("/predict")
def get_predict():
    if state.last_result is None:
        return {"message": "no flows processed yet"}

    result = dict(state.last_result)
    # features/shap_explanation already summarized elsewhere; keep
    # this endpoint focused on the prediction itself.
    return {
        "flow_id": result["flow_id"],
        "xgb_probability": result["xgb_probability"],
        "xgb_prediction": result["xgb_prediction"],
        "isolation_prediction": result["isolation_prediction"],
        "hybrid_prediction": result["hybrid_prediction"],
    }


@app.get("/drift")
def get_drift():
    if state.last_result is None:
        return {"message": "no flows processed yet"}

    return {
        "flow_id": state.last_result["flow_id"],
        "drift_detected": state.last_result["drift_detected"],
    }


@app.get("/shap")
def get_shap():
    if state.last_result is None:
        return {"message": "no flows processed yet"}

    return {
        "flow_id": state.last_result["flow_id"],
        "top_features": state.last_result["shap_explanation"],
    }


@app.get("/system")
def get_system():
    return {
        "status": "ok" if state.last_error is None else "degraded",
        "uptime_seconds": time.time() - state.start_time,
        "last_error": state.last_error,
    }


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await websocket.accept()
    state.add_client(websocket)
    try:
        while True:
            # Keep the connection open; we only push from the server side.
            await websocket.receive_text()
    except WebSocketDisconnect:
        state.remove_client(websocket)
