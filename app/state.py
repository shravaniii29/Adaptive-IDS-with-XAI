"""
Shared in-memory state for the API layer.

Nothing here touches a database. It's just a thread-safe place for the
background capture thread to drop results, and for the async FastAPI
endpoints/websocket to read them from.
"""

import asyncio
import threading


class AppState:

    def __init__(self):
        self.lock = threading.Lock()
        self.last_result = None
        self.last_error = None
        self.start_time = 0.0
        self.loop = None  # set on startup, needed to schedule broadcasts
        self._clients = set()

    # -------------------------------------------------
    # Called from the background capture thread
    # -------------------------------------------------

    def record_result(self, result):
        with self.lock:
            self.last_result = result
            self.last_error = None

    def record_error(self, message):
        with self.lock:
            self.last_error = message

    def broadcast_soon(self, result):
        """Schedule a websocket broadcast from a non-async thread."""
        if self.loop is None:
            return

        asyncio.run_coroutine_threadsafe(
            self._broadcast(result), self.loop
        )

    # -------------------------------------------------
    # Websocket client bookkeeping (called from the async side)
    # -------------------------------------------------

    def add_client(self, websocket):
        self._clients.add(websocket)

    def remove_client(self, websocket):
        self._clients.discard(websocket)

    async def _broadcast(self, result):
        payload = {
            "flow_id": result["flow_id"],
            "hybrid_prediction": result["hybrid_prediction"],
            "xgb_probability": result["xgb_probability"],
            "drift_detected": result["drift_detected"],
        }

        dead = []
        for client in list(self._clients):
            try:
                await client.send_json(payload)
            except Exception:
                dead.append(client)

        for client in dead:
            self._clients.discard(client)
