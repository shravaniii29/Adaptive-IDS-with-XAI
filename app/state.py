"""
Shared in-memory state for the API layer.

Stores the latest IDS result, keeps a short history of recent
flows, and broadcasts agentic analysis results to connected
dashboard clients.
"""

import asyncio
import threading


class AppState:

    def __init__(self):

        self.lock = threading.Lock()

        # Latest IDS result
        self.last_result = None

        # Recent IDS results for dashboard history
        self.result_history = []

        # Maximum number of flows to retain
        self.max_history = 20

        self.last_error = None

        self.start_time = 0.0

        # Event loop used for websocket broadcasts
        self.loop = None

        # Connected websocket clients
        self._clients = set()


    # -------------------------------------------------
    # Called from the background capture thread
    # -------------------------------------------------

    def record_result(self, result):

        with self.lock:

            # Store latest result
            self.last_result = result

            # Add result to history
            self.result_history.append(result)

            # Keep only the latest 20 flows
            if len(self.result_history) > self.max_history:

                self.result_history = (
                    self.result_history[-self.max_history:]
                )

            self.last_error = None


    def record_error(self, message):

        with self.lock:

            self.last_error = message


    # -------------------------------------------------
    # Return recent IDS history
    # -------------------------------------------------

    def get_history(self):

        with self.lock:

            return list(self.result_history)


    # -------------------------------------------------
    # WebSocket broadcasting
    # -------------------------------------------------

    def broadcast_soon(self, result):

        """
        Schedule a websocket broadcast from
        the background capture thread.
        """

        if self.loop is None:

            return

        asyncio.run_coroutine_threadsafe(

            self._broadcast(result),

            self.loop

        )


    # -------------------------------------------------
    # WebSocket client management
    # -------------------------------------------------

    def add_client(self, websocket):

        self._clients.add(websocket)


    def remove_client(self, websocket):

        self._clients.discard(websocket)


    # -------------------------------------------------
    # Broadcast complete agentic IDS result
    # -------------------------------------------------

    async def _broadcast(self, result):

        agent_analysis = result.get(
            "agent_analysis",
            {}
        )

        response = agent_analysis.get(
            "response",
            {}
        )

        explanation = agent_analysis.get(
            "explanation",
            {}
        )

        drift = agent_analysis.get(
            "drift",
            {}
        )

        memory = agent_analysis.get(
            "memory",
            {}
        )

        consensus = agent_analysis.get(
            "consensus",
            {}
        )

        incident = agent_analysis.get(
            "incident_report",
            {}
        )

        payload = {

            # -----------------------------------------
            # Detection
            # -----------------------------------------

            "flow_id":
                result.get("flow_id"),

            "xgb_probability":
                result.get("xgb_probability"),

            "xgb_prediction":
                result.get("xgb_prediction"),

            "isolation_prediction":
                result.get("isolation_prediction"),

            "hybrid_prediction":
                result.get("hybrid_prediction"),

            # -----------------------------------------
            # Drift
            # -----------------------------------------

            "drift_detected":
                result.get("drift_detected"),

            "drift_status":
                drift.get("status"),

            "drift_severity":
                drift.get("severity"),

            "model_recommendation":
                drift.get("recommendation"),

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

            "explanation_summary":
                explanation.get("summary"),

            "reasoning":
                explanation.get("reasoning", []),

            "supporting_features":
                explanation.get("top_features", []),

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
            # Agent Consensus
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

        dead_clients = []

        for client in list(self._clients):

            try:

                await client.send_json(payload)

            except Exception:

                dead_clients.append(client)


        for client in dead_clients:

            self._clients.discard(client)