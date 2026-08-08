from collections import deque


class DriftAgent:
    """
    Intelligent Drift Agent

    Monitors concept drift over time instead of
    reacting to a single ADWIN output.
    """

    def __init__(self):

        # Store recent drift observations
        self.history = deque(maxlen=50)

    def analyze(self, drift_detected):

        # -----------------------------------------
        # Update history
        # -----------------------------------------

        self.history.append(int(drift_detected))

        total_flows = len(self.history)

        drift_events = sum(self.history)

        drift_ratio = (
            drift_events / total_flows
            if total_flows > 0
            else 0
        )

        # -----------------------------------------
        # Determine drift status
        # -----------------------------------------

        if drift_ratio >= 0.40:

            status = "MODEL DEGRADING"

            severity = "HIGH"

            recommendation = (
                "Frequent concept drift detected. "
                "Retrain the Hybrid IDS model as soon as possible."
            )

            confidence = "HIGH"

            agent_confidence = 0.95

        elif drift_ratio >= 0.20:

            status = "MODERATE DRIFT"

            severity = "MEDIUM"

            recommendation = (
                "Drift is increasing. Continue monitoring "
                "and prepare for retraining."
            )

            confidence = "MEDIUM"

            agent_confidence = 0.75

        elif drift_detected:

            status = "MINOR DRIFT"

            severity = "LOW"

            recommendation = (
                "Small drift detected. "
                "No immediate retraining required."
            )

            confidence = "LOW"

            agent_confidence = 0.60

        else:

            status = "MODEL STABLE"

            severity = "LOW"

            recommendation = (
                "Model behaviour is stable. "
                "No retraining required."
            )

            confidence = "HIGH"

            agent_confidence = 0.95

        # -----------------------------------------
        # Trend Analysis
        # -----------------------------------------

        if drift_ratio >= 0.40:

            trend = (
                "Concept drift is consistently increasing."
            )

        elif drift_ratio >= 0.20:

            trend = (
                "Drift is present but currently manageable."
            )

        elif drift_detected:

            trend = (
                "An isolated drift event was detected."
            )

        else:

            trend = (
                "No significant drift trend observed."
            )

        # -----------------------------------------
        # Return Agent Report
        # -----------------------------------------

        return {

            "status": status,

            "severity": severity,

            "recommendation": recommendation,

            "confidence": confidence,

            "agent_confidence": agent_confidence,

            "trend": trend,

            "recent_drift_events": drift_events,

            "history_size": total_flows,

            "drift_ratio": round(
                drift_ratio,
                3
            )

        }