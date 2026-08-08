class ResponseAgent:
    """
    Intelligent Response Agent.

    Makes decisions using the outputs of the
    Explainability Agent and Drift Agent
    instead of raw values alone.
    """

    def __init__(self):
        pass

    def analyze(
        self,
        detection_result,
        explanation_result,
        drift_result
    ):

        hybrid_prediction = detection_result["hybrid_prediction"]

        xgb_probability = detection_result["xgb_probability"]

        isolation_prediction = detection_result["isolation_prediction"]

        explanation_confidence = explanation_result["confidence"]

        attack_hypothesis = explanation_result["attack_hypothesis"]

        drift_detected = detection_result["drift_detected"]

        model_status = drift_result["status"]

        # -----------------------------------------
        # Normal traffic
        # -----------------------------------------

        if hybrid_prediction == 0:

            return {

                "threat_level": "LOW",

                "action": "CONTINUE MONITORING",

                "alert": False,

                "reason":
                    "All collaborating agents agree that the flow appears benign.",

                "agent_consensus":
                    "FULL"
            }

        # -----------------------------------------
        # High confidence attack
        # -----------------------------------------

        if (

            xgb_probability >= 0.80

            and

            explanation_confidence == "HIGH"

            and

            model_status == "MODEL STABLE"

        ):

            return {

                "threat_level": "HIGH",

                "action": "BLOCK SOURCE IP",

                "alert": True,

                "reason":
                    f"Explainability Agent indicates '{attack_hypothesis}' "
                    "with HIGH confidence while Drift Agent confirms the "
                    "model is reliable.",

                "agent_consensus":
                    "FULL"

            }

        # -----------------------------------------
        # Drift detected
        # -----------------------------------------

        if drift_detected:

            return {

                "threat_level": "MEDIUM",

                "action":
                    "MONITOR CLOSELY AND CONSIDER MODEL RETRAINING",

                "alert": True,

                "reason":
                    "Attack indicators exist but Drift Agent reports "
                    "possible model degradation.",

                "agent_consensus":
                    "PARTIAL"

            }

        # -----------------------------------------
        # Isolation Forest disagreement
        # -----------------------------------------

        if isolation_prediction == 1:

            return {

                "threat_level": "MEDIUM",

                "action":
                    "LOG EVENT AND CONTINUE MONITORING",

                "alert": True,

                "reason":
                    "Isolation Forest detected anomalous behaviour "
                    "while other evidence is moderate.",

                "agent_consensus":
                    "PARTIAL"

            }

        # -----------------------------------------
        # Default
        # -----------------------------------------

        return {

            "threat_level": "MEDIUM",

            "action": "CONTINUE MONITORING",

            "alert": True,

            "reason":
                "Agents produced mixed evidence. Continue monitoring.",

            "agent_consensus":
                "LOW"

        }