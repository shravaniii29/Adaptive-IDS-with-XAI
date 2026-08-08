from agents.drift_agent import DriftAgent
from agents.response_agent import ResponseAgent
from agents.explainability_agent import ExplainabilityAgent
from agents.memory_agent import MemoryAgent


class CoordinatorAgent:
    """
    Coordinator Agent

    Orchestrates all intelligent agents and
    produces the final AI Security Incident Report.
    """

    def __init__(self):

        self.drift_agent = DriftAgent()

        self.response_agent = ResponseAgent()

        self.explainability_agent = ExplainabilityAgent()

        self.memory_agent = MemoryAgent()

    def analyze(self, detection_result):

        # -----------------------------------------
        # Explainability Agent
        # -----------------------------------------

        explanation_result = self.explainability_agent.analyze(

            detection_result["shap_explanation"]

        )

        # -----------------------------------------
        # Drift Agent
        # -----------------------------------------

        drift_result = self.drift_agent.analyze(

            detection_result["drift_detected"]

        )

        # -----------------------------------------
        # Response Agent
        # -----------------------------------------

        response_result = self.response_agent.analyze(

            detection_result,

            explanation_result,

            drift_result

        )

        # -----------------------------------------
        # Memory Agent
        # -----------------------------------------

        memory_result = self.memory_agent.analyze(

            flow_id=detection_result["flow_id"],

            source_ip=detection_result["source_ip"],

            hybrid_prediction=detection_result["hybrid_prediction"],

            threat_level=response_result["threat_level"]

        )

        # -----------------------------------------
        # Agent Consensus
        # -----------------------------------------

        consensus = self._calculate_consensus(

            explanation_result,

            drift_result,

            response_result,

            memory_result

        )

        # -----------------------------------------
        # Incident Report
        # -----------------------------------------

        incident_report = self._generate_incident_report(

            detection_result,

            explanation_result,

            drift_result,

            response_result,

            memory_result,

            consensus

        )

        return {

            "prediction": detection_result["hybrid_prediction"],

            "explanation": explanation_result,

            "drift": drift_result,

            "response": response_result,

            "memory": memory_result,

            "consensus": consensus,

            "incident_report": incident_report

        }

    # =====================================================

    def _calculate_consensus(

        self,

        explanation,

        drift,

        response,

        memory

    ):

        score = 0

        # Explainability

        if explanation["confidence"] == "HIGH":
            score += 30

        elif explanation["confidence"] == "MEDIUM":
            score += 20

        else:
            score += 10

        # Drift

        score += int(
            drift["agent_confidence"] * 20
        )

        # Response

        if response["agent_consensus"] == "FULL":
            score += 20

        elif response["agent_consensus"] == "PARTIAL":
            score += 15

        else:
            score += 8

        # Memory

        if memory["risk"] == "CRITICAL":
            score += 30

        elif memory["risk"] == "HIGH":
            score += 25

        elif memory["risk"] == "MEDIUM":
            score += 15

        else:
            score += 10

        score = min(score, 100)

        if score >= 90:
            agreement = "VERY HIGH"

        elif score >= 75:
            agreement = "HIGH"

        elif score >= 60:
            agreement = "MODERATE"

        else:
            agreement = "LOW"

        return {

            "score": score,

            "agreement": agreement

        }

    # =====================================================

    def _generate_incident_report(

        self,

        detection,

        explanation,

        drift,

        response,

        memory,

        consensus

    ):

        if detection["hybrid_prediction"]:

            verdict = "MALICIOUS NETWORK ACTIVITY DETECTED"

        else:

            verdict = "NORMAL NETWORK ACTIVITY"

        return {

            "verdict": verdict,

            "overall_confidence": consensus["agreement"],

            "consensus_score": consensus["score"],

            "threat_level": response["threat_level"],

            "recommended_action": response["action"],

            "response_reason": response["reason"],

            "attack_hypothesis": explanation["attack_hypothesis"],

            "summary": explanation["summary"],

            "reasoning": explanation["reasoning"],

            "supporting_features": explanation["top_features"],

            "drift_status": drift["status"],

            "drift_trend": drift["trend"],

            "model_recommendation": drift["recommendation"],

            "memory_pattern": memory["pattern"],

            "memory_risk": memory["risk"],

            "memory_recommendation": memory["recommendation"]

        }