from collections import deque, Counter


class MemoryAgent:
    """
    Memory Agent

    Maintains short-term memory of recently analysed
    network flows and identifies recurring attack
    patterns that may not be obvious from a single flow.
    """

    def __init__(self, memory_size=20):

        self.memory = deque(maxlen=memory_size)

    def analyze(
        self,
        flow_id,
        source_ip,
        hybrid_prediction,
        threat_level
    ):

        # -----------------------------------------
        # Store current observation
        # -----------------------------------------

        self.memory.append({

            "flow_id": flow_id,

            "source_ip": source_ip,

            "prediction": hybrid_prediction,

            "threat_level": threat_level

        })

        # -----------------------------------------
        # Basic statistics
        # -----------------------------------------

        total_flows = len(self.memory)

        attacks = [

            flow
            for flow in self.memory
            if flow["prediction"] == 1

        ]

        attack_count = len(attacks)

        source_counter = Counter(

            flow["source_ip"]
            for flow in attacks

        )

        repeated_sources = {

            ip: count
            for ip, count in source_counter.items()
            if count >= 3
        }

        # -----------------------------------------
        # Determine pattern
        # -----------------------------------------

        if attack_count >= 10:

            pattern = "SUSTAINED ATTACK CAMPAIGN"

            risk = "CRITICAL"

            recommendation = (
                "Multiple malicious flows observed recently. "
                "Immediate investigation required."
            )

            confidence = "VERY HIGH"

        elif repeated_sources:

            source = max(

                repeated_sources,

                key=repeated_sources.get

            )

            pattern = (
                f"REPEATED SUSPICIOUS ACTIVITY "
                f"FROM {source}"
            )

            risk = "HIGH"

            recommendation = (
                "Repeated malicious behaviour detected "
                "from the same source."
            )

            confidence = "HIGH"

        elif attack_count >= 3:

            pattern = "EMERGING ATTACK TREND"

            risk = "MEDIUM"

            recommendation = (
                "Suspicious activity is increasing. "
                "Continue close monitoring."
            )

            confidence = "MEDIUM"

        else:

            pattern = "NORMAL NETWORK BEHAVIOUR"

            risk = "LOW"

            recommendation = (
                "No recurring malicious pattern detected."
            )

            confidence = "HIGH"

        # -----------------------------------------
        # Return memory assessment
        # -----------------------------------------

        return {

            "pattern": pattern,

            "risk": risk,

            "confidence": confidence,

            "recommendation": recommendation,

            "flows_in_memory": total_flows,

            "recent_attacks": attack_count,

            "repeated_sources": repeated_sources

        }