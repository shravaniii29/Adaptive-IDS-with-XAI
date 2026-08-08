from agents.coordinator import CoordinatorAgent


coordinator = CoordinatorAgent()


# --------------------------------------------------
# Simulate multiple malicious flows
# --------------------------------------------------

for flow_id in range(1, 6):

    dummy_detection_result = {

        "flow_id": flow_id,

        "source_ip": "192.168.1.100",

        "hybrid_prediction": 1,

        "xgb_probability": 0.91,

        "isolation_prediction": 1,

        "drift_detected": False,

        "shap_explanation": [

            {
                "feature": "Flow IAT Min",
                "value": 135596,
                "impact": -1.95
            },

            {
                "feature": "Fwd Header Len",
                "value": 20,
                "impact": -1.50
            },

            {
                "feature": "Init Bwd Win Bytes",
                "value": 65535,
                "impact": -1.10
            }

        ]
    }

    result = coordinator.analyze(
        dummy_detection_result
    )

    incident = result["incident_report"]

    consensus = result["consensus"]

    memory = result["memory"]

    print("\n" + "=" * 90)
    print(f"FLOW {flow_id}")
    print("=" * 90)

    print(
        "VERDICT              :",
        incident["verdict"]
    )

    print(
        "THREAT LEVEL         :",
        incident["threat_level"]
    )

    print(
        "OVERALL CONFIDENCE   :",
        incident["overall_confidence"]
    )

    print(
        "CONSENSUS SCORE      :",
        incident["consensus_score"]
    )

    print(
        "ATTACK HYPOTHESIS    :",
        incident["attack_hypothesis"]
    )

    print()

    print("MEMORY AGENT")
    print("-" * 90)

    print(
        "Pattern             :",
        memory["pattern"]
    )

    print(
        "Risk                :",
        memory["risk"]
    )

    print(
        "Confidence          :",
        memory["confidence"]
    )

    print(
        "Flows in Memory     :",
        memory["flows_in_memory"]
    )

    print(
        "Recent Attacks      :",
        memory["recent_attacks"]
    )

    print(
        "Repeated Sources    :",
        memory["repeated_sources"]
    )

    print()

    print("RESPONSE")
    print("-" * 90)

    print(
        "Action              :",
        incident["recommended_action"]
    )

    print(
        "Reason              :",
        incident["response_reason"]
    )

    print()

    print("DRIFT")
    print("-" * 90)

    print(
        "Status              :",
        incident["drift_status"]
    )

    print(
        "Trend               :",
        incident["drift_trend"]
    )

    print()

print("\n" + "=" * 90)
print("MEMORY AGENT TEST PASSED")
print("=" * 90)