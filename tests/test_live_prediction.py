from packet_capture.capture import start_capture

from feature_extraction.flow_manager import FlowManager

from detection.detection_service import DetectionService


flow_manager = FlowManager(
    flow_timeout=5
)

detection_service = DetectionService()


def predict_completed_flow(key, flow):

    # -----------------------------------------
    # Ignore extremely small flows
    # -----------------------------------------

    if flow.packet_count < 5:
        return

    # -----------------------------------------
    # Run complete IDS pipeline
    # -----------------------------------------

    result = detection_service.detect(flow)

    # -----------------------------------------
    # Basic IDS Output
    # -----------------------------------------

    print("\n" + "=" * 80)
    print("LIVE IDS FLOW ANALYSIS")
    print("=" * 80)

    print(
        f"Flow               : {key}"
    )

    print(
        f"Source IP          : {result['source_ip']}"
    )

    print(
        f"Destination IP     : {result['destination_ip']}"
    )

    print(
        f"Flow ID            : {result['flow_id']}"
    )

    print(
        f"Packets            : {result['packet_count']}"
    )

    print(
        f"Duration           : "
        f"{result['duration']:.6f} sec"
    )

    print()

    # -----------------------------------------
    # XGBoost
    # -----------------------------------------

    print(
        f"XGB Probability    : "
        f"{result['xgb_probability']:.6f}"
    )

    print(
        f"XGB Prediction     : "
        f"{result['xgb_prediction']}"
    )

    # -----------------------------------------
    # Isolation Forest
    # -----------------------------------------

    print(
        f"Isolation Score    : "
        f"{result['isolation_score']:.6f}"
    )

    print(
        f"Isolation Anomaly  : "
        f"{result['isolation_prediction']}"
    )

    # -----------------------------------------
    # Hybrid Prediction
    # -----------------------------------------

    print(
        f"Hybrid Prediction  : "
        f"{result['hybrid_prediction']}"
    )

    print(
        f"Drift Detected     : "
        f"{result['drift_detected']}"
    )

    if result["hybrid_prediction"] == 1:

        print(
            "STATUS             : ATTACK / ANOMALY"
        )

    else:

        print(
            "STATUS             : NORMAL"
        )

    # =====================================================
    # SHAP EXPLANATION
    # =====================================================

    print("\n" + "=" * 80)
    print("SHAP EXPLAINABILITY")
    print("=" * 80)

    for index, feature in enumerate(

        result["shap_explanation"],

        start=1

    ):

        print(

            f"{index}. "
            f"{feature['feature']}"
            f" | Value: {feature['value']:.4f}"
            f" | Impact: {feature['impact']:.6f}"

        )

    # =====================================================
    # AGENT LAYER
    # =====================================================

    agent = result["agent_analysis"]

    # =====================================================
    # EXPLAINABILITY AGENT
    # =====================================================

    print("\n" + "=" * 80)
    print("EXPLAINABILITY AGENT")
    print("=" * 80)

    explanation = agent["explanation"]

    print(
        "\nAttack Hypothesis:"
    )

    print(
        explanation["attack_hypothesis"]
    )

    print(
        "\nConfidence:",
        explanation["confidence"]
    )

    print(
        "\nSummary:"
    )

    print(
        explanation["summary"]
    )

    print(
        "\nTop Important Features:"
    )

    for feature in explanation["top_features"]:

        print(
            f"• {feature}"
        )

    # =====================================================
    # DRIFT AGENT
    # =====================================================

    print("\n" + "=" * 80)
    print("DRIFT AGENT")
    print("=" * 80)

    drift = agent["drift"]

    print(
        f"Status              : "
        f"{drift['status']}"
    )

    print(
        f"Severity            : "
        f"{drift['severity']}"
    )

    print(
        f"Confidence          : "
        f"{drift['confidence']}"
    )

    print(
        f"Agent Confidence    : "
        f"{drift['agent_confidence']}"
    )

    print(
        f"Trend               : "
        f"{drift['trend']}"
    )

    print(
        f"Recent Drift Events : "
        f"{drift['recent_drift_events']}"
    )

    print(
        f"History Size        : "
        f"{drift['history_size']}"
    )

    print(
        f"Drift Ratio         : "
        f"{drift['drift_ratio']}"
    )

    print(
        f"Recommendation      : "
        f"{drift['recommendation']}"
    )

    # =====================================================
    # RESPONSE AGENT
    # =====================================================

    print("\n" + "=" * 80)
    print("RESPONSE AGENT")
    print("=" * 80)

    response = agent["response"]

    print(
        f"Threat Level        : "
        f"{response['threat_level']}"
    )

    print(
        f"Action              : "
        f"{response['action']}"
    )

    print(
        f"Alert               : "
        f"{response['alert']}"
    )

    print(
        f"Agent Consensus     : "
        f"{response['agent_consensus']}"
    )

    print(
        "\nReason:"
    )

    print(
        response["reason"]
    )

    # =====================================================
    # MEMORY AGENT
    # =====================================================

    print("\n" + "=" * 80)
    print("MEMORY AGENT")
    print("=" * 80)

    memory = agent["memory"]

    print(
        f"Pattern             : "
        f"{memory['pattern']}"
    )

    print(
        f"Risk                : "
        f"{memory['risk']}"
    )

    print(
        f"Confidence          : "
        f"{memory['confidence']}"
    )

    print(
        f"Flows in Memory     : "
        f"{memory['flows_in_memory']}"
    )

    print(
        f"Recent Attacks      : "
        f"{memory['recent_attacks']}"
    )

    print(
        f"Repeated Sources    : "
        f"{memory['repeated_sources']}"
    )

    print(
        "\nRecommendation:"
    )

    print(
        memory["recommendation"]
    )

    # =====================================================
    # COORDINATOR / CONSENSUS
    # =====================================================

    print("\n" + "=" * 80)
    print("AGENT COORDINATOR")
    print("=" * 80)

    consensus = agent["consensus"]

    print(
        f"Consensus Score     : "
        f"{consensus['score']}"
    )

    print(
        f"Agreement Level     : "
        f"{consensus['agreement']}"
    )

    # =====================================================
    # FINAL AI INCIDENT REPORT
    # =====================================================

    incident = agent["incident_report"]

    print("\n" + "=" * 80)
    print("FINAL AI SECURITY INCIDENT REPORT")
    print("=" * 80)

    print(
        f"\nVerdict             : "
        f"{incident['verdict']}"
    )

    print(
        f"Threat Level        : "
        f"{incident['threat_level']}"
    )

    print(
        f"Overall Confidence  : "
        f"{incident['overall_confidence']}"
    )

    print(
        f"Consensus Score     : "
        f"{incident['consensus_score']}"
    )

    print(
        f"\nAttack Hypothesis   : "
        f"{incident['attack_hypothesis']}"
    )

    print(
        f"\nRecommended Action  : "
        f"{incident['recommended_action']}"
    )

    print(
        f"\nResponse Reason     : "
        f"{incident['response_reason']}"
    )

    print(
        f"\nMemory Pattern      : "
        f"{incident['memory_pattern']}"
    )

    print(
        f"Memory Risk         : "
        f"{incident['memory_risk']}"
    )

    print(
        f"\nDrift Status        : "
        f"{incident['drift_status']}"
    )

    print(
        f"Drift Trend         : "
        f"{incident['drift_trend']}"
    )

    print(
        f"\nModel Recommendation:"
    )

    print(
        incident["model_recommendation"]
    )

    print(
        f"\nMemory Recommendation:"
    )

    print(
        incident["memory_recommendation"]
    )

    print("\n" + "=" * 80)


def process_packet(packet):

    flow_manager.process_packet(packet)

    expired_flows = flow_manager.get_expired_flows()

    for key, flow in expired_flows:

        predict_completed_flow(
            key,
            flow
        )


# =========================================================
# START LIVE IDS
# =========================================================

print(
    "Starting Live Adaptive IDS..."
)

print(
    "Listening for network traffic...\n"
)


start_capture(

    process_packet,

    packet_count=0

)


# =========================================================
# FLUSH REMAINING FLOWS
# =========================================================

print(
    "\nCapture completed."
)

print(
    "Flushing remaining active flows..."
)


remaining_flows = flow_manager.flush_all_flows()


for key, flow in remaining_flows:

    predict_completed_flow(
        key,
        flow
    )


# =========================================================
# FINAL STATISTICS
# =========================================================

stats = detection_service.get_statistics()


print("\n" + "=" * 80)
print("DETECTION SUMMARY")
print("=" * 80)

print(
    f"Total Flows      : "
    f"{stats['total_flows']}"
)

print(
    f"Normal Flows     : "
    f"{stats['normal_flows']}"
)

print(
    f"Positive Flows   : "
    f"{stats['positive_flows']}"
)

print("=" * 80)

print(
    "\nLive Adaptive IDS test completed."
)