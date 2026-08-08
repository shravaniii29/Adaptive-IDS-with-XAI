FEATURE_KNOWLEDGE = {

    "Flow IAT Min": {
        "meaning":
            "Minimum time between packets in the network flow.",
        "interpretation":
            "Very small packet intervals indicate packets are arriving rapidly.",
        "possible_behavior":
            "Common in automated scanning, flooding or scripted traffic."
    },

    "Flow IAT Max": {
        "meaning":
            "Maximum time gap between packets.",
        "interpretation":
            "Large delays indicate bursty or irregular communication.",
        "possible_behavior":
            "Can occur in unstable or suspicious sessions."
    },

    "iat_variation": {
        "meaning":
            "Variation in packet arrival times.",
        "interpretation":
            "High variation indicates inconsistent packet timing.",
        "possible_behavior":
            "Often observed in abnormal network behaviour."
    },

    "Fwd Header Len": {
        "meaning":
            "Total header length of forward packets.",
        "interpretation":
            "Abnormal TCP/IP header sizes may indicate crafted packets.",
        "possible_behavior":
            "Frequently observed during reconnaissance or packet manipulation."
    },

    "Init Bwd Win Bytes": {
        "meaning":
            "Initial TCP receive window advertised by the destination.",
        "interpretation":
            "Unusual TCP window sizes differ from expected benign traffic.",
        "possible_behavior":
            "Can contribute to anomaly detection."
    },

    "Pkt Len Max": {
        "meaning":
            "Largest packet observed in the flow.",
        "interpretation":
            "Very large packets indicate unusual payload transfer.",
        "possible_behavior":
            "May occur during abnormal communication."
    },

    "Bwd Pkt Len Std": {
        "meaning":
            "Variation in backward packet sizes.",
        "interpretation":
            "Large variation indicates inconsistent responses.",
        "possible_behavior":
            "Often associated with abnormal communication."
    },

    "Subflow Fwd Byts": {
        "meaning":
            "Bytes transmitted in the forward direction.",
        "interpretation":
            "Large forward data transfer indicates aggressive communication.",
        "possible_behavior":
            "Can occur during scanning or flooding behaviour."
    }
}


class ExplainabilityAgent:

    def __init__(self):
        pass

    def analyze(self, shap_explanation):

        report = []
        top_features = []

        for feature in shap_explanation:

            feature_name = feature["feature"]

            top_features.append(feature_name)

            info = FEATURE_KNOWLEDGE.get(
                feature_name,
                {
                    "meaning":
                        "Unknown feature.",

                    "interpretation":
                        "No interpretation available.",

                    "possible_behavior":
                        "Unknown behaviour."
                }
            )

            report.append({

                "feature":
                    feature_name,

                "value":
                    feature["value"],

                "impact":
                    feature["impact"],

                "meaning":
                    info["meaning"],

                "interpretation":
                    info["interpretation"],

                "possible_behavior":
                    info["possible_behavior"]
            })

        attack_hypothesis = self._generate_attack_hypothesis(
            top_features
        )

        confidence = self._estimate_confidence(
            shap_explanation
        )

        reasoning = self._generate_reasoning(
            report
        )

        incident_summary = self._generate_summary(
            attack_hypothesis,
            confidence
        )

        return {

            "summary":
                incident_summary,

            "attack_hypothesis":
                attack_hypothesis,

            "confidence":
                confidence,

            "reasoning":
                reasoning,

            "top_features":
                top_features,

            "detailed_report":
                report
        }

    def _generate_attack_hypothesis(
        self,
        top_features
    ):

        if (
            "Flow IAT Min" in top_features
            and
            "Fwd Header Len" in top_features
        ):

            return (
                "Observed behaviour resembles rapid automated "
                "network communication commonly seen during "
                "reconnaissance or scanning activity."
            )

        if (
            "Pkt Len Max" in top_features
            or
            "Subflow Fwd Byts" in top_features
        ):

            return (
                "Observed behaviour indicates unusually large "
                "data transfer that differs from typical benign traffic."
            )

        if (
            "iat_variation" in top_features
        ):

            return (
                "Traffic timing is highly irregular, suggesting "
                "potential anomalous communication."
            )

        return (
            "No specific attack behaviour could be inferred. "
            "The flow is classified based on the overall evidence."
        )

    def _estimate_confidence(
        self,
        shap_explanation
    ):

        average_impact = (
            sum(
                abs(feature["impact"])
                for feature in shap_explanation
            )
            /
            len(shap_explanation)
        )

        if average_impact >= 1.5:
            return "HIGH"

        if average_impact >= 0.8:
            return "MEDIUM"

        return "LOW"

    def _generate_reasoning(
        self,
        report
    ):

        reasoning = []

        for feature in report:

            reasoning.append(

                f"{feature['feature']}: "
                f"{feature['interpretation']} "
                f"This behaviour is {feature['possible_behavior']}"

            )

        return reasoning

    def _generate_summary(
        self,
        hypothesis,
        confidence
    ):

        return (

            f"AI Security Assessment\n\n"

            f"Hypothesis:\n"
            f"{hypothesis}\n\n"

            f"Confidence Level:\n"
            f"{confidence}\n\n"

            f"The conclusion is based on the SHAP feature "
            f"importance values generated by the deployed "
            f"hybrid IDS."

        )