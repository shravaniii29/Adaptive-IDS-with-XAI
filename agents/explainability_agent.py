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

    "Flow IAT Mean": {
        "meaning":
            "Average time between packets in the flow.",
        "interpretation":
            "A very low average interval indicates rapid, machine-generated traffic.",
        "possible_behavior":
            "Common in automated scanning or flooding tools."
    },

    "Flow IAT Std": {
        "meaning":
            "Standard deviation of time between packets in the flow.",
        "interpretation":
            "A high standard deviation means packet timing is inconsistent and irregular.",
        "possible_behavior":
            "Often seen in evasive or scripted traffic that does not follow normal usage patterns."
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

    "Fwd IAT Tot": {
        "meaning":
            "Total time between forward packets, summed across the flow.",
        "interpretation":
            "A very low total means the source transmitted continuously with almost no pauses.",
        "possible_behavior":
            "Typical of flooding or scripted request bursts."
    },

    "Fwd IAT Mean": {
        "meaning":
            "Average time between consecutive forward packets.",
        "interpretation":
            "Very small average gaps mean the source is transmitting without pause.",
        "possible_behavior":
            "Seen in flooding attacks or automated request bursts."
    },

    "Fwd IAT Max": {
        "meaning":
            "Longest gap between two consecutive forward packets.",
        "interpretation":
            "A large maximum gap suggests intermittent or bursty forward transmission.",
        "possible_behavior":
            "Can indicate stealthy, low-and-slow scanning or intermittent beaconing."
    },

    "Fwd Pkts/s": {
        "meaning":
            "Packets per second sent from the source, in the forward direction.",
        "interpretation":
            "A high forward packet rate shows the source pushing data aggressively.",
        "possible_behavior":
            "Typical of SYN floods, brute-force attempts, or scripted attack traffic."
    },

    "Flow Pkts/s": {
        "meaning":
            "Total packets per second across the whole flow.",
        "interpretation":
            "High packet rates indicate fast, high-volume traffic.",
        "possible_behavior":
            "Frequently seen in flooding attacks or automated scanning tools."
    },

    "Flow Duration": {
        "meaning":
            "Total duration of the network flow.",
        "interpretation":
            "Very short durations suggest quick, automated probes; unusually long durations suggest a sustained session.",
        "possible_behavior":
            "Short bursts are typical of port scans; long-lived flows can indicate persistent connections such as C2 channels."
    },

    "pkt_rate_ratio": {
        "meaning":
            "Ratio of the forward packet rate to the total flow packet rate.",
        "interpretation":
            "Values close to 1 mean the flow is dominated by one-directional traffic from the source.",
        "possible_behavior":
            "Common in scanning, flooding, or one-way data transfer where responses are minimal."
    },

    "Pkt Len Max": {
        "meaning":
            "Largest packet observed in the flow.",
        "interpretation":
            "Very large packets indicate unusual payload transfer.",
        "possible_behavior":
            "May occur during abnormal communication."
    },

    "Pkt Len Mean": {
        "meaning":
            "Average packet size across the entire flow, in both directions.",
        "interpretation":
            "Deviation from typical average sizes suggests a non-standard traffic shape.",
        "possible_behavior":
            "Uniformly small packets are typical of scans; irregular sizes can indicate crafted attack traffic."
    },

    "Pkt Size Avg": {
        "meaning":
            "Average packet size across the flow.",
        "interpretation":
            "Unusually small or large average sizes deviate from typical application traffic.",
        "possible_behavior":
            "Small uniform packets often indicate scanning; large packets can indicate bulk transfer or exfiltration."
    },

    "TotLen Fwd Pkts": {
        "meaning":
            "Total bytes sent in the forward direction.",
        "interpretation":
            "Large totals indicate the source pushed a significant amount of data.",
        "possible_behavior":
            "Can indicate bulk uploads, flooding, or data exfiltration attempts."
    },

    "TotLen Bwd Pkts": {
        "meaning":
            "Total bytes sent in the backward direction.",
        "interpretation":
            "Large backward totals show a large response volume relative to the request.",
        "possible_behavior":
            "Common in amplification attacks, where small requests trigger large responses."
    },

    "Subflow Fwd Byts": {
        "meaning":
            "Bytes transmitted in the forward direction.",
        "interpretation":
            "Large forward data transfer indicates aggressive communication.",
        "possible_behavior":
            "Can occur during scanning or flooding behaviour."
    },

    "Subflow Bwd Byts": {
        "meaning":
            "Bytes transmitted in the backward direction.",
        "interpretation":
            "Large values indicate the destination is returning significant data per exchange.",
        "possible_behavior":
            "Can be normal for downloads, but combined with other anomalies may indicate amplification abuse."
    },

    "Init Bwd Win Byts": {
        "meaning":
            "Initial TCP receive window advertised by the destination.",
        "interpretation":
            "Unusual TCP window sizes differ from expected benign traffic.",
        "possible_behavior":
            "Can indicate crafted packets or non-standard TCP stack behaviour used for evasion."
    },

    "Bwd Pkt Len Max": {
        "meaning":
            "Largest packet size seen in the backward (response) direction.",
        "interpretation":
            "Very large backward packets indicate significant data sent back to the source.",
        "possible_behavior":
            "Can occur when a server responds with large payloads, sometimes seen in reflection/amplification attacks."
    },

    "Bwd Pkt Len Mean": {
        "meaning":
            "Average packet size in the backward direction.",
        "interpretation":
            "Small average backward packets can mean minimal or no real response; large ones indicate substantial reply data.",
        "possible_behavior":
            "Very small values are common when scanning targets that barely respond; large values suggest heavy data return."
    },

    "Bwd Pkt Len Std": {
        "meaning":
            "Variation in backward packet sizes.",
        "interpretation":
            "Large variation indicates inconsistent responses.",
        "possible_behavior":
            "Often associated with abnormal communication."
    },

    "Bwd Seg Size Avg": {
        "meaning":
            "Average segment size returned by the destination.",
        "interpretation":
            "Deviations from typical segment sizes can indicate abnormal server responses.",
        "possible_behavior":
            "May reflect crafted or unusual responses generated during an attack."
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