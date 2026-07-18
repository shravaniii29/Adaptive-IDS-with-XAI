from feature_extraction.feature_extractor import extract_features

from detection.predictor import predict_flow


class DetectionService:

    def __init__(self):

        self.total_flows = 0
        self.normal_flows = 0
        self.positive_flows = 0

    def detect(self, flow):

        features = extract_features(flow)

        prediction = predict_flow(features)

        self.total_flows += 1

        if prediction["hybrid_prediction"] == 1:
            self.positive_flows += 1
        else:
            self.normal_flows += 1

        result = {
            "flow_id": self.total_flows,
            "packet_count": flow.packet_count,
            "duration": flow.duration,
            "features": features,
            "xgb_probability": prediction[
                "xgb_probability"
            ],
            "xgb_prediction": prediction[
                "xgb_prediction"
            ],
            "isolation_score": prediction[
                "isolation_score"
            ],
            "isolation_prediction": prediction[
                "isolation_prediction"
            ],
            "hybrid_prediction": prediction[
                "hybrid_prediction"
            ],
        }

        return result

    def get_statistics(self):

        return {
            "total_flows": self.total_flows,
            "normal_flows": self.normal_flows,
            "positive_flows": self.positive_flows,
        }