export interface Prediction {
  flow_id: string | number;
  xgb_probability: number;
  xgb_prediction: string | number;
  isolation_prediction: string | number;
  hybrid_prediction: string | number;
  packet_count?: number;
}

export interface PredictionHistoryEntry extends Prediction {
  observedAt: string;
}
