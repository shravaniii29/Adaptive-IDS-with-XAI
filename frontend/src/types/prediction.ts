export interface Prediction {
  flow_id: string | number;
  source_ip?: string;
  destination_ip?: string;
  xgb_probability: number;
  xgb_prediction: string | number;
  isolation_prediction: string | number;
  hybrid_prediction: string | number;
}

export interface PredictionHistoryEntry extends Prediction {
  observedAt: string;
}
