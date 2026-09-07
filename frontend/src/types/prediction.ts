export interface Prediction {
  flow_id: string | number;
  xgb_probability: number;
  xgb_prediction: string | number;
  isolation_prediction: string | number;
  hybrid_prediction: string | number;
  packet_count?: number;
  detection_source?: string;
  consensus_score?: number;
  summary?: string;
  response_reason?: string;
  recommended_action?: string;
  threat_level?: string;
}

export interface PredictionHistoryEntry extends Prediction {
  observedAt: string;
}
