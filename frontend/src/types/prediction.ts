export interface ShapFeature {
  feature: string;
  value: number;
  impact: number;
}

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
  timestamp?: number;
  attack_hypothesis?: string;
  confidence?: string;
  explanation_summary?: string;
  reasoning?: string[];
  supporting_features?: ShapFeature[];
  detailed_explanation?: string[];
  threat_level?: string;
  recommended_action?: string;
  response_reason?: string;
  verdict?: string;
}
