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
  isolation_anomaly?: number | null;
  confidence_score?: number | null;
  fusion_mode?: string | null;
}

export interface FlowDetail {
  flow_id: string | number;
  attack_hypothesis?: string;
  confidence?: string;
  summary?: string;
  top_features?: ShapFeature[];
}

export interface PredictionHistoryEntry extends Prediction {
  observedAt: string;
  timestamp?: number;
  recorded_at?: number;
  attack_hypothesis?: string;
  confidence?: string;
  explanation_summary?: string;
  reasoning?: string[];
  supporting_features?: ShapFeature[] | string[];
  detailed_explanation?: (string | Record<string, unknown>)[];
  threat_level?: string;
  recommended_action?: string;
  response_reason?: string;
  verdict?: string;
}
