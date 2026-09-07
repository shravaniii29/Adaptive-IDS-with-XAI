export interface SimulationListEntry {
  name: string;
  generated_at: number | null;
  trials: number | null;
  target_ip: string | null;
  scenario_count: number;
}

export interface SimulationListResponse {
  simulations: SimulationListEntry[];
}

export interface ScenarioResult {
  name: string;
  is_attack: boolean;
  flow_count: number;
  model_scores: Record<string, number | null>;
  file: string;
}

export interface ConfusionMatrix {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface ModelMetrics {
  confusion_matrix: ConfusionMatrix;
  accuracy: number;
  precision: number | null;
  recall: number;
  f1: number | null;
  specificity: number;
  total_flows: number;
}

export interface FamilyModelMetrics extends ModelMetrics {
  specialty_scenarios: string[];
}

export interface SimulationDetail {
  generated_at: number;
  target_ip: string;
  trials: number;
  scenarios: ScenarioResult[];
  aggregate_metrics: Record<string, ModelMetrics>;
  family_aware_metrics: Record<string, FamilyModelMetrics>;
}

export interface SimulationRunStatus {
  running: boolean;
  out_dir: string | null;
  trials: number | null;
  started_at: number | null;
  elapsed_seconds: number | null;
  exit_code: number | null;
  log_tail: string;
}

export interface SimulationRunStartResponse {
  status: string;
  out_dir: string;
  trials: number;
}

// Mirrors simulate_attacks.py's MODEL_LABELS - kept in sync by hand,
// same as this file mirrors summary.json's own shape.
export const MODEL_LABELS: Record<string, string> = {
  deployed_hybrid: "Deployed hybrid",
  variant1_xgb_single_flow: "Var1 XGB single-flow",
  variant2_xgb_temporal: "Var2 XGB temporal",
  variant3_cnn_lstm: "Var3 CNN+LSTM",
  xgboost: "Candidate: XGBoost",
  random_forest: "Candidate: Random Forest",
  histgradientboosting: "Candidate: HistGradientBoosting",
  raw_flood: "Family: Raw Flood",
  reflection: "Family: Reflection",
  connection_application_layer: "Family: Connection",
  rl_verdict_classifier: "RL verdict (bandit)",
  temporal25_candidate: "Candidate: 25feat+temporal",
  v8_candidate: "V8 (paper baseline)",
};

export const modelLabel = (key: string): string => MODEL_LABELS[key] ?? key;
