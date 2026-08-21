export interface ExperimentalVariantResult {
  available: boolean;
  label?: string;
  probability?: number;
  prediction?: number;
  threshold?: number;
  error?: string;
}

export interface ExperimentalPredictions {
  flow_id: string | number;
  source_ip?: string;
  destination_ip?: string;
  disclaimer: string;
  variant1_xgb_single_flow: ExperimentalVariantResult;
  variant2_xgb_temporal: ExperimentalVariantResult;
  variant3_cnn_lstm: ExperimentalVariantResult;
}
