import { useCallback } from "react";
import { getExperimentalPredictions } from "../services/experimentalModelsService";
import type { ExperimentalPredictions } from "../types/experimentalModels";
import { usePolling } from "./usePolling";

const hasPredictions = (value: ExperimentalPredictions | { message: string }): value is ExperimentalPredictions => "variant1_xgb_single_flow" in value;

export function useExperimentalModels() {
  const request = useCallback(getExperimentalPredictions, []);
  const result = usePolling(request);
  return { ...result, predictions: result.data && hasPredictions(result.data) ? result.data : null };
}
