import { useCallback } from "react";
import { getLatestPrediction } from "../services/predictionService";
import type { Prediction } from "../types/prediction";
import { usePolling } from "./usePolling";
const hasPrediction = (value: Prediction | { message: string }): value is Prediction => "hybrid_prediction" in value;
export function usePrediction() { const request = useCallback(getLatestPrediction, []); const result = usePolling(request); return { ...result, prediction: result.data && hasPrediction(result.data) ? result.data : null }; }
