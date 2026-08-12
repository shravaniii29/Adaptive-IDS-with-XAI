import { useCallback, useEffect, useState } from "react";
import { getLatestPrediction } from "../services/predictionService";
import type { Prediction, PredictionHistoryEntry } from "../types/prediction";
import { usePolling } from "./usePolling";
const hasPrediction = (value: Prediction | { message: string }): value is Prediction => "hybrid_prediction" in value;

const HISTORY_LIMIT = 100;

export function usePrediction() {
  const request = useCallback(getLatestPrediction, []);
  const result = usePolling(request);
  const prediction = result.data && hasPrediction(result.data) ? result.data : null;
  const [history, setHistory] = useState<PredictionHistoryEntry[]>([]);

  useEffect(() => {
    if (!prediction) return;

    setHistory((current) => {
      const existing = current.find((entry) => entry.flow_id === prediction.flow_id);
      if (existing && existing.xgb_prediction === prediction.xgb_prediction && existing.isolation_prediction === prediction.isolation_prediction && existing.hybrid_prediction === prediction.hybrid_prediction && existing.xgb_probability === prediction.xgb_probability) return current;

      const nextEntry: PredictionHistoryEntry = { ...prediction, observedAt: new Date().toISOString() };
      return [nextEntry, ...current.filter((entry) => entry.flow_id !== prediction.flow_id)].slice(0, HISTORY_LIMIT);
    });
  }, [prediction]);

  return { ...result, prediction, history };
}
