import { useCallback, useEffect, useRef, useState } from "react";
import { getFlowHistory, getLatestPrediction } from "../services/predictionService";
import type { Prediction, PredictionHistoryEntry } from "../types/prediction";
import { usePolling } from "./usePolling";
const hasPrediction = (value: Prediction | { message: string }): value is Prediction => "hybrid_prediction" in value;

const HISTORY_LIMIT = 100;

export function usePrediction() {
  const request = useCallback(getLatestPrediction, []);
  const result = usePolling(request);
  const prediction = result.data && hasPrediction(result.data) ? result.data : null;
  const [history, setHistory] = useState<PredictionHistoryEntry[]>([]);
  const seeded = useRef(false);

  useEffect(() => {
    if (seeded.current) return;
    seeded.current = true;
    getFlowHistory()
      .then((res) => {
        if (!res.flows || res.flows.length === 0) return;
        const entries: PredictionHistoryEntry[] = res.flows
          .map((f) => ({
            ...f,
            observedAt: f.timestamp ? new Date(f.timestamp * 1000).toISOString() : new Date().toISOString(),
          }))
          .reverse();
        setHistory((current) => {
          const ids = new Set(current.map((e) => e.flow_id));
          const merged = [...current];
          for (const entry of entries) {
            if (!ids.has(entry.flow_id)) {
              merged.push(entry);
              ids.add(entry.flow_id);
            }
          }
          merged.sort((a, b) => Number(b.flow_id) - Number(a.flow_id));
          return merged.slice(0, HISTORY_LIMIT);
        });
      })
      .catch(() => {});
  }, []);

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
