import { useCallback, useEffect, useState } from "react";
import { getFlowHistory, getLatestPrediction } from "../services/predictionService";
import type { Prediction, PredictionHistoryEntry } from "../types/prediction";
import { usePolling } from "./usePolling";
import { useModeVersion } from "./useModeVersion";
const hasPrediction = (value: Prediction | { message: string }): value is Prediction => "hybrid_prediction" in value;

const HISTORY_LIMIT = 100;

export function usePrediction() {
  const request = useCallback(getLatestPrediction, []);
  const result = usePolling(request);
  const prediction = result.data && hasPrediction(result.data) ? result.data : null;
  const [history, setHistory] = useState<PredictionHistoryEntry[]>([]);
  // Changes when the Hybrid | V8 switch is used. Every flow is scored by
  // both models and the backend serves the selected one, so on a switch the
  // table is replaced with the other model's view of the same flows.
  const modeVersion = useModeVersion();

  useEffect(() => {
    let active = true;
    getFlowHistory()
      .then((res) => {
        if (!active || !res.flows || res.flows.length === 0) return;
        const entries: PredictionHistoryEntry[] = res.flows
          .map((f) => {
            // /history reports the wall-clock time as `recorded_at` (seconds).
            const seconds = f.timestamp ?? f.recorded_at;
            return {
              ...f,
              observedAt: seconds ? new Date(seconds * 1000).toISOString() : new Date().toISOString(),
            };
          })
          .reverse();
        setHistory((current) => {
          const replace = modeVersion > 0;
          const ids = new Set(replace ? [] : current.map((e) => e.flow_id));
          const merged = replace ? [] : [...current];
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
    return () => { active = false; };
  }, [modeVersion]);

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
