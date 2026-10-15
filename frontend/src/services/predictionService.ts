import { apiGet } from "./api";
import type { Prediction, PredictionHistoryEntry } from "../types/prediction";

export function getLatestPrediction() { return apiGet<Prediction | { message: string }>("/predict"); }

export function getFlowHistory() {
  return apiGet<{ flows: PredictionHistoryEntry[] }>("/history");
}
