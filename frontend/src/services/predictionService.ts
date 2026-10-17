import { apiGet } from "./api";
import type { FlowDetail, Prediction, PredictionHistoryEntry } from "../types/prediction";

export function getLatestPrediction() { return apiGet<Prediction | { message: string }>("/predict"); }

export function getFlowHistory() {
  return apiGet<{ flows: PredictionHistoryEntry[] }>("/history");
}

/** One flow's explanation (SHAP features with impacts, hypothesis, summary)
 * for the model currently being viewed. /history rows only carry the
 * verdict, so the Live Logs row asks for this when it is expanded. */
export function getFlowDetail(flowId: string | number) {
  return apiGet<FlowDetail | { message: string }>(`/history/${encodeURIComponent(String(flowId))}`);
}
