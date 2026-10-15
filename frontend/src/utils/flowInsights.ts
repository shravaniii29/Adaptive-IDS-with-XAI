import type { Prediction } from "../types/prediction";

export const isAttack = (value: string | number) => value === 1 || String(value).toLowerCase() === "attack";

export function agreement(prediction: Pick<Prediction, "xgb_prediction" | "isolation_prediction">) {
  return String(prediction.xgb_prediction) === String(prediction.isolation_prediction);
}

export function riskLevel(prediction: Prediction) {
  if (!isAttack(prediction.hybrid_prediction)) return "LOW";
  if (prediction.xgb_probability >= 0.8) return "CRITICAL";
  if (prediction.xgb_probability >= 0.5) return "HIGH";
  return "MEDIUM";
}

export function nextAction(prediction: Prediction) {
  if (!isAttack(prediction.hybrid_prediction)) return "No action needed — keep monitoring.";
  if (agreement(prediction)) return "Review and block this connection if it is not expected.";
  return "Review this unusual traffic now; the two AI checks disagree.";
}

export function plainSummary(prediction: Prediction) {
  if (!isAttack(prediction.hybrid_prediction)) return "This traffic looks normal. The system will continue monitoring it.";
  return agreement(prediction) ? "Both AI checks found suspicious traffic. Please review this connection." : "One AI check found unusual traffic while the other did not. This needs a quick human review.";
}
