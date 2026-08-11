import { useCallback } from "react";
import { getShapExplanation } from "../services/shapService";
import type { ShapExplanation } from "../types/shap";
import { usePolling } from "./usePolling";

const hasExplanation = (value: ShapExplanation | { message: string }): value is ShapExplanation => "top_features" in value;

export function useShap() {
  const request = useCallback(getShapExplanation, []);
  const result = usePolling(request);
  return { ...result, explanation: result.data && hasExplanation(result.data) ? result.data : null };
}
