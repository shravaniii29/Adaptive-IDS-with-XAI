import { apiGet } from "./api";
import type { ShapExplanation } from "../types/shap";

export function getShapExplanation() {
  return apiGet<ShapExplanation | { message: string }>("/shap");
}
