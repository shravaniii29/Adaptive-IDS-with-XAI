import { apiGet } from "./api";
import type { Prediction } from "../types/prediction";
export function getLatestPrediction() { return apiGet<Prediction | { message: string }>("/predict"); }
