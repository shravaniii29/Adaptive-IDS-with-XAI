import { apiGet } from "./api";
import type { ExperimentalPredictions } from "../types/experimentalModels";
export function getExperimentalPredictions() { return apiGet<ExperimentalPredictions | { message: string }>("/experimental"); }
