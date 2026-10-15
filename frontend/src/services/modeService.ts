import { apiGet, apiPost } from "./api";

export interface DetectionModeOption {
  id: string;
  label: string;
  available: boolean;
}

export interface DetectionModeState {
  mode: string;
  modes: DetectionModeOption[];
}

export function getDetectionMode() {
  return apiGet<DetectionModeState>("/mode");
}

export function setDetectionMode(mode: string) {
  return apiPost<DetectionModeState>("/mode", { mode });
}
