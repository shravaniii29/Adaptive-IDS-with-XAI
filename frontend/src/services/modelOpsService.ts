import { apiGet, apiPost } from "./api";

export interface FusionConfig {
  alpha?: number;
  threshold?: number;
  calibrated_at?: string;
  heldout_confidence?: { recall?: number; spec_ordinary?: number; balanced?: number };
  network_recall?: number;
  network_specificity?: number;
  [key: string]: unknown;
}

export interface CalibrationProposal {
  alpha: number;
  threshold: number;
  recall: number;
  specificity: number;
  balanced: number;
  benign_flows: number;
  attack_flows: number;
  current_alpha?: number | null;
  current_threshold?: number | null;
  computed_at: number;
}

export interface CalibrationResponse {
  hybrid: FusionConfig | null;
  v8: FusionConfig | null;
  proposal?: CalibrationProposal | null;
}

export interface CandidateMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface Candidate {
  id: string;
  created_at: number;
  dataset: string;
  training_rows: number;
  validation_rows: number;
  deployed_metrics: CandidateMetrics;
  candidate_metrics: CandidateMetrics;
  accepted: boolean;
  status: "pending" | "promoted" | "discarded";
}

export interface RetrainStatus {
  running: boolean;
  started_at: number | null;
  result: Candidate | null;
  error: string | null;
}

export const getCalibration = () => apiGet<CalibrationResponse>("/calibration");
export const triggerDemoDrift = () => apiPost<{ status: string; retrain: string }>("/drift/demo_trigger");
export const getRetrainStatus = () => apiGet<RetrainStatus>("/retrain/status");
export const listCandidates = () => apiGet<{ candidates: Candidate[] }>("/retrain/candidates");
export const promoteCandidate = (id: string) => apiPost<{ status: string }>(`/retrain/candidates/${id}/promote`);
export const discardCandidate = (id: string) => apiPost<{ status: string }>(`/retrain/candidates/${id}/discard`);

export const recalibrateNetwork = () => apiPost<CalibrationProposal>("/calibration/recalibrate");
export const applyCalibration = () => apiPost<{ status: string; alpha: number; threshold: number }>("/calibration/apply");
export const discardCalibration = () => apiPost<{ status: string }>("/calibration/discard");
