import { apiGet, apiPost } from "./api";
import type {
  SimulationDetail,
  SimulationListResponse,
  SimulationRunStartResponse,
  SimulationRunStatus,
} from "../types/simulation";

export const listSimulations = () => apiGet<SimulationListResponse>("/simulations");
export const getSimulation = (name: string) => apiGet<SimulationDetail>(`/simulations/${encodeURIComponent(name)}`);

export const startSimulationRun = (trials: number, targetIp?: string) =>
  apiPost<SimulationRunStartResponse>("/simulations/run", targetIp ? { trials, target_ip: targetIp } : { trials });
export const getSimulationRunStatus = () => apiGet<SimulationRunStatus>("/simulations/run/status");
export const cancelSimulationRun = () => apiPost<{ status: string }>("/simulations/run/cancel");
