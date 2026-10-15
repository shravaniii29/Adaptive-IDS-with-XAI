import { apiGet } from "./api";
import type { AgentAnalysisResponse } from "../types/agent";

// Existing backend integration: keep the endpoint and its contract unchanged.
export function getAgentAnalysis(flowId: string | number) {
  return apiGet<AgentAnalysisResponse>(`/analysis/${encodeURIComponent(String(flowId))}`);
}
