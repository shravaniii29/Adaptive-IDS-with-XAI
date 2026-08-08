import { apiGet } from "./api";
import type { AgentAnalysisResponse } from "../types/agent";

export function getAgentAnalysis(flowId: string | number) {
  return apiGet<AgentAnalysisResponse>(`/analysis/${encodeURIComponent(String(flowId))}`);
}
