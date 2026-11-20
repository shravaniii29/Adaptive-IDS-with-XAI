import type { AgentAnalysisResponse } from "../types/agent";

// The per-flow agent insight shown in the dashboard (reasoning, incident
// summary, recommended action, memory pattern, SHAP features, …) is already
// embedded in every /predict and /history entry, so the UI reads it straight
// from the flow record. The old GET /analysis/{flow_id} route no longer exists
// on the backend; polling it produced a 404 on every flow and returned nothing
// usable. This hook is kept as a stable no-op so its callers are unchanged, but
// it no longer makes that dead request.
export function useAgentAnalysis(_flowId?: string | number | undefined): {
  analysis: AgentAnalysisResponse | null;
  loading: boolean;
} {
  return { analysis: null, loading: false };
}
