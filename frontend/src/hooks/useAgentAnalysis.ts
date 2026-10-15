import { useEffect, useState } from "react";
import { getAgentAnalysis } from "../services/agentService";
import type { AgentAnalysisResponse } from "../types/agent";

export function useAgentAnalysis(flowId: string | number | undefined) {
  const [analysis, setAnalysis] = useState<AgentAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (flowId === undefined) {
      setAnalysis(null);
      return;
    }
    let active = true;
    setLoading(true);
    void getAgentAnalysis(flowId)
      .then((result) => { if (active) setAnalysis(result); })
      // Agent analysis is optional: an IDS deployment without this route stays usable.
      .catch(() => { if (active) setAnalysis(null); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [flowId]);

  return { analysis, loading };
}
