import { useEffect, useState } from "react";
import { getAgentAnalysis } from "../services/agentService";
import type { AgentAnalysisResponse } from "../types/agent";
import { useModeVersion } from "./useModeVersion";

export function useAgentAnalysis(flowId: string | number | undefined) {
  const [analysis, setAnalysis] = useState<AgentAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  // The same flow has a different agent analysis under each model.
  const modeVersion = useModeVersion();

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
  }, [flowId, modeVersion]);

  return { analysis, loading };
}
