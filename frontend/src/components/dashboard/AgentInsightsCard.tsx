import Card from "../common/Card";
import Badge from "../common/Badge";
import type { AgentAnalysisResponse } from "../../types/agent";
import type { Prediction } from "../../types/prediction";
import { nextAction, plainSummary, riskLevel } from "../../utils/flowInsights";

const badgeVariant = (severity: string) => severity === "critical" || severity === "high" ? "danger" : severity === "medium" ? "warning" : "success";

export default function AgentInsightsCard({ result, prediction }: { result: AgentAnalysisResponse | null; prediction: Prediction | null }) {
  const agent = result?.analysis;
  const severity = agent?.severity?.toUpperCase() || (prediction ? riskLevel(prediction) : "WAITING");
  const summary = agent?.soc_analyst_summary || agent?.explanation || (prediction ? plainSummary(prediction) : "The system is waiting for the first network flow.");
  const action = agent?.incident_report?.recommended_next_step || agent?.recommended_mitigation?.[0] || (prediction ? nextAction(prediction) : "No action needed yet.");
  return <Card><div className="mb-4 flex items-start justify-between gap-3"><div><p className="text-sm text-slate-400">Plain-language security update</p><h2 className="mt-1 text-xl font-semibold text-white">What happened and what to do</h2></div><Badge text={severity} variant={badgeVariant(severity.toLowerCase())} /></div><p className="text-xs font-medium uppercase tracking-wide text-slate-500">Incident summary</p><p className="mt-1 text-sm leading-6 text-slate-200">{summary}</p><div className="mt-4 border-t border-white/10 pt-4"><p className="text-xs font-medium uppercase tracking-wide text-slate-500">Recommended action</p><p className="mt-1 text-sm text-sky-200">{action}</p></div>{agent?.incident_report?.title && <p className="mt-3 text-xs text-slate-400">Incident name: {agent.incident_report.title}</p>}</Card>;
}
