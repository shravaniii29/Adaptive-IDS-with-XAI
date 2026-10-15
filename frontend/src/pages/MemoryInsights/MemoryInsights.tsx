import Card from "../../components/common/Card";
import EmptyState from "../../components/common/EmptyState";
import PageHeader from "../../components/common/PageHeader";
import PageContainer from "../../components/layout/PageContainer";
import Badge from "../../components/common/Badge";
import { useAgentAnalysis } from "../../hooks/useAgentAnalysis";
import { usePrediction } from "../../hooks/usePrediction";
import { agreement, isAttack, riskLevel } from "../../utils/flowInsights";

const riskVariant = (risk: string) => risk === "CRITICAL" || risk === "HIGH" ? "danger" : risk === "MEDIUM" ? "warning" : "success";

export default function MemoryInsights() {
  const { prediction, history } = usePrediction();
  const { analysis } = useAgentAnalysis(prediction?.flow_id);
  const memory = analysis?.analysis.memory_agent_result;
  const attacks = history.filter((entry) => isAttack(entry.hybrid_prediction)).length;
  const agreements = history.filter(agreement).length;
  const agreedPercent = history.length ? Math.round((agreements / history.length) * 100) : 0;

  return <PageContainer><PageHeader title="Memory Insights" subtitle="Recent network activity at a glance." />
    {!prediction ? <EmptyState title="Waiting for network activity" description="Results will appear after the first connection is checked." /> : <><div className="grid gap-6 md:grid-cols-3"><Card><p className="text-sm text-slate-400">Current risk</p><div className="mt-3"><Badge text={riskLevel(prediction)} variant={riskVariant(riskLevel(prediction))} /></div><p className="mt-3 text-sm text-slate-300">Connection #{prediction.flow_id}</p></Card><Card><p className="text-sm text-slate-400">Needs review</p><h2 className="mt-2 text-3xl font-semibold text-white">{attacks}</h2><p className="mt-2 text-sm text-slate-400">of {history.length} recent connections</p></Card><Card><p className="text-sm text-slate-400">AI agreement</p><h2 className="mt-2 text-3xl font-semibold text-white">{agreedPercent}%</h2><p className="mt-2 text-sm text-slate-400">models reached the same result</p></Card></div>
      <div className="mt-6 grid gap-6 xl:grid-cols-2"><Card><p className="text-sm text-slate-400">Memory Agent result</p><h2 className="mt-1 text-xl font-semibold text-white">Similar activity</h2>{memory ? <div className="mt-4 space-y-3"><p className="text-sm text-slate-200">{memory.summary || "Related activity was found."}</p><div className="flex flex-wrap gap-2"><Badge text={`${memory.similar_incidents ?? 0} similar incidents`} variant="warning" /><Badge text={memory.pattern_detected ? "PATTERN FOUND" : "NO PATTERN"} variant={memory.pattern_detected ? "danger" : "success"} /></div>{memory.last_seen && <p className="text-xs text-slate-400">Last seen: {new Date(memory.last_seen).toLocaleString()}</p>}</div> : <div className="mt-4 rounded-xl border border-white/10 bg-slate-800/40 p-4"><p className="text-sm text-slate-300">No saved-memory match is available for this connection.</p></div>}</Card><Card><p className="text-sm text-slate-400">Quick status</p><h2 className="mt-1 text-xl font-semibold text-white">Current decision</h2><div className="mt-4 space-y-3 text-sm text-slate-300"><p>{isAttack(prediction.hybrid_prediction) ? "This connection needs review." : "This connection looks normal."}</p><p>{agreement(prediction) ? "Both AI checks agree." : "The AI checks disagree — review it."}</p></div></Card></div></>}
  </PageContainer>;
}
