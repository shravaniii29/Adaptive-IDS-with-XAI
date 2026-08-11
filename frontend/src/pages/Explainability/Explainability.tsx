import PageHeader from "../../components/common/PageHeader";
import EmptyState from "../../components/common/EmptyState";
import PageContainer from "../../components/layout/PageContainer";
import ExplanationCard from "../../components/explainability/ExplanationCard";
import AgentInsightsCard from "../../components/dashboard/AgentInsightsCard";
import CurrentThreatCard from "../../components/dashboard/CurrentThreatCard";
import { useAgentAnalysis } from "../../hooks/useAgentAnalysis";
import { usePrediction } from "../../hooks/usePrediction";
import { useShap } from "../../hooks/useShap";
import { isAttack } from "../../utils/flowInsights";

export default function Explainability() {
  const { prediction } = usePrediction();
  const { explanation } = useShap();
  const { analysis } = useAgentAnalysis(prediction?.flow_id);
  return <PageContainer><PageHeader title="Why this result appeared" subtitle="A simple explanation of the latest connection checked by your security system." />
    {!prediction ? <EmptyState title="Waiting for a connection to be checked" description="When network traffic is analysed, this page will show what the system noticed and what you should do next." /> : <><div className="grid gap-6 xl:grid-cols-2"><CurrentThreatCard flowId={String(prediction.flow_id)} verdict={isAttack(prediction.hybrid_prediction) ? "ATTACK" : "NORMAL"} probability={prediction.xgb_probability} xgbPrediction={String(prediction.xgb_prediction)} isolationPrediction={String(prediction.isolation_prediction)} /><ExplanationCard explanation={explanation} /></div><div className="mt-6 grid gap-6 xl:grid-cols-2"><AgentInsightsCard result={analysis} prediction={prediction} /><section className="rounded-2xl border border-white/10 bg-slate-900/50 p-6"><p className="text-sm text-slate-400">Quick guide</p><h2 className="mt-1 text-xl font-semibold text-white">How to use this information</h2><div className="mt-4 space-y-3 text-sm leading-6 text-slate-300"><p><span className="font-medium text-red-300">More risky</span> means the system saw something unusual in the connection.</p><p><span className="font-medium text-emerald-300">More normal</span> means the connection resembles ordinary activity.</p><p>Use the “What you should do” recommendation first. The technical details are only there to explain the result, not to require technical knowledge.</p></div></section></div></>}
  </PageContainer>;
}
