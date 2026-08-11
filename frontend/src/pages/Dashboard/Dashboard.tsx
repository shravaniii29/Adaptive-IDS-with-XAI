import EmptyState from "../../components/common/EmptyState";
import ErrorState from "../../components/common/ErrorState";
import Loader from "../../components/common/Loader";
import PageHeader from "../../components/common/PageHeader";
import ConnectionStatus from "../../components/dashboard/ConnectionStatus";
import CurrentThreatCard from "../../components/dashboard/CurrentThreatCard";
import DetectionGauge from "../../components/dashboard/DetectionGauge";
import DriftCard from "../../components/dashboard/DriftCard";
import FlowHistoryChart from "../../components/dashboard/FlowHistoryChart";
import AgentInsightsCard from "../../components/dashboard/AgentInsightsCard";
import ModelConsensusCard from "../../components/dashboard/ModelConsensusCard";
import LiveLogTable from "../../components/dashboard/LiveLogTable";
import ExplanationCard from "../../components/explainability/ExplanationCard";
import StatCard from "../../components/dashboard/StatCard";
import SystemHealthCard from "../../components/dashboard/SystemHealthCard";
import ThreatSummary from "../../components/dashboard/ThreatSummary";
import PageContainer from "../../components/layout/PageContainer";
import { useDrift } from "../../hooks/useDrift";
import { usePrediction } from "../../hooks/usePrediction";
import { useShap } from "../../hooks/useShap";
import { useSystemStatus } from "../../hooks/useSystemStatus";
import { useAgentAnalysis } from "../../hooks/useAgentAnalysis";

const duration = (seconds: number) => `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
const isAttack = (value: string | number) => value === 1 || String(value).toLowerCase() === "attack";

export default function Dashboard() {
  const { prediction, history, loading: predictionLoading } = usePrediction();
  const { drift } = useDrift();
  const { explanation } = useShap();
  const { system, stats, error, loading } = useSystemStatus();
  const { analysis } = useAgentAnalysis(prediction?.flow_id);
  const attack = prediction ? isAttack(prediction.hybrid_prediction) : false;
  return <PageContainer><PageHeader title="Security Overview" subtitle="Live explainable AI network threat monitoring" />
    {error && <div className="mb-6"><ErrorState message={`Backend unavailable: ${error}`} /></div>}
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4"><StatCard title="Total Flows" value={stats?.total_flows ?? "—"} color="#38bdf8" /><StatCard title="Normal" value={stats?.normal_flows ?? "—"} color="#22c55e" /><StatCard title="Attacks" value={stats?.positive_flows ?? "—"} color="#ef4444" /><StatCard title="Drift Status" value={drift ? (drift.drift_detected ? "Detected" : "Stable") : "—"} color={drift?.drift_detected ? "#f59e0b" : "#94a3b8"} /></div>
    <div className="mt-6 grid gap-6 xl:grid-cols-2">{predictionLoading ? <Loader label="Fetching latest detection..." /> : prediction ? <CurrentThreatCard flowId={String(prediction.flow_id)} verdict={attack ? "ATTACK" : "NORMAL"} probability={prediction.xgb_probability} xgbPrediction={String(prediction.xgb_prediction)} isolationPrediction={String(prediction.isolation_prediction)} /> : <EmptyState title="Waiting for the first flow" description="The dashboard will populate from /predict when the backend processes a network flow." />}{prediction && <DetectionGauge probability={prediction.xgb_probability} />}</div>
    <div className="mt-6 grid gap-6 md:grid-cols-2 xl:grid-cols-4"><ConnectionStatus connected={Boolean(system) && !error} backend="FastAPI" /><DriftCard detected={drift?.drift_detected ?? false} /><SystemHealthCard uptime={system ? duration(system.uptime_seconds) : "—"} status={system?.status === "ok" ? "Healthy" : "Warning"} /><ThreatSummary attacks={stats?.positive_flows ?? 0} normal={stats?.normal_flows ?? 0} /></div>
    <div className="mt-6 grid gap-6 xl:grid-cols-2"><FlowHistoryChart entries={history} /><ExplanationCard explanation={explanation} /></div>
    <div className="mt-6 grid gap-6 xl:grid-cols-2"><ModelConsensusCard prediction={prediction} /><AgentInsightsCard result={analysis} prediction={prediction} /></div>
    <LiveLogTable entries={history} driftDetected={drift?.drift_detected} latestAnalysis={analysis} />
    {loading && !stats && <Loader label="Connecting to backend..." />}
  </PageContainer>;
}
