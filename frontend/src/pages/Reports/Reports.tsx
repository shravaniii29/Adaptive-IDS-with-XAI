import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import PageHeader from "../../components/common/PageHeader";
import EmptyState from "../../components/common/EmptyState";
import Card from "../../components/common/Card";
import StatCard from "../../components/dashboard/StatCard";
import FlowHistoryChart from "../../components/dashboard/FlowHistoryChart";
import PageContainer from "../../components/layout/PageContainer";
import { usePrediction } from "../../hooks/usePrediction";

const isAttack = (value: string | number) => value === 1 || String(value).toLowerCase() === "attack";

export default function Reports() {
  const { history } = usePrediction();
  const attacks = history.filter((entry) => isAttack(entry.hybrid_prediction)).length;
  const normal = history.length - attacks;
  const agreed = history.filter((entry) => String(entry.xgb_prediction) === String(entry.isolation_prediction)).length;
  const chartData = [{ name: "Normal", flows: normal, fill: "#22c55e" }, { name: "Attack", flows: attacks, fill: "#ef4444" }];
  return <PageContainer><PageHeader title="Reports" subtitle="Live reporting based on the flows retained in this browser session." />
    {history.length === 0 ? <EmptyState title="Waiting for report data" description="Graphs appear as the IDS processes flows. The current session retains the latest 100 flows." /> : <><div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3"><StatCard title="Flows in report" value={history.length} color="#38bdf8" /><StatCard title="Model agreement" value={`${Math.round((agreed / history.length) * 100)}%`} color="#a78bfa" /><StatCard title="Attack rate" value={`${Math.round((attacks / history.length) * 100)}%`} color="#ef4444" /></div><div className="mt-6 grid gap-6 xl:grid-cols-2"><FlowHistoryChart entries={history} /><Card><p className="text-sm text-slate-400">Report distribution</p><h2 className="mt-1 text-xl font-semibold text-white">Normal vs attack flows</h2><p className="mt-1 text-xs text-slate-500">Current session, latest {history.length} processed flows.</p><div className="mt-5 h-64"><ResponsiveContainer width="100%" height="100%"><BarChart data={chartData}><CartesianGrid stroke="#334155" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="name" tick={{ fill: "#94a3b8" }} /><YAxis allowDecimals={false} tick={{ fill: "#94a3b8" }} /><Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8 }} /><Bar dataKey="flows" radius={[6, 6, 0, 0]} /></BarChart></ResponsiveContainer></div></Card></div></>}
  </PageContainer>;
}
