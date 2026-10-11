import { Fragment, useState } from "react";
import Badge from "../common/Badge";
import Card from "../common/Card";
import EmptyState from "../common/EmptyState";
import type { PredictionHistoryEntry } from "../../types/prediction";
import type { AgentAnalysisResponse } from "../../types/agent";
import { agreement, isAttack, nextAction, riskLevel } from "../../utils/flowInsights";

interface LiveLogTableProps { entries: PredictionHistoryEntry[]; driftDetected?: boolean; latestAnalysis?: AgentAnalysisResponse | null; }
const displayTimestamp = (timestamp: string) => new Date(timestamp).toLocaleString();
const riskVariant = (risk: string) => risk === "CRITICAL" || risk === "HIGH" ? "danger" : risk === "MEDIUM" ? "warning" : "success";

function FeatureBar({ name, impact }: { name: string; impact: number }) {
  const absImpact = Math.abs(impact);
  const width = Math.min(absImpact * 100, 100);
  const positive = impact > 0;
  return <div className="flex items-center gap-3 py-1">
    <span className="w-36 shrink-0 truncate text-xs text-slate-400">{name}</span>
    <div className="h-2 flex-1 rounded-full bg-white/5">
      <div className={`h-2 rounded-full ${positive ? "bg-rose-400" : "bg-emerald-400"}`} style={{ width: `${width}%` }} />
    </div>
    <span className={`w-16 text-right text-xs font-mono ${positive ? "text-rose-300" : "text-emerald-300"}`}>
      {positive ? "+" : ""}{impact.toFixed(3)}
    </span>
  </div>;
}

function ExpandedRow({ entry, analysis }: { entry: PredictionHistoryEntry; analysis?: AgentAnalysisResponse["analysis"] | null }) {
  const features = entry.supporting_features ?? [];
  const hypothesis = entry.attack_hypothesis;
  const reasoning = entry.reasoning ?? [];
  const details = entry.detailed_explanation ?? [];

  return <tr><td colSpan={9} className="bg-slate-900/60 px-6 py-5">
    <div className="grid gap-6 lg:grid-cols-2">
      <div>
        <h4 className="mb-3 text-sm font-semibold text-slate-200">Feature Impact (SHAP)</h4>
        {features.length > 0 ? features.map((f) => <FeatureBar key={f.feature} name={f.feature} impact={f.impact} />)
          : <p className="text-xs text-slate-500">No feature data available for this flow.</p>}
        <p className="mt-2 text-xs text-slate-500">Red = pushes toward attack, Green = pushes toward normal</p>
      </div>
      <div>
        {hypothesis && <div className="mb-4">
          <h4 className="mb-1 text-sm font-semibold text-slate-200">AI Hypothesis</h4>
          <p className="text-sm text-slate-300">{hypothesis}</p>
        </div>}
        {reasoning.length > 0 && <div className="mb-4">
          <h4 className="mb-1 text-sm font-semibold text-slate-200">Reasoning</h4>
          <ul className="list-inside list-disc space-y-1 text-xs text-slate-400">{reasoning.map((r, i) => <li key={i}>{r}</li>)}</ul>
        </div>}
        {details.length > 0 && <div className="mb-4">
          <h4 className="mb-1 text-sm font-semibold text-slate-200">Detection Details</h4>
          <ul className="space-y-1 text-xs text-slate-400">{details.map((d, i) => <li key={i}>{d}</li>)}</ul>
        </div>}
        {analysis && <div>
          <h4 className="mb-1 text-sm font-semibold text-slate-200">SOC Summary</h4>
          <p className="text-xs text-slate-400">{analysis.soc_analyst_summary}</p>
          {analysis.recommended_mitigation?.length > 0 && <div className="mt-2">
            <span className="text-xs font-medium text-slate-300">Mitigation:</span>
            <ul className="mt-1 list-inside list-disc text-xs text-slate-400">{analysis.recommended_mitigation.map((m, i) => <li key={i}>{m}</li>)}</ul>
          </div>}
        </div>}
        <div className="mt-3 flex flex-wrap gap-3 text-xs">
          {entry.confidence && <span className="rounded-md bg-white/5 px-2 py-1 text-slate-400">Confidence: <span className="text-slate-200">{entry.confidence}</span></span>}
          {entry.threat_level && <span className="rounded-md bg-white/5 px-2 py-1 text-slate-400">Threat: <span className="text-slate-200">{entry.threat_level}</span></span>}
          {entry.source_ip && <span className="rounded-md bg-white/5 px-2 py-1 text-slate-400">Source: <span className="font-mono text-slate-200">{entry.source_ip}</span></span>}
          {entry.destination_ip && <span className="rounded-md bg-white/5 px-2 py-1 text-slate-400">Dest: <span className="font-mono text-slate-200">{entry.destination_ip}</span></span>}
        </div>
      </div>
    </div>
  </td></tr>;
}

export default function LiveLogTable({ entries, driftDetected, latestAnalysis }: LiveLogTableProps) {
  const [expandedId, setExpandedId] = useState<string | number | null>(null);

  return <Card className="mt-6 overflow-hidden p-0 hover:translate-y-0"><div className="flex items-start justify-between gap-4 border-b border-white/5 px-6 py-5"><div><p className="text-sm text-slate-400">Live activity</p><h2 className="mt-1 text-xl font-semibold text-white">What is happening on your network</h2><p className="mt-1 text-xs text-slate-500">Each row is one recent connection checked by the security system. Click a row to see the AI explanation.</p></div><span className="rounded-full bg-sky-500/10 px-3 py-1 text-xs font-medium text-sky-400">LIVE</span></div>
    {entries.length === 0 ? <div className="p-6"><EmptyState title="No connections checked yet" description="As soon as the system sees network traffic, simple results and next steps will appear here." /></div> : <div className="overflow-x-auto"><table className="w-full min-w-[1180px] text-left text-sm"><thead className="bg-slate-900/50 text-xs uppercase tracking-wider text-slate-500"><tr><th className="px-6 py-4 font-medium">Connection</th><th className="px-6 py-4 font-medium">Time checked</th><th className="px-6 py-4 font-medium">Overall result</th><th className="px-6 py-4 font-medium">AI check 1</th><th className="px-6 py-4 font-medium">AI check 2</th><th className="px-6 py-4 font-medium">Do they agree?</th><th className="px-6 py-4 font-medium">Risk</th><th className="px-6 py-4 font-medium">What you should do</th>{driftDetected !== undefined && <th className="px-6 py-4 font-medium">Traffic changed?</th>}</tr></thead><tbody className="divide-y divide-white/5 text-slate-300">{entries.map((entry) => { const attack = isAttack(entry.hybrid_prediction); const agreed = agreement(entry); const agent = String(latestAnalysis?.flow_id) === String(entry.flow_id) ? latestAnalysis?.analysis : null; const risk = agent?.severity?.toUpperCase() || riskLevel(entry); const expanded = expandedId === entry.flow_id; return <Fragment key={`${entry.flow_id}-${entry.observedAt}`}><tr onClick={() => setExpandedId(expanded ? null : entry.flow_id)} className={`cursor-pointer transition-colors hover:bg-white/[0.04] ${expanded ? "bg-white/[0.03]" : ""}`}><td className="px-6 py-4 font-mono text-xs text-sky-300">#{entry.flow_id} {expanded ? <span className="text-slate-500">▼</span> : <span className="text-slate-600">▶</span>}</td><td className="px-6 py-4 whitespace-nowrap text-slate-400">{displayTimestamp(entry.observedAt)}</td><td className="px-6 py-4"><Badge text={attack ? "NEEDS REVIEW" : "LOOKS NORMAL"} variant={attack ? "danger" : "success"} /></td><td className="px-6 py-4">{isAttack(entry.xgb_prediction) ? "Attack likely" : "Looks normal"} <span className="text-xs text-slate-500">({(entry.xgb_probability * 100).toFixed(1)}%)</span></td><td className="px-6 py-4">{isAttack(entry.isolation_prediction) ? "Unusual traffic found" : "Looks normal"}</td><td className="px-6 py-4"><Badge text={agreed ? "YES" : "NO — REVIEW"} variant={agreed ? "success" : "warning"} /></td><td className="px-6 py-4"><Badge text={risk} variant={riskVariant(risk)} /></td><td className="max-w-72 px-6 py-4 text-xs leading-5 text-slate-300">{agent?.incident_report?.recommended_next_step || agent?.recommended_mitigation?.[0] || nextAction(entry)}</td>{driftDetected !== undefined && <td className="px-6 py-4"><Badge text={driftDetected ? "YES — CHECK" : "NO"} variant={driftDetected ? "warning" : "success"} /></td>}</tr>{expanded && <ExpandedRow entry={entry} analysis={agent} />}</Fragment>;})}</tbody></table></div>}
  </Card>;
}
