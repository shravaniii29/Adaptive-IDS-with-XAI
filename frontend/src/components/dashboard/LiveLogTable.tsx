import { Fragment, useEffect, useState } from "react";
import Badge from "../common/Badge";
import Card from "../common/Card";
import EmptyState from "../common/EmptyState";
import ErrorBoundary from "../common/ErrorBoundary";
import { getFlowDetail } from "../../services/predictionService";
import { useModeVersion } from "../../hooks/useModeVersion";
import type { FlowDetail, PredictionHistoryEntry, ShapFeature } from "../../types/prediction";
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
      {positive ? "+" : ""}{Number.isFinite(impact) ? impact.toFixed(3) : "n/a"}
    </span>
  </div>;
}

function ExpandedRow({ entry, analysis }: { entry: PredictionHistoryEntry; analysis?: AgentAnalysisResponse["analysis"] | null }) {
  // /history rows carry only the verdict; fetch this flow's explanation when
  // the row is opened (and again if the Hybrid | V8 view is switched).
  const modeVersion = useModeVersion();
  const [detail, setDetail] = useState<FlowDetail | null>(null);
  useEffect(() => {
    let active = true;
    setDetail(null);
    getFlowDetail(entry.flow_id)
      .then((res) => { if (active && "top_features" in res) setDetail(res); })
      .catch(() => {});
    return () => { active = false; };
  }, [entry.flow_id, modeVersion]);

  // Never trust payload shapes in the render path: only objects with a real
  // numeric impact are drawn as bars, and text lines must be strings.
  const features: ShapFeature[] = [...(detail?.top_features ?? []), ...(Array.isArray(entry.supporting_features) ? (entry.supporting_features as unknown[]) : [])]
    .filter((f): f is ShapFeature => !!f && typeof f === "object" && typeof (f as ShapFeature).feature === "string" && Number.isFinite((f as ShapFeature).impact))
    .filter((f, index, all) => all.findIndex((other) => other.feature === f.feature) === index)
    .slice(0, 8);
  // Plain-language reason for the verdict. The SHAP bars explain XGBoost
  // only, so when the Isolation Forest is what raised the alarm they point
  // the other way - say so instead of leaving the row self-contradicting.
  const flagged = Number(entry.hybrid_prediction) === 1;
  const xgbFired = Number(entry.xgb_prediction) === 1;
  const isoFired = Number(entry.isolation_prediction) === 1;
  const xgbPct = Number.isFinite(entry.xgb_probability) ? `${(entry.xgb_probability * 100).toFixed(1)}%` : "n/a";
  const whyFlagged = entry.fusion_mode === "v8"
    ? (flagged
      ? `V8 raises an alarm when either detector fires. ${isoFired ? "The Isolation Forest found the flow unusual" : ""}${isoFired && xgbFired ? ", and " : ""}${xgbFired ? "XGBoost rated it an attack" : ""}${!xgbFired ? ` (XGBoost alone said normal: ${xgbPct}, below its alarm line)` : ""}.`
      : `Both detectors left this flow alone (XGBoost ${xgbPct}, Isolation Forest normal).`)
    : (Number.isFinite(entry.confidence_score ?? NaN)
      ? `The hybrid scores 0.7 x XGBoost (${xgbPct}) + 0.3 x Isolation Forest anomaly (${Number(entry.isolation_anomaly ?? 0).toFixed(2)}) = ${Number(entry.confidence_score).toFixed(3)}, which ${flagged ? "reached" : "stayed below"} its alert line.`
      : null);
  const hypothesis = detail?.attack_hypothesis ?? entry.attack_hypothesis;
  const summary = detail?.summary ?? entry.explanation_summary;
  const reasoning = (entry.reasoning ?? []).filter((line): line is string => typeof line === "string");
  const details = (entry.detailed_explanation ?? []).filter((line): line is string => typeof line === "string");

  return <tr><td colSpan={9} className="bg-slate-900/60 px-6 py-5">
    <div className="grid gap-6 lg:grid-cols-2">
      <div>
        <h4 className="mb-3 text-sm font-semibold text-slate-200">Feature Impact (SHAP)</h4>
        {features.length > 0 ? features.map((f) => <FeatureBar key={f.feature} name={f.feature} impact={f.impact} />)
          : <p className="text-xs text-slate-500">No feature data available for this flow.</p>}
        <p className="mt-2 text-xs text-slate-500">Red = pushes toward attack, Green = pushes toward normal. These bars explain XGBoost only, not the Isolation Forest.</p>
      </div>
      <div>
        {whyFlagged && <div className="mb-4 rounded-lg border border-white/10 bg-white/[0.04] p-3">
          <h4 className="mb-1 text-sm font-semibold text-slate-200">Why this verdict</h4>
          <p className="text-xs leading-5 text-slate-300">{whyFlagged}</p>
        </div>}
        {hypothesis && <div className="mb-4">
          <h4 className="mb-1 text-sm font-semibold text-slate-200">AI Hypothesis <span className="text-[10px] font-normal text-slate-500">(rule-based text from XGBoost's features; it can disagree with the verdict)</span></h4>
          <p className="text-sm text-slate-300">{hypothesis}</p>
          {summary && <p className="mt-1 text-xs text-slate-400">{summary}</p>}
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
    {entries.length === 0 ? <div className="p-6"><EmptyState title="No connections checked yet" description="As soon as the system sees network traffic, simple results and next steps will appear here." /></div> : <div className="overflow-x-auto"><table className="w-full min-w-[1180px] text-left text-sm"><thead className="bg-slate-900/50 text-xs uppercase tracking-wider text-slate-500"><tr><th className="px-6 py-4 font-medium">Connection</th><th className="px-6 py-4 font-medium">Time checked</th><th className="px-6 py-4 font-medium">Overall result</th><th className="px-6 py-4 font-medium">AI check 1</th><th className="px-6 py-4 font-medium">AI check 2</th><th className="px-6 py-4 font-medium">Do they agree?</th><th className="px-6 py-4 font-medium">Risk</th><th className="px-6 py-4 font-medium">What you should do</th>{driftDetected !== undefined && <th className="px-6 py-4 font-medium">Traffic changed?</th>}</tr></thead><tbody className="divide-y divide-white/5 text-slate-300">{entries.map((entry) => { const attack = isAttack(entry.hybrid_prediction); const agreed = agreement(entry); const agent = String(latestAnalysis?.flow_id) === String(entry.flow_id) ? latestAnalysis?.analysis : null; const risk = agent?.severity?.toUpperCase() || riskLevel(entry); const expanded = expandedId === entry.flow_id; return <Fragment key={`${entry.flow_id}-${entry.observedAt}`}><tr onClick={() => setExpandedId(expanded ? null : entry.flow_id)} className={`cursor-pointer transition-colors hover:bg-white/[0.04] ${expanded ? "bg-white/[0.03]" : ""}`}><td className="px-6 py-4 font-mono text-xs text-sky-300">#{entry.flow_id} {expanded ? <span className="text-slate-500">▼</span> : <span className="text-slate-600">▶</span>}</td><td className="px-6 py-4 whitespace-nowrap text-slate-400">{displayTimestamp(entry.observedAt)}</td><td className="px-6 py-4"><Badge text={attack ? "NEEDS REVIEW" : "LOOKS NORMAL"} variant={attack ? "danger" : "success"} /></td><td className="px-6 py-4">{isAttack(entry.xgb_prediction) ? "Attack likely" : "Looks normal"} {Number.isFinite(entry.xgb_probability) && <span className="text-xs text-slate-500"> ({(entry.xgb_probability * 100).toFixed(1)}%)</span>}</td><td className="px-6 py-4">{isAttack(entry.isolation_prediction) ? "Unusual traffic found" : "Looks normal"}</td><td className="px-6 py-4"><Badge text={agreed ? "YES" : "NO — REVIEW"} variant={agreed ? "success" : "warning"} /></td><td className="px-6 py-4"><Badge text={risk} variant={riskVariant(risk)} /></td><td className="max-w-72 px-6 py-4 text-xs leading-5 text-slate-300">{agent?.incident_report?.recommended_next_step || agent?.recommended_mitigation?.[0] || nextAction(entry)}</td>{driftDetected !== undefined && <td className="px-6 py-4"><Badge text={driftDetected ? "YES — CHECK" : "NO"} variant={driftDetected ? "warning" : "success"} /></td>}</tr>{expanded && <tr><td colSpan={9}><ErrorBoundary label="The explanation"><table className="w-full"><tbody><ExpandedRow entry={entry} analysis={agent} /></tbody></table></ErrorBoundary></td></tr>}</Fragment>;})}</tbody></table></div>}
  </Card>;
}
