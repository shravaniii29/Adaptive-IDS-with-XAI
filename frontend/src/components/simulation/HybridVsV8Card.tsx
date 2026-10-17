import Card from "../common/Card";
import type { ModelMetrics, SimulationDetail } from "../../types/simulation";

const V8 = "v8_candidate";

// The two models compared: the deployed hybrid and V8 for a live run, or the
// earlier V7 prototype and V8 for the paper's offline evaluation entry.
function pickPair(detail: SimulationDetail) {
  const m = detail.aggregate_metrics;
  if (m["deployed_hybrid"] && m[V8]) return { a: "deployed_hybrid", aLabel: "Hybrid", title: "Hybrid vs V8", note: true };
  if (m["v7_baseline"] && m[V8]) return { a: "v7_baseline", aLabel: "V7", title: "V7 vs V8", note: false };
  return null;
}

const pct = (value: number | null | undefined) =>
  value === null || value === undefined || Number.isNaN(value) ? "—" : `${(value * 100).toFixed(1)}%`;

type Metric = { label: string; hint: string; pick: (m: ModelMetrics) => number | null };

const metrics: Metric[] = [
  { label: "Attack recall", hint: "attack flows caught", pick: (m) => m.recall },
  { label: "Specificity", hint: "normal flows left alone", pick: (m) => m.specificity },
  { label: "Precision", hint: "alerts that were real", pick: (m) => m.precision },
  { label: "F1", hint: "recall and precision together", pick: (m) => m.f1 },
  { label: "Accuracy", hint: "all flows judged correctly", pick: (m) => m.accuracy },
];

function Value({ value, best }: { value: number | null; best: boolean }) {
  return <span className={`text-lg font-semibold tabular-nums ${best ? "text-emerald-300" : "text-slate-200"}`}>{pct(value)}</span>;
}

function Bar({ value, color }: { value: number | null; color: string }) {
  const width = value === null || Number.isNaN(value) ? 0 : Math.max(0, Math.min(100, value * 100));
  return <div className="h-1.5 w-24 rounded-full bg-white/10"><div className="h-1.5 rounded-full" style={{ width: `${width}%`, background: color }} /></div>;
}

// Head-to-head of the two live detectors on the identical flows of one run:
// pooled metrics first, then each attack type (recall) and the benign
// baseline (specificity).
export default function HybridVsV8Card({ detail }: { detail: SimulationDetail }) {
  const pair = pickPair(detail);

  if (!pair) {
    return <Card><p className="text-sm text-slate-400">Hybrid vs V8</p><p className="mt-2 text-sm text-slate-300">This run did not score both the deployed hybrid and V8, so there is nothing to compare. Run a new simulation to see both.</p></Card>;
  }

  const HYBRID = pair.a;
  const hybrid = detail.aggregate_metrics[HYBRID];
  const v8 = detail.aggregate_metrics[V8];

  return <Card>
    <div className="mb-5">
      <p className="text-sm text-slate-400">Head to head</p>
      <h2 className="mt-1 text-xl font-semibold text-white">{pair.title}</h2>
    </div>

    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
      {metrics.map((metric) => {
        const a = metric.pick(hybrid);
        const b = metric.pick(v8);
        const aBest = a !== null && b !== null && a > b;
        const bBest = a !== null && b !== null && b > a;
        return <div key={metric.label} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500">{metric.label}</p>
          <p className="mb-3 text-[11px] text-slate-500">{metric.hint}</p>
          <div className="flex items-baseline justify-between"><span className="text-xs text-sky-300">{pair.aLabel}</span><Value value={a} best={aBest} /></div>
          <div className="mt-1 flex items-baseline justify-between"><span className="text-xs text-violet-300">V8</span><Value value={b} best={bBest} /></div>
        </div>;
      })}
    </div>

    <div className="mt-3 grid gap-3 text-xs text-slate-400 sm:grid-cols-2">
      <p>{pair.aLabel}: {hybrid.confusion_matrix.tp} attacks caught, {hybrid.confusion_matrix.fn} missed; {hybrid.confusion_matrix.fp} false alarms, {hybrid.confusion_matrix.tn} normal flows correct.</p>
      <p>V8: {v8.confusion_matrix.tp} attacks caught, {v8.confusion_matrix.fn} missed; {v8.confusion_matrix.fp} false alarms, {v8.confusion_matrix.tn} normal flows correct.</p>
    </div>

    <div className="mt-6 overflow-x-auto">
      <table className="w-full min-w-[560px] text-left text-sm">
        <thead className="text-xs uppercase tracking-wider text-slate-500">
          <tr><th className="py-2 pr-4 font-medium">Scenario</th><th className="py-2 pr-4 font-medium">Flows</th><th className="py-2 pr-4 font-medium text-sky-300">{pair.aLabel}</th><th className="py-2 font-medium text-violet-300">V8</th></tr>
        </thead>
        <tbody className="divide-y divide-white/5 text-slate-300">
          {detail.scenarios.map((scenario) => {
            const a = scenario.model_scores[HYBRID] ?? null;
            const b = scenario.model_scores[V8] ?? null;
            const aBest = a !== null && b !== null && a > b;
            const bBest = a !== null && b !== null && b > a;
            return <tr key={scenario.name}>
              <td className="py-3 pr-4"><span className="font-medium text-slate-100">{scenario.name}</span><span className="ml-2 text-xs text-slate-500">{scenario.is_attack ? "attack: caught" : "normal: left alone"}</span></td>
              <td className="py-3 pr-4 tabular-nums text-slate-400">{scenario.flow_count}</td>
              <td className="py-3 pr-4"><div className="flex items-center gap-3"><span className={`w-14 tabular-nums ${aBest ? "font-semibold text-emerald-300" : ""}`}>{pct(a)}</span><Bar value={a} color="#38bdf8" /></div></td>
              <td className="py-3"><div className="flex items-center gap-3"><span className={`w-14 tabular-nums ${bBest ? "font-semibold text-emerald-300" : ""}`}>{pct(b)}</span><Bar value={b} color="#a78bfa" /></div></td>
            </tr>;
          })}
        </tbody>
      </table>
    </div>
  </Card>;
}
