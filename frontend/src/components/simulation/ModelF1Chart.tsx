import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Card from "../common/Card";
import type { ModelMetrics } from "../../types/simulation";
import { modelLabel } from "../../types/simulation";

interface Props {
  aggregateMetrics: Record<string, ModelMetrics>;
}

const barColor = (f1: number) => {
  if (f1 >= 0.75) return "#22c55e";
  if (f1 >= 0.4) return "#eab308";
  return "#ef4444";
};

export default function ModelF1Chart({ aggregateMetrics }: Props) {
  const data = Object.entries(aggregateMetrics)
    .map(([key, metrics]) => ({
      key,
      name: modelLabel(key),
      f1: Math.round((metrics.f1 ?? 0) * 1000) / 10,
    }))
    .sort((a, b) => b.f1 - a.f1);

  return (
    <Card>
      <p className="text-sm text-slate-400">Overall model comparison</p>
      <h2 className="mt-1 text-xl font-semibold text-white">F1 score, all models</h2>
      <p className="mt-1 text-xs text-slate-500">Pooled across every scenario in this run.</p>

      <div className="mt-5 h-96">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ left: 24 }}>
            <CartesianGrid stroke="#334155" strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" domain={[0, 100]} tick={{ fill: "#94a3b8" }} unit="%" />
            <YAxis type="category" dataKey="name" width={190} tick={{ fill: "#94a3b8", fontSize: 12 }} />
            <Tooltip
              contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8 }}
              labelStyle={{ color: "#e2e8f0" }}
              formatter={(value) => [`${value}%`, "F1 score"]}
            />
            <Bar dataKey="f1" radius={[0, 6, 6, 0]}>
              {data.map((entry) => (
                <Cell key={entry.key} fill={barColor(entry.f1 / 100)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
