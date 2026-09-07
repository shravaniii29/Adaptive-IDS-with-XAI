import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Card from "../common/Card";
import type { ScenarioResult } from "../../types/simulation";
import { modelLabel } from "../../types/simulation";

interface Props {
  scenario: ScenarioResult;
}

// Red (low) -> yellow (mid) -> green (high), interpolated in HSL. High is
// always good here: recall on an attack scenario, specificity on the
// benign one - both are "% this model got right for this scenario".
const barColor = (pct: number) => {
  const hue = Math.round((pct / 100) * 120);
  return `hsl(${hue}, 70%, 50%)`;
};

export default function ScenarioModelChart({ scenario }: Props) {
  const metric = scenario.is_attack ? "recall" : "specificity";

  const data = Object.entries(scenario.model_scores)
    .filter(([, value]) => value !== null)
    .map(([key, value]) => ({
      key,
      name: modelLabel(key),
      pct: Math.round((value as number) * 1000) / 10,
    }))
    .sort((a, b) => b.pct - a.pct);

  return (
    <Card>
      <p className="text-sm text-slate-400">{scenario.name}</p>
      <h2 className="mt-1 text-xl font-semibold text-white">
        {scenario.is_attack ? "Recall" : "Specificity"} by model
      </h2>
      <p className="mt-1 text-xs text-slate-500">
        {scenario.flow_count} flows attributed to this scenario · {metric} = % correctly flagged{" "}
        {scenario.is_attack ? "as attack" : "as benign"}.
      </p>

      <div className="mt-5" style={{ height: Math.max(320, data.length * 34) }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ left: 24 }}>
            <CartesianGrid stroke="#334155" strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" domain={[0, 100]} tick={{ fill: "#94a3b8" }} unit="%" />
            <YAxis type="category" dataKey="name" width={190} tick={{ fill: "#94a3b8", fontSize: 12 }} />
            <Tooltip
              contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8 }}
              labelStyle={{ color: "#e2e8f0" }}
              formatter={(value) => [`${value}%`, metric]}
            />
            <Bar dataKey="pct" radius={[0, 6, 6, 0]}>
              {data.map((entry) => (
                <Cell key={entry.key} fill={barColor(entry.pct)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
