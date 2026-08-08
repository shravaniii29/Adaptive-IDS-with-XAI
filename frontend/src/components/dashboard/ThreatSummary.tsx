import Card from "../common/Card";

interface ThreatSummaryProps {
  attacks: number;
  normal: number;
}

export default function ThreatSummary({
  attacks,
  normal,
}: ThreatSummaryProps) {

  const total = attacks + normal;

  const attackPercent =
    total === 0
      ? 0
      : Math.round((attacks / total) * 100);

  return (
    <Card>

      <p className="text-sm text-slate-400">
        Threat Summary
      </p>

      <div className="mt-6">

        <div className="flex justify-between mb-2">

          <span>Attack Rate</span>

          <span>{attackPercent}%</span>

        </div>

        <div className="h-3 rounded-full bg-slate-800 overflow-hidden">

          <div
            className="h-full bg-red-500 rounded-full"
            style={{
              width: `${attackPercent}%`,
            }}
          />

        </div>

        <div className="mt-6 flex justify-between">

          <div>

            <p className="text-slate-400 text-sm">
              Normal
            </p>

            <h2 className="text-2xl font-bold text-green-400">
              {normal}
            </h2>

          </div>

          <div>

            <p className="text-slate-400 text-sm">
              Attack
            </p>

            <h2 className="text-2xl font-bold text-red-400">
              {attacks}
            </h2>

          </div>

        </div>

      </div>

    </Card>
  );
}