import Card from "../common/Card";

interface DetectionGaugeProps {
  probability: number;
}

export default function DetectionGauge({
  probability,
}: DetectionGaugeProps) {

  const percent = Math.round(probability * 100);

  return (
    <Card>

      <p className="text-sm text-slate-400 mb-6">
        Detection Confidence
      </p>

      <div className="flex flex-col items-center">

        <div className="relative h-44 w-44 rounded-full border-[10px] border-slate-800 flex items-center justify-center">

          <div
            className="absolute left-0 top-0 h-full rounded-full bg-gradient-to-b from-indigo-500 to-cyan-400"
            style={{
              width: `${percent}%`,
              opacity: 0.15,
            }}
          />

          <div className="text-center">

            <h1 className="text-5xl font-bold">
              {percent}
            </h1>

            <p className="text-slate-400">
              %
            </p>

          </div>

        </div>

        <div className="mt-6 w-full">

          <div className="h-3 rounded-full bg-slate-800 overflow-hidden">

            <div
              className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-cyan-400 transition-all duration-700"
              style={{
                width: `${percent}%`,
              }}
            />

          </div>

        </div>

      </div>

    </Card>
  );
}