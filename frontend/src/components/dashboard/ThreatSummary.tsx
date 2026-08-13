import Card from "../common/Card";

interface ThreatSummaryProps {
  attacks: number;
  normal: number;
  benignPackets?: number;
  attackPackets?: number;
}

export default function ThreatSummary({
  attacks,
  normal,
  benignPackets = 0,
  attackPackets = 0,
}: ThreatSummaryProps) {

  const totalFlows = attacks + normal;
  const totalPackets = benignPackets + attackPackets;

  const attackPercent =
    totalFlows === 0
      ? 0
      : Math.round((attacks / totalFlows) * 100);

  return (
    <Card>

      <p className="text-sm text-slate-400">
        Threat & Packet Summary
      </p>

      <div className="mt-4">

        <div className="flex justify-between mb-2 text-sm">

          <span>Attack Flow Rate</span>

          <span className="font-semibold text-slate-200">{attackPercent}%</span>

        </div>

        <div className="h-2 rounded-full bg-slate-800 overflow-hidden">

          <div
            className="h-full bg-red-500 rounded-full"
            style={{
              width: `${attackPercent}%`,
            }}
          />

        </div>

        <div className="mt-4 grid grid-cols-2 gap-4 border-b border-white/5 pb-4">

          <div>

            <p className="text-slate-400 text-xs">
              Normal Flows
            </p>

            <h2 className="text-xl font-bold text-green-400">
              {normal}
            </h2>

          </div>

          <div>

            <p className="text-slate-400 text-xs">
              Attack Flows
            </p>

            <h2 className="text-xl font-bold text-red-400">
              {attacks}
            </h2>

          </div>

        </div>

        {/* Aggregated Packet Counts */}
        <div className="mt-3">
          <p className="text-xs text-slate-400 font-medium">
            Packets Aggregated from Classified Flows
          </p>

          <div className="mt-2 grid grid-cols-3 gap-2 text-center">

            <div className="rounded-lg bg-slate-800/40 p-2">
              <p className="text-[10px] text-slate-400">Benign</p>
              <p className="text-sm font-semibold text-green-400">{benignPackets}</p>
            </div>

            <div className="rounded-lg bg-slate-800/40 p-2">
              <p className="text-[10px] text-slate-400">Attack</p>
              <p className="text-sm font-semibold text-red-400">{attackPackets}</p>
            </div>

            <div className="rounded-lg bg-slate-800/40 p-2">
              <p className="text-[10px] text-slate-400">Total</p>
              <p className="text-sm font-semibold text-sky-400">{totalPackets}</p>
            </div>

          </div>

        </div>

      </div>

    </Card>
  );
}