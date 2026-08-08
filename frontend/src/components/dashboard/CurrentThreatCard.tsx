import Card from "../common/Card";
import Badge from "../common/Badge";
import { ShieldAlert, Activity } from "lucide-react";

interface CurrentThreatCardProps {
  flowId: string;
  verdict: "ATTACK" | "NORMAL";
  probability: number;
  xgbPrediction: string;
  isolationPrediction: string;
}

export default function CurrentThreatCard({
  flowId,
  verdict,
  probability,
  xgbPrediction,
  isolationPrediction,
}: CurrentThreatCardProps) {
  const isAttack = verdict === "ATTACK";

  return (
    <Card className="col-span-2">
      <div className="flex items-center justify-between mb-6">
        <div>
          <p className="text-sm text-slate-400">
            Current Threat Analysis
          </p>

          <h2 className="text-2xl font-bold mt-1">
            {flowId}
          </h2>
        </div>

        <Badge
          text={verdict}
          variant={isAttack ? "danger" : "success"}
        />
      </div>

      <div className="grid md:grid-cols-3 gap-6">

        <div className="rounded-xl bg-slate-800/50 p-5">
          <ShieldAlert
            className={`mb-3 ${
              isAttack
                ? "text-red-400"
                : "text-green-400"
            }`}
            size={34}
          />

          <p className="text-sm text-slate-400">
            Threat Probability
          </p>

          <h1 className="text-4xl font-bold mt-2">
            {(probability * 100).toFixed(1)}%
          </h1>
        </div>

        <div className="rounded-xl bg-slate-800/50 p-5">
          <Activity
            className="text-indigo-400 mb-3"
            size={34}
          />

          <p className="text-sm text-slate-400">
            XGBoost
          </p>

          <h2 className="text-xl font-semibold mt-2">
            {xgbPrediction}
          </h2>
        </div>

        <div className="rounded-xl bg-slate-800/50 p-5">
          <Activity
            className="text-yellow-400 mb-3"
            size={34}
          />

          <p className="text-sm text-slate-400">
            Isolation Forest
          </p>

          <h2 className="text-xl font-semibold mt-2">
            {isolationPrediction}
          </h2>
        </div>

      </div>
    </Card>
  );
}