import Card from "../common/Card";
import Badge from "../common/Badge";
import { TrendingUp } from "lucide-react";

interface DriftCardProps {
  detected: boolean;
  score?: number;
}

export default function DriftCard({
  detected,
  score,
}: DriftCardProps) {
  return (
    <Card>

      <div className="flex items-center justify-between">

        <div>

          <p className="text-sm text-slate-400">
            Concept Drift
          </p>

          <h2 className="text-xl font-semibold mt-1">
            Model Stability
          </h2>

        </div>

        <Badge
          text={detected ? "DRIFT" : "STABLE"}
          variant={detected ? "warning" : "success"}
        />

      </div>

      <div className="mt-6 flex items-center gap-4">

        <TrendingUp
          className={
            detected
              ? "text-yellow-400"
              : "text-green-400"
          }
          size={34}
        />

        <div>

          <p className="text-slate-400">
            Drift Score
          </p>

          <h1 className="text-4xl font-bold mt-1">
            {score === undefined ? "—" : score.toFixed(2)}
          </h1>

        </div>

      </div>

    </Card>
  );
}
