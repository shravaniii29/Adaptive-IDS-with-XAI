import Card from "../common/Card";
import Badge from "../common/Badge";
import Tooltip from "../common/Tooltip";
import type { ExperimentalVariantResult } from "../../types/experimentalModels";

export default function ExperimentalModelCard({ result, fallbackLabel, disclaimer }: { result: ExperimentalVariantResult | undefined; fallbackLabel: string; disclaimer: string }) {
  if (!result) {
    return (
      <Card>
        <div className="flex items-center justify-between">
          <p className="text-sm text-slate-400">{fallbackLabel}</p>
          <Badge text="EXPERIMENTAL" variant="warning" />
        </div>
        <h2 className="mt-1 text-xl font-semibold text-white">Waiting for a flow</h2>
      </Card>
    );
  }

  if (!result.available) {
    return (
      <Card>
        <div className="flex items-center justify-between">
          <p className="text-sm text-slate-400">{fallbackLabel}</p>
          <Badge text="EXPERIMENTAL" variant="warning" />
        </div>
        <h2 className="mt-1 text-xl font-semibold text-white">Unavailable</h2>
        {result.error && <p className="mt-2 text-xs leading-5 text-slate-500">{result.error}</p>}
      </Card>
    );
  }

  const attack = result.prediction === 1;
  const probabilityPct = result.probability !== undefined ? Math.round(result.probability * 100) : null;

  return (
    <Card>
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm text-slate-400">{result.label ?? fallbackLabel}</p>
        <Tooltip label={disclaimer}>
          <Badge text="EXPERIMENTAL" variant="warning" />
        </Tooltip>
      </div>

      <div className="mt-2 flex items-center justify-between">
        <h2 className="text-xl font-semibold text-white">{probabilityPct !== null ? `${probabilityPct}%` : "—"}</h2>
        <Badge text={attack ? "ATTACK" : "NORMAL"} variant={attack ? "danger" : "success"} />
      </div>

      <p className="mt-3 text-xs leading-5 text-slate-500">
        Not the deployed detector - research model, disclosed limitations apply.
      </p>
    </Card>
  );
}
