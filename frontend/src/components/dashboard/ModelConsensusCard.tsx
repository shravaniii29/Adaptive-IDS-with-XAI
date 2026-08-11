import Card from "../common/Card";
import Badge from "../common/Badge";
import type { Prediction } from "../../types/prediction";

const isAttack = (value: string | number) => value === 1 || String(value).toLowerCase() === "attack";

export default function ModelConsensusCard({ prediction }: { prediction: Prediction | null }) {
  if (!prediction) return <Card><p className="text-sm text-slate-400">Model consensus</p><h2 className="mt-1 text-xl font-semibold text-white">Waiting for a flow</h2></Card>;
  const agreed = String(prediction.xgb_prediction) === String(prediction.isolation_prediction);
  const score = agreed ? 100 : 50;
  return <Card><div className="flex items-start justify-between gap-3"><div><p className="text-sm text-slate-400">Model consensus</p><h2 className="mt-1 text-xl font-semibold text-white">{score}% confidence</h2></div><Badge text={agreed ? "AGREED" : "MIXED"} variant={agreed ? "success" : "warning"} /></div><div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-800"><div className={agreed ? "h-full bg-emerald-400" : "h-full bg-amber-400"} style={{ width: `${score}%` }} /></div><p className="mt-3 text-xs leading-5 text-slate-400">Agreement level: {agreed ? "Both XGBoost and Isolation Forest reached the same verdict." : "The models differ, so this flow should be reviewed."} Current decision: {isAttack(prediction.hybrid_prediction) ? "Attack" : "Normal"}.</p></Card>;
}
