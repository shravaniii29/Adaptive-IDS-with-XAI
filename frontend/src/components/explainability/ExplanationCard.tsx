import Card from "../common/Card";
import EmptyState from "../common/EmptyState";
import type { ShapExplanation } from "../../types/shap";

const friendlyFeature: Record<string, { name: string; meaning: string }> = {
  "Fwd Header Len": { name: "Packet header size", meaning: "how much routing information was sent with outgoing packets" },
  "Pkt Len Max": { name: "Largest packet size", meaning: "the size of the biggest piece of data in this connection" },
  "Subflow Fwd Byts": { name: "Outgoing data volume", meaning: "how much data was sent out in this part of the connection" },
  "Init Bwd Win Byts": { name: "Incoming connection capacity", meaning: "how much data the remote side was ready to receive" },
  "iat variation": { name: "Timing variation", meaning: "whether the gaps between packets were unusually irregular" },
};
const fallback = (feature?: string | null) => ({
  name: (feature ?? "Unknown feature").replace(/_/g, " "),
  meaning: "a network traffic measurement",
});

export default function ExplanationCard({ explanation }: { explanation: ShapExplanation | null }) {
  return <Card className="h-full"><div className="mb-5"><p className="text-sm text-slate-400">Why the system made this decision</p><h2 className="mt-1 text-xl font-semibold text-white">What the AI noticed</h2></div>
    {!explanation ? <EmptyState title="Waiting for an explanation" description="After the next flow is checked, this area will explain the decision in everyday language." /> : <><p className="mb-4 text-sm leading-6 text-slate-300">The system compares small details of the connection. Red means a detail made the traffic look more risky; green means it made the traffic look safer.</p><div className="space-y-4">{explanation.top_features.map((item) => { const positive = item.impact >= 0; const magnitude = Math.min(Math.abs(item.impact) * 100, 100); const feature = friendlyFeature[item.feature] || fallback(item.feature); return <div key={item.feature}><div className="flex items-center justify-between gap-3 text-sm"><span className="font-medium text-slate-200">{feature.name}</span><span className={positive ? "text-red-300" : "text-emerald-300"}>{positive ? "More risky" : "More normal"}</span></div><p className="mt-1 text-xs leading-5 text-slate-400">This measures {feature.meaning}.</p><div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-800"><div className={positive ? "h-full bg-red-400" : "h-full bg-emerald-400"} style={{ width: `${magnitude}%` }} /></div></div>; })}</div></>}
  </Card>;
}
