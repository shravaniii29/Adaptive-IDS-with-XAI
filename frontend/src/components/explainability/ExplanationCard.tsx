import Card from "../common/Card";
import EmptyState from "../common/EmptyState";
import type { ShapExplanation } from "../../types/shap";

const friendlyFeature: Record<string, { name: string; meaning: string }> = {
  "Fwd Header Len": { name: "Packet header size", meaning: "how much routing information was sent with outgoing packets" },
  "Pkt Len Max": { name: "Largest packet size", meaning: "the size of the biggest piece of data in this connection" },
  "Subflow Fwd Byts": { name: "Outgoing data volume", meaning: "how much data was sent out in this part of the connection" },
  "Init Bwd Win Byts": { name: "Incoming connection capacity", meaning: "how much data the remote side was ready to receive" },
  "iat variation": { name: "Timing variation", meaning: "whether the gaps between packets were unusually irregular" },
  // V8-mode features
  "Dst Port": { name: "Service contacted", meaning: "which network port the connection was addressed to" },
  "Init Fwd Win Byts": { name: "Sender's opening window", meaning: "how much data the sender said it could receive when the connection started" },
  "Fwd Pkt Len Mean": { name: "Average outgoing packet size", meaning: "how big the packets sent out were, on average" },
  "Fwd Pkt Len Max": { name: "Largest outgoing packet", meaning: "the biggest packet sent out in this connection" },
  "Fwd Seg Size Avg": { name: "Average outgoing segment size", meaning: "the typical size of the data chunks sent out" },
  "Pkt Len Std": { name: "Packet size variation", meaning: "how much packet sizes differ within this connection" },
  "Pkt Len Var": { name: "Packet size spread", meaning: "how widely packet sizes are spread within this connection" },
  "Bwd Pkts/s": { name: "Reply rate", meaning: "how many packets per second came back from the other side" },
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
