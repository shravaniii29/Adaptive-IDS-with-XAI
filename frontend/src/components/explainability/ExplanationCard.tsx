import Card from "../common/Card";
import EmptyState from "../common/EmptyState";
import type { ShapExplanation } from "../../types/shap";

const friendlyFeature: Record<string, { name: string; meaning: string }> = {
  "pkt_rate_ratio": { name: "Packet Rate Ratio", meaning: "the ratio of packet transmission rates" },
  "Flow Duration": { name: "Flow Duration", meaning: "the total duration of this connection" },
  "Flow IAT Max": { name: "Max Flow Interval", meaning: "the maximum delay between consecutive packets" },
  "Flow Pkts/s": { name: "Flow Packet Rate", meaning: "the number of packets transferred per second" },
  "Fwd Pkts/s": { name: "Forward Packet Rate", meaning: "outgoing packets sent per second" },
  "Flow IAT Mean": { name: "Mean Flow Interval", meaning: "the average delay between consecutive packets" },
  "Pkt Len Max": { name: "Largest Packet Size", meaning: "the size of the biggest piece of data in this connection" },
  "Pkt Size Avg": { name: "Average Packet Size", meaning: "the average payload size across all packets" },
  "Fwd IAT Tot": { name: "Total Forward Interval", meaning: "the cumulative time gap between outgoing packets" },
  "iat_variation": { name: "Timing Variation", meaning: "whether the gaps between packets were unusually irregular" },
  "iat variation": { name: "Timing Variation", meaning: "whether the gaps between packets were unusually irregular" },
  "Fwd Header Len": { name: "Packet Header Size", meaning: "how much routing information was sent with outgoing packets" },
  "Fwd IAT Mean": { name: "Mean Forward Interval", meaning: "the average gap between outgoing packets" },
  "Fwd IAT Max": { name: "Max Forward Interval", meaning: "the maximum gap between outgoing packets" },
  "Subflow Fwd Byts": { name: "Outgoing Data Volume", meaning: "how much data was sent out in this part of the connection" },
  "Flow IAT Std": { name: "Interval Variation (Std)", meaning: "the standard deviation of packet inter-arrival times" },
  "TotLen Fwd Pkts": { name: "Total Forward Bytes", meaning: "the total volume of data sent forward" },
  "Flow IAT Min": { name: "Min Flow Interval", meaning: "the smallest delay between consecutive packets" },
  "Init Bwd Win Byts": { name: "Incoming Connection Capacity", meaning: "how much data the remote side was ready to receive" },
  "Bwd Pkt Len Max": { name: "Max Response Packet Size", meaning: "the largest incoming response packet size" },
  "TotLen Bwd Pkts": { name: "Total Backward Bytes", meaning: "the total volume of data received" },
  "Subflow Bwd Byts": { name: "Incoming Data Volume", meaning: "the volume of data received in this subflow" },
  "Bwd Seg Size Avg": { name: "Average Response Segment Size", meaning: "the average size of incoming segments" },
  "Bwd Pkt Len Mean": { name: "Mean Response Packet Size", meaning: "the average size of incoming response packets" },
  "Bwd Pkt Len Std": { name: "Response Packet Size Variation", meaning: "the variation in incoming response packet sizes" },
  "Pkt Len Mean": { name: "Mean Packet Length", meaning: "the average length of all packets in the flow" },
};

const fallback = (featureKey?: string | null) => {
  if (!featureKey) return { name: "Network traffic feature", meaning: "a network traffic measurement" };
  const cleaned = featureKey.replace(/_/g, " ");
  return {
    name: cleaned,
    meaning: `the ${cleaned} measurement for this connection`,
  };
};

export default function ExplanationCard({ explanation }: { explanation: ShapExplanation | null }) {
  return (
    <Card className="h-full">
      <div className="mb-5">
        <p className="text-sm text-slate-400">Why the system made this decision</p>
        <h2 className="mt-1 text-xl font-semibold text-white">What the AI noticed</h2>
      </div>
      {!explanation || !explanation.top_features || explanation.top_features.length === 0 ? (
        <EmptyState title="Waiting for an explanation" description="After the next flow is checked, this area will explain the decision in everyday language." />
      ) : (
        <>
          <p className="mb-4 text-sm leading-6 text-slate-300">
            The system compares small details of the connection. Red means a detail made the traffic look more risky; green means it made the traffic look safer.
          </p>
          <div className="space-y-4">
            {explanation.top_features.map((item, index) => {
              const featureKey = typeof item === "string" ? item : (item?.feature ?? item?.name ?? "");
              const impact = typeof item === "object" && item !== null && typeof item.impact === "number" ? item.impact : 0;
              const positive = impact >= 0;
              const magnitude = Math.min(Math.abs(impact) * 100, 100);
              const featureInfo = friendlyFeature[featureKey] || fallback(featureKey);
              return (
                <div key={`${featureKey}-${index}`}>
                  <div className="flex items-center justify-between gap-3 text-sm">
                    <span className="font-medium text-slate-200">{featureInfo.name}</span>
                    <span className={positive ? "text-red-300" : "text-emerald-300"}>
                      {positive ? "More risky" : "More normal"}
                    </span>
                  </div>
                  <p className="mt-1 text-xs leading-5 text-slate-400">This measures {featureInfo.meaning}.</p>
                  <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-800">
                    <div
                      className={positive ? "h-full bg-red-400" : "h-full bg-emerald-400"}
                      style={{ width: `${magnitude > 0 ? magnitude : 20}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </Card>
  );
}
