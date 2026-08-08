import Card from "../common/Card";
import Badge from "../common/Badge";
import { Cpu } from "lucide-react";

interface SystemHealthCardProps {
  uptime: string;
  status: "Healthy" | "Warning" | "Critical";
}

export default function SystemHealthCard({
  uptime,
  status,
}: SystemHealthCardProps) {
  return (
    <Card>

      <div className="flex justify-between">

        <div>

          <p className="text-sm text-slate-400">
            System Health
          </p>

          <h2 className="text-xl font-semibold mt-1">
            IDS Runtime
          </h2>

        </div>

        <Badge
          text={status}
          variant={
            status === "Healthy"
              ? "success"
              : status === "Warning"
              ? "warning"
              : "danger"
          }
        />

      </div>

      <div className="mt-6 flex gap-4">

        <Cpu
          className="text-indigo-400"
          size={34}
        />

        <div>

          <p className="text-slate-400">
            Uptime
          </p>

          <h1 className="text-3xl font-bold mt-1">
            {uptime}
          </h1>

        </div>

      </div>

    </Card>
  );
}