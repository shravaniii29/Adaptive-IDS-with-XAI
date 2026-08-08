import Card from "../common/Card";
import Badge from "../common/Badge";
import { Wifi, Server } from "lucide-react";

interface ConnectionStatusProps {
  connected: boolean;
  backend: string;
  latency?: number;
}

export default function ConnectionStatus({
  connected,
  backend,
  latency,
}: ConnectionStatusProps) {
  return (
    <Card>

      <div className="flex items-center justify-between mb-6">

        <div>
          <p className="text-sm text-slate-400">
            Connection Status
          </p>

          <h2 className="text-xl font-semibold mt-1">
            Backend Service
          </h2>

        </div>

        <Badge
          text={connected ? "ONLINE" : "OFFLINE"}
          variant={connected ? "success" : "danger"}
        />

      </div>

      <div className="space-y-4">

        <div className="flex items-center gap-3">

          <Wifi
            className={
              connected
                ? "text-green-400"
                : "text-red-400"
            }
          />

          <div>

            <p className="text-sm text-slate-400">
              WebSocket
            </p>

            <p className="font-medium">
              {connected ? "Connected" : "Disconnected"}
            </p>

          </div>

        </div>

        <div className="flex items-center gap-3">

          <Server className="text-indigo-400" />

          <div>

            <p className="text-sm text-slate-400">
              Backend
            </p>

            <p className="font-medium">
              {backend}
            </p>

          </div>

        </div>

        <div className="pt-3 border-t border-slate-800 flex justify-between">

          <span className="text-slate-400">
            Latency
          </span>

          <span className="font-semibold text-sky-400">
            {latency === undefined ? "Not reported" : `${latency} ms`}
          </span>

        </div>

      </div>

    </Card>
  );
}
