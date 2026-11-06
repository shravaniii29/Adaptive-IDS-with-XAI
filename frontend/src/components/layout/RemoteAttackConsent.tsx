import { useCallback, useEffect, useState } from "react";
import { ShieldQuestion, Check, X } from "lucide-react";
import {
  approveRemoteAttackRequest,
  denyRemoteAttackRequest,
  listRemoteAttackRequests,
  SCENARIO_LABELS,
  type RemoteAttackRequest,
} from "../../services/remoteAttackService";

// Polls this backend for remote-test requests other machines on the LAN have
// raised, and lets the operator approve or deny each one. Nothing a remote
// machine asks for runs until Approve is clicked here. See
// /remote_attack/* in app/main.py.
export default function RemoteAttackConsent() {
  const [pending, setPending] = useState<RemoteAttackRequest[]>([]);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    listRemoteAttackRequests()
      .then((data) => setPending(data.requests.filter((r) => r.status === "pending")))
      .catch(() => setPending([]));
  }, []);

  useEffect(() => {
    load();
    const id = window.setInterval(load, 3000);
    return () => window.clearInterval(id);
  }, [load]);

  const decide = (id: string, approve: boolean) => {
    if (busy) return;
    setBusy(id);
    const call = approve ? approveRemoteAttackRequest(id) : denyRemoteAttackRequest(id);
    call.catch(() => undefined).finally(() => { setBusy(null); load(); });
  };

  if (pending.length === 0) return null;

  return (
    <div className="pointer-events-auto fixed bottom-4 right-4 z-50 w-80 space-y-3">
      {pending.map((req) => {
        const secondsLeft = Math.max(0, Math.round(req.expires_at - Date.now() / 1000));
        return (
          <div
            key={req.id}
            className="rounded-xl border border-amber-400/30 bg-slate-900 p-4 shadow-2xl ring-1 ring-amber-400/10"
          >
            <div className="mb-2 flex items-center gap-2 text-amber-200">
              <ShieldQuestion size={18} />
              <h3 className="text-sm font-semibold">Remote test request</h3>
            </div>
            <p className="text-xs text-slate-300">
              <span className="font-mono text-slate-100">{req.source_ip}</span> wants to run a{" "}
              <span className="font-medium text-amber-200">
                {SCENARIO_LABELS[req.scenario] ?? req.scenario}
              </span>{" "}
              against this machine for {req.duration}s.
            </p>
            <p className="mt-1 text-[11px] text-slate-500">
              Expires in {secondsLeft}s · nothing runs until you approve.
            </p>
            <div className="mt-3 flex gap-2">
              <button
                type="button"
                disabled={busy === req.id}
                onClick={() => decide(req.id, true)}
                className="flex flex-1 items-center justify-center gap-1 rounded-lg bg-emerald-500 py-1.5 text-xs font-semibold text-white transition hover:bg-emerald-400 disabled:opacity-50"
              >
                <Check size={14} /> Approve
              </button>
              <button
                type="button"
                disabled={busy === req.id}
                onClick={() => decide(req.id, false)}
                className="flex flex-1 items-center justify-center gap-1 rounded-lg border border-white/10 bg-white/5 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 disabled:opacity-50"
              >
                <X size={14} /> Deny
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
