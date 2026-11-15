import { useCallback, useEffect, useRef, useState } from "react";
import { Loader2, Radio, Send, Square } from "lucide-react";
import Card from "../common/Card";
import {
  cancelRemoteAttack,
  getRemoteAttackStatus,
  REMOTE_SCENARIOS,
  startRemoteAttack,
  type RemoteRunStatus,
} from "../../services/remoteRunService";

const phaseLabel: Record<string, string> = {
  running: "Starting…",
  awaiting_approval: "Waiting for the other PC to approve…",
  attacking: "Sending the attack…",
  finished: "Done — check the target's Live Logs",
  stopped: "Stopped before it finished",
};

const phaseTone = (phase?: string) =>
  phase === "finished" ? "text-emerald-200"
  : phase === "stopped" ? "text-rose-200"
  : phase === "awaiting_approval" ? "text-amber-200"
  : "text-sky-200";

// Launches an attack at ANOTHER PC on the LAN, through the consent handshake:
// the target PC's operator must approve it on their own dashboard before any
// packet is sent. Demonstrates a cross-device detection. See
// /simulations/run_remote and lan_consent_test.py.
export default function RemoteAttackPanel() {
  const [backend, setBackend] = useState("");
  const [scenario, setScenario] = useState(REMOTE_SCENARIOS[0].id);
  const [duration, setDuration] = useState(10);
  const [status, setStatus] = useState<RemoteRunStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const timer = useRef<number | null>(null);

  const poll = useCallback(() => {
    getRemoteAttackStatus()
      .then((s) => setStatus(s))
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    poll();
    timer.current = window.setInterval(poll, 2000);
    return () => { if (timer.current) window.clearInterval(timer.current); };
  }, [poll]);

  const running = status?.running ?? false;

  const start = async () => {
    setError(null);
    if (!backend.trim()) { setError("Enter the target PC's backend address, e.g. http://192.168.1.20:8000"); return; }
    setStarting(true);
    try {
      await startRemoteAttack({ target_backend: backend.trim(), scenario, duration });
      poll();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not start the remote attack");
    } finally {
      setStarting(false);
    }
  };

  return (
    <Card>
      <div className="flex items-start gap-3">
        <Radio className="mt-0.5 shrink-0 text-indigo-300" size={20} />
        <div>
          <p className="text-sm text-slate-400">Cross-device demo</p>
          <h2 className="mt-1 text-xl font-semibold text-white">Attack another PC on your LAN</h2>
          <p className="mt-1 text-xs text-slate-500">
            Sends one bounded scenario at another machine running this IDS. That machine's operator must approve the
            request on their own dashboard first — nothing is sent until they do. Only use it on machines you own or are
            authorised to test.
          </p>
        </div>
      </div>

      {!running ? (
        <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-[1fr_auto_auto_auto] sm:items-end">
          <label className="block text-sm">
            <span className="mb-1 block text-slate-400">Target PC backend</span>
            <input
              value={backend}
              onChange={(e) => setBackend(e.target.value)}
              placeholder="http://192.168.1.20:8000"
              spellCheck={false}
              className="w-full rounded-xl border border-white/10 bg-[#111827] px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-indigo-400/50"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-slate-400">Scenario</span>
            <select
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
              className="w-full rounded-xl border border-white/10 bg-[#111827] px-3 py-2 text-sm text-slate-100 outline-none focus:border-indigo-400/50 sm:w-auto"
            >
              {REMOTE_SCENARIOS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-slate-400">Seconds</span>
            <select
              value={duration}
              onChange={(e) => setDuration(Number(e.target.value))}
              className="w-full rounded-xl border border-white/10 bg-[#111827] px-3 py-2 text-sm text-slate-100 outline-none focus:border-indigo-400/50 sm:w-auto"
            >
              {[5, 10, 15].map((n) => <option key={n} value={n}>{n}s</option>)}
            </select>
          </label>
          <button
            onClick={start}
            disabled={starting}
            className="flex items-center justify-center gap-2 rounded-xl bg-indigo-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-400 disabled:opacity-50"
          >
            {starting ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
            Request &amp; run
          </button>
        </div>
      ) : (
        <button
          onClick={() => cancelRemoteAttack().catch(() => undefined)}
          className="mt-5 flex items-center gap-2 rounded-xl bg-rose-500/15 px-4 py-2 text-sm font-semibold text-rose-200 ring-1 ring-inset ring-rose-400/30 transition hover:bg-rose-500/25"
        >
          <Square size={16} /> Cancel
        </button>
      )}

      {error && <p className="mt-4 text-sm text-rose-300">{error}</p>}

      {status && (status.running || status.phase === "finished" || status.phase === "stopped") && (
        <div className="mt-5 rounded-xl border border-white/10 bg-black/30 p-4">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
            <span className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${running ? "animate-pulse bg-amber-400" : status.phase === "finished" ? "bg-emerald-400" : "bg-rose-400"}`} />
              <span className={phaseTone(status.phase)}>{phaseLabel[status.phase ?? "running"]}</span>
            </span>
            {status.scenario && <span className="text-slate-400">scenario: <span className="text-slate-200">{status.scenario}</span></span>}
            {status.target_backend && <span className="text-slate-400">target: <span className="font-mono text-slate-200">{status.target_backend}</span></span>}
          </div>
          {status.log_tail && (
            <pre className="mt-3 max-h-40 overflow-y-auto whitespace-pre-wrap break-words rounded-lg bg-black/40 p-3 font-mono text-xs text-slate-400">{status.log_tail}</pre>
          )}
        </div>
      )}
    </Card>
  );
}
