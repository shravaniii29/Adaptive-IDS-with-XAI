import { useState } from "react";
import { Loader2, Play, Square } from "lucide-react";
import Card from "../common/Card";
import type { SimulationRunStatus } from "../../types/simulation";

interface Props {
  status: SimulationRunStatus | null;
  error: string | null;
  onStart: (trials: number) => Promise<void>;
  onCancel: () => void;
}

const formatElapsed = (seconds: number | null) => {
  if (seconds === null) return "0:00";
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${String(s).padStart(2, "0")}`;
};

// Every scenario takes its own duration plus a mandatory drain, so trial
// count directly drives how long a real run takes - shown so "Run" isn't
// a mystery-length action. Matches DRAIN_SECONDS/SCENARIO_GAP_SECONDS/
// TRIAL_COOLDOWN in simulate_attacks.py.
const estimateMinutes = (trials: number) => Math.round(((10 + 35) * 6 * trials + 5 * (trials - 1) + 35) / 60);

export default function RunSimulationPanel({ status, error, onStart, onCancel }: Props) {
  const [trials, setTrials] = useState(1);
  const [starting, setStarting] = useState(false);

  const running = status?.running ?? false;

  const handleStart = async () => {
    setStarting(true);
    try {
      await onStart(trials);
    } catch {
      // surfaced via the `error` prop
    } finally {
      setStarting(false);
    }
  };

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">Trigger a new run</p>
          <h2 className="mt-1 text-xl font-semibold text-white">Run live simulation</h2>
          <p className="mt-1 text-xs text-slate-500">
            Launches simulate_attacks.py against this machine's own loopback interface - self-targeted, real
            packets, real detection results.
          </p>
        </div>

        {!running ? (
          <div className="flex items-center gap-3">
            <label className="text-sm text-slate-400" htmlFor="trial-count">
              Trials
            </label>
            <select
              id="trial-count"
              value={trials}
              onChange={(event) => setTrials(Number(event.target.value))}
              className="rounded-xl border border-white/10 bg-[#111827] px-3 py-2 text-sm text-slate-100 outline-none focus:border-indigo-400/50"
            >
              {[1, 2, 3, 5].map((n) => (
                <option key={n} value={n}>
                  {n} trial{n === 1 ? "" : "s"} (~{estimateMinutes(n)} min)
                </option>
              ))}
            </select>
            <button
              onClick={handleStart}
              disabled={starting}
              className="flex items-center gap-2 rounded-xl bg-indigo-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-400 disabled:opacity-50"
            >
              {starting ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
              Run simulation
            </button>
          </div>
        ) : (
          <button
            onClick={onCancel}
            className="flex items-center gap-2 rounded-xl bg-rose-500/15 px-4 py-2 text-sm font-semibold text-rose-200 ring-1 ring-inset ring-rose-400/30 transition hover:bg-rose-500/25"
          >
            <Square size={16} />
            Cancel run
          </button>
        )}
      </div>

      {error && <p className="mt-4 text-sm text-rose-300">{error}</p>}

      {status && (running || status.out_dir) && (
        <div className="mt-5 rounded-xl border border-white/10 bg-black/30 p-4">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
            <span className="flex items-center gap-2">
              {running ? (
                <>
                  <span className="h-2 w-2 animate-pulse rounded-full bg-amber-400" />
                  <span className="text-amber-200">Running</span>
                </>
              ) : (
                <>
                  <span className={`h-2 w-2 rounded-full ${status.exit_code === 0 ? "bg-emerald-400" : "bg-rose-400"}`} />
                  <span className={status.exit_code === 0 ? "text-emerald-200" : "text-rose-200"}>
                    {status.exit_code === 0 ? "Finished" : `Exited (code ${status.exit_code})`}
                  </span>
                </>
              )}
            </span>
            <span className="text-slate-400">
              out_dir: <span className="text-slate-200">{status.out_dir}</span>
            </span>
            <span className="text-slate-400">
              trials: <span className="text-slate-200">{status.trials}</span>
            </span>
            <span className="text-slate-400">
              elapsed: <span className="text-slate-200">{formatElapsed(status.elapsed_seconds)}</span>
            </span>
          </div>

          {status.log_tail && (
            <pre className="mt-3 max-h-56 overflow-y-auto whitespace-pre-wrap break-words rounded-lg bg-black/40 p-3 font-mono text-xs text-slate-400">
              {status.log_tail}
            </pre>
          )}
        </div>
      )}
    </Card>
  );
}
