import { useCallback, useEffect, useState } from "react";
import { getDetectionMode, setDetectionMode, type DetectionModeState } from "../../services/modeService";
import { MODE_CHANGED_EVENT } from "../../hooks/useModeVersion";

const shortLabel: Record<string, string> = { confidence: "Hybrid", v8: "V8" };

// Kept outside the component so the switch never blanks out when it is
// re-mounted (page changes, hot reload): it renders the last known state
// straight away and refreshes it in the background.
let lastKnown: DetectionModeState | null = null;

// Both models score every flow all the time; this only chooses whose results
// the dashboard shows. The backend switches instantly (past flows included),
// and the event below makes every page refetch immediately.
export default function ModeSwitch() {
  const [state, setState] = useState<DetectionModeState | null>(lastKnown);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const apply = (value: DetectionModeState) => { lastKnown = value; setState(value); setError(null); };

  const load = useCallback(() => {
    getDetectionMode().then((value) => { lastKnown = value; setState(value); setError(null); }).catch(() => setError("Backend unavailable"));
  }, []);

  useEffect(() => { load(); const id = window.setInterval(load, 15000); return () => window.clearInterval(id); }, [load]);

  const choose = (mode: string) => {
    if (busy || state?.mode === mode) return;
    setBusy(true);
    // Optimistic: show the choice now, correct it if the backend refuses.
    if (state) apply({ ...state, mode });
    setDetectionMode(mode)
      .then((value) => { apply(value); window.dispatchEvent(new Event(MODE_CHANGED_EVENT)); })
      .catch((reason: Error) => { setError(reason.message); load(); })
      .finally(() => setBusy(false));
  };

  if (!state) return error ? <span className="hidden text-xs text-rose-300 lg:block">{error}</span> : null;

  return <div className="hidden items-center gap-2 lg:flex" title={error ?? "Both models score every flow; this chooses whose results are shown"}>
    <span className="text-xs text-slate-500">Showing</span>
    <div role="group" aria-label="Detection mode" className="flex rounded-lg border border-white/10 bg-white/5 p-0.5">
      {state.modes.map((option) => {
        const active = option.id === state.mode;
        return <button key={option.id} type="button" disabled={!option.available || busy} aria-pressed={active} title={option.label} onClick={() => choose(option.id)}
          className={`rounded-md px-3 py-1 text-xs font-medium transition ${active ? "bg-indigo-500 text-white" : "text-slate-400 hover:text-white"} disabled:cursor-not-allowed disabled:opacity-40`}>
          {shortLabel[option.id] ?? option.label}
        </button>;
      })}
    </div>
    {error && <span className="text-xs text-rose-300">{error}</span>}
  </div>;
}
