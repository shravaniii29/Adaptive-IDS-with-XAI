import { useCallback, useEffect, useState } from "react";
import { getDetectionMode, setDetectionMode, type DetectionModeState } from "../../services/modeService";

const shortLabel: Record<string, string> = { confidence: "Hybrid", v8: "V8" };

// Switches which model is the primary detector. Flows already on screen keep
// the verdict they were scored with; new flows use the selected model.
export default function ModeSwitch() {
  const [state, setState] = useState<DetectionModeState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getDetectionMode().then((value) => { setState(value); setError(null); }).catch(() => setError("Backend unavailable"));
  }, []);

  useEffect(() => { load(); const id = window.setInterval(load, 15000); return () => window.clearInterval(id); }, [load]);

  const choose = (mode: string) => {
    if (busy || state?.mode === mode) return;
    setBusy(true);
    setDetectionMode(mode).then((value) => { setState(value); setError(null); }).catch((reason: Error) => setError(reason.message)).finally(() => setBusy(false));
  };

  if (!state) return error ? <span className="hidden text-xs text-rose-300 lg:block">{error}</span> : null;

  return <div className="hidden items-center gap-2 lg:flex" title={error ?? "Choose which model decides whether a flow is an attack"}>
    <span className="text-xs text-slate-500">Detection</span>
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
