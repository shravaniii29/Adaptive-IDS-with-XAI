import { useEffect, useState } from "react";
import { getDetectionMode, setDetectionMode } from "../../services/modeService";
import { MODE_CHANGED_EVENT } from "../../hooks/useModeVersion";

// The dashboard is V8-only: the hybrid view has been removed, so there is no
// model toggle any more. This renders a static "V8" badge and, on mount,
// makes sure the backend is actually serving V8 (the backend also defaults to
// V8, but a backend left in hybrid mode from an earlier session would
// otherwise still show hybrid numbers). It never offers hybrid as a choice.
let forced = false;

export default function ModeSwitch() {
  const [ok, setOk] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getDetectionMode()
      .then((state) => {
        if (cancelled) return;
        setOk(true);
        if (state.mode !== "v8" && !forced) {
          forced = true;
          setDetectionMode("v8")
            .then(() => window.dispatchEvent(new Event(MODE_CHANGED_EVENT)))
            .catch(() => undefined);
        }
      })
      .catch(() => undefined);
    return () => { cancelled = true; };
  }, []);

  if (!ok) return null;

  return (
    <div className="hidden items-center gap-2 lg:flex" title="Detection model">
      <span className="text-xs text-slate-500">Model</span>
      <span className="rounded-md border border-indigo-400/40 bg-indigo-500/15 px-3 py-1 text-xs font-semibold text-indigo-200">V8</span>
    </div>
  );
}
