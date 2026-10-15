import { useEffect, useState } from "react";

// Fired by the Hybrid | V8 switch after the backend has switched which
// model's results it serves. Anything that caches per-flow data listens to
// it and refetches immediately instead of waiting for the next poll.
export const MODE_CHANGED_EVENT = "ids:mode-changed";

export function useModeVersion() {
  const [version, setVersion] = useState(0);
  useEffect(() => {
    const onChange = () => setVersion((value) => value + 1);
    window.addEventListener(MODE_CHANGED_EVENT, onChange);
    return () => window.removeEventListener(MODE_CHANGED_EVENT, onChange);
  }, []);
  return version;
}
