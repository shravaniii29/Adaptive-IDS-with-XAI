import { useEffect, useState } from "react";

export function usePolling<T>(request: () => Promise<T>, intervalMs = 5000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    const load = async () => {
      try { const next = await request(); if (active) { setData(next); setError(null); } }
      catch (cause) { if (active) setError(cause instanceof Error ? cause.message : "Unable to reach backend"); }
      finally { if (active) setLoading(false); }
    };
    void load();
    const timer = window.setInterval(() => void load(), intervalMs);
    return () => { active = false; window.clearInterval(timer); };
  }, [request, intervalMs]);
  return { data, error, loading };
}
