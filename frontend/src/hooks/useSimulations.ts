import { useCallback, useEffect, useRef, useState } from "react";
import { cancelSimulationRun, getSimulation, getSimulationRunStatus, listSimulations, startSimulationRun } from "../services/simulationService";
import type { SimulationDetail, SimulationListEntry, SimulationRunStatus } from "../types/simulation";

export function useSimulationList() {
  const [data, setData] = useState<SimulationListEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshToken, setRefreshToken] = useState(0);

  useEffect(() => {
    let active = true;
    listSimulations()
      .then((res) => { if (active) { setData(res.simulations); setError(null); } })
      .catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : "Unable to reach backend"); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [refreshToken]);

  const refresh = useCallback(() => setRefreshToken((t) => t + 1), []);

  return { data, error, loading, refresh };
}

/** Polls run status every 2s while a simulation is in flight (and once
 * on mount otherwise), so the UI can show live progress without the
 * caller needing to manage its own interval. Calls onComplete exactly
 * once when a run transitions from running -> finished, passing the
 * final status directly (not read back from component state, which
 * wouldn't have re-rendered yet at the point this fires - a stale
 * closure over `status` here would still see the previous "running"
 * value), so the page can refresh the run list and jump to the new
 * result without racing its own state update. */
export function useSimulationRun(onComplete?: (finalStatus: SimulationRunStatus) => void) {
  const [status, setStatus] = useState<SimulationRunStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const wasRunning = useRef(false);
  const onCompleteRef = useRef(onComplete);
  onCompleteRef.current = onComplete;

  useEffect(() => {
    let active = true;

    const poll = async () => {
      try {
        const next = await getSimulationRunStatus();
        if (!active) return;
        setStatus(next);
        setError(null);
        if (wasRunning.current && !next.running) onCompleteRef.current?.(next);
        wasRunning.current = next.running;
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : "Unable to reach backend");
      }
    };

    void poll();
    const timer = window.setInterval(() => void poll(), 2000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  const start = useCallback(async (trials: number) => {
    setError(null);
    try {
      await startSimulationRun(trials);
      const next = await getSimulationRunStatus();
      setStatus(next);
      wasRunning.current = next.running;
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to start simulation");
      throw cause;
    }
  }, []);

  const cancel = useCallback(async () => {
    try {
      await cancelSimulationRun();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to cancel simulation");
    }
  }, []);

  return { status, error, start, cancel };
}

export function useSimulationDetail(name: string | null) {
  const [data, setData] = useState<SimulationDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!name) { setData(null); return; }
    let active = true;
    setLoading(true);
    getSimulation(name)
      .then((res) => { if (active) { setData(res); setError(null); } })
      .catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : "Unable to load this simulation"); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [name]);

  return { data, error, loading };
}
