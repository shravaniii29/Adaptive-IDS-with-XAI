import { useCallback } from "react";
import { getDetectionStats, getSystemStatus } from "../services/systemService";
import { usePolling } from "./usePolling";
export function useSystemStatus() { const systemRequest = useCallback(getSystemStatus, []); const statsRequest = useCallback(getDetectionStats, []); const system = usePolling(systemRequest); const stats = usePolling(statsRequest); return { system: system.data, stats: stats.data, error: system.error ?? stats.error, loading: system.loading || stats.loading }; }
