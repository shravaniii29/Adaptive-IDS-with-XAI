import { useCallback } from "react";
import { getDriftStatus } from "../services/driftService";
import type { DriftStatus } from "../types/drift";
import { usePolling } from "./usePolling";
const hasDrift = (value: DriftStatus | { message: string }): value is DriftStatus => "drift_detected" in value;
export function useDrift() { const request = useCallback(getDriftStatus, []); const result = usePolling(request); return { ...result, drift: result.data && hasDrift(result.data) ? result.data : null }; }
