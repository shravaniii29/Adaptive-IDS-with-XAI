import { apiGet, apiPost } from "./api";

export type RemoteRunPhase = "running" | "awaiting_approval" | "attacking" | "finished" | "stopped";

export interface RemoteRunStatus {
  running: boolean;
  phase?: RemoteRunPhase;
  target_backend?: string;
  scenario?: string;
  duration?: number;
  started_at?: number;
  elapsed_seconds?: number | null;
  exit_code?: number | null;
  log_tail?: string;
}

export interface StartRemoteAttackBody {
  target_backend: string;
  scenario: string;
  duration: number;
}

export function startRemoteAttack(body: StartRemoteAttackBody) {
  return apiPost<{ status: string }>("/simulations/run_remote", body);
}

export function getRemoteAttackStatus() {
  return apiGet<RemoteRunStatus>("/simulations/run_remote/status");
}

export function cancelRemoteAttack() {
  return apiPost<{ status: string }>("/simulations/run_remote/cancel");
}

export const REMOTE_SCENARIOS: { id: string; label: string }[] = [
  { id: "icmp_flood", label: "ICMP flood" },
  { id: "syn_flood", label: "SYN flood" },
  { id: "udp_flood", label: "UDP flood" },
  { id: "http_flood", label: "HTTP flood" },
  { id: "port_scan", label: "Port scan" },
];
