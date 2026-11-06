import { apiGet, apiPost } from "./api";

export type RemoteRequestStatus =
  | "pending"
  | "approved"
  | "denied"
  | "consumed"
  | "expired";

export interface RemoteAttackRequest {
  id: string;
  source_ip: string;
  scenario: string;
  duration: number;
  status: RemoteRequestStatus;
  created_at: number;
  expires_at: number;
  decided_at: number | null;
}

export interface RemoteAttackList {
  requests: RemoteAttackRequest[];
  pending: number;
  max_duration: number;
}

export function listRemoteAttackRequests() {
  return apiGet<RemoteAttackList>("/remote_attack/requests");
}

export function approveRemoteAttackRequest(id: string) {
  return apiPost<RemoteAttackRequest>(`/remote_attack/requests/${id}/approve`);
}

export function denyRemoteAttackRequest(id: string) {
  return apiPost<RemoteAttackRequest>(`/remote_attack/requests/${id}/deny`);
}

export const SCENARIO_LABELS: Record<string, string> = {
  icmp_flood: "ICMP flood",
  syn_flood: "SYN flood",
  udp_flood: "UDP flood",
  http_flood: "HTTP flood",
  port_scan: "Port scan",
};
