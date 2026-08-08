export interface SystemStatus { status: "ok" | "degraded"; uptime_seconds: number; last_error: string | null; }
export interface DetectionStats { total_flows: number; normal_flows: number; positive_flows: number; last_error: string | null; }
