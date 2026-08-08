import { apiGet } from "./api";
import type { DetectionStats, SystemStatus } from "../types/system";
export const getSystemStatus = () => apiGet<SystemStatus>("/system");
export const getDetectionStats = () => apiGet<DetectionStats>("/status");
