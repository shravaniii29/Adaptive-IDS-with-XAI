import { apiGet } from "./api";
import type { DriftStatus } from "../types/drift";
export function getDriftStatus() { return apiGet<DriftStatus | { message: string }>("/drift"); }
