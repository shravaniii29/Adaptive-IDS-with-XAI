export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface IncidentReport {
  title: string;
  affected_asset: string;
  evidence: string[];
  recommended_next_step: string;
}

export interface AgentAnalysis {
  explanation: string;
  severity: Severity;
  recommended_mitigation: string[];
  business_impact: string;
  soc_analyst_summary: string;
  incident_report: IncidentReport;
  model_name: string;
}

export interface AgentAnalysisResponse {
  flow_id: string | number;
  analysis: AgentAnalysis;
}
