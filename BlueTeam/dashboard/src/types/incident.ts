export interface Incident {
  incident_id: string;
  created_at: string;
  updated_at: string;
  alert_id: string;
  severity: string;
  risk_score: number;
  attack_types: string[];
  source_ips: string[];
  rule_names: string[];
  detection_count: number;
  reasons: string[];
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | string;
}

export interface IncidentListResponse {
  persisted: boolean;
  status: string;
  message: string;
  incidents: Incident[] | null;
}
