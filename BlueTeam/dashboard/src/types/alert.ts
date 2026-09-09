export interface Alert {
  alert_id: string;
  timestamp: string;
  severity: 'SAFE' | 'SUSPICIOUS' | 'HIGH RISK' | string;
  risk_score: number;
  attack_types: string[];
  source_ips: string[];
  rule_names: string[];
  detection_count: number;
  reasons: string[];
  status?: string;
}

export interface AlertListResponse {
  persisted: boolean;
  status: string;
  message: string;
  alerts: Alert[] | null;
}

export interface WebSocketAlertMessage {
  type: 'security_alert' | string;
  alert_id: string;
  risk_level: string;
  risk_score: number;
  attack_types: string[];
  source_ips: string[];
  rules_triggered: string[];
  reasons: string[];
  timestamp: string;
}
