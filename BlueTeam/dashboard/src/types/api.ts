export interface HealthStatus {
  status: string;
}

export interface DataAvailabilityStatus {
  events_persisted: boolean;
  alerts_persisted: boolean;
  incidents_persisted: boolean;
  risk_analysis_persisted: boolean;
  detection_results_persisted: boolean;
}

export interface DashboardSummaryResponse {
  total_events: number;
  data_availability: DataAvailabilityStatus;
  active_alerts_count?: number | null;
  open_incidents_count?: number | null;
  system_status?: string | null;
  system_status_note: string;
}

export interface TopSourceIP {
  source_ip: string;
  count: number;
}

export interface DashboardStatsResponse {
  total_events: number;
  events_by_type: Record<string, number>;
  top_source_ips: TopSourceIP[];
  detected_attack_count?: number | null;
  detected_attack_count_note: string;
  data_availability: DataAvailabilityStatus;
}
