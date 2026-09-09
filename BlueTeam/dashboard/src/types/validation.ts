export interface ValidationChecks {
  detection: boolean;
  risk: boolean;
  alert: boolean;
  incident: boolean;
  response: boolean;
}

export interface ValidationRecord {
  validation_id: string;
  event_id: string;
  attack_type: string;
  checks: ValidationChecks;
  overall_result: 'PASS' | 'FAIL';
  reasons: string[];
  created_at: string;
}

export interface ReplayTimelineEvent {
  stage: string;
  timestamp: string;
  status: string;
  detail?: string;
  rule?: string;
  score?: number;
  mode?: string;
  validation_id?: string;
}

export interface ReplayResponse {
  validation_id: string | null;
  event_id: string;
  timeline: ReplayTimelineEvent[];
}

