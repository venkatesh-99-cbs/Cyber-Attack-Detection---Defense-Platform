export interface SecurityEvent {
  id?: number;
  event_id: string;
  timestamp: string;
  source_ip: string;
  target_ip: string;
  event_type: string;
  endpoint?: string | null;
  method?: string | null;
  status_code?: number | null;
  message: string;
  metadata?: Record<string, any>;
  received_at?: string;
}

export interface EventListResponse {
  total: number;
  limit: number;
  offset: number;
  events: SecurityEvent[];
}
