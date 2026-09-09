import { WebSocketAlertMessage } from '../types/alert';

export type ConnectionState = 'DISCONNECTED' | 'CONNECTING' | 'CONNECTED' | 'ERROR';

export type AlertHandler = (alert: WebSocketAlertMessage) => void;
export type StatusHandler = (status: ConnectionState) => void;

const getWsUrl = (): string => {
  if (import.meta.env.VITE_WS_URL) {
    return import.meta.env.VITE_WS_URL;
  }
  return 'ws://localhost:8000/ws';
};

class SecurityWebSocketClient {
  private socket: WebSocket | null = null;
  private url: string;
  private state: ConnectionState = 'DISCONNECTED';
  private alertListeners: Set<AlertHandler> = new Set();
  private statusListeners: Set<StatusHandler> = new Set();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private isExplicitDisconnect = false;

  constructor() {
    this.url = getWsUrl();
  }

  public getWsUrl(): string {
    return this.url;
  }

  public connect(): void {
    if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this.isExplicitDisconnect = false;
    this.updateState('CONNECTING');

    try {
      this.socket = new WebSocket(this.url);

      this.socket.onopen = () => {
        this.reconnectAttempts = 0;
        this.updateState('CONNECTED');
      };

      this.socket.onmessage = (event: MessageEvent) => {
        this.handleMessage(event.data);
      };

      this.socket.onerror = () => {
        this.updateState('ERROR');
      };

      this.socket.onclose = () => {
        this.socket = null;
        if (!this.isExplicitDisconnect) {
          this.updateState('DISCONNECTED');
          this.scheduleReconnect();
        } else {
          this.updateState('DISCONNECTED');
        }
      };
    } catch (err) {
      console.warn('WebSocket connection instantiation failed:', err);
      this.updateState('ERROR');
      this.scheduleReconnect();
    }
  }

  public disconnect(): void {
    this.isExplicitDisconnect = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.updateState('DISCONNECTED');
  }

  public getState(): ConnectionState {
    return this.state;
  }

  public subscribeAlerts(handler: AlertHandler): () => void {
    this.alertListeners.add(handler);
    return () => {
      this.alertListeners.delete(handler);
    };
  }

  public subscribeStatus(handler: StatusHandler): () => void {
    this.statusListeners.add(handler);
    handler(this.state);
    return () => {
      this.statusListeners.delete(handler);
    };
  }

  private updateState(newState: ConnectionState): void {
    this.state = newState;
    this.statusListeners.forEach((listener) => {
      try {
        listener(newState);
      } catch (err) {
        console.error('Status listener error:', err);
      }
    });
  }

  public handleMessage(rawData: string): void {
    try {
      const parsed = JSON.parse(rawData);
      if (!parsed || typeof parsed !== 'object') {
        return;
      }

      if (parsed.type !== 'security_alert') {
        return;
      }

      // Strict Data Honesty Validation:
      // Required fields must exist and be valid. DO NOT fabricate missing security values!
      if (
        typeof parsed.alert_id !== 'string' ||
        !parsed.alert_id.trim() ||
        typeof parsed.risk_level !== 'string' ||
        !parsed.risk_level.trim() ||
        typeof parsed.risk_score !== 'number' ||
        typeof parsed.timestamp !== 'string' ||
        !parsed.timestamp.trim()
      ) {
        console.warn('Malformed security_alert WebSocket message ignored due to missing required fields:', parsed);
        return;
      }

      const alertMsg: WebSocketAlertMessage = {
        type: 'security_alert',
        alert_id: parsed.alert_id,
        risk_level: parsed.risk_level,
        risk_score: parsed.risk_score,
        attack_types: Array.isArray(parsed.attack_types) ? parsed.attack_types : [],
        source_ips: Array.isArray(parsed.source_ips) ? parsed.source_ips : [],
        rules_triggered: Array.isArray(parsed.rules_triggered) ? parsed.rules_triggered : [],
        reasons: Array.isArray(parsed.reasons) ? parsed.reasons : [],
        timestamp: parsed.timestamp,
      };

      this.alertListeners.forEach((listener) => {
        try {
          listener(alertMsg);
        } catch (err) {
          console.error('Alert listener error:', err);
        }
      });
    } catch (err) {
      // Safely ignore non-JSON or malformed message strings
    }
  }

  private scheduleReconnect(): void {
    if (this.isExplicitDisconnect) return;

    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 10000);
      if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
      this.reconnectTimer = setTimeout(() => {
        this.connect();
      }, delay);
    }
  }
}

export const wsClient = new SecurityWebSocketClient();
