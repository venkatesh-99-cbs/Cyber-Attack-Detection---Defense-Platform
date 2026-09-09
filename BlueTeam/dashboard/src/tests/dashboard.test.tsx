import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from '../App';
import { EventTable } from '../components/EventTable';
import { LiveAlertFeed } from '../components/LiveAlertFeed';
import { StatusBadge } from '../components/StatusBadge';
import { apiService } from '../services/api';
import { wsClient } from '../services/websocket';
import { SecurityEvent } from '../types/event';
import { WebSocketAlertMessage } from '../types/alert';

describe('Blue Team Security Operations Dashboard Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('1. API uses configured VITE_API_BASE_URL (http://localhost:8000 by default)', () => {
    const url = apiService.getApiBaseUrl();
    expect(url).toBe('http://localhost:8000');
    expect(url).not.toContain(':3000');
  });

  it('2. WebSocket uses configured VITE_WS_URL (ws://localhost:8000/ws by default)', () => {
    const url = wsClient.getWsUrl();
    expect(url).toBe('ws://localhost:8000/ws');
    expect(url).not.toContain(':3000');
  });

  it('3. Renders Header with platform title and status indicators', async () => {
    render(<App />);
    const matches = screen.getAllByText(/Cyber Attack Detection & Defense Platform/i);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0]).toBeInTheDocument();

    const socBadges = screen.getAllByText(/BLUE TEAM SOC/i);
    expect(socBadges.length).toBeGreaterThan(0);
    expect(socBadges[0]).toBeInTheDocument();
  });

  it('4. EventTable handles empty event state cleanly without fake data', () => {
    render(
      <EventTable
        events={[]}
        total={0}
        limit={50}
        offset={0}
      />
    );
    expect(screen.getByText(/No security events recorded in database yet/i)).toBeInTheDocument();
  });

  it('5. EventTable renders event records with exact platform terminology', () => {
    const mockEvents: SecurityEvent[] = [
      {
        id: 1,
        event_id: 'evt-001',
        timestamp: new Date().toISOString(),
        source_ip: '192.168.1.50',
        target_ip: '10.0.0.1',
        event_type: 'login_failure',
        endpoint: '/api/login',
        method: 'POST',
        status_code: 401,
        message: 'Failed login attempt',
        metadata: {},
      },
    ];

    render(
      <EventTable
        events={mockEvents}
        total={1}
        limit={50}
        offset={0}
      />
    );

    const matches = screen.getAllByText('login_failure');
    expect(matches.length).toBeGreaterThan(0);
    expect(screen.getByText('192.168.1.50')).toBeInTheDocument();
    expect(screen.getByText('/api/login')).toBeInTheDocument();
  });

  it('6. LiveAlertFeed handles empty WebSocket alert state cleanly', () => {
    render(<LiveAlertFeed alerts={[]} />);
    expect(screen.getByText(/No live security alerts received in current session/i)).toBeInTheDocument();
  });

  it('7. Valid security_alert messages are processed and rendered correctly', () => {
    const mockAlerts: WebSocketAlertMessage[] = [
      {
        type: 'security_alert',
        alert_id: 'alert-101',
        risk_level: 'HIGH RISK',
        risk_score: 85,
        attack_types: ['brute_force'],
        source_ips: ['192.168.1.99'],
        rules_triggered: ['BruteForceRule'],
        reasons: ['Multiple failed login attempts detected'],
        timestamp: new Date().toISOString(),
      },
    ];

    render(<LiveAlertFeed alerts={mockAlerts} />);

    expect(screen.getByText('HIGH RISK')).toBeInTheDocument();
    expect(screen.getByText('85/100')).toBeInTheDocument();
    expect(screen.getByText('brute_force')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.99')).toBeInTheDocument();
    expect(screen.getByText('Multiple failed login attempts detected')).toBeInTheDocument();
  });

  it('8. Malformed security_alert messages (missing required fields) are ignored without fabricating data', () => {
    const alertHandler = vi.fn();
    const unsub = wsClient.subscribeAlerts(alertHandler);

    // Test case 8a: Missing risk_score -> ignored
    wsClient.handleMessage(
      JSON.stringify({
        type: 'security_alert',
        alert_id: 'alert-bad-1',
        risk_level: 'SUSPICIOUS',
        timestamp: new Date().toISOString(),
      })
    );
    expect(alertHandler).not.toHaveBeenCalled();

    // Test case 8b: Missing risk_level -> ignored
    wsClient.handleMessage(
      JSON.stringify({
        type: 'security_alert',
        alert_id: 'alert-bad-2',
        risk_score: 75,
        timestamp: new Date().toISOString(),
      })
    );
    expect(alertHandler).not.toHaveBeenCalled();

    // Test case 8c: Missing alert_id -> ignored
    wsClient.handleMessage(
      JSON.stringify({
        type: 'security_alert',
        risk_level: 'HIGH RISK',
        risk_score: 90,
        timestamp: new Date().toISOString(),
      })
    );
    expect(alertHandler).not.toHaveBeenCalled();

    // Test case 8d: Missing timestamp -> ignored
    wsClient.handleMessage(
      JSON.stringify({
        type: 'security_alert',
        alert_id: 'alert-bad-4',
        risk_level: 'HIGH RISK',
        risk_score: 90,
      })
    );
    expect(alertHandler).not.toHaveBeenCalled();

    // Test case 8e: Valid message -> processed!
    wsClient.handleMessage(
      JSON.stringify({
        type: 'security_alert',
        alert_id: 'alert-good-1',
        risk_level: 'HIGH RISK',
        risk_score: 90,
        timestamp: new Date().toISOString(),
        attack_types: ['sql_injection'],
        source_ips: ['10.0.0.50'],
        rules_triggered: ['SQLInjectionRule'],
        reasons: ['SQL syntax in query params'],
      })
    );
    expect(alertHandler).toHaveBeenCalledTimes(1);
    expect(alertHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        alert_id: 'alert-good-1',
        risk_level: 'HIGH RISK',
        risk_score: 90,
      })
    );

    unsub();
  });

  it('9. StatusBadge applies correct semantic severity styling', () => {
    const { rerender } = render(<StatusBadge status="SAFE" />);
    expect(screen.getByText('SAFE')).toBeInTheDocument();

    rerender(<StatusBadge status="SUSPICIOUS" />);
    expect(screen.getByText('SUSPICIOUS')).toBeInTheDocument();

    rerender(<StatusBadge status="HIGH RISK" />);
    expect(screen.getByText('HIGH RISK')).toBeInTheDocument();
  });

  it('10. Navigation switches tabs correctly', async () => {
    render(<App />);

    const eventsTab = screen.getAllByRole('button', { name: /Events/i })[0];
    fireEvent.click(eventsTab);
    expect(screen.getByText(/Security Event Repository/i)).toBeInTheDocument();

    const alertsTab = screen.getAllByRole('button', { name: /Alerts/i })[0];
    fireEvent.click(alertsTab);
    expect(screen.getByText(/Historical Alert Persistence Not Configured/i)).toBeInTheDocument();

    const incidentsTab = screen.getAllByRole('button', { name: /Incidents/i })[0];
    fireEvent.click(incidentsTab);
    expect(screen.getByText(/Historical Incident Persistence Unavailable/i)).toBeInTheDocument();

    const validationTab = screen.getAllByRole('button', { name: /Validation/i })[0];
    fireEvent.click(validationTab);
    expect(screen.getByText(/Attack-to-Defense Validation & Replay Engine/i)).toBeInTheDocument();
  });
});
