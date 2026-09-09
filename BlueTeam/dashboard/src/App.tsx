import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { Navigation, TabType } from './components/Navigation';
import { OverviewPage } from './pages/OverviewPage';
import { EventsPage } from './pages/EventsPage';
import { AlertsPage } from './pages/AlertsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { ValidationPage } from './pages/ValidationPage';
import { EventDetailModal } from './components/EventDetailModal';

import { apiService } from './services/api';
import { wsClient, ConnectionState } from './services/websocket';
import { SecurityEvent } from './types/event';
import { WebSocketAlertMessage } from './types/alert';
import { DashboardStatsResponse, DashboardSummaryResponse } from './types/api';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('overview');

  // API & WS states
  const [apiStatus, setApiStatus] = useState<string>('loading');
  const [wsStatus, setWsStatus] = useState<ConnectionState>('DISCONNECTED');

  // Domain data
  const [summary, setSummary] = useState<DashboardSummaryResponse | null>(null);
  const [stats, setStats] = useState<DashboardStatsResponse | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [eventLimit] = useState<number>(50);
  const [eventOffset, setEventOffset] = useState<number>(0);
  const [isLoadingEvents, setIsLoadingEvents] = useState<boolean>(false);

  // Live WebSocket Alert stream
  const [liveAlerts, setLiveAlerts] = useState<WebSocketAlertMessage[]>([]);

  // Selected event for detail inspection modal
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Load API Data
  const loadDashboardData = useCallback(async () => {
    setIsLoadingEvents(true);
    try {
      const [healthRes, summaryRes, statsRes, eventsRes] = await Promise.all([
        apiService.fetchHealth(),
        apiService.fetchSummary(),
        apiService.fetchStatistics(),
        apiService.fetchEvents(eventLimit, eventOffset),
      ]);

      setApiStatus(healthRes.status);
      setSummary(summaryRes);
      setStats(statsRes);
      setEvents(eventsRes.events || []);
      setTotalEvents(eventsRes.total || 0);
    } catch (err) {
      console.warn('Dashboard data fetch error:', err);
      setApiStatus('error');
    } finally {
      setIsLoadingEvents(false);
    }
  }, [eventLimit, eventOffset]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Connect WebSocket on mount & subscribe to live alerts
  useEffect(() => {
    const unsubStatus = wsClient.subscribeStatus((status) => {
      setWsStatus(status);
    });

    const unsubAlerts = wsClient.subscribeAlerts((alert) => {
      setLiveAlerts((prev) => [alert, ...prev]);
      // Silently refresh summary & stats on new alert
      apiService.fetchSummary().then((s) => s && setSummary(s));
      apiService.fetchStatistics().then((st) => st && setStats(st));
    });

    wsClient.connect();

    return () => {
      unsubStatus();
      unsubAlerts();
      wsClient.disconnect();
    };
  }, []);

  // Handlers
  const handlePageChange = (newOffset: number) => {
    setEventOffset(newOffset);
  };

  const handleClearLiveAlerts = () => {
    setLiveAlerts([]);
  };

  return (
    <div className="min-h-screen bg-soc-bg text-soc-textMain flex flex-col font-sans">
      {/* Header Bar */}
      <Header apiStatus={apiStatus} wsStatus={wsStatus} />

      {/* Navigation Bar */}
      <Navigation
        activeTab={activeTab}
        onTabChange={setActiveTab}
        liveAlertCount={liveAlerts.length}
      />

      {/* Main Content Area */}
      <main className="flex-1 p-4 sm:p-6 max-w-7xl w-full mx-auto">
        {activeTab === 'overview' && (
          <OverviewPage
            summary={summary}
            stats={stats}
            events={events}
            totalEvents={totalEvents}
            liveAlerts={liveAlerts}
            isLoadingEvents={isLoadingEvents}
            onSelectEvent={setSelectedEvent}
            onViewAllEvents={() => setActiveTab('events')}
            onClearLiveAlerts={handleClearLiveAlerts}
            onRefreshEvents={loadDashboardData}
          />
        )}

        {activeTab === 'events' && (
          <EventsPage
            events={events}
            total={totalEvents}
            limit={eventLimit}
            offset={eventOffset}
            isLoading={isLoadingEvents}
            onPageChange={handlePageChange}
            onSelectEvent={setSelectedEvent}
            onRefresh={loadDashboardData}
          />
        )}

        {activeTab === 'alerts' && (
          <AlertsPage
            liveAlerts={liveAlerts}
            onClearLiveAlerts={handleClearLiveAlerts}
          />
        )}

        {activeTab === 'incidents' && <IncidentsPage />}

        {activeTab === 'validation' && <ValidationPage />}
      </main>

      {/* Inspection Modal */}
      <EventDetailModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />

      {/* Console Footer */}
      <footer className="border-t border-soc-border py-3 px-6 bg-soc-panel text-center text-xs font-mono text-soc-textMuted select-none">
        Cyber Attack Detection & Defense Platform &copy; {new Date().getFullYear()} — Blue Team SOC Console
      </footer>
    </div>
  );
};

export default App;
