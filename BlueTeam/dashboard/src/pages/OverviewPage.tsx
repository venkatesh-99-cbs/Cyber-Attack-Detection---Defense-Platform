import React from 'react';
import { ThreatPosture } from '../components/ThreatPosture';
import { LiveAlertFeed } from '../components/LiveAlertFeed';
import { EventTable } from '../components/EventTable';
import { StatisticsCharts } from '../components/StatisticsCharts';
import { SecurityEvent } from '../types/event';
import { WebSocketAlertMessage } from '../types/alert';
import { DashboardStatsResponse, DashboardSummaryResponse } from '../types/api';

interface OverviewPageProps {
  summary: DashboardSummaryResponse | null;
  stats: DashboardStatsResponse | null;
  events: SecurityEvent[];
  totalEvents: number;
  liveAlerts: WebSocketAlertMessage[];
  isLoadingEvents: boolean;
  onSelectEvent: (evt: SecurityEvent) => void;
  onViewAllEvents: () => void;
  onClearLiveAlerts: () => void;
  onRefreshEvents: () => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  summary,
  stats,
  events,
  totalEvents,
  liveAlerts,
  isLoadingEvents,
  onSelectEvent,
  onViewAllEvents,
  onClearLiveAlerts,
  onRefreshEvents,
}) => {
  return (
    <div className="space-y-6">
      {/* 1. Threat Posture Banner */}
      <ThreatPosture
        totalEvents={totalEvents}
        liveAlertCount={liveAlerts.length}
        dataAvailability={summary?.data_availability}
      />

      {/* 2. Main Live Activity & Statistics Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Live Alerts Feed (5 cols on lg screens) */}
        <div className="lg:col-span-5 flex flex-col h-[520px]">
          <LiveAlertFeed alerts={liveAlerts} onClear={onClearLiveAlerts} />
        </div>

        {/* Statistics Charts (7 cols on lg screens) */}
        <div className="lg:col-span-7 flex flex-col justify-between">
          <StatisticsCharts stats={stats} />
        </div>
      </div>

      {/* 3. Recent Security Events Log Table */}
      <div className="space-y-2">
        <div className="flex items-center justify-between px-1">
          <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider">
            Recent Security Activity Log
          </h3>
          <button
            onClick={onViewAllEvents}
            className="text-xs font-mono text-sky-400 hover:text-sky-300 underline font-medium"
          >
            View All Security Events →
          </button>
        </div>

        <div className="min-h-[350px]">
          <EventTable
            events={events.slice(0, 10)}
            total={totalEvents}
            limit={10}
            offset={0}
            isLoading={isLoadingEvents}
            onSelectEvent={onSelectEvent}
            onRefresh={onRefreshEvents}
          />
        </div>
      </div>
    </div>
  );
};
