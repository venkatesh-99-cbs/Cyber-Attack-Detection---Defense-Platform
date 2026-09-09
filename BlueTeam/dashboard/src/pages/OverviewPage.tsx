import React from 'react';
import { ThreatPosture } from '../components/ThreatPosture';
import { LiveAlertFeed } from '../components/LiveAlertFeed';
import { EventTable } from '../components/EventTable';
import { StatisticsCharts } from '../components/StatisticsCharts';
import { SecurityEvent } from '../types/event';
import { WebSocketAlertMessage } from '../types/alert';
import { DashboardStatsResponse, DashboardSummaryResponse } from '../types/api';

import { ConnectionState } from '../services/websocket';
import { Cpu, ArrowRight } from 'lucide-react';

interface OverviewPageProps {
  summary: DashboardSummaryResponse | null;
  stats: DashboardStatsResponse | null;
  events: SecurityEvent[];
  totalEvents: number;
  liveAlerts: WebSocketAlertMessage[];
  isLoadingEvents: boolean;
  apiStatus?: string;
  wsStatus?: ConnectionState;
  onSelectEvent: (evt: SecurityEvent) => void;
  onViewAllEvents: () => void;
  onViewValidation?: () => void;
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
  apiStatus = 'ok',
  wsStatus = 'DISCONNECTED',
  onSelectEvent,
  onViewAllEvents,
  onViewValidation,
  onClearLiveAlerts,
  onRefreshEvents,
}) => {
  return (
    <div className="space-y-6">
      {/* 1. Threat Posture & SOC Metrics Header */}
      <ThreatPosture
        totalEvents={totalEvents}
        liveAlertCount={liveAlerts.length}
        summary={summary}
        stats={stats}
        liveAlerts={liveAlerts}
        apiStatus={apiStatus}
        wsStatus={wsStatus}
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

      {/* 3. Attack-to-Defense Validation Status Strip */}
      <div className="bg-soc-panel border border-sky-500/30 rounded-lg p-3.5 px-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs shadow-sm select-none">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-slate-900 border border-slate-800 rounded text-sky-400">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-slate-100 uppercase tracking-wider text-[11px]">
                Attack-to-Defense Validation & Replay Engine
              </span>
              <span className="bg-emerald-950 text-emerald-400 border border-emerald-500/30 text-[9px] px-1.5 py-0.2 rounded font-bold">
                ACTIVE
              </span>
            </div>
            <p className="text-[11px] text-soc-textMuted font-sans mt-0.5">
              Automated audit of Blue Team detection efficacy and chronological security lifecycle replay.
            </p>
          </div>
        </div>

        {onViewValidation && (
          <button
            onClick={onViewValidation}
            className="flex items-center space-x-1.5 bg-sky-950 hover:bg-sky-900 text-sky-300 border border-sky-500/40 px-3 py-1.5 rounded transition-colors text-xs font-semibold shrink-0"
          >
            <span>Launch Replay Engine</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* 4. Recent Security Events Log Table */}
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
