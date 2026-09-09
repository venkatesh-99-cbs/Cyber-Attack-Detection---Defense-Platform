import React from 'react';
import { ShieldCheck, Database, Radio, AlertOctagon } from 'lucide-react';
import { DataAvailabilityStatus } from '../types/api';

interface ThreatPostureProps {
  totalEvents: number;
  liveAlertCount: number;
  dataAvailability?: DataAvailabilityStatus;
}

export const ThreatPosture: React.FC<ThreatPostureProps> = ({
  totalEvents,
  liveAlertCount,
  dataAvailability,
}) => {
  const isEventsPersisted = dataAvailability?.events_persisted ?? true;
  const isAlertsPersisted = dataAvailability?.alerts_persisted ?? false;
  const isIncidentsPersisted = dataAvailability?.incidents_persisted ?? false;

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-4 sm:p-5 shadow-sm">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-soc-borderMuted">
        <div>
          <div className="flex items-center space-x-2">
            <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded bg-sky-950/60 border border-sky-500/30 text-sky-400 font-mono text-xs font-semibold">
              <span className="w-2 h-2 rounded-full bg-sky-400 animate-ping" />
              <span>REAL-TIME MONITORING ACTIVE</span>
            </span>
          </div>
          <h2 className="text-sm font-semibold text-slate-200 font-mono mt-2">
            Security Event Pipeline Posture
          </h2>
          <p className="text-xs text-soc-textMuted mt-0.5 font-sans">
            Target Ingestion → SQLite Storage → Detection Engine → Risk Scoring → Live Alert Broadcast
          </p>
        </div>

        {/* Live metric summary cards */}
        <div className="flex items-center space-x-3">
          <div className="bg-soc-card border border-soc-border px-3.5 py-2 rounded-md text-right">
            <div className="text-[10px] text-soc-textMuted font-mono uppercase tracking-wider">Persisted Events</div>
            <div className="text-lg font-bold font-mono text-slate-100">{totalEvents.toLocaleString()}</div>
          </div>
          <div className="bg-soc-card border border-soc-border px-3.5 py-2 rounded-md text-right">
            <div className="text-[10px] text-soc-textMuted font-mono uppercase tracking-wider">Session Live Alerts</div>
            <div className="text-lg font-bold font-mono text-amber-400">{liveAlertCount}</div>
          </div>
        </div>
      </div>

      {/* Honest Data Availability Breakdown */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 mt-4 text-xs font-mono">
        <div className="flex items-center space-x-2.5 bg-soc-bg/60 p-2.5 rounded border border-soc-borderMuted">
          <Database className="w-4 h-4 text-emerald-400 shrink-0" />
          <div>
            <div className="text-slate-300 font-medium">Security Events</div>
            <div className="text-[11px] text-emerald-400">{isEventsPersisted ? 'Persisted in SQLite' : 'Not Persisted'}</div>
          </div>
        </div>

        <div className="flex items-center space-x-2.5 bg-soc-bg/60 p-2.5 rounded border border-soc-borderMuted">
          <Radio className="w-4 h-4 text-sky-400 shrink-0" />
          <div>
            <div className="text-slate-300 font-medium">WebSocket Alerts</div>
            <div className="text-[11px] text-sky-400">Live In-Memory Broadcast</div>
          </div>
        </div>

        <div className="flex items-center space-x-2.5 bg-soc-bg/60 p-2.5 rounded border border-soc-borderMuted">
          <AlertOctagon className="w-4 h-4 text-amber-400 shrink-0" />
          <div>
            <div className="text-slate-300 font-medium">Alert Persistence</div>
            <div className="text-[11px] text-amber-400/90">{isAlertsPersisted ? 'Persisted' : 'Not Configured'}</div>
          </div>
        </div>

        <div className="flex items-center space-x-2.5 bg-soc-bg/60 p-2.5 rounded border border-soc-borderMuted">
          <ShieldCheck className="w-4 h-4 text-amber-400 shrink-0" />
          <div>
            <div className="text-slate-300 font-medium">Incident History</div>
            <div className="text-[11px] text-amber-400/90">{isIncidentsPersisted ? 'Persisted' : 'In-Memory Scope'}</div>
          </div>
        </div>
      </div>
    </div>
  );
};
