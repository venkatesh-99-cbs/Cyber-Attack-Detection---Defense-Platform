import React from 'react';
import { DataAvailabilityBanner } from '../components/DataAvailabilityBanner';
import { ShieldAlert } from 'lucide-react';

export const IncidentsPage: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Honest Data Availability Banner */}
      <DataAvailabilityBanner
        title="Historical Incident Persistence Unavailable"
        message="Security Incident objects are managed in-memory during active backend execution by IncidentManager. State transitions are controlled in runtime memory, but persistent incident storage in SQLite is not configured."
        scope="incidents"
      />

      {/* Incident Workflow Architecture Panel */}
      <div className="bg-soc-panel border border-soc-border rounded-lg p-5 space-y-4 shadow-sm">
        <div className="flex items-center space-x-2 border-b border-soc-border pb-3">
          <ShieldAlert className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
            Incident Management State Machine Model
          </h3>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed font-sans">
          The Blue Team Incident Manager enforces controlled status transitions from originating Alert objects:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono pt-2">
          {/* OPEN */}
          <div className="bg-soc-bg p-4 rounded border border-rose-500/30 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-rose-400 font-bold text-sm">1. OPEN</span>
              <span className="bg-rose-950 text-rose-300 text-[10px] px-2 py-0.5 rounded border border-rose-500/30 font-semibold">Initial State</span>
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              Automatically created when a high-risk security alert triggers defensive analysis.
            </p>
          </div>

          {/* INVESTIGATING */}
          <div className="bg-soc-bg p-4 rounded border border-amber-500/30 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-amber-400 font-bold text-sm">2. INVESTIGATING</span>
              <span className="bg-amber-950 text-amber-300 text-[10px] px-2 py-0.5 rounded border border-amber-500/30 font-semibold">Active Review</span>
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              Analyst or controlled response engine assumes active investigation of source IP evidence.
            </p>
          </div>

          {/* RESOLVED */}
          <div className="bg-soc-bg p-4 rounded border border-emerald-500/30 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-emerald-400 font-bold text-sm">3. RESOLVED</span>
              <span className="bg-emerald-950 text-emerald-300 text-[10px] px-2 py-0.5 rounded border border-emerald-500/30 font-semibold">Terminal State</span>
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              Defensive response completed (e.g. simulated or real firewall block executed).
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
