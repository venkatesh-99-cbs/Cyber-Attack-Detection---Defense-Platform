import React, { useEffect, useState } from 'react';
import { ShieldAlert, RefreshCw, Clock, AlertCircle, ShieldCheck } from 'lucide-react';
import { DataAvailabilityBanner } from '../components/DataAvailabilityBanner';
import { StatusBadge } from '../components/StatusBadge';
import { apiService } from '../services/api';
import { Incident } from '../types/incident';

export const IncidentsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(false);

  const loadIncidents = async () => {
    setLoading(true);
    try {
      const res = await apiService.fetchIncidents();
      if (res && res.incidents) {
        setIncidents(res.incidents);
      } else {
        setIncidents([]);
      }
    } catch (err) {
      console.warn('Failed to fetch incidents:', err);
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  return (
    <div className="space-y-6">
      {/* Architecture & Persistence Status Banner */}
      <DataAvailabilityBanner
        title="Historical Incident Persistence Unavailable"
        message="Security Incident objects are managed by the Blue Team IncidentManager. When lifecycle persistence is active, incidents are persisted into SQLite and track lifecycle status transitions from OPEN to INVESTIGATING to RESOLVED."
        scope="incidents"
      />

      {/* Incidents Header */}
      <div className="bg-soc-panel border border-soc-border rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm select-none">
        <div className="flex items-center space-x-2">
          <div className="p-2 bg-slate-900 border border-slate-800 rounded text-rose-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold font-mono text-slate-100 uppercase tracking-wider">
              Security Incident Operations Console
            </h2>
            <p className="text-xs text-soc-textMuted font-sans">
              Escalated security incident triage, source IP tracking, and defensive response status
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 font-mono text-xs">
          <span className="bg-slate-800 text-slate-300 border border-slate-700 px-2.5 py-1 rounded">
            {incidents.length} Persisted Incidents
          </span>
          <button
            onClick={loadIncidents}
            disabled={loading}
            className="p-1.5 bg-soc-bg hover:bg-slate-800 text-slate-300 border border-soc-border rounded transition-colors disabled:opacity-50"
            title="Refresh Incidents"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Incidents Records List */}
      <div className="space-y-4">
        {loading ? (
          <div className="bg-soc-panel border border-soc-border rounded-lg p-12 text-center text-xs font-mono text-slate-400">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />
            <span>Querying incident records from SQLite database...</span>
          </div>
        ) : incidents.length === 0 ? (
          <div className="bg-soc-panel border border-soc-border rounded-lg p-12 text-center text-xs font-mono text-slate-400 space-y-2">
            <ShieldCheck className="w-8 h-8 mx-auto text-slate-600 mb-2" />
            <p className="text-slate-300 font-semibold">No incidents available.</p>
            <p className="text-slate-500 max-w-md mx-auto text-[11px] font-sans">
              No active or historical security incidents are logged in SQLite. Incidents are automatically triggered when attack detections reach escalated threat thresholds.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4">
            {incidents.map((inc) => (
              <div
                key={inc.incident_id}
                className="bg-soc-panel border border-soc-border rounded-lg p-5 shadow-sm space-y-3.5 hover:border-slate-700 transition-colors"
              >
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-soc-border pb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge status={inc.status} size="md" />
                    <span className="font-mono text-xs font-bold text-slate-200">
                      {inc.incident_id}
                    </span>
                    <span className="text-[11px] font-mono text-sky-400 bg-sky-950/40 border border-sky-500/30 px-2 py-0.5 rounded">
                      Linked Alert: {inc.alert_id}
                    </span>
                  </div>

                  <div className="flex items-center space-x-3 text-xs font-mono text-slate-400">
                    <span className="flex items-center space-x-1">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      <span>Created: {new Date(inc.created_at).toLocaleString()}</span>
                    </span>
                  </div>
                </div>

                {/* Attributes Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                  <div className="bg-soc-bg p-3 rounded border border-soc-borderMuted">
                    <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Threat Attribution</span>
                    <div className="mt-1 font-bold text-amber-300">
                      SRC: {inc.source_ips && inc.source_ips.length > 0 ? inc.source_ips.join(', ') : 'N/A'}
                    </div>
                  </div>

                  <div className="bg-soc-bg p-3 rounded border border-soc-borderMuted">
                    <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Attack Classifications</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {inc.attack_types && inc.attack_types.length > 0 ? (
                        inc.attack_types.map((at, i) => (
                          <span key={i} className="bg-slate-800 text-sky-300 px-1.5 py-0.5 rounded text-[11px] border border-slate-700 font-medium">
                            {at}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500">Unspecified</span>
                      )}
                    </div>
                  </div>

                  <div className="bg-soc-bg p-3 rounded border border-soc-borderMuted">
                    <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Severity & Risk</span>
                    <div className="mt-1 text-slate-200 flex items-center space-x-2">
                      <span className="font-bold">{inc.severity}</span>
                      <span className="text-slate-400">({inc.risk_score}/100)</span>
                    </div>
                  </div>
                </div>

                {/* Reasons / Evidence */}
                {inc.reasons && inc.reasons.length > 0 && (
                  <div className="bg-soc-bg p-3.5 rounded border border-soc-borderMuted space-y-1 text-xs font-mono">
                    <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Incident Investigation Findings</span>
                    <div className="space-y-1 pt-1">
                      {inc.reasons.map((reason, rIdx) => (
                        <div key={rIdx} className="flex items-start space-x-2 text-slate-300 text-xs">
                          <AlertCircle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                          <span>{reason}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Incident Workflow Architecture Panel for Presenter */}
      <div className="bg-soc-panel border border-soc-border rounded-lg p-5 space-y-4 shadow-sm">
        <div className="flex items-center space-x-2 border-b border-soc-border pb-3">
          <ShieldAlert className="w-5 h-5 text-amber-400" />
          <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
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
