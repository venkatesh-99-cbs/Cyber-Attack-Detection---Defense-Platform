import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Database,
  Radio,
  Terminal,
  Layers,
  CheckCircle2
} from 'lucide-react';
import { DashboardStatsResponse, DashboardSummaryResponse } from '../types/api';
import { ConnectionState } from '../services/websocket';
import { WebSocketAlertMessage } from '../types/alert';

interface ThreatPostureProps {
  totalEvents: number;
  liveAlertCount: number;
  summary?: DashboardSummaryResponse | null;
  stats?: DashboardStatsResponse | null;
  liveAlerts?: WebSocketAlertMessage[];
  apiStatus: string;
  wsStatus: ConnectionState;
}

export const ThreatPosture: React.FC<ThreatPostureProps> = ({
  totalEvents,
  liveAlertCount,
  summary,
  stats,
  liveAlerts = [],
  apiStatus,
  wsStatus,
}) => {
  // Threat Posture from backend summary or fallback
  const systemStatus = summary?.system_status || (liveAlertCount > 0 ? 'SUSPICIOUS' : 'SAFE');
  const normalizedStatus = systemStatus.toUpperCase().trim();

  const isSuspicious = normalizedStatus === 'SUSPICIOUS';
  const isHighRisk = normalizedStatus === 'HIGH RISK' || normalizedStatus === 'HIGH';

  // Semantic styles for the command center hero
  let postureBorder = 'border-emerald-500/30 bg-emerald-950/15';
  let postureTextColor = 'text-emerald-400';
  let PostureIcon = ShieldCheck;
  let postureDesc = 'All evaluated network traffic and telemetry signatures within normal baseline parameters.';

  if (isHighRisk) {
    postureBorder = 'border-rose-500/40 bg-rose-950/20';
    postureTextColor = 'text-rose-400';
    PostureIcon = ShieldAlert;
    postureDesc = 'High-risk exploit patterns detected. Defensive response and incident containment active.';
  } else if (isSuspicious) {
    postureBorder = 'border-amber-500/40 bg-amber-950/20';
    postureTextColor = 'text-amber-400';
    PostureIcon = AlertTriangle;
    postureDesc = 'Anomalous activity detected exceeding baseline thresholds. Under active surveillance.';
  }

  // Determine actual risk score
  const latestAlert = liveAlerts.length > 0 ? liveAlerts[0] : null;
  const riskScoreDisplay = latestAlert?.risk_score !== undefined
    ? `${latestAlert.risk_score} / 100`
    : normalizedStatus === 'SAFE'
    ? '0 / 100 (Safe)'
    : 'Risk score unavailable';

  // Active alerts count
  const activeAlertsDisplay = summary?.active_alerts_count !== null && summary?.active_alerts_count !== undefined
    ? summary.active_alerts_count
    : (liveAlertCount > 0 ? liveAlertCount : '0');

  // Open incidents count
  const openIncidentsDisplay = summary?.open_incidents_count !== null && summary?.open_incidents_count !== undefined
    ? summary.open_incidents_count
    : 'Data unavailable';

  // Detected attacks count
  const detectedAttacksDisplay = stats?.detected_attack_count !== null && stats?.detected_attack_count !== undefined
    ? stats.detected_attack_count
    : 'Data unavailable';

  return (
    <div className="space-y-4">
      {/* ========================================================================= */}
      {/* 2. THREAT COMMAND CENTER HERO                                            */}
      {/* ========================================================================= */}
      <div className={`border rounded-lg p-5 shadow-md transition-all ${postureBorder}`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5">
          {/* Main Threat Posture Identity */}
          <div className="flex items-start space-x-4">
            <div className="p-3.5 bg-slate-900 border border-slate-800 rounded-lg shrink-0 mt-1 shadow-inner">
              <PostureIcon className={`w-9 h-9 ${postureTextColor}`} />
            </div>

            <div className="space-y-1.5">
              <div className="text-[11px] font-mono text-slate-400 uppercase tracking-widest flex items-center space-x-2">
                <span className="font-bold text-sky-400">THREAT COMMAND CENTER</span>
                <span className="text-slate-600">/</span>
                <span>CURRENT THREAT POSTURE</span>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <span className={`text-2xl sm:text-3xl font-black font-mono tracking-wider ${postureTextColor}`}>
                  {systemStatus}
                </span>

                <div className="h-5 w-px bg-slate-700/60 hidden sm:block" />

                <div className="flex items-center space-x-2 text-xs font-mono text-slate-300">
                  <span className="text-slate-400">Risk Score:</span>
                  <strong className="text-slate-100 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    {riskScoreDisplay}
                  </strong>
                </div>

                <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded bg-slate-900/90 border border-slate-800 text-[11px] font-mono text-slate-300">
                  <span className={`w-2 h-2 rounded-full ${wsStatus === 'CONNECTED' ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
                  <span>{wsStatus === 'CONNECTED' ? 'Monitoring Active' : 'Monitoring Standby'}</span>
                </span>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed font-sans max-w-3xl pt-0.5">
                {summary?.system_status_note || postureDesc}
              </p>
            </div>
          </div>

          {/* System Link Badges & Architecture Stamp */}
          <div className="flex flex-row lg:flex-col items-center lg:items-end justify-between lg:justify-center gap-2 border-t lg:border-t-0 lg:border-l border-slate-800/80 pt-3 lg:pt-0 lg:pl-6 shrink-0 font-mono text-xs">
            <div className="flex items-center space-x-2">
              <span className={`px-2.5 py-1 rounded text-[11px] font-bold border ${
                apiStatus === 'ok'
                  ? 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40'
                  : 'bg-rose-950/80 text-rose-400 border-rose-500/40'
              }`}>
                API {apiStatus === 'ok' ? 'ONLINE' : 'OFFLINE'}
              </span>

              <span className={`px-2.5 py-1 rounded text-[11px] font-bold border ${
                wsStatus === 'CONNECTED'
                  ? 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40'
                  : 'bg-slate-900 text-slate-400 border-slate-700'
              }`}>
                WS {wsStatus === 'CONNECTED' ? 'CONNECTED' : 'DISCONNECTED'}
              </span>
            </div>

            <div className="text-[11px] text-slate-400 text-right">
              SQLite Security Telemetry Engine
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 3. KEY METRICS (4 Compact SOC Cards)                                     */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 font-mono">
        {/* Metric 1: PERSISTED SECURITY EVENTS */}
        <div className="bg-soc-panel border border-soc-border p-4 rounded-lg shadow-sm hover:border-slate-700 transition-colors">
          <div className="text-[10px] text-soc-textMuted uppercase tracking-wider font-semibold">
            PERSISTED SECURITY EVENTS
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-1.5">
            {totalEvents.toLocaleString()}
          </div>
          <div className="text-[11px] text-emerald-400 mt-1 flex items-center space-x-1.5">
            <Database className="w-3.5 h-3.5 shrink-0" />
            <span>Recorded in SQLite table</span>
          </div>
        </div>

        {/* Metric 2: ACTIVE ALERTS */}
        <div className="bg-soc-panel border border-soc-border p-4 rounded-lg shadow-sm hover:border-slate-700 transition-colors">
          <div className="text-[10px] text-soc-textMuted uppercase tracking-wider font-semibold">
            ACTIVE ALERTS
          </div>
          <div className="text-2xl font-bold text-amber-400 mt-1.5">
            {activeAlertsDisplay}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center space-x-1.5">
            <Radio className="w-3.5 h-3.5 text-sky-400 shrink-0" />
            <span>{liveAlertCount > 0 ? `${liveAlertCount} live in session` : 'Persisted pipeline alerts'}</span>
          </div>
        </div>

        {/* Metric 3: OPEN INCIDENTS */}
        <div className="bg-soc-panel border border-soc-border p-4 rounded-lg shadow-sm hover:border-slate-700 transition-colors">
          <div className="text-[10px] text-soc-textMuted uppercase tracking-wider font-semibold">
            OPEN INCIDENTS
          </div>
          <div className="text-2xl font-bold text-rose-400 mt-1.5">
            {openIncidentsDisplay}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center space-x-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
            <span>Unresolved state machine items</span>
          </div>
        </div>

        {/* Metric 4: DETECTED ATTACKS */}
        <div className="bg-soc-panel border border-soc-border p-4 rounded-lg shadow-sm hover:border-slate-700 transition-colors">
          <div className="text-[10px] text-soc-textMuted uppercase tracking-wider font-semibold">
            DETECTED ATTACKS
          </div>
          <div className="text-2xl font-bold text-sky-400 mt-1.5">
            {detectedAttacksDisplay}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 truncate" title={stats?.detected_attack_count_note || 'Rule triggers'}>
            <Terminal className="w-3.5 h-3.5 text-sky-400 shrink-0 inline mr-1" />
            <span>Rule engine verified matches</span>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 4. SECURITY LIFECYCLE VISUALIZATION STRIP                                */}
      {/* ========================================================================= */}
      <div className="bg-soc-panel border border-soc-border rounded-lg p-3.5 shadow-sm select-none">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 pb-2.5 border-b border-soc-borderMuted mb-2.5">
          <div className="flex items-center space-x-2 text-xs font-mono">
            <Layers className="w-4 h-4 text-sky-400" />
            <span className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
              Security Lifecycle Architecture Flow
            </span>
          </div>
          <span className="text-[10px] font-mono text-soc-textMuted">
            End-to-End Cyber Attack Detection & Defense Pipeline
          </span>
        </div>

        {/* 7-Stage Horizontal Pipeline Progression */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 font-mono text-center text-xs">
          {/* Stage 1: EVENT */}
          <div className="bg-soc-bg border border-soc-borderMuted p-2 rounded flex flex-col justify-between">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">1. EVENT</div>
            <div className="text-xs font-bold text-sky-300 mt-0.5">RECORDED</div>
            <div className="text-[9px] text-slate-500 mt-0.5">Ingestion API</div>
          </div>

          {/* Stage 2: DETECTION */}
          <div className="bg-soc-bg border border-soc-borderMuted p-2 rounded flex flex-col justify-between">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">2. DETECTION</div>
            <div className="text-xs font-bold text-sky-400 mt-0.5">DETECTED</div>
            <div className="text-[9px] text-slate-500 mt-0.5">Rule Engine</div>
          </div>

          {/* Stage 3: RISK */}
          <div className="bg-soc-bg border border-soc-borderMuted p-2 rounded flex flex-col justify-between">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">3. RISK</div>
            <div className="text-xs font-bold text-amber-400 mt-0.5">SCORED</div>
            <div className="text-[9px] text-slate-500 mt-0.5">Risk Analysis</div>
          </div>

          {/* Stage 4: ALERT */}
          <div className="bg-soc-bg border border-soc-borderMuted p-2 rounded flex flex-col justify-between">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">4. ALERT</div>
            <div className="text-xs font-bold text-amber-300 mt-0.5">ALERTED</div>
            <div className="text-[9px] text-slate-500 mt-0.5">WS & Persistence</div>
          </div>

          {/* Stage 5: INCIDENT */}
          <div className="bg-soc-bg border border-soc-borderMuted p-2 rounded flex flex-col justify-between">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">5. INCIDENT</div>
            <div className="text-xs font-bold text-rose-400 mt-0.5">OPEN</div>
            <div className="text-[9px] text-slate-500 mt-0.5">Incident State</div>
          </div>

          {/* Stage 6: RESPONSE */}
          <div className="bg-soc-bg border border-soc-borderMuted p-2 rounded flex flex-col justify-between">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">6. RESPONSE</div>
            <div className="text-xs font-bold text-indigo-400 mt-0.5">RESPONDED</div>
            <div className="text-[9px] text-slate-500 mt-0.5">Simulation Block</div>
          </div>

          {/* Stage 7: VALIDATION */}
          <div className="bg-soc-bg border border-sky-500/30 p-2 rounded flex flex-col justify-between bg-sky-950/10">
            <div className="text-[10px] text-sky-400 uppercase tracking-wider font-bold">7. VALIDATION</div>
            <div className="text-xs font-bold text-emerald-400 mt-0.5 flex items-center justify-center space-x-1">
              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              <span>VALIDATED</span>
            </div>
            <div className="text-[9px] text-sky-300/80 mt-0.5">Efficacy Replay</div>
          </div>
        </div>
      </div>
    </div>
  );
};
