import React from 'react';
import { Bell, Radio, Terminal, AlertCircle, Flame } from 'lucide-react';
import { WebSocketAlertMessage } from '../types/alert';
import { StatusBadge } from './StatusBadge';

interface LiveAlertFeedProps {
  alerts: WebSocketAlertMessage[];
  onClear?: () => void;
}

export const LiveAlertFeed: React.FC<LiveAlertFeedProps> = ({ alerts, onClear }) => {
  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg flex flex-col h-full overflow-hidden shadow-sm">
      {/* Feed Header */}
      <div className="px-4 py-3 border-b border-soc-border flex items-center justify-between bg-soc-panel select-none">
        <div className="flex items-center space-x-2">
          <Bell className="w-4 h-4 text-amber-400" />
          <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
            Live Security Alert Feed
          </h3>
          <span className="bg-amber-950/80 text-amber-400 border border-amber-500/30 text-[10px] font-mono px-2 py-0.5 rounded font-medium">
            {alerts.length} LIVE
          </span>
        </div>

        <div className="flex items-center space-x-2">
          <span className="flex items-center space-x-1.5 text-[11px] font-mono text-slate-400">
            <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
            <span>WS STREAM</span>
          </span>
          {alerts.length > 0 && onClear && (
            <button
              onClick={onClear}
              className="text-[10px] font-mono text-slate-400 hover:text-slate-200 bg-soc-bg px-2 py-1 rounded border border-soc-border transition-colors"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Alert items list */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3 max-h-[500px]">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 px-4 text-center space-y-2">
            <div className="p-3 bg-soc-bg border border-soc-border rounded-full text-sky-400 mb-1">
              <Radio className="w-6 h-6 animate-pulse" />
            </div>
            <div className="text-[11px] font-mono font-bold text-sky-400 uppercase tracking-widest">
              STREAM STANDBY
            </div>
            <p className="text-xs font-mono text-slate-300 font-medium">
              Waiting for security telemetry...
            </p>
            <div className="flex items-center space-x-3 text-[10px] font-mono text-slate-400 bg-soc-bg px-3 py-1.5 rounded border border-soc-borderMuted mt-1">
              <span>WebSocket: <strong className="text-emerald-400">CONNECTED</strong></span>
              <span className="text-slate-600">|</span>
              <span>Pipeline: <strong className="text-sky-400">MONITORING</strong></span>
            </div>
            <p className="text-[10px] font-mono text-slate-500 pt-1">
              No live security alerts received in current session
            </p>
          </div>
        ) : (
          alerts.map((alert, idx) => {
            const isHigh = (alert.risk_level || '').toUpperCase() === 'HIGH RISK';
            const alertStatus = (alert as any).status || 'ACTIVE';
            const targetIp = (alert as any).target_ip;

            return (
              <div
                key={`${alert.alert_id}-${idx}`}
                className={`bg-soc-card border p-3.5 rounded-md transition-all shadow-sm space-y-2.5 animate-fadeIn ${
                  isHigh
                    ? 'border-rose-500/40 border-l-4 border-l-rose-500 bg-rose-950/15 hover:border-rose-500/60'
                    : 'border-soc-border hover:border-slate-700'
                }`}
              >
                {/* Alert Meta Header */}
                <div className="flex items-center justify-between text-xs font-mono border-b border-soc-borderMuted pb-2">
                  <div className="flex items-center space-x-2">
                    <StatusBadge status={alert.risk_level || 'SUSPICIOUS'} size="sm" />
                    <span className="text-slate-400 font-medium">
                      Score: <strong className={isHigh ? 'text-rose-300 font-bold' : 'text-slate-200'}>{alert.risk_score}/100</strong>
                    </span>
                    {isHigh && (
                      <span className="hidden sm:inline-flex items-center space-x-1 text-[10px] text-rose-400 font-bold px-1.5 py-0.2 rounded bg-rose-950/60 border border-rose-500/40">
                        <Flame className="w-3 h-3" />
                        <span>ACTION REQUIRED</span>
                      </span>
                    )}
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] bg-slate-900 text-slate-400 border border-slate-800 px-1.5 py-0.5 rounded font-mono">
                      {alertStatus}
                    </span>
                    <span className="text-[11px] text-soc-textMuted">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>

                {/* Attack Types & Network Attribution */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                  <div>
                    <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Attack Types</span>
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      {alert.attack_types && alert.attack_types.length > 0 ? (
                        alert.attack_types.map((at, i) => (
                          <span key={i} className="bg-slate-800 text-sky-300 px-1.5 py-0.5 rounded text-[11px] border border-slate-700 font-medium">
                            {at}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500 text-[11px]">Unspecified</span>
                      )}
                    </div>
                  </div>

                  <div>
                    <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Attribution</span>
                    <div className="font-mono text-slate-200 mt-0.5 flex flex-wrap items-center gap-1.5">
                      <span className="text-slate-300">
                        SRC: <strong className="text-amber-300">{alert.source_ips && alert.source_ips.length > 0 ? alert.source_ips.join(', ') : 'N/A'}</strong>
                      </span>
                      {targetIp && (
                        <span className="text-slate-400 text-[11px]">
                          → TGT: <strong className="text-slate-200">{targetIp}</strong>
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Triggered Rules & Detection Reasons / Evidence */}
                {((alert.rules_triggered && alert.rules_triggered.length > 0) || (alert.reasons && alert.reasons.length > 0)) && (
                  <div className="bg-soc-bg p-2.5 rounded border border-soc-borderMuted text-xs font-mono space-y-1.5">
                    {alert.rules_triggered && alert.rules_triggered.length > 0 && (
                      <div className="flex items-center space-x-1.5 text-slate-300">
                        <Terminal className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                        <span>Rule: <strong className="text-sky-300">{alert.rules_triggered.join(', ')}</strong></span>
                      </div>
                    )}

                    {alert.reasons && alert.reasons.length > 0 && (
                      <div className="space-y-0.5">
                        {alert.reasons.map((reason, rIdx) => (
                          <div key={rIdx} className="flex items-start space-x-1.5 text-slate-400 text-[11px]">
                            <AlertCircle className="w-3 h-3 text-amber-400/80 shrink-0 mt-0.5" />
                            <span>{reason}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
