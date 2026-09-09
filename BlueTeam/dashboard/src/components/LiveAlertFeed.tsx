import React from 'react';
import { Bell, Radio, ShieldAlert, Terminal, AlertCircle } from 'lucide-react';
import { WebSocketAlertMessage } from '../types/alert';
import { StatusBadge } from './StatusBadge';

interface LiveAlertFeedProps {
  alerts: WebSocketAlertMessage[];
  onClear?: () => void;
}

export const LiveAlertFeed: React.FC<LiveAlertFeedProps> = ({ alerts, onClear }) => {
  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg flex flex-col h-full overflow-hidden">
      {/* Header */}
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
          <span className="flex items-center space-x-1 text-[11px] font-mono text-slate-400">
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

      {/* Alert items container */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3 max-h-[500px]">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
            <div className="p-3 bg-soc-bg border border-soc-border rounded-full text-slate-500 mb-3">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <p className="text-xs font-mono text-slate-300 font-medium">No live security alerts received in current session</p>
            <p className="text-[11px] text-soc-textMuted mt-1 max-w-sm">
              Connected to WebSocket endpoint <code className="text-sky-400 font-mono">/ws</code>. Pipeline alerts will stream here in real time when Target attack events are detected.
            </p>
          </div>
        ) : (
          alerts.map((alert, idx) => (
            <div
              key={`${alert.alert_id}-${idx}`}
              className="bg-soc-card border border-soc-border hover:border-slate-700 p-3.5 rounded-md transition-all shadow-sm space-y-2.5 animate-fadeIn"
            >
              {/* Alert Meta Header */}
              <div className="flex items-center justify-between text-xs font-mono border-b border-soc-borderMuted pb-2">
                <div className="flex items-center space-x-2">
                  <StatusBadge status={alert.risk_level || 'SUSPICIOUS'} size="sm" />
                  <span className="text-slate-400 font-medium">
                    Score: <strong className="text-slate-200">{alert.risk_score}/100</strong>
                  </span>
                </div>
                <span className="text-[11px] text-soc-textMuted">
                  {new Date(alert.timestamp).toLocaleTimeString()}
                </span>
              </div>

              {/* Attack types & Source IP */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                <div>
                  <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Attack Types</span>
                  <div className="flex flex-wrap gap-1 mt-0.5">
                    {alert.attack_types && alert.attack_types.length > 0 ? (
                      alert.attack_types.map((at, i) => (
                        <span key={i} className="bg-slate-800 text-sky-300 px-1.5 py-0.5 rounded text-[11px] border border-slate-700">
                          {at}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-500 text-[11px]">Unspecified</span>
                    )}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Source IP(s)</span>
                  <div className="font-mono text-slate-200 mt-0.5">
                    {alert.source_ips && alert.source_ips.length > 0 ? alert.source_ips.join(', ') : 'N/A'}
                  </div>
                </div>
              </div>

              {/* Triggered Rules & Detection Reasons */}
              {((alert.rules_triggered && alert.rules_triggered.length > 0) || (alert.reasons && alert.reasons.length > 0)) && (
                <div className="bg-soc-bg p-2.5 rounded border border-soc-borderMuted text-xs font-mono space-y-1.5">
                  {alert.rules_triggered && alert.rules_triggered.length > 0 && (
                    <div className="flex items-center space-x-1.5 text-slate-300">
                      <Terminal className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                      <span>Rules: <strong className="text-sky-300">{alert.rules_triggered.join(', ')}</strong></span>
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
          ))
        )}
      </div>
    </div>
  );
};
