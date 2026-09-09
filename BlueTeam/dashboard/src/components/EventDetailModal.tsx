import React from 'react';
import { X, Shield, Clock, HardDrive, Terminal, FileCode, HelpCircle } from 'lucide-react';
import { SecurityEvent } from '../types/event';

interface EventDetailModalProps {
  event: SecurityEvent | null;
  onClose: () => void;
}

export const EventDetailModal: React.FC<EventDetailModalProps> = ({ event, onClose }) => {
  if (!event) return null;

  // Synthesis summary for presenter
  const eventSummary = (() => {
    const isConn = event.event_type === 'connection_attempt';
    const endpointStr = event.endpoint ? ` at endpoint ${event.endpoint}` : '';
    const methodStr = event.method ? ` via HTTP ${event.method}` : '';

    if (event.event_type === 'login_failure') {
      return `Failed authentication attempt received from source IP ${event.source_ip} targeting ${event.target_ip}${endpointStr}. This event was fed into BruteForceRule detection.`;
    }
    if (isConn) {
      return `Inbound connection attempt initiated from source IP ${event.source_ip} to target port/service on ${event.target_ip}. Evaluated against PortScanRule.`;
    }
    if (event.event_type === 'http_request') {
      return `HTTP payload ${methodStr} dispatched from ${event.source_ip} to ${event.target_ip}${endpointStr} (Status: ${event.status_code ?? 'N/A'}). Evaluated for SQL injection and URI anomalies.`;
    }
    return `Security telemetry event (${event.event_type}) recorded from ${event.source_ip} destined for ${event.target_ip}. Log message: "${event.message}".`;
  })();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-soc-panel border border-soc-border rounded-lg max-w-2xl w-full overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="px-5 py-3.5 border-b border-soc-border flex items-center justify-between bg-soc-card select-none">
          <div className="flex items-center space-x-2.5">
            <div className="p-1.5 bg-slate-900 border border-slate-800 rounded text-sky-400">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-xs font-bold font-mono text-slate-100 uppercase tracking-wider">
                Security Event Evidence Inspector
              </h3>
              <p className="text-[11px] font-mono text-sky-400">{event.event_id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            title="Close Inspector"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-4 font-mono text-xs text-slate-300">
          {/* Presenter "What Happened?" Briefing Card */}
          <div className="bg-sky-950/20 border border-sky-500/30 rounded-lg p-3.5 space-y-1.5">
            <div className="flex items-center space-x-2 text-sky-400 font-bold uppercase tracking-wider text-[11px]">
              <HelpCircle className="w-4 h-4 shrink-0" />
              <span>Executive Telemetry Briefing: What Happened?</span>
            </div>
            <p className="text-slate-200 text-xs font-sans leading-relaxed">
              {eventSummary}
            </p>
          </div>

          {/* Key Overview Attributes */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="bg-soc-bg p-3 rounded border border-soc-borderMuted space-y-1">
              <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Event Type</span>
              <span className="inline-block bg-slate-800 text-sky-300 px-2 py-0.5 rounded text-xs border border-slate-700 font-bold">
                {event.event_type}
              </span>
            </div>

            <div className="bg-soc-bg p-3 rounded border border-soc-borderMuted space-y-1">
              <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Status / Code</span>
              <span className="inline-block text-slate-200 font-bold text-xs">
                {event.status_code !== undefined && event.status_code !== null ? `HTTP ${event.status_code}` : 'Recorded'}
              </span>
            </div>

            <div className="bg-soc-bg p-3 rounded border border-soc-borderMuted space-y-1">
              <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Timestamp (UTC)</span>
              <div className="flex items-center space-x-1.5 text-slate-200 text-[11px]">
                <Clock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span className="truncate">{new Date(event.timestamp).toUTCString()}</span>
              </div>
            </div>
          </div>

          {/* Network Routing Attribution */}
          <div className="bg-soc-bg p-3.5 rounded border border-soc-borderMuted space-y-2">
            <div className="flex items-center space-x-2 text-slate-200 font-semibold border-b border-slate-800 pb-2">
              <HardDrive className="w-4 h-4 text-sky-400" />
              <span>Network Routing Attributes</span>
            </div>
            <div className="grid grid-cols-2 gap-4 pt-1">
              <div>
                <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Source IP (Attacker / Client)</span>
                <span className="text-amber-300 font-bold text-sm">{event.source_ip}</span>
              </div>
              <div>
                <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Target IP (Victim Server)</span>
                <span className="text-slate-100 font-bold text-sm">{event.target_ip}</span>
              </div>
            </div>
          </div>

          {/* HTTP Context if available */}
          {(event.endpoint || event.method || event.status_code !== undefined) && (
            <div className="bg-soc-bg p-3.5 rounded border border-soc-borderMuted space-y-2">
              <div className="flex items-center space-x-2 text-slate-200 font-semibold border-b border-slate-800 pb-2">
                <Terminal className="w-4 h-4 text-amber-400" />
                <span>HTTP Application Context</span>
              </div>
              <div className="grid grid-cols-3 gap-3 pt-1">
                <div>
                  <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Method</span>
                  <span className="text-slate-200 font-semibold">{event.method || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Endpoint</span>
                  <span className="text-sky-300 font-semibold truncate block">{event.endpoint || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Status Code</span>
                  <span className="text-slate-200 font-semibold">{event.status_code ?? 'N/A'}</span>
                </div>
              </div>
            </div>
          )}

          {/* Log Message */}
          <div className="bg-soc-bg p-3.5 rounded border border-soc-borderMuted space-y-1">
            <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Log Message</span>
            <p className="text-slate-200 leading-relaxed font-sans">{event.message}</p>
          </div>

          {/* Metadata JSON */}
          <div className="bg-soc-bg p-3.5 rounded border border-soc-borderMuted space-y-2">
            <div className="flex items-center space-x-2 text-slate-200 font-semibold border-b border-slate-800 pb-2">
              <FileCode className="w-4 h-4 text-emerald-400" />
              <span>Raw Event Telemetry Metadata (SQLite JSON)</span>
            </div>
            <pre className="p-3 bg-slate-950 rounded border border-slate-900 text-[11px] text-emerald-400 overflow-x-auto max-h-40">
              {JSON.stringify(event.metadata || {}, null, 2)}
            </pre>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-5 py-3 border-t border-soc-border bg-soc-card flex items-center justify-between">
          <span className="text-[11px] text-soc-textMuted font-mono">
            Database ID: #{event.id ?? '-'} | Event ID: {event.event_id}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs rounded border border-slate-700 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
