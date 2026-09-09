import React, { useEffect, useState } from 'react';
import { Bell, RefreshCw, ShieldAlert, Terminal, AlertCircle, Database, Radio, Clock } from 'lucide-react';
import { DataAvailabilityBanner } from '../components/DataAvailabilityBanner';
import { LiveAlertFeed } from '../components/LiveAlertFeed';
import { StatusBadge } from '../components/StatusBadge';
import { apiService } from '../services/api';
import { Alert, WebSocketAlertMessage } from '../types/alert';

interface AlertsPageProps {
  liveAlerts: WebSocketAlertMessage[];
  onClearLiveAlerts: () => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ liveAlerts, onClearLiveAlerts }) => {
  const [persistedAlerts, setPersistedAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'persisted' | 'live'>('persisted');

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const res = await apiService.fetchAlerts();
      if (res && res.alerts) {
        setPersistedAlerts(res.alerts);
      } else {
        setPersistedAlerts([]);
      }
    } catch (err) {
      console.warn('Failed to fetch persisted alerts:', err);
      setPersistedAlerts([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  return (
    <div className="space-y-6">
      {/* Architecture & Persistence Status Banner */}
      <DataAvailabilityBanner
        title="Historical Alert Persistence Not Configured"
        message="Alert objects are evaluated dynamically by the Blue Team AlertEngine during security pipeline execution and broadcast over WebSockets (/ws). When lifecycle persistence is active, generated alerts are committed to the SQLite database."
        scope="alerts"
      />

      {/* Mode Selector & Controls Header */}
      <div className="bg-soc-panel border border-soc-border rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm select-none">
        <div className="flex items-center space-x-2">
          <div className="p-2 bg-slate-900 border border-slate-800 rounded text-amber-400">
            <Bell className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold font-mono text-slate-100 uppercase tracking-wider">
              Security Alert Management Console
            </h2>
            <p className="text-xs text-soc-textMuted font-sans">
              Inspection of pipeline-generated alerts and real-time threat notifications
            </p>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center space-x-2 font-mono text-xs">
          <button
            onClick={() => setActiveTab('persisted')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded border transition-colors ${
              activeTab === 'persisted'
                ? 'bg-slate-800 text-sky-400 border-slate-700 font-bold'
                : 'bg-soc-bg text-slate-400 border-soc-border hover:text-slate-200'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span>Persisted Alerts ({persistedAlerts.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('live')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded border transition-colors ${
              activeTab === 'live'
                ? 'bg-slate-800 text-amber-400 border-slate-700 font-bold'
                : 'bg-soc-bg text-slate-400 border-soc-border hover:text-slate-200'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Live Stream ({liveAlerts.length})</span>
          </button>

          {activeTab === 'persisted' && (
            <button
              onClick={loadAlerts}
              disabled={loading}
              className="p-1.5 bg-soc-bg hover:bg-slate-800 text-slate-300 border border-soc-border rounded transition-colors disabled:opacity-50 ml-1"
              title="Refresh Persisted Alerts"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* Main Alerts Content */}
      {activeTab === 'persisted' ? (
        <div className="space-y-4">
          {loading ? (
            <div className="bg-soc-panel border border-soc-border rounded-lg p-12 text-center text-xs font-mono text-slate-400">
              <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />
              <span>Querying persisted alerts from SQLite database...</span>
            </div>
          ) : persistedAlerts.length === 0 ? (
            <div className="bg-soc-panel border border-soc-border rounded-lg p-12 text-center text-xs font-mono text-slate-400 space-y-2">
              <ShieldAlert className="w-8 h-8 mx-auto text-slate-600 mb-2" />
              <p className="text-slate-300 font-semibold">No alerts available.</p>
              <p className="text-slate-500 max-w-md mx-auto text-[11px] font-sans">
                No historical security alerts are currently stored in SQLite. Alerts are recorded when high-risk or suspicious attack signatures are ingested.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {persistedAlerts.map((alert) => {
                const isHigh = (alert.severity || '').toUpperCase() === 'HIGH RISK';
                return (
                  <div
                    key={alert.alert_id}
                    className={`bg-soc-panel border rounded-lg p-5 shadow-sm space-y-3.5 transition-all ${
                      isHigh ? 'border-rose-500/40 border-l-4 border-l-rose-500 bg-rose-950/10' : 'border-soc-border'
                    }`}
                  >
                    {/* Header: Alert ID, Severity, Score, Status, Time */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-soc-border pb-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <StatusBadge status={alert.severity || 'SUSPICIOUS'} size="md" />
                        <span className="font-mono text-xs font-bold text-slate-200">
                          {alert.alert_id}
                        </span>
                        <span className="font-mono text-xs text-slate-400">
                          Score: <strong className={isHigh ? 'text-rose-400 font-bold' : 'text-slate-200'}>{alert.risk_score}/100</strong>
                        </span>
                      </div>

                      <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
                        <span className="bg-slate-800 text-slate-300 border border-slate-700 px-2 py-0.5 rounded text-[11px]">
                          {alert.status || 'ACTIVE'}
                        </span>
                        <span className="flex items-center space-x-1 text-slate-400">
                          <Clock className="w-3.5 h-3.5 text-slate-500" />
                          <span>{new Date(alert.timestamp).toLocaleString()}</span>
                        </span>
                      </div>
                    </div>

                    {/* Attribution & Rules */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                      <div className="bg-soc-bg p-3 rounded border border-soc-borderMuted">
                        <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Attack Types</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {alert.attack_types && alert.attack_types.length > 0 ? (
                            alert.attack_types.map((at, i) => (
                              <span key={i} className="bg-slate-800 text-sky-300 px-2 py-0.5 rounded text-[11px] border border-slate-700 font-medium">
                                {at}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-500">None</span>
                          )}
                        </div>
                      </div>

                      <div className="bg-soc-bg p-3 rounded border border-soc-borderMuted">
                        <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Source IP(s)</span>
                        <div className="mt-1 text-amber-300 font-bold">
                          {alert.source_ips && alert.source_ips.length > 0 ? alert.source_ips.join(', ') : 'N/A'}
                        </div>
                      </div>

                      <div className="bg-soc-bg p-3 rounded border border-soc-borderMuted">
                        <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Triggered Rules</span>
                        <div className="mt-1 text-sky-300 font-medium flex items-center space-x-1">
                          <Terminal className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                          <span>{alert.rule_names && alert.rule_names.length > 0 ? alert.rule_names.join(', ') : 'Rule Engine'}</span>
                        </div>
                      </div>
                    </div>

                    {/* Reasons / Evidence */}
                    {alert.reasons && alert.reasons.length > 0 && (
                      <div className="bg-soc-bg p-3.5 rounded border border-soc-borderMuted space-y-1 text-xs font-mono">
                        <span className="text-[10px] text-soc-textMuted uppercase tracking-wider block">Evidence & Reasons</span>
                        <div className="space-y-1 pt-1">
                          {alert.reasons.map((reason, rIdx) => (
                            <div key={rIdx} className="flex items-start space-x-2 text-slate-300 text-xs">
                              <AlertCircle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                              <span>{reason}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ) : (
        /* Live Session Alerts Stream */
        <div className="min-h-[500px]">
          <LiveAlertFeed alerts={liveAlerts} onClear={onClearLiveAlerts} />
        </div>
      )}
    </div>
  );
};
