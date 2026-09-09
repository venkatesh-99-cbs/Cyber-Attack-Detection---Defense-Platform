import React, { useState, useEffect } from 'react';
import { Shield, Activity, Radio, Clock } from 'lucide-react';
import { ConnectionState } from '../services/websocket';
import { StatusBadge } from './StatusBadge';

interface HeaderProps {
  apiStatus: string;
  wsStatus: ConnectionState;
}

export const Header: React.FC<HeaderProps> = ({ apiStatus, wsStatus }) => {
  const [utcTime, setUtcTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="bg-soc-panel border-b border-soc-border px-4 py-3 sm:px-6 flex flex-col md:flex-row md:items-center justify-between gap-4 select-none">
      {/* Title & Brand */}
      <div className="flex items-center space-x-3">
        <div className="p-2 bg-slate-900 border border-slate-800 rounded-md text-sky-400">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-bold tracking-tight text-slate-100 font-mono">
              Cyber Attack Detection & Defense Platform
            </h1>
            <span className="bg-slate-800 text-slate-400 text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-700">
              BLUE TEAM SOC v0.1.0
            </span>
          </div>
          <p className="text-xs text-soc-textMuted font-sans">
            Real-Time Security Event Ingestion & Threat Analysis Console
          </p>
        </div>
      </div>

      {/* Connection & Time Status Indicators */}
      <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
        {/* Clock */}
        <div className="flex items-center space-x-1.5 bg-soc-bg px-3 py-1.5 rounded border border-soc-border text-slate-300">
          <Clock className="w-3.5 h-3.5 text-slate-400" />
          <span>{utcTime || 'UTC --:--:--'}</span>
        </div>

        {/* API Status */}
        <div className="flex items-center space-x-2 bg-soc-bg px-3 py-1.5 rounded border border-soc-border">
          <Activity className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-400">API:</span>
          <StatusBadge status={apiStatus === 'ok' ? 'OK' : 'ERROR'} size="sm" showIcon={false} />
        </div>

        {/* WebSocket Status */}
        <div className="flex items-center space-x-2 bg-soc-bg px-3 py-1.5 rounded border border-soc-border">
          <Radio className={`w-3.5 h-3.5 ${wsStatus === 'CONNECTED' ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
          <span className="text-slate-400">WS:</span>
          <StatusBadge status={wsStatus} size="sm" showIcon={false} />
        </div>
      </div>
    </header>
  );
};
