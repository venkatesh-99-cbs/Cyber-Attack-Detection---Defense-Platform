import React from 'react';
import { Info, Database, Radio } from 'lucide-react';

interface DataAvailabilityBannerProps {
  title: string;
  message: string;
  scope: 'alerts' | 'incidents' | 'risk';
}

export const DataAvailabilityBanner: React.FC<DataAvailabilityBannerProps> = ({
  title,
  message,
  scope,
}) => {
  return (
    <div className="bg-soc-panel border border-amber-500/30 rounded-lg p-4 font-mono text-xs shadow-sm space-y-3">
      <div className="flex items-start space-x-3">
        <div className="p-2 bg-amber-950/60 border border-amber-500/40 text-amber-400 rounded shrink-0 mt-0.5">
          <Info className="w-4 h-4" />
        </div>

        <div className="space-y-1">
          <h4 className="text-slate-200 font-bold tracking-wide uppercase">{title}</h4>
          <p className="text-slate-300 leading-relaxed font-sans">{message}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-soc-borderMuted text-[11px]">
        <div className="flex items-center space-x-2 text-slate-300 bg-soc-bg p-2 rounded border border-soc-borderMuted">
          <Database className="w-3.5 h-3.5 text-sky-400 shrink-0" />
          <span>SQLite Database stores raw <strong className="text-slate-100">SecurityEvents</strong></span>
        </div>

        <div className="flex items-center space-x-2 text-slate-300 bg-soc-bg p-2 rounded border border-soc-borderMuted">
          <Radio className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          <span>Live {scope === 'alerts' ? 'Alerts' : 'Events'} broadcast via <strong className="text-slate-100">WebSocket (/ws)</strong></span>
        </div>
      </div>
    </div>
  );
};
