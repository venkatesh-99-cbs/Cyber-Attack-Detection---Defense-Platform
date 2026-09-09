import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, Info } from 'lucide-react';

interface StatusBadgeProps {
  status: string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md', showIcon = true }) => {
  const normalized = status.toUpperCase().trim();

  let colorClasses = 'bg-slate-800/80 text-slate-300 border-slate-700/80';
  let Icon = Info;

  if (normalized === 'SAFE' || normalized === 'OK' || normalized === 'CONNECTED' || normalized === 'RESOLVED') {
    colorClasses = 'bg-emerald-950/60 text-emerald-400 border-emerald-500/30';
    Icon = ShieldCheck;
  } else if (normalized === 'SUSPICIOUS' || normalized === 'WARNING' || normalized === 'CONNECTING' || normalized === 'INVESTIGATING') {
    colorClasses = 'bg-amber-950/60 text-amber-400 border-amber-500/30';
    Icon = AlertTriangle;
  } else if (normalized === 'HIGH RISK' || normalized === 'HIGH' || normalized === 'CRITICAL' || normalized === 'ERROR' || normalized === 'OPEN') {
    colorClasses = 'bg-rose-950/60 text-rose-400 border-rose-500/30';
    Icon = ShieldAlert;
  }

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 space-x-1',
    md: 'text-xs font-medium px-2.5 py-1 space-x-1.5',
    lg: 'text-sm font-semibold px-3 py-1.5 space-x-2',
  }[size];

  return (
    <span
      className={`inline-flex items-center rounded border font-mono tracking-wide transition-colors ${colorClasses} ${sizeClasses}`}
    >
      {showIcon && <Icon className="w-3.5 h-3.5 shrink-0" />}
      <span>{status}</span>
    </span>
  );
};
