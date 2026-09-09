import React from 'react';
import { LayoutDashboard, Database, Bell, ShieldAlert, Cpu } from 'lucide-react';

export type TabType = 'overview' | 'events' | 'alerts' | 'incidents' | 'validation';

interface NavigationProps {
  activeTab: TabType;
  onTabChange: (tab: TabType) => void;
  liveAlertCount: number;
}

export const Navigation: React.FC<NavigationProps> = ({ activeTab, onTabChange, liveAlertCount }) => {
  const tabs: { id: TabType; label: string; icon: React.ElementType; badge?: string | number }[] = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'events', label: 'Events', icon: Database },
    { id: 'alerts', label: 'Alerts', icon: Bell, badge: liveAlertCount > 0 ? liveAlertCount : undefined },
    { id: 'incidents', label: 'Incidents', icon: ShieldAlert },
    { id: 'validation', label: 'Validation', icon: Cpu, badge: 'ENGINE' },
  ];

  return (
    <nav className="bg-soc-panel/60 border-b border-soc-border px-4 sm:px-6">
      <div className="flex space-x-1 overflow-x-auto py-2">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          const isReserved = tab.id === 'validation';

          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`flex items-center space-x-2 px-3.5 py-2 rounded-md text-xs font-mono font-medium transition-all whitespace-nowrap ${
                isActive
                  ? 'bg-slate-800 text-sky-400 border border-slate-700 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-500'}`} />
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <span
                  className={`ml-1.5 px-1.5 py-0.2 rounded text-[10px] ${
                    isReserved
                      ? 'bg-sky-950 text-sky-400 border border-sky-500/30'
                      : 'bg-amber-950 text-amber-400 border border-amber-500/30'
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
};
